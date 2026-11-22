"""A Buzz message that arrives while the gateway drains for a restart is answered after the restart.

Before T-487 the drain refused it ("not accepting new work") and the Buzz cursor moved past it, so the
relay's durable copy was never read again (11-21: two messages lost in one drain). Now the runner hands
it back to the adapter, which leaves it unread on disk; the next adapter life replays it.

Real ``BuzzAdapter`` and real ``GatewayRunner`` drain gates, two adapter lives sharing one
``HERMES_HOME`` cursor file; only the relay (the ``buzz`` CLI) is faked.
"""

import asyncio

import pytest
from unittest.mock import AsyncMock

from gateway.platforms.event import MessageEvent
from gateway.run import GatewayRunner
from tests.gateway._plugin_adapter_loader import load_plugin_adapter
from tests.gateway.restart_test_helpers import make_restart_runner

_buzz = load_plugin_adapter("buzz")

SELF_PUBKEY = "9fd5c7ba6d3ef224da78f541e0fcb9c50f72cc63edb19aae76ac6a0474dfa860"
SELF_NPUB = "npub1nl2u0wnd8mezfknc74q7pl9ec58h9nrrakce4tnk434qgaxl4psqe5twr6"
SENDER = "a" * 64
CHANNEL = "ccc2bc1a-7a82-5a8f-8c4e-57a070cbe7cd"
REFUSAL = "not accepting"


class FakeRelay:
    """The relay as the ``buzz`` CLI sees it: every message ever posted, filtered by ``--since``."""

    def __init__(self):
        self.events = []
        self.sent = []

    def post(self, event_id, content, created_at):
        self.events.append({"id": event_id, "pubkey": SENDER, "content": content, "created_at": created_at,
                            "kind": 9, "tags": [["h", CHANNEL], ["p", SELF_PUBKEY]]})

    async def __call__(self, args, *, input_text=None):
        import json
        if args[:2] == ["messages", "get"]:
            since = int(args[args.index("--since") + 1]) if "--since" in args else 0
            return 0, json.dumps([e for e in self.events if e["created_at"] >= since]), ""
        if args[:2] == ["messages", "send"]:
            self.sent.append(input_text if input_text is not None else args[-1])
            return 0, json.dumps({"accepted": True, "event_id": f"reply-{len(self.sent)}"}), ""
        return 0, "[]", ""


def _adapter(relay):
    from gateway.config import PlatformConfig
    adapter = _buzz.BuzzAdapter(PlatformConfig(enabled=True, extra={"relay_url": "https://test.relay"}))
    adapter._self_pubkey, adapter._self_npub, adapter._display_name = SELF_PUBKEY, SELF_NPUB, "Chip"
    adapter._private_key = "nsec1test"
    adapter.set_authorization_check(lambda *_args: True)
    adapter._run_cli = relay
    adapter.send_reaction = AsyncMock()
    return adapter


async def _start(adapter):
    """What connect() does for intake: restore (or seed) the cursor, then read the channel."""
    adapter._load_cursors()
    await adapter._seed_channel(CHANNEL, chat_type="group")
    adapter._save_cursors()


def _draining_runner(adapter):
    runner, _ = make_restart_runner(adapter)
    runner.adapters = {adapter.platform: adapter}
    runner._draining = runner._restart_requested = True
    return runner


async def _settle(adapter):
    for _ in range(100):
        if not adapter._background_tasks:
            return
        await asyncio.sleep(0.01)
    raise AssertionError("adapter background work never finished")


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    return tmp_path


@pytest.mark.asyncio
async def test_message_during_restart_drain_is_answered_after_restart(home):
    relay = FakeRelay()
    relay.post("old", "@Chip answered before the restart", 100)

    # Life 1: the gateway is draining for a restart when a new mention lands.
    first = _adapter(relay)
    await _start(first)
    runner = _draining_runner(first)
    first.set_message_handler(runner._handle_message)
    relay.post("during", "@Chip are you there?", 200)
    relay.post("command", "@Chip /frobnicate", 210)
    await first._poll_channel(CHANNEL)
    await _settle(first)

    assert len(relay.sent) == 2, relay.sent
    # The mention is held; the command is refused as before, never held (a replayed command would run again).
    assert sorted("when it's back" in reply for reply in relay.sent) == [False, True]
    assert sorted(REFUSAL in reply for reply in relay.sent) == [False, True]

    # Still draining: the next read must not hand the held message to the gateway a second time.
    await first._poll_channel(CHANNEL)
    await _settle(first)
    assert len(relay.sent) == 2

    # Life 2: a new process, same HERMES_HOME. The held message is delivered; nothing else is.
    second = _adapter(relay)
    answered = []

    async def gateway(event: MessageEvent):
        answered.append(event.message_id)
        return "here now"

    second.set_message_handler(gateway)
    await _start(second)
    await second._poll_channel(CHANNEL)
    await _settle(second)
    assert answered == ["during"]
    assert relay.sent[-1] == "here now"


@pytest.mark.asyncio
@pytest.mark.parametrize("head", ["merged follow-ups", "a slash command"])
async def test_follow_ups_queued_before_the_drain_are_all_held(home, head):
    relay = FakeRelay()
    first = _adapter(relay)
    await _start(first)
    for event_id, text, ts in (("q1", "@Chip one more thing", 300), ("q2", "@Chip and another", 301),
                               ("q3", "@Chip third", 302), ("q4", "@Chip fourth", 303)):
        relay.post(event_id, text, ts)
    raw = {e["id"]: e for e in relay.events}
    # Both were read (and so marked seen) while a turn was busy, before the drain began.
    await first._handle_events(CHANNEL, first._channel_state[CHANNEL], list(raw.values()))
    assert {"q1", "q2", "q3", "q4"} <= set(first._channel_state[CHANNEL]["seen"])
    runner = _draining_runner(first)

    # The busy turn had queued them before the drain began: q1 and q2 merged into the adapter slot, q3 and q4
    # behind them in the runner's FIFO (q3 gets staged into the slot as the slot drains).
    from gateway.platforms.base import merge_pending_message_event
    source = first.build_source(chat_id=CHANNEL, chat_type="group", user_id=SENDER)
    session_key = runner._session_key_for_source(source)

    def queued(event_id):
        return MessageEvent(text=raw[event_id]["content"], source=source, message_id=event_id,
                            raw_message=raw[event_id])

    if head == "a slash command":
        # A queued command is never held or run after the turn; the follow-ups behind it still must be.
        first._pending_messages[session_key] = MessageEvent(text="/model x", source=source, message_id="cmd")
        expected = ["q3", "q4"]
    else:
        for event_id in ("q1", "q2"):
            merge_pending_message_event(first._pending_messages, session_key, queued(event_id), merge_text=True)
        expected = ["q1", "q2", "q3", "q4"]
    for event_id in ("q3", "q4"):
        runner._enqueue_fifo(session_key, queued(event_id), first)
    assert len(runner._overflow_queue(session_key)) == 2
    pending_event, pending = await GatewayRunner._run_agent_drain_pending(
        runner, {"final_response": "done"}, first, source, session_key)
    assert (pending_event, pending) == (None, None)

    second = _adapter(relay)
    answered = []

    async def gateway(event: MessageEvent):
        answered.extend(part.message_id for part in event.parts())  # later ones merge into a busy turn

    second.set_message_handler(gateway)
    await _start(second)
    await second._poll_channel(CHANNEL)
    await _settle(second)
    if head == "a slash command":
        answered = [event_id for event_id in answered if event_id in expected]  # q1, q2 were never queued
    assert sorted(answered) == expected


@pytest.mark.asyncio
async def test_a_part_that_cannot_be_replayed_holds_nothing(home):
    """All or nothing: the runner refuses the whole message, so no part of it may also be replayed later."""
    import json
    relay = FakeRelay()
    relay.post("ok", "@Chip replayable", 400)
    adapter = _adapter(relay)
    await _start(adapter)
    await adapter._handle_events(CHANNEL, adapter._channel_state[CHANNEL], list(relay.events))
    source = adapter.build_source(chat_id=CHANNEL, chat_type="group", user_id=SENDER)
    good = MessageEvent(text="replayable", source=source, message_id="ok", raw_message=relay.events[0])
    no_copy = MessageEvent(text="never on the relay", source=source, message_id="local")

    assert adapter.hold_for_restart([good, no_copy]) is False
    saved = json.loads((home / "buzz" / "channel-cursors.json").read_text())["channels"][CHANNEL]
    assert "ok" in saved["seen"] and saved["last_ts"] == 400
