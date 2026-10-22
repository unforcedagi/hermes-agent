"""Byte-stable gateway system prompts (the ephemeral session-context pin).

The composed system prompt used to change bytes nearly every gateway turn:
the "## Current Session Context" block was re-rendered from live platform
state per message (thread renames, voice-channel member/speaking state,
one-shot onboarding and auto-reset notes).  Every byte change re-keys the
provider prompt cache AND changes the gateway agent-cache signature, forcing
a full AIAgent rebuild per message.

The fix pins the rendered session-context bytes per session keyed by a hash
of the exact renderer inputs (``_ephemeral_change_key``) and relocates
must-deliver per-turn facts onto the current user message (the api_content
sidecar), so a key hit reuses the pinned bytes verbatim.

The maintained invariant — every rendered input appears in the change key —
is guarded by the parity test below.
"""

from __future__ import annotations

import hashlib
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from gateway.config import GatewayConfig, HomeChannel, Platform, PlatformConfig
from gateway.session import (
    SessionContext,
    SessionSource,
    build_session_context,
    build_session_context_prompt,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_runner(**attrs):
    from gateway.run import GatewayRunner

    runner = object.__new__(GatewayRunner)
    runner._session_ephemeral_pin = {}
    runner._session_vc_last = {}
    runner._pending_turn_sidecar_notes = {}
    runner._session_model_overrides = {}
    runner._session_reasoning_overrides = {}
    runner.adapters = {}
    runner.session_store = MagicMock()
    for key, value in attrs.items():
        setattr(runner, key, value)
    return runner


def _make_context(
    *,
    platform: Platform = Platform.DISCORD,
    chat_id: str = "111222333",
    chat_name: str = "general",
    chat_type: str = "channel",
    thread_id: str | None = "444555666",
    parent_chat_id: str | None = "111222333",
    chat_topic: str | None = "ops chatter",
    user_name: str | None = "pix",
    user_id: str | None = "9001",
    guild_id: str | None = "777888999",
    message_id: str | None = "1357",
    shared_multi_user: bool = False,
    connected: list[Platform] | None = None,
    home_channels: dict | None = None,
) -> SessionContext:
    source = SessionSource(
        platform=platform,
        chat_id=chat_id,
        chat_name=chat_name,
        chat_type=chat_type,
        user_id=user_id,
        user_name=user_name,
        thread_id=thread_id,
        chat_topic=chat_topic,
        parent_chat_id=parent_chat_id,
        scope_id=guild_id,
        message_id=message_id,
    )
    connected = connected if connected is not None else [Platform.DISCORD, Platform.TELEGRAM]
    if home_channels is None:
        home_channels = {
            Platform.DISCORD: HomeChannel(
                platform=Platform.DISCORD, chat_id="111222333", name="general"
            ),
        }
    return SessionContext(
        source=source,
        connected_platforms=connected,
        home_channels=home_channels,
        shared_multi_user_session=shared_multi_user,
    )


@pytest.fixture(autouse=True)
def _stable_discord_tools(monkeypatch):
    """Pin the config/env-dependent renderer gates so key<->render parity is
    evaluated on the same footing in every environment."""
    monkeypatch.setattr("gateway.session._discord_tools_loaded", lambda: True)
    monkeypatch.setattr("gateway.session._slack_tools_loaded", lambda: False)


def _key(runner, context, redact_pii=False):
    return runner._ephemeral_change_key(context, redact_pii)  # noqa: SLF001


def _render(context, redact_pii=False):
    return build_session_context_prompt(context, redact_pii=redact_pii)


# ---------------------------------------------------------------------------
# 1. Parity: key <-> render (the maintained invariant)
# ---------------------------------------------------------------------------

class TestEphemeralChangeKeyParity:
    # Single-field mutations spanning every rendered input.  For each:
    # if the rendered bytes change, the key MUST change (staleness guard).
    _MUTATIONS = [
        ("chat_name", dict(chat_name="renamed-thread")),
        ("chat_topic", dict(chat_topic="new topic")),
        ("chat_topic_cleared", dict(chat_topic=None)),
        ("thread_id", dict(thread_id="000111222")),
        ("thread_cleared", dict(thread_id=None, parent_chat_id=None)),
        ("chat_type", dict(chat_type="group")),
        ("user_name", dict(user_name="somebody-else")),
        ("user_name_cleared", dict(user_name=None)),
        ("user_id", dict(user_name=None, user_id="1234")),
        ("shared_multi_user", dict(shared_multi_user=True)),
        ("guild_id", dict(guild_id="123123123")),
        ("parent_chat_id", dict(parent_chat_id="999000111")),
        ("chat_id", dict(chat_id="999999999", parent_chat_id="999999999")),
        ("platform", dict(platform=Platform.TELEGRAM)),
        ("connected_platforms", dict(connected=[Platform.DISCORD])),
        (
            "home_channel_renamed",
            dict(
                home_channels={
                    Platform.DISCORD: HomeChannel(
                        platform=Platform.DISCORD, chat_id="111222333", name="ops-home"
                    )
                }
            ),
        ),
        (
            "home_channel_added",
            dict(
                home_channels={
                    Platform.DISCORD: HomeChannel(
                        platform=Platform.DISCORD, chat_id="111222333", name="general"
                    ),
                    Platform.TELEGRAM: HomeChannel(
                        platform=Platform.TELEGRAM, chat_id="tg1", name="tg-home"
                    ),
                }
            ),
        ),
        ("message_id_cleared", dict(message_id=None)),
    ]


    def test_redact_pii_flip_changes_key(self):
        # PII redaction only rewrites bytes on pii-safe platforms; the key
        # must react wherever the render does.
        runner = _make_runner()
        ctx = _make_context(platform=Platform.TELEGRAM, thread_id=None, parent_chat_id=None)
        assert _render(ctx, False) != _render(ctx, True)
        assert _key(runner, ctx, False) != _key(runner, ctx, True)


    def test_slack_note_byte_stable_across_turns_in_one_session(self):
        """Within one session (gate state constant), the Slack platform note
        must be byte-stable turn over turn — the pin returns the identical
        object, so the composed system prompt cannot drift mid-conversation."""
        runner = _make_runner()

        def _slack_ctx():
            return _make_context(
                platform=Platform.SLACK,
                chat_id="C123",
                thread_id=None,
                parent_chat_id=None,
                guild_id=None,
            )

        t1 = runner._pinned_session_context_prompt(_slack_ctx(), False, "sk-slack")  # noqa: SLF001
        t2 = runner._pinned_session_context_prompt(_slack_ctx(), False, "sk-slack")  # noqa: SLF001
        t3 = runner._pinned_session_context_prompt(_slack_ctx(), False, "sk-slack")  # noqa: SLF001
        assert t2 is t1 and t3 is t1
        assert hashlib.sha256(t1.encode()).hexdigest() == hashlib.sha256(t3.encode()).hexdigest()


# ---------------------------------------------------------------------------
# 2. The pin: reuse verbatim on hit, exactly one legit bust on change
# ---------------------------------------------------------------------------

class TestSessionContextPin:
    def test_pin_hit_returns_identical_object(self):
        runner = _make_runner()
        ctx = _make_context()
        first = runner._pinned_session_context_prompt(ctx, False, "sk")  # noqa: SLF001
        second = runner._pinned_session_context_prompt(_make_context(), False, "sk")  # noqa: SLF001
        # Identity, not just equality: the pinned bytes are reused verbatim,
        # immunizing against renderer nondeterminism.
        assert second is first


# ---------------------------------------------------------------------------
# 3. Two-turn byte test: composed system prompt sha256 + codex cache key
# ---------------------------------------------------------------------------

def _compose(context_prompt: str) -> str:
    """Compose base + ephemeral exactly like conversation_loop does."""
    base = "BASE IDENTITY PROMPT\n" + "x" * 8000
    return (base + "\n\n" + context_prompt).strip()


class TestComposedPromptByteStability:
    def test_turn2_equals_turn3_sha256(self):
        runner = _make_runner()
        name = "Fixing the flaky deploy"
        t2 = _compose(
            runner._pinned_session_context_prompt(  # noqa: SLF001
                _make_context(chat_name=name), False, "sk"
            )
        )
        t3 = _compose(
            runner._pinned_session_context_prompt(  # noqa: SLF001
                _make_context(chat_name=name), False, "sk"
            )
        )
        assert hashlib.sha256(t2.encode()).hexdigest() == hashlib.sha256(t3.encode()).hexdigest()


# ---------------------------------------------------------------------------
# 4. Voice-channel sidecar note: only-when-changed
# ---------------------------------------------------------------------------

def _source():
    return SessionSource(
        platform=Platform.DISCORD, chat_id="c1", chat_type="channel", user_id="u1"
    )


class _VcAdapter:
    def __init__(self, value):
        self.value = value

    def get_voice_channel_context(self, guild_id):
        return self.value


def _vc_runner(vc_value):
    adapter = _VcAdapter(vc_value)
    runner = _make_runner(adapters={Platform.DISCORD: adapter})
    return runner, adapter


def _vc_event():
    return SimpleNamespace(raw_message=SimpleNamespace(guild_id="777"))


class TestVoiceChannelSidecarNote:
    def test_first_sighting_injects(self):
        runner, _ = _vc_runner("**Voice:** dev-vc (2 members)")
        note = runner._voice_channel_sidecar_note(_vc_event(), _source(), "sk")  # noqa: SLF001
        assert note == "[Voice channel now: **Voice:** dev-vc (2 members)]"

    def test_unchanged_state_injects_nothing(self):
        runner, _ = _vc_runner("**Voice:** dev-vc (2 members)")
        assert runner._voice_channel_sidecar_note(_vc_event(), _source(), "sk")  # noqa: SLF001
        assert runner._voice_channel_sidecar_note(_vc_event(), _source(), "sk") is None  # noqa: SLF001

    def test_member_change_injects_again(self):
        runner, adapter = _vc_runner("**Voice:** dev-vc (2 members)")
        runner._voice_channel_sidecar_note(_vc_event(), _source(), "sk")  # noqa: SLF001
        adapter.value = "**Voice:** dev-vc (3 members)"
        note = runner._voice_channel_sidecar_note(_vc_event(), _source(), "sk")  # noqa: SLF001
        assert note == "[Voice channel now: **Voice:** dev-vc (3 members)]"

    def test_leaving_channel_injects_disconnect_note(self):
        runner, adapter = _vc_runner("**Voice:** dev-vc (2 members)")
        runner._voice_channel_sidecar_note(_vc_event(), _source(), "sk")  # noqa: SLF001
        adapter.value = ""
        note = runner._voice_channel_sidecar_note(_vc_event(), _source(), "sk")  # noqa: SLF001
        assert note == "[Voice channel now: not connected to a voice channel]"

    def test_never_in_channel_injects_nothing(self):
        runner, _ = _vc_runner("")
        assert runner._voice_channel_sidecar_note(_vc_event(), _source(), "sk") is None  # noqa: SLF001


# ---------------------------------------------------------------------------
# 5. Sidecar note staging: one-shot per turn
# ---------------------------------------------------------------------------

class TestSidecarNoteStaging:
    def test_set_then_consume_once(self):
        runner = _make_runner()
        runner._set_pending_turn_sidecar_notes("sk", ["[System note: reset]"])  # noqa: SLF001
        assert runner._consume_pending_turn_sidecar_notes("sk") == ["[System note: reset]"]  # noqa: SLF001
        assert runner._consume_pending_turn_sidecar_notes("sk") == []  # noqa: SLF001


# ---------------------------------------------------------------------------
# 6. Connected platforms: stable order
# ---------------------------------------------------------------------------

class TestConnectedPlatformsOrder:
    def test_sorted_regardless_of_insertion_order(self):
        cfg_a = GatewayConfig(
            platforms={
                Platform.TELEGRAM: PlatformConfig(enabled=True, token="t"),
                Platform.DISCORD: PlatformConfig(enabled=True, token="d"),
            }
        )
        cfg_b = GatewayConfig(
            platforms={
                Platform.DISCORD: PlatformConfig(enabled=True, token="d"),
                Platform.TELEGRAM: PlatformConfig(enabled=True, token="t"),
            }
        )
        assert cfg_a.get_connected_platforms() == cfg_b.get_connected_platforms()
        values = [p.value for p in cfg_a.get_connected_platforms()]
        assert values == sorted(values)


# ---------------------------------------------------------------------------
# 7. Internal turns render the human turn's bytes (T-133)
# ---------------------------------------------------------------------------
# Driven through the real GatewayRunner._handle_message_with_agent -> _hmwa_prepare_turn, so the
# run_turn.py call site is covered, not only the helper. The agent run itself is the boundary.

_KEY = "agent:main:telegram:group:-1001:pk-owner"


def _src(*, user_name=None, chat_name=None, chat_topic=None, user_id="pk-owner"):
    """A group chat source. The bare call is the real uni-relay room-digest origin shape: platform,
    chat_id, chat_type and user_id only."""
    return SessionSource(platform=Platform.TELEGRAM, chat_id="-1001", chat_type="group", chat_name=chat_name,
                         chat_topic=chat_topic, user_id=user_id, user_name=user_name)


def _turn_runner(monkeypatch, tmp_path, *, origin=None, shared=False):
    """A real GatewayRunner with the session store and the agent run faked (the
    test_internal_notification_marker.py harness)."""
    import sys
    import types
    from datetime import datetime
    from unittest.mock import AsyncMock

    import gateway.run as gateway_run
    from gateway.session import SessionEntry

    fake_dotenv = types.ModuleType("dotenv")
    fake_dotenv.load_dotenv = lambda *args, **kwargs: None
    monkeypatch.setitem(sys.modules, "dotenv", fake_dotenv)
    config = GatewayConfig(platforms={Platform.TELEGRAM: PlatformConfig(enabled=True, token="t")})
    config.group_sessions_per_user = not shared
    runner = gateway_run.GatewayRunner(config)
    runner.adapters = {}
    runner._is_user_authorized = lambda _source: True
    runner._set_session_env = lambda _context: None
    runner._handle_active_session_busy_message = AsyncMock(return_value=False)
    runner._session_db = MagicMock()
    runner._recover_telegram_topic_thread_id = lambda _source: None
    runner._cache_session_source = lambda _key, _source: None
    runner._is_session_run_current = lambda _key, _gen: True
    runner._begin_session_run_generation = lambda _key: 1
    runner._reply_anchor_for_event = lambda _event: None
    runner._get_guild_id = lambda _event: None
    runner._should_send_voice_reply = lambda *_a, **_kw: False
    runner.hooks = MagicMock()
    runner.hooks.emit = AsyncMock()
    runner.session_store = MagicMock()
    runner.session_store.get_or_create_session.return_value = SessionEntry(
        session_key=_KEY, session_id="sess-t133", created_at=datetime.now(), updated_at=datetime.now(),
        platform=Platform.TELEGRAM, chat_type="group", origin=origin)
    runner.session_store.load_transcript.return_value = []
    runner.session_store.has_platform_message_id.return_value = False
    runner._run_agent = AsyncMock(return_value={
        "final_response": "ok", "messages": [], "tools": [], "history_offset": 0, "last_prompt_tokens": 0})
    monkeypatch.setattr(gateway_run, "_hermes_home", tmp_path)
    monkeypatch.setattr(gateway_run, "_resolve_runtime_agent_kwargs", lambda: {"api_key": "fake"})
    monkeypatch.setattr("agent.model_metadata.get_model_context_length", lambda *_a, **_kw: 100_000)
    return runner


async def _turn(runner, source, *, internal):
    """One gateway turn; returns the session-context prompt it handed to the agent run."""
    from gateway.platforms.event import MessageEvent

    event = MessageEvent(text="[digest] nothing new" if internal else "hello", source=source,
                         message_id=None if internal else f"m-{runner._run_agent.call_count}", internal=internal)
    calls = runner._run_agent.call_count
    try:
        await runner._handle_message_with_agent(event, source, _KEY, 1)  # noqa: SLF001
    finally:
        runner._release_turn_lease(_KEY, 1)  # what _handle_message's finally does  # noqa: SLF001
    assert runner._run_agent.call_count == calls + 1, "the turn never reached the agent run"
    return runner._run_agent.call_args.kwargs["context_prompt"]


def _sig(runner, prompt, user_id):
    return runner._agent_config_signature(  # noqa: SLF001
        "opus", {"provider": "p", "base_url": "b", "api_mode": "chat_completions"}, ["t"], prompt, user_id=user_id)


class TestInternalTurnPromptStability:
    """A self-injected turn (plugin wake, room digest, process or delegation notice) is built from a
    plugin origin or the creation-time session origin, whose display labels are missing or stale.
    Rendered as is, it flipped the system prompt tail and the agent-cache signature on every
    human <-> internal alternation: a fresh AIAgent and a full prompt-cache re-write (measured
    2026-10-17..21: 38 of 92 warm turn-starts after a sender change missed, ~6M tokens written)."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("human, internal, origin, between", [
        (_src(user_name="pix", chat_name="main"), _src(), None, None),                              # room digest
        (_src(user_name="pix", chat_name="main"), _src(chat_name="at-creation"), None, None),         # stale stored origin
        (_src(user_name="pix", chat_name="main"), _src(chat_topic="cleared since"), None, None),      # human cleared it
        (_src(user_name="pix", chat_name="main"), _src(), None, "evict"),                            # agent evicted between
        (_src(user_name="pix", chat_name="main", user_id="pk-a"), _src(user_id="pk-creator"), None, "shared"),
        (_src(user_name="pix", chat_name="main"), _src(), _src(user_name="pix", chat_name="main"), "internal-first"),
    ], ids=["digest", "stale-origin", "cleared-label", "after-eviction", "shared-thread", "internal-first"])
    async def test_internal_turn_renders_the_human_bytes(self, monkeypatch, tmp_path, human, internal, origin, between):
        runner = _turn_runner(monkeypatch, tmp_path, origin=origin, shared=between == "shared")
        if between == "internal-first":  # no human turn seen yet (e.g. after a restart): origin labels fill in
            text = await _turn(runner, internal, internal=True)
            first = await _turn(runner, human, internal=False)
        else:
            first = await _turn(runner, human, internal=False)
            if between == "evict":
                runner._evict_cached_agent(_KEY)  # noqa: SLF001
            text = await _turn(runner, internal, internal=True)
        assert _render(build_session_context(internal, runner.config)) != first  # the source really differs
        assert _compose(text) == _compose(first)
        if between != "shared":  # same user -> the cached agent is reused
            assert _sig(runner, text, internal.user_id) == _sig(runner, first, human.user_id)
        assert await _turn(runner, human, internal=False) == first

    @pytest.mark.asyncio
    async def test_internal_turn_never_hides_a_real_change(self, monkeypatch, tmp_path):
        runner = _turn_runner(monkeypatch, tmp_path)
        assert "-1001" in await _turn(runner, _src(user_name="pix"), internal=False)  # no chat_name: raw id shown
        (tmp_path / "config.yaml").write_text("privacy:\n  redact_pii: true\n")
        redacted = await _turn(runner, _src(), internal=True)
        assert "-1001" not in redacted and "pk-owner" not in redacted and '"pix"' in redacted

        runner = _turn_runner(monkeypatch, tmp_path / "home")
        await _turn(runner, _src(user_name="pix", chat_name="main"), internal=False)
        runner.config.platforms[Platform.TELEGRAM].home_channel = HomeChannel(
            platform=Platform.TELEGRAM, chat_id="42", name="new-home")
        moved = await _turn(runner, _src(), internal=True)
        assert "new-home" in moved and '"pix"' in moved

        # Another owner takes no labels, from the last human turn or from the origin.
        runner = _turn_runner(monkeypatch, tmp_path / "other", origin=_src(user_name="pix", chat_name="main"))
        await _turn(runner, _src(user_name="pix", chat_name="main"), internal=False)
        other = _src(user_id="pk-bridge")
        foreign = await _turn(runner, other, internal=True)
        assert foreign == _render(build_session_context(other, runner.config)) and "pix" not in foreign
