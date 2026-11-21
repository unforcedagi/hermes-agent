"""A vault call that waits on the user keeps its browser open (T-487).

browser_vault_enter_code asks the user for a one-time code and can wait minutes for the answer. The browser's
inactivity janitor and the agent-browser daemon's own idle timer both closed the browser under that wait, so the
supervisor lost its socket and every code entry ended in ``supervisor_required``.
"""

import contextlib
import http.server
import os
import shutil
import threading
import time
from unittest.mock import patch

import pytest

from tools import browser_tool as bt
from tools import browser_tool_lifecycle as lifecycle


@pytest.fixture
def tracking():
    """A clean slate of the browser tool's session tracking, restored afterwards."""
    saved = (dict(bt._active_sessions), dict(bt._session_last_activity), dict(bt._session_holds))
    bt._active_sessions.clear(); bt._session_last_activity.clear(); bt._session_holds.clear()
    yield
    for live, old in zip((bt._active_sessions, bt._session_last_activity, bt._session_holds), saved):
        live.clear(); live.update(old)


def test_held_session_outlives_the_inactivity_timeout_and_its_daemon_is_kept_awake(tracking):
    stale = time.time() - bt.BROWSER_SESSION_INACTIVITY_TIMEOUT - 5
    for key in ("held", "idle"):
        bt._active_sessions[key] = {"session_name": f"h_{key}", "cdp_url": None}
        bt._session_last_activity[key] = stale

    closed, pinged = [], []

    def agent_browser(key, info, cmd_parts, command, *_):  # the external CLI process
        (closed if command == "close" else pinged).append(key)
        return {"success": True, "data": {}}

    with patch("tools.browser_tool_session._browser_command_preflight", return_value={"browser_cmd": "agent-browser"}), \
         patch("tools.browser_tool_session._spawn_and_collect", side_effect=agent_browser), \
         patch("tools.browser_tool._maybe_stop_recording"):
        with lifecycle.hold_browser_session("held"):
            lifecycle._cleanup_inactive_browser_sessions()
            lifecycle._keep_held_sessions_alive()
            lifecycle._keep_held_sessions_alive()  # fresh again: no second ping
        assert closed == ["idle"] and pinged == ["held"]
        assert "held" in bt._active_sessions

        bt._session_last_activity["held"] = stale
        with lifecycle.hold_browser_session("held"):  # a cloud/CDP session is never pinged: its stamp stays old
            pass
        lifecycle._cleanup_inactive_browser_sessions()  # the release restarts the clock: no teardown right after
        assert closed == ["idle"]

        bt._session_last_activity["held"] = stale  # released: an ordinary idle session again
        lifecycle._cleanup_inactive_browser_sessions()
        assert closed == ["idle", "held"]


def test_a_hold_never_relaunches_a_session_that_is_already_gone(tracking):
    with patch("tools.browser_tool_session._browser_command_preflight", return_value={"browser_cmd": "agent-browser"}), \
         patch("tools.browser_tool_session._spawn_and_collect") as agent_browser:
        with lifecycle.hold_browser_session("gone"):
            lifecycle._keep_held_sessions_alive()
    agent_browser.assert_not_called()
    assert "gone" not in bt._session_holds


_OTP_PAGE = b"""<!doctype html><title>Code</title><form>
<label>Verification code <input id=otp name=otp inputmode=numeric autocomplete=one-time-code></label>
<button>Verify</button></form>"""


@pytest.mark.integration
@pytest.mark.skipif(os.environ.get("HERMES_E2E_BROWSER", "").strip() != "1",
                    reason="real-browser E2E: set HERMES_E2E_BROWSER=1 to opt in")
@pytest.mark.skipif(not shutil.which("chromium") and not shutil.which("google-chrome"),
                    reason="Chrome/Chromium not installed")
def test_code_entered_after_the_user_takes_longer_than_the_browser_timeout(monkeypatch, tracking):
    """Real agent-browser + Chromium: the user answers the code prompt after both idle timers ran out."""
    from agent.vault_backends.unlock import set_code_prompt_callback, set_unlock_prompt_callback
    from tools.browser_supervisor import SUPERVISOR_REGISTRY
    from tools.browser_vault_tool import _handle_vault_enter_code
    from hermes_constants import get_hermes_home

    (get_hermes_home() / "config.yaml").write_text("browser:\n  backend: 'off'\n", encoding="utf-8")
    timeout = 4
    monkeypatch.setattr(bt, "BROWSER_SESSION_INACTIVITY_TIMEOUT", timeout)

    class Page(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
            self.wfile.write(_OTP_PAGE)

        def log_message(self, *_):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Page)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    task, code = "hold-e2e", "482916"  # made up

    def slow_user(site, hint):
        time.sleep(timeout * 3)  # past the daemon's idle exit and the janitor's timeout
        lifecycle._cleanup_inactive_browser_sessions()  # a janitor tick while the user is still typing
        return code

    set_unlock_prompt_callback(lambda *_: "")
    set_code_prompt_callback(slow_user)
    try:
        nav = bt.browser_navigate(f"http://127.0.0.1:{server.server_address[1]}/otp", task_id=task)
        assert '"success": true' in nav, nav
        result = _handle_vault_enter_code({}, task_id=task)
        assert '"success": true' in result, result
        landed = SUPERVISOR_REGISTRY.get(task).evaluate_runtime(f"document.querySelector('#otp').value === '{code}'")
        assert landed.get("result") is True
    finally:
        set_code_prompt_callback(None); set_unlock_prompt_callback(None)
        server.shutdown()
        with contextlib.suppress(Exception):
            lifecycle.cleanup_all_browsers()
