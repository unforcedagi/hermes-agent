"""browser_vault_enter_code(source="own_inbox"): a code from the agent's own mailbox, entered unseen.

The real reader (scripts/own_inbox_code.py) runs as a subprocess against a stand-in JMAP server (the mail server is
the external system); the page is faked at the browser boundary like the other enter_code tests.
"""

import http.server
import importlib.util
import json
import logging
import re
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from tools import browser_vault_tool
from tools import browser_vault_tool_own_inbox as own

READER = Path(__file__).resolve().parents[2] / "scripts" / "own_inbox_code.py"
INBOX = "agent@inbox.test"
OTP_BOX = [{"index": 0, "type": "text", "name": "otp", "label": "Verification code", "autocomplete": "one-time-code"}]


def _reader_module():
    spec = importlib.util.spec_from_file_location("own_inbox_code", READER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Mailbox:
    """A JMAP server holding a few messages; it ignores the query's date filter, so the reader must apply it."""

    def __init__(self):
        self.messages, self.requests = [], 0
        box = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self._json({"primaryAccounts": {"urn:ietf:params:jmap:mail": "a1"}})

            def do_POST(self):
                box.requests += 1
                calls = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))["methodCalls"]
                if calls[0][0] == "Mailbox/get":
                    self._json({"methodResponses": [["Mailbox/get", {"list": [{"id": "i", "role": "inbox"}]}, "m"]]})
                    return
                listed = [{"from": [{"email": m["from"]}], "subject": m["subject"],
                           "receivedAt": datetime.fromtimestamp(m["at"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                           "textBody": [{"partId": "1"}], "bodyValues": {"1": {"value": m["body"]}}}
                          for m in sorted(box.messages, key=lambda m: -m["at"])]  # the query sorts newest first
                self._json({"methodResponses": [["Email/query", {}, "q"], ["Email/get", {"list": listed}, "g"]]})

            def _json(self, obj):
                data = json.dumps(obj).encode()
                self.send_response(200); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

            def log_message(self, *_):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"


@pytest.fixture
def mailbox(tmp_path, monkeypatch):
    box = _Mailbox()
    secret = tmp_path / "secret"
    secret.write_text("not-a-real-password", encoding="utf-8")
    cfg = {"reader": [sys.executable, "-I", str(READER), "--jmap", f"{INBOX}={secret}", "--jmap-url", box.url],
           "addresses": [INBOX], "origins": []}
    monkeypatch.setattr(own, "own_inbox_config", lambda: cfg)
    monkeypatch.setattr(own, "_used", set())
    yield box
    box.server.shutdown()


def _enter(page_origin="https://acme.test", **kw):
    seen = {}
    fake_eval = lambda t, e: {"success": True, "result": json.dumps(OTP_BOX) if "querySelectorAll" in e else page_origin + "/2fa"}

    def fake_secret(t, e):
        seen["expr"] = e
        return {"success": True, "result": json.dumps({"filled": 1})}

    with patch.object(browser_vault_tool, "_focus_bound_origin", lambda *a, **k: None), \
         patch.object(browser_vault_tool, "_eval_js", side_effect=fake_eval), \
         patch.object(browser_vault_tool, "_eval_js_secret", side_effect=fake_secret):
        raw = browser_vault_tool.browser_vault_enter_code(task_id="t", source="own_inbox", wait_s=0, **kw)
    typed = re.findall(r'"value": "(\d+)"', seen.get("expr", ""))
    return json.loads(raw), raw, typed


def test_newest_fresh_code_is_entered_unseen_once_and_audited(mailbox, caplog):
    now = time.time()
    mailbox.messages = [
        {"from": "no-reply@acme.test", "subject": "Your sign-in code", "body": "Your code is 482 913.", "at": now - 60},
        {"from": "no-reply@acme.test", "subject": "Code", "body": "Your code is 735001", "at": now - 180},  # replaced by a resend
        {"from": "no-reply@acme.test", "subject": "Old", "body": "Your code is 111222", "at": now - 1200},  # > 10 min
    ]
    with caplog.at_level(logging.INFO, logger=own.__name__):
        out, raw, typed = _enter(site="https://acme.test", sender="acme.test")
    assert out["success"] and out["source"] == "own_inbox" and typed == ["482913"]
    assert "482913" not in raw and "482913" not in caplog.text
    assert "entered: origin=https://acme.test basis=named" in caplog.text

    # The newest code was used: wait for the next mail, never fall back to the older code a resend replaced.
    again, _, typed_again = _enter(site="https://acme.test", sender="acme.test")
    assert again["error_type"] == "no_code_found" and typed_again == []


def test_origin_without_basis_is_refused_before_any_mail_is_read(mailbox, caplog):
    mailbox.messages = [{"from": "x@evil.test", "subject": "code", "body": "Your code is 654321", "at": time.time()}]
    with caplog.at_level(logging.INFO, logger=own.__name__):
        out, _, typed = _enter(page_origin="https://evil.test", site="https://acme.test", sender="evil.test")
        unsent, _, _ = _enter(site="https://acme.test")  # naming the site needs the sender too
    assert out["error_type"] == "origin_not_allowed" and typed == [] and mailbox.requests == 0
    assert unsent["error_type"] == "origin_not_allowed"
    assert "refused: origin=https://evil.test" in caplog.text

    other, _, _ = _enter(inbox="someone-else@inbox.test", site="https://acme.test", sender="acme.test")  # not one of the agent's inboxes
    assert other["error_type"] == "inbox_not_allowed" and mailbox.requests == 0


def test_reader_refuses_an_inbox_it_holds_no_key_for(mailbox):
    import subprocess

    cfg = own.own_inbox_config()
    proc = subprocess.run(cfg["reader"], input=json.dumps({"address": "user@inbox.test"}), capture_output=True,
                          text=True, timeout=30)
    assert proc.returncode == 1 and "not one of this reader's inboxes" in proc.stdout and mailbox.requests == 0


@pytest.mark.parametrize("subject,body,code", [
    ("Your verification code", "Enter 739 201 to continue.", "739201"),
    ("123456 is your login code", "", "123456"),
    ("Welcome", "Order #554433 shipped on 2026-11-21 for $120000. Your one-time passcode: 8842", "8842"),
    ("Sign in", "<p>Your security code is <b>662-019</b></p>", "662019"),
    ("Hello", "Your account number is 998877.", "998877"),     # one bare 6-digit number: it is the code
    ("Hello", "Call 555 0100 or 555 0199 about 301122 or 301133", None),  # ambiguous: no code
    ("Receipt", "Total 2026 items, ref 12", None),
    ("Hi", "Please verify " + "x" * 66 + " ref 4815162342", None),  # a long number across the window is not a code
])
def test_code_extraction(subject, body, code):
    assert _reader_module().extract_code(subject, body) == code


def test_hermes_enforces_the_ten_minutes_whatever_the_reader_returns(mailbox, monkeypatch):
    stale = json.dumps({"candidates": [{"code": "246810", "received_at": time.time() - 900, "from": "a@acme.test"}]})
    cfg = {**own.own_inbox_config(), "reader": [sys.executable, "-I", "-c", f"print({stale!r})"]}
    monkeypatch.setattr(own, "own_inbox_config", lambda: cfg)
    out, _, typed = _enter(site="https://acme.test", sender="acme.test")
    assert out["error_type"] == "no_code_found" and typed == []


@pytest.mark.parametrize("reply", ["null", "[1, 2]", '{"candidates": [{"code": "1234", "received_at": "yesterday"}]}', "not json"])
def test_a_malformed_reader_reply_is_a_clean_refusal(mailbox, monkeypatch, reply):
    cfg = {**own.own_inbox_config(), "reader": [sys.executable, "-I", "-c", f"print({reply!r})"]}
    monkeypatch.setattr(own, "own_inbox_config", lambda: cfg)
    out, _, typed = _enter(site="https://acme.test", sender="acme.test")
    assert out["error_type"] == "reader_failed" and typed == []
