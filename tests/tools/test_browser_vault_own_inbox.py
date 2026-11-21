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
                listed = [{"id": str(i), "from": [{"email": m["from"]}], "subject": m["subject"],
                           "receivedAt": datetime.fromtimestamp(m["at"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                           "textBody": [{"partId": "1"}], "bodyValues": {"1": {"value": m["body"]}}}
                          for i, m in sorted(enumerate(box.messages), key=lambda im: -im[1]["at"])]  # newest first
                listed = listed[:calls[0][1].get("limit", 10**6)] if calls[0][0] == "Email/query" else listed
                ids = calls[-1][1].get("ids")
                if ids is not None:  # a body fetch for named messages
                    listed = [m for m in listed if m["id"] in ids]
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


def _enter(page_origin="https://acme.test", wait_s=0, **kw):
    seen = {}
    fake_eval = lambda t, e: {"success": True, "result": json.dumps(OTP_BOX) if "querySelectorAll" in e else page_origin + "/2fa"}

    def fake_secret(t, e):
        seen["expr"] = e
        return {"success": True, "result": json.dumps({"filled": 1})}

    with patch.object(browser_vault_tool, "_focus_bound_origin", lambda *a, **k: None), \
         patch.object(browser_vault_tool, "_eval_js", side_effect=fake_eval), \
         patch.object(browser_vault_tool, "_eval_js_secret", side_effect=fake_secret):
        raw = browser_vault_tool.browser_vault_enter_code(task_id="t", source="own_inbox", wait_s=wait_s, **kw)
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

    def resend():
        time.sleep(1.5)
        mailbox.messages.append({"from": "no-reply@mail.acme.test", "subject": "Your new code", "body": "Code: 906144",
                                 "at": time.time()})
    threading.Thread(target=resend, daemon=True).start()
    third, _, typed_third = _enter(site="https://acme.test", sender="acme.test", wait_s=20)  # waits for the resend
    assert third["success"] and typed_third == ["906144"]


def test_origin_without_basis_is_refused_before_any_mail_is_read(mailbox, caplog):
    mailbox.messages = [{"from": "x@evil.test", "subject": "code", "body": "Your code is 654321", "at": time.time()}]
    with caplog.at_level(logging.INFO, logger=own.__name__):
        out, _, typed = _enter(page_origin="https://evil.test", site="https://acme.test", sender="evil.test")
        unsent, _, _ = _enter(site="https://acme.test")  # no sender: another site's newer code could be the one read
    assert out["error_type"] == "origin_not_allowed" and typed == [] and mailbox.requests == 0
    assert unsent["error_type"] == "sender_required"
    assert "refused: origin=https://evil.test" in caplog.text

    other, _, _ = _enter(inbox="someone-else@inbox.test", site="https://acme.test", sender="acme.test")  # not one of the agent's inboxes
    assert other["error_type"] == "inbox_not_allowed" and mailbox.requests == 0


def test_reader_refuses_an_inbox_it_holds_no_key_for(mailbox):
    import subprocess

    cfg = own.own_inbox_config()
    proc = subprocess.run(cfg["reader"], input=json.dumps({"address": "user@inbox.test", "sender": "acme.test"}), capture_output=True,
                          text=True, timeout=30)
    assert proc.returncode == 1 and "not one of this reader's inboxes" in proc.stdout and mailbox.requests == 0


@pytest.mark.parametrize("subject,body,code", [
    ("Your verification code", "Enter 739 201 to continue.", "739201"),
    ("123456 is your login code", "", "123456"),
    ("Welcome", "Order #554433 shipped on 2026-11-21 for $120000. Your one-time passcode: 8842", "8842"),
    ("Sign in", "<p>Your security code is <b>662-019</b></p>", "662019"),
    ("Welcome!", "Your member ID is 553311.", None),  # no word that names a code: not a code
    ("Sign in", "This code is valid until Nov 21, 2026. Code: 482913", "482913"),
    ("Sign in", "We sent a code to the phone ending in 4321. Your code is 482913", "482913"),
    ("Order", "Order 12345678 received. Your verification code is 4821.", "4821"),
    ("Code", "Your code is 2024.", "2024"),  # a year-like code still counts when it is the only number
    ("482913 is your Acme verification code", "If you didn't request this code, write to Acme, 1600 Main St", "482913"),
    ("Sign in", "482913 is your code. \u00a92026 Acme", "482913"),
    ("Code", "Your code is \u0664\u0668\u0662\u0661\u0669\u0663", None),  # only ASCII digits are typed
    ("Hello", "Call 555 0100 or 555 0199 about 301122 or 301133", None),  # ambiguous: no code
    ("Receipt", "Total 2026 items, ref 12", None),
    ("Hi", "Your code is ready " + "x" * 66 + " ref 4815162342", None),  # a long number across the window is not a code
    ("New sign-in to your account", "We noticed a sign in on Nov 21, 2026 from Chrome. Your verification code is 482913.", "482913"),
    ("Welcome", "Thanks for signing up, Pinterest user 1234! Your code: 482913", "482913"),
])
def test_code_extraction(subject, body, code):
    assert _reader_module().extract_code(subject, body) == code


def test_hermes_enforces_the_ten_minutes_whatever_the_reader_returns(mailbox, monkeypatch):
    stale = json.dumps({"candidates": [{"code": "246810", "received_at": time.time() - 900, "from": "a@acme.test"}]})
    cfg = {**own.own_inbox_config(), "reader": [sys.executable, "-I", "-c", f"print({stale!r})"]}
    monkeypatch.setattr(own, "own_inbox_config", lambda: cfg)
    out, _, typed = _enter(site="https://acme.test", sender="acme.test")
    assert out["error_type"] == "no_code_found" and typed == []


@pytest.mark.parametrize("reply", ["null", "[1, 2]", '{"candidates": [{"code": "1234", "received_at": "yesterday"}]}', "not json",
                                   '{"candidates": [{"code": "None", "received_at": 9999999999}]}'])
def test_a_malformed_reader_reply_is_a_clean_refusal(mailbox, monkeypatch, reply):
    cfg = {**own.own_inbox_config(), "reader": [sys.executable, "-I", "-c", f"print({reply!r})"]}
    monkeypatch.setattr(own, "own_inbox_config", lambda: cfg)
    out, _, typed = _enter(site="https://acme.test", sender="acme.test")
    assert out["error_type"] == "reader_failed" and typed == []


@pytest.mark.parametrize("frm,sender,ok", [
    ('"no-reply@acme.test" <x@evil.example>', "acme.test", False),  # a display name is not the address
    ("no-reply@acme.test", "acme.test", True),
    ("Acme <no-reply@mail.acme.test>", "acme.test", True),
    ("no-reply@acme.test.attacker.example", "acme.test", False),
    ("x@evil-acme.test", "acme.test", False),
    ("no-reply@acme.test", "no-reply@acme.test", True),
    ("other@acme.test", "no-reply@acme.test", False),
])
def test_sender_matches_the_from_domain_not_a_substring(frm, sender, ok):
    assert _reader_module().from_matches(frm, sender) is ok


@pytest.mark.parametrize("sender,ok", [("acme.test", True), ("no-reply@gmail.com", True), ("com", False),
                                       ("gmail.com", False), (".com", False), ("co.uk", False), ("github.io", False),
                                       ("@acme.test", False), ("x@", False)])
def test_a_sender_must_name_one_site(sender, ok):
    assert _reader_module().sender_ok(sender) is ok


def test_a_saved_authenticator_key_wins_over_the_inbox(mailbox, tmp_path):
    from agent.vault_store import VaultStore

    store = VaultStore(tmp_path / "vault")
    meta = store.add_item("login", "acme", {"identifier_type": "username", "identifier": "agent", "password": "pw",
                                            "otp_secret": "JBSWY3DPEHPK3PXP"}, origin="https://acme.test")
    with patch("agent.vault_store.get_vault_store", return_value=store):
        out, raw, typed = _enter(handle=meta.id)  # own_inbox asked for, no sender: the key mints it, no mail is read
    assert out["success"] and out["source"] == "local" and len(typed) == 1 and mailbox.requests == 0


def test_a_busy_inbox_does_not_hide_the_sites_mail(mailbox):
    now = time.time()
    mailbox.messages = [{"from": "no-reply@acme.test", "subject": "Code", "body": "Your code is 318264", "at": now - 120}]
    mailbox.messages += [{"from": f"news{i}@other.test", "subject": "News", "body": "Your code is 111111", "at": now - i}
                         for i in range(30)]  # thirty newer mails from other senders
    out, _, typed = _enter(site="https://acme.test", sender="acme.test")
    assert out["success"] and typed == ["318264"]
