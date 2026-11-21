#!/usr/bin/env python3
"""Read the newest one-time codes from the agent's OWN mailboxes, for browser_vault_enter_code(source="own_inbox").

Hermes runs this as the ``vault.own_inbox.reader`` command (usually through ``sudo -n python3 -I``, since mailbox
credentials are root-only). The inboxes it may read are named on its own command line, each with the credential
that opens it; any other address is refused, whatever Hermes asks for:

  own_inbox_code.py --jmap ADDRESS=SECRET_FILE [--jmap-url URL] --agentmail ADDRESS=CURL_CONFIG

  --jmap       a JMAP server account (Stalwart): SECRET_FILE holds the password, or "ADDRESS:password".
  --agentmail  an AgentMail inbox: CURL_CONFIG is a curl config with the API's Authorization header.

Request on stdin: {"address": "...", "sender": "acme.com | no-reply@acme.com", "max_age_s": 600, "wait_s": 60,
                   "skip": ["<sha256 of a code already used>", ...]}
  sender: a domain matches mail From that domain or its subdomains; an address matches only itself.
  The newest message from the sender holding a code is the answer. If its code is in ``skip`` (or there is none yet),
  the reader waits up to ``wait_s`` for new mail (JMAP: the server's push stream; AgentMail: every 5 s); it never
  falls back to an older message, whose code a resend has replaced.
Reply on stdout:  {"candidates": [{"code": "...", "received_at": <epoch>, "from": "..."}]} (at most one), or
                  {"error": "..."} with exit status 1. Nothing else is ever printed: no body, link or subject.
Stdlib only, so it runs under ``python3 -I``.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Callable, Iterable, List, Optional, Tuple

MAX_AGE_S = 600  # a hard ceiling: older mail never yields a code, whatever the request says
# Words that name a code. Not "sign in" / "security" / "confirm": a sign-in alert's date or a user number follows those.
_KEYWORDS = re.compile(r"\b(?:code|passcode|verification|one[- ]time|otp|pin)\b", re.IGNORECASE)
# 4-8 digits, or 3+3 / 4+4 split by a space or dash; never part of a longer token, URL, date, time or price.
_CODE = re.compile(r"(?<![\w/#.$€£:-])(\d{3,4}[ -]\d{3,4}|\d{4,8})(?![\w/%:-]|\.\d)")
_NEAR = 80  # characters after a keyword that still count as "the code it names"
_BEFORE = 40  # ... and before it ("123456 is your code")
_YEAR = re.compile(r"(?:19|20)\d\d")
_ADDRESS = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_MAX_WAIT_S = 120


def _flat(text: str) -> str:
    if "<" in text and ">" in text:
        text = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", text)
        text = html.unescape(re.sub(r"<[^>]+>", " ", text))
    return re.sub(r"\s+", " ", text)


def _near_keywords(text: str) -> List[str]:
    """Numbers just after (or shortly before) a word that names a code, in reading order; years left out."""
    numbers = [(m.start(), m.end(), re.sub(r"[ -]", "", m.group(1))) for m in _CODE.finditer(text)]
    out = []
    for kw in _KEYWORDS.finditer(text):
        out += [n for start, end, n in numbers
                if kw.end() <= start <= kw.end() + _NEAR or kw.start() - _BEFORE <= end <= kw.start()]
    return [n for n in out if not (len(n) == 4 and _YEAR.fullmatch(n))]


def extract_code(subject: str, body: str) -> Optional[str]:
    """The one code this message is about, or None when there is none or it is unclear.

    Numbers next to a word that names a code ("code", "verification", "one-time", ...) count, subject first: the first
    of 6-8 digits, else the first shorter one (never a year). A subject that names a code and a body holding exactly
    one 6-8 digit number also count. A message with no such word yields nothing (a welcome mail's member number is
    not a code). Split codes ("123 456") come back joined."""
    subject, body = _flat(subject or ""), _flat(body or "")
    near = _near_keywords(subject) + _near_keywords(body)
    long = [n for n in near if len(n) >= 6]
    if long or near:
        return (long or near)[0]
    if _KEYWORDS.search(subject):
        bare = {re.sub(r"[ -]", "", m.group(1)) for m in _CODE.finditer(body)}
        bare = {n for n in bare if len(n) >= 6}
        if len(bare) == 1:
            return bare.pop()
    return None


def from_matches(frm: str, sender: str) -> bool:
    """``sender`` is a domain (matches that domain and its subdomains) or a full address (matches only itself)."""
    sender = sender.strip().lower()
    for addr in _ADDRESS.findall(frm.lower()):
        domain = addr.rsplit("@", 1)[1]
        if addr == sender or ("@" not in sender and (domain == sender or domain.endswith("." + sender))):
            return True
    return False


def _epoch(stamp: str) -> float:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()


def _get(url: str, headers: dict, body: Optional[dict] = None, context=None) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                 headers={**headers, "Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, context=context, timeout=30).read())


def _jmap_inbox(address: str, secret_file: str, base: str) -> Tuple[Callable, Callable]:
    """``(messages(since), wait(seconds))`` for a JMAP account. ``wait`` returns when the server pushes a change
    (the session's EventSource, on the same loopback base) or the time is up."""
    raw = open(secret_file, encoding="utf-8").read().strip()
    if raw.partition(":")[0].lower() != address:  # the password alone (it may hold a colon itself)
        raw = f"{address}:{raw}"
    headers = {"Authorization": "Basic " + base64.b64encode(raw.encode()).decode()}
    ctx = ssl._create_unverified_context() if urllib.parse.urlsplit(base).hostname in ("127.0.0.1", "localhost") else None
    session = _get(base + "/jmap/session", headers, context=ctx)
    account = session["primaryAccounts"]["urn:ietf:params:jmap:mail"]
    using = {"using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"]}
    boxes = _get(base + "/jmap/", headers, {**using, "methodCalls": [["Mailbox/get", {"accountId": account,
                 "properties": ["role"]}, "m"]]}, context=ctx)["methodResponses"][0][1]["list"]
    outgoing = [b["id"] for b in boxes if b.get("role") in ("sent", "drafts", "trash")]  # mail the agent wrote or binned
    push = session.get("eventSourceUrl") or ""
    push = (base + urllib.parse.urlsplit(push).path + "?types=Email&closeafter=state&ping=0") if push else ""

    def wait(seconds: float) -> bool:
        """True when the server pushed a change; False after a plain pause or a timeout."""
        if not push:
            time.sleep(min(5.0, seconds))
            return False
        try:
            stream = urllib.request.urlopen(urllib.request.Request(push, headers={**headers, "Accept": "text/event-stream"}),
                                            context=ctx, timeout=max(1.0, seconds))
            with stream:
                for line in stream:
                    if line.startswith(b"event: state"):
                        return True
        except OSError:  # timed out with no change (or the stream broke): the caller queries again either way
            pass
        return False

    return (lambda since: _jmap_query(base, headers, ctx, account, using, outgoing, since)), wait


def _jmap_query(base: str, headers: dict, ctx, account: str, using: dict, outgoing: list, since: float) -> Iterable[tuple]:
    after = datetime.fromtimestamp(since, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    calls = [["Email/query", {"accountId": account, "filter": {"after": after, "inMailboxOtherThan": outgoing},
                              "sort": [{"property": "receivedAt", "isAscending": False}], "limit": 20}, "q"],
             ["Email/get", {"accountId": account, "#ids": {"resultOf": "q", "name": "Email/query", "path": "/ids"},
                            "properties": ["from", "subject", "receivedAt", "textBody", "htmlBody", "bodyValues"],
                            "fetchTextBodyValues": True, "fetchHTMLBodyValues": True}, "g"]]
    out = _get(base + "/jmap/", headers, {**using, "methodCalls": calls}, context=ctx)
    for m in out["methodResponses"][1][1]["list"]:
        values = m.get("bodyValues") or {}
        parts = (m.get("textBody") or []) or (m.get("htmlBody") or [])
        body = " ".join(str((values.get(p.get("partId")) or {}).get("value") or "") for p in parts)
        sender = ",".join(a.get("email", "") for a in (m.get("from") or []))
        yield _epoch(m["receivedAt"]), sender, m.get("subject") or "", body


def _agentmail_inbox(address: str, curl_config: str, sender: str) -> Tuple[Callable, Callable]:
    """``(messages(since), wait(seconds))`` for an AgentMail inbox: no push here, so ``wait`` is a 5 s pause."""
    return (lambda since: _agentmail_messages(address, curl_config, since, sender)), \
        (lambda seconds: bool(time.sleep(min(5.0, seconds))))


def _agentmail_messages(address: str, curl_config: str, since: float, sender: str) -> Iterable[tuple]:
    """Newest first (the API's order); a message body is fetched only for mail that can match."""
    m = re.search(r'(?:header\s*=?|-H)\s*"(Authorization):\s*([^"]+)"', open(curl_config, encoding="utf-8").read(),
                  re.IGNORECASE)
    if not m:
        raise ValueError("no Authorization header in the AgentMail curl config")
    headers = {"Authorization": m.group(2).strip()}
    inbox = "https://api.agentmail.to/v0/inboxes/" + urllib.parse.quote(address, safe="@")
    for msg in _get(inbox + "/messages?limit=20", headers).get("messages", []):
        at = _epoch(msg.get("timestamp") or msg["created_at"])
        if at < since or "sent" in (msg.get("labels") or []) or not from_matches(str(msg.get("from") or ""), sender):
            continue
        full = _get(inbox + "/messages/" + urllib.parse.quote(msg["message_id"], safe=""), headers)
        body = full.get("extracted_text") or full.get("text") or full.get("html") or ""
        yield at, str(msg.get("from") or ""), msg.get("subject") or "", body


def candidates(messages: Iterable[tuple], sender: str, since: float) -> List[dict]:
    """The newest message (``messages`` come newest first) from ``sender`` since ``since`` that holds a code."""
    for at, frm, subject, body in messages:
        if at < since or not from_matches(frm, sender):
            continue
        code = extract_code(subject, body)
        if code:
            return [{"code": code, "received_at": at, "from": frm}]
    return []


def _pairs(values: List[str], flag: str) -> dict:
    out = {}
    for v in values or []:
        addr, sep, path = v.partition("=")
        if not sep or "@" not in addr or not path:
            raise SystemExit(f"{flag} wants ADDRESS=PATH, got {v!r}")
        out[addr.strip().lower()] = path
    return out


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--jmap", action="append", default=[])
    ap.add_argument("--jmap-url", default="https://127.0.0.1:8480")
    ap.add_argument("--agentmail", action="append", default=[])
    args = ap.parse_args(argv)
    jmap, agentmail = _pairs(args.jmap, "--jmap"), _pairs(args.agentmail, "--agentmail")
    try:
        req = json.loads(sys.stdin.read() or "{}")
        address = str(req.get("address") or "").strip().lower()
        sender = str(req.get("sender") or "").strip()
        max_age = min(MAX_AGE_S, max(0, int(req.get("max_age_s") or MAX_AGE_S)))
        deadline = time.monotonic() + min(_MAX_WAIT_S, max(0, int(req.get("wait_s") or 0)))
        skip = {str(h) for h in (req.get("skip") or [])}
        if not sender:
            print(json.dumps({"error": "no sender: name the domain or address the code comes from"}))
            return 1
        if address in jmap:
            messages, wait = _jmap_inbox(address, jmap[address], args.jmap_url.rstrip("/"))
        elif address in agentmail:
            messages, wait = _agentmail_inbox(address, agentmail[address], sender)
        else:
            print(json.dumps({"error": f"{address or 'no address'} is not one of this reader's inboxes"}))
            return 1
        settle = 0  # after a push the new mail can take a moment to become searchable: a few quick re-queries
        while True:
            found = candidates(messages(time.time() - max_age), sender, time.time() - max_age)
            if found and hashlib.sha256(found[0]["code"].encode()).hexdigest() in skip:
                found = []  # the newest code was already used: only a newer mail can answer
            left = deadline - time.monotonic()
            if found or left <= 0:
                break
            if settle:
                settle -= 1
                time.sleep(min(1.0, left))
            elif wait(left):
                settle = 5
    except Exception as exc:  # the message never carries mail content: only the failure's kind and text
        print(json.dumps({"error": f"{type(exc).__name__}: {re.sub(r'[0-9]{4,}', '[digits]', str(exc))[:200]}"}))
        return 1
    print(json.dumps({"candidates": found}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
