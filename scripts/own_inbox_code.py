#!/usr/bin/env python3
"""Read the newest one-time code from the agent's OWN mailboxes, for browser_vault_enter_code(source="own_inbox").

Runs as a socket-activated service (systemd ``Accept=yes``: one process per connection, the connection on stdin and
stdout), as its own service user, never as the agent's user and never as root. Hermes connects to the unix socket and
sends one request line; this answers with one reply line. The inboxes it may read are fixed on its own command line,
each with the credential that opens it, by whoever installed the service; any other address is refused before any
mail server is contacted, whatever the request says:

  own_inbox_code.py --peer-uid UID --jmap ADDRESS=SECRET_FILE [--jmap-url URL] --agentmail ADDRESS=CURL_CONFIG

  --peer-uid   the only uid that may ask (checked with SO_PEERCRED on the connection); anyone else is refused.
  --jmap       a JMAP server account (Stalwart): SECRET_FILE holds its password, or "login@domain:password" for a
               login of the reader's own that ADDRESS shares its Inbox with read-only (the least it needs: such a
               login can open nothing else). Only the account named ADDRESS is ever queried.
  --agentmail  an AgentMail inbox: CURL_CONFIG is a curl config with the API's Authorization header.

Request, one JSON line: {"address": "...", "sender": "acme.com | no-reply@acme.com", "max_age_s": 600,
                         "wait_s": 60, "skip": ["<sha256 of a code already used>", ...]}
  No other key is accepted. sender: a domain (two labels at least, not a free-mail one) matches mail From that domain
  or its subdomains; an address matches only itself. Only the From address counts, never its display name.
  The newest message from the sender holding a code is the answer. If its code is in ``skip`` (or there is none yet),
  the reader waits up to ``wait_s`` for new mail (JMAP: the server's push stream; AgentMail: every 5 s); it never
  falls back to an older message, whose code a resend has replaced.
Reply, one JSON line: {"candidates": [{"code": "...", "received_at": <epoch>, "from": "..."}]} (at most one), or
                      {"error": "..."}. Nothing else is ever sent: no body, link or subject.
Each request writes one audit line to stderr (the journal): who asked, which inbox and sender, and the outcome. Never
the code. Stdlib only, so it runs under ``python3 -I``.
"""
from __future__ import annotations

import argparse
import base64
import email.utils
import hashlib
import html
import json
import os
import re
import socket
import ssl
import struct
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Callable, Iterable, List, Optional, Tuple

MAX_AGE_S = 600  # a hard ceiling: older mail never yields a code, whatever the request says
# Words that name a code. Not "sign in" / "security" / "confirm": a sign-in alert's date or a user number follows those.
_KEYWORDS = re.compile(r"\b(?:code|passcode|verification|one[- ]time|otp|pin)\b", re.IGNORECASE)
# 4-8 ASCII digits, or 3+3 / 4+4 split by a space or dash; never part of a longer token, URL, date, time or price.
_CODE = re.compile(r"(?<![\w/#.$€£:-])([0-9]{3,4}[ -][0-9]{3,4}|[0-9]{4,8})(?![\w/%:-]|\.[0-9])")
_NEAR = 80  # characters after a keyword that still count as "the code it names"
_BEFORE = 40  # ... and before it ("123456 is your code")
_YEAR = re.compile(r"(?:19|20)[0-9]{2}")
_EMAIL = re.compile(r"[^@\s:]+@[^@\s:]+\.[^@\s:]+")
# Domains many unrelated senders share: naming one would not name a site.
_SHARED = {"co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.jp", "co.nz", "com.br", "co.in", "github.io",
           "herokuapp.com", "vercel.app", "netlify.app", "pages.dev", "workers.dev", "appspot.com", "blogspot.com",
           "azurewebsites.net", "cloudfront.net", "amazonaws.com", "firebaseapp.com", "web.app"}
_FREE_MAIL = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "icloud.com",
              "me.com", "aol.com", "proton.me", "protonmail.com", "gmx.com", "gmx.net", "mail.com", "yandex.com"}
_MAX_WAIT_S = 120
_MAX_REQUEST = 32768  # bytes in the one request line
_FIELDS = {"address", "sender", "max_age_s", "wait_s", "skip"}
_SHA256 = re.compile(r"[0-9a-f]{64}")


def _flat(text: str) -> str:
    if "<" in text and ">" in text:
        text = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", text)
        text = html.unescape(re.sub(r"<[^>]+>", " ", text))
    return re.sub(r"\s+", " ", text)


def _near_keywords(text: str, years: bool) -> Tuple[Optional[str], Optional[str]]:
    """``(after, before)``: the number closest after a word that names a code (within 80 characters), and the first
    number shortly before one (within 40: "123456 is your code"). ``years=False`` passes over 19xx/20xx."""
    numbers = [(m.start(), m.end(), re.sub(r"[ -]", "", m.group(1))) for m in _CODE.finditer(text)]
    numbers = [t for t in numbers if years or not _YEAR.fullmatch(t[2])]
    after, before, best = None, None, _NEAR + 1
    for kw in _KEYWORDS.finditer(text):
        for start, end, n in numbers:
            if kw.end() <= start and start - kw.end() < best:
                after, best = n, start - kw.end()
            elif before is None and kw.start() - _BEFORE <= end <= kw.start():
                before = n
    return after, before


def extract_code(subject: str, body: str) -> Optional[str]:
    """The one code this message is about, or None when there is none or it is unclear.

    The subject first, then the body: in each, the number closest after a word that names a code ("code",
    "verification", "one-time", ...), else one just before such a word. A year (19xx/20xx, a footer's "(c)2026") counts
    only when nothing else does. Else, when the subject names a code, the body's only 6-8 digit number. A message
    with no such word yields nothing (a welcome mail's member number is not a code). Split codes come back joined."""
    subject, body = _flat(subject or ""), _flat(body or "")
    for years in (False, True):
        for text in (subject, body):
            after, before = _near_keywords(text, years)
            if after or before:
                return after or before
    if _KEYWORDS.search(subject):
        bare = {re.sub(r"[ -]", "", m.group(1)) for m in _CODE.finditer(body)}
        bare = {n for n in bare if len(n) >= 6}
        if len(bare) == 1:
            return bare.pop()
    return None


def sender_ok(sender: str) -> bool:
    """A sender narrow enough to name one site: an address, or a domain of two labels or more that is not free mail."""
    sender = sender.strip().lower()
    if "@" in sender:
        return bool(_EMAIL.fullmatch(sender))
    return bool(re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", sender)) and sender not in _FREE_MAIL | _SHARED


def from_matches(frm: str, sender: str) -> bool:
    """``sender`` is a domain (matches that domain and its subdomains) or a full address (matches only itself). Only
    the From addresses count, never a display name that looks like one."""
    sender = sender.strip().lower()
    for _, addr in email.utils.getaddresses([frm]):
        addr = addr.lower()
        domain = addr.rsplit("@", 1)[-1] if "@" in addr else ""
        if domain and (addr == sender or ("@" not in sender and (domain == sender or domain.endswith("." + sender)))):
            return True
    return False


def _epoch(stamp: str) -> float:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()


def _get(url: str, headers: dict, body: Optional[dict] = None, context=None) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                 headers={**headers, "Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, context=context, timeout=30).read())


def _jmap_inbox(address: str, secret_file: str, base: str, sender: str) -> Tuple[Callable, Callable]:
    """``(messages(since), wait(seconds))`` for the JMAP account named ``address``. SECRET_FILE holds that account's
    password, or ``login@domain:password`` for a login of its own that ``address`` shares its Inbox with (read-only).
    Only the account named ``address`` is ever queried, whatever else the login can see. ``wait`` returns when the
    server pushes a change (the session's EventSource, on the same loopback base) or the time is up; a shared mailbox
    gets no push from the server, so there it is a 5 s pause."""
    raw = open(secret_file, encoding="utf-8").read().strip()
    login, colon, _ = raw.partition(":")
    if not (colon and _EMAIL.fullmatch(login)):  # the password alone (it may hold an @ or a colon itself)
        login, raw = address, f"{address}:{raw}"
    headers = {"Authorization": "Basic " + base64.b64encode(raw.encode()).decode()}
    ctx = ssl._create_unverified_context() if urllib.parse.urlsplit(base).hostname in ("127.0.0.1", "localhost") else None
    session = _get(base + "/jmap/session", headers, context=ctx)
    account = next((aid for aid, a in (session.get("accounts") or {}).items()
                    if str(a.get("name") or "").lower() == address), None)
    if account is None:
        raise LookupError("this reader's login sees no account by that name")
    using = {"using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"]}
    boxes = _get(base + "/jmap/", headers, {**using, "methodCalls": [["Mailbox/get", {"accountId": account,
                 "properties": ["role"]}, "m"]]}, context=ctx)["methodResponses"][0][1]["list"]
    outgoing = [b["id"] for b in boxes if b.get("role") in ("sent", "drafts", "trash")]  # mail the agent wrote or binned
    push = (session.get("eventSourceUrl") or "") if login.lower() == address else ""
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

    return (lambda since: _jmap_query(base, headers, ctx, account, using, outgoing, since, sender)), wait


def _jmap_get(base: str, headers: dict, ctx, using: dict, calls: list) -> list:
    out = _get(base + "/jmap/", headers, {**using, "methodCalls": calls}, context=ctx)
    return next(r[1].get("list") or [] for r in out["methodResponses"] if r[0] == "Email/get")


def _jmap_query(base: str, headers: dict, ctx, account: str, using: dict, outgoing: list, since: float,
                sender: str) -> Iterable[tuple]:
    """Newest first: the From of every recent message (all of the window, whatever else arrived), then the bodies
    of the sender's messages one at a time, so the caller stops at the first that holds a code."""
    after = datetime.fromtimestamp(since, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    match = {"after": after, "inMailboxOtherThan": outgoing}  # from_matches decides the sender (subdomains too)
    heads = _jmap_get(base, headers, ctx, using, [
        ["Email/query", {"accountId": account, "filter": match,
                         "sort": [{"property": "receivedAt", "isAscending": False}], "limit": 500}, "q"],
        ["Email/get", {"accountId": account, "#ids": {"resultOf": "q", "name": "Email/query", "path": "/ids"},
                       "properties": ["id", "from", "receivedAt"]}, "g"]])
    for head in heads:
        frm = ",".join(a.get("email", "") for a in (head.get("from") or []))
        if not from_matches(frm, sender):
            continue
        full = _jmap_get(base, headers, ctx, using, [["Email/get", {
            "accountId": account, "ids": [head["id"]], "fetchTextBodyValues": True, "fetchHTMLBodyValues": True,
            "properties": ["from", "subject", "receivedAt", "textBody", "htmlBody", "bodyValues"]}, "g"]])
        for m in full:
            values = m.get("bodyValues") or {}
            parts = (m.get("textBody") or []) or (m.get("htmlBody") or [])
            body = " ".join(str((values.get(p.get("partId")) or {}).get("value") or "") for p in parts)
            yield _epoch(m["receivedAt"]), frm, m.get("subject") or "", body


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


def peer_uid(fd: int = 0) -> Optional[int]:
    """The uid of the process on the other end of the unix socket on ``fd`` (SO_PEERCRED), or None when ``fd`` is
    not a unix socket."""
    try:
        conn = socket.socket(fileno=os.dup(fd))
    except OSError:
        return None
    with conn:
        if conn.family != socket.AF_UNIX:
            return None
        _, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        return uid


def parse_request(line: bytes) -> dict:
    """The one request shape, checked field by field; ValueError for anything else."""
    if len(line) > _MAX_REQUEST:
        raise ValueError("request too long")
    req = json.loads(line or b"{}")
    if not isinstance(req, dict) or set(req) - _FIELDS:
        raise ValueError(f"a request holds only {', '.join(sorted(_FIELDS))}")
    skip = req.get("skip") or []
    if not isinstance(skip, list) or not all(isinstance(h, str) and _SHA256.fullmatch(h) for h in skip):
        raise ValueError("skip is a list of sha256 hex digests")
    return {"address": str(req.get("address") or "").strip().lower(), "sender": str(req.get("sender") or "").strip(),
            "max_age_s": min(MAX_AGE_S, max(0, int(req.get("max_age_s") or MAX_AGE_S))),
            "wait_s": min(_MAX_WAIT_S, max(0, int(req.get("wait_s") or 0))), "skip": set(skip)}


def _audit(uid: Optional[int], address: str, sender: str, outcome: str) -> None:
    """One journal line per request. Values are JSON-quoted, so a request cannot forge a second line."""
    print(f"own-inbox-code audit: peer_uid={uid} address={json.dumps(address[:120])} "
          f"sender={json.dumps(sender[:120])} outcome={outcome}", file=sys.stderr, flush=True)


def _reply(obj: dict) -> int:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()
    return 0 if "candidates" in obj else 1


def serve(args: argparse.Namespace, line: bytes, uid: Optional[int]) -> int:
    """Answer one request: refusals first (wrong peer, malformed request, an inbox not on the command line, a vague
    sender), each before any mail server is contacted; then the newest unused code from the sender, waiting for it."""
    jmap, agentmail = _pairs(args.jmap, "--jmap"), _pairs(args.agentmail, "--agentmail")
    if uid != args.peer_uid:
        _audit(uid, "", "", "refused:peer")
        return _reply({"error": "this reader answers only its own user"})
    try:
        req = parse_request(line)
    except (ValueError, TypeError) as exc:
        _audit(uid, "", "", "refused:request")
        return _reply({"error": f"malformed request: {str(exc)[:200]}"})
    address, sender = req["address"], req["sender"]
    if address not in jmap and address not in agentmail:
        _audit(uid, address, sender, "refused:inbox")
        return _reply({"error": f"{address or 'no address'} is not one of this reader's inboxes"})
    if not sender_ok(sender):
        _audit(uid, address, sender, "refused:sender")
        return _reply({"error": "sender must be the address or the site's own domain the code comes from "
                                "(not a bare suffix or a free-mail domain)"})
    max_age, skip = req["max_age_s"], req["skip"]
    deadline = time.monotonic() + req["wait_s"]
    try:
        if address in jmap:
            messages, wait = _jmap_inbox(address, jmap[address], args.jmap_url.rstrip("/"), sender)
        else:
            messages, wait = _agentmail_inbox(address, agentmail[address], sender)
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
            elif wait(min(left, 15.0)):  # a mail that lands before the stream connects costs 15 s at most
                settle = 5
    except Exception as exc:  # the message never carries mail content: only the failure's kind and text
        _audit(uid, address, sender, f"error:{type(exc).__name__}")
        return _reply({"error": f"{type(exc).__name__}: {re.sub(r'[0-9]{4,}', '[digits]', str(exc))[:200]}"})
    _audit(uid, address, sender, "found" if found else "none")
    return _reply({"candidates": found})


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--peer-uid", type=int, required=True)
    ap.add_argument("--jmap", action="append", default=[])
    ap.add_argument("--jmap-url", default="https://127.0.0.1:8480")
    ap.add_argument("--agentmail", action="append", default=[])
    args = ap.parse_args(argv)
    return serve(args, sys.stdin.buffer.readline(_MAX_REQUEST + 1), peer_uid(0))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
