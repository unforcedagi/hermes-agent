#!/usr/bin/env python3
"""Read the newest one-time codes from the agent's OWN mailboxes, for browser_vault_enter_code(source="own_inbox").

Hermes runs this as the ``vault.own_inbox.reader`` command (usually through ``sudo -n python3 -I``, since mailbox
credentials are root-only). The inboxes it may read are named on its own command line, each with the credential
that opens it; any other address is refused, whatever Hermes asks for:

  own_inbox_code.py --jmap ADDRESS=SECRET_FILE [--jmap-url URL] --agentmail ADDRESS=CURL_CONFIG

  --jmap       a JMAP server account (Stalwart): SECRET_FILE holds "user:password" or just the password.
  --agentmail  an AgentMail inbox: CURL_CONFIG is a curl config with the API's Authorization header.

Request on stdin: {"address": "...", "sender": "<substring of From, optional>", "max_age_s": 600}
Reply on stdout:  {"candidates": [{"code": "...", "received_at": <epoch>, "from": "..."}]}: the newest message
                  that holds a code, or none; or {"error": "..."} with exit status 1. Nothing else is ever printed: no body, link or subject.
Stdlib only, so it runs under ``python3 -I``.
"""
from __future__ import annotations

import argparse
import base64
import html
import json
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Iterable, List, Optional

MAX_AGE_S = 600  # a hard ceiling: older mail never yields a code, whatever the request says
# Words that name a code. Not "sign in" / "security" / "confirm": a sign-in alert's date or a user number follows those.
_KEYWORDS = re.compile(r"\b(?:code|passcode|verification|one[- ]time|otp|pin)\b", re.IGNORECASE)
# 4-8 digits, or 3+3 / 4+4 split by a space or dash; never part of a longer token, URL, date, time or price.
_CODE = re.compile(r"(?<![\w/#.$€£:-])(\d{3,4}[ -]\d{3,4}|\d{4,8})(?![\w/%:-]|\.\d)")
_NEAR = 80  # characters after a keyword that still count as "the code it names"


def _flat(text: str) -> str:
    if "<" in text and ">" in text:
        text = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", text)
        text = html.unescape(re.sub(r"<[^>]+>", " ", text))
    return re.sub(r"\s+", " ", text)


def extract_code(subject: str, body: str) -> Optional[str]:
    """The one code this message is about, or None when there is none or it is ambiguous.

    A code shortly after a keyword ("code", "verification", ...) wins, subject first. Without a keyword the message
    must hold exactly one distinct 6-8 digit number. Split codes ("123 456") come back joined."""
    for text in (_flat(subject or ""), _flat(body or "")):
        for kw in _KEYWORDS.finditer(text):
            m = _CODE.search(text, kw.end())  # the whole rest of the text: a window cut would truncate a long number
            if m and m.start() <= kw.end() + _NEAR:
                return re.sub(r"[ -]", "", m.group(1))
    bare = {re.sub(r"[ -]", "", m.group(1)) for m in _CODE.finditer(_flat(subject or "") + " \n " + _flat(body or ""))}
    bare = {c for c in bare if 6 <= len(c) <= 8}
    return bare.pop() if len(bare) == 1 else None


def _epoch(stamp: str) -> float:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()


def _get(url: str, headers: dict, body: Optional[dict] = None, context=None) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                 headers={**headers, "Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, context=context, timeout=30).read())


def _jmap_messages(address: str, secret_file: str, base: str, since: float) -> Iterable[tuple]:
    raw = open(secret_file, encoding="utf-8").read().strip()
    if "@" not in raw.partition(":")[0]:  # a bare password (it may hold a colon itself)
        raw = f"{address}:{raw}"
    headers = {"Authorization": "Basic " + base64.b64encode(raw.encode()).decode()}
    ctx = ssl._create_unverified_context() if urllib.parse.urlsplit(base).hostname in ("127.0.0.1", "localhost") else None
    session = _get(base + "/jmap/session", headers, context=ctx)
    account = session["primaryAccounts"]["urn:ietf:params:jmap:mail"]
    using = {"using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"]}
    boxes = _get(base + "/jmap/", headers, {**using, "methodCalls": [["Mailbox/get", {"accountId": account,
                 "properties": ["role"]}, "m"]]}, context=ctx)["methodResponses"][0][1]["list"]
    outgoing = [b["id"] for b in boxes if b.get("role") in ("sent", "drafts", "trash")]  # mail the agent wrote or binned
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
        if at < since or "sent" in (msg.get("labels") or []) or sender.lower() not in str(msg.get("from") or "").lower():
            continue
        full = _get(inbox + "/messages/" + urllib.parse.quote(msg["message_id"], safe=""), headers)
        body = full.get("extracted_text") or full.get("text") or full.get("html") or ""
        yield at, str(msg.get("from") or ""), msg.get("subject") or "", body


def candidates(messages: Iterable[tuple], sender: str, since: float) -> List[dict]:
    """The newest message (``messages`` come newest first) from ``sender`` since ``since`` that holds a code."""
    for at, frm, subject, body in messages:
        if at < since or (sender and sender.lower() not in frm.lower()):
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
        since = time.time() - min(MAX_AGE_S, max(0, int(req.get("max_age_s") or MAX_AGE_S)))
        if address in jmap:
            found = candidates(_jmap_messages(address, jmap[address], args.jmap_url.rstrip("/"), since), sender, since)
        elif address in agentmail:
            found = candidates(_agentmail_messages(address, agentmail[address], since, sender), sender, since)
        else:
            print(json.dumps({"error": f"{address or 'no address'} is not one of this reader's inboxes"}))
            return 1
    except Exception as exc:  # the message never carries mail content: only the failure's kind and text
        print(json.dumps({"error": f"{type(exc).__name__}: {re.sub(r'[0-9]{4,}', '[digits]', str(exc))[:200]}"}))
        return 1
    print(json.dumps({"candidates": found}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
