"""browser_vault_enter_code(source="own_inbox"): a one-time code sent to the agent's OWN mailbox, entered unseen.

The agent signs in to accounts that are its own (their codes go to its own inboxes, never the user's). The code is
read by the inbox reader service (``scripts/own_inbox_code.py``, installed by the machine's admin as a socket-activated
service under its own user, holding the mailbox credentials Hermes never sees) over the unix socket named in
``vault.own_inbox.socket``: one request line out, one reply line back, nothing in argv. The code is typed into the
page over the supervisor socket like every vault secret, and never reaches the tool result, a log line or the
transcript. Limits, all enforced here:

- only the inboxes listed in ``vault.own_inbox.addresses`` (the reader also refuses any inbox it holds no key for);
- only the NEWEST message holding a code, received in the last 10 minutes, and each message's code at most once
  per process, claimed before it is typed (a used code means "wait for the next mail", never "fall back to an older
  one" a resend has replaced);
- the agent names the ``sender`` (a From domain or address, never a substring), so another site's newer code is
  never the one typed;
- the page's origin must be bound to the saved login, listed in ``vault.own_inbox.origins``, or named by the agent
  in the call (``site``); every attempt writes one audit line with the origin and which of the three allowed it.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import socket
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

MAX_AGE_S = 600
_MAX_WAIT_S = 120
_CODE = re.compile(r"[0-9]{4,8}")  # what a reader may hand back: anything else is refused, never typed
_KEY = re.compile(r"[0-9a-f]{64}")
# Codes taken from a mail, keyed by the reader's key for that message (inbox, code, received_at) -> received_at: one message's code is typed once (a
# resend of the same code in a new mail is a new key), and is claimed before it is typed so two sessions never type
# the same one. Process-wide on purpose: the inboxes belong to the machine, not to a profile. A key is dropped once its
# mail is older than the reader's window, so the list holds minutes of mail, however long the gateway runs.
_used: Dict[str, float] = {}
_used_lock = threading.Lock()
_warned_reader: set = set()  # profile homes already told that vault.own_inbox.reader is retired


def own_inbox_config() -> Dict[str, Any]:
    from hermes_cli.config import load_config_readonly

    cfg = ((load_config_readonly().get("vault") or {}).get("own_inbox") or {})
    return cfg if isinstance(cfg, dict) else {}


def _list(value: Any) -> List[str]:
    """A YAML list of strings; a scalar (``addresses: a@b``) is one entry, never its characters."""
    items = value if isinstance(value, list) else [value] if value else []
    return [str(v).strip() for v in items if str(v).strip()]


def _warn_retired_reader(cfg: Dict[str, Any], effect: str) -> None:
    """Once per profile home: a config that still names the old reader command is told it is no longer read."""
    from hermes_constants import hermes_home_key

    home = hermes_home_key()
    if cfg.get("reader") and home not in _warned_reader:
        _warned_reader.add(home)
        logger.warning("vault.own_inbox.reader is no longer read (Hermes never runs a reader command; the inbox reader "
                       "is a service on vault.own_inbox.socket): %s. Remove the reader key.", effect)


def own_inbox_addresses(cfg: Optional[Dict[str, Any]] = None) -> List[str]:
    cfg = own_inbox_config() if cfg is None else cfg
    if not isinstance(cfg.get("socket"), str) or not cfg["socket"].strip():  # the reader service's unix socket
        _warn_retired_reader(cfg, "source=own_inbox is off")
        return []
    _warn_retired_reader(cfg, "the socket is used")
    return [a.lower() for a in _list(cfg.get("addresses"))]


def origin_basis(origin: str, item_origins: List[str], site: str, cfg: Dict[str, Any]) -> Optional[str]:
    """Why ``origin`` may take a code from the agent's inbox: ``item`` (the saved login is bound to it), ``config``
    (``vault.own_inbox.origins``) or ``named`` (the agent named this exact origin in the call); None = refused."""
    from agent.vault_store import normalize_origin

    def norm(value: str) -> str:
        try:
            return normalize_origin(value)
        except Exception:
            return ""

    if origin in item_origins:
        return "item"
    if origin in {norm(o) for o in _list(cfg.get("origins"))}:
        return "config"
    if site and norm(site) == origin:
        return "named"
    return None


def gate(cfg: Dict[str, Any], inbox: str, sender: str, origin: str, item_origins: List[str],
         site: str) -> Tuple[str, Optional[str], Optional[Dict[str, Any]]]:
    """``(inbox, basis, None)`` when this call may read a code from the agent's inbox, else ``(inbox, None, refusal)``.
    Nothing is read here; a refused origin is audited."""
    addresses = own_inbox_addresses(cfg)
    inbox = inbox.strip().lower() or (addresses[0] if addresses else "")
    if inbox not in addresses:
        return inbox, None, {"success": False, "error_type": "inbox_not_allowed", "error": (
            f"{inbox or 'No inbox'} is not one of your own inboxes (vault.own_inbox.addresses: "
            f"{', '.join(addresses) or 'none configured'}). Codes for the user's accounts come from the user: "
            "call again without source.")}
    if not sender.strip():
        return inbox, None, {"success": False, "error_type": "sender_required", "error": (
            "Pass sender=<the domain the site mails from, or its exact address> so only that site's mail is read. "
            "Nothing was read.")}
    basis = origin_basis(origin, item_origins, site, cfg)
    if basis is None:
        audit("refused", origin, None, inbox, sender)
        return inbox, None, {"success": False, "error_type": "origin_not_allowed", "error": (
            f"Refused: {origin} is not bound to a saved login or listed in vault.own_inbox.origins. If this code "
            "is for this exact site, name it with site=<its origin>; the call is audited. Nothing was read.")}
    return inbox, basis, None


def audit(outcome: str, origin: str, basis: Optional[str], inbox: str, sender: str) -> None:
    """One line per attempt. A site the agent vouched for itself (``named``) or a refusal is a WARNING, so it also
    lands in errors.log where a person looks."""
    level = logging.INFO if basis in ("item", "config") else logging.WARNING
    logger.log(level, "AUDIT vault own-inbox code %s: origin=%s basis=%s inbox=%s sender=%s",
               outcome, origin, basis or "-", inbox, sender or "-")


_MAX_REPLY = 65536


def _ask(sock_path: str, request: str, timeout: float) -> bytes:
    """One request line to the reader service, its whole reply back (it closes the connection after one answer)."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(timeout)
        conn.connect(sock_path)
        conn.sendall(request.encode() + b"\n")
        conn.shutdown(socket.SHUT_WR)
        reply = b""
        while len(reply) <= _MAX_REPLY:
            chunk = conn.recv(65536)
            if not chunk:
                break
            reply += chunk
        return reply


def _read(sock_path: str, inbox: str, sender: str, wait_s: int) -> Tuple[Optional[dict], Optional[str]]:
    """``(newest, None)`` with the reader's newest ``{"code", "received_at"}`` (None when it found none), or
    ``(None, error)``. The reader does the waiting (on the mail server's push where it has one) and skips codes
    already used. Its output is checked, never trusted: anything malformed is an error, not a crash."""
    with _used_lock:
        _forget_old_codes()
        skip = sorted(_used)
    request = json.dumps({"address": inbox, "sender": sender, "max_age_s": MAX_AGE_S, "wait_s": wait_s, "skip": skip})
    try:
        raw = _ask(sock_path, request, wait_s + 60)
    except OSError as exc:
        return None, f"the inbox reader could not be reached: {type(exc).__name__}"
    try:
        reply = json.loads(raw)
    except ValueError:
        reply = None
    if not isinstance(reply, dict) or "error" in reply:
        why = reply.get("error") if isinstance(reply, dict) else None
        return None, f"the inbox reader failed: {str(why or 'no usable reply')[:200]}"
    found = reply.get("candidates")
    newest = found[0] if isinstance(found, list) and found else None
    if newest is None:
        return None, None
    try:
        code, received_at, key = str(newest["code"]), float(newest["received_at"]), str(newest["key"])
    except (TypeError, KeyError, ValueError):
        return None, "the inbox reader failed: a reply without a code, a numeric received_at and a key"
    if not _CODE.fullmatch(code):
        return None, "the inbox reader failed: what it returned is not a 4-8 digit code"
    if not _KEY.fullmatch(key):
        return None, "the inbox reader failed: its key is not a sha256 digest"
    return {"code": code, "received_at": received_at, "key": key}, None


def fetch_code(inbox: str, sender: str, wait_s: int,
               cfg: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """``(code, None, claim)``: the newest unused code in ``inbox`` from the last 10 minutes, waiting up to ``wait_s``
    for one to arrive, already claimed under the reader's key for that message (no other session gets it;
    ``release(claim)`` if it was certainly not typed); ``(None, error, None)`` otherwise. The code is returned to the
    caller only, never logged."""
    deadline = time.monotonic() + max(0, min(int(wait_s), _MAX_WAIT_S))
    while True:
        newest, err = _read(str(cfg.get("socket") or "").strip(), inbox, sender,
                            int(max(0.0, deadline - time.monotonic())))
        if err or newest is None or time.time() - newest["received_at"] > MAX_AGE_S:
            return None, err, None
        with _used_lock:
            if newest["key"] not in _used:
                _used[newest["key"]] = newest["received_at"]
                return newest["code"], None, newest["key"]
        # another session claimed this mail while we read it; the reader skips it from now on
        if deadline - time.monotonic() <= 1:
            return None, None, None
        time.sleep(1)


def release(claim: Optional[str]) -> None:
    """Give back a claimed code that was not typed (the fill failed), so the next call can use it."""
    with _used_lock:
        _used.pop(claim or "", None)


def _forget_old_codes() -> None:
    """Drop keys whose mail the reader can no longer return (call with ``_used_lock`` held)."""
    cutoff = time.time() - MAX_AGE_S - _MAX_WAIT_S
    for h in [h for h, at in _used.items() if at < cutoff]:
        del _used[h]


OWN_INBOX_PROPERTIES = {
    "source": {"type": "string", "enum": ["user", "own_inbox"],
               "description": ("own_inbox: the code was sent to one of YOUR OWN inboxes (an account you hold, signed up "
                               "with your own address). Hermes reads the newest code from that inbox and enters it; you "
                               "never see it. Never use it for the user's accounts: their codes come from them (omit "
                               "source).")},
    "inbox": {"type": "string", "description": "Which of your own inboxes the code went to. Default: the first one."},
    "sender": {"type": "string", "description": ("Required with own_inbox: the domain the site mails from (matches that "
                                                 "domain and its subdomains) or the exact sender address.")},
    "site": {"type": "string", "description": ("The site's origin (https://host) when no saved login is bound to it: you "
                                               "vouch the code is for this exact site, and the call is audited.")},
    "wait_s": {"type": "integer", "description": f"Seconds to wait for the mail to arrive (default 60, max {_MAX_WAIT_S})."},
}
