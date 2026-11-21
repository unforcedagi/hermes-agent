"""browser_vault_enter_code(source="own_inbox"): a one-time code sent to the agent's OWN mailbox, entered unseen.

The agent signs in to accounts that are its own (their codes go to its own inboxes, never the user's). The code is
read by the configured reader command (``scripts/own_inbox_code.py``: the request goes in on stdin, the code comes
back on stdout, nothing in argv), typed into the page over the supervisor socket like every vault secret, and never
reaches the tool result, a log line or the transcript. Limits, all enforced here:

- only the inboxes listed in ``vault.own_inbox.addresses`` (the reader refuses any inbox it holds no key for);
- only the NEWEST message holding a code, received in the last 10 minutes, and each code at most once per process
  (a used code means "wait for the next mail", never "fall back to an older one" a resend has replaced);
- the agent names the ``sender`` (part of the From address), so another site's newer code is never the one typed;
- the page's origin must be bound to the saved login, listed in ``vault.own_inbox.origins``, or named by the agent
  in the call (``site``); every attempt writes one audit line with the origin and which of the three allowed it.
"""

from __future__ import annotations

import hashlib
import json
import logging
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

MAX_AGE_S = 600
_POLL_S = 5
_MAX_WAIT_S = 120
_used: set = set()  # sha256 of codes already entered: a stale code is never typed twice


def own_inbox_config() -> Dict[str, Any]:
    from hermes_cli.config import load_config_readonly

    cfg = ((load_config_readonly().get("vault") or {}).get("own_inbox") or {})
    return cfg if isinstance(cfg, dict) else {}


def own_inbox_addresses(cfg: Optional[Dict[str, Any]] = None) -> List[str]:
    cfg = own_inbox_config() if cfg is None else cfg
    if not cfg.get("reader"):
        return []
    return [str(a).strip().lower() for a in (cfg.get("addresses") or []) if str(a).strip()]


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
    if origin in {norm(str(o)) for o in (cfg.get("origins") or [])}:
        return "config"
    if site and norm(site) == origin:
        return "named"
    return None


def audit(outcome: str, origin: str, basis: Optional[str], inbox: str, sender: str) -> None:
    logger.info("AUDIT vault own-inbox code %s: origin=%s basis=%s inbox=%s sender=%s",
                outcome, origin, basis or "-", inbox, sender or "-")


def _read(reader: List[str], inbox: str, sender: str) -> Tuple[Optional[dict], Optional[str]]:
    """``(newest, None)`` with the reader's newest ``{"code", "received_at"}`` (None when it found none), or
    ``(None, error)``. Reader output is checked, never trusted: anything malformed is an error, not a crash."""
    request = json.dumps({"address": inbox, "sender": sender, "max_age_s": MAX_AGE_S})
    try:
        proc = subprocess.run(reader, input=request, capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"the inbox reader could not run: {type(exc).__name__}"
    try:
        reply = json.loads(proc.stdout or "")
    except ValueError:
        reply = None
    if proc.returncode != 0 or not isinstance(reply, dict) or "error" in reply:
        why = reply.get("error") if isinstance(reply, dict) else None
        return None, f"the inbox reader failed: {str(why or f'exit {proc.returncode}, no usable reply')[:200]}"
    found = reply.get("candidates")
    newest = found[0] if isinstance(found, list) and found else None
    if newest is None:
        return None, None
    try:
        return {"code": str(newest["code"]), "received_at": float(newest["received_at"])}, None
    except (TypeError, KeyError, ValueError):
        return None, "the inbox reader failed: a reply without a code and a numeric received_at"


def fetch_code(inbox: str, sender: str, wait_s: int, cfg: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """``(code, None)``: the newest unused code in ``inbox`` from the last 10 minutes, waiting up to ``wait_s`` for
    one to arrive; ``(None, error)`` otherwise. The code is returned to the caller only, never logged."""
    reader = [str(part) for part in (cfg.get("reader") or [])]
    deadline = time.monotonic() + max(0, min(int(wait_s), _MAX_WAIT_S))
    while True:
        newest, err = _read(reader, inbox, sender)
        if err:
            return None, err
        if newest and newest["code"] and time.time() - newest["received_at"] <= MAX_AGE_S \
                and hashlib.sha256(newest["code"].encode()).hexdigest() not in _used:
            return newest["code"], None
        if time.monotonic() + _POLL_S > deadline:
            return None, None
        time.sleep(_POLL_S)


def mark_used(code: str) -> None:
    _used.add(hashlib.sha256(code.encode()).hexdigest())


OWN_INBOX_PROPERTIES = {
    "source": {"type": "string", "enum": ["user", "own_inbox"],
               "description": ("own_inbox: the code was sent to one of YOUR OWN inboxes (an account you hold, signed up "
                               "with your own address). Hermes reads the newest code from that inbox and enters it; you "
                               "never see it. Never use it for the user's accounts: their codes come from them (omit "
                               "source).")},
    "inbox": {"type": "string", "description": "Which of your own inboxes the code went to. Default: the first one."},
    "sender": {"type": "string", "description": ("Required with own_inbox: part of the sender's address (usually the "
                                                 "site's domain), so only that site's mail is read.")},
    "site": {"type": "string", "description": ("The site's origin (https://host) when no saved login is bound to it: you "
                                               "vouch the code is for this exact site, and the call is audited.")},
    "wait_s": {"type": "integer", "description": f"Seconds to wait for the mail to arrive (default 60, max {_MAX_WAIT_S})."},
}
