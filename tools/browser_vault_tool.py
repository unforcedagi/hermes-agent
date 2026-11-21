#!/usr/bin/env python3
"""Vault-backed model-blind browser autofill tools.

Two model-facing tools, gated on the local vault having at least one item
(zero schema cost otherwise, same ``check_fn`` pattern as the Home Assistant
tools):

- ``browser_vault_list``  → handles + metadata (for logins this includes the
  identifier — it is NOT a secret; the agent types it itself). Passwords are
  never returned.
- ``browser_vault_fill``  → server-side fill of the CURRENT page from a vault
  handle: the password field for logins, card fields for payment items (after
  the user confirms), address fields for address items. The secret is
  resolved locally, the page origin must EXACTLY match the item's bound
  origin (pre-checked AND re-asserted synchronously inside the fill script),
  the field is chosen by the ported login-control classifier, injection runs
  exclusively over the supervisor CDP WebSocket (never argv), and the tool
  result reports only ``{filled_fields, kind, origin, success}`` — the
  password never appears in tool results, logs, or the session DB, and its
  exact bytes are registered with the browser-result redaction boundary so
  no later browser tool call can echo them back to the model.

Ported design from Merit-Systems/OpenInstinct (MIT): opaque-handle vault
autofill (kernel-login-autofill.ts / fill_from_vault.ts).
"""

from __future__ import annotations

import json
import re
import secrets
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Availability check
# ---------------------------------------------------------------------------

def _check_vault_available() -> bool:
    """Schema-gate: the vault tools ride with the browser. An empty vault still needs
    browser_vault_save_login so the agent can offer to remember a login the first time it meets a
    form; hiding the tools until an item exists meant nobody ever discovered the feature."""
    from tools.browser_tool_install import check_browser_requirements
    from tools.browser_use_cli import is_browser_use_cli_mode
    # check_browser_requirements() is False by design in Browser Use mode (browser_exec replaces the
    # built-in surface); the vault serves both stacks.
    return bool(is_browser_use_cli_mode() or check_browser_requirements())


# ---------------------------------------------------------------------------
# JS evaluation plumbing (server-side; results never carry secret values)
# ---------------------------------------------------------------------------

def _eval_js(task_id: str, expression: str) -> Dict[str, Any]:
    """Evaluate NON-SECRET JS on the current page (inspection, origin reads).

    Prefers the supervisor's persistent CDP WebSocket, falls back to the
    agent-browser CLI ``eval`` command. Never use this for expressions that
    embed secret values — the fallback places the expression in subprocess
    argv. Use :func:`_eval_js_secret` for secret-bearing expressions. In
    Browser Use mode there is no fallback: the agent-browser session is a
    different browser from the one browser_exec drives.
    """
    try:
        from tools.browser_supervisor import SUPERVISOR_REGISTRY

        supervisor = SUPERVISOR_REGISTRY.get(task_id)
        if supervisor is not None:
            sup = supervisor.evaluate_runtime(expression)
            if sup.get("ok"):
                return {"success": True, "result": sup.get("result")}
            err = str(sup.get("error") or "")
            if "supervisor" not in err.lower():
                return {"success": False, "error": err}
    except ImportError:
        pass
    except Exception as exc:  # pragma: no cover — defensive
        logger.debug("vault fill: supervisor eval unavailable (%s)", exc)
    if _browser_use_mode():
        return {"success": False, "error": "the vault has no supervised connection to the browser_exec session"}

    from tools.browser_tool import _last_session_key
    from tools.browser_tool_session import _run_browser_command

    effective = _last_session_key(task_id)
    result = _run_browser_command(effective, "eval", [expression])
    if not result.get("success"):
        return {"success": False, "error": result.get("error", "eval failed")}
    return {"success": True, "result": result.get("data", {}).get("result")}


def _ensure_supervisor(task_id: str):
    """The supervisor for ``task_id``, attaching one on demand for a LOCAL built-in browser session.

    Cloud/CDP-override sessions and browser_exec attach their supervisor when the session is created;
    a local agent-browser ``--session`` has no ``cdp_url`` of its own, so nothing did. Ask the daemon
    for the packaged Chromium's endpoint (``get cdp-url``: same daemon, same reaper) and attach.
    Returns None when no endpoint is reachable; the fill then refuses rather than touching argv."""
    from tools.browser_supervisor import SUPERVISOR_REGISTRY

    supervisor = SUPERVISOR_REGISTRY.get(task_id)
    if supervisor is not None or _browser_use_mode():  # agent-browser's browser is not browser_exec's
        return supervisor
    from tools.browser_tool import _last_session_key
    from tools.browser_tool_cdp import _get_dialog_policy_config, _resolve_cdp_override
    from tools.browser_tool_session import _run_browser_command

    res = _run_browser_command(_last_session_key(task_id), "get", ["cdp-url"])
    cdp_url = str(((res or {}).get("data") or {}).get("cdpUrl") or "") if (res or {}).get("success") else ""
    if not cdp_url:
        return None
    policy, timeout_s = _get_dialog_policy_config()
    try:
        return SUPERVISOR_REGISTRY.get_or_start(task_id=task_id, cdp_url=_resolve_cdp_override(cdp_url),
                                                dialog_policy=policy, dialog_timeout_s=timeout_s)
    except Exception as exc:
        logger.debug("vault fill: supervisor attach to local session failed (%s)", exc)
        return None


def _eval_js_secret(task_id: str, expression: str) -> Dict[str, Any]:
    """Evaluate a SECRET-BEARING JS expression. Supervisor CDP-WS only.

    Fails closed: there is deliberately NO fallback to the agent-browser CLI
    ``eval`` path, because that places the expression — and therefore the
    credential bytes — in subprocess argv, visible to any process listing.
    When no supervisor session is available the caller gets a typed refusal
    (``error_type='supervisor_required'``) and nothing is written.
    """
    try:
        supervisor = _ensure_supervisor(task_id)
    except Exception as exc:
        logger.debug("vault fill: supervisor unavailable (%s)", exc)
        supervisor = None

    if supervisor is None:
        return {
            "success": False,
            "error_type": "supervisor_required",
            "error": (
                "Vault fill requires the supervised browser session (direct "
                "CDP WebSocket). The fallback eval path would place the "
                "credential in subprocess argv, so it is never used for "
                "secrets. Start the browser through the Hermes-managed "
                "session and retry."
            ),
        }

    sup = supervisor.evaluate_runtime(expression)
    if sup.get("ok"):
        return {"success": True, "result": sup.get("result")}
    return {
        "success": False,
        "error_type": "supervisor_required"
        if "supervisor" in str(sup.get("error") or "").lower()
        else "eval_failed",
        "error": str(sup.get("error") or "eval failed"),
    }


def _inspect_controls(task_id: str, nonce: str, include_hidden: bool) -> tuple[Optional[list], str]:
    """``(controls, "")`` for the page's inputs, stamped with ``nonce``; ``(None, error)`` when unreadable (any stamps
    the script managed to set are taken off again)."""
    from agent.vault_login_classifier import LoginControl, build_inspection_js

    inspect = _eval_js(task_id, build_inspection_js(nonce, include_hidden=include_hidden))
    raw = _parse_json_result(inspect.get("result")) if inspect.get("success") else None
    if isinstance(raw, str):
        raw = _parse_json_result(raw)
    if not isinstance(raw, list):
        if inspect.get("success"):
            _unstamp(task_id, {})
        return None, str(inspect.get("error") or "no usable controls")[:200]
    return [LoginControl.from_dict(r) for r in raw if isinstance(r, dict)], ""


def _unstamp(task_id: str, refusal: Dict[str, Any]) -> str:
    """A refusal after the page was inspected: take the inspection's stamps off the inputs first."""
    from agent.vault_login_classifier import build_unstamp_js

    _eval_js(task_id, build_unstamp_js())
    return json.dumps(refusal)


def _parse_json_result(raw: Any) -> Any:
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return raw
    return raw


def _browser_use_mode() -> bool:
    from tools.browser_use_cli import is_browser_use_cli_mode

    return is_browser_use_cli_mode()


def _page_origin(task_id: str, where: str = "") -> tuple[Optional[str], Optional[Dict[str, Any]]]:
    """``(origin, None)`` for the supervised tab, or ``(None, refusal)``. Only http(s) pages have an origin a login
    can be bound to or filled on: about:blank, chrome://new-tab-page, data:, file: and the like are refused here,
    before anyone is asked for anything."""
    from urllib.parse import urlsplit

    res = _eval_js(task_id, "window.location.href")
    if not res.get("success"):
        return None, {"success": False, "error": f"Could not read the address of the browser tab{where}: "
                                                 f"{str(res.get('error') or 'eval failed')[:200]}"}
    href = str(res.get("result") or "").strip().strip('"').strip("'")
    scheme = urlsplit(href).scheme.lower()
    if scheme not in ("http", "https"):
        shown = href.split("?", 1)[0].split(",", 1)[0][:60] or "an empty page"
        return None, {"success": False, "error_type": "not_a_website",
                      "error": (f"Refused: the browser tab{where} is on {shown}, not a website (http/https). Open the "
                                "site's login page in that tab first. Nothing was asked, saved or filled.")}
    try:
        from agent.vault_store import normalize_origin

        return normalize_origin(href), None
    except Exception:
        return None, {"success": False, "error": f"Could not read an origin from the browser tab{where}."}


def _pin_exec_tab(task_id: str, session: str) -> tuple[str, Optional[Dict[str, Any]]]:
    """Browser Use mode: point the supervisor at the exact tab browser_exec's daemon is on in ``session`` (empty =
    the session this task drove last, else the default one). Returns ``(where, None)`` with ``where`` naming the
    session for messages, or ``("", refusal)``. The supervisor is keyed by task, and a browser_exec in another session
    re-points it, so every vault call pins again rather than trusting where it was left."""
    from tools.browser_supervisor import SUPERVISOR_REGISTRY
    from tools.browser_use_cli import driven_sessions, exec_current_tab, last_exec_session

    name = session.strip() if session else (last_exec_session(task_id) or "")
    where = f" in browser session {name!r}" if name else " in the default browser session"
    if name not in driven_sessions(task_id):  # never start a browser (or move the default) on a vault call
        return "", {"success": False, "error_type": "no_browser_session",
                    "error": (f"No page is open{where} in this conversation. Open the login page with the browser "
                              "first, in the session you pass here.")}
    tab, err = exec_current_tab(name, task_id)
    if tab is None:
        return "", {"success": False, "error_type": "no_browser_session",
                    "error": f"Could not find the tab{where}: {err}"}
    supervisor = SUPERVISOR_REGISTRY.get(task_id)
    if supervisor is None:
        return "", {"success": False, "error_type": "supervisor_required",
                    "error": (f"The browser{where} has no CDP endpoint Hermes can attach to (Browser Use cloud), so "
                              "the vault cannot fill it without putting the secret in process arguments.")}
    focused = supervisor.focus_target(tab["targetId"])
    if not focused.get("ok"):
        return "", {"success": False, "error": f"Could not attach to the tab{where}: {focused.get('error')}"}
    return where, None


def _locate_page(task_id: str, session: str, kind: str) -> tuple[str, Optional[str], Optional[Dict[str, Any]]]:
    """``(where, origin, refusal)`` for the page a ``kind`` vault call acts on. Browser Use mode: the exact tab
    browser_exec is on in the session. Built-in tools: the open tab holding a ``kind`` form, else the current one."""
    if _browser_use_mode():
        where, refusal = _pin_exec_tab(task_id, session)
        if refusal:
            return "", None, refusal
    else:
        where = ""
        _focus_bound_origin(task_id, "", kind)
    origin, refusal = _page_origin(task_id, where)
    return where, origin, refusal


# Per kind: a JS probe that is truthy on a tab holding the form this kind fills (open shadow roots included).
def _tab_probe(selector: str) -> str:
    from agent.vault_login_classifier import build_probe_js

    return build_probe_js(selector)


_TAB_PROBES = {
    "login": _tab_probe("input[type=password]"),
    "payment": _tab_probe("input[autocomplete^=cc-], [name*=card i], [placeholder*=card i], [name*=cvc i], [name*=cvv i]"),
    "address": _tab_probe("input[autocomplete^=address-], [autocomplete=postal-code], [name*=address i], [name*=zip i], [name*=postal i]"),
}


def _focus_bound_origin(task_id: str, origin: str, kind: str) -> Optional[str]:
    """Point the supervisor's page session at the open tab on ``origin`` that holds a ``kind`` form
    (browser_exec sessions open their own tabs, so the tab the supervisor attached to first is rarely the
    login page). Returns the origin when a tab was focused, else None (caller falls back to the current page)."""
    try:
        supervisor = _ensure_supervisor(task_id)
    except Exception:
        supervisor = None
    if supervisor is None:
        return None
    focused = supervisor.focus_page(origin, accept=_TAB_PROBES.get(kind))
    return (origin or focused.get("url")) if focused.get("ok") else None


# ---------------------------------------------------------------------------
# Identifiers that read like passwords
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"[^@\s]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"\+[\d\s().-]{7,20}|\(?\d[\d\s().-]{9,19}")
# What a chosen username looks like: letters, then letters and . _ -, then at most two digits (aaron_g, john.smith2).
_PLAIN_USERNAME_RE = re.compile(r"[A-Za-z][A-Za-z._-]{0,63}\d{0,2}")
IDENTIFIER_HIDDEN = "(hidden: it looks like a password)"


def identifier_type(identifier: str) -> str:
    """The vault's ``identifier_type`` for a username the agent or the user gave."""
    return "email" if "@" in identifier else ("phone" if identifier.lstrip("+").isdigit() else "username")


def identifier_looks_like_password(identifier: str, password: str = "") -> bool:
    """True when what the user gave as a username reads like a password, so it must never be echoed to the model.

    A user who types their password into the username field (the 11-02 Buzz card mix-up) would otherwise see it
    returned as agent-visible metadata. Shown: an email, a phone number, or a plain username (letters with . _ -
    and at most two trailing digits, not mixing lower, upper and digits). Anything else, and anything that matches
    the password, is hidden. Errs towards hiding: a hidden username costs the agent one question, a shown password
    costs the account."""
    ident = (identifier or "").strip()
    if not ident:
        return False
    if password and (ident == password or (len(ident) >= 6 and (ident in password or password in ident))):
        return True
    if _EMAIL_RE.fullmatch(ident) or (_PHONE_RE.fullmatch(ident) and sum(c.isdigit() for c in ident) >= 7):
        return False
    if not _PLAIN_USERNAME_RE.fullmatch(ident):
        return True
    classes = sum(bool(re.search(p, ident)) for p in (r"[a-z]", r"[A-Z]", r"\d"))
    return len(ident) >= 8 and classes == 3


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def browser_vault_list() -> str:
    """List login handles + metadata across every enabled backend. Passwords are never included.

    A locked external manager contributes no items; instead it is reported under ``locked`` so the
    agent knows to call browser_vault_fill (which prompts the user to unlock) or tell the user.
    """
    from agent.vault_backends import enabled_backends
    from agent.vault_backends.unlock import can_prompt_here

    items, locked, errors = [], [], []
    for backend in enabled_backends():
        if backend.needs_unlock and not backend.is_unlocked():
            locked.append({"backend": backend.name, "display_name": backend.display_name,
                           "unlock": "browser_vault_unlock" if can_prompt_here() else "unavailable_in_this_session"})
            continue
        try:
            metas = backend.list_items()
        except Exception as exc:
            errors.append({"backend": backend.name, "error": str(exc)[:200]})
            continue
        for meta in metas:
            entry = {"handle": meta.id, "backend": backend.name, "label": meta.label, "kind": meta.kind,
                     "origin": meta.origin, "available": meta.kind == "login" or bool(meta.origin)}
            if len(meta.allowed_origins) > 1:
                entry["allowed_origins"] = list(meta.allowed_origins)
            if meta.has_otp or backend.needs_unlock:
                entry["two_factor"] = "automatic" if meta.has_otp else "automatic if the manager stores a TOTP seed, else the user is asked"
            if meta.identifier and not meta.generated and identifier_looks_like_password(meta.identifier):
                entry["identifier"], entry["identifier_masked"] = IDENTIFIER_HIDDEN, True
            elif meta.identifier:
                entry["identifier"] = meta.identifier
                entry["identifier_type"] = meta.identifier_type
            items.append(entry)
    out: Dict[str, Any] = {"success": True, "items": items}
    if not items:
        out["hint"] = ("No saved logins. On a login page, call browser_vault_save_login to ask the user to save one. "
                       "Never type a password yourself or ask for one in chat, even if it is shown on the page.")
    if locked:
        out["locked"] = locked
    if errors:
        out["errors"] = errors
    return json.dumps(out, ensure_ascii=False)


def browser_vault_unlock(backend_name: str) -> str:
    """Ask the user (via the surface's masked prompt) to unlock an external manager for this session."""
    from agent.vault_backends import enabled_backends
    from agent.vault_backends.unlock import can_prompt_here, get_unlock_prompt_callback

    backend = next((b for b in enabled_backends() if b.name == backend_name and b.needs_unlock), None)
    if backend is None:
        return json.dumps({"success": False, "error": f"No unlockable vault backend named {backend_name!r}."})
    if backend.is_unlocked():
        return json.dumps({"success": True, "backend": backend.name, "already_unlocked": True})
    if not can_prompt_here():
        return json.dumps({"success": False, "error_type": "unlock_unavailable",
                           "error": (f"{backend.display_name} is locked and this session cannot prompt for the "
                                     "master password (headless/cron/API). Unlock it from an interactive Hermes "
                                     "session or the Desktop app first.")})
    prompt = get_unlock_prompt_callback()
    master = prompt(backend.name, backend.display_name) if prompt else ""
    if not master:
        return json.dumps({"success": False, "error_type": "unlock_cancelled",
                           "error": f"The user declined to unlock {backend.display_name}."})
    try:
        backend.unlock(master)  # type: ignore[attr-defined]
    except Exception as exc:
        return json.dumps({"success": False, "error_type": "unlock_failed", "error": str(exc)[:300]})
    finally:
        del master
    return json.dumps({"success": True, "backend": backend.name})


def browser_vault_save_login(label: str = "", task_id: Optional[str] = None, session: str = "") -> str:
    """Ask the user (masked prompt on their surface) for the login of the CURRENT page, store it in the local
    vault bound to that origin, and fill the password at once. The values never enter the conversation."""
    from agent.vault_backends.unlock import can_prompt_here, get_save_login_prompt_callback
    from agent.vault_store import get_vault_store

    effective_task_id = task_id or "default"
    if _browser_use_mode():  # the save and its fill act in ONE session, even if another runs in between
        from tools.browser_use_cli import last_exec_session
        session = session.strip() or last_exec_session(effective_task_id) or ""
    _, origin, refusal = _locate_page(effective_task_id, session, "login")
    if refusal:
        return json.dumps(refusal)
    prompt = get_save_login_prompt_callback()
    if prompt is None or not can_prompt_here():
        return json.dumps({"success": False, "error_type": "prompt_unavailable",
                           "error": (f"This session cannot ask the user for a login (headless/cron/API). Tell them to run "
                                     f"`hermes vault add` or use Desktop → Settings → Passwords & Logins for {origin}.")})
    host = origin.split("://", 1)[-1]
    site = label.strip() or host
    answer = prompt(origin, host)  # the prompt names the site by host: the user recognises URLs, not agent labels
    if not answer or not answer.get("password") or not answer.get("identifier"):
        return json.dumps({"success": False, "error_type": "save_declined",
                           "error": "The user chose not to save a login for this site. Do not ask again this turn."})
    identifier = str(answer["identifier"]).strip()
    # The same value twice, or an email in the password field: the answers went into the wrong fields.
    if identifier == str(answer["password"]).strip() or _EMAIL_RE.fullmatch(str(answer["password"]).strip()):
        answer.clear()
        return json.dumps({"success": False, "error_type": "identifier_is_password",
                           "error": ("The username and password the user entered look mixed up (the same value twice, "
                                     "or an email in the password field). Nothing was saved. Ask them to save it again "
                                     "with their username or email in the first field and the password in the second; "
                                     "never ask for either in chat.")})
    masked = identifier_looks_like_password(identifier, str(answer["password"]))
    id_type = identifier_type(identifier)
    try:
        meta = get_vault_store().add_item("login", site, {"identifier_type": id_type, "identifier": identifier,
                                                        "password": str(answer["password"])}, origin=origin)
    except Exception as exc:
        return json.dumps({"success": False, "error_type": "save_failed", "error": str(exc)[:200]})
    finally:
        answer.clear()
    filled = json.loads(browser_vault_fill(meta.id, task_id=effective_task_id, session=session))
    out = {"success": True, "handle": meta.id, "origin": origin, "identifier": identifier,
           "identifier_type": id_type, "fill": filled,
           "next": "Type the identifier into the username field if the form has one, then submit."}
    if masked:
        del out["identifier_type"]  # even "email" says something about a hidden value
        out.update(identifier=IDENTIFIER_HIDDEN, identifier_masked=True, next=(
            "The username the user entered looks like a password, so it is hidden from you. Do not type it or ask "
            "for it in chat. Tell the user the saved username may be their password by mistake; they can delete "
            "the login (Settings → Passwords & Logins or `hermes vault`) and save it again."))
    del identifier
    return json.dumps(out, ensure_ascii=False)


_TAB_PROBES["otp"] = _tab_probe("input[autocomplete=one-time-code], input[name*=otp i], input[name*=code i], "
                                "input[id*=otp i], input[id*=code i], input[name*=totp i], input[aria-label*=code i]")


def browser_vault_enter_code(handle: str = "", task_id: Optional[str] = None, session: str = "", source: str = "",
                             inbox: str = "", sender: str = "", site: str = "", wait_s: int = 60) -> str:
    """Second factor: fill the one-time code the CURRENT page asks for. If the saved login (``handle``) has an
    authenticator seed, the code is minted server-side and nobody is asked; ``source="own_inbox"`` reads it from the
    agent's own mailbox (``browser_vault_tool_own_inbox``); otherwise the user is prompted on their surface for the
    code their phone/email/app shows. The code goes into the page over the supervisor socket and never enters the
    conversation."""
    from agent.redact import register_vault_redaction_value
    from agent.vault_backends import backend_for_handle
    from agent.vault_backends.unlock import can_prompt_here, get_code_prompt_callback
    from agent.vault_login_classifier import LoginControl, build_fill_js, build_inspection_js, build_otp_fills, classify_otp_controls

    effective_task_id = task_id or "default"
    from_inbox, named_site = source == "own_inbox", site
    _, origin, refusal = _locate_page(effective_task_id, session, "otp")
    if refusal:
        return json.dumps(refusal)
    site = origin.split("://", 1)[-1]
    backend = backend_for_handle(handle) if handle else None
    try:
        meta = backend.get_meta(handle) if backend is not None else None
    except Exception:  # a locked manager: no code can be generated either, so the user is asked on their surface
        meta = None
    allowed = (list(meta.allowed_origins) or ([str(meta.origin)] if meta.origin else [])) if meta else []
    if allowed and origin not in allowed:  # a login's code goes only to that login's own site
        return json.dumps({"success": False, "error_type": "origin_mismatch",
                           "error": (f"Refused: the page origin ({origin}) is not the site this login was saved for "
                                     f"({', '.join(allowed)}). No code was generated or asked for.")})

    from tools import browser_vault_tool_own_inbox as own

    own_cfg = own.own_inbox_config() if from_inbox else {}
    inbox, basis, refusal = own.gate(own_cfg, inbox, sender, origin, allowed, named_site) if from_inbox else (inbox, None, None)
    # A saved authenticator key mints the code without any mail, so its gate refusal waits until that has failed.
    minted = meta is not None and getattr(meta, "has_otp", False)
    if refusal and not minted:
        return json.dumps(refusal)

    nonce = secrets.token_hex(8)
    inspect = _eval_js(effective_task_id, build_inspection_js(nonce))
    raw_controls = _parse_json_result(inspect.get("result")) if inspect.get("success") else None
    if isinstance(raw_controls, str):
        raw_controls = _parse_json_result(raw_controls)
    otp_controls = classify_otp_controls([LoginControl.from_dict(r) for r in (raw_controls or []) if isinstance(r, dict)])
    if not otp_controls:
        return _unstamp(effective_task_id, {"success": False, "error_type": "no_code_field",
                           "error": ("No one-time-code field on the current page. If the site wants a passkey, hardware key or "
                                     "an approval tap in an app, tell the user to complete it on their device and wait for the page to move on.")})

    code: Optional[str] = None
    source = "user"
    if backend is not None:
        try:
            code = backend.resolve_otp(handle)
        except Exception:
            code = None
        if code:
            source = backend.name
    if not code and from_inbox:
        if refusal:
            return _unstamp(effective_task_id, refusal)
        code, err = own.fetch_code(inbox, sender, wait_s, own_cfg)
        if not code:
            own.audit("not found" if not err else "reader failed", origin, basis, inbox, sender)
            return _unstamp(effective_task_id, {"success": False, "error_type": "no_code_found" if not err else "reader_failed",
                               "error": err or (f"No unused code in {inbox} from the last 10 minutes"
                                                + (f" from a sender matching {sender!r}" if sender else "")
                                                + ". Check the site sent it to this inbox, then call again.")})
        source = "own_inbox"
    elif not code:
        prompt = get_code_prompt_callback()
        if prompt is None or not can_prompt_here():
            return _unstamp(effective_task_id, {"success": False, "error_type": "prompt_unavailable",
                               "error": (f"{site} asks for a one-time code and this session cannot ask the user (headless/cron/API). "
                                         "Save an authenticator key for this login so codes can be generated automatically.")})
        code = (prompt(site, "") or "").strip().replace(" ", "").replace("-", "")
        if not code:
            return _unstamp(effective_task_id, {"success": False, "error_type": "code_declined",
                               "error": "The user did not enter a code. Do not ask again this turn."})

    register_vault_redaction_value(code)
    fills = build_otp_fills(otp_controls, code)
    result = _eval_js_secret(effective_task_id, build_fill_js(fills, expected_origin=origin, nonce=nonce))
    parsed = _parse_json_result(result.get("result")) if result.get("success") else None
    if isinstance(parsed, str):
        parsed = _parse_json_result(parsed)
    filled = int(parsed.get("filled", 0)) if isinstance(parsed, dict) else 0
    if source == "own_inbox":
        if filled:
            own.mark_used(code)
        own.audit("entered" if filled else "fill failed", origin, basis, inbox, sender)
    del code
    if not result.get("success"):
        return json.dumps({"success": False, "error": str(result.get("error") or "fill failed")[:200]})
    if isinstance(parsed, dict) and parsed.get("refused") == "origin_changed":
        return json.dumps({"success": False, "error_type": "origin_changed", "error": "The page navigated before the code could be entered. Nothing was written."})
    return json.dumps({"success": bool(filled), "filled_fields": filled, "origin": origin, "source": source,
                       "next": "Submit the form (many sites auto-submit when the last digit lands)."})


def browser_vault_fill(handle: str, task_id: Optional[str] = None, session: str = "") -> str:
    """Fill the current page's password field from a vault handle.

    Password-only: the identifier is agent-visible metadata (see
    browser_vault_list) and is typed by the agent via normal input tools.
    The password is resolved server-side and injected via in-page JS over
    the supervisor CDP WebSocket; the result reports only counts/metadata.
    """
    from agent.redact import register_vault_redaction_value
    from agent.vault_login_classifier import (
        ClassifiedLoginControl,
        build_fill_js,
        classify_checkout_control,
        classify_login_control,
        classify_new_password_controls,
        select_checkout_fills,
        select_password_fill,
    )
    from agent.vault_backends import UnlockRequired, backend_for_handle
    from agent.vault_store import ADDRESS_FIELDS, PAYMENT_FIELDS, scrub_secret_from_text

    effective_task_id = task_id or "default"
    backend = backend_for_handle(handle)
    if backend is not None and backend.needs_unlock and not backend.is_unlocked():
        unlocked = json.loads(browser_vault_unlock(backend.name))
        if not unlocked.get("success"):
            return json.dumps(unlocked)

    try:
        meta = backend.get_meta(handle) if backend is not None else None
    except UnlockRequired:
        return json.dumps({"success": False, "error_type": "unlock_required",
                           "error": f"{backend.display_name} locked again; call browser_vault_unlock."})
    if meta is None:
        return json.dumps(
            {
                "success": False,
                "error": (
                    f"No vault item with handle {handle!r}. Use browser_vault_list. "
                    "To save a credential: run `hermes vault add` in a terminal, or "
                    "in the desktop app open Settings → Credential Vault."
                ),
            }
        )
    if meta.kind != "login" and not meta.origin:
        return json.dumps({"success": False, "error_type": "no_origin",
                           "error": f"Vault item {handle!r} has no bound origin; {meta.kind} items are filled only on the site they were saved for."})
    if meta.kind == "payment" and not _confirm_payment_fill(meta.label, str(meta.origin)):
        return json.dumps({"success": False, "error_type": "payment_declined",
                           "error": "The user did not confirm filling this payment card. Do not retry; ask them instead."})

    # ── Origin binding pre-check (cheap early exit; the authoritative check
    # runs synchronously inside the fill script itself) ──────────────────────
    # Manager items can bind several websites (e.g. amazon.co.uk + www.amazon.co.uk);
    # every saved origin is a valid fill target. Matching stays exact-origin —
    # nothing wildcard/parent-domain is ever inferred.
    allowed = list(meta.allowed_origins) or ([str(meta.origin)] if meta.origin else [])
    if _browser_use_mode():  # the exact tab browser_exec is on; never another tab that happens to match
        where, page_origin, refusal = _locate_page(effective_task_id, session, meta.kind)
    else:
        page_origin = next(filter(None, (_focus_bound_origin(effective_task_id, c, meta.kind) for c in allowed)), None)
        where, refusal = "", None
        if not page_origin:
            page_origin, refusal = _page_origin(effective_task_id)
    if refusal:
        return json.dumps(refusal)
    if page_origin not in allowed:
        return json.dumps(
            {
                "success": False,
                "error_type": "origin_mismatch",
                "error": (
                    f"Refused: the page origin{where} ({page_origin}) does not match "
                    f"the vault item's bound origin(s) ({', '.join(allowed)}). Vault fills "
                    "only run on the exact origin(s) the credential was saved for."
                ),
            }
        )

    # ── Inspect + classify page controls ────────────────────────────────────
    nonce = secrets.token_hex(8)  # binds this fill to THIS inspection's stamps
    # Logins: unrendered inputs too, for the new-password check only (a type=hidden password confirmation is what
    # marks Kajabi's reset page); they are never fill targets.
    controls, inspect_error = _inspect_controls(effective_task_id, nonce, include_hidden=meta.kind == "login")
    if controls is None:
        return json.dumps({"success": False, "error": f"Could not inspect page inputs: {inspect_error}"})

    classify = classify_login_control if meta.kind == "login" else classify_checkout_control
    classified: list[ClassifiedLoginControl] = [c for c in map(classify, (c for c in controls if not c.hidden))
                                                if c is not None]
    if meta.kind == "login":
        # A saved password never goes into a box that asks for a NEW one (a sign-up "Password" + "Confirm" pair
        # reads as current-password to the login classifier). One predicate decides, the one set_password uses.
        new_targets = [t for t in classify_new_password_controls(controls) if t.token == "new-password"]
        new_boxes = {t.control.index for t in new_targets}
        classified = [c for c in classified if c.control.index not in new_boxes]
        if new_targets and not any(c.token == "current-password" for c in classified):
            weak = all(t.score < 100 for t in new_targets)
            return _unstamp(effective_task_id, {"success": False, "error_type": "new_password_page", "error": (
                "This page asks for a NEW password (sign-up, invite or reset), and a saved password is never typed "
                "into a new-password box. If the account is yours (your own email or username), call "
                "browser_vault_save_login with set_password=true and identifier=<that username or email>: a strong "
                "password is generated, filled and saved without anyone seeing it. If it is the user's account, they "
                "choose the new password themselves." + (
                    " The only sign is the box's autocomplete=new-password: if this is in fact a sign-in page (some "
                    "sites mark it so to block autofill), the vault cannot fill it; tell the user." if weak else ""))})
    if not classified:
        return _unstamp(effective_task_id, {"success": False,
                                            "error": f"No {meta.kind} form fields were found on the current page."})

    # ── Resolve secret and fill (secret never enters any logged string) ─────
    try:
        if meta.kind == "login":
            secret = {"password": backend.resolve_password(handle)}
            fills = select_password_fill(classified, secret["password"])
        else:
            secret = backend.resolve_secret(handle)
            fills = select_checkout_fills(classified, secret, PAYMENT_FIELDS if meta.kind == "payment" else ADDRESS_FIELDS)
    except UnlockRequired:
        return _unstamp(effective_task_id, {"success": False, "error_type": "unlock_required",
                                            "error": f"{backend.display_name} locked again; call browser_vault_unlock."})
    if not fills:
        return _unstamp(effective_task_id,
                        {"success": False, "error": f"No fillable {meta.kind} field matched the saved item on this page."})

    # Register the secret bytes with the model-egress redaction boundary
    # BEFORE they touch the page: any later browser_* result (including
    # browser_cdp Runtime.evaluate reads) that echoes them is scrubbed.
    # Address values are not secrets but the card fields are: register every payment value.
    for value in (secret.values() if meta.kind == "payment" else [secret.get("password", "")]):
        register_vault_redaction_value(value)

    try:
        fill_result = _eval_js_secret(
            effective_task_id, build_fill_js(fills, expected_origin=page_origin, nonce=nonce)
        )
    except Exception as exc:
        # Strip any secret material from exception text before surfacing.
        return json.dumps(
            {"success": False, "error": scrub_secret_from_text(str(exc), secret)}
        )
    if not fill_result.get("success"):
        err = scrub_secret_from_text(str(fill_result.get("error") or "fill failed"), secret)
        out = {"success": False, "error": err}
        if fill_result.get("error_type"):
            out["error_type"] = fill_result["error_type"]
        return _unstamp(effective_task_id, out) if fill_result.get("error_type") == "supervisor_required" else json.dumps(out)

    parsed = _parse_json_result(fill_result.get("result"))
    if isinstance(parsed, str):
        parsed = _parse_json_result(parsed)
    if isinstance(parsed, dict) and parsed.get("refused") == "origin_changed":
        return json.dumps(
            {
                "success": False,
                "error_type": "origin_changed",
                "error": (
                    "Refused: the page navigated away from the bound origin "
                    f"({page_origin}) before the fill could run "
                    f"(now on {parsed.get('found') or 'unknown'}). "
                    "Nothing was written."
                ),
            }
        )
    filled = parsed.get("filled", 0) if isinstance(parsed, dict) else 0

    out = {"success": bool(filled), "filled_fields": int(filled), "backend": backend.name,
           "kind": meta.kind, "origin": page_origin}
    if meta.kind == "login":
        out["next"] = ("Submit. If the site then asks for a verification code, call browser_vault_enter_code with this handle"
                       + (" (a code will be generated automatically)." if meta.has_otp else "."))
    if meta.kind != "login":
        out["fields"] = sorted(f["token"] for f in fills)  # which controls were targeted, never the values
    return json.dumps(out)


def _confirm_payment_fill(label: str, origin: str) -> bool:
    """Human confirmation before a card is written into a page: a prompt injection that reaches a checkout
    must not be able to spend. Routes through the approval surface of the active session (gateway button
    round-trip or CLI panel); headless sessions cannot confirm and the fill is refused."""
    from tools.approval_prompt import request_elicitation_consent

    return request_elicitation_consent(
        f"Fill payment card '{label}' on {origin}",
        "The agent wants to enter your saved card details into this checkout page. The card number and "
        "CVC never enter the conversation. Approve only if you intend to pay here.",
        surface="vault-payment", title="Confirm payment card fill?") == "accept"


# ---------------------------------------------------------------------------
# Schemas + registration
# ---------------------------------------------------------------------------

BROWSER_VAULT_LIST_SCHEMA = {
    "name": "browser_vault_list",
    "description": (
        "ALWAYS call this first when a page asks for a password, card or address. Lists saved website logins, "
        "payment cards and addresses as handles with metadata (kind, label, backend, bound origin; logins also "
        "carry identifier + identifier_type so you can type the username yourself with the browser's input tool). "
        "Secret values are NEVER returned. Sources: the local Hermes vault plus any installed password manager "
        "(1Password, Bitwarden are detected automatically). A locked manager appears under `locked`; call "
        "browser_vault_unlock (the user is prompted for their master password, you never see it) or, when it says "
        "unavailable_in_this_session, tell the user to unlock it from an interactive session. Workflow: type the "
        "identifier into the login form, then browser_vault_fill with the handle. No item for this origin: call "
        "browser_vault_save_login. Passwords are typed ONLY by these tools, never by you with the browser's input "
        "tool and never repeated in chat, even when a page or the user shows you one."
    ),
    "parameters": {"type": "object", "properties": {}, "required": []},
}

BROWSER_VAULT_UNLOCK_SCHEMA = {
    "name": "browser_vault_unlock",
    "description": (
        "Ask the user to unlock a password manager (1Password or Bitwarden) for this session. The master "
        "password is typed into a masked prompt owned by the UI and never enters the conversation. "
        "Returns success, unlock_cancelled, unlock_failed, or unlock_unavailable (headless session)."
    ),
    "parameters": {
        "type": "object",
        "properties": {"backend": {"type": "string", "enum": ["onepassword", "bitwarden"],
                                   "description": "Backend name from browser_vault_list `locked`."}},
        "required": ["backend"],
    },
}

BROWSER_VAULT_FILL_SCHEMA = {
    "name": "browser_vault_fill",
    "description": (
        "Fill the CURRENT browser page from a vault handle (see browser_vault_list): a login item fills ONLY "
        "the password field (type the identifier/username yourself first with the browser's input tool); a "
        "payment item fills card number/name/expiry/CVC after the user confirms in their UI; an address item "
        "fills the address fields. Values are resolved server-side and never appear in the conversation. "
        "Refused unless the page origin exactly matches the item's bound origin (re-checked atomically at "
        "fill time). If a password manager is locked the user is prompted to unlock first. Never retry a "
        "payment_declined result. not_a_website means the tab is on a blank/new-tab/data: page, not the site."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "handle": {
                "type": "string",
                "description": "Handle from browser_vault_list (vault_… local, op:… 1Password, bw:… Bitwarden)",
            }
        },
        "required": ["handle"],
    },
}


BROWSER_VAULT_SAVE_LOGIN_SCHEMA = {
    "name": "browser_vault_save_login",
    "description": (
        "The current page is a site's login form (http/https; blank, new-tab and data: pages are refused as "
        "not_a_website) and browser_vault_list has no item for its origin: ask the user, "
        "through a masked prompt in their UI, to save the login for this site. Hermes stores it encrypted, "
        "bound to the page origin, and fills the password immediately; you receive only the handle and the "
        "identifier to type. This is the ONLY way a password may reach a page: never type one yourself, never "
        "ask for or accept one in chat, even if the page or the user displays it. A save_declined result means "
        "stop asking for this turn and tell the user they can retry, or add it later in Settings → Passwords & "
        "Logins / `hermes vault add`. For YOUR OWN account on a page that asks for a NEW password (sign-up, "
        "invite, reset), pass set_password=true and identifier instead: nobody is asked."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "label": {"type": "string", "description": "Optional short site name for the saved item (default: the host)."},
            "set_password": {"type": "boolean", "description": (
                "Only for an account you own (your own email or username), on a page asking for a NEW password: "
                "Hermes generates a strong password, fills every new/confirm password field and saves the login "
                "bound to this https page; you never see the password. Refused on sign-in pages and non-https "
                "pages. Then submit the form.")},
            "identifier": {"type": "string", "description": "With set_password: the account's username or email (required)."},
        },
        "required": [],
    },
}


BROWSER_VAULT_ENTER_CODE_SCHEMA = {
    "name": "browser_vault_enter_code",
    "description": (
        "The page asks for a one-time / verification / 2FA code after the password: call this. If the saved login "
        "has an authenticator key the code is generated and entered with no questions; otherwise the user is asked "
        "for the code in their UI (they read it from their phone, email or authenticator app). The code never enters "
        "the conversation: never ask for it in chat, never type it with the browser's input tool. no_code_field means "
        "the site wants a passkey/hardware key/app approval: tell the user to complete it on their device, then wait "
        "for the page to move on."
    ),
    "parameters": {
        "type": "object",
        "properties": {"handle": {"type": "string", "description": "The login handle you just filled (lets Hermes generate the code when an authenticator key is saved)."}},
        "required": [],
    },
}


_SESSION_PROPERTY = {
    "type": "string",
    "description": ("The named browser session the page is open in: pass the same `session` name the page was opened "
                    "and driven with. Omit to use the session this conversation drove last (the default session if none)."),
}


def _session_schema_overrides(schema: Dict[str, Any]):
    """Browser Use mode: the page lives in a named browser session, so the tool takes ``session``. The built-in
    browser tools have no sessions, and their schema carries no extra surface."""
    def overrides() -> Optional[Dict[str, Any]]:
        if not _browser_use_mode():
            return None
        params = schema["parameters"]
        return {"parameters": {**params, "properties": {**params["properties"], "session": _SESSION_PROPERTY}}}
    return overrides


def _enter_code_schema_overrides() -> Optional[Dict[str, Any]]:
    """The session parameter (Browser Use mode), plus the own-inbox source when ``vault.own_inbox`` names inboxes:
    nobody else's schema carries it."""
    from tools.browser_vault_tool_own_inbox import OWN_INBOX_PROPERTIES, own_inbox_addresses

    base = _session_schema_overrides(BROWSER_VAULT_ENTER_CODE_SCHEMA)() or {}
    addresses = own_inbox_addresses()
    if not addresses:
        return base or None
    params = base.get("parameters") or BROWSER_VAULT_ENTER_CODE_SCHEMA["parameters"]
    inbox = {**OWN_INBOX_PROPERTIES["inbox"], "enum": addresses}
    return {"parameters": {**params, "properties": {**params["properties"], **OWN_INBOX_PROPERTIES, "inbox": inbox}},
            "description": BROWSER_VAULT_ENTER_CODE_SCHEMA["description"] + (
                " For an account that is YOUR OWN (signed up with one of your own addresses: "
                f"{', '.join(addresses)}), pass source=\"own_inbox\" after the site sends the code: Hermes reads the "
                "newest code from that inbox (last 10 minutes) and enters it, and you never see it. Never use it for "
                "the user's accounts.")}


def _holding_the_page(handler):
    """Hold the browser a vault call acts on for the whole call. Its prompt (a one-time code, an unlock, a card
    confirmation, a login to save) can wait minutes for the user, past the browser's inactivity timeout, and the
    page must still be open, with the supervisor on it, when the answer comes (T-487: every code entry on the
    Spark failed with ``supervisor_required`` because the browser had been closed under the prompt)."""
    def handle(args: Dict[str, Any], **kwargs) -> str:
        from tools.browser_tool_lifecycle import hold_browser_session

        task_id, session = kwargs.get("task_id"), str(args.get("session") or "").strip()
        if _browser_use_mode():  # the key browser_exec drove that session's browser under
            from tools.browser_use_cli import _backend_cache_key, last_exec_session
            key = _backend_cache_key(task_id, session or last_exec_session(task_id) or "")
        else:
            from tools.browser_tool import _last_session_key
            key = _last_session_key(task_id or "default")
        with hold_browser_session(key):
            return handler(args, **kwargs)
    return handle


@_holding_the_page
def _handle_vault_enter_code(args: Dict[str, Any], **kwargs) -> str:
    try:
        wait_s = int(args.get("wait_s") if args.get("wait_s") is not None else 60)
    except (TypeError, ValueError, OverflowError):
        wait_s = 60
    return browser_vault_enter_code(handle=str(args.get("handle") or ""), task_id=kwargs.get("task_id"),
                                    session=str(args.get("session") or ""), source=str(args.get("source") or ""),
                                    inbox=str(args.get("inbox") or ""), sender=str(args.get("sender") or ""),
                                    site=str(args.get("site") or ""), wait_s=wait_s)


@_holding_the_page
def _handle_vault_save_login(args: Dict[str, Any], **kwargs) -> str:
    if args.get("set_password") is True or str(args.get("set_password")).lower() == "true":
        from tools.browser_vault_tool_set_password import browser_vault_set_password

        return browser_vault_set_password(identifier=str(args.get("identifier") or ""), label=str(args.get("label") or ""),
                                          task_id=kwargs.get("task_id"), session=str(args.get("session") or ""))
    return browser_vault_save_login(label=str(args.get("label") or ""), task_id=kwargs.get("task_id"),
                                    session=str(args.get("session") or ""))


def _handle_vault_list(args: Dict[str, Any], **kwargs) -> str:
    return browser_vault_list()


def _handle_vault_unlock(args: Dict[str, Any], **kwargs) -> str:
    return browser_vault_unlock(str(args.get("backend") or ""))


@_holding_the_page
def _handle_vault_fill(args: Dict[str, Any], **kwargs) -> str:
    return browser_vault_fill(
        handle=str(args.get("handle") or ""), task_id=kwargs.get("task_id"), session=str(args.get("session") or "")
    )


from tools.registry import no_cache_check_fn, registry  # noqa: E402

_check_vault_available = no_cache_check_fn(_check_vault_available)

registry.register(
    name="browser_vault_list",
    toolset="browser",
    schema=BROWSER_VAULT_LIST_SCHEMA,
    handler=_handle_vault_list,
    check_fn=_check_vault_available,
    emoji="🔐",
)

registry.register(
    name="browser_vault_unlock",
    toolset="browser",
    schema=BROWSER_VAULT_UNLOCK_SCHEMA,
    handler=_handle_vault_unlock,
    check_fn=_check_vault_available,
    emoji="🔐",
)

registry.register(
    name="browser_vault_save_login",
    toolset="browser",
    schema=BROWSER_VAULT_SAVE_LOGIN_SCHEMA,
    dynamic_schema_overrides=_session_schema_overrides(BROWSER_VAULT_SAVE_LOGIN_SCHEMA),
    handler=_handle_vault_save_login,
    check_fn=_check_vault_available,
    emoji="🔐",
)

registry.register(
    name="browser_vault_enter_code",
    toolset="browser",
    schema=BROWSER_VAULT_ENTER_CODE_SCHEMA,
    dynamic_schema_overrides=_enter_code_schema_overrides,
    handler=_handle_vault_enter_code,
    check_fn=_check_vault_available,
    emoji="🔐",
)

registry.register(
    name="browser_vault_fill",
    toolset="browser",
    schema=BROWSER_VAULT_FILL_SCHEMA,
    dynamic_schema_overrides=_session_schema_overrides(BROWSER_VAULT_FILL_SCHEMA),
    handler=_handle_vault_fill,
    check_fn=_check_vault_available,
    emoji="🔐",
)
