"""browser_vault_save_login(set_password=true): a new password for an account the agent owns (T-335).

Kajabi's invite page (app.kajabi.com/password/edit, 11-02) asks Uni's own account for a NEW password. The fill
refuses new-password fields on purpose (a saved sign-in password must never land in a change-password box) and
save_login asks a human, yet nobody should type a password for an account the agent owns. Here the password is
generated in this process, written into the page only over the supervisor socket (never argv), and stored bound to
the page's exact https origin; the tool result carries the handle, never the value.
"""

from __future__ import annotations

import json
import secrets
import string
from typing import Any, Dict, Optional

# Symbols every site we met accepts (Kajabi wants one of "e.g. !?$"); no quotes, spaces or backslashes.
_SYMBOLS = "!?$#%*-_+=."
_PASSWORD_LENGTH = 24


def generate_password(length: int = _PASSWORD_LENGTH) -> str:
    """A random password with lower and upper case, a digit and a symbol (the usual site rules)."""
    alphabet = string.ascii_letters + string.digits + _SYMBOLS
    classes = (string.ascii_lowercase, string.ascii_uppercase, string.digits, _SYMBOLS)
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(ch in cls for ch in password) for cls in classes):
            return password


def _refuse(error_type: str, error: str) -> str:
    return json.dumps({"success": False, "error_type": error_type, "error": error})


def browser_vault_set_password(identifier: str, label: str = "", task_id: Optional[str] = None,
                               session: str = "") -> str:
    """Generate a password, fill every new-password field of the exact tab, and save or update the login."""
    from agent.redact import register_vault_redaction_value
    from agent.vault_login_classifier import LoginControl, build_fill_js, build_inspection_js, classify_new_password_controls
    from agent.vault_store import get_vault_store, scrub_secret_from_text
    from tools import browser_vault_tool as bvt

    identifier = (identifier or "").strip()
    if not identifier:
        return _refuse("identifier_required", (
            "set_password needs `identifier`: the username or email of YOUR account on this site (the one the "
            "password is for). Nothing was generated or saved."))
    if bvt.identifier_looks_like_password(identifier):
        return _refuse("identifier_is_password", (
            "The identifier reads like a password, not a username or email. Pass the account's username or email. "
            "Nothing was generated or saved."))
    effective_task_id = task_id or "default"
    if bvt._browser_use_mode():  # the inspection and the fill act in ONE session, even if another runs in between
        from tools.browser_use_cli import last_exec_session
        session = session.strip() or last_exec_session(effective_task_id) or ""
    where, origin, refusal = bvt._locate_page(effective_task_id, session, "login")
    if refusal:
        return json.dumps(refusal)
    if not origin.startswith("https://"):
        return _refuse("not_https", (f"Refused: the page{where} is {origin}, not https. A generated password is only "
                                     "set on an https page. Nothing was generated or saved."))

    nonce = secrets.token_hex(8)
    inspect = bvt._eval_js(effective_task_id, build_inspection_js(nonce, include_hidden=True))
    raw_controls = bvt._parse_json_result(inspect.get("result")) if inspect.get("success") else None
    if isinstance(raw_controls, str):
        raw_controls = bvt._parse_json_result(raw_controls)
    if not isinstance(raw_controls, list):
        return json.dumps({"success": False, "error": f"Could not inspect the page{where}: "
                                                      f"{str(inspect.get('error') or 'no usable controls')[:200]}"})
    targets = classify_new_password_controls([LoginControl.from_dict(r) for r in raw_controls if isinstance(r, dict)])
    if not targets:
        return _refuse("no_new_password_field", (
            f"No new-password field on the page{where} ({origin}). set_password only runs where a site asks for a NEW "
            "password (sign-up, invite, reset). On a sign-in page use browser_vault_fill with the saved handle. "
            "Nothing was generated or saved."))

    store = get_vault_store()
    existing = next((m for m in store.list_items() if m.kind == "login" and m.origin == origin
                     and (m.identifier or "").casefold() == identifier.casefold()), None)
    password = generate_password()
    register_vault_redaction_value(password)  # before it touches the page: no later browser result can echo it
    secret = {"password": password}
    previous: Optional[str] = None
    try:
        if existing is not None:
            previous = str(store.resolve_secret(existing.id).get("password") or "")
            meta = store.set_password(existing.id, password)
        else:
            id_type = "email" if "@" in identifier else ("phone" if identifier.lstrip("+").isdigit() else "username")
            meta = store.add_item("login", label.strip() or origin.split("://", 1)[-1],
                                  {"identifier_type": id_type, "identifier": identifier, "password": password}, origin=origin)
    except Exception as exc:
        return _refuse("save_failed", scrub_secret_from_text(str(exc), secret)[:200])

    fills = [{"index": t.control.index, "token": t.token, "value": password} for t in targets]
    result = bvt._eval_js_secret(effective_task_id, build_fill_js(fills, expected_origin=origin, nonce=nonce))
    parsed: Any = bvt._parse_json_result(result.get("result")) if result.get("success") else None
    if isinstance(parsed, str):
        parsed = bvt._parse_json_result(parsed)
    landed = isinstance(parsed, dict) and not parsed.get("refused") and parsed.get("matched") == len(fills)
    if not landed:
        # The vault changes only when the page took the password: undo the save, so a new login is not left behind
        # and an existing one keeps the password the site still has.
        if previous:
            store.set_password(meta.id, previous)
        else:
            store.remove_item(meta.id)
        del password, previous
        if isinstance(parsed, dict) and parsed.get("refused") == "origin_changed":
            return _refuse("origin_changed", f"The page left {origin} before the password went in. Nothing was saved.")
        if not result.get("success"):
            err = scrub_secret_from_text(str(result.get("error") or "fill failed"), secret)[:200]
            return json.dumps({"success": False, "error_type": result.get("error_type") or "fill_failed",
                               "error": f"{err} Nothing was saved."})
        took = parsed.get("matched", 0) if isinstance(parsed, dict) else 0
        return _refuse("fill_failed", (f"The page{where} kept the password in {took} of {len(fills)} new-password "
                                       "fields, so nothing was saved. Reload the page and try again once."))
    del password, previous
    out: Dict[str, Any] = {
        "success": True, "handle": meta.id, "origin": origin, "identifier": identifier,
        "filled_fields": sum(t.token == "new-password" for t in targets),
        "confirmation_synced": any(t.token == "new-password-sync" for t in targets),
        "updated_existing": existing is not None,
        "next": ("Submit the form now. The new password is saved under this handle; sign in later with "
                 "browser_vault_fill. If the site rejects it, read its rules and call set_password again (each call "
                 "makes a new password and replaces this one)."),
    }
    return json.dumps(out, ensure_ascii=False)
