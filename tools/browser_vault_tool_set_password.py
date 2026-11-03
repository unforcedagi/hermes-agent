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
_MIN_LENGTH = 12


def generate_password(length: int = _PASSWORD_LENGTH) -> str:
    """A random password with lower and upper case, a digit and a symbol (the usual site rules)."""
    alphabet = string.ascii_letters + string.digits + _SYMBOLS
    classes = (string.ascii_lowercase, string.ascii_uppercase, string.digits, _SYMBOLS)
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(ch in cls for ch in password) for cls in classes):
            return password


def _person_agrees(identifier: str, origin: str) -> bool:
    """One tap on the user's surface (gateway approval card or CLI panel; headless sessions answer no)."""
    from tools.approval_prompt import request_elicitation_consent

    return request_elicitation_consent(
        f"Replace the saved password for {identifier} on {origin}",
        "The agent wants to set a new, generated password for this account on the site's set-password page and save it "
        "in place of the password saved now. Nobody sees the new password, and the saved one is gone once replaced. "
        "Approve only if this is the agent's own account.",
        surface="vault-set-password", title="Replace a saved password?") == "accept"


def _in_password_manager(origin: str, identifier: str) -> str:
    """The display name of an external manager (1Password, Bitwarden) that holds a login for this account, or that
    is locked or unreadable so it cannot be ruled out."""
    from agent.vault_backends import enabled_backends

    for backend in enabled_backends():
        if backend.name == "local":
            continue
        if backend.needs_unlock and not backend.is_unlocked():
            return backend.display_name
        try:
            metas = backend.list_items()
        except Exception:
            return backend.display_name
        if any(m.kind == "login" and (m.identifier or "").casefold() == identifier.casefold()
               and origin in (m.allowed_origins or (m.origin,)) for m in metas):
            return backend.display_name
    return ""


def _refuse(error_type: str, error: str) -> str:
    return json.dumps({"success": False, "error_type": error_type, "error": error})


def browser_vault_set_password(identifier: str, label: str = "", task_id: Optional[str] = None,
                               session: str = "") -> str:
    """Generate a password, fill every new-password field of the exact tab, and save or update the login."""
    from agent.redact import register_vault_redaction_value
    from agent.vault_login_classifier import build_fill_js, classify_new_password_controls
    from agent.vault_store import get_vault_store, scrub_secret_from_text
    from tools import browser_vault_tool as bvt

    identifier = (identifier or "").strip()
    if not identifier:
        return _refuse("identifier_required", (
            "set_password needs `identifier`: the username or email of YOUR account on this site (the one the "
            "password is for). Nothing was generated or saved."))
    if len(identifier) > 254 or any(ch.isspace() for ch in identifier):
        return _refuse("identifier_invalid", ("`identifier` must be the account's username or email (no spaces). "
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

    if bvt._ensure_supervisor(effective_task_id) is None:  # before anything changes: the fill could not run at all
        return _refuse("supervisor_required", (
            f"The browser{where} has no CDP connection Hermes can write a secret through (the fallback would put it in "
            "process arguments). Nothing was generated or saved."))
    nonce = secrets.token_hex(8)
    controls, inspect_error = bvt._inspect_controls(effective_task_id, nonce, include_hidden=True)
    if controls is None:
        return json.dumps({"success": False, "error": f"Could not inspect the page{where}: {inspect_error}"})
    targets = classify_new_password_controls(controls)
    new_boxes = [t for t in targets if t.token == "new-password"]

    def refuse(error_type: str, error: str) -> str:  # after the inspection: take its stamps off the page too
        return bvt._unstamp(effective_task_id, {"success": False, "error_type": error_type, "error": error})

    if not new_boxes:
        return refuse("no_new_password_field", (
            f"No new-password field on the page{where} ({origin}). set_password only runs where a site asks for a NEW "
            "password (sign-up, invite, reset). On a sign-in page use browser_vault_fill with the saved handle. "
            "Nothing was generated or saved."))
    unclear = [t for t in targets if t.token == "unclear-password"]
    if unclear:
        named = ", ".join(repr((t.control.label.strip() or t.control.name.strip())[:40]) for t in unclear)
        return refuse("unclear_password_form", (
            f"Next to the new-password box{where} there is a password box ({named}) not marked as the current password "
            "or as a confirmation, and set_password does not guess. Mark it with browser_exec, then call again: "
            "autocomplete=\"current-password\" if it asks for the current password, autocomplete=\"new-password\" if it "
            "repeats the new one. Nothing was generated or saved."))
    managed = _in_password_manager(origin, identifier)
    if managed:
        return refuse("login_in_password_manager", (
            f"{managed} has a login for {identifier} on {origin}, or is locked so it cannot be checked; set_password only "
            f"manages the Hermes vault and would leave such an entry stale. If it is locked, unlock it "
            f"(browser_vault_unlock) and call again; if it holds this login, ask the user to change the password in "
            f"{managed}. Nothing was generated or saved."))
    store = get_vault_store()
    existing = next((m for m in store.list_items() if m.kind == "login" and m.origin == origin
                     and (m.identifier or "").casefold() == identifier.casefold()), None)
    weak = all(t.score < 100 for t in new_boxes)
    if existing is not None and weak:
        return refuse("not_clearly_a_new_password_page", (
            f"The page{where} has one password box marked new-password and nothing else saying so (no label, "
            "confirmation or current-password box). Some sign-in pages mark their box that way to block autofill, and "
            f"a login for {identifier} is already saved here ({existing.id}), so set_password will not replace it on "
            "this page. Nothing was generated or saved."))
    if existing is not None and not existing.generated and not _person_agrees(identifier, origin):
        # A person typed that password (save_login, `hermes vault add`) and may still use it.
        return refuse("login_saved_by_person", (
            f"A login for {identifier} on {origin} was saved by a person ({existing.id}), and they did not agree to "
            "replace it with a generated password. Ask them in chat whether to replace it, then call again; never "
            "remove it yourself. Nothing was generated or saved."))
    limits = [t.control.max_length for t in new_boxes if t.control.max_length]
    length = min([_PASSWORD_LENGTH, *limits])
    if length < _MIN_LENGTH:
        return refuse("password_too_short", (f"The new-password field{where} takes at most {length} characters, too "
                                             "short for a generated password. Nothing was generated or saved."))
    password = generate_password(length)
    register_vault_redaction_value(password)  # before it touches the page: no later browser result can echo it
    secret = {"password": password}
    previous: Dict[str, Any] = {}
    try:
        if existing is not None:
            previous = store.resolve_secret(existing.id)
            meta = store.set_password(existing.id, password, generated=True)
        else:
            meta = store.add_item("login", label.strip() or origin.split("://", 1)[-1],
                                  {"identifier_type": bvt.identifier_type(identifier), "identifier": identifier,
                                   "password": password}, origin=origin, generated=True)
    except Exception as exc:
        return refuse("save_failed", scrub_secret_from_text(str(exc), secret)[:200])

    # A change form's current box takes the password being replaced, in the same all-or-nothing write: once the vault
    # holds the new one, nothing else could fill it. Without a saved one it is left for the agent.
    old_password = str(previous.get("password") or "")
    current = [t for t in targets if t.token == "current-password"]
    if old_password:
        register_vault_redaction_value(old_password)
    fills = [{"index": t.control.index, "token": t.token, "value": password} for t in targets
             if t.token != "current-password"]
    fills += [{"index": t.control.index, "token": t.token, "value": old_password} for t in current if old_password]
    try:
        result = bvt._eval_js_secret(effective_task_id, build_fill_js(fills, expected_origin=origin, nonce=nonce,
                                                                      all_or_nothing=True))
    except Exception as exc:
        result = {"success": False, "error": str(exc)}
    parsed: Any = bvt._parse_json_result(result.get("result")) if result.get("success") else None
    if isinstance(parsed, str):
        parsed = bvt._parse_json_result(parsed)
    landed = isinstance(parsed, dict) and not parsed.get("refused") and parsed.get("matched") == len(fills)
    if not landed:
        # The vault changes only when the page took the password. An all-or-nothing fill that ran leaves no field
        # holding it; when the call itself failed (the script may have run), reload the page to discard any.
        reloaded = None
        if not result.get("success") and result.get("error_type") != "supervisor_required":  # outcome unknown
            reloaded = bool(bvt._eval_js(effective_task_id, "location.reload(), true").get("success"))
        try:
            if existing is not None:
                store.set_password(meta.id, old_password, generated=existing.generated)
            else:
                store.remove_item(meta.id)
        except Exception as exc:
            return refuse("rollback_failed", (
                f"The page did not take the password, and the vault could not be put back ({type(exc).__name__}): "
                f"login {meta.id} may now hold a password the site never got. Tell the user."))
        if isinstance(parsed, dict) and parsed.get("refused") == "origin_changed":
            return _refuse("origin_changed", f"The page left {origin} before the password went in. Nothing was saved.")
        if not result.get("success"):
            err = scrub_secret_from_text(scrub_secret_from_text(str(result.get("error") or "fill failed"), secret),
                                         previous)[:200]
            then = {None: "", True: " The page was reloaded, so it holds none of it."}.get(
                reloaded, " The page could not be reloaded: reload it before anything else and do not submit it.")
            return json.dumps({"success": False, "error_type": result.get("error_type") or "fill_failed",
                               "error": f"{err} Nothing was saved.{then}"})
        took = parsed.get("matched", 0) if isinstance(parsed, dict) else 0
        return _refuse("fill_failed", (f"The page{where} kept {took} of {len(fills)} values, so every field written "
                                       "was emptied again and nothing was saved. Reload the page and try again once."))
    out: Dict[str, Any] = {
        "success": True, "handle": meta.id, "origin": origin, "identifier": identifier,
        "filled_fields": len(new_boxes),
        "confirmation_synced": any(t.token == "new-password-sync" for t in targets),
        "updated_existing": existing is not None,
        "next": ("Submit the form now and read the page's answer. The new password is saved under this handle; sign "
                 "in later with browser_vault_fill. Only if the site rejects it, call set_password again: each call "
                 "makes a new password and replaces this one, so never call it after the site accepted one."),
    }
    if current:
        out["current_password_filled"] = bool(old_password)
        if not old_password:
            out["next"] = ("This form also asks for the CURRENT password, which is not in the Hermes vault: fill that "
                           "box first (browser_vault_fill with the login that holds it), then submit. ") + out["next"]
    if weak:
        out["next"] += (" The page's only sign of a new password is autocomplete=new-password: if the submit fails "
                        "as a wrong sign-in, this was a sign-in page; remove this login (it holds nothing the site "
                        "knows) and tell the user.")
    return json.dumps(out, ensure_ascii=False)
