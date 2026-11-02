"""Live E2E: the vault tools act on the exact tab browser_exec is on, in the session the page is in (T-335).

The 11-02 bug: browser_exec showed app.kajabi.com/password/edit, and browser_vault_save_login right after offered to
save a login for chrome://new-tab-page. The vault's CDP supervisor sat on the browser's first tab, not on the tab
the Browser Use daemon drives, and it followed whichever named session browser_exec ran last.

Everything is throwaway: a self-signed https server on 127.0.0.1 (reached as 127.0.0.1 and as localhost, two
origins), a temp HERMES_HOME, Hermes' packaged Chromium through the real browser_exec path, and the dummy login
uni-test@example.invalid with a random password.

Also the set-password path (T-335, 11-02): Kajabi's invite page asks Uni's own account for a NEW password, which
the fill refuses on purpose. ``browser_vault_save_login(set_password=true, identifier=...)`` generates one, fills the
shadow-DOM box and the hidden confirmation (synced by the component, or not), and the server below accepts it only
when both match its rules; then the regular fill signs in with the saved item. Every file under the temp home (DEBUG
logs included) and every tool result is searched for the generated passwords.

Run: HERMES_E2E_BROWSER=1 <venv>/bin/python evals/vault_session_live_e2e.py
"""
from __future__ import annotations

import http.server
import json
import os
import secrets
import ssl
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
HOME = Path(tempfile.mkdtemp(prefix="hermes-vault-session-e2e-"))
os.environ["HERMES_HOME"] = str(HOME)
# Harness daemons are named per user (BU_NAME), not per HERMES_HOME: give this run its own, so it can never
# reuse (or restart) a live Hermes's "default" or "kajabi" daemon.
os.environ["BH_HOME"] = str(HOME / "bh")

PAGES = {
    # The path from the bug report.
    "/password/edit": b"""<!doctype html><title>sign in</title><form>
<input name=email type=email autocomplete=username><input name=pw type=password autocomplete=current-password>
<input type=submit></form>""",
    "/login": b"""<!doctype html><title>login</title><form>
<input name=email type=email autocomplete=username><input name=pw type=password autocomplete=current-password>
<input type=submit></form>""",
    # Kajabi's shape (11-02): the password box sits in an open shadow root of a <pds-input>, a hidden
    # confirmation field is in the light DOM, and the page listens on document (so events must be composed).
    "/shadow-login": b"""<!doctype html><title>shadow login</title><form>
<pds-input type=email name="user[email]" autocomplete=username></pds-input>
<pds-input type=password name="user[password]" label="Password"></pds-input>
<input type=password name="user[password_confirmation]" style="display:none"><button>Sign in</button></form>
<script>
customElements.define("pds-input", class extends HTMLElement {
  connectedCallback() {
    const input = document.createElement("input");
    input.type = this.getAttribute("type") || "text";
    input.name = this.getAttribute("name");
    if (this.getAttribute("autocomplete")) input.autocomplete = this.getAttribute("autocomplete");
    this.attachShadow({mode: "open"}).appendChild(input);
  }
});
document.addEventListener("input", (e) => { if (e.composedPath()[0].name === "user[password]") document.body.dataset.heard = "input"; });
document.addEventListener("change", (e) => { if (e.composedPath()[0].name === "user[password]") document.body.dataset.changed = "yes"; });
</script>""",
    # Kajabi's /password/edit as browser_exec saw it on 11-02: hidden _method, authenticity_token and
    # user[reset_password_token], a type=hidden user[password_confirmation], and the password box in a <pds-input>'s open
    # shadow root. The component submits its value through ElementInternals and (here) syncs the confirmation itself.
    "/kajabi/password/edit": b"""<!doctype html><title>Change your password</title>
<form method=post action="/kajabi/password"><input type=hidden name=_method value=put>
<input type=hidden name=authenticity_token value=tok><input type=hidden name="user[reset_password_token]" id=user_reset_password_token value=rst>
<h1>Change your password</h1><p>Enter your new password below.</p>
<pds-input type=password name="user[password]" id=user_password autocomplete=new-password sync="user[password_confirmation]"></pds-input>
<input type=hidden name="user[password_confirmation]"><button type=submit>Change my password</button></form>""" + b"__PDS__",
    # The same page whose component does NOT sync the confirmation, and says "New password" only on the host.
    "/kajabi/password/edit-nosync": b"""<!doctype html><title>Change your password</title>
<form method=post action="/kajabi/password"><input type=hidden name=_method value=put>
<input type=hidden name=authenticity_token value=tok>
<pds-input type=password name="user[password]" id=user_password label="New password"></pds-input>
<input type=hidden name="user[password_confirmation]"><button type=submit>Change my password</button></form>""" + b"__PDS__",
    "/kajabi/login": b"""<!doctype html><title>Log in</title><form method=post action="/kajabi/sign_in">
<input type=email name="user[email]" autocomplete=username>
<pds-input type=password name="user[password]" id=user_password autocomplete=current-password label="Password"></pds-input>
<button type=submit>Log in</button></form>""" + b"__PDS__",
    # Step one of a two-step login: no password field yet.
    "/identifier": b"""<!doctype html><title>step 1</title><form><input name=email type=email autocomplete=username>
<input type=submit value=Continue></form>""",
}
_PDS = b"""<script>
customElements.define("pds-input", class extends HTMLElement {
  static formAssociated = true;
  constructor() { super(); this.internals = this.attachInternals(); }
  connectedCallback() {
    const input = document.createElement("input");
    input.type = this.getAttribute("type") || "text";
    input.name = this.getAttribute("name");
    input.id = this.id;
    if (this.getAttribute("autocomplete")) input.autocomplete = this.getAttribute("autocomplete");
    this.attachShadow({mode: "open"}).appendChild(input);
    input.addEventListener("input", () => {
      this.internals.setFormValue(input.value);
      const sync = this.getAttribute("sync");
      if (sync) this.closest("form").querySelector(`[name="${sync}"]`).value = input.value;
    });
  }
});
</script>"""
PAGES = {path: body.replace(b"__PDS__", _PDS) for path, body in PAGES.items()}
ACCOUNT: dict = {}  # the site's side of Uni's Kajabi-like account: email -> password, as set through the form


def _strong(pw: str) -> bool:  # Kajabi's rule: at least 10 characters, upper and lower case, a number, a symbol
    import re
    return len(pw) >= 10 and all(re.search(p, pw) for p in ("[a-z]", "[A-Z]", r"\d", r"[^A-Za-z0-9]"))


def _post(path: str, form: dict) -> bytes:
    one = {k: v[0] for k, v in form.items()}
    if path == "/kajabi/password":
        pw, confirm = one.get("user[password]", ""), one.get("user[password_confirmation]", "")
        if not pw or pw != confirm:
            return b"<title>error</title><p id=result>Password confirmation doesn't match</p>"
        if not _strong(pw):
            return b"<title>error</title><p id=result>Password is too weak</p>"
        ACCOUNT[IDENTIFIER] = pw
        return b"<title>changed</title><p id=result>Your password has been changed</p>"
    if path == "/kajabi/sign_in":
        ok = ACCOUNT.get(one.get("user[email]", "")) == one.get("user[password]") and ACCOUNT
        return (b"<title>in</title><p id=result>Signed in as " + one["user[email]"].encode() + b"</p>") if ok else \
            b"<title>no</title><p id=result>Invalid email or password</p>"
    return b"nope"


TASK = "vault-session-e2e"
IDENTIFIER = "uni-test@example.invalid"
results: list[tuple[str, bool, str]] = []


def check(name: str, ok, note: str = "") -> bool:
    results.append((name, bool(ok), note))
    print(f"{'PASS' if ok else 'FAIL'}  {name}{('  · ' + note) if note else ''}", flush=True)
    return bool(ok)


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = PAGES.get(self.path, b"nope")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        from urllib.parse import parse_qs

        form = parse_qs(self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode(), keep_blank_values=True)
        body = _post(self.path, form)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # noqa: ARG002 — quiet
        pass


def _https_server() -> http.server.ThreadingHTTPServer:
    cert, key = HOME / "cert.pem", HOME / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-keyout", str(key), "-out", str(cert)],
                   check=True, capture_output=True)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _exec(code: str, session: str = "") -> dict:
    from tools import browser_use_cli as bu

    out = json.loads(bu.browser_exec(code, session=session, task_id=TASK, timeout_s=90))
    assert out.get("success"), out
    return out


def _open(url: str, session: str = "") -> dict:
    """A new tab on ``url``. The page is self-signed and the cert override is per tab, so set it before navigating."""
    return _exec(f"new_tab(); cdp('Security.setIgnoreCertificateErrors', ignore=True); goto_url({url!r}); wait_for_load(); "
                 "print(page_info()['url'])", session)


def _page_value(session: str, selector: str, raw: bool = False) -> str:
    """The field's value as the daemon's own tab sees it. browser_exec output scrubs vault secrets (as it must), so
    the page hands it back reversed and this undoes that. ``raw``: ``selector`` is a JS expression for the element."""
    el = selector if raw else f"document.querySelector('{selector}')"
    out = _exec(f"print(js(\"({el} || {{value: ''}}).value.split('').reverse().join('')\"))", session)["output"].strip()
    return out[::-1]


def _stop_harness_daemons(bh_home: Path) -> None:
    """Stop the harness daemons this run started under its own BH_HOME (the harness never reaps them)."""
    from tools import browser_use_cli as bu

    cmd = bu._find_cli()
    for pid_file in (bh_home / "runtime").glob("bu-*.pid") if cmd else ():
        env = {**os.environ, "BH_HOME": str(bh_home), "BU_NAME": pid_file.stem[3:]}
        subprocess.run(cmd + ["--reload"], env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=60)


def _set_password_checks(origin: str, call, seen: list) -> list[str]:
    """Kajabi's set-password page, then sign-in with the saved item. Returns the passwords generated (never printed)."""
    from agent.vault_store import get_vault_store

    store = get_vault_store()

    def exec_seen(code: str, session: str = "kajabi") -> str:
        out = _exec(code, session)["output"]
        seen.append(out)
        return out.strip()

    def submit() -> str:
        return exec_seen("js(\"document.querySelector('form').requestSubmit()\"); wait_for_load(); "
                         "print(js(\"document.getElementById('result').textContent\"))")

    def sign_in(handle: str) -> tuple[dict, str]:
        _open(origin + "/kajabi/login", "kajabi")
        exec_seen(f"js(\"document.querySelector('input[name=\\\"user[email]\\\"]').value = {IDENTIFIER!r}\")")
        filled = call("browser_vault_fill", {"handle": handle, "session": "kajabi"})
        return filled, submit()

    generated: list[str] = []
    _open(origin + "/kajabi/password/edit", "kajabi")
    before = len(store.list_items())
    out = call("browser_vault_fill", {"handle": store.list_items()[0].id, "session": "kajabi"})
    check("fill on Kajabi's set-password page refuses and points at set_password", out.get("error_type") == "new_password_page"
          and "set_password" in (out.get("error") or ""), json.dumps(out)[:160])
    out = call("browser_vault_save_login", {"set_password": True, "session": "kajabi"})
    check("set_password without an identifier is refused", out.get("error_type") == "identifier_required"
          and len(store.list_items()) == before, out.get("error_type") or "")

    out = call("browser_vault_save_login", {"set_password": True, "identifier": IDENTIFIER, "session": "kajabi"})
    handle = out.get("handle") or ""
    meta = store.get_meta(handle) if handle else None
    pw = store.resolve_secret(handle)["password"] if meta else ""
    generated += [pw] if pw else []
    check("set_password on Kajabi's page (shadow box, component syncs the hidden confirmation) saves a login bound to "
          "the https origin", out.get("success") is True and meta is not None and meta.origin == origin
          and meta.identifier == IDENTIFIER and out.get("confirmation_synced") is True and out.get("filled_fields") == 1,
          json.dumps({k: out.get(k) for k in ("success", "origin", "filled_fields", "confirmation_synced", "error_type",
                                              "error")})[:220])
    check("…the shadow box and the confirmation hold the generated password",
          bool(pw) and _page_value("kajabi", "document.querySelector('pds-input').shadowRoot.querySelector('input')", raw=True) == pw
          and _page_value("kajabi", "document.getElementsByName('user[password_confirmation]')[0]", raw=True) == pw)
    result = submit()
    check("…and the site accepts it (password = confirmation, Kajabi's rules)", result == "Your password has been changed"
          and ACCOUNT.get(IDENTIFIER) == pw, result)

    filled, result = sign_in(handle)
    check("the regular fill signs in with the saved item", filled.get("success") is True
          and result == f"Signed in as {IDENTIFIER}", f"{json.dumps(filled)[:120]} → {result}")
    out = call("browser_vault_save_login", {"set_password": True, "identifier": IDENTIFIER, "session": "kajabi"})
    check("set_password on a sign-in page is refused and changes nothing", out.get("error_type") == "no_new_password_field"
          and store.resolve_secret(handle)["password"] == pw, out.get("error_type") or json.dumps(out)[:120])

    # The component does not sync the confirmation, and only the host says "New password": the tool fills the hidden
    # input itself, and a second set_password for the same account updates the saved login in place.
    _open(origin + "/kajabi/password/edit-nosync", "kajabi")
    out = call("browser_vault_save_login", {"set_password": True, "identifier": IDENTIFIER, "session": "kajabi"})
    pw2 = store.resolve_secret(handle)["password"] if out.get("handle") == handle else ""
    generated += [pw2] if pw2 else []
    result = submit()
    check("set_password where the component does not sync the confirmation fills it too, updating the same login",
          out.get("updated_existing") is True and bool(pw2) and pw2 != pw and result == "Your password has been changed"
          and ACCOUNT.get(IDENTIFIER) == pw2, f"{json.dumps({k: out.get(k) for k in ('success', 'updated_existing', 'error')})} → {result}")
    filled, result = sign_in(handle)
    check("…and sign-in works with the new one", result == f"Signed in as {IDENTIFIER}", result)

    plain = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=plain.serve_forever, daemon=True).start()
    try:
        _exec(f"goto_url('http://127.0.0.1:{plain.server_address[1]}/kajabi/password/edit'); wait_for_load()", "kajabi")
        count = len(store.list_items())
        out = call("browser_vault_save_login", {"set_password": True, "identifier": IDENTIFIER, "session": "kajabi"})
        check("set_password on an http page is refused", out.get("error_type") == "not_https"
              and len(store.list_items()) == count and store.resolve_secret(handle)["password"] == pw2, out.get("error_type") or "")
    finally:
        plain.shutdown()

    # Chromium's own profile (outside the temp home): session restore, form autofill, the password store.
    profile = Path(exec_seen("new_tab(); goto_url('chrome://version'); wait_for_load(); "
                             "print(js(\"document.getElementById('profile_path').textContent\"))"))
    files = [f for f in profile.rglob("*") if f.is_file() and not f.is_symlink()] if profile.is_dir() else []
    in_profile = [str(f.relative_to(profile)) for f in files if any(p.encode() in f.read_bytes() for p in generated)]
    check("no generated password in the browser's profile files", generated and files and not in_profile,
          ", ".join(in_profile[:5]) or f"{len(files)} files under {profile}")
    return generated


def main() -> int:
    srv = _https_server()
    port = srv.server_address[1]
    origin, decoy = f"https://127.0.0.1:{port}", f"https://localhost:{port}"

    from agent.vault_backends import unlock as vault_unlock
    from agent.vault_store import get_vault_store
    from tools import browser_vault_tool as bvt
    from tools.browser_supervisor import SUPERVISOR_REGISTRY
    from tools.registry import registry

    import hermes_logging

    hermes_logging.setup_logging(hermes_home=HOME, log_level="DEBUG", mode="gateway", force=True)
    asked: list[str] = []
    password = f"t335-dummy-{secrets.token_hex(8)}"
    generated: list[str] = []
    seen: list[str] = []  # every tool result and every browser_exec output, searched for generated passwords at the end

    def prompt(o: str, host: str) -> dict:
        asked.append(o)
        return {"identifier": IDENTIFIER, "password": password}

    def call(tool: str, args: dict) -> dict:
        raw = registry.dispatch(tool, args, task_id=TASK)
        assert password not in raw, f"{tool} leaked the password"
        seen.append(raw)
        return json.loads(raw)

    vault_unlock.set_save_login_prompt_callback(prompt)
    vault_unlock.set_unlock_prompt_callback(lambda *a: "")  # can_prompt_here keys off an interactive surface
    try:
        # Session "kajabi": a login tab on the decoy origin first, then the reset page the agent is on.
        _open(decoy + "/login", "kajabi")
        info = _open(origin + "/password/edit", "kajabi")
        check("browser_exec in session kajabi is on the reset page", "/password/edit" in info["output"], info["output"].strip())
        # The default session, used after it: the supervisor followed it before the fix.
        _exec("print(page_info())")

        asked.clear()
        out = call("browser_vault_save_login", {"label": "throwaway", "session": "kajabi"})
        check("save_login(session=kajabi) binds the tab browser_exec is on", out.get("origin") == origin and asked == [origin],
              json.dumps({k: out.get(k) for k in ("success", "origin", "error_type", "error")})[:200])
        check("…and fills the password into that tab", (out.get("fill") or {}).get("success") is True
              and _page_value("kajabi", "input[name=pw]") == password, json.dumps(out.get("fill"))[:200])
        handle = out.get("handle")
        scrubbed = _exec("print(js(\"document.querySelector('input[name=pw]').value\"))", "kajabi")["output"]
        check("browser_exec output scrubs the filled password", password not in scrubbed)

        # Default session on a two-step login (no password field): the save is bound to it, not to a blank tab.
        _open(origin + "/identifier")
        asked.clear()
        out = call("browser_vault_save_login", {})
        check("save_login() with no session uses the session browser_exec last drove (default) and its tab",
              out.get("origin") == origin and asked == [origin],
              json.dumps({k: out.get(k) for k in ("success", "origin", "error_type", "error")})[:200])

        # Another conversation (task) drives ITS default session, on its own browser, in between (11-02: two rooms).
        from tools import browser_use_cli as bu
        bu.browser_exec(f"new_tab(); cdp('Security.setIgnoreCertificateErrors', ignore=True); goto_url({decoy + '/login'!r}); "
                        "wait_for_load()", task_id="another-conversation", timeout_s=90)
        mine = _exec("print(page_info()['url'])")["output"].strip()
        check("this conversation's default session still drives its own browser, not the other conversation's",
              mine.startswith(origin + "/identifier"), mine)
        asked.clear()
        out = call("browser_vault_save_login", {})
        check("…and the vault acts on that same tab", out.get("origin") == origin and asked == [origin],
              json.dumps({k: out.get(k) for k in ("success", "origin", "error_type", "error")})[:200])

        # Non-website tabs are refused before anyone is asked (one more browser, three pages in turn).
        for url in ("about:blank", "chrome://new-tab-page/", "data:text/html,<input type=password>"):
            _exec(f"cdp('Page.navigate', url={url!r}); wait_for_load()", "other")
            asked.clear()
            out = call("browser_vault_save_login", {"session": "other"})
            check(f"save_login refuses a {url.split(':')[0]}: tab and asks nobody", out.get("success") is False
                  and out.get("error_type") == "not_a_website" and not asked, (out.get("error") or "")[:160])
            out = call("browser_vault_enter_code", {"session": "other"})
            check(f"enter_code refuses a {url.split(':')[0]}: tab", out.get("error_type") == "not_a_website", (out.get("error") or "")[:120])

        if handle:
            # Fill in session kajabi after another session ran: the fill and its origin check use kajabi's tab.
            _exec("cdp('Runtime.evaluate', expression=\"document.querySelector('input[name=pw]').value=''\")", "kajabi")
            out = call("browser_vault_fill", {"handle": handle, "session": "kajabi"})
            check("fill(session=kajabi) fills kajabi's tab while another session was used last",
                  out.get("success") is True and _page_value("kajabi", "input[name=pw]") == password, json.dumps(out)[:200])
            # kajabi's current tab moves to the decoy origin: the fill refuses there; it does not hop to another tab.
            _open(decoy + "/login", "kajabi")
            out = call("browser_vault_fill", {"handle": handle, "session": "kajabi"})
            check("fill refuses when the session's tab is on another origin (no tab hopping)",
                  out.get("error_type") == "origin_mismatch" and _page_value("kajabi", "input[name=pw]") == "", json.dumps(out)[:200])
            # Kajabi's shadow-DOM password box: found, filled with the native setter, heard through the shadow root.
            _open(origin + "/shadow-login", "kajabi")
            out = call("browser_vault_fill", {"handle": handle, "session": "kajabi"})
            shadow_pw = "document.querySelector('pds-input[type=password]').shadowRoot.querySelector('input')"
            heard = _exec("print(js(\"[document.body.dataset.heard, document.body.dataset.changed, "
                          "document.querySelector('form > input[type=password]').value.length].join('|')\"))",
                          "kajabi")["output"].strip()
            check("fill finds and fills a password box inside an open shadow root (Kajabi)",
                  out.get("success") is True and _page_value("kajabi", shadow_pw, raw=True) == password, json.dumps(out)[:200])
            check("…the page hears input and change (composed, bubbling); the hidden confirmation stays empty",
                  heard == "input|yes|0", heard)
            asked.clear()
            out = call("browser_vault_save_login", {"session": "kajabi"})
            check("save_login on the shadow-DOM page fills the shadow password box",
                  (out.get("fill") or {}).get("success") is True, json.dumps(out.get("fill") or out)[:200])
        generated = _set_password_checks(origin, call, seen)
        stored = [m.origin for m in get_vault_store().list_items()]
        check("no vault item is bound to a non-website origin", all(o.startswith("https://") for o in stored), ", ".join(stored))
    finally:
        vault_unlock.set_save_login_prompt_callback(None)
        vault_unlock.set_unlock_prompt_callback(None)
        SUPERVISOR_REGISTRY.stop_all()
        try:
            from tools.browser_tool_lifecycle import cleanup_all_browsers
            cleanup_all_browsers()
        except Exception:
            pass
        srv.shutdown()
        _stop_harness_daemons(HOME / "bh")

    hermes_logging.flush_log_queue()
    leaks = [str(f.relative_to(HOME)) for f in HOME.rglob("*") if f.is_file() and not f.is_symlink()
             and any(pw.encode() in f.read_bytes() for pw in generated)]
    check("no generated password in any file under the temp home (DEBUG logs, harness logs, vault)",
          generated and not leaks, ", ".join(leaks[:5]) or f"{sum(1 for f in HOME.rglob('*') if f.is_file())} files")
    check("…nor in any tool result or browser_exec output", generated and not any(pw in out for pw in generated
                                                                                   for out in seen + [n for _, _, n in results]))
    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
