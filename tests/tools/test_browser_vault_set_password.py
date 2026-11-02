"""browser_vault_save_login(set_password=true): a new password for an account the agent owns (T-335).

Kajabi's invite page (app.kajabi.com/password/edit, 11-02) asks for a NEW password: a <pds-input> with the password
box in an open shadow root, plus a ``type=hidden`` ``user[password_confirmation]`` in the light DOM. browser_vault_fill
refuses new-password fields on purpose, and save_login asks a human, but the account is the agent's own. These tests
pin which fields count as "new password", the refusals (no identifier, not https, a sign-in page) and that the vault
only changes when the page took the password. The page itself is faked at the browser boundary (the supervisor's
``evaluate_runtime``); evals/vault_session_live_e2e.py runs the real JS in Chromium.
"""

from __future__ import annotations

import json
import re
from unittest.mock import patch

import pytest

from agent.vault_login_classifier import LoginControl, classify_new_password_controls
from agent.vault_store import VaultStore


def _c(index, type_="password", name="", label="", autocomplete="", form=0, hidden=False):
    return LoginControl(autocomplete=autocomplete, form_index=form, index=index, label=label, name=name, type=type_,
                        hidden=hidden)


def _targets(controls):
    return sorted((t.control.index, t.token) for t in classify_new_password_controls(controls))


class TestWhichFieldsTakeTheNewPassword:
    def test_kajabi_shadow_box_and_its_hidden_confirmation(self):
        """The shadow-root input has no form (form association stops at the shadow boundary); the hidden
        confirmation sits in the light-DOM form. Both take the password."""
        controls = [_c(0, "hidden", "_method", form=0, hidden=True),
                    _c(1, "hidden", "user[reset_password_token] user_reset_password_token", form=0, hidden=True),
                    _c(2, "hidden", "user[password_confirmation]", form=0, hidden=True),
                    _c(3, "password", "user[password] user_password", autocomplete="new-password", form=None)]
        assert _targets(controls) == [(2, "new-password-sync"), (3, "new-password")]

    def test_sign_up_form_with_a_plain_password_and_a_confirm_box(self):
        controls = [_c(0, "email", "email"), _c(1, "password", "password", "Password"),
                    _c(2, "password", "password2", "Confirm password")]
        assert _targets(controls) == [(1, "new-password"), (2, "new-password")]

    def test_change_password_page_leaves_the_current_password_alone(self):
        controls = [_c(0, "password", "current", "Current password", "current-password"),
                    _c(1, "password", "new", "New password", "new-password"),
                    _c(2, "password", "again", "Repeat new password")]
        assert _targets(controls) == [(1, "new-password"), (2, "new-password")]

    @pytest.mark.parametrize("controls", [
        [_c(0, "email", "email", autocomplete="username"), _c(1, "password", "pw", autocomplete="current-password")],
        [_c(0, "text", "login", "Username"), _c(1, "password", "password", "Password")],
        # A hidden field that merely mentions a password is not a confirmation of one.
        [_c(0, "password", "password"), _c(1, "hidden", "password_reset_token", hidden=True)],
    ])
    def test_a_sign_in_page_has_no_target(self, controls):
        assert _targets(controls) == []

    def test_a_hidden_confirmation_alone_is_not_a_new_password_page(self):
        assert _targets([_c(0, "hidden", "user[password_confirmation]", hidden=True)]) == []

    def test_a_sign_in_form_beside_a_sign_up_form_is_not_touched(self):
        controls = [_c(0, "email", "email", form=0), _c(1, "password", "pw", "Password", form=0),
                    _c(2, "email", "email", form=1), _c(3, "password", "new_pw", "Create password", form=1),
                    _c(4, "password", "confirm", "Confirm password", form=1)]
        assert _targets(controls) == [(3, "new-password"), (4, "new-password")]


# ---------------------------------------------------------------------------
# The tool, through the registry, with the page faked at the supervisor
# ---------------------------------------------------------------------------

KAJABI = [  # what the inspection script reports for Kajabi's /password/edit (include_hidden)
    {"index": 0, "type": "hidden", "name": "_method ", "label": "", "autocomplete": "", "formIndex": 0, "hidden": True},
    {"index": 1, "type": "hidden", "name": "user[password_confirmation] ", "label": "", "autocomplete": "",
     "formIndex": 0, "hidden": True},
    {"index": 2, "type": "password", "name": "user[password] user_password", "label": "", "autocomplete": "new-password",
     "formIndex": None},
]
SIGN_IN = [
    {"index": 0, "type": "email", "name": "user[email]", "label": "", "autocomplete": "username", "formIndex": 0},
    {"index": 1, "type": "password", "name": "user[password]", "label": "Password", "autocomplete": "current-password",
     "formIndex": 0},
]


class _FakePage:
    """One tab as the supervisor sees it: answers the address read, the inspection and the fill. ``takes`` is how
    many targets end up holding the value (None = all of them)."""

    def __init__(self, url, controls, takes=None, navigated=False):
        self.url, self.controls, self.takes, self.navigated = url, controls, takes, navigated
        self.written: list[dict] = []

    def focus_page(self, origin, accept=None):
        return {"ok": True, "url": self.url}

    def evaluate_runtime(self, expression):
        if expression == "window.location.href":
            return {"ok": True, "result": self.url}
        if "getComputedStyle" in expression:  # the inspection
            return {"ok": True, "result": json.dumps(self.controls)}
        fills = json.loads(re.search(r"const fills = (\[.*?\]);\n", expression).group(1))
        if self.navigated:
            return {"ok": True, "result": json.dumps({"refused": "origin_changed", "found": "https://evil.test"})}
        self.written = fills
        taken = len(fills) if self.takes is None else self.takes
        return {"ok": True, "result": json.dumps({"filled": taken, "matched": taken})}


@pytest.fixture()
def store(tmp_path):
    return VaultStore(base_dir=tmp_path / "vault")


@pytest.fixture()
def page(monkeypatch, store):
    from tools import browser_vault_tool
    from tools.browser_supervisor import SUPERVISOR_REGISTRY

    fake = _FakePage("https://app.kajabi.test/password/edit?reset_password_token=x", KAJABI)
    monkeypatch.setattr(browser_vault_tool, "_browser_use_mode", lambda: False)
    monkeypatch.setattr(SUPERVISOR_REGISTRY, "get", lambda task_id: fake)
    with patch("agent.vault_store.get_vault_store", return_value=store):
        yield fake


def _set_password(**args):
    from tools.registry import registry

    return registry.dispatch("browser_vault_save_login", {"set_password": True, **args}, task_id="t1")


def test_generates_fills_every_target_and_saves_bound_to_the_page_origin(store, page):
    raw = _set_password(identifier="agi@unforced.test")
    out = json.loads(raw)
    assert out["success"] is True and out["origin"] == "https://app.kajabi.test", out
    [meta] = store.list_items()
    password = store.resolve_secret(meta.id)["password"]
    assert password not in raw
    assert (meta.origin, meta.identifier, meta.id) == ("https://app.kajabi.test", "agi@unforced.test", out["handle"])
    assert sorted((f["index"], f["value"]) for f in page.written) == [(1, password), (2, password)]
    # Strong enough for Kajabi's rule (10+, upper, lower, digit, special) and not reused.
    assert len(password) >= 16 and all(re.search(p, password) for p in ("[a-z]", "[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    json.loads(_set_password(identifier="agi@unforced.test"))
    [again] = store.list_items()  # the same login is updated, not duplicated
    assert again.id == meta.id and store.resolve_secret(meta.id)["password"] != password


def test_a_sign_in_page_is_refused_and_nothing_is_saved(store, page):
    page.controls = SIGN_IN
    out = json.loads(_set_password(identifier="agi@unforced.test"))
    assert out["success"] is False and out["error_type"] == "no_new_password_field", out
    assert "browser_vault_fill" in out["error"] and page.written == [] and store.list_items() == []


@pytest.mark.parametrize("identifier", ["", "   ", "Xk9#mP2$vL7q"])
def test_an_identifier_is_required_and_must_not_read_like_a_password(store, page, identifier):
    out = json.loads(_set_password(identifier=identifier))
    assert out["success"] is False and out["error_type"] in ("identifier_required", "identifier_is_password"), out
    assert identifier.strip() not in out["error"] or not identifier.strip()
    assert page.written == [] and store.list_items() == []


@pytest.mark.parametrize("url", ["http://app.kajabi.test/password/edit", "about:blank"])
def test_only_https_pages(store, page, url):
    page.url = url
    out = json.loads(_set_password(identifier="agi@unforced.test"))
    assert out["success"] is False and out["error_type"] in ("not_https", "not_a_website"), out
    assert page.written == [] and store.list_items() == []


@pytest.mark.parametrize("failure", [{"takes": 1}, {"navigated": True}])
def test_the_vault_changes_only_when_the_page_took_the_password(store, page, failure):
    """A new login is not left behind, and an existing one keeps its password, when the fill did not land."""
    existing = store.add_item("login", "kajabi", {"identifier_type": "email", "identifier": "agi@unforced.test",
                                                  "password": "the-old-one-77"}, origin="https://app.kajabi.test")
    other = store.add_item("login", "kajabi", {"identifier_type": "email", "identifier": "someone@else.test",
                                               "password": "theirs-88"}, origin="https://app.kajabi.test")
    for key, value in failure.items():
        setattr(page, key, value)
    out = json.loads(_set_password(identifier="agi@unforced.test"))
    assert out["success"] is False, out
    assert store.resolve_secret(existing.id)["password"] == "the-old-one-77"
    store.remove_item(existing.id)
    out = json.loads(_set_password(identifier="agi@unforced.test"))
    assert out["success"] is False and [m.id for m in store.list_items()] == [other.id]
    assert store.resolve_secret(other.id)["password"] == "theirs-88"


def test_fill_on_a_new_password_page_says_what_to_do(store, page):
    """The 11-02 dead end: fill answered "No login form fields were found" on Kajabi's reset page."""
    from tools import browser_vault_tool

    meta = store.add_item("login", "kajabi", {"identifier_type": "email", "identifier": "agi@unforced.test",
                                              "password": "pw-77-x"}, origin="https://app.kajabi.test")
    out = json.loads(browser_vault_tool.browser_vault_fill(meta.id, task_id="t1"))
    assert out["success"] is False and out["error_type"] == "new_password_page" and "set_password" in out["error"], out
    assert page.written == []
