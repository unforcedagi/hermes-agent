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
    @pytest.mark.parametrize("autocomplete", ["new-password", ""])
    def test_kajabi_shadow_box_and_its_hidden_confirmation(self, autocomplete):
        """The shadow-root input counts in its host's form (the inspection reports it so); the hidden confirmation sits
        in the same light-DOM form. Both take the password, also when the box itself carries no new-password hint."""
        controls = [_c(0, "hidden", "_method", form=0, hidden=True),
                    _c(1, "hidden", "user[reset_password_token] user_reset_password_token", form=0, hidden=True),
                    _c(2, "hidden", "user[password_confirmation]", form=0, hidden=True),
                    _c(3, "password", "user[password] user_password", autocomplete=autocomplete, form=0)]
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

    @pytest.mark.parametrize("label", ["Verify your password", "Confirm password", "Re-enter password"])
    def test_a_lone_confirm_style_box_is_a_re_authentication_prompt(self, label):
        assert _targets([_c(0, "password", "pw", label)]) == []

    def test_a_change_page_whose_current_box_is_labelled_just_password(self):
        controls = [_c(0, "password", "password", "Password"), _c(1, "password", "new", "New password"),
                    _c(2, "password", "again", "Confirm new password")]
        assert _targets(controls) == [(1, "new-password"), (2, "new-password")]

    def test_no_forms_a_sign_in_box_beside_a_sign_up_box(self):
        controls = [_c(0, "password", "pw", "Password", form=None), _c(1, "password", "new_pw", "Create password", form=None)]
        assert _targets(controls) == [(1, "new-password")]

    def test_only_autocomplete_on_a_lone_box_is_weak_evidence(self):
        """Some sign-in pages mark their password box new-password to block autofill."""
        lone = classify_new_password_controls([_c(0, "email", "email"), _c(1, "password", "pw", autocomplete="new-password")])
        labelled = classify_new_password_controls([_c(1, "password", "pw", "Create a password", "new-password")])
        assert [t.score for t in lone] == [80] and [t.score for t in labelled] == [100]

    def test_a_hidden_register_tab_does_not_turn_the_sign_in_box_into_a_target(self):
        """No forms on the page (an SPA): the visible sign-in box and an unrendered Register panel's boxes."""
        controls = [_c(0, "email", "email", form=None), _c(1, "password", "password", "Password", form=None),
                    _c(2, "password", "confirm", "Confirm password", form=None, hidden=True)]
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
     "formIndex": 0},
]
SIGN_IN = [
    {"index": 0, "type": "email", "name": "user[email]", "label": "", "autocomplete": "username", "formIndex": 0},
    {"index": 1, "type": "password", "name": "user[password]", "label": "Password", "autocomplete": "current-password",
     "formIndex": 0},
]


class _FakePage:
    """One tab as the supervisor sees it: answers the address read, the inspection and the fill. ``takes`` is how
    many targets end up holding the value (None = all of them)."""

    def __init__(self, url, controls, takes=None, navigated=False, raises=False):
        self.url, self.controls, self.takes, self.navigated, self.raises = url, controls, takes, navigated, raises
        self.written: list[dict] = []

    def focus_page(self, origin, accept=None):
        return {"ok": True, "url": self.url}

    def evaluate_runtime(self, expression):
        if expression == "window.location.href":
            return {"ok": True, "result": self.url}
        if "getComputedStyle" in expression:  # the inspection; unrendered inputs only when it asks for them
            wanted = self.controls if "const includeHidden = true" in expression else \
                [c for c in self.controls if not c.get("hidden")]
            return {"ok": True, "result": json.dumps(wanted)}
        fills = json.loads(re.search(r"const fills = (\[.*?\]);\n", expression).group(1))
        if self.navigated:
            return {"ok": True, "result": json.dumps({"refused": "origin_changed", "found": "https://evil.test"})}
        if self.raises:
            raise ConnectionError(f"websocket closed while evaluating {expression[:4000]}")
        self.written = fills
        taken = len(fills) if self.takes is None else self.takes
        if taken < len(fills) and "if (true && matched !== fills.length)" in expression:  # all_or_nothing
            self.written = []
            return {"ok": True, "result": json.dumps({"filled": 0, "matched": taken, "cleared": True})}
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


@pytest.mark.parametrize("identifier", ["", "   ", "agi @unforced.test"])
def test_an_identifier_is_required(store, page, identifier):
    out = json.loads(_set_password(identifier=identifier))
    assert out["success"] is False and out["error_type"] in ("identifier_required", "identifier_invalid"), out
    assert page.written == [] and store.list_items() == []


def test_the_agents_own_username_is_never_masked(store, page):
    """The agent chose it, so the echo-hiding heuristic for usernames a person typed does not apply."""
    from tools import browser_vault_tool

    out = json.loads(_set_password(identifier="UniBot2026"))
    assert out["success"] is True and out["identifier"] == "UniBot2026", out
    assert json.loads(browser_vault_tool.browser_vault_list())["items"][0]["identifier"] == "UniBot2026"


@pytest.mark.parametrize("url", ["http://app.kajabi.test/password/edit", "about:blank"])
def test_only_https_pages(store, page, url):
    page.url = url
    out = json.loads(_set_password(identifier="agi@unforced.test"))
    assert out["success"] is False and out["error_type"] in ("not_https", "not_a_website"), out
    assert page.written == [] and store.list_items() == []


@pytest.mark.parametrize("failure", [{"takes": 1}, {"navigated": True}, {"raises": True}])
def test_the_vault_changes_only_when_the_page_took_the_password(store, page, failure):
    """A new login is not left behind, and an earlier generated one keeps its password, when the fill did not land;
    an error from the browser comes back without the password."""
    earlier = store.add_item("login", "kajabi", {"identifier_type": "email", "identifier": "agi@unforced.test",
                                                 "password": "the-old-one-77"}, origin="https://app.kajabi.test",
                             generated=True)
    other = store.add_item("login", "kajabi", {"identifier_type": "email", "identifier": "someone@else.test",
                                               "password": "theirs-88"}, origin="https://app.kajabi.test")
    for key, value in failure.items():
        setattr(page, key, value)
    raw = _set_password(identifier="agi@unforced.test")
    assert json.loads(raw)["success"] is False, raw
    assert store.resolve_secret(earlier.id)["password"] == "the-old-one-77"
    store.remove_item(earlier.id)
    raw = _set_password(identifier="agi@unforced.test")
    assert json.loads(raw)["success"] is False and [m.id for m in store.list_items()] == [other.id]
    assert store.resolve_secret(other.id)["password"] == "theirs-88"
    assert "const fills" not in raw and "data-hermes-vault-slot" not in raw  # no part of the fill script (it holds the value)
    assert page.written == []  # and the page keeps none of it (all-or-nothing fill)


def test_on_a_page_that_only_might_be_a_new_password_page_a_saved_login_is_kept(store, page):
    page.controls = [SIGN_IN[0], dict(SIGN_IN[1], autocomplete="new-password", label="")]
    earlier = store.add_item("login", "kajabi", {"identifier_type": "email", "identifier": "agi@unforced.test",
                                                 "password": "the-old-one-77"}, origin="https://app.kajabi.test",
                             generated=True)
    out = json.loads(_set_password(identifier="agi@unforced.test"))
    assert out["error_type"] == "not_clearly_a_new_password_page", out
    assert page.written == [] and store.resolve_secret(earlier.id)["password"] == "the-old-one-77"
    store.remove_item(earlier.id)
    assert json.loads(_set_password(identifier="agi@unforced.test"))["success"] is True  # a fresh sign-up is fine


def test_a_login_a_person_saved_is_replaced_only_when_they_agree(store, page):
    """save_login / `hermes vault add` items hold a password a person typed and may still use: the user is asked
    (one tap, the approval surface the card fill uses); headless sessions and a no keep it."""
    saved = store.add_item("login", "kajabi", {"identifier_type": "email", "identifier": "Agi@Unforced.test",
                                               "password": "typed-by-aaron-1"}, origin="https://app.kajabi.test")
    asked = []
    with patch("tools.approval_prompt.request_elicitation_consent", lambda *a, **k: asked.append(a) or "decline"):
        out = json.loads(_set_password(identifier="agi@unforced.test"))
    assert out["error_type"] == "login_saved_by_person" and "never remove it yourself" in out["error"], out
    assert len(asked) == 1 and page.written == [] and store.resolve_secret(saved.id)["password"] == "typed-by-aaron-1"
    with patch("tools.approval_prompt.request_elicitation_consent", lambda *a, **k: "accept"):
        out = json.loads(_set_password(identifier="agi@unforced.test"))
    [meta] = store.list_items()
    assert out["success"] is True and out["handle"] == saved.id and meta.generated, out
    assert store.resolve_secret(saved.id)["password"] != "typed-by-aaron-1"


def test_the_password_fits_the_fields_maxlength(store, page):
    page.controls = [dict(KAJABI[2], maxLength=16), KAJABI[1]]
    out = json.loads(_set_password(identifier="agi@unforced.test"))
    assert out["success"] is True, out
    assert len(store.resolve_secret(out["handle"])["password"]) == 16
    page.controls = [dict(KAJABI[2], maxLength=6), KAJABI[1]]
    store.remove_item(out["handle"])
    assert json.loads(_set_password(identifier="agi@unforced.test"))["error_type"] == "password_too_short"
    assert store.list_items() == []


SIGN_UP = [  # what the login classifier alone reads as an email + a current password
    {"index": 0, "type": "email", "name": "email", "label": "Email", "autocomplete": "", "formIndex": 0},
    {"index": 1, "type": "password", "name": "password", "label": "Password", "autocomplete": "", "formIndex": 0},
    {"index": 2, "type": "password", "name": "password2", "label": "Confirm password", "autocomplete": "", "formIndex": 0},
]


KAJABI_NO_HINT = [KAJABI[0], KAJABI[1], dict(KAJABI[2], autocomplete="")]  # only the hidden confirmation says so


@pytest.mark.parametrize("controls", [KAJABI, KAJABI_NO_HINT, SIGN_UP], ids=["kajabi", "kajabi-no-hint", "sign-up"])
def test_fill_never_types_a_saved_password_into_a_new_password_box(store, page, controls):
    """The 11-02 dead end (fill answered "No login form fields were found" on Kajabi's reset page), and a sign-up form
    whose plain "Password" box the login classifier alone would have filled with the saved password."""
    from tools import browser_vault_tool

    page.controls = controls
    meta = store.add_item("login", "kajabi", {"identifier_type": "email", "identifier": "agi@unforced.test",
                                              "password": "pw-77-x"}, origin="https://app.kajabi.test")
    out = json.loads(browser_vault_tool.browser_vault_fill(meta.id, task_id="t1"))
    assert out["success"] is False and out["error_type"] == "new_password_page" and "set_password" in out["error"], out
    assert page.written == []
