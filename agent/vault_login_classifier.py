"""Login / checkout form control classifier for vault autofill.

Python port (~170 LOC) of Merit-Systems/OpenInstinct's
``lib/manager/server/kernel-login-autofill.ts`` (MIT). Classifies visible
input controls on a page into login-autofill tokens. The vault fill path
uses the classification to select the single best current-password control
(the identifier is agent-visible metadata and is typed by the agent
itself via normal input tools).

Scoring:
- exact autocomplete-token match ................ 100
- type=password (not new/confirm/create/repeat) .. 90
- type=email / type=tel .......................... 85
- label/name regex heuristics .................. 70-75
Hard exclusions: autocomplete ``new-password`` / ``one-time-code``, and
label/name text matching ``(new|confirm|create|repeat)\\s*password``.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

LOGIN_AUTOFILL_TOKENS = ("username", "email", "tel", "current-password")

# Payment / address autocomplete tokens (WHATWG) the checkout fill targets. ``cc-exp`` (combined
# MM/YY) is derived at fill time from exp_month + exp_year. Field-name/label heuristics below back
# up sites that omit autocomplete attributes.
PAYMENT_AUTOFILL_TOKENS = ("cc-number", "cc-name", "cc-exp", "cc-exp-month", "cc-exp-year", "cc-csc")
ADDRESS_AUTOFILL_TOKENS = ("address-line1", "address-line2", "address-level2", "address-level1",
                           "postal-code", "country-name", "country")
_CHECKOUT_HEURISTICS = (
    (re.compile(r"\b(?:card\s*number|cardnumber|ccnumber|cc\s*num|pan)\b"), "cc-number"),
    (re.compile(r"\b(?:name\s*on\s*card|cardholder|cc\s*name|ccname)\b"), "cc-name"),
    (re.compile(r"\b(?:cvc|cvv|csc|security\s*code|card\s*code)\b"), "cc-csc"),
    (re.compile(r"\b(?:exp(?:iry|iration)?\s*month|exp\s*mm|ccmonth)\b"), "cc-exp-month"),
    (re.compile(r"\b(?:exp(?:iry|iration)?\s*year|exp\s*yy(?:yy)?|ccyear)\b"), "cc-exp-year"),
    (re.compile(r"\b(?:exp(?:iry|iration)?(?:\s*date)?|mm\s*yy|valid\s*thru)\b"), "cc-exp"),
    (re.compile(r"\b(?:address\s*(?:line\s*)?2|apt|suite|unit)\b"), "address-line2"),
    (re.compile(r"\b(?:address(?:\s*line\s*1)?|street)\b"), "address-line1"),
    (re.compile(r"\b(?:city|town|locality)\b"), "address-level2"),
    (re.compile(r"\b(?:state|province|region|county)\b"), "address-level1"),
    (re.compile(r"\b(?:zip|postal|postcode)\b"), "postal-code"),
    (re.compile(r"\b(?:country)\b"), "country-name"),
)

_EXCLUDED_AUTOCOMPLETE = {"new-password", "one-time-code"}

_RE_EXCLUDED_PASSWORD = re.compile(r"\b(?:new|confirm|create|repeat)\s*password\b")
_RE_EMAIL = re.compile(r"\b(?:e[\s-]?mail|email address)\b")
_RE_TEL = re.compile(r"\b(?:phone|telephone|mobile)\b")
_RE_USERNAME = re.compile(
    r"\b(?:user\s*name|username|login|account|member|membership|mileageplus)\b"
)


def _normalize_text(value: str) -> str:
    value = unicodedata.normalize("NFKD", value).lower()
    return re.sub(r"[^a-z0-9]+", " ", value).strip()


@dataclass(frozen=True)
class LoginControl:
    """Descriptor of a visible input control, as inspected in the page."""

    autocomplete: str
    form_index: Optional[int]
    index: int
    label: str
    name: str
    type: str
    max_length: Optional[int] = None
    hidden: bool = False  # not rendered (type=hidden, display:none); reported only by an include_hidden inspection

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "LoginControl":
        form_index = raw.get("formIndex", raw.get("form_index"))
        max_length = raw.get("maxLength", raw.get("max_length"))
        return cls(
            autocomplete=str(raw.get("autocomplete") or ""),
            form_index=int(form_index) if form_index is not None else None,
            index=int(raw.get("index") or 0),
            label=str(raw.get("label") or ""),
            name=str(raw.get("name") or ""),
            type=str(raw.get("type") or ""),
            max_length=int(max_length) if max_length is not None else None,
            hidden=bool(raw.get("hidden")),
        )


@dataclass(frozen=True)
class ClassifiedLoginControl:
    control: LoginControl
    score: int
    token: str


def classify_login_control(control: LoginControl) -> Optional[ClassifiedLoginControl]:
    """Classify one control, or return None if it is not a login fill target."""
    autocomplete_tokens = [
        t for t in control.autocomplete.lower().split() if t
    ]
    if any(t in _EXCLUDED_AUTOCOMPLETE for t in autocomplete_tokens):
        return None

    for token in LOGIN_AUTOFILL_TOKENS:
        if token in autocomplete_tokens:
            return ClassifiedLoginControl(control, 100, token)

    searchable = _normalize_text(
        " ".join(part for part in (control.name, control.label) if part)
    )
    if _RE_EXCLUDED_PASSWORD.search(searchable):
        return None
    if control.type == "password":
        return ClassifiedLoginControl(control, 90, "current-password")
    if control.type == "email":
        return ClassifiedLoginControl(control, 85, "email")
    if control.type == "tel":
        return ClassifiedLoginControl(control, 85, "tel")
    if _RE_EMAIL.search(searchable):
        return ClassifiedLoginControl(control, 75, "email")
    if _RE_TEL.search(searchable):
        return ClassifiedLoginControl(control, 75, "tel")
    if _RE_USERNAME.search(searchable):
        return ClassifiedLoginControl(control, 70, "username")
    return None


_RE_OTP = re.compile(
    r"\b(?:one[\s-]?time|verification|security|auth(?:entication|enticator)?|2fa|two[\s-]?factor|mfa|totp|otp|"
    r"passcode|sms)\b.*\b(?:code|pin|token)\b|\b(?:otp|totp|2fa|mfa|verification\s*code|passcode)\b"
)


def classify_otp_controls(controls: List[LoginControl]) -> List[ClassifiedLoginControl]:
    """The controls that take a second-factor code. ``autocomplete=one-time-code`` is authoritative;
    otherwise a text/tel/number input whose name/label says code/OTP/2FA/verification. Some sites split
    the code into one input per digit (``maxlength=1`` boxes): they are returned in DOM order and the
    fill spreads the code across them."""
    out: List[ClassifiedLoginControl] = []
    for c in controls:
        tokens = c.autocomplete.lower().split()
        if "one-time-code" in tokens:
            out.append(ClassifiedLoginControl(c, 100, "one-time-code"))
            continue
        if c.type not in ("text", "tel", "number", "password", ""):
            continue
        if _RE_OTP.search(_normalize_text(" ".join(p for p in (c.name, c.label) if p))):
            out.append(ClassifiedLoginControl(c, 70, "one-time-code"))
    return out


def select_password_fill(
    classified: List[ClassifiedLoginControl],
    password: str,
) -> List[Dict[str, Any]]:
    """Select the single best current-password control to fill.

    The vault fill path is password-only: the identifier is agent-visible
    metadata and is typed by the agent via normal input tools. This picks
    the highest-scoring ``current-password`` control (ties broken by DOM
    order) and returns ``[{"index": int, "token": "current-password",
    "value": password}]`` or ``[]`` when no password field exists.
    """
    passwords = [c for c in classified if c.token == "current-password"]
    if not passwords or not password:
        return []
    best_password = sorted(
        passwords, key=lambda c: (-c.score, c.control.index)
    )[0]
    return [
        {
            "index": best_password.control.index,
            "token": "current-password",
            "value": password,
        }
    ]


# A box that asks for a password nobody has yet. "Confirm/verify/repeat password" alone is also what a re-authentication
# prompt says, so those count only next to another password box (see classify_new_password_controls).
_RE_NEW_PASSWORD = re.compile(r"\b(?:new|create|choose|set)\s*(?:a\s*|your\s*)?(?:new\s*)?password\b")
_RE_CONFIRM_PASSWORD = re.compile(r"\bpassword\s*(?:again|confirm|confirmation|repeat)\b|"
                                  r"\b(?:confirm|repeat|retype|re\s*enter|verify)\s*(?:your\s*)?(?:new\s*)?password\b")
_RE_CURRENT_PASSWORD = re.compile(r"\b(?:current|old|existing|present)\s*password\b")


def classify_new_password_controls(controls: List[LoginControl]) -> List[ClassifiedLoginControl]:
    """The fields of a set-password page (sign-up, invite, reset): ``[]`` on a sign-in page.

    Per form (an input inside a web component counts in its host's form; inputs outside any form share one group): a
    password box is "new" when its autocomplete says ``new-password`` or its label says new/create/choose password,
    and confirm-style boxes (confirm/repeat/verify password, password confirmation) join it. Without a "new" box, each
    confirmation pairs with the nearest plain box: a sign-up "Password" + "Confirm" pair, or Kajabi's box with its
    ``type=hidden`` ``user[password_confirmation]`` (synced by its <pds-input>). So a lone "Verify your password" is a
    re-authentication prompt, and a sign-in box beside a sign-up pair stays out. Tokens: ``new-password`` for the
    boxes taking the new password, ``new-password-sync`` for a hidden confirmation (only ``type=hidden`` inputs named
    like one; an unrendered password box, e.g. a hidden Register tab, is never filled), and ``current-password`` for
    the current box of a change form (``current-password`` or "current/old password"), which set_password fills
    only with the saved password it replaces, and ``unclear-password`` for a plain box beside a "new" one: it may be
    the current password or a confirmation ("Type it again"), and set_password refuses rather than guess.

    New-password scores are 100, or 80 when the only evidence is ``autocomplete=new-password`` on a lone box with no
    label, confirmation or current box: some sign-in pages mark their password box that way to block autofill."""
    def text(c: LoginControl) -> str:
        return _normalize_text(" ".join(p for p in (c.name, c.label) if p))

    forms: Dict[Optional[int], Dict[str, List[LoginControl]]] = {}
    for c in controls:
        tokens, t = c.autocomplete.lower().split(), text(c)
        if "one-time-code" in tokens:
            continue
        if c.hidden:
            if c.type != "hidden" or not _RE_CONFIRM_PASSWORD.search(t):
                continue
            kind = "sync"
        elif c.type != "password":
            continue
        elif "current-password" in tokens or _RE_CURRENT_PASSWORD.search(t):
            kind = "current"
        elif "new-password" in tokens or _RE_NEW_PASSWORD.search(t):
            kind = "new"
        else:
            kind = "confirm" if _RE_CONFIRM_PASSWORD.search(t) else "plain"
        forms.setdefault(c.form_index, {}).setdefault(kind, []).append(c)

    def by_index(cs: List[LoginControl]) -> List[LoginControl]:
        return sorted(cs, key=lambda c: c.index)

    out: List[ClassifiedLoginControl] = []
    for group in forms.values():
        new, confirm, plain, sync, current = (group.get(k, []) for k in ("new", "confirm", "plain", "sync", "current"))
        unclear: List[LoginControl] = []
        if new:  # a plain box beside a new one may be the current password or a confirmation: never guessed
            visible, unclear = new + confirm, plain
        else:
            paired = {min(plain, key=lambda p: (abs(p.index - c.index), p.index > c.index)).index
                      for c in confirm + sync} if plain else set()
            visible = [p for p in plain if p.index in paired] + (confirm if paired else [])
        if not visible:
            continue
        weak = (len(visible) == 1 and not sync and not current
                and not _RE_NEW_PASSWORD.search(text(visible[0])))  # autocomplete=new-password is all there is
        out += [ClassifiedLoginControl(c, 80 if weak else 100, "new-password") for c in by_index(visible)]
        out += [ClassifiedLoginControl(c, 100, "new-password-sync") for c in by_index(sync)]
        out += [ClassifiedLoginControl(c, 100, "current-password") for c in by_index(current)]
        out += [ClassifiedLoginControl(c, 0, "unclear-password") for c in by_index(unclear)]
    return out


def classify_checkout_control(control: LoginControl) -> Optional[ClassifiedLoginControl]:
    """Classify one control as a payment/address fill target (autocomplete token exact match 100,
    label/name heuristic 70), or None. Password/email inputs are never checkout targets."""
    tokens = [t for t in control.autocomplete.lower().split() if t]
    for token in PAYMENT_AUTOFILL_TOKENS + ADDRESS_AUTOFILL_TOKENS:
        if token in tokens:
            return ClassifiedLoginControl(control, 100, "country-name" if token == "country" else token)
    if control.type in ("password", "email"):
        return None
    searchable = _normalize_text(" ".join(part for part in (control.name, control.label) if part))
    for pattern, token in _CHECKOUT_HEURISTICS:
        if pattern.search(searchable):
            return ClassifiedLoginControl(control, 70, token)
    return None


def select_checkout_fills(classified: List[ClassifiedLoginControl], secret: Dict[str, str],
                          field_tokens: Dict[str, str]) -> List[Dict[str, Any]]:
    """Map a payment/address secret payload onto the best control per autocomplete token.

    ``field_tokens`` is ``PAYMENT_FIELDS`` / ``ADDRESS_FIELDS`` (agent/vault_store.py). A combined
    ``cc-exp`` control gets ``MM/YY`` from exp_month + exp_year and then suppresses the separate
    month/year fills. Returns ``[{"index", "token", "value"}]``: one control per token, highest
    score then DOM order.
    """
    values: Dict[str, str] = {tok: secret[f] for f, tok in field_tokens.items() if secret.get(f)}
    if "cc-exp-month" in values and "cc-exp-year" in values:
        values["cc-exp"] = f"{values['cc-exp-month'].zfill(2)}/{values['cc-exp-year'][-2:]}"
    fills: List[Dict[str, Any]] = []
    for token, value in values.items():
        candidates = sorted((c for c in classified if c.token == token), key=lambda c: (-c.score, c.control.index))
        if candidates:
            fills.append({"index": candidates[0].control.index, "token": token, "value": value})
    if any(f["token"] == "cc-exp" for f in fills):
        fills = [f for f in fills if f["token"] not in ("cc-exp-month", "cc-exp-year")]
    return fills


# JS expression evaluated in the page to inspect candidate input controls.
# Ported from OpenInstinct's nativeLoginControlInspectionExpression.
# Inspection stamps every input with ``<nonce>:<index>`` under a per-inspection attribute; the fill
# script resolves targets by the stamp of ITS OWN inspection instead of re-querying by position, so
# neither a DOM reflow nor a second inspection in between can redirect the password into another field.
INSPECTION_STAMP_ATTR = "data-hermes-vault-slot"


def build_otp_fills(otp_controls: List[ClassifiedLoginControl], code: str) -> List[Dict[str, Any]]:
    """One fill per box. Default: the single best-scoring code field takes the whole code.

    Per-digit entry only when the page unmistakably uses it: exactly len(code) OTP controls that are all
    ``maxlength=1``, all in the same form, and adjacent in DOM order (the classic N-box widget). Anything
    looser (several code-like inputs scattered over a page) gets ONE field, never a digit sprayed across
    unrelated inputs."""
    best = max(otp_controls, key=lambda c: c.score)
    boxes = sorted((c for c in otp_controls if c.control.max_length == 1), key=lambda c: c.control.index)
    if (len(boxes) == len(code)
            and len({b.control.form_index for b in boxes}) == 1
            and all(b.control.index - a.control.index == 1 for a, b in zip(boxes, boxes[1:]))):
        return [{"index": b.control.index, "token": "one-time-code", "value": ch} for b, ch in zip(boxes, code)]
    return [{"index": best.control.index, "token": "one-time-code", "value": code}]


def build_inspection_js(nonce: str, include_hidden: bool = False) -> str:
    """``include_hidden``: also report unrendered inputs (``hidden: true``): the confirmation a web component keeps in
    a ``type=hidden`` input marks a set-password form, and set_password fills it. Nothing else ever targets them."""
    return (_LOGIN_CONTROL_INSPECTION_JS_TEMPLATE.replace("__NONCE__", json.dumps(nonce))
            .replace("__INCLUDE_HIDDEN__", "true" if include_hidden else "false"))


# Every element matching ``sel`` in the document AND in every open shadow root, in tree order (a shadow root's
# content right after its host). Design systems put login inputs inside web components (Kajabi's <pds-input>,
# 11-02): document.querySelectorAll never sees them. Closed shadow roots stay out of reach, as they should.
_DEEP_QUERY_JS = """const deepAll = (sel, root = document) => {
    const out = [];
    for (const el of root.querySelectorAll("*")) {
      if (el.matches(sel)) out.push(el);
      if (el.shadowRoot) out.push(...deepAll(sel, el.shadowRoot));
    }
    return out;
  };"""


def build_unstamp_js() -> str:
    """Removes every inspection stamp (open shadow roots included): run when a vault call stops after inspecting a
    page without filling it, so no marker is left for later DOM reads to address the fields by."""
    return ("(() => { " + _DEEP_QUERY_JS + ' deepAll("[data-hermes-vault-slot]").forEach((n) => '
            'n.removeAttribute("data-hermes-vault-slot")); return true; })()')


def build_probe_js(selector: str) -> str:
    """A JS expression, true when an element matching ``selector`` exists in the page or an open shadow root."""
    return "(() => { " + _DEEP_QUERY_JS + " return deepAll(" + json.dumps(selector) + ").length > 0; })()"


_LOGIN_CONTROL_INSPECTION_JS_TEMPLATE = """(() => {
  const nonce = __NONCE__;
  const includeHidden = __INCLUDE_HIDDEN__;
  __DEEP_QUERY__
  const elements = deepAll("input, select");
  const forms = Array.from(document.forms);
  elements.forEach((element, index) => element.setAttribute("data-hermes-vault-slot", nonce + ":" + index));
  const out = elements.flatMap((element, index) => {
    if (element.disabled || element.readOnly) return [];
    if (["submit", "button", "reset", "file", "image", "checkbox", "radio"].includes(element.type)) return [];
    const style = getComputedStyle(element);
    const hidden = element.type === "hidden" || style.display === "none" || style.visibility === "hidden"
      || element.getClientRects().length === 0;
    if (hidden && !includeHidden) return [];
    const labels = element.labels ? Array.from(element.labels, (l) => l.textContent || "") : [];
    const root = element.getRootNode();
    const ariaText = (element.getAttribute("aria-labelledby") || "")
      .split(/\\s+/).filter(Boolean)
      .map((id) => { const n = (root.getElementById ? root : document).getElementById(id); return n ? (n.textContent || "") : ""; })
      .join(" ");
    // Inside a web component the host carries the label/name the page author wrote (<pds-input label="Password">).
    const host = root instanceof ShadowRoot ? root.host : null;
    const hostText = host ? ["label", "aria-label", "placeholder", "name"].map((a) => host.getAttribute(a) || "").join(" ") : "";
    // Form association stops at a shadow boundary: an input inside a web component counts in its host's form
    // (through nested components too).
    let form = element.form;
    for (let h = host; !form && h; h = h.getRootNode() instanceof ShadowRoot ? h.getRootNode().host : null) {
      form = h.closest ? h.closest("form") : null;
    }
    const resolvedFormIndex = form ? forms.indexOf(form) : -1;
    return [{
      autocomplete: element.autocomplete || "",
      formIndex: resolvedFormIndex >= 0 ? resolvedFormIndex : null,
      index,
      maxLength: element.maxLength > 0 ? element.maxLength : null,
      label: [
        ...labels,
        element.getAttribute("aria-label") || "",
        ariaText,
        element.getAttribute("placeholder") || "",
        element.getAttribute("title") || "",
        hostText,
      ].join(" "),
      name: [element.name, element.id].join(" "),
      type: element.tagName === "SELECT" ? "select" : (element.type || ""),
      ...(hidden ? { hidden: true } : {}),
    }];
  });
  return JSON.stringify(out);
})()""".replace("__DEEP_QUERY__", _DEEP_QUERY_JS)


def build_fill_js(fills: List[Dict[str, Any]], expected_origin: str, nonce: str = "", all_or_nothing: bool = False) -> str:
    """Build a JS expression that fills the selected controls and reports only a count. The
    returned expression never echoes the values back.

    ``expected_origin`` is asserted against ``window.location.origin`` synchronously inside the SAME
    evaluated script, immediately before any write. If the page navigated between inspection and fill
    (TOCTOU), the script writes nothing and returns ``{"refused": "origin_changed", "found": <actual>}``:
    proof scope equals mutation scope (#88706). Targets resolve by the ``<nonce>:<index>`` stamp of
    THIS inspection, in the document and in open shadow roots alike; values go in through the native value setter
    and ``input``/``change`` fire bubbling AND composed, so a listener outside a web component hears them. A
    ``current-password`` / ``new-password`` fill additionally requires ``type=password`` (``new-password-sync``:
    password or hidden), and ``matched`` counts the targets still holding their value after all writes
    (``all_or_nothing``: unless every target does, each written field is emptied again and ``cleared`` set); ``<select>``
    controls (country, state, expiry month) match an option by value or visible text. No marker is
    left on filled controls so later model-driven DOM reads cannot address them deterministically.
    """
    payload = json.dumps(
        [{"index": f["index"], "token": f.get("token", "current-password"), "value": f["value"]} for f in fills]
    )
    return (_FILL_JS_TEMPLATE.replace("__EXPECTED_ORIGIN__", json.dumps(expected_origin))
            .replace("__FILLS__", payload).replace("__NONCE__", json.dumps(nonce))
            .replace("__ALL_OR_NOTHING__", "true" if all_or_nothing else "false"))


_FILL_JS_TEMPLATE = """(() => {
  const expectedOrigin = __EXPECTED_ORIGIN__;
  if (window.location.origin !== expectedOrigin) {
    return JSON.stringify({ refused: "origin_changed", found: window.location.origin });
  }
  const fills = __FILLS__;
  const nonce = __NONCE__;
  __DEEP_QUERY__
  const stamped = deepAll("[data-hermes-vault-slot]");
  // A password only ever goes into a password box; a set-password confirmation may also be an unrendered input.
  const needsType = {"current-password": ["password"], "new-password": ["password"], "new-password-sync": ["hidden", "password"]};
  const written = [];
  let filled = 0;
  const norm = (t) => String(t || "").trim().toLowerCase();
  for (const f of fills) {
    const el = stamped.find((n) => n.getAttribute("data-hermes-vault-slot") === nonce + ":" + f.index);
    const types = needsType[f.token];
    if (!el || (types && !types.includes(el.type))) continue;
    try {
      if (el.tagName === "SELECT") {
        const want = norm(f.value);
        const opt = Array.from(el.options).find((o) => [o.value, o.textContent].some((t) => norm(t) === want || norm(t) === want.replace(/^0/, "")));
        if (opt) { el.value = opt.value; el.dispatchEvent(new Event("change", { bubbles: true, composed: true })); filled += 1; }
        continue;
      }
      el.focus();
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
      // one-time-code split into single-character boxes: f.value is the slice for THIS box (see build_otp_fills)
      if (setter && setter.set) { setter.set.call(el, f.value); } else { el.value = f.value; }
      el.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, inputType: "insertText" }));
      el.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
      if (el.value.length > 0) filled += 1;
      written.push([el, f.value]);
    } catch (e) { /* skip */ }
  }
  stamped.forEach((n) => n.removeAttribute("data-hermes-vault-slot"));
  // Read back after every write: a component that re-syncs or clears a field on input shows up here.
  const matched = written.filter(([el, value]) => el.value === value).length;
  if (__ALL_OR_NOTHING__ && matched !== fills.length) {
    // A set-password fill that did not land everywhere leaves no half-written password a later submit could set.
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
    for (const [el] of written) {
      if (setter && setter.set) { setter.set.call(el, ""); } else { el.value = ""; }
      el.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, inputType: "deleteContent" }));
      el.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
    }
    return JSON.stringify({ filled: 0, matched, cleared: true });
  }
  return JSON.stringify({ filled, matched });
})()""".replace("__DEEP_QUERY__", _DEEP_QUERY_JS)
