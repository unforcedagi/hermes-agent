"""skills.load_guidance: 'light' swaps the err-on-loading rule for a knowledge-gap rule (T-132)."""

import agent.prompt_builder as pb


def _render(monkeypatch, cfg):
    monkeypatch.setattr(pb, "_config_readonly", lambda what: cfg)
    monkeypatch.setattr("agent.oneshot_footprint.is_single_query_session", lambda: False)
    return pb._render_skills_index({"creative": [("frontend-design", "Design pages.")]}, {}, None, None)


def test_default_is_strict(monkeypatch):
    out = _render(monkeypatch, {})
    assert "you MUST load it" in out
    assert "- frontend-design: Design pages." in out


def test_light_guidance(monkeypatch):
    out = _render(monkeypatch, {"skills": {"load_guidance": "light"}})
    assert "you MUST load it" not in out
    assert "knowledge you lack" in out
    assert "<available_skills>" in out and "- frontend-design: Design pages." in out


def test_unknown_value_stays_strict(monkeypatch):
    assert "you MUST load it" in _render(monkeypatch, {"skills": {"load_guidance": "weird"}})


def test_default_registered():
    from hermes_cli.config_defaults import DEFAULT_CONFIG
    assert DEFAULT_CONFIG["skills"]["load_guidance"] == "strict"
