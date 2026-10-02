"""Anthropic's OAuth usage API reports utilization as a percent (0-100), not a fraction.

Regression: fraction=True scaled 1.0 (1%) to 100%, so a fresh week read as maxed out.
"""
from agent import account_usage as au


def test_one_percent_stays_one_percent(monkeypatch):
    monkeypatch.setattr(au, "resolve_anthropic_token", lambda: "sk-ant-oat01-x")
    monkeypatch.setattr(au, "_is_oauth_token", lambda t: True)
    monkeypatch.setattr(au, "_get_json", lambda *a, **k: {
        "five_hour": {"utilization": 18.0, "resets_at": None},
        "seven_day": {"utilization": 1.0, "resets_at": None},
        "seven_day_opus": {"utilization": 0.5, "resets_at": None},
    })
    snap = au._fetch_anthropic_account_usage()
    got = {w.label: w.used_percent for w in snap.windows}
    assert got == {"Current session": 18.0, "Current week": 1.0, "Opus week": 0.5}
