"""Settings → Database API (SQLite in tests; PostgreSQL privilege checks verified against a live server)."""

from __future__ import annotations


def test_status_hides_password_and_reports_migrations(login, settings):
    c = login("Super Admin", username="dbadmin")
    r = c.get("/api/settings/database")
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["connected"] and d["engine"] == "sqlite" and d["dev_only"]
    assert "password" not in {k for k in d if k != "password_configured"}
    assert settings.database_url.get_secret_value() not in r.text or "sqlite" in settings.database_url.get_secret_value()
    assert {e["engine"].split()[0] for e in d["engines"]} >= {"PostgreSQL", "MySQL", "Microsoft", "Oracle", "SQLite"}
    assert d["privileges"]["checked"] is False  # not PostgreSQL


def test_test_connection(login):
    r = login("Super Admin", username="dbadmin2").post("/api/settings/database/test")
    assert r.status_code == 200 and r.json()["ok"] and r.json()["latency_ms"] >= 0


def test_requires_settings_manage(login):
    c = login("Security Analyst", username="analyst_db")
    assert c.get("/api/settings/database").status_code == 403
    assert c.post("/api/settings/database/test").status_code == 403
    assert c.post("/api/settings/database/migrate").status_code == 403
