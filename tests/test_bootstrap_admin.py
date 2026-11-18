"""Default break-glass account: generated password, created only on an empty installation, forced password change and
MFA enrolment at first sign-in."""

from __future__ import annotations

import re
import sys

import pyotp
import pytest
from fastapi.testclient import TestClient

from exposurecatalyst import bootstrap, deployment
from exposurecatalyst.config import PROJECT_ROOT, Settings
from exposurecatalyst.db.base import Base
from exposurecatalyst.db.session import get_engine, get_session_factory
from exposurecatalyst.models import AppSetting, AuditLog, User

NEW_PW = "Brand-New-Passphrase-42"  # gitleaks:allow - fake test value
GEN_PW = "AbCdEf-GhJkMn-PqRsTu-VwXyZ2"  # gitleaks:allow - fake generated test password


def make(monkeypatch, tmp_path, *, password: str | None = GEN_PW, **extra):
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    if password:
        (secrets_dir / "initial_admin_password").write_text(password + "\n")
    s = Settings(env="test", database_url="sqlite://", cookie_secure=False, log_json=False, log_level="WARNING",
                 ssrf_resolve_dns=False, secrets_dir=secrets_dir, frontend_dist_dir=PROJECT_ROOT / "nonexistent",
                 docs_site_dir=PROJECT_ROOT / "nonexistent", **extra)
    import exposurecatalyst.api.auth as auth_mod
    import exposurecatalyst.main  # noqa: F401
    from exposurecatalyst.security import crypto

    for name, mod in list(sys.modules.items()):
        if name.startswith("exposurecatalyst") and hasattr(mod, "get_settings"):
            monkeypatch.setattr(mod, "get_settings", lambda: s)
    crypto.get_secret_box.cache_clear()
    auth_mod._limiter = None
    from exposurecatalyst.main import create_app

    app = create_app(s)
    Base.metadata.create_all(get_engine())
    return app, s


def test_password_generated_once_typeable_and_optional(tmp_path, monkeypatch):
    for k in ("EXCAT_ENCRYPTION_KEY", "POSTGRES_PASSWORD", "EXCAT_BOOTSTRAP_ADMIN"):
        monkeypatch.delenv(k, raising=False)
    for d in ("SECRETS", "DB_SECRET", "CERTS"):
        monkeypatch.setenv(f"EXCAT_{d}_DIR", str(tmp_path / d.lower()))
    p = bootstrap.Paths.from_env()
    p.secrets.mkdir(parents=True)
    assert "generated" in bootstrap.ensure_initial_admin_password(p)
    f = p.secrets / "initial_admin_password"
    pw = f.read_text().strip()
    assert re.fullmatch(r"([A-Za-z2-9]{6}-){3}[A-Za-z2-9]{6}", pw) and oct(f.stat().st_mode & 0o777) == "0o600"
    assert "kept" in bootstrap.ensure_initial_admin_password(p) and f.read_text().strip() == pw
    monkeypatch.setenv("EXCAT_BOOTSTRAP_ADMIN", "false")
    f.unlink()
    assert bootstrap.ensure_initial_admin_password(p) is None and not f.exists()


def test_created_only_on_empty_installation(monkeypatch, tmp_path, capsys):
    app, s = make(monkeypatch, tmp_path)
    with TestClient(app):
        pass  # startup creates the account
    assert "setup token" not in capsys.readouterr().out  # wizard not needed: a user exists
    with get_session_factory()() as db:
        u = db.query(User).one()
        assert u.username == "breakglass" and u.must_change_password and not u.totp_enabled
        assert [r.name for r in u.roles] == ["Super Admin"] and u.password_hash and "AbCdEf" not in u.password_hash
        assert db.query(AuditLog).filter_by(action="user.created").one().details["via"] == "bootstrap"
        assert deployment.ensure_bootstrap_admin(db, s) is None  # never a second time
        assert db.get(AppSetting, deployment.SETUP_KEY) is None


@pytest.mark.parametrize("variant", ["opt_out", "no_file", "short"])
def test_not_created_without_file_or_when_disabled(monkeypatch, tmp_path, variant):
    kw = {"opt_out": {"bootstrap_admin": False}, "no_file": {"password": None}, "short": {"password": "short"}}[variant]
    app, s = make(monkeypatch, tmp_path, **kw)
    with TestClient(app):
        pass
    with get_session_factory()() as db:
        assert db.query(User).count() == 0
        assert deployment.ensure_setup_token(db, s)  # falls back to the setup-token wizard


def test_first_sign_in_forces_password_change_then_mfa(monkeypatch, tmp_path):
    app, s = make(monkeypatch, tmp_path, require_mfa_for_local_admins=True)
    with TestClient(app) as c:
        r = c.post("/api/auth/login", json={"username": "breakglass", "password": GEN_PW})
        assert r.status_code == 200
        me = r.json()
        assert me["must_change_password"] and me["first_login_pending"]
        c.headers["X-CSRF-Token"] = me["csrf_token"]
        blocked = c.get("/api/admin/users")
        assert blocked.status_code == 403 and blocked.json()["detail"] == "Password change required"
        assert c.get("/api/cves").status_code == 403  # every permissioned route, not only admin ones
        same = c.post("/api/auth/password", json={"current_password": GEN_PW,
                                                  "new_password": GEN_PW})
        assert same.status_code == 422
        r = c.post("/api/auth/password", json={"current_password": GEN_PW,
                                               "new_password": NEW_PW})
        assert r.status_code == 204
        me = c.get("/api/auth/me").json()
        c.headers["X-CSRF-Token"] = me["csrf_token"]
        assert not me["must_change_password"] and me["first_login_pending"]  # MFA still to enrol
        assert c.get("/api/cves").status_code == 200
        assert c.get("/api/admin/users").json()["detail"] == "MFA enrolment required for admin actions"
        secret = c.post("/api/auth/mfa/setup").json()["secret"]
        assert c.post("/api/auth/mfa/enable", json={"totp_code": pyotp.TOTP(secret).now()}).status_code == 204
        assert not c.get("/api/auth/me").json()["first_login_pending"]
        assert c.get("/api/admin/users").status_code == 200
    with TestClient(app) as c2:  # the generated password no longer works
        assert c2.post("/api/auth/login", json={"username": "breakglass",
                                                "password": GEN_PW}).status_code == 401


def test_other_users_unaffected(monkeypatch, tmp_path):
    app, s = make(monkeypatch, tmp_path)
    with TestClient(app):
        pass
    from exposurecatalyst.security.passwords import hash_password

    with get_session_factory()() as db:
        db.add(User(username="analyst1", password_hash=hash_password(NEW_PW)))
        db.commit()
    with TestClient(app) as c:
        me = c.post("/api/auth/login", json={"username": "analyst1", "password": NEW_PW}).json()
        assert me["must_change_password"] is False and me["first_login_pending"] is False
