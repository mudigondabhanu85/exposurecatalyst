"""Phase 2: YAML config, FQDN-derived URLs (set and unset), feature flags, banners, first-run setup wizard."""

from __future__ import annotations

import sys

import pyotp
import pytest
from fastapi.testclient import TestClient

from exposurecatalyst import deployment
from exposurecatalyst.config import PROJECT_ROOT, Settings, load_config_file
from exposurecatalyst.db.base import Base
from exposurecatalyst.db.session import get_engine, get_session_factory
from exposurecatalyst.models import AppSetting, AuditLog, User
from exposurecatalyst.security.rbac import seed_roles

BASE = dict(env="test", database_url="sqlite://", cookie_secure=False, log_json=False, log_level="WARNING",
            ssrf_resolve_dns=False, require_mfa_for_local_admins=False,
            frontend_dist_dir=PROJECT_ROOT / "nonexistent", docs_site_dir=PROJECT_ROOT / "nonexistent")


@pytest.fixture(autouse=True)
def _fresh_setup_limiter(monkeypatch):
    from exposurecatalyst.api import setup as setup_api
    from exposurecatalyst.security.middleware import SlidingWindowLimiter

    monkeypatch.setattr(setup_api, "_limiter", SlidingWindowLimiter(10))


def make_app(monkeypatch, **overrides):
    s = Settings(**{**BASE, **overrides})
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
    with get_session_factory()() as db:
        seed_roles(db)
        db.commit()
    return app, s


# ---- config sources --------------------------------------------------------------------------------------

def test_yaml_is_opt_in_and_env_wins(tmp_path, monkeypatch):
    cfg = tmp_path / "exposurecatalyst.yaml"
    cfg.write_text("fqdn: excat.corp.example\nhttps_port: 8443\nlog_level: DEBUG\n"
                   "features:\n  acme: true\n  subscriptions: true\nunknown_key: ignored\n")
    for k in ("EXCAT_CONFIG_FILE", "EXCAT_FQDN", "EXCAT_LOG_LEVEL", "EXCAT_FEATURES__ACME"):
        monkeypatch.delenv(k, raising=False)
    assert Settings(**BASE, _env_file=None).fqdn is None  # file present but not referenced → ignored
    monkeypatch.setenv("EXCAT_CONFIG_FILE", str(cfg))
    s = Settings(**{k: v for k, v in BASE.items() if k != "log_level"}, _env_file=None)
    assert s.fqdn == "excat.corp.example" and s.public_url == "https://excat.corp.example:8443"
    assert s.log_level == "DEBUG" and s.features.acme and s.features.subscriptions
    monkeypatch.setenv("EXCAT_FQDN", "")              # compose passes unset vars as empty → YAML still applies
    monkeypatch.setenv("EXCAT_FEATURES__ACME", "false")  # explicit nested env beats YAML, per key
    s = Settings(**BASE, _env_file=None)
    assert s.fqdn == "excat.corp.example" and not s.features.acme and s.features.subscriptions
    monkeypatch.setenv("EXCAT_FQDN", "override.corp.example")
    assert Settings(**BASE, _env_file=None).fqdn == "override.corp.example"


def test_yaml_must_be_a_mapping(tmp_path, monkeypatch):
    bad = tmp_path / "c.yaml"
    bad.write_text("- just\n- a list\n")
    with pytest.raises(ValueError, match="mapping"):
        load_config_file(bad)


def test_example_config_parses_and_flags_default_off():
    data = load_config_file(PROJECT_ROOT / "config" / "exposurecatalyst.example.yaml")
    assert data["fqdn"] == "localhost" and set(data["features"]) == {"ui_tls_management", "acme", "subscriptions",
                                                                     "run_watch_mode"}
    assert not any(data["features"].values())
    assert Settings(**BASE, _env_file=None).features.model_dump() == dict.fromkeys(data["features"], False)


# ---- FQDN unset = previous behaviour -----------------------------------------------------------------------

def test_fqdn_unset_keeps_previous_behaviour(monkeypatch):
    monkeypatch.delenv("EXCAT_FQDN", raising=False)
    monkeypatch.delenv("EXCAT_CONFIG_FILE", raising=False)
    s = Settings(**BASE, public_url="https://excat.example.org", _env_file=None)
    assert s.public_url == "https://excat.example.org" and s.allowed_hosts is None
    assert s.allowed_origins == {"https://excat.example.org"} and s.explicit_public_url is None
    assert s.hsts_enabled is False  # follows cookie_secure, as before
    assert Settings(**{**BASE, "cookie_secure": True}, _env_file=None).hsts_enabled is True


def test_no_host_restriction_without_fqdn(monkeypatch):
    app, _ = make_app(monkeypatch)
    with TestClient(app, base_url="http://anything.example") as c:
        assert c.get("/api/health/live").status_code == 200


# ---- FQDN set drives every URL -----------------------------------------------------------------------------

def test_fqdn_drives_urls_hosts_and_origins(monkeypatch):
    app, s = make_app(monkeypatch, fqdn="Excat.Corp.Example", public_url="http://localhost:8000")
    assert s.public_url == "https://excat.corp.example"
    assert s.allowed_origins == {"https://excat.corp.example", "http://localhost:8000"}  # old URL still accepted
    urls = deployment.derived_urls(s)
    assert urls["SAML ACS URL"] == "https://excat.corp.example/api/auth/saml/acs"
    assert urls["OIDC redirect URI"] == "https://excat.corp.example/api/auth/oidc/callback"
    with TestClient(app, base_url="https://excat.corp.example") as c:
        meta = c.get("/api/saml/metadata")
        assert meta.status_code == 200 and 'entityID="https://excat.corp.example/api/saml/metadata"' in meta.text
        assert "https://excat.corp.example/api/auth/saml/acs" in meta.text
        assert c.get("/api/health/live").status_code == 200
    with TestClient(app, base_url="https://evil.example") as c:
        assert c.get("/api/health/live").status_code == 400  # Host header not allowed
    with TestClient(app, base_url="http://127.0.0.1:8000") as c:  # container healthcheck
        assert c.get("/api/health/live").status_code == 200


def test_fqdn_csrf_origin_and_hsts(monkeypatch, make_user=None):
    app, _ = make_app(monkeypatch, fqdn="excat.corp.example", hsts=True, hsts_max_age_seconds=300)
    with TestClient(app, base_url="https://excat.corp.example") as c:
        r = c.post("/api/auth/login", json={"username": "x", "password": "y"},
                   headers={"Origin": "https://attacker.example"})
        assert r.status_code == 403
        r = c.post("/api/auth/login", json={"username": "x", "password": "y"},
                   headers={"Origin": "https://excat.corp.example"})
        assert r.status_code == 401
        assert r.headers["strict-transport-security"] == "max-age=300; includeSubDomains"


def test_docker_deployment_defaults_fqdn_to_localhost(monkeypatch):
    monkeypatch.delenv("EXCAT_FQDN", raising=False)
    s = Settings(**BASE, deployment="docker", _env_file=None)
    assert s.fqdn == "localhost" and s.public_url == "https://localhost"


@pytest.mark.parametrize("bad", ["https://x.example", "x.example:443", "x.example/path", "bad_host!", "-x.example"])
def test_fqdn_validation(bad):
    with pytest.raises(ValueError):
        Settings(**BASE, fqdn=bad, _env_file=None)


# ---- domain change detection + banners ---------------------------------------------------------------------

def test_domain_change_raises_banner_once_and_is_dismissible(monkeypatch, tmp_path):
    app, s = make_app(monkeypatch, fqdn="old.corp.example", certs_dir=tmp_path / "certs")
    with get_session_factory()() as db:
        assert deployment.record_domain(db, s) is False  # first start: just remembered
        assert deployment.banners(db, s, admin=True) == []
        s2 = Settings(**BASE, fqdn="new.corp.example", certs_dir=tmp_path / "certs", _env_file=None)
        assert deployment.record_domain(db, s2) is True
        assert deployment.record_domain(db, s2) is False  # no repeat on the next start
        b = deployment.banners(db, s2, admin=True)
        assert b[0]["id"] == "domain_changed" and "new.corp.example" in b[0]["message"]
        assert deployment.banners(db, s2, admin=False) == []
        assert db.query(AuditLog).filter_by(action="system.domain_changed").count() == 1
        assert deployment.dismiss(db, "domain_changed") and not deployment.dismiss(db, "self_signed")
        db.commit()
        assert deployment.banners(db, s2, admin=True) == []


def test_self_signed_banner_and_cert_status(monkeypatch, tmp_path):
    from exposurecatalyst import bootstrap

    cert, key = bootstrap.generate_self_signed("excat.corp.example")
    bootstrap.write_active_cert(tmp_path, cert, key, {"mode": "self-signed", "fqdn": "excat.corp.example"})
    s = Settings(**BASE, fqdn="excat.corp.example", certs_dir=tmp_path, _env_file=None)
    st = deployment.certificate_status(s)
    assert st["mode"] == "self-signed" and st["covers_fqdn"] and st["days_left"] > 300
    app, s = make_app(monkeypatch, fqdn="excat.corp.example", certs_dir=tmp_path)
    with get_session_factory()() as db:
        assert [b["id"] for b in deployment.banners(db, s, admin=True)] == ["self_signed"]


def test_banner_api_rbac(monkeypatch, tmp_path):
    from exposurecatalyst.models import Role
    from exposurecatalyst.security.passwords import hash_password

    app, s = make_app(monkeypatch)
    with get_session_factory()() as db:
        for name, role in (("adm", "Admin"), ("viewer", "Viewer")):
            db.add(User(username=name, password_hash=hash_password("Correct-Horse-Battery-9"),
                        roles=[db.query(Role).filter_by(name=role).one()]))
        db.commit()
    with TestClient(app) as c:
        assert c.get("/api/system/banners").status_code == 401
        c.post("/api/auth/login", json={"username": "viewer", "password": "Correct-Horse-Battery-9"})
        assert c.get("/api/system/banners").json() == []
        assert c.get("/api/system/deployment").status_code == 403
    with TestClient(app) as c:
        r = c.post("/api/auth/login", json={"username": "adm", "password": "Correct-Horse-Battery-9"})
        c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
        d = c.get("/api/system/deployment").json()
        assert d["fqdn"] is None and d["features"]["ui_tls_management"] is False and "SAML ACS URL" in d["urls"]
        assert c.post("/api/system/banners/nope/dismiss").status_code == 404


# ---- first-run setup wizard --------------------------------------------------------------------------------

@pytest.fixture
def empty_app(monkeypatch):
    app, s = make_app(monkeypatch)
    return app, s


def _token(s):
    with get_session_factory()() as db:
        return deployment.ensure_setup_token(db, s)


def test_setup_wizard_creates_mfa_super_admin_once(empty_app, capsys):
    app, s = empty_app
    with TestClient(app) as c:
        out = capsys.readouterr().out
        token = _token(s)
        assert token and token in out  # printed once at startup (same token on every process)
        assert c.get("/api/auth/sso").json()["setup_required"] is True
        assert c.get("/api/setup/verify").status_code == 401
        assert c.get("/api/setup/verify", headers={"Authorization": "Bearer wrong-token-value"}).status_code == 401
        auth = {"Authorization": f"Bearer {token}"}
        assert c.get("/api/setup/verify", headers=auth).json() == {"ok": True}
        weak = c.post("/api/setup/begin", headers=auth, json={"username": "root", "password": "short"})
        assert weak.status_code == 422
        r = c.post("/api/setup/begin", headers=auth,
                   json={"username": "breakglass", "email": "sec@corp.example", "password": "Correct-Horse-Battery-9"})
        assert r.status_code == 200
        secret = r.json()["secret"]
        assert c.post("/api/setup/complete", headers=auth, json={"totp_code": "000000"}).status_code == 422
        r = c.post("/api/setup/complete", headers=auth, json={"totp_code": pyotp.TOTP(secret).now()})
        assert r.status_code == 201 and r.json() == {"username": "breakglass"}
        # token consumed, wizard disabled for good
        assert c.get("/api/setup/verify", headers=auth).status_code == 401
        assert c.get("/api/auth/sso").json()["setup_required"] is False
        login = c.post("/api/auth/login", json={"username": "breakglass", "password": "Correct-Horse-Battery-9"})
        assert login.status_code == 401 and login.json()["detail"]["mfa_required"]  # MFA is enforced
    with get_session_factory()() as db:
        u = db.query(User).filter_by(username="breakglass").one()
        assert u.totp_enabled and [r.name for r in u.roles] == ["Super Admin"]
        assert db.get(AppSetting, deployment.SETUP_KEY) is None
        assert db.query(AuditLog).filter_by(action="user.created").one().details["via"] == "setup"


def test_setup_skipped_when_users_exist(monkeypatch, capsys):
    from exposurecatalyst.security.passwords import hash_password

    app, s = make_app(monkeypatch)
    with get_session_factory()() as db:
        db.add(User(username="existing", password_hash=hash_password("Correct-Horse-Battery-9")))
        db.commit()
    with TestClient(app) as c:
        assert "setup token" not in capsys.readouterr().out
        assert c.get("/api/auth/sso").json()["setup_required"] is False
        assert c.get("/api/setup/verify", headers={"Authorization": "Bearer anything-here"}).status_code == 401
    with get_session_factory()() as db:
        assert deployment.ensure_setup_token(db, s) is None


def test_setup_token_expires(empty_app):
    from datetime import timedelta

    from exposurecatalyst.db.base import utcnow

    app, s = empty_app
    with TestClient(app) as c:
        token = _token(s)
        with get_session_factory()() as db:
            row = db.get(AppSetting, deployment.SETUP_KEY)
            row.value = {**row.value, "expires_at": (utcnow() - timedelta(minutes=1)).isoformat()}
            db.commit()
        assert c.get("/api/setup/verify", headers={"Authorization": f"Bearer {token}"}).status_code == 401
        new = _token(s)
        assert new and new != token  # a fresh token on the next start


def test_setup_is_rate_limited(empty_app, monkeypatch):
    from exposurecatalyst.api import setup as setup_api
    from exposurecatalyst.security.middleware import SlidingWindowLimiter

    monkeypatch.setattr(setup_api, "_limiter", SlidingWindowLimiter(3))
    app, _ = empty_app
    with TestClient(app) as c:
        codes = [c.get("/api/setup/verify", headers={"Authorization": "Bearer guess-guess-guess"}).status_code
                 for _ in range(5)]
    assert codes[:3] == [401, 401, 401] and codes[3:] == [429, 429]
