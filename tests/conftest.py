from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from exposurecatalyst.config import PROJECT_ROOT, Settings
from exposurecatalyst.db.base import Base
from exposurecatalyst.db.session import get_engine, get_session_factory, init_engine
from exposurecatalyst.ingestion.service import ensure_source_states
from exposurecatalyst.models import Role, User
from exposurecatalyst.security.passwords import hash_password
from exposurecatalyst.security.rbac import seed_roles

FIXTURES = Path(__file__).parent / "fixtures"
PASSWORD = "Correct-Horse-Battery-9"


def load_fixture(name: str):
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture
def settings(monkeypatch) -> Settings:
    s = Settings(
        env="test",
        database_url="sqlite://",
        cookie_secure=False,
        log_json=False,
        log_level="WARNING",
        ssrf_resolve_dns=False,
        http_max_retries=2,
        http_backoff_base_seconds=0.01,
        require_mfa_for_local_admins=False,
        egress_allowlist="services.nvd.nist.gov,www.cisa.gov,api.first.org,epss.empiricalsecurity.com",
        frontend_dist_dir=PROJECT_ROOT / "nonexistent",
        docs_site_dir=PROJECT_ROOT / "nonexistent",
    )
    import sys

    import exposurecatalyst.api.auth as auth_mod
    import exposurecatalyst.api.help as help_mod
    import exposurecatalyst.main  # noqa: F401 - import every module that binds get_settings
    from exposurecatalyst.security import crypto

    for name, mod in list(sys.modules.items()):
        if name.startswith("exposurecatalyst") and hasattr(mod, "get_settings"):
            monkeypatch.setattr(mod, "get_settings", lambda: s)
    crypto.get_secret_box.cache_clear()
    help_mod.repo.cache_clear()
    auth_mod._limiter = None
    return s


@pytest.fixture
def db_factory(settings):
    init_engine(settings)
    Base.metadata.create_all(get_engine())
    factory = get_session_factory()
    with factory() as db:
        seed_roles(db)
        ensure_source_states(db)
        db.commit()
    yield factory
    Base.metadata.drop_all(get_engine())


@pytest.fixture
def db(db_factory):
    with db_factory() as session:
        yield session


@pytest.fixture
def app(settings, db_factory):
    from exposurecatalyst.main import create_app

    application = create_app(settings)
    # create_app re-initialises the engine; recreate the in-memory schema on that engine.
    Base.metadata.create_all(get_engine())
    with get_session_factory()() as s:
        seed_roles(s)
        ensure_source_states(s)
        s.commit()
    return application


@pytest.fixture
def make_user(app):
    def _make(username: str, *roles: str, password: str = PASSWORD, **kw) -> User:
        with get_session_factory()() as s:
            role_rows = [s.query(Role).filter_by(name=r).one() for r in roles]
            u = User(username=username, password_hash=hash_password(password), roles=role_rows, **kw)
            s.add(u)
            s.commit()
            s.refresh(u)
            return u

    return _make


class ApiClient(TestClient):
    csrf: str = ""

    def request(self, method, url, *args, **kwargs):  # type: ignore[override]
        if method.upper() in {"POST", "PUT", "PATCH", "DELETE"} and self.csrf:
            headers = dict(kwargs.get("headers") or {})
            headers.setdefault("X-CSRF-Token", self.csrf)
            kwargs["headers"] = headers
        return super().request(method, url, *args, **kwargs)


@pytest.fixture
def client(app):
    with ApiClient(app) as c:
        yield c


@pytest.fixture
def login(app, make_user):
    def _login(*roles: str, username: str | None = None) -> ApiClient:
        name = username or ("u_" + "_".join(r.replace(" ", "").lower() for r in roles) or "noroles")
        make_user(name, *roles)
        c = ApiClient(app)
        c.__enter__()
        r = c.post("/api/auth/login", json={"username": name, "password": PASSWORD})
        assert r.status_code == 200, r.text
        c.csrf = r.json()["csrf_token"]
        return c

    return _login
