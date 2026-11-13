from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pyotp
import pytest
from fastapi.routing import APIRoute

from exposurecatalyst.db.session import get_session_factory
from exposurecatalyst.models import AuditLog, User, UserSession
from exposurecatalyst.security.audit import record, verify_chain
from exposurecatalyst.security.crypto import get_secret_box
from tests.conftest import PASSWORD, ApiClient

# /api/docs + /api/redoc are static explorer pages (disable with EXCAT_API_DOCS_ENABLED=false).
PUBLIC = {"/api/health/live", "/api/health/ready", "/api/auth/login", "/api/docs", "/api/redoc"}


def test_every_api_route_requires_auth(app, client):
    for route in app.routes:
        if not isinstance(route, APIRoute) or not route.path.startswith("/api") or route.path in PUBLIC:
            continue
        path = route.path.replace("{cve_id}", "CVE-2024-0001").replace("{name}", "nvd")
        path = path.replace("{page_id}", "x").replace("{search_id}", "1").replace("{role_id}", "1")
        path = path.replace("{user_id}", "1")
        for method in route.methods - {"HEAD", "OPTIONS"}:
            r = client.request(method, path, json={})
            assert r.status_code == 401, f"{method} {path} returned {r.status_code}"


def test_login_success_sets_hardened_cookies(client, make_user):
    make_user("alice", "Viewer")
    r = client.post("/api/auth/login", json={"username": "ALICE", "password": PASSWORD})
    assert r.status_code == 200
    body = r.json()
    assert body["permissions"] == ["cve:view", "news:view"]
    cookies = r.headers.get_list("set-cookie")
    sess = next(c for c in cookies if c.startswith("excat_session="))
    assert "HttpOnly" in sess and "SameSite=strict" in sess
    assert client.get("/api/auth/me").status_code == 200


def test_wrong_password_is_generic_and_locks_out(client, make_user, settings):
    make_user("bob", "Viewer")
    for _ in range(settings.login_max_attempts):
        r = client.post("/api/auth/login", json={"username": "bob", "password": "nope-nope-nope"})
        assert r.status_code == 401 and r.json()["detail"].startswith("Invalid username")
    r = client.post("/api/auth/login", json={"username": "bob", "password": PASSWORD})
    assert r.status_code == 423
    unknown = client.post("/api/auth/login", json={"username": "ghost", "password": "x"})
    assert unknown.json()["detail"] == r.json()["detail"] or unknown.status_code == 401


def test_login_rate_limit(client, settings):
    settings.login_rate_limit_per_minute = 3
    codes = [client.post("/api/auth/login", json={"username": "x", "password": "y"}).status_code for _ in range(4)]
    assert codes[-1] == 429


def test_totp_required_and_replay_blocked(client, make_user):
    secret = pyotp.random_base32()
    make_user("carol", "Admin", totp_secret_enc=get_secret_box().encrypt(secret), totp_enabled=True)
    r = client.post("/api/auth/login", json={"username": "carol", "password": PASSWORD})
    assert r.status_code == 401 and r.json()["detail"]["mfa_required"] is True
    code = pyotp.TOTP(secret).now()
    assert client.post("/api/auth/login",
                       json={"username": "carol", "password": PASSWORD, "totp_code": code}).status_code == 200
    replay = client.post("/api/auth/login", json={"username": "carol", "password": PASSWORD, "totp_code": code})
    assert replay.status_code == 401


def test_csrf_required_on_unsafe_methods(login):
    c = login("Security Analyst")
    token, c.csrf = c.csrf, ""
    assert c.post("/api/sources/refresh").status_code == 403
    assert c.post("/api/sources/refresh", headers={"X-CSRF-Token": "wrong"}).status_code == 403
    assert c.post("/api/sources/refresh", headers={"X-CSRF-Token": token}).status_code == 202


def test_cross_origin_post_rejected(login):
    c = login("Security Analyst")
    assert c.post("/api/sources/refresh", headers={"Origin": "https://evil.example"}).status_code == 403


def test_idle_session_expires(login, settings):
    c = login("Viewer")
    with get_session_factory()() as s:
        for row in s.query(UserSession):
            row.last_seen_at = datetime.now(UTC) - timedelta(minutes=settings.session_idle_timeout_minutes + 1)
        s.commit()
    assert c.get("/api/auth/me").status_code == 401


def test_logout_revokes_session(login):
    c = login("Viewer")
    assert c.post("/api/auth/logout").status_code == 204
    assert c.get("/api/auth/me").status_code == 401


@pytest.mark.parametrize("role,method,path,expected", [
    ("Viewer", "GET", "/api/cves", 200),
    ("Viewer", "POST", "/api/sources/refresh", 403),
    ("Security Analyst", "POST", "/api/sources/refresh", 202),
    ("Security Analyst", "PATCH", "/api/sources/nvd", 403),
    ("Admin", "PATCH", "/api/sources/nvd", 200),
    ("Viewer", "GET", "/api/admin/users", 403),
    ("Auditor", "GET", "/api/admin/audit", 200),
    ("Approver", "GET", "/api/admin/audit", 403),
    ("Admin", "POST", "/api/admin/roles", 403),  # role:manage is Super Admin only
])
def test_permission_matrix_enforced_server_side(login, role, method, path, expected):
    c = login(role)
    body = {"interval_minutes": 30} if method == "PATCH" else {}
    assert c.request(method, path, json=body).status_code == expected


def test_admin_cannot_escalate_to_super_admin(login, make_user):
    admin = login("Admin")
    target = make_user("dave", "Viewer")
    roles = {r["name"]: r["id"] for r in admin.get("/api/admin/rbac").json()["roles"]}
    r = admin.put(f"/api/admin/users/{target.id}/roles", json={"role_ids": [roles["Super Admin"]]})
    assert r.status_code == 403 and "do not hold" in r.json()["detail"]
    r = admin.put(f"/api/admin/users/{target.id}/roles", json={"role_ids": [roles["Security Analyst"]]})
    # Admin lacks advisory:* so cannot grant Analyst either — SoD by construction.
    assert r.status_code == 403
    assert admin.put(f"/api/admin/users/{target.id}/roles", json={"role_ids": [roles["Auditor"]]}).status_code == 200


def test_mfa_required_for_admin_actions_when_enforced(login, settings):
    settings.require_mfa_for_local_admins = True
    c = login("Admin")
    assert c.get("/api/admin/users").status_code == 403
    assert c.get("/api/cves").status_code == 200  # non-admin actions still allowed


def test_audit_chain_detects_tampering(app, login):
    login("Viewer")  # produces an auth.login entry
    with get_session_factory()() as s:
        record(s, "test.event", actor_username="x", details={"api_key": "should-be-redacted"})
        s.commit()
        ok, bad, n = verify_chain(s)
        assert ok and n >= 2
        last = s.query(AuditLog).order_by(AuditLog.id.desc()).first()
        assert last.details["api_key"] == "***REDACTED***"
        last.action = "tampered"
        s.commit()
        ok, bad, _ = verify_chain(s)
        assert not ok and bad == last.id


def test_security_headers(client):
    r = client.get("/api/health/live")
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert "unsafe-inline" not in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"


def test_unused_client_cls():
    assert ApiClient and User


def test_docs_require_login(app, settings, tmp_path, login):
    (tmp_path / "index.html").write_text("<h1>docs</h1>")
    settings.docs_site_dir = tmp_path
    from exposurecatalyst.main import create_app

    a = create_app(settings)
    anon = ApiClient(a)
    r = anon.get("/docs/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login")


def test_spa_branding_assets(settings, tmp_path):
    (tmp_path / "index.html").write_text('<meta property="og:image" content="__EXCAT_PUBLIC_URL__/brand/png/og.png">')
    (tmp_path / "manifest.webmanifest").write_text("{}")
    settings.frontend_dist_dir = tmp_path
    settings.public_url = "https://excat.example.com"
    from exposurecatalyst.main import create_app

    c = ApiClient(create_app(settings))
    assert 'content="https://excat.example.com/brand/png/og.png"' in c.get("/cves").text
    assert c.get("/manifest.webmanifest").headers["content-type"].startswith("application/manifest+json")
    swagger = c.get("/api/docs").text
    assert "<title>ExposureCatalyst API</title>" in swagger and "/brand/favicon/favicon.svg" in swagger
