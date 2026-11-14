"""OIDC sign-in (Authorization Code + PKCE) against a mock Okta authorization server."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from joserfc import jwt
from joserfc.jwk import OctKey, RSAKey

from exposurecatalyst.db.session import get_session_factory
from exposurecatalyst.models import AuditLog, OidcRequest, User
from exposurecatalyst.sso import oidc
from tests.conftest import ApiClient

ISSUER = "https://acme.okta.com/oauth2/default"
CLIENT_ID = "0oa-excat"
SECRET = "test-client-secret-value"  # noqa: S105 - test fixture value
REDIRECT = "http://localhost:8000/api/auth/oidc/callback"


class FakeOkta:
    """Discovery, JWKS, token and userinfo endpoints. Each test tweaks what the token endpoint returns."""

    def __init__(self):
        self.key = RSAKey.generate_key(2048, parameters={"kid": "k1", "use": "sig"}, private=True)
        self.published = [self.key]
        self.codes: dict[str, dict] = {}  # code → {nonce, challenge}
        self.claims_override: dict = {}
        self.drop: set[str] = set()
        self.sign_with = None
        self.alg = "RS256"
        self.token_requests: list[dict] = []
        self.meta_override: dict = {}
        self.userinfo: dict | None = None

    def meta(self):
        base = ISSUER
        return {"issuer": ISSUER, "authorization_endpoint": f"{base}/v1/authorize", "token_endpoint": f"{base}/v1/token",
                "jwks_uri": f"{base}/v1/keys", "userinfo_endpoint": f"{base}/v1/userinfo",
                "response_types_supported": ["code"], "code_challenge_methods_supported": ["S256"],
                **self.meta_override}

    def id_token(self, nonce):
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": CLIENT_ID, "sub": "00u-ana", "iat": now, "exp": now + 300, "nonce": nonce,
                  "email": "ana@acme.com", "email_verified": True, "given_name": "Ana", "family_name": "Lopez",
                  "groups": ["ExcatAnalysts"], **self.claims_override}
        for k in self.drop:
            claims.pop(k, None)
        key = self.sign_with or self.key
        header = {"alg": self.alg, "kid": key.kid} if key.kid else {"alg": self.alg}
        return jwt.encode(header, claims, key, algorithms=[self.alg])

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json=self.meta())
        if path.endswith("/v1/keys"):
            return httpx.Response(200, json={"keys": [k.as_dict(private=False) for k in self.published]})
        if path.endswith("/v1/token"):
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            self.token_requests.append({"form": form, "auth": request.headers.get("authorization")})
            expected = "Basic " + base64.b64encode(f"{CLIENT_ID}:{SECRET}".encode()).decode()
            if request.headers.get("authorization") != expected:
                return httpx.Response(401, json={"error": "invalid_client"})
            grant = self.codes.pop(form.get("code"), None)
            if grant is None or form.get("redirect_uri") != REDIRECT:
                return httpx.Response(400, json={"error": "invalid_grant"})
            challenge = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest()).rstrip(b"=")
            if challenge.decode() != grant["challenge"]:
                return httpx.Response(400, json={"error": "invalid_grant", "error_description": "PKCE"})
            return httpx.Response(200, json={"id_token": self.id_token(grant["nonce"]), "access_token": "at-1",
                                             "token_type": "Bearer"})
        if path.endswith("/v1/userinfo"):
            return httpx.Response(200, json=self.userinfo or {})
        return httpx.Response(404)

    def authorize(self, location: str, *, code="code-1") -> dict:
        q = {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}
        assert q["code_challenge_method"] == "S256" and q["redirect_uri"] == REDIRECT and "openid" in q["scope"]
        self.codes[code] = {"nonce": q["nonce"], "challenge": q["code_challenge"]}
        return q


@pytest.fixture
def okta(monkeypatch):
    fake = FakeOkta()
    monkeypatch.setattr(oidc, "_transport", httpx.MockTransport(fake.handler))
    oidc._cache.clear()
    yield fake
    oidc._cache.clear()


@pytest.fixture
def root(login):
    return login("Super Admin", username="root")


BODY = {"issuer": ISSUER + "/", "client_id": CLIENT_ID, "client_secret": SECRET, "enabled": True}


@pytest.fixture
def oidc_on(root, okta):
    r = root.put("/api/settings/sso/oidc", json=BODY)
    assert r.status_code == 422 and "Map at least one group" in r.text
    roles = {r["name"]: r["id"] for r in root.get("/api/admin/rbac").json()["roles"]}
    assert root.post("/api/settings/sso/mappings", json={"group_name": "ExcatAnalysts",
                                                         "role_id": roles["Security Analyst"]}).status_code == 201
    r = root.put("/api/settings/sso/oidc", json=BODY)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["issuer"] == ISSUER and out["client_secret_set"] and "client_secret_enc" not in out
    assert SECRET not in r.text and out["redirect_uri"] == REDIRECT
    return roles


def start(app, okta, next_path="/advisories"):
    c = ApiClient(app)
    c.__enter__()
    r = c.get("/api/auth/oidc/login", params={"next": next_path}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith(ISSUER + "/v1/authorize?")
    return c, okta.authorize(r.headers["location"])


def callback(c, **params):
    return c.get("/api/auth/oidc/callback", params=params, follow_redirects=False)


def test_status_and_settings_hide_secret(client, root, oidc_on):
    s = client.get("/api/auth/sso").json()
    assert s["oidc_enabled"] and s["oidc_login_url"] == "/api/auth/oidc/login"
    cfg = root.get("/api/settings/sso/oidc").json()
    assert cfg["client_secret_set"] and SECRET not in json.dumps(cfg)
    # Saving without a secret keeps the stored one
    assert root.put("/api/settings/sso/oidc", json={**BODY, "client_secret": None}).json()["client_secret_set"]
    with get_session_factory()() as s:
        details = [a.details for a in s.query(AuditLog).filter_by(action="settings.oidc_updated")]
    assert details and SECRET not in json.dumps(details)


def test_oidc_login_maps_groups_and_uses_pkce(app, okta, oidc_on):
    c, q = start(app, okta)
    r = callback(c, code="code-1", state=q["state"])
    assert r.status_code == 200 and 'url=/advisories"' in r.text, r.text
    me = c.get("/api/auth/me").json()
    assert me["username"] == "ana@acme.com" and me["roles"] == ["Security Analyst"] and me["mfa_verified"]
    req = okta.token_requests[-1]
    assert req["form"]["grant_type"] == "authorization_code" and len(req["form"]["code_verifier"]) >= 43
    assert "client_secret" not in req["form"]  # client_secret_basic: secret only in the Authorization header
    with get_session_factory()() as s:
        u = s.query(User).filter_by(username="ana@acme.com").one()
        assert u.auth_source == "oidc" and not u.is_local and u.password_hash is None and u.display_name == "Ana Lopez"
        stored = s.query(OidcRequest).one()
        assert stored.used_at is not None and stored.state_hash != q["state"]
        assert req["form"]["code_verifier"] not in stored.code_verifier_enc


def _alt_key(kid):
    return RSAKey.generate_key(2048, parameters={"kid": kid}, private=True)


@pytest.mark.parametrize("variant", [
    "state_replay", "unknown_state", "wrong_nonce", "wrong_audience", "wrong_issuer", "expired", "bad_signature",
    "alg_none_hmac", "unverified_email", "no_email", "unmapped_group", "idp_error", "multi_aud_no_azp",
])
def test_oidc_rejections(app, okta, oidc_on, variant):
    c, q = start(app, okta)
    params = {"code": "code-1", "state": q["state"]}
    if variant == "state_replay":
        assert 'url=/advisories"' in callback(c, **params).text
        okta.codes["code-1"] = okta.codes.get("code-1") or {"nonce": q["nonce"], "challenge": q["code_challenge"]}
        r = callback(ApiClient(app).__enter__(), **params)
    elif variant == "unknown_state":
        r = callback(c, code="code-1", state="forged-state")
    elif variant == "idp_error":
        r = callback(c, state=q["state"], error="access_denied", error_description="User not assigned")
    else:
        now = int(time.time())
        okta.claims_override = {
            "wrong_nonce": {"nonce": "other"}, "wrong_audience": {"aud": "someone-else"},
            "wrong_issuer": {"iss": "https://evil.okta.com"}, "expired": {"exp": now - 600, "iat": now - 900},
            "unverified_email": {"email_verified": False}, "unmapped_group": {"groups": ["Marketing"]},
            "multi_aud_no_azp": {"aud": [CLIENT_ID, "other-app"]},
        }.get(variant, {})
        if variant == "no_email":
            okta.drop = {"email"}
        if variant == "bad_signature":
            okta.sign_with = _alt_key("k1")  # same kid, different key
        if variant == "alg_none_hmac":
            okta.sign_with, okta.alg = OctKey.import_key(b"x" * 32), "HS256"
        r = callback(c, **params)
    assert r.status_code == 200 and "url=/login?sso_error=" in r.text, (variant, r.text[:300])
    assert not any(k.startswith("excat_session") for k in r.cookies), variant


def test_signing_key_rotation_refetches_jwks(app, okta, oidc_on, monkeypatch):
    monkeypatch.setattr(oidc, "JWKS_REFRESH_MIN_INTERVAL", 0)
    new = _alt_key("k2")
    okta.sign_with, okta.published = new, [okta.key, new]
    c, q = start(app, okta)
    assert 'url=/advisories"' in callback(c, code="code-1", state=q["state"]).text


def test_groups_from_userinfo_when_not_in_id_token(app, okta, oidc_on):
    okta.drop = {"groups"}
    okta.userinfo = {"sub": "00u-ana", "groups": ["ExcatAnalysts"]}
    c, q = start(app, okta)
    assert 'url=/advisories"' in callback(c, code="code-1", state=q["state"]).text
    okta.userinfo = {"sub": "00u-mallory", "groups": ["ExcatAnalysts"]}  # userinfo for someone else → refused
    c, q = start(app, okta)
    assert "sso_error=" in callback(c, code="code-1", state=q["state"]).text


def test_oidc_cannot_take_over_local_account(app, okta, oidc_on, make_user):
    make_user("breakglass@acme.com", "Super Admin")
    okta.claims_override = {"email": "breakglass@acme.com"}
    c, q = start(app, okta)
    r = callback(c, code="code-1", state=q["state"])
    assert "sso_error=" in r.text and "local" in r.text


def test_open_redirect_blocked(app, okta, oidc_on):
    c, q = start(app, okta, next_path="https://evil.example/x")
    assert 'url=/cves"' in callback(c, code="code-1", state=q["state"]).text


@pytest.mark.parametrize("override", [
    {"token_endpoint": "https://evil.example/token"},        # endpoint off the issuer host
    {"jwks_uri": "http://acme.okta.com/oauth2/default/v1/keys"},  # not https
    {"issuer": "https://acme.okta.com/oauth2/other"},        # issuer mismatch
    {"code_challenge_methods_supported": ["plain"]},          # no S256
])
def test_discovery_is_validated(root, okta, oidc_on, override):
    okta.meta_override = override
    r = root.post("/api/settings/sso/oidc/test")
    assert r.status_code == 200 and r.json()["ok"] is False, override
    assert root.put("/api/settings/sso/oidc", json=BODY).status_code == 422


def test_issuer_must_be_allowlisted_https(root, okta):
    assert root.put("/api/settings/sso/oidc", json={**BODY, "enabled": False, "issuer": "http://acme.okta.com"}).status_code == 422
    r = root.put("/api/settings/sso/oidc", json={**BODY, "enabled": False, "issuer": "https://idp.evil.example"})
    assert r.status_code == 200  # saving disabled config is allowed…
    assert root.post("/api/settings/sso/oidc/test").json()["ok"] is False  # …but egress is refused


def test_settings_require_sso_manage(login, okta):
    c = login("Security Analyst")
    assert c.get("/api/settings/sso/oidc").status_code == 403
    assert c.put("/api/settings/sso/oidc", json=BODY).status_code == 403


def test_login_refused_when_disabled(client, okta):
    assert client.get("/api/auth/oidc/login", follow_redirects=False).status_code == 409
    r = client.get("/api/auth/oidc/callback", params={"code": "x", "state": "y"}, follow_redirects=False)
    assert "sso_error=" in r.text
