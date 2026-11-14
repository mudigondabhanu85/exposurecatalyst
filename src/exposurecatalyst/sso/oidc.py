"""OpenID Connect sign-in (Okta or any OIDC provider) — the alternative to SAML 2.0.

Authorization Code flow with PKCE (S256), confidential client:

* ``state`` (stored hashed, single use, ≤ REQUEST_TTL), ``nonce`` bound to the ID token, PKCE verifier stored
  Fernet-encrypted server-side — nothing sensitive lives in the browser
* discovery and every endpoint it names must be https **on the issuer's host**, and that host must be an Okta
  domain or in the egress allowlist (SSRF guard + no metadata-driven redirection of the token request)
* ID token: signature via the provider's JWKS (asymmetric algorithms only; ``none``/HMAC refused), ``iss``,
  ``aud`` (+ ``azp`` when several audiences), ``exp``/``iat`` with 60 s leeway, ``nonce``, ``sub``
* ``email_verified: false`` is refused; groups come from the ID token, or the userinfo endpoint when absent
* the redirect URI is built from EXCAT_PUBLIC_URL, never from request headers
* roles come only from group → role mappings (shared with SAML/SCIM in :mod:`exposurecatalyst.sso.identity`)
"""

from __future__ import annotations

import hashlib
import time
from datetime import timedelta
from typing import Any
from urllib.parse import urlencode, urlsplit

from authlib.common.security import generate_token
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from joserfc import jwt
from joserfc.errors import InvalidKeyIdError, JoseError
from joserfc.jwk import KeySet
from sqlalchemy.orm import Session

from exposurecatalyst.config import Settings
from exposurecatalyst.db.base import as_utc, utcnow
from exposurecatalyst.ingestion.http import SourceClient
from exposurecatalyst.models import AppSetting, OidcRequest
from exposurecatalyst.security.crypto import get_secret_box
from exposurecatalyst.sso.saml import safe_relay

CFG_KEY = "sso.oidc"
LOGIN_PATH, CALLBACK_PATH = "/api/auth/oidc/login", "/api/auth/oidc/callback"
REQUEST_TTL = timedelta(minutes=10)
METADATA_TTL = 3600  # seconds
JWKS_REFRESH_MIN_INTERVAL = 60  # an unknown `kid` triggers at most one JWKS refetch per minute
ALGORITHMS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"]
OKTA_HOSTS = ["*.okta.com", "*.oktapreview.com", "*.okta-emea.com", "*.okta-gov.com", "*.okta.mil"]
DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "issuer": "",
    "client_id": "",
    "client_secret_enc": "",  # nosec B105 - empty default, set via the settings API (encrypted)
    "token_auth_method": "client_secret_basic",  # nosec B105 - method name; or client_secret_post
    "scopes": "openid email profile groups",
    "claim_email": "email",
    "claim_first_name": "given_name",
    "claim_last_name": "family_name",
    "claim_groups": "groups",
    "jit_provisioning": True,
    "button_label": "Sign in with Okta",
}

_cache: dict[str, dict[str, Any]] = {}  # issuer → {"at", "meta", "jwks", "jwks_at"}
_transport: Any = None  # tests inject an httpx.MockTransport


class OidcError(PermissionError):
    pass


# ---------------------------------------------------------------------------------------------- config
def load_config(db: Session) -> dict[str, Any]:
    row = db.get(AppSetting, CFG_KEY)
    return {**DEFAULTS, **(row.value if row and row.value else {})}


def save_config(db: Session, cfg: dict[str, Any], actor: str) -> None:
    row = db.get(AppSetting, CFG_KEY)
    if row is None:
        db.add(AppSetting(key=CFG_KEY, value=cfg, updated_by=actor))
    else:
        row.value, row.updated_by = cfg, actor
    _cache.clear()


def public_config(cfg: dict[str, Any]) -> dict[str, Any]:
    out = {k: v for k, v in cfg.items() if k != "client_secret_enc"}
    out["client_secret_set"] = bool(cfg.get("client_secret_enc"))
    return out


def redirect_uri(settings: Settings) -> str:
    return settings.public_url.rstrip("/") + CALLBACK_PATH


def normalize_issuer(issuer: str) -> str:
    issuer = issuer.strip().rstrip("/")
    parts = urlsplit(issuer)
    if parts.scheme != "https" or not parts.hostname or parts.query or parts.fragment or parts.username:
        raise OidcError("issuer must be an https URL without query, fragment or credentials")
    return issuer


# ---------------------------------------------------------------------------------------------- discovery
def _client(settings: Settings, name: str = "oidc") -> SourceClient:
    return SourceClient(name, settings, rate=10, per=1.0, transport=_transport,
                        allowlist=[*OKTA_HOSTS, *settings.egress_allowlist_list])


def _same_host(url: str, issuer: str, field: str) -> str:
    u, i = urlsplit(url or ""), urlsplit(issuer)
    if u.scheme != "https" or (u.hostname or "").lower() != (i.hostname or "").lower() or u.port != i.port:
        raise OidcError(f"discovery {field} must be https on the issuer host")
    return url


def _fetch_jwks(client: SourceClient, uri: str) -> KeySet:
    try:
        return KeySet.import_key_set(client.get(uri).json())
    except (ValueError, JoseError) as exc:
        raise OidcError(f"invalid JWKS: {str(exc)[:150]}") from exc


def provider(settings: Settings, issuer: str, *, refresh: bool = False) -> dict[str, Any]:
    """Discovery document + JWKS for the issuer (cached for METADATA_TTL)."""
    issuer = normalize_issuer(issuer)
    hit = _cache.get(issuer)
    if hit and not refresh and time.monotonic() - hit["at"] < METADATA_TTL:
        return hit
    client = _client(settings)
    try:
        try:
            meta = client.get(issuer + "/.well-known/openid-configuration").json()
        except ValueError as exc:
            raise OidcError("discovery document is not JSON") from exc
        if meta.get("issuer", "").rstrip("/") != issuer:
            raise OidcError("discovery issuer does not match the configured issuer")
        for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            _same_host(meta.get(field, ""), issuer, field)
        if meta.get("userinfo_endpoint"):
            _same_host(meta["userinfo_endpoint"], issuer, "userinfo_endpoint")
        if "code" not in meta.get("response_types_supported", ["code"]):
            raise OidcError("provider does not support the authorization code flow")
        methods = meta.get("code_challenge_methods_supported")
        if methods is not None and "S256" not in methods:
            raise OidcError("provider does not support PKCE S256")
        jwks = _fetch_jwks(client, meta["jwks_uri"])
    finally:
        client.close()
    now = time.monotonic()
    entry = {"at": now, "meta": meta, "jwks": jwks, "jwks_at": now}
    _cache[issuer] = entry
    return entry


def _refresh_jwks(settings: Settings, entry: dict[str, Any]) -> bool:
    if time.monotonic() - entry["jwks_at"] < JWKS_REFRESH_MIN_INTERVAL:
        return False
    client = _client(settings)
    try:
        entry["jwks"] = _fetch_jwks(client, entry["meta"]["jwks_uri"])
    finally:
        client.close()
    entry["jwks_at"] = time.monotonic()
    return True


# ---------------------------------------------------------------------------------------------- login
def _hash(state: str) -> str:
    return hashlib.sha256(state.encode()).hexdigest()


def login_url(db: Session, settings: Settings, next_path: str | None) -> str:
    cfg = load_config(db)
    if not cfg["enabled"]:
        raise OidcError("OIDC sign-in is not enabled")
    entry = provider(settings, cfg["issuer"])
    state, nonce, verifier = generate_token(43), generate_token(43), generate_token(64)
    db.add(OidcRequest(state_hash=_hash(state), nonce=nonce, relay_state=safe_relay(next_path),
                       code_verifier_enc=get_secret_box().encrypt(verifier)))
    db.commit()
    query = {
        "response_type": "code",
        "client_id": cfg["client_id"],
        "redirect_uri": redirect_uri(settings),
        "scope": cfg["scopes"],
        "state": state,
        "nonce": nonce,
        "code_challenge": create_s256_code_challenge(verifier),
        "code_challenge_method": "S256",
    }
    return entry["meta"]["authorization_endpoint"] + "?" + urlencode(query)


def _claim(claims: dict[str, Any], name: str) -> Any:
    return claims.get(name) if name else None


def validate_id_token(settings: Settings, cfg: dict[str, Any], entry: dict[str, Any], id_token: str,
                      nonce: str) -> dict[str, Any]:
    def decode():
        return jwt.decode(id_token, entry["jwks"], algorithms=ALGORITHMS)

    try:
        try:
            token = decode()
        except InvalidKeyIdError:  # provider rotated its signing key: refetch the JWKS once, then retry
            if not _refresh_jwks(settings, entry):
                raise
            token = decode()
        registry = jwt.JWTClaimsRegistry(
            leeway=60,
            iss={"essential": True, "value": entry["meta"]["issuer"]},
            aud={"essential": True, "value": cfg["client_id"]},
            sub={"essential": True},
            exp={"essential": True},
            iat={"essential": True},
            nonce={"essential": True, "value": nonce},
        )
        registry.validate(token.claims)
    except (JoseError, ValueError) as exc:
        raise OidcError(f"ID token rejected: {type(exc).__name__}: {str(exc)[:150]}") from exc
    claims = token.claims
    aud = claims.get("aud")
    if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != cfg["client_id"]:
        raise OidcError("ID token rejected: azp does not match the client ID")
    return claims


def consume(db: Session, settings: Settings, params: dict[str, str]) -> dict[str, Any]:
    """Validate the callback. Returns {email, first_name, last_name, groups, sub, relay}."""
    cfg = load_config(db)
    if not cfg["enabled"]:
        raise OidcError("OIDC sign-in is not enabled")
    state = params.get("state") or ""
    req = db.get(OidcRequest, _hash(state)) if state else None
    if req is None or req.used_at is not None or utcnow() - as_utc(req.created_at) > REQUEST_TTL:
        raise OidcError("sign-in request is unknown, expired or already used — start again")
    req.used_at = utcnow()
    db.flush()
    if params.get("error"):
        detail = params.get("error_description", "")[:200]
        raise OidcError(f"identity provider returned {params['error'][:60]}: {detail}")
    code = params.get("code")
    if not code:
        raise OidcError("missing authorization code")
    entry = provider(settings, cfg["issuer"])
    secret = get_secret_box().decrypt(cfg["client_secret_enc"]) if cfg["client_secret_enc"] else ""
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri(settings),
            "code_verifier": get_secret_box().decrypt(req.code_verifier_enc)}
    auth: tuple[str, str] | None = None
    if cfg["token_auth_method"] == "client_secret_post":  # noqa: S105 - a method name, not a secret
        form |= {"client_id": cfg["client_id"], "client_secret": secret}
    else:
        auth = (cfg["client_id"], secret)
    client = _client(settings, "oidc-token")
    try:
        try:
            tokens = client.request("POST", entry["meta"]["token_endpoint"], data=form, auth=auth,
                                    headers={"Accept": "application/json"}).json()
        except ValueError as exc:
            raise OidcError("token response is not JSON") from exc
        except Exception as exc:  # noqa: BLE001 - surfaced to the user without secrets
            raise OidcError(f"token exchange failed: {str(exc)[:200]}") from exc
        id_token = tokens.get("id_token")
        if not isinstance(id_token, str):
            raise OidcError("token response has no ID token (is the 'openid' scope requested?)")
        claims = validate_id_token(settings, cfg, entry, id_token, req.nonce)
        groups = _claim(claims, cfg["claim_groups"])
        if groups is None and entry["meta"].get("userinfo_endpoint") and tokens.get("access_token"):
            info = client.get(entry["meta"]["userinfo_endpoint"],
                              headers={"Authorization": f"Bearer {tokens['access_token']}"}).json()
            if info.get("sub") != claims["sub"]:
                raise OidcError("userinfo subject does not match the ID token")
            groups = _claim(info, cfg["claim_groups"])
            claims = {**info, **claims}
    finally:
        client.close()
    email = _claim(claims, cfg["claim_email"])
    if not isinstance(email, str) or "@" not in email:
        raise OidcError(f"ID token has no '{cfg['claim_email']}' claim (request the 'email' scope)")
    if claims.get("email_verified") is False:
        raise OidcError("the identity provider reports this email address as unverified")
    return {
        "email": email.strip().lower()[:320],
        "first_name": str(_claim(claims, cfg["claim_first_name"]) or "")[:100],
        "last_name": str(_claim(claims, cfg["claim_last_name"]) or "")[:100],
        "groups": groups if isinstance(groups, list | str) else [],
        "sub": str(claims["sub"])[:255],
        "relay": req.relay_state,
    }
