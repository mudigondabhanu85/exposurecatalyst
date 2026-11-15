"""Okta SAML and OIDC endpoints, Settings → Identity & SSO, group → role mapping, SCIM tokens."""

from __future__ import annotations

import hashlib
import html
import secrets
from datetime import datetime
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from exposurecatalyst import deployment
from exposurecatalyst.api.auth import _set_cookies
from exposurecatalyst.api.deps import Principal, client_ip, require, settings_dep
from exposurecatalyst.config import Settings
from exposurecatalyst.db.base import utcnow
from exposurecatalyst.db.session import get_db
from exposurecatalyst.ingestion.http import SourceClient
from exposurecatalyst.models import GroupRoleMapping, Role, ScimGroup, ScimToken, User
from exposurecatalyst.security import audit
from exposurecatalyst.security.crypto import get_secret_box
from exposurecatalyst.security.rbac import Permission as P
from exposurecatalyst.security.sessions import create_session
from exposurecatalyst.sso import oidc, saml
from exposurecatalyst.sso.identity import (
    AccountConflictError,
    apply_groups,
    find_identity,
    guard_not_local,
    normalize_groups,
    recompute_all,
)

router = APIRouter(tags=["sso"])
OKTA_HOSTS = ["*.okta.com", "*.oktapreview.com", "*.okta-emea.com", "*.okta-gov.com", "*.okta.mil"]


# ---- public SAML endpoints --------------------------------------------------------------------------


@router.get("/api/auth/sso")
def sso_status(db: Session = Depends(get_db)) -> dict:
    cfg, ocfg = saml.load_config(db), oidc.load_config(db)
    return {"saml_enabled": bool(cfg["enabled"]), "login_url": saml.LOGIN_PATH,
            "oidc_enabled": bool(ocfg["enabled"]), "oidc_login_url": oidc.LOGIN_PATH,
            "oidc_button_label": ocfg["button_label"],
            # additive (1.4): lets the login page offer the first-run wizard on an empty installation
            "setup_required": deployment.setup_required(db)}


@router.get(saml.METADATA_PATH)
def sp_metadata(db: Session = Depends(get_db), settings: Settings = Depends(settings_dep)) -> Response:
    xml = saml.metadata_xml(db, settings)
    db.commit()  # persists SP keys on first generation
    return Response(
        xml,
        media_type="application/samlmetadata+xml",
        headers={"Content-Disposition": 'attachment; filename="exposurecatalyst-sp-metadata.xml"'},
    )


@router.get(saml.LOGIN_PATH)
def saml_login(
    next: str | None = Query(None, max_length=500),
    db: Session = Depends(get_db),  # noqa: A002
    settings: Settings = Depends(settings_dep),
) -> RedirectResponse:
    try:
        return RedirectResponse(saml.login_url(db, settings, next), status_code=303)
    except saml.SamlError as exc:
        raise HTTPException(409, str(exc)) from exc


def _bounce(target: str, message: str | None = None) -> HTMLResponse:
    """Same-origin hop: the SameSite=Strict session cookie set on this cross-site POST response is only sent
    on a navigation started by our own page. A meta refresh needs no inline script (strict CSP preserved)."""
    url = target if message is None else "/login?sso_error=" + quote(message[:200], safe="")
    safe = html.escape(url, quote=True)
    return HTMLResponse(
        f'<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url={safe}">'
        f'<title>Signing in…</title><p>Signing in… <a href="{safe}">Continue</a></p>'
    )


class SsoLoginError(PermissionError):
    pass


def _complete_sso_login(db: Session, request: Request, settings: Settings, ident: dict[str, Any], *,
                        method: str, jit: bool) -> tuple[str, Any]:
    """Shared by SAML and OIDC: find or JIT-create the SSO user (never a local account), derive roles from
    group mappings only, and open a session. Returns (session token, session)."""
    user = find_identity(db, email=ident["email"], username=ident["email"])
    guard_not_local(user)
    if user is None:
        if not jit:
            raise SsoLoginError("no account provisioned for this identity (SCIM provisioning required)")
        user = User(username=ident["email"], email=ident["email"], is_local=False, auth_source=method,
                    password_hash=None, roles=[], sso_groups=[])
        db.add(user)
        db.flush()
    if not user.is_active:
        raise SsoLoginError("account is deactivated")
    name = " ".join(x for x in (ident["first_name"], ident["last_name"]) if x)
    user.display_name = name or user.display_name
    # SCIM-provisioned users keep SCIM-managed groups; other SSO users take the IdP's groups.
    if user.auth_source != "scim":
        apply_groups(db, user, normalize_groups(ident["groups"]))
    if not user.roles:
        raise SsoLoginError("your groups are not mapped to any ExposureCatalyst role — ask an administrator")
    user.last_login_at = utcnow()
    token, sess = create_session(
        db, user, settings, ip=client_ip(request), user_agent=request.headers.get("user-agent"), mfa_verified=True
    )
    audit.record(db, "auth.login", actor=user, request=request,
                 details={"method": method, "groups": user.sso_groups, "roles": [r.name for r in user.roles]})
    db.commit()
    return token, sess


def _sso_failure(db: Session, request: Request, method: str, exc: Exception) -> HTMLResponse:
    db.rollback()
    audit.record(db, "auth.login", actor_username=method, request=request, outcome="failure",
                 details={"method": method, "reason": str(exc)[:300]})
    db.commit()
    return _bounce("/login", str(exc))


@router.post(saml.ACS_PATH, include_in_schema=False)
async def saml_acs(request: Request, db: Session = Depends(get_db), settings: Settings = Depends(settings_dep)):
    form = {k: str(v) for k, v in (await request.form()).items() if k in ("SAMLResponse", "RelayState")}
    try:
        ident = saml.consume(db, settings, form)
        token, sess = _complete_sso_login(db, request, settings, ident, method="saml",
                                          jit=saml.load_config(db)["jit_provisioning"])
    except (saml.SamlError, SsoLoginError, AccountConflictError) as exc:
        return _sso_failure(db, request, "saml", exc)
    resp = _bounce(ident["relay"])
    _set_cookies(resp, settings, token, sess.csrf_token)
    return resp


# ---- public OIDC endpoints --------------------------------------------------------------------------


@router.get(oidc.LOGIN_PATH)
def oidc_login(
    next: str | None = Query(None, max_length=500),  # noqa: A002
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> RedirectResponse:
    try:
        return RedirectResponse(oidc.login_url(db, settings, next), status_code=303)
    except oidc.OidcError as exc:
        raise HTTPException(409, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - discovery outage: tell the user, keep details in logs
        raise HTTPException(502, f"Identity provider unavailable: {type(exc).__name__}") from exc


@router.get(oidc.CALLBACK_PATH, include_in_schema=False)
def oidc_callback(request: Request, db: Session = Depends(get_db), settings: Settings = Depends(settings_dep)):
    params = {k: v[:4000] for k, v in request.query_params.items()
              if k in ("code", "state", "error", "error_description")}
    try:
        ident = oidc.consume(db, settings, params)
        token, sess = _complete_sso_login(db, request, settings, ident, method="oidc",
                                          jit=oidc.load_config(db)["jit_provisioning"])
    except (oidc.OidcError, SsoLoginError, AccountConflictError) as exc:
        return _sso_failure(db, request, "oidc", exc)
    except Exception as exc:  # noqa: BLE001 - e.g. provider unreachable; never leak a stack trace
        return _sso_failure(db, request, "oidc", oidc.OidcError(f"sign-in failed: {type(exc).__name__}"))
    resp = _bounce(ident["relay"])
    _set_cookies(resp, settings, token, sess.csrf_token)
    return resp


# ---- Settings → Identity & SSO --------------------------------------------------------------------


class SamlConfigIn(BaseModel):
    enabled: bool = False
    idp_entity_id: str = Field("", max_length=500)
    idp_sso_url: str = Field("", max_length=1000)
    idp_x509_cert: str = Field("", max_length=10_000)
    sp_entity_id: str = Field("", max_length=500)
    attr_email: str = Field("email", max_length=200)
    attr_first_name: str = Field("firstName", max_length=200)
    attr_last_name: str = Field("lastName", max_length=200)
    attr_groups: str = Field("groups", max_length=200)
    allow_idp_initiated: bool = False
    jit_provisioning: bool = True


def _saml_out(db: Session, settings: Settings) -> dict[str, Any]:
    cfg = saml.load_config(db)
    return {
        **cfg,
        "sp": saml.sp_urls(settings, cfg),
        "app_tile": "/brand/png/app-icon-512.png",
        "mappings": db.scalar(select(func.count()).select_from(GroupRoleMapping)) or 0,
    }


@router.get("/api/settings/sso/saml")
def get_saml(
    _: Principal = Depends(require(P.SSO_MANAGE)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> dict:
    return _saml_out(db, settings)


@router.put("/api/settings/sso/saml")
def put_saml(
    body: SamlConfigIn,
    request: Request,
    p: Principal = Depends(require(P.SSO_MANAGE)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> dict:
    cfg = body.model_dump()
    if cfg["idp_sso_url"] and not cfg["idp_sso_url"].startswith("https://"):
        raise HTTPException(422, "IdP SSO URL must be https")
    if cfg["enabled"] and not (cfg["idp_entity_id"] and cfg["idp_sso_url"] and cfg["idp_x509_cert"]):
        raise HTTPException(422, "Import IdP metadata (entity ID, SSO URL, certificate) before enabling SAML")
    if cfg["idp_x509_cert"]:
        try:
            from cryptography import x509

            pem = cfg["idp_x509_cert"].strip()
            if "BEGIN CERTIFICATE" not in pem:
                pem = "-----BEGIN CERTIFICATE-----\n" + pem + "\n-----END CERTIFICATE-----"
            x509.load_pem_x509_certificate(pem.encode())
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(422, "IdP certificate is not a valid X.509 certificate") from exc
    if cfg["enabled"] and not db.scalar(select(func.count()).select_from(GroupRoleMapping)):
        raise HTTPException(422, "Map at least one group to a role before enabling SAML (otherwise nobody can sign in)")
    saml.save_config(db, cfg, p.user.username)
    audit.record(
        db,
        "settings.saml_updated",
        actor=p.user,
        request=request,
        target_type="settings",
        target_id="sso.saml",
        details={k: v for k, v in cfg.items() if k != "idp_x509_cert"},
    )
    db.commit()
    return _saml_out(db, settings)


class MetadataIn(BaseModel):
    url: str | None = Field(None, max_length=1000)
    xml: str | None = Field(None, max_length=200_000)


@router.post("/api/settings/sso/saml/metadata")
def import_metadata(
    body: MetadataIn,
    request: Request,
    p: Principal = Depends(require(P.SSO_MANAGE)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> dict:
    xml = body.xml
    if body.url:
        client = SourceClient(
            "okta-metadata", settings, rate=5, per=1.0, allowlist=[*OKTA_HOSTS, *settings.egress_allowlist_list]
        )
        try:
            xml = client.get(body.url).text  # SSRF guard: https, Okta domains or allowlist only
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(422, f"Could not fetch metadata: {type(exc).__name__}: {str(exc)[:200]}") from exc
        finally:
            client.close()
    if not xml:
        raise HTTPException(422, "Provide a metadata URL or XML")
    try:
        parsed = saml.parse_idp_metadata(xml)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(422, f"Invalid IdP metadata: {str(exc)[:200]}") from exc
    cfg = {**saml.load_config(db), **parsed}
    saml.save_config(db, cfg, p.user.username)
    audit.record(
        db,
        "settings.saml_metadata_imported",
        actor=p.user,
        request=request,
        target_type="settings",
        target_id="sso.saml",
        details={"idp_entity_id": parsed["idp_entity_id"], "source": "url" if body.url else "xml"},
    )
    db.commit()
    return _saml_out(db, settings)


class OidcConfigIn(BaseModel):
    enabled: bool = False
    issuer: str = Field("", max_length=500)
    client_id: str = Field("", max_length=255)
    client_secret: str | None = Field(None, max_length=1000)  # write-only; None keeps the stored secret
    token_auth_method: str = Field("client_secret_basic", pattern="^client_secret_(basic|post)$")
    scopes: str = Field("openid email profile groups", max_length=500)
    claim_email: str = Field("email", max_length=100)
    claim_first_name: str = Field("given_name", max_length=100)
    claim_last_name: str = Field("family_name", max_length=100)
    claim_groups: str = Field("groups", max_length=100)
    jit_provisioning: bool = True
    button_label: str = Field("Sign in with Okta", min_length=1, max_length=60)


def _oidc_out(db: Session, settings: Settings) -> dict[str, Any]:
    return {**oidc.public_config(oidc.load_config(db)), "redirect_uri": oidc.redirect_uri(settings),
            "login_url": oidc.LOGIN_PATH}


@router.get("/api/settings/sso/oidc")
def get_oidc(_: Principal = Depends(require(P.SSO_MANAGE)), db: Session = Depends(get_db),
             settings: Settings = Depends(settings_dep)) -> dict:
    return _oidc_out(db, settings)


@router.put("/api/settings/sso/oidc")
def put_oidc(body: OidcConfigIn, request: Request, p: Principal = Depends(require(P.SSO_MANAGE)),
             db: Session = Depends(get_db), settings: Settings = Depends(settings_dep)) -> dict:
    current = oidc.load_config(db)
    cfg = body.model_dump(exclude={"client_secret"})
    if cfg["issuer"]:
        try:
            cfg["issuer"] = oidc.normalize_issuer(cfg["issuer"])
        except oidc.OidcError as exc:
            raise HTTPException(422, str(exc)) from exc
    if "openid" not in cfg["scopes"].split():
        raise HTTPException(422, "Scopes must include 'openid'")
    if body.client_secret is not None:
        cfg["client_secret_enc"] = get_secret_box().encrypt(body.client_secret) if body.client_secret else ""
    else:
        cfg["client_secret_enc"] = current["client_secret_enc"]
    if cfg["enabled"]:
        if not (cfg["issuer"] and cfg["client_id"] and cfg["client_secret_enc"]):
            raise HTTPException(422, "Set the issuer, client ID and client secret before enabling OIDC")
        if not db.scalar(select(func.count()).select_from(GroupRoleMapping)):
            raise HTTPException(422, "Map at least one group to a role before enabling OIDC "
                                     "(otherwise nobody can sign in)")
        try:
            oidc.provider(settings, cfg["issuer"], refresh=True)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(422, f"OIDC discovery failed: {str(exc)[:200]}") from exc
    oidc.save_config(db, cfg, p.user.username)
    audit.record(db, "settings.oidc_updated", actor=p.user, request=request, target_type="settings",
                 target_id="sso.oidc", details={**oidc.public_config(cfg),
                                                "client_secret_changed": body.client_secret is not None})
    db.commit()
    return _oidc_out(db, settings)


@router.post("/api/settings/sso/oidc/test")
def test_oidc(p: Principal = Depends(require(P.SSO_MANAGE)), db: Session = Depends(get_db),
              settings: Settings = Depends(settings_dep)) -> dict:
    """Discovery + JWKS check (the client secret is only verified by a real sign-in)."""
    cfg = oidc.load_config(db)
    if not cfg["issuer"]:
        raise HTTPException(422, "Set the issuer first")
    try:
        entry = oidc.provider(settings, cfg["issuer"], refresh=True)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "message": f"{type(exc).__name__}: {str(exc)[:300]}"}
    meta = entry["meta"]
    return {"ok": True,
            "message": "Discovery and signing keys loaded. Finish with a test sign-in in a private window.",
            "issuer": meta["issuer"], "authorization_endpoint": meta["authorization_endpoint"],
            "token_endpoint": meta["token_endpoint"], "userinfo_endpoint": meta.get("userinfo_endpoint"),
            "keys": len(entry["jwks"].keys), "scopes_supported": meta.get("scopes_supported", [])[:30]}


# ---- group → role mapping ----------------------------------------------------------------------


class MappingIn(BaseModel):
    group_name: str = Field(min_length=1, max_length=255)
    role_id: int


@router.get("/api/settings/sso/mappings")
def list_mappings(_: Principal = Depends(require(P.SSO_MANAGE)), db: Session = Depends(get_db)) -> dict:
    roles = {r.id: r.name for r in db.scalars(select(Role))}
    sso_users = list(db.scalars(select(User).where(User.is_local.is_(False))))
    counts: dict[str, int] = {}
    for u in sso_users:
        for g in u.sso_groups or []:
            counts[g.lower()] = counts.get(g.lower(), 0) + 1
    mappings = [
        {
            "id": m.id,
            "group_name": m.group_name,
            "role_id": m.role_id,
            "role": roles.get(m.role_id),
            "users": counts.get(m.group_name.lower(), 0),
        }
        for m in db.scalars(select(GroupRoleMapping).order_by(GroupRoleMapping.group_name))
    ]
    mapped = {m["group_name"].lower() for m in mappings}
    unmapped = sorted({g for u in sso_users for g in (u.sso_groups or []) if g.lower() not in mapped})
    last_scim = db.scalar(select(func.max(ScimToken.last_used_at)))
    return {
        "mappings": mappings,
        "unmapped_groups": unmapped[:200],
        "sso_users": len(sso_users),
        "users_without_access": sum(1 for u in sso_users if not u.roles),
        "scim_groups": db.scalar(select(func.count()).select_from(ScimGroup)) or 0,
        "last_scim_activity": last_scim,
    }


def _remap(db: Session, request: Request, p: Principal, action: str, details: dict) -> None:
    changed = recompute_all(db)
    audit.record(
        db,
        action,
        actor=p.user,
        request=request,
        target_type="sso_mapping",
        details={**details, "users_recomputed": changed},
    )
    db.commit()


@router.post("/api/settings/sso/mappings", status_code=201)
def add_mapping(
    body: MappingIn,
    request: Request,
    p: Principal = Depends(require(P.SSO_MANAGE, P.ROLE_MANAGE)),
    db: Session = Depends(get_db),
) -> dict:
    role = db.get(Role, body.role_id)
    if role is None:
        raise HTTPException(422, "Unknown role")
    excess = role.permission_names - p.permissions
    if excess:
        raise HTTPException(403, f"Cannot map a role with permissions you do not hold: {', '.join(sorted(excess))}")
    name = body.group_name.strip()
    if db.scalar(
        select(GroupRoleMapping).where(
            func.lower(GroupRoleMapping.group_name) == name.lower(), GroupRoleMapping.role_id == role.id
        )
    ):
        raise HTTPException(409, "Mapping exists")
    db.add(GroupRoleMapping(group_name=name, role_id=role.id, created_by=p.user.id))
    db.flush()
    _remap(db, request, p, "sso.mapping_added", {"group": name, "role": role.name})
    return {"ok": True}


@router.delete("/api/settings/sso/mappings/{mapping_id}", status_code=204)
def delete_mapping(
    mapping_id: int,
    request: Request,
    p: Principal = Depends(require(P.SSO_MANAGE, P.ROLE_MANAGE)),
    db: Session = Depends(get_db),
) -> None:
    m = db.get(GroupRoleMapping, mapping_id)
    if m is None:
        raise HTTPException(404, "Not found")
    details = {"group": m.group_name, "role_id": m.role_id}
    db.delete(m)
    db.flush()
    _remap(db, request, p, "sso.mapping_deleted", details)


# ---- SCIM tokens ---------------------------------------------------------------------------------


class TokenIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)


class TokenOut(BaseModel):
    id: int
    name: str
    created_at: datetime
    last_used_at: datetime | None
    revoked: bool


@router.get("/api/settings/scim/tokens", response_model=list[TokenOut])
def list_tokens(_: Principal = Depends(require(P.SSO_MANAGE)), db: Session = Depends(get_db)):
    return [
        TokenOut(
            id=t.id, name=t.name, created_at=t.created_at, last_used_at=t.last_used_at, revoked=t.revoked_at is not None
        )
        for t in db.scalars(select(ScimToken).order_by(ScimToken.id))
    ]


@router.post("/api/settings/scim/tokens", status_code=201)
def create_token(
    body: TokenIn,
    request: Request,
    p: Principal = Depends(require(P.SSO_MANAGE, P.USER_MANAGE)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> dict:
    token = "excat_scim_" + secrets.token_urlsafe(32)
    t = ScimToken(name=body.name.strip(), token_hash=hashlib.sha256(token.encode()).hexdigest(), created_by=p.user.id)
    db.add(t)
    db.flush()
    audit.record(
        db,
        "scim.token_created",
        actor=p.user,
        request=request,
        target_type="scim_token",
        target_id=t.id,
        details={"name": t.name},
    )
    db.commit()
    return {
        "id": t.id,
        "token": token,
        "base_url": f"{settings.public_url.rstrip('/')}/scim/v2",
        "note": "Copy the token now — it is not shown again.",
    }


@router.delete("/api/settings/scim/tokens/{token_id}", status_code=204)
def revoke_token(
    token_id: int, request: Request, p: Principal = Depends(require(P.SSO_MANAGE)), db: Session = Depends(get_db)
) -> None:
    t = db.get(ScimToken, token_id)
    if t is None:
        raise HTTPException(404, "Not found")
    t.revoked_at = utcnow()
    audit.record(db, "scim.token_revoked", actor=p.user, request=request, target_type="scim_token", target_id=t.id)
    db.commit()
