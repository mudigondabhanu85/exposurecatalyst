"""SCIM 2.0 (RFC 7643/7644) for SailPoint IdentityNow / ISC and IdentityIQ provisioning.

Auth: ``Authorization: Bearer <token>`` (Settings → Identity & SSO → SCIM tokens; stored as SHA-256).
Users map to SSO accounts (never to local break-glass accounts); Group membership → ``users.sso_groups`` →
roles through the group → role mapping. DELETE /Users deactivates (keeps audit history).
"""

from __future__ import annotations

import hashlib
import re
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from exposurecatalyst.api.deps import settings_dep
from exposurecatalyst.config import Settings
from exposurecatalyst.db.base import utcnow
from exposurecatalyst.db.session import get_db
from exposurecatalyst.models import ScimGroup, ScimGroupMember, ScimToken, User
from exposurecatalyst.security import audit
from exposurecatalyst.security.sessions import revoke_user_sessions
from exposurecatalyst.sso.identity import apply_groups, guard_not_local, scim_groups_of

router = APIRouter(prefix="/scim/v2", tags=["scim"])
CT = "application/scim+json"
U_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
G_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
ERR = "urn:ietf:params:scim:api:messages:2.0:Error"
PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
FILTER_RE = re.compile(r'^\s*(userName|displayName|externalId)\s+eq\s+"([^"]{1,255})"\s*$', re.IGNORECASE)
MAX_COUNT = 200


class ScimError(Exception):
    def __init__(self, status: int, detail: str, scim_type: str | None = None):
        self.status, self.detail, self.scim_type = status, detail, scim_type


def scim_json(body: Any, status: int = 200) -> JSONResponse:
    return JSONResponse(body, status_code=status, media_type=CT)


def error_response(exc: ScimError) -> JSONResponse:
    body = {"schemas": [ERR], "status": str(exc.status), "detail": exc.detail}
    if exc.scim_type:
        body["scimType"] = exc.scim_type
    return scim_json(body, exc.status)


def scim_auth(request: Request, db: Session = Depends(get_db)) -> ScimToken:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer ") or len(header) > 512:
        raise ScimError(401, "Bearer token required")
    digest = hashlib.sha256(header[7:].strip().encode()).hexdigest()
    tok = db.scalar(select(ScimToken).where(ScimToken.token_hash == digest, ScimToken.revoked_at.is_(None)))
    if tok is None:
        raise ScimError(401, "Invalid or revoked token")
    tok.last_used_at = utcnow()
    return tok


def _loc(settings: Settings, kind: str, rid: str) -> str:
    return f"{settings.public_url.rstrip('/')}/scim/v2/{kind}/{rid}"


def user_resource(db: Session, u: User, settings: Settings) -> dict[str, Any]:
    first, _, last = (u.display_name or "").partition(" ")
    groups = db.scalars(
        select(ScimGroup)
        .join(ScimGroupMember, ScimGroupMember.group_id == ScimGroup.id)
        .where(ScimGroupMember.user_id == u.id)
    )
    return {
        "schemas": [U_SCHEMA],
        "id": u.scim_id,
        "externalId": u.external_id,
        "userName": u.username,
        "displayName": u.display_name,
        "name": {"givenName": first or None, "familyName": last or None},
        "emails": [{"value": u.email, "type": "work", "primary": True}] if u.email else [],
        "active": u.is_active,
        "groups": [{"value": g.id, "display": g.display_name} for g in groups],
        "meta": {
            "resourceType": "User",
            "created": u.created_at.isoformat(),
            "lastModified": u.updated_at.isoformat(),
            "location": _loc(settings, "Users", u.scim_id or ""),
        },
    }


def group_resource(db: Session, g: ScimGroup, settings: Settings) -> dict[str, Any]:
    members = db.scalars(
        select(User).join(ScimGroupMember, ScimGroupMember.user_id == User.id).where(ScimGroupMember.group_id == g.id)
    )
    return {
        "schemas": [G_SCHEMA],
        "id": g.id,
        "externalId": g.external_id,
        "displayName": g.display_name,
        "members": [{"value": m.scim_id, "display": m.username} for m in members if m.scim_id],
        "meta": {
            "resourceType": "Group",
            "created": g.created_at.isoformat(),
            "lastModified": g.updated_at.isoformat(),
            "location": _loc(settings, "Groups", g.id),
        },
    }


def _sync_user_groups(db: Session, user: User) -> None:
    apply_groups(db, user, scim_groups_of(db, user))


def _get_user(db: Session, sid: str) -> User:
    u = db.scalar(select(User).where(User.scim_id == sid))
    if u is None:
        raise ScimError(404, f"User {sid} not found")
    return u


def _get_group(db: Session, gid: str) -> ScimGroup:
    g = db.get(ScimGroup, gid)
    if g is None:
        raise ScimError(404, f"Group {gid} not found")
    return g


def _apply_user(u: User, body: dict[str, Any]) -> None:
    if "userName" in body:
        name = str(body["userName"]).strip().lower()
        if not name or len(name) > 150:
            raise ScimError(400, "invalid userName", "invalidValue")
        u.username = name
    emails = body.get("emails")
    if isinstance(emails, list) and emails:
        primary = next((e for e in emails if isinstance(e, dict) and e.get("primary")), emails[0])
        u.email = str(primary.get("value", "")).strip().lower()[:320] or u.email
    elif not u.email and "@" in u.username:
        u.email = u.username
    name = body.get("name") if isinstance(body.get("name"), dict) else {}
    display = body.get("displayName") or " ".join(x for x in (name.get("givenName"), name.get("familyName")) if x)
    if display:
        u.display_name = str(display)[:200]
    if "externalId" in body:
        u.external_id = str(body["externalId"])[:255] if body["externalId"] else None
    if "active" in body:
        u.is_active = bool(body["active"]) if not isinstance(body["active"], str) else body["active"].lower() == "true"


def _list(items: list[dict[str, Any]], start: int, total: int) -> JSONResponse:
    return scim_json(
        {"schemas": [LIST], "totalResults": total, "startIndex": start, "itemsPerPage": len(items), "Resources": items}
    )


def _page(request: Request) -> tuple[int, int, re.Match | None]:
    try:
        start = max(1, int(request.query_params.get("startIndex", 1)))
        count = min(MAX_COUNT, max(0, int(request.query_params.get("count", 100))))
    except ValueError as exc:
        raise ScimError(400, "startIndex/count must be integers", "invalidValue") from exc
    flt = request.query_params.get("filter")
    m = FILTER_RE.match(flt) if flt else None
    if flt and m is None:
        raise ScimError(
            400, 'only `attr eq "value"` filters on userName/displayName/externalId are supported', "invalidFilter"
        )
    return start, count, m


# ---- discovery ------------------------------------------------------------------------------------


@router.get("/ServiceProviderConfig")
def service_provider_config(_: ScimToken = Depends(scim_auth)) -> JSONResponse:
    return scim_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": {"supported": True},
            "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": MAX_COUNT},
            "changePassword": {"supported": False},
            "sort": {"supported": False},
            "etag": {"supported": False},
            "authenticationSchemes": [
                {
                    "type": "oauthbearertoken",
                    "name": "Bearer token",
                    "primary": True,
                    "description": "Token from Settings → Identity & SSO → SCIM tokens",
                }
            ],
        }
    )


@router.get("/ResourceTypes")
def resource_types(_: ScimToken = Depends(scim_auth)) -> JSONResponse:
    return _list(
        [
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "User",
                "name": "User",
                "endpoint": "/Users",
                "schema": U_SCHEMA,
            },
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "Group",
                "name": "Group",
                "endpoint": "/Groups",
                "schema": G_SCHEMA,
            },
        ],
        1,
        2,
    )


@router.get("/Schemas")
def schemas(_: ScimToken = Depends(scim_auth)) -> JSONResponse:
    return _list([{"id": U_SCHEMA, "name": "User"}, {"id": G_SCHEMA, "name": "Group"}], 1, 2)


# ---- Users ------------------------------------------------------------------------------------------


@router.get("/Users")
def list_users(
    request: Request,
    _: ScimToken = Depends(scim_auth),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> JSONResponse:
    start, count, m = _page(request)
    stmt = select(User).where(User.is_local.is_(False), User.scim_id.is_not(None))
    if m:
        col = {"username": User.username, "externalid": User.external_id, "displayname": User.display_name}[
            m.group(1).lower()
        ]
        stmt = stmt.where(func.lower(col) == m.group(2).lower())
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(User.id).offset(start - 1).limit(count))
    resp = _list([user_resource(db, u, settings) for u in rows], start, total)
    db.commit()
    return resp


@router.get("/Users/{sid}")
def get_user(
    sid: str,
    _: ScimToken = Depends(scim_auth),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> JSONResponse:
    resp = scim_json(user_resource(db, _get_user(db, sid), settings))
    db.commit()
    return resp


@router.post("/Users")
async def create_user(
    request: Request,
    tok: ScimToken = Depends(scim_auth),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> JSONResponse:
    body = await request.json()
    username = str(body.get("userName", "")).strip().lower()
    if not username:
        raise ScimError(400, "userName is required", "invalidValue")
    existing = db.scalar(select(User).where(func.lower(User.username) == username))
    guard = existing
    if guard is not None and guard.is_local:
        raise ScimError(409, "userName matches a local account", "uniqueness")
    if existing is not None and existing.scim_id:
        raise ScimError(409, "User already exists", "uniqueness")
    u = existing or User(username=username, is_local=False, password_hash=None, roles=[], sso_groups=[])
    u.auth_source, u.scim_id = "scim", str(uuid.uuid4())
    _apply_user(u, body)
    if u.email and db.scalar(select(User).where(func.lower(User.email) == u.email, User.id != (u.id or 0))):
        raise ScimError(409, "email already used by another account", "uniqueness")
    db.add(u)
    db.flush()
    _sync_user_groups(db, u)
    audit.record(
        db,
        "scim.user_created",
        actor_username=f"scim:{tok.name}",
        request=request,
        target_type="user",
        target_id=u.id,
        details={"userName": u.username, "externalId": u.external_id},
    )
    resp = scim_json(user_resource(db, u, settings), 201)
    db.commit()
    return resp


@router.put("/Users/{sid}")
async def replace_user(
    sid: str,
    request: Request,
    tok: ScimToken = Depends(scim_auth),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> JSONResponse:
    u = _get_user(db, sid)
    body = await request.json()
    _apply_user(u, {"active": True, **body})
    if not u.is_active:
        revoke_user_sessions(db, u.id)
    audit.record(
        db,
        "scim.user_replaced",
        actor_username=f"scim:{tok.name}",
        request=request,
        target_type="user",
        target_id=u.id,
        details={"active": u.is_active},
    )
    resp = scim_json(user_resource(db, u, settings))
    db.commit()
    return resp


@router.patch("/Users/{sid}")
async def patch_user(
    sid: str,
    request: Request,
    tok: ScimToken = Depends(scim_auth),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> JSONResponse:
    u = _get_user(db, sid)
    body = await request.json()
    for op in body.get("Operations", []):
        kind = str(op.get("op", "")).lower()
        if kind not in ("replace", "add"):
            continue
        path, value = op.get("path"), op.get("value")
        if path:
            key = {
                "active": "active",
                "displayname": "displayName",
                "username": "userName",
                "externalid": "externalId",
                "name.givenname": "givenName",
                "name.familyname": "familyName",
                "emails": "emails",
                'emails[type eq "work"].value': "workEmail",
            }.get(str(path).lower())
            if key in ("givenName", "familyName"):
                _apply_user(u, {"name": {key: value}})
            elif key == "workEmail":
                _apply_user(u, {"emails": [{"value": value, "primary": True}]})
            elif key:
                _apply_user(u, {key: value})
        elif isinstance(value, dict):
            _apply_user(u, value)
    if not u.is_active:
        revoke_user_sessions(db, u.id)
    audit.record(
        db,
        "scim.user_patched",
        actor_username=f"scim:{tok.name}",
        request=request,
        target_type="user",
        target_id=u.id,
        details={"active": u.is_active},
    )
    resp = scim_json(user_resource(db, u, settings))
    db.commit()
    return resp


@router.delete("/Users/{sid}", status_code=204)
def delete_user(
    sid: str, request: Request, tok: ScimToken = Depends(scim_auth), db: Session = Depends(get_db)
) -> Response:
    u = _get_user(db, sid)
    u.is_active = False
    u.roles = []
    revoke_user_sessions(db, u.id)
    audit.record(
        db,
        "scim.user_deactivated",
        actor_username=f"scim:{tok.name}",
        request=request,
        target_type="user",
        target_id=u.id,
    )
    db.commit()
    return Response(status_code=204)


# ---- Groups -----------------------------------------------------------------------------------------


def _set_members(db: Session, g: ScimGroup, scim_ids: list[str], *, mode: str) -> None:
    users = list(db.scalars(select(User).where(User.scim_id.in_(scim_ids)))) if scim_ids else []
    for u in users:
        guard_not_local(u)
    current = set(db.scalars(select(ScimGroupMember.user_id).where(ScimGroupMember.group_id == g.id)))
    target_ids = {u.id for u in users}
    if mode == "replace":
        remove, add = current - target_ids, target_ids - current
    elif mode == "add":
        remove, add = set(), target_ids - current
    else:
        remove, add = current & target_ids, set()
    for uid in remove:
        db.delete(db.get(ScimGroupMember, (g.id, uid)))
    for uid in add:
        db.add(ScimGroupMember(group_id=g.id, user_id=uid))
    db.flush()
    for uid in remove | add:
        _sync_user_groups(db, db.get(User, uid))


def _member_ids(value: Any) -> list[str]:
    if isinstance(value, dict):
        value = value.get("members", [value])
    return [str(m.get("value")) for m in (value or []) if isinstance(m, dict) and m.get("value")]


@router.get("/Groups")
def list_groups(
    request: Request,
    _: ScimToken = Depends(scim_auth),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> JSONResponse:
    start, count, m = _page(request)
    stmt = select(ScimGroup)
    if m:
        col = ScimGroup.external_id if m.group(1).lower() == "externalid" else ScimGroup.display_name
        stmt = stmt.where(func.lower(col) == m.group(2).lower())
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(ScimGroup.display_name).offset(start - 1).limit(count))
    resp = _list([group_resource(db, g, settings) for g in rows], start, total)
    db.commit()
    return resp


@router.get("/Groups/{gid}")
def get_group(
    gid: str,
    _: ScimToken = Depends(scim_auth),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> JSONResponse:
    resp = scim_json(group_resource(db, _get_group(db, gid), settings))
    db.commit()
    return resp


@router.post("/Groups")
async def create_group(
    request: Request,
    tok: ScimToken = Depends(scim_auth),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> JSONResponse:
    body = await request.json()
    name = str(body.get("displayName", "")).strip()
    if not name:
        raise ScimError(400, "displayName is required", "invalidValue")
    if db.scalar(select(ScimGroup).where(func.lower(ScimGroup.display_name) == name.lower())):
        raise ScimError(409, "Group already exists", "uniqueness")
    g = ScimGroup(id=str(uuid.uuid4()), display_name=name[:255], external_id=body.get("externalId"))
    db.add(g)
    db.flush()
    _set_members(db, g, _member_ids(body.get("members")), mode="replace")
    audit.record(
        db,
        "scim.group_created",
        actor_username=f"scim:{tok.name}",
        request=request,
        target_type="scim_group",
        target_id=g.id,
        details={"displayName": g.display_name},
    )
    resp = scim_json(group_resource(db, g, settings), 201)
    db.commit()
    return resp


@router.put("/Groups/{gid}")
async def replace_group(
    gid: str,
    request: Request,
    tok: ScimToken = Depends(scim_auth),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> JSONResponse:
    g = _get_group(db, gid)
    body = await request.json()
    old = g.display_name
    if body.get("displayName"):
        g.display_name = str(body["displayName"])[:255]
    _set_members(db, g, _member_ids(body.get("members")), mode="replace")
    if g.display_name != old:  # renamed: every member's mapped roles may change
        for uid in db.scalars(select(ScimGroupMember.user_id).where(ScimGroupMember.group_id == g.id)):
            _sync_user_groups(db, db.get(User, uid))
    audit.record(
        db,
        "scim.group_replaced",
        actor_username=f"scim:{tok.name}",
        request=request,
        target_type="scim_group",
        target_id=g.id,
        details={"displayName": g.display_name},
    )
    resp = scim_json(group_resource(db, g, settings))
    db.commit()
    return resp


@router.patch("/Groups/{gid}")
async def patch_group(
    gid: str,
    request: Request,
    tok: ScimToken = Depends(scim_auth),
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> Response:
    g = _get_group(db, gid)
    body = await request.json()
    for op in body.get("Operations", []):
        kind, path, value = str(op.get("op", "")).lower(), str(op.get("path") or ""), op.get("value")
        if path.lower().startswith("members[value eq"):  # remove single member: members[value eq "id"]
            mm = re.search(r'"([^"]+)"', path)
            if mm:
                _set_members(db, g, [mm.group(1)], mode="remove")
        elif path.lower() == "members" or (not path and isinstance(value, dict) and "members" in value):
            mode = {"add": "add", "remove": "remove", "replace": "replace"}.get(kind)
            if mode:
                _set_members(db, g, _member_ids(value), mode=mode)
        elif path.lower() == "displayname" or (not path and isinstance(value, dict) and "displayName" in value):
            g.display_name = str(value if path else value["displayName"])[:255]
            for uid in db.scalars(select(ScimGroupMember.user_id).where(ScimGroupMember.group_id == g.id)):
                _sync_user_groups(db, db.get(User, uid))
    audit.record(
        db,
        "scim.group_patched",
        actor_username=f"scim:{tok.name}",
        request=request,
        target_type="scim_group",
        target_id=g.id,
        details={"operations": len(body.get("Operations", []))},
    )
    resp = scim_json(group_resource(db, g, settings))
    db.commit()
    return resp


@router.delete("/Groups/{gid}", status_code=204)
def delete_group(
    gid: str, request: Request, tok: ScimToken = Depends(scim_auth), db: Session = Depends(get_db)
) -> Response:
    g = _get_group(db, gid)
    members = list(db.scalars(select(ScimGroupMember.user_id).where(ScimGroupMember.group_id == g.id)))
    db.delete(g)
    db.flush()
    for uid in members:
        _sync_user_groups(db, db.get(User, uid))
    audit.record(
        db,
        "scim.group_deleted",
        actor_username=f"scim:{tok.name}",
        request=request,
        target_type="scim_group",
        target_id=gid,
    )
    db.commit()
    return Response(status_code=204)
