"""Users, roles and the permission matrix (Settings → RBAC). Authorization is enforced here, not in the UI."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from exposurecatalyst.api.deps import Principal, require, settings_dep
from exposurecatalyst.config import Settings
from exposurecatalyst.db.session import get_db
from exposurecatalyst.models import AuditLog, Role, RolePermission, User
from exposurecatalyst.security import audit
from exposurecatalyst.security.passwords import hash_password, password_problems
from exposurecatalyst.security.rbac import PERMISSION_DESCRIPTIONS, Permission
from exposurecatalyst.security.sessions import revoke_user_sessions

router = APIRouter(prefix="/api/admin", tags=["admin"])


class RoleOut(BaseModel):
    id: int
    name: str
    description: str | None
    is_system: bool
    permissions: list[str]
    user_count: int


class MatrixOut(BaseModel):
    permissions: list[dict[str, str]]
    roles: list[RoleOut]


def _role_out(db: Session, r: Role) -> RoleOut:
    count = db.scalar(select(func.count()).select_from(User).where(User.roles.any(Role.id == r.id))) or 0
    return RoleOut(id=r.id, name=r.name, description=r.description, is_system=r.is_system,
                   permissions=sorted(r.permission_names), user_count=count)


@router.get("/rbac", response_model=MatrixOut)
def matrix(_: Principal = Depends(require(Permission.USER_MANAGE)), db: Session = Depends(get_db)) -> MatrixOut:
    perms = [{"id": str(p), "description": PERMISSION_DESCRIPTIONS[p]} for p in Permission]
    roles = [_role_out(db, r) for r in db.scalars(select(Role).order_by(Role.is_system.desc(), Role.name))]
    return MatrixOut(permissions=perms, roles=roles)


class RoleIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    description: str | None = Field(None, max_length=500)
    permissions: list[Permission]


@router.post("/roles", response_model=RoleOut, status_code=201)
def create_role(body: RoleIn, request: Request, p: Principal = Depends(require(Permission.ROLE_MANAGE)),
                db: Session = Depends(get_db)) -> RoleOut:
    if db.scalar(select(Role).where(func.lower(Role.name) == body.name.strip().lower())):
        raise HTTPException(409, "Role name already exists")
    role = Role(name=body.name.strip(), description=body.description, is_system=False,
                permissions=[RolePermission(permission=str(x)) for x in set(body.permissions)])
    db.add(role)
    db.flush()
    audit.record(db, "role.created", actor=p.user, request=request, target_type="role", target_id=role.id,
                 details={"name": role.name, "permissions": sorted(role.permission_names)})
    db.commit()
    return _role_out(db, role)


@router.put("/roles/{role_id}", response_model=RoleOut)
def update_role(role_id: int, body: RoleIn, request: Request,
                p: Principal = Depends(require(Permission.ROLE_MANAGE)), db: Session = Depends(get_db)) -> RoleOut:
    role = db.get(Role, role_id)
    if role is None:
        raise HTTPException(404, "Role not found")
    if role.is_system:
        raise HTTPException(409, "System roles are read-only; create a custom role instead")
    before = sorted(role.permission_names)
    role.name, role.description = body.name.strip(), body.description
    role.permissions.clear()
    db.flush()
    role.permissions.extend(RolePermission(permission=str(x)) for x in set(body.permissions))
    audit.record(db, "role.updated", actor=p.user, request=request, target_type="role", target_id=role.id,
                 details={"before": before, "after": sorted(role.permission_names)})
    db.commit()
    return _role_out(db, role)


@router.delete("/roles/{role_id}", status_code=204)
def delete_role(role_id: int, request: Request, p: Principal = Depends(require(Permission.ROLE_MANAGE)),
                db: Session = Depends(get_db)) -> None:
    role = db.get(Role, role_id)
    if role is None:
        raise HTTPException(404, "Role not found")
    if role.is_system:
        raise HTTPException(409, "System roles cannot be deleted")
    if role.users:
        raise HTTPException(409, f"Role is assigned to {len(role.users)} user(s); reassign them first")
    audit.record(db, "role.deleted", actor=p.user, request=request, target_type="role", target_id=role.id,
                 details={"name": role.name})
    db.delete(role)
    db.commit()


class UserOut(BaseModel):
    id: int
    username: str
    email: str | None
    display_name: str | None
    is_active: bool
    is_local: bool
    mfa_enabled: bool
    locked: bool
    roles: list[str]
    last_login_at: datetime | None
    auth_source: str = "local"
    sso_groups: list[str] = []


def _user_out(u: User) -> UserOut:
    return UserOut(id=u.id, username=u.username, email=u.email, display_name=u.display_name,
                   is_active=u.is_active, is_local=u.is_local, mfa_enabled=u.totp_enabled,
                   locked=u.locked_until is not None, roles=sorted(r.name for r in u.roles),
                   last_login_at=u.last_login_at, auth_source=u.auth_source or "local", sso_groups=u.sso_groups or [])


@router.get("/users", response_model=list[UserOut])
def list_users(_: Principal = Depends(require(Permission.USER_MANAGE)), db: Session = Depends(get_db)):
    return [_user_out(u) for u in db.scalars(select(User).order_by(User.username))]


class UserIn(BaseModel):
    username: str = Field(min_length=3, max_length=150, pattern=r"^[A-Za-z0-9._@-]+$")
    email: EmailStr | None = None
    display_name: str | None = Field(None, max_length=200)
    password: str = Field(max_length=256)
    role_ids: list[int] = []


def _check_escalation(db: Session, actor: Principal, role_ids: list[int]) -> list[Role]:
    roles = list(db.scalars(select(Role).where(Role.id.in_(role_ids)))) if role_ids else []
    if len(roles) != len(set(role_ids)):
        raise HTTPException(422, "Unknown role id")
    granted = set().union(*(r.permission_names for r in roles)) if roles else set()
    excess = granted - actor.permissions
    if excess:  # nobody can hand out permissions they do not hold themselves
        raise HTTPException(403, f"Cannot grant permissions you do not hold: {', '.join(sorted(excess))}")
    return roles


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(body: UserIn, request: Request, p: Principal = Depends(require(Permission.USER_MANAGE)),
                db: Session = Depends(get_db), settings: Settings = Depends(settings_dep)) -> UserOut:
    problems = password_problems(body.password, username=body.username, min_length=settings.password_min_length)
    if problems:
        raise HTTPException(422, "Password " + "; ".join(problems))
    if db.scalar(select(User).where(func.lower(User.username) == body.username.lower())):
        raise HTTPException(409, "Username already exists")
    roles = _check_escalation(db, p, body.role_ids)
    user = User(username=body.username, email=body.email, display_name=body.display_name,
                password_hash=hash_password(body.password), is_local=True, roles=roles)
    db.add(user)
    db.flush()
    audit.record(db, "user.created", actor=p.user, request=request, target_type="user", target_id=user.id,
                 details={"username": user.username, "roles": [r.name for r in roles]})
    db.commit()
    return _user_out(user)


class UserRolesIn(BaseModel):
    role_ids: list[int]


@router.put("/users/{user_id}/roles", response_model=UserOut)
def set_user_roles(user_id: int, body: UserRolesIn, request: Request,
                   p: Principal = Depends(require(Permission.USER_MANAGE)), db: Session = Depends(get_db)) -> UserOut:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "User not found")
    if user.id == p.user.id:
        raise HTTPException(409, "You cannot change your own roles")
    if not user.is_local:
        raise HTTPException(409, "Roles of SSO users come from group → role mappings (Settings → Identity & SSO)")
    roles = _check_escalation(db, p, body.role_ids)
    before = sorted(r.name for r in user.roles)
    user.roles = roles
    revoke_user_sessions(db, user.id)  # new permissions take effect on next login
    audit.record(db, "user.roles_changed", actor=p.user, request=request, target_type="user", target_id=user.id,
                 details={"before": before, "after": sorted(r.name for r in roles)})
    db.commit()
    return _user_out(user)


class UserStatusIn(BaseModel):
    is_active: bool | None = None
    unlock: bool = False


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user_status(user_id: int, body: UserStatusIn, request: Request,
                       p: Principal = Depends(require(Permission.USER_MANAGE)),
                       db: Session = Depends(get_db)) -> UserOut:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "User not found")
    if user.id == p.user.id and body.is_active is False:
        raise HTTPException(409, "You cannot deactivate yourself")
    if body.unlock:
        user.locked_until, user.failed_login_count = None, 0
    if body.is_active is not None:
        user.is_active = body.is_active
        if not body.is_active:
            revoke_user_sessions(db, user.id)
    audit.record(db, "user.status_changed", actor=p.user, request=request, target_type="user", target_id=user.id,
                 details=body.model_dump())
    db.commit()
    return _user_out(user)


class AuditOut(BaseModel):
    id: int
    occurred_at: datetime
    actor_username: str | None
    action: str
    target_type: str | None
    target_id: str | None
    outcome: str
    ip_address: str | None
    details: dict


@router.get("/audit", response_model=list[AuditOut])
def audit_log(action: str | None = Query(None, max_length=64), before_id: int | None = None,
              limit: int = Query(100, ge=1, le=500), p: Principal = Depends(require(Permission.AUDIT_VIEW)),
              db: Session = Depends(get_db)):
    stmt = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if before_id:
        stmt = stmt.where(AuditLog.id < before_id)
    return [AuditOut.model_validate(r, from_attributes=True) for r in db.scalars(stmt)]
