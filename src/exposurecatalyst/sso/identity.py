"""SSO identities: group → role mapping shared by SAML logins and SCIM provisioning.

Rules
* SSO users' roles are derived **only** from GroupRoleMapping. Manual role edits are refused for them.
* An SSO user whose groups map to no role has no access (least privilege) and cannot sign in.
* An IdP/SCIM identity can never bind to a **local** account (break-glass takeover protection).
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from exposurecatalyst.models import GroupRoleMapping, Role, ScimGroup, ScimGroupMember, User
from exposurecatalyst.security.sessions import revoke_user_sessions


class NoAccessError(PermissionError):
    pass


class AccountConflictError(PermissionError):
    pass


def normalize_groups(groups: list[str] | str | None) -> list[str]:
    if groups is None:
        return []
    if isinstance(groups, str):
        groups = [groups]
    return sorted({g.strip()[:255] for g in groups if g and g.strip()})


def roles_for_groups(db: Session, groups: list[str]) -> list[Role]:
    if not groups:
        return []
    lowered = [g.lower() for g in groups]
    ids = db.scalars(select(GroupRoleMapping.role_id).where(func.lower(GroupRoleMapping.group_name).in_(lowered)))
    role_ids = set(ids)
    return list(db.scalars(select(Role).where(Role.id.in_(role_ids)))) if role_ids else []


def apply_groups(db: Session, user: User, groups: list[str]) -> bool:
    """Set the user's groups and recompute roles. Returns True if roles changed (sessions are revoked)."""
    user.sso_groups = normalize_groups(groups)
    new_roles = roles_for_groups(db, user.sso_groups)
    changed = {r.id for r in user.roles} != {r.id for r in new_roles}
    user.roles = new_roles
    if changed and user.id is not None:
        revoke_user_sessions(db, user.id)  # permissions change takes effect immediately
    return changed


def find_identity(db: Session, *, email: str | None, username: str | None) -> User | None:
    keys = {k.lower() for k in (email, username) if k}
    if not keys:
        return None
    return db.scalar(select(User).where(func.lower(User.username).in_(keys) | func.lower(User.email).in_(keys)))


def guard_not_local(user: User | None) -> None:
    if user is not None and user.is_local:
        raise AccountConflictError("identity matches a local (break-glass) account; SSO cannot sign in as it")


def scim_groups_of(db: Session, user: User) -> list[str]:
    return list(
        db.scalars(
            select(ScimGroup.display_name)
            .join(ScimGroupMember, ScimGroupMember.group_id == ScimGroup.id)
            .where(ScimGroupMember.user_id == user.id)
        )
    )


def recompute_all(db: Session) -> int:
    """After mapping changes: recompute roles for every SSO user. Returns number of users whose roles changed."""
    n = 0
    for u in db.scalars(select(User).where(User.is_local.is_(False))):
        n += apply_groups(db, u, u.sso_groups or [])
    return n
