"""Authentication, CSRF and authorization dependencies.

Every router except /api/health and /api/auth/login depends on ``current_session``; a test asserts
that no /api route is reachable anonymously by accident.
"""

from __future__ import annotations

import hmac
from collections.abc import Callable
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from exposurecatalyst.config import Settings, get_settings
from exposurecatalyst.db.session import get_db
from exposurecatalyst.models import User, UserSession
from exposurecatalyst.security.middleware import UNSAFE_METHODS
from exposurecatalyst.security.rbac import ADMIN_PERMISSIONS, Permission, user_permissions
from exposurecatalyst.security.sessions import cookie_names, resolve_session

CSRF_HEADER = "x-csrf-token"


@dataclass
class Principal:
    user: User
    session: UserSession
    permissions: set[str]

    def has(self, perm: str) -> bool:
        return perm in self.permissions


def settings_dep() -> Settings:
    return get_settings()


def current_principal(
    request: Request, db: Session = Depends(get_db), settings: Settings = Depends(settings_dep)
) -> Principal:
    session_cookie, _ = cookie_names(settings)
    sess = resolve_session(db, request.cookies.get(session_cookie), settings)
    if sess is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    if request.method in UNSAFE_METHODS:
        sent = request.headers.get(CSRF_HEADER, "")
        if not sent or not hmac.compare_digest(sent, sess.csrf_token):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF token missing or invalid")
    principal = Principal(user=sess.user, session=sess, permissions=user_permissions(sess.user))
    request.state.principal = principal
    return principal


def require(*perms: Permission) -> Callable[..., Principal]:
    """Dependency factory: the caller must hold *all* listed permissions."""

    def checker(
        principal: Principal = Depends(current_principal), settings: Settings = Depends(settings_dep)
    ) -> Principal:
        missing = [p for p in perms if p not in principal.permissions]
        if missing:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Missing permission: {', '.join(missing)}")
        admin_action = any(p in ADMIN_PERMISSIONS for p in perms)
        if (admin_action and settings.require_mfa_for_local_admins and principal.user.is_local
                and not principal.session.mfa_verified):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "MFA enrolment required for admin actions")
        return principal

    return checker


def require_any(*perms: Permission) -> Callable[..., Principal]:
    """Dependency factory: the caller must hold *at least one* of the listed permissions."""

    def checker(principal: Principal = Depends(current_principal)) -> Principal:
        if not any(p in principal.permissions for p in perms):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Requires one of: {', '.join(perms)}")
        return principal

    return checker


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None
