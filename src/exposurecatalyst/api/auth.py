from __future__ import annotations

from datetime import timedelta

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from exposurecatalyst.api.deps import Principal, client_ip, current_principal, settings_dep
from exposurecatalyst.config import Settings
from exposurecatalyst.db.base import as_utc, utcnow
from exposurecatalyst.db.session import get_db
from exposurecatalyst.models import User
from exposurecatalyst.security import audit
from exposurecatalyst.security.crypto import get_secret_box
from exposurecatalyst.security.middleware import SlidingWindowLimiter
from exposurecatalyst.security.passwords import (
    hash_password,
    needs_rehash,
    password_problems,
    verify_password,
)
from exposurecatalyst.security.rbac import user_permissions
from exposurecatalyst.security.sessions import cookie_names, create_session, revoke_user_sessions

router = APIRouter(prefix="/api/auth", tags=["auth"])
_limiter: SlidingWindowLimiter | None = None
GENERIC_FAIL = "Invalid username, password or verification code"


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=150)
    password: str = Field(min_length=1, max_length=256)
    totp_code: str | None = Field(None, pattern=r"^\d{6}$")


class MeOut(BaseModel):
    id: int
    username: str
    display_name: str | None
    email: str | None
    roles: list[str]
    permissions: list[str]
    mfa_enabled: bool
    mfa_verified: bool
    tour_completed: bool
    csrf_token: str
    must_change_password: bool = False
    first_login_pending: bool = False  # default break-glass account: new password and/or MFA enrolment pending


def _me(p: Principal) -> MeOut:
    u = p.user
    return MeOut(id=u.id, username=u.username, display_name=u.display_name, email=u.email,
                 roles=sorted(r.name for r in u.roles), permissions=sorted(p.permissions),
                 mfa_enabled=u.totp_enabled, mfa_verified=p.session.mfa_verified,
                 tour_completed=u.tour_completed, csrf_token=p.session.csrf_token,
                 must_change_password=bool(u.must_change_password), first_login_pending=_first_login(u))


def _first_login(u: User) -> bool:
    from exposurecatalyst.config import get_settings

    s = get_settings()
    bootstrap = s.bootstrap_admin and u.username == s.bootstrap_admin_username and u.is_local
    return bool(u.must_change_password) or (bootstrap and s.require_mfa_for_local_admins and not u.totp_enabled)


def _verify_totp(user: User, code: str) -> bool:
    if not user.totp_secret_enc:
        return False
    totp = pyotp.TOTP(get_secret_box().decrypt(user.totp_secret_enc))
    now = utcnow()
    for offset in (-1, 0, 1):  # ±30 s clock drift
        counter = int(now.timestamp()) // 30 + offset
        if totp.at(counter * 30) == code:
            if user.totp_last_counter is not None and counter <= user.totp_last_counter:
                return False  # replayed code
            user.totp_last_counter = counter
            return True
    return False


def _set_cookies(response: Response, settings: Settings, token: str, csrf: str) -> None:
    session_cookie, csrf_cookie = cookie_names(settings)
    max_age = settings.session_absolute_timeout_minutes * 60
    response.set_cookie(session_cookie, token, max_age=max_age, httponly=True, secure=settings.cookie_secure,
                        samesite="strict", path="/")
    # Readable by the SPA so it can echo it in X-CSRF-Token (double-submit, bound to the session row).
    response.set_cookie(csrf_cookie, csrf, max_age=max_age, httponly=False, secure=settings.cookie_secure,
                        samesite="strict", path="/")


@router.post("/login", response_model=MeOut)
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db),
          settings: Settings = Depends(settings_dep)) -> MeOut:
    global _limiter
    if _limiter is None or _limiter.limit != settings.login_rate_limit_per_minute:
        _limiter = SlidingWindowLimiter(settings.login_rate_limit_per_minute)
    ip = client_ip(request) or "unknown"
    if not _limiter.allow(ip):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many login attempts; try again shortly")

    user = db.scalar(select(User).where(func.lower(User.username) == body.username.strip().lower()))
    now = utcnow()
    if user is not None and user.locked_until and as_utc(user.locked_until) > now:
        verify_password(body.password, None)  # constant-ish timing
        audit.record(db, "auth.login", actor_username=body.username[:150], request=request,
                     outcome="failure", details={"reason": "locked"})
        db.commit()
        raise HTTPException(status.HTTP_423_LOCKED, "Account temporarily locked. Try later or contact an admin.")

    ok = verify_password(body.password, user.password_hash if user else None)
    if ok and user is not None and user.is_active and user.totp_enabled:
        if not body.totp_code:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, {"message": "Verification code required",
                                                                "mfa_required": True})
        ok = _verify_totp(user, body.totp_code)

    if not ok or user is None or not user.is_active:
        if user is not None:
            user.failed_login_count = (user.failed_login_count or 0) + 1
            if user.failed_login_count >= settings.login_max_attempts:
                user.locked_until = now + timedelta(minutes=settings.login_lockout_minutes)
                user.failed_login_count = 0
                audit.record(db, "auth.lockout", actor=user, request=request, outcome="failure")
        audit.record(db, "auth.login", actor_username=body.username[:150], request=request, outcome="failure")
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, GENERIC_FAIL)

    if needs_rehash(user.password_hash or ""):
        user.password_hash = hash_password(body.password)
    user.failed_login_count, user.locked_until, user.last_login_at = 0, None, now
    token, sess = create_session(db, user, settings, ip=ip, user_agent=request.headers.get("user-agent"),
                                 mfa_verified=user.totp_enabled)
    audit.record(db, "auth.login", actor=user, request=request, details={"mfa": user.totp_enabled})
    db.commit()
    _set_cookies(response, settings, token, sess.csrf_token)
    return _me(Principal(user=user, session=sess, permissions=user_permissions(user)))


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response, p: Principal = Depends(current_principal),
           db: Session = Depends(get_db), settings: Settings = Depends(settings_dep)) -> Response:
    p.session.revoked_at = utcnow()
    db.merge(p.session)
    audit.record(db, "auth.logout", actor=p.user, request=request)
    db.commit()
    for name in cookie_names(settings):
        response.delete_cookie(name, path="/", secure=settings.cookie_secure, samesite="strict")
    response.status_code = 204
    return response


@router.get("/me", response_model=MeOut)
def me(p: Principal = Depends(current_principal)) -> MeOut:
    return _me(p)


class MfaSetupOut(BaseModel):
    secret: str
    otpauth_uri: str


@router.post("/mfa/setup", response_model=MfaSetupOut)
def mfa_setup(request: Request, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    user = db.merge(p.user)
    if user.totp_enabled:
        raise HTTPException(409, "MFA already enabled")
    secret = pyotp.random_base32()
    user.totp_secret_enc = get_secret_box().encrypt(secret)
    db.commit()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.username, issuer_name="ExposureCatalyst")
    return MfaSetupOut(secret=secret, otpauth_uri=uri)


class CodeIn(BaseModel):
    totp_code: str = Field(pattern=r"^\d{6}$")


@router.post("/mfa/enable", status_code=204)
def mfa_enable(body: CodeIn, request: Request, p: Principal = Depends(current_principal),
               db: Session = Depends(get_db)) -> Response:
    user = db.merge(p.user)
    if not _verify_totp(user, body.totp_code):
        raise HTTPException(400, "Invalid verification code")
    user.totp_enabled = True
    sess = db.merge(p.session)
    sess.mfa_verified = True
    audit.record(db, "auth.mfa_enabled", actor=user, request=request)
    db.commit()
    return Response(status_code=204)


class PasswordChangeIn(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


@router.post("/password", status_code=204)
def change_password(body: PasswordChangeIn, request: Request, response: Response,
                    p: Principal = Depends(current_principal), db: Session = Depends(get_db),
                    settings: Settings = Depends(settings_dep)) -> Response:
    user = db.merge(p.user)
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(400, "Current password is incorrect")
    problems = password_problems(body.new_password, username=user.username, min_length=settings.password_min_length)
    if problems:
        raise HTTPException(422, "Password " + "; ".join(problems))
    if verify_password(body.new_password, user.password_hash):
        raise HTTPException(422, "Choose a password different from the current one")
    user.password_hash = hash_password(body.new_password)
    user.must_change_password = False
    revoke_user_sessions(db, user.id)  # sign out everywhere, then issue a fresh session
    token, sess = create_session(db, user, settings, ip=client_ip(request),
                                 user_agent=request.headers.get("user-agent"), mfa_verified=p.session.mfa_verified)
    audit.record(db, "auth.password_changed", actor=user, request=request)
    db.commit()
    _set_cookies(response, settings, token, sess.csrf_token)
    response.status_code = 204
    return response


@router.post("/tour-complete", status_code=204)
def tour_complete(p: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> Response:
    db.merge(p.user).tour_completed = True
    db.commit()
    return Response(status_code=204)
