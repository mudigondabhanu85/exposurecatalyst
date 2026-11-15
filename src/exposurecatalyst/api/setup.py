"""First-run setup wizard: on an installation with no users, the holder of the one-time setup token (printed to
the API logs) creates the break-glass Super Admin with mandatory TOTP MFA.

The token is the credential: it is sent as ``Authorization: Bearer <token>``, so every endpoint here answers 401
without it, like any other protected route. It is deleted when the first administrator is created (or
whenever users already exist), which disables the wizard for good. Whether setup is needed is exposed to the
login page through ``GET /api/auth/sso`` (``setup_required``).
"""

from __future__ import annotations

from typing import Any

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from exposurecatalyst import deployment
from exposurecatalyst.api.deps import client_ip, settings_dep
from exposurecatalyst.config import Settings
from exposurecatalyst.db.session import get_db
from exposurecatalyst.models import AppSetting, Role, User
from exposurecatalyst.security import audit
from exposurecatalyst.security.crypto import get_secret_box
from exposurecatalyst.security.middleware import SlidingWindowLimiter
from exposurecatalyst.security.passwords import hash_password, password_problems
from exposurecatalyst.security.rbac import seed_roles

router = APIRouter(prefix="/api/setup", tags=["setup"])
_limiter = SlidingWindowLimiter(10)


def setup_token(request: Request, db: Session = Depends(get_db)) -> None:
    """Dependency: valid, unexpired setup token as a bearer credential (rate-limited per client IP)."""
    if not _limiter.allow(client_ip(request) or "unknown"):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts; try again shortly")
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token or not deployment.check_setup_token(db, token):
        if token:
            audit.record(db, "setup.token_rejected", actor_username="anonymous", request=request,
                         outcome="failure")
            db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired setup token (see the API logs)",
                            headers={"WWW-Authenticate": "Bearer"})
    if not deployment.setup_required(db):
        raise HTTPException(status.HTTP_409_CONFLICT, "Setup is already complete — sign in instead")


@router.get("/verify", dependencies=[Depends(setup_token)])
def verify() -> dict[str, bool]:
    """Step 1 of the wizard: is this token valid?"""
    return {"ok": True}


class BeginIn(BaseModel):
    username: str = Field(min_length=3, max_length=150, pattern=r"^[A-Za-z0-9._@-]+$")
    email: EmailStr | None = None
    password: str = Field(min_length=1, max_length=256)


@router.post("/begin", dependencies=[Depends(setup_token)])
def begin(body: BeginIn, db: Session = Depends(get_db), settings: Settings = Depends(settings_dep)) -> dict[str, Any]:
    """Validate the password and return a TOTP secret to enroll. Nothing is created yet."""
    problems = password_problems(body.password, username=body.username, min_length=settings.password_min_length)
    if problems:
        raise HTTPException(422, "Password " + "; ".join(problems))
    secret = pyotp.random_base32()
    box = get_secret_box()
    pending = {"username": body.username, "email": str(body.email) if body.email else None,
               "password_hash": hash_password(body.password), "totp_secret_enc": box.encrypt(secret)}
    row = db.get(AppSetting, deployment.SETUP_PENDING_KEY)
    if row is None:
        db.add(AppSetting(key=deployment.SETUP_PENDING_KEY, value=pending, updated_by="setup"))
    else:
        row.value = pending
    db.commit()
    return {"secret": secret,
            "otpauth_uri": pyotp.TOTP(secret).provisioning_uri(name=body.username, issuer_name="ExposureCatalyst")}


class CompleteIn(BaseModel):
    totp_code: str = Field(pattern=r"^\d{6}$")


@router.post("/complete", status_code=201, dependencies=[Depends(setup_token)])
def complete(body: CompleteIn, request: Request, db: Session = Depends(get_db)) -> dict[str, str]:
    """Verify the TOTP code and create the Super Admin (MFA enabled). Consumes the token."""
    row = db.get(AppSetting, deployment.SETUP_PENDING_KEY)
    if row is None or not row.value:
        raise HTTPException(409, "Start the setup again")
    p = row.value
    secret = get_secret_box().decrypt(p["totp_secret_enc"])
    if not pyotp.TOTP(secret).verify(body.totp_code, valid_window=1):
        raise HTTPException(422, "The authenticator code is not valid — check the time on your device")
    seed_roles(db)
    role = db.scalar(select(Role).where(Role.name == "Super Admin"))
    if db.scalar(select(func.count()).select_from(User)):  # lost a race with another setup request
        raise HTTPException(409, "Setup is already complete — sign in instead")
    user = User(username=p["username"], email=p.get("email"), display_name=p["username"],
                password_hash=p["password_hash"], is_local=True, roles=[role],
                totp_secret_enc=p["totp_secret_enc"], totp_enabled=True)
    db.add(user)
    db.flush()
    deployment.consume_setup_token(db)
    audit.record(db, "user.created", actor_username="setup-wizard", request=request, target_type="user",
                 target_id=user.id, details={"username": user.username, "roles": ["Super Admin"], "via": "setup",
                                              "mfa": True})
    db.commit()
    return {"username": user.username}
