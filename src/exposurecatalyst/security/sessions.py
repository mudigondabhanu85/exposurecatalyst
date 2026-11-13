from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta

from sqlalchemy.orm import Session

from exposurecatalyst.config import Settings
from exposurecatalyst.db.base import as_utc, utcnow
from exposurecatalyst.models import User, UserSession

TOUCH_EVERY = timedelta(seconds=60)


def cookie_names(settings: Settings) -> tuple[str, str]:
    # __Host- prefix forces Secure, Path=/ and no Domain → cannot be set by subdomains.
    if settings.cookie_secure:
        return "__Host-excat_session", "__Host-excat_csrf"
    return "excat_session", "excat_csrf"


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(
    db: Session, user: User, settings: Settings, *, ip: str | None, user_agent: str | None, mfa_verified: bool
) -> tuple[str, UserSession]:
    token = secrets.token_urlsafe(32)
    now = utcnow()
    row = UserSession(
        token_hash=hash_token(token),
        user_id=user.id,
        csrf_token=secrets.token_urlsafe(32),
        mfa_verified=mfa_verified,
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(minutes=settings.session_absolute_timeout_minutes),
        ip_address=ip,
        user_agent=(user_agent or "")[:400],
    )
    db.add(row)
    db.flush()
    return token, row


def resolve_session(db: Session, token: str | None, settings: Settings) -> UserSession | None:
    if not token or len(token) > 128:
        return None
    row = db.get(UserSession, hash_token(token))
    if row is None or row.revoked_at is not None:
        return None
    now = utcnow()
    if as_utc(row.expires_at) <= now:
        return None
    if as_utc(row.last_seen_at) + timedelta(minutes=settings.session_idle_timeout_minutes) <= now:
        return None
    if not row.user.is_active:
        return None
    if now - as_utc(row.last_seen_at) >= TOUCH_EVERY:
        row.last_seen_at = now
        db.commit()
    return row


def revoke_user_sessions(db: Session, user_id: int) -> None:
    now = utcnow()
    for row in db.query(UserSession).filter(UserSession.user_id == user_id, UserSession.revoked_at.is_(None)):
        row.revoked_at = now
