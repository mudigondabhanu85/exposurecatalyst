"""Housekeeping: data retention (daily) and secret re-encryption (key rotation)."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timedelta

import structlog
from sqlalchemy import delete, or_, select
from sqlalchemy.orm import Session, sessionmaker

from exposurecatalyst.config import Settings
from exposurecatalyst.db.base import as_utc, utcnow
from exposurecatalyst.models import (
    AiProvider,
    AiUsage,
    AlertEvent,
    AlertRule,
    AppSetting,
    Integration,
    JobRun,
    SamlRequest,
    User,
    UserSession,
)
from exposurecatalyst.security import audit
from exposurecatalyst.security.crypto import SecretBox, get_secret_box

log = structlog.get_logger(__name__)
LAST_RUN_KEY = "maintenance.last_run"


def retention(db: Session, settings: Settings) -> dict[str, int]:
    now = utcnow()
    counts = {}

    def purge(name: str, stmt) -> None:
        counts[name] = db.execute(stmt).rowcount or 0

    purge(
        "sessions",
        delete(UserSession).where(
            or_(
                UserSession.expires_at < now - timedelta(days=settings.retention_sessions_days),
                UserSession.revoked_at < now - timedelta(days=settings.retention_sessions_days),
            )
        ),
    )
    purge("job_runs", delete(JobRun).where(JobRun.started_at < now - timedelta(days=settings.retention_job_runs_days)))
    purge(
        "ai_usage", delete(AiUsage).where(AiUsage.occurred_at < now - timedelta(days=settings.retention_ai_usage_days))
    )
    purge(
        "alert_events",
        delete(AlertEvent).where(AlertEvent.delivered_at < now - timedelta(days=settings.retention_alert_events_days)),
    )
    purge("saml_requests", delete(SamlRequest).where(SamlRequest.created_at < now - timedelta(days=1)))
    return counts


def run_daily(settings: Settings, session_factory: sessionmaker[Session]) -> dict[str, int] | None:
    """Called every scheduler tick; does work at most once per 24 h (across replicas, via app_settings)."""
    with session_factory() as db:
        row = db.get(AppSetting, LAST_RUN_KEY)
        last = as_utc(datetime.fromisoformat(row.value["at"])) if row and row.value else None
        if last and utcnow() - last < timedelta(hours=24):
            return None
        counts = retention(db, settings)
        value = {"at": utcnow().isoformat(), "deleted": counts}
        if row is None:
            db.add(AppSetting(key=LAST_RUN_KEY, value=value, updated_by="scheduler"))
        else:
            row.value = value
        audit.record(db, "maintenance.retention", actor_username="scheduler", details=counts)
        db.commit()
        log.info("retention_done", **counts)
        return counts


def rotate_secrets(
    db: Session,
    box: SecretBox | None = None,
    *,
    dry_run: bool = False,
    progress: Callable[[str], None] = lambda _m: None,
) -> dict[str, int]:
    """Re-encrypt every encrypted value under the primary key. All-or-nothing (single transaction)."""
    box = box or get_secret_box()
    counts = {"users.totp": 0, "integrations": 0, "ai_providers": 0, "alert_rules": 0, "smtp": 0, "saml_sp_key": 0}

    def rot(token: str | None) -> str | None:
        return box.rotate(token) if token else token

    for u in db.scalars(select(User).where(User.totp_secret_enc.is_not(None))):
        u.totp_secret_enc = rot(u.totp_secret_enc)
        counts["users.totp"] += 1
    for model, attr, key in (
        (Integration, "secrets_enc", "integrations"),
        (AiProvider, "secrets_enc", "ai_providers"),
        (AlertRule, "webhooks_enc", "alert_rules"),
    ):
        for row in db.scalars(select(model).where(getattr(model, attr).is_not(None))):
            setattr(row, attr, rot(getattr(row, attr)))
            counts[key] += 1
    smtp = db.get(AppSetting, "smtp")
    if smtp and smtp.value and smtp.value.get("password_enc"):
        smtp.value = {**smtp.value, "password_enc": rot(smtp.value["password_enc"])}
        counts["smtp"] = 1
    sp = db.get(AppSetting, "sso.saml.sp_keys")
    if sp and sp.value and sp.value.get("key_enc"):
        sp.value = {**sp.value, "key_enc": rot(sp.value["key_enc"])}
        counts["saml_sp_key"] = 1
    progress(json.dumps(counts))
    if dry_run:
        db.rollback()
    else:
        audit.record(db, "security.secrets_rotated", actor_username="cli", details=counts)
        db.commit()
    return counts
