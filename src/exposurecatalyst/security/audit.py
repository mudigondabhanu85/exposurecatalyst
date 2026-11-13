from __future__ import annotations

import hashlib
import json
from typing import Any

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from exposurecatalyst.db.base import as_utc, utcnow
from exposurecatalyst.logging import redact
from exposurecatalyst.models import AuditLog, User

GENESIS = "0" * 64


def _digest(prev_hash: str, row: AuditLog) -> str:
    body = {
        "occurred_at": as_utc(row.occurred_at).isoformat(),
        "actor_user_id": row.actor_user_id,
        "actor_username": row.actor_username,
        "action": row.action,
        "target_type": row.target_type,
        "target_id": row.target_id,
        "outcome": row.outcome,
        "ip_address": row.ip_address,
        "details": row.details,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256((prev_hash + canonical).encode()).hexdigest()


def record(
    db: Session,
    action: str,
    *,
    actor: User | None = None,
    request: Request | None = None,
    target_type: str | None = None,
    target_id: str | int | None = None,
    outcome: str = "success",
    details: dict[str, Any] | None = None,
    actor_username: str | None = None,
) -> AuditLog:
    """Append an audit entry. Caller commits (so the entry is atomic with the audited change)."""
    prev = db.execute(
        select(AuditLog.hash).order_by(AuditLog.id.desc()).limit(1).with_for_update()
    ).scalar_one_or_none() or GENESIS
    row = AuditLog(
        occurred_at=utcnow().replace(microsecond=0),
        actor_user_id=actor.id if actor else None,
        actor_username=actor.username if actor else actor_username,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        outcome=outcome,
        ip_address=request.client.host if request and request.client else None,
        user_agent=(request.headers.get("user-agent", "")[:400] if request else None),
        details=redact(details or {}),
        prev_hash=prev,
    )
    row.hash = _digest(prev, row)
    db.add(row)
    db.flush()
    return row


def verify_chain(db: Session) -> tuple[bool, int | None, int]:
    """Return (ok, first_bad_id, rows_checked)."""
    prev = GENESIS
    count = 0
    for row in db.scalars(select(AuditLog).order_by(AuditLog.id)).yield_per(1000):
        count += 1
        if row.prev_hash != prev or _digest(prev, row) != row.hash:
            return False, row.id, count
        prev = row.hash
    return True, None, count
