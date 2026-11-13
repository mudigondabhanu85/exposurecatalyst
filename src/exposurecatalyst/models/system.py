from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from exposurecatalyst.db.base import Base, utcnow


class AuditLog(Base):
    """Append-only, hash-chained audit trail.

    Each row's ``hash`` = SHA-256(prev_hash + canonical JSON of the row). Tampering with or deleting
    any row breaks the chain, detected by ``exposurecatalyst audit-verify``. On PostgreSQL a trigger
    additionally rejects UPDATE/DELETE (see migration 0001).
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor_user_id: Mapped[int | None] = mapped_column(Integer, index=True)  # no FK: survives user deletion
    actor_username: Mapped[str | None] = mapped_column(String(150))
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str | None] = mapped_column(String(64))
    target_id: Mapped[str | None] = mapped_column(String(128))
    outcome: Mapped[str] = mapped_column(String(16), default="success")
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(400))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64), unique=True)


class AppSetting(Base):
    """Small key/value store for runtime-editable, non-secret settings and heartbeats."""

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[Any] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    updated_by: Mapped[str | None] = mapped_column(String(150))
