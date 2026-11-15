from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Integer, String, Text
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


class TlsCertificate(Base):
    """A proxy certificate (Settings → Certificates & Domain). The private key is Fernet-encrypted and never
    returned by the API; the certs volume holds only the active (and previous) files the proxy serves."""

    __tablename__ = "tls_certificates"

    id: Mapped[int] = mapped_column(primary_key=True)
    status: Mapped[str] = mapped_column(String(16), index=True)  # active | previous | archived
    source: Mapped[str] = mapped_column(String(16))  # pem | pkcs12 | paste | csr
    fingerprint_sha256: Mapped[str] = mapped_column(String(64), index=True)
    subject: Mapped[str] = mapped_column(String(500))
    issuer: Mapped[str] = mapped_column(String(500))
    serial: Mapped[str] = mapped_column(String(128))
    sans: Mapped[list[str]] = mapped_column(JSON, default=list)
    key_type: Mapped[str] = mapped_column(String(32))
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    fullchain_pem: Mapped[str] = mapped_column(Text)
    key_enc: Mapped[str] = mapped_column(Text)
    warnings: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_by: Mapped[str | None] = mapped_column(String(150))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TlsCsr(Base):
    """A certificate signing request; the private key is generated and kept (encrypted) on the server."""

    __tablename__ = "tls_csrs"

    id: Mapped[int] = mapped_column(primary_key=True)
    status: Mapped[str] = mapped_column(String(16), index=True)  # pending | completed | cancelled
    common_name: Mapped[str] = mapped_column(String(255))
    sans: Mapped[list[str]] = mapped_column(JSON, default=list)
    key_type: Mapped[str] = mapped_column(String(16))
    public_key_id: Mapped[str] = mapped_column(String(64), index=True)
    csr_pem: Mapped[str] = mapped_column(Text)
    key_enc: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str | None] = mapped_column(String(150))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
