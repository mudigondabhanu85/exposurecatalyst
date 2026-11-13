from __future__ import annotations

from datetime import date, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Date, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from exposurecatalyst.db.base import Base, utcnow


class Integration(Base):
    """A configured connector instance (e.g. the Qualys US2 pod). Secrets are Fernet-encrypted JSON."""

    __tablename__ = "integrations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)  # registry key: qualys, wiz, ...
    name: Mapped[str] = mapped_column(String(100), unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    base_url: Mapped[str] = mapped_column(String(500))
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # non-secret options + field_map
    secrets_enc: Mapped[str | None] = mapped_column(Text)  # never returned to the UI
    status: Mapped[str] = mapped_column(String(16), default="never")  # never | ok | error
    last_test_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    state: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # connector bookkeeping (cursors)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class IntegrationCveCheck(Base):
    """Result of asking one integration about one CVE. Distinguishes 'checked, none found' (No)
    from 'never checked' (Not Integrated) in the validation matrix."""

    __tablename__ = "integration_cve_checks"
    __table_args__ = (UniqueConstraint("integration_id", "cve_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    integration_id: Mapped[int] = mapped_column(ForeignKey("integrations.id", ondelete="CASCADE"), index=True)
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    status: Mapped[str] = mapped_column(String(16))  # ok | error | unsupported
    asset_count: Mapped[int] = mapped_column(Integer, default=0)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str | None] = mapped_column(Text)


class AssetFinding(Base):
    """Normalized affected asset reported by an integration for a CVE (replaced on each check)."""

    __tablename__ = "asset_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    integration_id: Mapped[int] = mapped_column(ForeignKey("integrations.id", ondelete="CASCADE"), index=True)
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    os: Mapped[str | None] = mapped_column(String(128))
    cloud_account: Mapped[str | None] = mapped_column(String(128))
    resource_id: Mapped[str | None] = mapped_column(String(512))
    owner: Mapped[str | None] = mapped_column(String(200))
    business_unit: Mapped[str | None] = mapped_column(String(200))
    environment: Mapped[str | None] = mapped_column(String(64))
    detection_date: Mapped[date | None] = mapped_column(Date)
    source_ref: Mapped[str | None] = mapped_column(String(128))
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IntegrationVulnMap(Base):
    """CVE → vendor vulnerability ID (e.g. Qualys QID), built by connectors that need it."""

    __tablename__ = "integration_vuln_map"
    __table_args__ = (UniqueConstraint("integration_id", "cve_id", "external_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    integration_id: Mapped[int] = mapped_column(ForeignKey("integrations.id", ondelete="CASCADE"), index=True)
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    external_id: Mapped[str] = mapped_column(String(64))
