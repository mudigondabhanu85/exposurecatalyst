from __future__ import annotations

from datetime import date, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Date, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from exposurecatalyst.db.base import Base, utcnow

# Workflow states
DRAFT, IN_REVIEW, APPROVED, SENT, CANCELLED = "draft", "in_review", "approved", "sent", "cancelled"
TEMPLATE_RETIRED = "retired"


class AdvisoryTemplate(Base):
    __tablename__ = "advisory_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    kind: Mapped[str] = mapped_column(String(32))  # critical | high | informational | executive | custom
    description: Mapped[str | None] = mapped_column(String(500))
    is_system: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    versions: Mapped[list[AdvisoryTemplateVersion]] = relationship(
        back_populates="template", order_by="AdvisoryTemplateVersion.version", cascade="all, delete-orphan"
    )


class AdvisoryTemplateVersion(Base):
    """Immutable once submitted. Editing = creating a new draft version (draft → in_review → approved)."""

    __tablename__ = "advisory_template_versions"
    __table_args__ = (UniqueConstraint("template_id", "version"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    template_id: Mapped[int] = mapped_column(ForeignKey("advisory_templates.id", ondelete="CASCADE"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16), default=DRAFT)
    subject_template: Mapped[str] = mapped_column(String(500))
    body_template: Mapped[str] = mapped_column(Text)  # sandboxed Jinja2, rendered inside the fixed branded layout
    change_note: Mapped[str | None] = mapped_column(String(500))
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    template: Mapped[AdvisoryTemplate] = relationship(back_populates="versions")


class AdvisorySequence(Base):
    """Per-year counter for EXCAT-YYYY-NNNN IDs (row-locked on allocation)."""

    __tablename__ = "advisory_sequences"

    year: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    last_value: Mapped[int] = mapped_column(Integer, default=0)


class Advisory(Base):
    __tablename__ = "advisories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    advisory_id: Mapped[str] = mapped_column(String(20), unique=True, index=True)  # EXCAT-YYYY-NNNN
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    template_version_id: Mapped[int] = mapped_column(ForeignKey("advisory_template_versions.id"))
    status: Mapped[str] = mapped_column(String(16), default=DRAFT, index=True)

    subject: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(16))
    title: Mapped[str | None] = mapped_column(String(512))
    summary: Mapped[str | None] = mapped_column(Text)
    business_impact: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)
    workaround: Mapped[str | None] = mapped_column(Text)
    affected_products: Mapped[str | None] = mapped_column(Text)
    owner_contact: Mapped[str | None] = mapped_column(String(300))
    sla_due_date: Mapped[date | None] = mapped_column(Date)

    to_addrs: Mapped[list[str]] = mapped_column(JSON, default=list)
    cc_addrs: Mapped[list[str]] = mapped_column(JSON, default=list)
    bcc_addrs: Mapped[list[str]] = mapped_column(JSON, default=list)

    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    review_comment: Mapped[str | None] = mapped_column(Text)
    sent_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    template_version: Mapped[AdvisoryTemplateVersion] = relationship(lazy="joined")
    sources: Mapped[list[AdvisorySourceStatus]] = relationship(
        back_populates="advisory", cascade="all, delete-orphan", order_by="AdvisorySourceStatus.id", lazy="selectin"
    )
    assets: Mapped[list[AdvisoryAsset]] = relationship(
        back_populates="advisory", cascade="all, delete-orphan", order_by="AdvisoryAsset.id", lazy="selectin"
    )


class AdvisorySourceStatus(Base):
    """One row per source in the asset validation matrix."""

    __tablename__ = "advisory_source_status"
    __table_args__ = (UniqueConstraint("advisory_pk", "source"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    advisory_pk: Mapped[int] = mapped_column(ForeignKey("advisories.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(String(64))
    integrated: Mapped[bool] = mapped_column(Boolean, default=False)  # set by connectors (Phase 3)
    manual_count: Mapped[int | None] = mapped_column(Integer)  # analyst-entered override
    last_checked: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    advisory: Mapped[Advisory] = relationship(back_populates="sources")


class AdvisoryAsset(Base):
    __tablename__ = "advisory_assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    advisory_pk: Mapped[int] = mapped_column(ForeignKey("advisories.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(String(64))
    hostname: Mapped[str | None] = mapped_column(String(255))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    os: Mapped[str | None] = mapped_column(String(128))
    cloud_account: Mapped[str | None] = mapped_column(String(128))
    resource_id: Mapped[str | None] = mapped_column(String(512))
    owner: Mapped[str | None] = mapped_column(String(200))
    business_unit: Mapped[str | None] = mapped_column(String(200))
    environment: Mapped[str | None] = mapped_column(String(64))
    detection_date: Mapped[date | None] = mapped_column(Date)
    source_ref: Mapped[str | None] = mapped_column(String(128))  # plugin / QID / finding ID
    is_manual: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    advisory: Mapped[Advisory] = relationship(back_populates="assets")


class AdvisoryDelivery(Base):
    """Every send / export: what, how, to whom, by whom."""

    __tablename__ = "advisory_deliveries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    advisory_pk: Mapped[int] = mapped_column(ForeignKey("advisories.id", ondelete="CASCADE"), index=True)
    channel: Mapped[str] = mapped_column(String(16))  # smtp | eml | html | pdf | xlsx | clipboard
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    actor_username: Mapped[str | None] = mapped_column(String(150))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    recipients: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    message_id: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), default="ok")
    error: Mapped[str | None] = mapped_column(Text)


class DistributionList(Base):
    __tablename__ = "distribution_lists"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    description: Mapped[str | None] = mapped_column(String(300))
    to_addrs: Mapped[list[str]] = mapped_column(JSON, default=list)
    cc_addrs: Mapped[list[str]] = mapped_column(JSON, default=list)
    bcc_addrs: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
