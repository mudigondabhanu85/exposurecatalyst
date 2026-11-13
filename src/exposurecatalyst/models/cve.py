from __future__ import annotations

from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from exposurecatalyst.db.base import Base, utcnow


class Cve(Base):
    """One normalized, de-duplicated CVE record.

    ``provenance`` maps each field name to ``{"source": ..., "at": iso8601}`` so the UI can show
    where every value came from.
    """

    __tablename__ = "cves"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    title: Mapped[str | None] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    vuln_status: Mapped[str | None] = mapped_column(String(64))

    severity: Mapped[str] = mapped_column(String(16), default="UNKNOWN", index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, index=True)
    cvss_version: Mapped[str | None] = mapped_column(String(8))
    cvss_vector: Mapped[str | None] = mapped_column(String(256))
    cvss_metrics: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)

    epss_score: Mapped[float | None] = mapped_column(Float, index=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    epss_date: Mapped[date | None] = mapped_column(Date)
    epss_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    kev: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    kev_date_added: Mapped[date | None] = mapped_column(Date)
    kev_due_date: Mapped[date | None] = mapped_column(Date)
    kev_required_action: Mapped[str | None] = mapped_column(Text)
    kev_ransomware_use: Mapped[str | None] = mapped_column(String(16))

    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    exploit_refs: Mapped[list[str]] = mapped_column(JSON, default=list)
    patch_refs: Mapped[list[str]] = mapped_column(JSON, default=list)
    cwes: Mapped[list[str]] = mapped_column(JSON, default=list)
    references: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    products: Mapped[list[CveProduct]] = relationship(
        cascade="all, delete-orphan", back_populates="cve", lazy="selectin"
    )
    events: Mapped[list[CveEvent]] = relationship(
        cascade="all, delete-orphan", back_populates="cve", order_by="CveEvent.occurred_at"
    )

    def set_prov(self, field: str, source: str, at: datetime) -> None:
        prov = dict(self.provenance or {})
        prov[field] = {"source": source, "at": at.isoformat()}
        self.provenance = prov  # reassign so JSON change is detected


class CveProduct(Base):
    __tablename__ = "cve_products"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_pk: Mapped[int] = mapped_column(ForeignKey("cves.id", ondelete="CASCADE"), index=True)
    vendor: Mapped[str] = mapped_column(String(128), index=True)
    product: Mapped[str] = mapped_column(String(256), index=True)
    cpe: Mapped[str | None] = mapped_column(String(512))
    version_start_including: Mapped[str | None] = mapped_column(String(64))
    version_start_excluding: Mapped[str | None] = mapped_column(String(64))
    version_end_including: Mapped[str | None] = mapped_column(String(64))
    version_end_excluding: Mapped[str | None] = mapped_column(String(64))
    vulnerable: Mapped[bool] = mapped_column(Boolean, default=True)
    source: Mapped[str] = mapped_column(String(32))

    cve: Mapped[Cve] = relationship(back_populates="products")


class CveEvent(Base):
    """Timeline entry: PUBLISHED, MODIFIED, KEV_ADDED, KEV_REMOVED, EPSS_CHANGED."""

    __tablename__ = "cve_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_pk: Mapped[int] = mapped_column(ForeignKey("cves.id", ondelete="CASCADE"), index=True)
    event_type: Mapped[str] = mapped_column(String(32), index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String(32))
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    cve: Mapped[Cve] = relationship(back_populates="events")


class SourceState(Base):
    """Per-source ingestion state and health. Also the cross-process job lock."""

    __tablename__ = "source_state"

    source: Mapped[str] = mapped_column(String(32), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    interval_minutes: Mapped[int | None] = mapped_column(Integer)  # NULL → global default
    status: Mapped[str] = mapped_column(String(16), default="never")  # never|running|ok|error
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    records_last_run: Mapped[int] = mapped_column(Integer, default=0)
    cursor_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    meta: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    refresh_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class JobRun(Base):
    __tablename__ = "job_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(32), index=True)
    trigger: Mapped[str] = mapped_column(String(16))  # scheduled|manual|cli
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(16), default="running")
    records: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)


class SavedSearch(Base):
    __tablename__ = "saved_searches"
    __table_args__ = (UniqueConstraint("user_id", "name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    query: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
