"""Paid / licensed threat-intel & news subscriptions (features.subscriptions) — additive tables only."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from exposurecatalyst.db.base import Base, utcnow


class IntelSubscription(Base):
    """A licensed source: a pre-built preset (vendor) or a custom REST / RSS / TAXII / file-drop source.
    Credentials are Fernet-encrypted JSON (never returned). `license` and `redistribution` hold contract
    metadata and the controls the email generator and AI layer enforce."""

    __tablename__ = "intel_subscriptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    vendor: Mapped[str] = mapped_column(String(100))
    preset: Mapped[str] = mapped_column(String(40))  # preset key or custom_rest | custom_rss | custom_taxii | manual
    source_type: Mapped[str] = mapped_column(String(16))  # rest | rss | taxii | manual
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    base_url: Mapped[str | None] = mapped_column(String(500))
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    secrets_enc: Mapped[str | None] = mapped_column(Text)
    license: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    redistribution: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="never")  # never | ok | error
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    error_log: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    usage: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # {period_start, api_calls, items}
    state: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # cursors / added_after
    created_by: Mapped[str | None] = mapped_column(String(150))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class IntelItem(Base):
    """One intel record from a subscription (pulled, imported or entered manually)."""

    __tablename__ = "intel_items"
    __table_args__ = (UniqueConstraint("subscription_id", "external_id", name="uq_intel_items_sub_ext"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subscription_id: Mapped[int] = mapped_column(ForeignKey("intel_subscriptions.id", ondelete="CASCADE"),
                                                 index=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)  # cve | news | advisory
    external_id: Mapped[str] = mapped_column(String(255))
    cve_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    title: Mapped[str] = mapped_column(String(500))
    summary: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str | None] = mapped_column(String(16))
    exploited: Mapped[bool | None] = mapped_column(Boolean)
    references: Mapped[list[str]] = mapped_column(JSON, default=list)
    url: Mapped[str | None] = mapped_column(String(1000))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    tlp: Mapped[str] = mapped_column(String(16), default="AMBER")  # CLEAR | GREEN | AMBER | AMBER+STRICT | RED
    analyst_notes: Mapped[str | None] = mapped_column(Text)
    is_manual: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str | None] = mapped_column(String(150))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    subscription: Mapped[IntelSubscription] = relationship(lazy="joined")
    attachments: Mapped[list[IntelAttachment]] = relationship(back_populates="item", cascade="all, delete-orphan",
                                                              lazy="selectin")


class IntelAttachment(Base):
    """PDF / HTML attached to a manual intel item (stored in the database, so backups include it)."""

    __tablename__ = "intel_attachments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    item_id: Mapped[int] = mapped_column(ForeignKey("intel_items.id", ondelete="CASCADE"), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    content_type: Mapped[str] = mapped_column(String(100))
    size: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    data: Mapped[bytes] = mapped_column(LargeBinary)
    created_by: Mapped[str | None] = mapped_column(String(150))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    item: Mapped[IntelItem] = relationship(back_populates="attachments")
