"""threat intel & news subscriptions (features.subscriptions) — new tables only

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-15 04:00:00
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "intel_subscriptions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("vendor", sa.String(length=100), nullable=False),
        sa.Column("preset", sa.String(length=40), nullable=False),
        sa.Column("source_type", sa.String(length=16), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("base_url", sa.String(length=500), nullable=True),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("secrets_enc", sa.Text(), nullable=True),
        sa.Column("license", sa.JSON(), nullable=False),
        sa.Column("redistribution", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("error_log", sa.JSON(), nullable=False),
        sa.Column("usage", sa.JSON(), nullable=False),
        sa.Column("state", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=150), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "intel_items",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("subscription_id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=False),
        sa.Column("cve_ids", sa.JSON(), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=True),
        sa.Column("exploited", sa.Boolean(), nullable=True),
        sa.Column("references", sa.JSON(), nullable=False),
        sa.Column("url", sa.String(length=1000), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("tlp", sa.String(length=16), nullable=False),
        sa.Column("analyst_notes", sa.Text(), nullable=True),
        sa.Column("is_manual", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=150), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["subscription_id"], ["intel_subscriptions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("subscription_id", "external_id", name="uq_intel_items_sub_ext"),
    )
    op.create_index(op.f("ix_intel_items_subscription_id"), "intel_items", ["subscription_id"])
    op.create_index(op.f("ix_intel_items_kind"), "intel_items", ["kind"])
    op.create_index(op.f("ix_intel_items_published_at"), "intel_items", ["published_at"])
    op.create_table(
        "intel_attachments",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("item_id", sa.Integer(), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("content_type", sa.String(length=100), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("data", sa.LargeBinary(), nullable=False),
        sa.Column("created_by", sa.String(length=150), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["item_id"], ["intel_items.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_intel_attachments_item_id"), "intel_attachments", ["item_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_intel_attachments_item_id"), table_name="intel_attachments")
    op.drop_table("intel_attachments")
    op.drop_index(op.f("ix_intel_items_published_at"), table_name="intel_items")
    op.drop_index(op.f("ix_intel_items_kind"), table_name="intel_items")
    op.drop_index(op.f("ix_intel_items_subscription_id"), table_name="intel_items")
    op.drop_table("intel_items")
    op.drop_table("intel_subscriptions")
