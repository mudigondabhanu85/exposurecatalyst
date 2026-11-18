"""Exposure-analysis advisories: per-tool check availability, detection method, notes and email visibility;
asset support group / asset class / detection method; vulnerability type and role-based actions — additive columns

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-18 03:00:00
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("advisories") as batch:
        batch.add_column(sa.Column("vuln_type", sa.String(300), nullable=True))
        batch.add_column(sa.Column("owner_actions", sa.Text(), nullable=True))
        batch.add_column(sa.Column("support_actions", sa.Text(), nullable=True))
    with op.batch_alter_table("advisory_source_status") as batch:
        batch.add_column(sa.Column("shown", sa.Boolean(), nullable=False, server_default=sa.true()))
        batch.add_column(sa.Column("check_available", sa.Boolean(), nullable=True))
        batch.add_column(sa.Column("detection_method", sa.String(32), nullable=True))
        batch.add_column(sa.Column("note", sa.Text(), nullable=True))
    with op.batch_alter_table("advisory_assets") as batch:
        batch.add_column(sa.Column("support_group", sa.String(200), nullable=True))
        batch.add_column(sa.Column("asset_class", sa.String(100), nullable=True))
        batch.add_column(sa.Column("detection_method", sa.String(32), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("advisory_assets") as batch:
        for c in ("detection_method", "asset_class", "support_group"):
            batch.drop_column(c)
    with op.batch_alter_table("advisory_source_status") as batch:
        for c in ("note", "detection_method", "check_available", "shown"):
            batch.drop_column(c)
    with op.batch_alter_table("advisories") as batch:
        for c in ("support_actions", "owner_actions", "vuln_type"):
            batch.drop_column(c)
