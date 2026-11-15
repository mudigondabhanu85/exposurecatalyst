"""advisory actions (tickets / chat posts from action connectors)

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-14 18:00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "advisory_actions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("advisory_id", sa.Integer(), nullable=False),
        sa.Column("integration_id", sa.Integer(), nullable=True),
        sa.Column("integration_name", sa.String(length=100), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("external_ref", sa.String(length=200), nullable=True),
        sa.Column("external_url", sa.String(length=1000), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["advisory_id"], ["advisories.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["integration_id"], ["integrations.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_advisory_actions_advisory_id"), "advisory_actions", ["advisory_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_advisory_actions_advisory_id"), table_name="advisory_actions")
    op.drop_table("advisory_actions")
