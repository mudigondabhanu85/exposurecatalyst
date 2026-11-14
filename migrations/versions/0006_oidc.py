"""oidc sign-in requests

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-14 09:00:00
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "oidc_requests",
        sa.Column("state_hash", sa.String(length=64), nullable=False),
        sa.Column("nonce", sa.String(length=128), nullable=False),
        sa.Column("code_verifier_enc", sa.Text(), nullable=False),
        sa.Column("relay_state", sa.String(length=500), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("state_hash"),
    )
    op.create_index(op.f("ix_oidc_requests_created_at"), "oidc_requests", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_oidc_requests_created_at"), table_name="oidc_requests")
    op.drop_table("oidc_requests")
