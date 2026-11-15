"""tls certificates and CSRs (Settings → Certificates & Domain) — new tables only

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-15 03:00:00
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "tls_certificates",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("fingerprint_sha256", sa.String(length=64), nullable=False),
        sa.Column("subject", sa.String(length=500), nullable=False),
        sa.Column("issuer", sa.String(length=500), nullable=False),
        sa.Column("serial", sa.String(length=128), nullable=False),
        sa.Column("sans", sa.JSON(), nullable=False),
        sa.Column("key_type", sa.String(length=32), nullable=False),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fullchain_pem", sa.Text(), nullable=False),
        sa.Column("key_enc", sa.Text(), nullable=False),
        sa.Column("warnings", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=150), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_tls_certificates_status"), "tls_certificates", ["status"])
    op.create_index(op.f("ix_tls_certificates_fingerprint_sha256"), "tls_certificates", ["fingerprint_sha256"])
    op.create_index(op.f("ix_tls_certificates_not_after"), "tls_certificates", ["not_after"])
    op.create_table(
        "tls_csrs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("common_name", sa.String(length=255), nullable=False),
        sa.Column("sans", sa.JSON(), nullable=False),
        sa.Column("key_type", sa.String(length=16), nullable=False),
        sa.Column("public_key_id", sa.String(length=64), nullable=False),
        sa.Column("csr_pem", sa.Text(), nullable=False),
        sa.Column("key_enc", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(length=150), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_tls_csrs_status"), "tls_csrs", ["status"])
    op.create_index(op.f("ix_tls_csrs_public_key_id"), "tls_csrs", ["public_key_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_tls_csrs_public_key_id"), table_name="tls_csrs")
    op.drop_index(op.f("ix_tls_csrs_status"), table_name="tls_csrs")
    op.drop_table("tls_csrs")
    op.drop_index(op.f("ix_tls_certificates_not_after"), table_name="tls_certificates")
    op.drop_index(op.f("ix_tls_certificates_fingerprint_sha256"), table_name="tls_certificates")
    op.drop_index(op.f("ix_tls_certificates_status"), table_name="tls_certificates")
    op.drop_table("tls_certificates")
