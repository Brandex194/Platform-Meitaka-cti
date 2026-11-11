"""Integrations (passo 10): encrypted third-party API keys and indicator enrichments.

Both tables are tenant tables with the usual RLS policy and a GRANT to sentinel_app.

Revision ID: 0010
Revises: 0009
Create Date: 2026-11-09
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_POLICY = (
    "current_setting('app.bypass_tenant_scope', true) = 'on' "
    "OR NULLIF(current_setting('app.current_tenant_id', true), '')::uuid = tenant_id"
)


def _secure(name: str) -> None:
    op.execute(f"ALTER TABLE {name} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {name} FORCE ROW LEVEL SECURITY")
    op.execute(f"CREATE POLICY tenant_isolation ON {name} USING ({_POLICY})")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {name} TO sentinel_app")


def upgrade() -> None:
    op.create_table(
        "integration_keys",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("ciphertext", sa.Text(), nullable=False),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "provider", name="uq_integration_tenant_provider"),
    )
    op.create_index("ix_integration_keys_tenant_id", "integration_keys", ["tenant_id"])
    _secure("integration_keys")

    op.create_table(
        "indicator_enrichments",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("indicator_id", sa.UUID(), nullable=False),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("malicious", sa.Integer(), nullable=True),
        sa.Column("suspicious", sa.Integer(), nullable=True),
        sa.Column("harmless", sa.Integer(), nullable=True),
        sa.Column("undetected", sa.Integer(), nullable=True),
        sa.Column("reputation", sa.Integer(), nullable=True),
        sa.Column("analysis_date", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("permalink", sa.String(512), nullable=True),
        sa.Column("fetched_at", sa.TIMESTAMP(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["indicator_id"], ["indicators.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("indicator_id", "tenant_id", "provider", name="uq_enrichment"),
    )
    op.create_index("ix_indicator_enrichments_tenant_id", "indicator_enrichments", ["tenant_id"])
    op.create_index("ix_indicator_enrichments_indicator_id", "indicator_enrichments", ["indicator_id"])
    _secure("indicator_enrichments")


def downgrade() -> None:
    op.drop_table("indicator_enrichments")
    op.drop_table("integration_keys")
