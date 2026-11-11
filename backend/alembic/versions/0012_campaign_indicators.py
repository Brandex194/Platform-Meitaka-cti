"""Campaign <-> indicator links (passo 11), the missing edge of the Knowledge Graph.

A link belongs to the tenant that made it (RLS), while the campaign and the indicator it joins can
be the tenant's own or shared ones.

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-09
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_POLICY = (
    "current_setting('app.bypass_tenant_scope', true) = 'on' "
    "OR NULLIF(current_setting('app.current_tenant_id', true), '')::uuid = tenant_id"
)


def upgrade() -> None:
    op.create_table(
        "campaign_indicators",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("campaign_id", sa.UUID(), nullable=False),
        sa.Column("indicator_id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["indicator_id"], ["indicators.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "campaign_id", "indicator_id", name="uq_campaign_indicator"),
    )
    for col in ("tenant_id", "campaign_id", "indicator_id"):
        op.create_index(f"ix_campaign_indicators_{col}", "campaign_indicators", [col])
    op.execute("ALTER TABLE campaign_indicators ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE campaign_indicators FORCE ROW LEVEL SECURITY")
    op.execute(f"CREATE POLICY tenant_isolation ON campaign_indicators USING ({_POLICY})")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON campaign_indicators TO sentinel_app")


def downgrade() -> None:
    op.drop_table("campaign_indicators")
