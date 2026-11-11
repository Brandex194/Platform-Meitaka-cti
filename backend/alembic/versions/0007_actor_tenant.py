"""threat_actors.tenant_id: tenants can keep their own actors next to the shared catalog.

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-09
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "threat_actors",
        sa.Column("tenant_id", sa.UUID(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True),
    )
    op.create_index("ix_threat_actors_tenant_id", "threat_actors", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_threat_actors_tenant_id", table_name="threat_actors")
    op.drop_column("threat_actors", "tenant_id")
