"""Case workspace (passo 7): SLA deadline, notes and timeline.

Adds cases.due_at / closed_at (backfilled from the severity), and the tables case_notes and
case_events with the same tenant RLS policy as the other tenant tables.

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-09
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_POLICY = (
    "current_setting('app.bypass_tenant_scope', true) = 'on' "
    "OR NULLIF(current_setting('app.current_tenant_id', true), '')::uuid = tenant_id"
)


def _tenant_table(name: str, *columns: sa.Column) -> None:
    op.create_table(
        name,
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=False),
        *columns,
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(f"ix_{name}_case_id", name, ["case_id"])
    op.execute(f"ALTER TABLE {name} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {name} FORCE ROW LEVEL SECURITY")
    op.execute(f"CREATE POLICY tenant_isolation ON {name} USING ({_POLICY})")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {name} TO sentinel_app")


def upgrade() -> None:
    op.add_column("cases", sa.Column("due_at", sa.TIMESTAMP(timezone=True), nullable=True))
    op.add_column("cases", sa.Column("closed_at", sa.TIMESTAMP(timezone=True), nullable=True))
    # Same hours as app/cases/sla.py SLA_HOURS, for the cases that already exist.
    op.execute(
        "UPDATE cases SET due_at = created_at + CASE severity "
        "WHEN 'critical' THEN interval '4 hours' WHEN 'high' THEN interval '24 hours' "
        "WHEN 'low' THEN interval '168 hours' ELSE interval '72 hours' END"
    )
    op.execute("UPDATE cases SET closed_at = updated_at WHERE status IN ('closed', 'false_positive')")

    _tenant_table(
        "case_notes",
        sa.Column("author_id", sa.UUID(), nullable=True),
        sa.Column("body", sa.Text(), nullable=False),
    )
    _tenant_table(
        "case_events",
        sa.Column("actor_id", sa.UUID(), nullable=True),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("case_events")
    op.drop_table("case_notes")
    op.drop_column("cases", "closed_at")
    op.drop_column("cases", "due_at")
