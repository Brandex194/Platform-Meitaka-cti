"""RLS policies — enable row-level security on 13 tenant-isolated tables.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-23
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# (table_name, policy_column)
_TENANT_TABLES = [
    ("assets", "tenant_id"),
    ("software", "tenant_id"),
    ("observations", "tenant_id"),
    ("exposure_matches", "tenant_id"),
    ("scores", "tenant_id"),
    ("score_rules", "tenant_id"),
    ("cases", "tenant_id"),
    ("identities", "tenant_id"),
    ("audit_logs", "tenant_id"),
    ("leaks", "tenant_id"),
    ("feedback_events", "tenant_id"),
    ("correlation_events", "tenant_id"),
    ("tenants", "id"),
]

_BYPASS = "current_setting('app.bypass_tenant_scope', true) = 'on'"
_CURRENT = "current_setting('app.current_tenant_id', true)::uuid"


def upgrade() -> None:
    for table, col in _TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING ({col} = {_CURRENT} OR {_BYPASS})"
        )

    # Grant app role access to all tables and sequences created by migration role
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sentinel_app"
    )
    op.execute(
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sentinel_app"
    )


def downgrade() -> None:
    op.execute(
        "REVOKE SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public FROM sentinel_app"
    )
    op.execute(
        "REVOKE USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public FROM sentinel_app"
    )
    for table, _ in reversed(_TENANT_TABLES):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
