"""Fix RLS policies: NULLIF guard prevents ''::uuid cast error on pooled connections.

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-23
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0004"
down_revision: Union[str, None] = "0003"
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

# Bypass check MUST come first to short-circuit the uuid cast when bypassing.
# NULLIF guards against '' from a pooled connection that never set the GUC.
_NEW_POLICY = (
    "current_setting('app.bypass_tenant_scope', true) = 'on' "
    "OR NULLIF(current_setting('app.current_tenant_id', true), '')::uuid = {col}"
)


def upgrade() -> None:
    for table, col in _TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING ({_NEW_POLICY.format(col=col)})"
        )


def downgrade() -> None:
    _OLD_BYPASS = "current_setting('app.bypass_tenant_scope', true) = 'on'"
    _OLD_CURRENT = "current_setting('app.current_tenant_id', true)::uuid"
    for table, col in _TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING ({col} = {_OLD_CURRENT} OR {_OLD_BYPASS})"
        )
