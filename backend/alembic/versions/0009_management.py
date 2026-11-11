"""Management (passo 8): API keys and richer audit rows.

Adds api_keys (RLS, same policy as the other tenant tables; the key lookup at authentication time
runs in a bypass session because the tenant is not known yet) and audit_logs.ip / status_code.

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-09
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_POLICY = (
    "current_setting('app.bypass_tenant_scope', true) = 'on' "
    "OR NULLIF(current_setting('app.current_tenant_id', true), '')::uuid = tenant_id"
)


def upgrade() -> None:
    # "DELETE /api/v1/tenants/<uuid>/cases/<uuid>/notes/<uuid>" is 130 characters: with 100 the audit
    # row of those requests failed to insert (and was silently dropped).
    op.alter_column("audit_logs", "action", existing_type=sa.String(100), type_=sa.String(255))
    op.add_column("audit_logs", sa.Column("ip", sa.String(45), nullable=True))
    op.add_column("audit_logs", sa.Column("status_code", sa.Integer(), nullable=True))
    op.create_index("ix_audit_logs_tenant_created", "audit_logs", ["tenant_id", "created_at"])

    op.create_table(
        "api_keys",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("prefix", sa.String(16), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("key_hash"),
    )
    op.create_index("ix_api_keys_tenant_id", "api_keys", ["tenant_id"])
    op.execute("ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE api_keys FORCE ROW LEVEL SECURITY")
    op.execute(f"CREATE POLICY tenant_isolation ON api_keys USING ({_POLICY})")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON api_keys TO sentinel_app")


def downgrade() -> None:
    op.execute("UPDATE audit_logs SET action = left(action, 100)")
    op.alter_column("audit_logs", "action", existing_type=sa.String(255), type_=sa.String(100))
    op.drop_table("api_keys")
    op.drop_index("ix_audit_logs_tenant_created", table_name="audit_logs")
    op.drop_column("audit_logs", "status_code")
    op.drop_column("audit_logs", "ip")
