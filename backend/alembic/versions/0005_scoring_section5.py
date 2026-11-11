"""Scoring according to Architettura §5 (passo 4, decided 09/11/2026).

- assets.exposure / assets.impact: the §5.2 context of each asset (NULL = not classified).
- score_rules.parameters: overrides of the §5 parameters, plus parameters.formula = "architettura-5".
- scores.score_rule_id / score_rule_version: which rule produced each score.
- RLS on score_rules: global rules readable from tenant sessions, never writable.
- A new global ScoreRule version with the §5 defaults. Older rules stay in the table for history;
  the engine ignores rules without parameters.formula.

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-09
"""
import json
import uuid
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_WEIGHTS = {"severity": 0.5, "confidence": 0.3, "recency": 0.2, "epss": 0.0}
_THRESHOLDS = {"low": 0.2, "medium": 0.4, "high": 0.7}
_PARAMETERS = {"formula": "architettura-5"}  # everything else: defaults in app.risk.formulas

# Same predicate as 0004. Global rules (tenant_id NULL) must be READABLE inside a tenant-scoped
# session, otherwise POST /scores/compute would silently fall back to the defaults; they stay
# unwritable from a tenant session (WITH CHECK has no NULL branch).
_TENANT_MATCH = (
    "current_setting('app.bypass_tenant_scope', true) = 'on' "
    "OR NULLIF(current_setting('app.current_tenant_id', true), '')::uuid = tenant_id"
)


def upgrade() -> None:
    op.add_column("assets", sa.Column("exposure", sa.String(20), nullable=True))
    op.add_column("assets", sa.Column("impact", sa.String(20), nullable=True))
    op.create_check_constraint(
        "ck_assets_exposure", "assets", "exposure IS NULL OR exposure IN ('internal', 'dmz', 'internet')"
    )
    op.create_check_constraint(
        "ck_assets_impact", "assets", "impact IS NULL OR impact IN ('low', 'business', 'critical')"
    )

    op.add_column("score_rules", sa.Column("parameters", sa.JSON(), nullable=True))
    op.alter_column(
        "score_rules",
        "weights",
        existing_type=sa.JSON(),
        server_default=json.dumps(_WEIGHTS),
    )

    op.add_column(
        "scores",
        sa.Column("score_rule_id", sa.Uuid(), sa.ForeignKey("score_rules.id", ondelete="SET NULL"), nullable=True),
    )
    op.add_column("scores", sa.Column("score_rule_version", sa.Integer(), nullable=True))

    op.execute("DROP POLICY IF EXISTS tenant_isolation ON score_rules")
    op.execute(
        "CREATE POLICY tenant_isolation ON score_rules "
        f"USING ({_TENANT_MATCH} OR tenant_id IS NULL) WITH CHECK ({_TENANT_MATCH})"
    )

    bind = op.get_bind()
    current = bind.execute(
        sa.text("SELECT COALESCE(MAX(version), 0) FROM score_rules WHERE tenant_id IS NULL")
    ).scalar()
    score_rules = sa.table(
        "score_rules",
        sa.column("id", sa.Uuid()),
        sa.column("tenant_id", sa.Uuid()),
        sa.column("version", sa.Integer()),
        sa.column("weights", sa.JSON()),
        sa.column("thresholds", sa.JSON()),
        sa.column("parameters", sa.JSON()),
    )
    op.bulk_insert(score_rules, [{
        "id": uuid.uuid4(),
        "tenant_id": None,
        "version": (current or 0) + 1,
        "weights": _WEIGHTS,
        "thresholds": _THRESHOLDS,
        "parameters": _PARAMETERS,
    }])


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON score_rules")
    op.execute(f"CREATE POLICY tenant_isolation ON score_rules USING ({_TENANT_MATCH})")
    op.execute("DELETE FROM score_rules WHERE parameters IS NOT NULL")
    op.drop_column("scores", "score_rule_version")
    op.drop_column("scores", "score_rule_id")
    op.alter_column(
        "score_rules",
        "weights",
        existing_type=sa.JSON(),
        server_default='{"severity": 0.45, "confidence": 0.27, "recency": 0.18, "epss": 0.10}',
    )
    op.drop_column("score_rules", "parameters")
    op.drop_constraint("ck_assets_impact", "assets", type_="check")
    op.drop_constraint("ck_assets_exposure", "assets", type_="check")
    op.drop_column("assets", "impact")
    op.drop_column("assets", "exposure")
