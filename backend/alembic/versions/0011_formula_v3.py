"""Formula v3 (passo 11): decreasing-weight aggregation and KEV floor.

Adds a new global ScoreRule version with formula "architettura-5-moltiplicativa-v3". Same weights,
exposure and impact as the multiplicative formula. Earlier rules stay in the table and keep
computing what they computed; tenants with their own rule are not touched.

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-09
"""
import uuid
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_FORMULA = "architettura-5-moltiplicativa-v3"
_WEIGHTS = {"severity": 0.0, "confidence": 0.3, "recency": 0.3, "epss": 0.4}
_THRESHOLDS = {"low": 0.2, "medium": 0.4, "high": 0.7}
_PARAMETERS = {
    "formula": _FORMULA,
    "exposure": {"internal": 0.3, "dmz": 0.7, "internet": 1.0},
    "impact": {"low": 0.4, "business": 0.7, "critical": 1.0},
    "aggregation_decay": 0.5,
    "kev_floor": 0.25,
}


def upgrade() -> None:
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
    op.execute(
        sa.text("DELETE FROM score_rules WHERE tenant_id IS NULL AND parameters->>'formula' = :f").bindparams(f=_FORMULA)
    )
