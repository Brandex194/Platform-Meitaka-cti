"""Query helpers shared by several routes."""
import uuid

from sqlalchemy import Select, and_, func, select

from app.db.models import Score


def latest_asset_scores(tenant_id: uuid.UUID) -> Select:
    """Latest Score row per asset of a tenant (scores is append-only)."""
    latest = (
        select(Score.asset_id, func.max(Score.computed_at).label("max_at"))
        .where(Score.tenant_id == tenant_id, Score.score_type == "asset")
        .group_by(Score.asset_id)
        .subquery()
    )
    return (
        select(Score)
        .join(latest, and_(Score.asset_id == latest.c.asset_id, Score.computed_at == latest.c.max_at))
        .where(Score.tenant_id == tenant_id, Score.score_type == "asset")
    )
