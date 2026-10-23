import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from app.api.v1.deps import get_scoped_db
from app.auth.roles import Role, require_roles
from app.db.models import Score
from app.risk.engine import run_for_tenant

router = APIRouter()


@router.get("/tenants/{tenant_id}/scores")
def list_scores(
    tenant_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
):
    # Only return the latest score per asset (not all historical rows)
    latest_subq = (
        db.query(Score.asset_id, func.max(Score.computed_at).label("max_at"))
        .filter(Score.tenant_id == tenant_id, Score.score_type == "asset")
        .group_by(Score.asset_id)
        .subquery()
    )
    scores = (
        db.query(Score)
        .join(latest_subq, and_(
            Score.asset_id == latest_subq.c.asset_id,
            Score.computed_at == latest_subq.c.max_at,
        ))
        .all()
    )
    return [
        {"id": str(s.id), "asset_id": str(s.asset_id), "value": s.value, "level": s.level}
        for s in scores
    ]


@router.post("/tenants/{tenant_id}/scores/compute")
def compute_scores(
    tenant_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(Role.super_admin, Role.tenant_admin, Role.analyst)),
):
    return run_for_tenant(tenant_id, db=db)
