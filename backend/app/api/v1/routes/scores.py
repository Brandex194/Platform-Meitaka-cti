import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.jwks import decode_token
from app.auth.roles import Role, require_roles
from app.db.models import Score
from app.db.session import get_db
from app.risk.engine import run_for_tenant

router = APIRouter()


@router.get("/tenants/{tenant_id}/scores")
def list_scores(
    tenant_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: dict = Depends(decode_token),
):
    scores = db.execute(
        select(Score).where(Score.tenant_id == tenant_id, Score.score_type == "asset")
    ).scalars().all()
    return [
        {"id": str(s.id), "asset_id": str(s.asset_id), "value": s.value, "level": s.level}
        for s in scores
    ]


@router.post("/tenants/{tenant_id}/scores/compute")
def compute_scores(
    tenant_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: dict = Depends(require_roles(Role.super_admin, Role.tenant_admin, Role.analyst)),
):
    return run_for_tenant(tenant_id, db=db)
