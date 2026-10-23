import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from app.auth.jwks import decode_token
from app.db.models import Case, Score
from app.db.session import get_db

router = APIRouter()


@router.get("/dashboard")
def dashboard(
    db: Session = Depends(get_db),
    payload: dict = Depends(decode_token),
):
    tenant_id_str = payload.get("tenant_id")
    if not tenant_id_str:
        return {"open_cases": 0, "top_assets": []}

    tenant_id = uuid.UUID(tenant_id_str)

    open_cases = db.execute(
        select(func.count()).select_from(Case).where(
            Case.tenant_id == tenant_id, Case.status == "open"
        )
    ).scalar_one()

    # Only latest score per asset to avoid duplicate entries
    latest_subq = (
        db.query(Score.asset_id, func.max(Score.computed_at).label("max_at"))
        .filter(Score.tenant_id == tenant_id, Score.score_type == "asset")
        .group_by(Score.asset_id)
        .subquery()
    )
    top_scores = (
        db.query(Score)
        .join(latest_subq, and_(
            Score.asset_id == latest_subq.c.asset_id,
            Score.computed_at == latest_subq.c.max_at,
        ))
        .order_by(Score.value.desc())
        .limit(5)
        .all()
    )

    return {
        "open_cases": open_cases,
        "top_assets": [
            {"asset_id": str(s.asset_id), "value": s.value, "level": s.level}
            for s in top_scores
        ],
    }
