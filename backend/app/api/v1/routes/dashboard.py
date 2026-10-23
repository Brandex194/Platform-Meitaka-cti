import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
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

    top_scores = db.execute(
        select(Score)
        .where(Score.tenant_id == tenant_id, Score.score_type == "asset")
        .order_by(Score.value.desc())
        .limit(5)
    ).scalars().all()

    return {
        "open_cases": open_cases,
        "top_assets": [
            {"asset_id": str(s.asset_id), "value": s.value, "level": s.level}
            for s in top_scores
        ],
    }
