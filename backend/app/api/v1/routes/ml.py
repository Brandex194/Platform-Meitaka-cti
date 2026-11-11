import os

import sqlalchemy as sa
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.v1.deps import get_scoped_db
from app.auth.roles import Role, require_roles
from app.ml.forecast import forecast_scores
from app.ml.similarity import IocSimilarityIndex

router = APIRouter(prefix="/ml", tags=["ml"])

FAISS_PATH = os.getenv("FAISS_INDEX_PATH", "/data/faiss/ioc.index")


def get_daily_score_avgs(db: Session, tenant_id: str, days: int = 30) -> list[float]:
    rows = (
        db.execute(
            sa.text(
                "SELECT DATE(computed_at) as day, AVG(value) as avg_val"
                " FROM scores WHERE tenant_id = :tid"
                " GROUP BY DATE(computed_at) ORDER BY day DESC LIMIT :days"
            ),
            {"tid": tenant_id, "days": days},
        )
        .fetchall()
    )
    return [float(r.avg_val) for r in reversed(rows)]


@router.get("/forecast")
def get_forecast(
    tenant_id: str = Query(...),
    horizon: int = Query(7, ge=1, le=30),
    db: Session = Depends(get_scoped_db),
    _user=Depends(require_roles(Role.super_admin, Role.tenant_admin, Role.analyst)),
):
    avgs = get_daily_score_avgs(db, tenant_id)
    if len(avgs) < 2:
        return {"forecast": [], "message": "Not enough score history"}
    return {"forecast": forecast_scores(avgs, horizon=horizon)}


@router.get("/similar-iocs")
def get_similar_iocs(
    value: str = Query(...),
    k: int = Query(10, ge=1, le=50),
    _user=Depends(require_roles(Role.super_admin, Role.tenant_admin, Role.analyst)),
):
    if not os.path.exists(FAISS_PATH):
        return {"results": [], "message": "FAISS index not built yet"}
    idx = IocSimilarityIndex.load(FAISS_PATH)
    results = idx.search(value, k=k)
    return {"results": [{"value": v, "score": s} for v, s in results]}
