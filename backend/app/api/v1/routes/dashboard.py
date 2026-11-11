import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.v1.deps import get_scoped_db
from app.api.v1.queries import latest_asset_scores
from app.api.v1.schemas import CorrelationEventOut, DashboardOut, LevelCount
from app.cases.sla import OPEN_STATUSES
from app.db.models import Case, CorrelationEvent, ExposureMatch

router = APIRouter()

_LEVELS = ("critical", "high", "medium", "low")
RECENT_EVENTS = 10


@router.get("/tenants/{tenant_id}/dashboard", response_model=DashboardOut)
def dashboard(tenant_id: uuid.UUID, db: Session = Depends(get_scoped_db)):
    open_cases = db.execute(
        select(func.count()).select_from(Case).where(Case.tenant_id == tenant_id, Case.status.in_(OPEN_STATUSES))
    ).scalar_one()

    active_exposures = db.execute(
        select(func.count()).select_from(ExposureMatch).where(
            ExposureMatch.tenant_id == tenant_id, ExposureMatch.status == "active"
        )
    ).scalar_one()

    # Count by level over the latest score of each asset, not the whole history
    latest = latest_asset_scores(tenant_id).subquery()
    counts = dict(
        db.execute(select(latest.c.level, func.count()).group_by(latest.c.level)).all()
    )
    scores_by_level = [LevelCount(level=lvl, count=counts.get(lvl, 0)) for lvl in _LEVELS]

    recent = db.execute(
        select(CorrelationEvent)
        .where(CorrelationEvent.tenant_id == tenant_id)
        .order_by(CorrelationEvent.created_at.desc(), CorrelationEvent.id)
        .limit(RECENT_EVENTS)
    ).scalars().all()

    return DashboardOut(
        open_cases=open_cases,
        critical_scores=counts.get("critical", 0),
        active_exposures=active_exposures,
        recent_events=[CorrelationEventOut.model_validate(e) for e in recent],
        scores_by_level=scores_by_level,
    )
