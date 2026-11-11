import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.v1.deps import get_scoped_db
from app.api.v1.pagination import PageParams, page_params, paginate
from app.api.v1.schemas import CorrelationEventOut, Page
from app.db.models import CorrelationEvent

router = APIRouter()


@router.get("/tenants/{tenant_id}/correlation-events", response_model=Page[CorrelationEventOut])
def list_correlation_events(
    tenant_id: uuid.UUID,
    active: bool | None = Query(None),
    db: Session = Depends(get_scoped_db),
    params: PageParams = Depends(page_params),
):
    stmt = select(CorrelationEvent).where(CorrelationEvent.tenant_id == tenant_id)
    if active is not None:
        stmt = stmt.where(CorrelationEvent.is_active == active)
    stmt = stmt.order_by(CorrelationEvent.created_at.desc(), CorrelationEvent.id)
    return paginate(db, stmt, params, CorrelationEventOut)
