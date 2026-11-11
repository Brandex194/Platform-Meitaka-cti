import uuid
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.v1.deps import get_scoped_db
from app.api.v1.pagination import PageParams, page_params, paginate
from app.api.v1.schemas import ExposureMatchOut, Page
from app.auth.roles import Role, require_roles
from app.core.errors import error_response
from app.db.models import CorrelationEvent, ExposureMatch

router = APIRouter()


class ExposurePatch(BaseModel):
    status: Literal["resolved", "false_positive"]


@router.get("/tenants/{tenant_id}/exposure-matches", response_model=Page[ExposureMatchOut])
def list_exposure_matches(
    tenant_id: uuid.UUID,
    status: str | None = Query(None, max_length=50),
    db: Session = Depends(get_scoped_db),
    params: PageParams = Depends(page_params),
):
    stmt = select(ExposureMatch).where(ExposureMatch.tenant_id == tenant_id)
    if status:
        stmt = stmt.where(ExposureMatch.status == status)
    stmt = stmt.order_by(ExposureMatch.updated_at.desc(), ExposureMatch.id)
    return paginate(db, stmt, params, ExposureMatchOut)


@router.patch("/tenants/{tenant_id}/exposure-matches/{match_id}", response_model=ExposureMatchOut)
def resolve_exposure_match(
    tenant_id: uuid.UUID,
    match_id: uuid.UUID,
    body: ExposurePatch,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(Role.super_admin, Role.tenant_admin, Role.analyst)),
):
    match = db.execute(
        select(ExposureMatch).where(
            ExposureMatch.id == match_id, ExposureMatch.tenant_id == tenant_id
        )
    ).scalar_one_or_none()
    if not match:
        raise HTTPException(
            status_code=404,
            detail=error_response("NOT_FOUND", "Exposure match not found"),
        )
    now = datetime.now(UTC)
    match.status = body.status
    match.updated_at = now
    # Deactivate the linked correlation event in the same transaction so the score can drop
    if match.correlation_event_id:
        event = db.execute(
            select(CorrelationEvent).where(
                CorrelationEvent.id == match.correlation_event_id,
                CorrelationEvent.tenant_id == tenant_id,
            )
        ).scalar_one_or_none()
        if event:
            event.is_active = False
            event.resolved_at = now
    db.flush()
    return match
