import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.v1.deps import get_scoped_db
from app.auth.roles import Role, require_roles
from app.core.errors import error_response
from app.db.models import CorrelationEvent, ExposureMatch

router = APIRouter()


class ExposurePatch(BaseModel):
    status: Literal["resolved", "false_positive"]


@router.get("/tenants/{tenant_id}/exposure-matches")
def list_exposure_matches(
    tenant_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
):
    matches = db.execute(
        select(ExposureMatch).where(ExposureMatch.tenant_id == tenant_id)
    ).scalars().all()
    return [
        {
            "id": str(m.id),
            "status": m.status,
            "correlation_event_id": str(m.correlation_event_id) if m.correlation_event_id else None,
        }
        for m in matches
    ]


@router.patch("/tenants/{tenant_id}/exposure-matches/{match_id}")
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
    match.status = body.status
    # Deactivate linked correlation event in the same transaction
    if match.correlation_event_id:
        event = db.execute(
            select(CorrelationEvent).where(CorrelationEvent.id == match.correlation_event_id)
        ).scalar_one_or_none()
        if event:
            event.is_active = False
            event.resolved_at = datetime.now(timezone.utc)
    db.flush()
    return {"id": str(match.id), "status": match.status}
