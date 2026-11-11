"""Tenant views on indicators (IoC) and raw observations."""
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, or_, select
from sqlalchemy.orm import Session

from app.api.v1.deps import get_scoped_db
from app.api.v1.pagination import PageParams, page_params, paginate
from app.api.v1.schemas import IndicatorOut, ObservationOut, Page
from app.auth.roles import Role, require_roles
from app.core.errors import error_response
from app.db.models import CampaignIndicator, Indicator, IndicatorEnrichment, Observation

router = APIRouter()

_WRITERS = (Role.super_admin, Role.tenant_admin, Role.analyst)


class IndicatorIn(BaseModel):
    ioc_type: Literal["ip", "domain", "url", "hash", "email"]
    value: str = Field(..., min_length=1, max_length=512)
    confidence: float | None = Field(None, ge=0, le=1)

    @field_validator("value")
    @classmethod
    def _strip_value(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("value must not be blank")
        return v


@router.get("/tenants/{tenant_id}/indicators", response_model=Page[IndicatorOut])
def list_indicators(
    tenant_id: uuid.UUID,
    ioc_type: str | None = Query(None, max_length=50),
    db: Session = Depends(get_scoped_db),
    params: PageParams = Depends(page_params),
):
    """Global indicators plus the tenant's own. `indicators` has no RLS: the filter is explicit."""
    stmt = select(Indicator).where(or_(Indicator.tenant_id.is_(None), Indicator.tenant_id == tenant_id))
    if ioc_type:
        stmt = stmt.where(Indicator.ioc_type == ioc_type)
    stmt = stmt.order_by(Indicator.created_at.desc(), Indicator.id)
    return paginate(db, stmt, params, IndicatorOut)


@router.get("/tenants/{tenant_id}/observations", response_model=Page[ObservationOut])
def list_observations(
    tenant_id: uuid.UUID,
    event_type: str | None = Query(None, max_length=100),
    db: Session = Depends(get_scoped_db),
    params: PageParams = Depends(page_params),
):
    stmt = select(Observation).where(Observation.tenant_id == tenant_id)
    if event_type:
        stmt = stmt.where(Observation.event_type == event_type)
    stmt = stmt.order_by(Observation.created_at.desc(), Observation.id)
    return paginate(db, stmt, params, ObservationOut)


@router.post("/tenants/{tenant_id}/indicators", status_code=201, response_model=IndicatorOut)
def create_indicator(
    tenant_id: uuid.UUID,
    body: IndicatorIn,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(*_WRITERS)),
):
    """Add an observable by hand. The same type and value twice in one tenant is a conflict."""
    value = body.value.lower() if body.ioc_type in ("domain", "email", "hash") else body.value
    exists = db.execute(
        select(Indicator.id).where(
            Indicator.tenant_id == tenant_id,
            Indicator.ioc_type == body.ioc_type,
            Indicator.value == value,
        )
    ).first()
    if exists:
        raise HTTPException(
            status_code=409,
            detail=error_response("CONFLICT", "This indicator already exists"),
        )
    indicator = Indicator(
        tenant_id=tenant_id, ioc_type=body.ioc_type, value=value, confidence=body.confidence
    )
    db.add(indicator)
    db.flush()
    db.refresh(indicator)
    return indicator


@router.delete("/tenants/{tenant_id}/indicators/{indicator_id}", status_code=204)
def delete_indicator(
    tenant_id: uuid.UUID,
    indicator_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(*_WRITERS)),
):
    """Only the tenant's own indicators: shared ones come from the feeds and stay."""
    indicator = db.execute(
        select(Indicator).where(Indicator.id == indicator_id, Indicator.tenant_id == tenant_id)
    ).scalar_one_or_none()
    if indicator is None:
        raise HTTPException(status_code=404, detail=error_response("NOT_FOUND", "Indicator not found"))
    db.execute(delete(CampaignIndicator).where(CampaignIndicator.indicator_id == indicator.id))
    db.execute(delete(IndicatorEnrichment).where(IndicatorEnrichment.indicator_id == indicator.id))
    db.delete(indicator)
    db.flush()
