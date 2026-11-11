"""Dark web: findings and leaks recorded by analysts.

There is no crawler. An analyst (or a future collector) records what was seen: a finding is an
observation of type `darkweb`; a leak is a breach an identity appears in. Leaks are stored by
SHA-256 of the lowercase email, never in clear, and feed the `leak_identity` correlation rule.
"""
import hashlib
import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.api.v1.deps import get_scoped_db
from app.api.v1.pagination import PageParams, page_params, paginate
from app.api.v1.schemas import ObservationOut, Page
from app.auth.roles import Role, require_roles
from app.core.errors import error_response
from app.db.models import Asset, Leak, Observation

router = APIRouter()
_WRITERS = (Role.super_admin, Role.tenant_admin, Role.analyst)
EVENT_TYPE = "darkweb"
Severity = Literal["low", "medium", "high", "critical"]
Status = Literal["new", "reviewed", "dismissed"]


class FindingIn(BaseModel):
    source: str = Field(min_length=1, max_length=255)
    context: str = Field(min_length=1, max_length=2000)
    severity: Severity = "medium"
    asset_id: uuid.UUID | None = None


class FindingPatch(BaseModel):
    status: Status


class LeakIn(BaseModel):
    email: str = Field(max_length=320, pattern=r"^[^@\s]+@[^@\s]+$")
    breach_name: str = Field(min_length=1, max_length=255)
    pwn_count: int | None = Field(None, ge=0)

    @field_validator("email", mode="before")
    @classmethod
    def _strip(cls, v):
        return v.strip() if isinstance(v, str) else v


def _finding(db: Session, tenant_id: uuid.UUID, finding_id: uuid.UUID) -> Observation:
    obs = db.execute(
        select(Observation).where(
            Observation.id == finding_id,
            Observation.tenant_id == tenant_id,
            Observation.event_type == EVENT_TYPE,
        )
    ).scalar_one_or_none()
    if obs is None:
        raise HTTPException(status_code=404, detail=error_response("NOT_FOUND", "Finding not found"))
    return obs


@router.post("/tenants/{tenant_id}/darkweb/findings", status_code=201, response_model=ObservationOut)
def create_finding(
    tenant_id: uuid.UUID,
    body: FindingIn,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(*_WRITERS)),
):
    if body.asset_id is not None:
        found = db.execute(
            select(Asset.id).where(Asset.id == body.asset_id, Asset.tenant_id == tenant_id)
        ).first()
        if found is None:
            raise HTTPException(status_code=404, detail=error_response("NOT_FOUND", "Asset not found"))
    obs = Observation(
        tenant_id=tenant_id,
        asset_id=body.asset_id,
        event_type=EVENT_TYPE,
        payload={
            "source": body.source.strip(),
            "context": body.context.strip(),
            "severity": body.severity,
            "status": "new",
        },
    )
    db.add(obs)
    db.flush()
    db.refresh(obs)
    return obs


@router.patch("/tenants/{tenant_id}/darkweb/findings/{finding_id}", response_model=ObservationOut)
def update_finding(
    tenant_id: uuid.UUID,
    finding_id: uuid.UUID,
    body: FindingPatch,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(*_WRITERS)),
):
    obs = _finding(db, tenant_id, finding_id)
    obs.payload = {**(obs.payload or {}), "status": body.status}  # new dict: JSON column change tracking
    db.flush()
    db.refresh(obs)
    return obs


@router.delete("/tenants/{tenant_id}/darkweb/findings/{finding_id}", status_code=204)
def delete_finding(
    tenant_id: uuid.UUID,
    finding_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(*_WRITERS)),
):
    db.delete(_finding(db, tenant_id, finding_id))


class LeakOut(BaseModel):
    id: uuid.UUID
    email_hash: str
    breach_name: str
    pwn_count: int | None
    created_at: datetime

    model_config = {"from_attributes": True}


@router.get("/tenants/{tenant_id}/darkweb/leaks", response_model=Page[LeakOut])
def list_leaks(
    tenant_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    params: PageParams = Depends(page_params),
):
    stmt = select(Leak).where(Leak.tenant_id == tenant_id).order_by(Leak.created_at.desc(), Leak.id)
    return paginate(db, stmt, params, LeakOut)


@router.post("/tenants/{tenant_id}/darkweb/leaks", status_code=201, response_model=LeakOut)
def create_leak(
    tenant_id: uuid.UUID,
    body: LeakIn,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(*_WRITERS)),
):
    email_hash = hashlib.sha256(body.email.strip().lower().encode()).hexdigest()
    breach = body.breach_name.strip()
    dup = db.execute(
        select(Leak.id).where(
            Leak.tenant_id == tenant_id, Leak.email_hash == email_hash, Leak.breach_name == breach
        )
    ).first()
    if dup is not None:
        raise HTTPException(
            status_code=409, detail=error_response("CONFLICT", "This email is already recorded for that breach")
        )
    leak = Leak(tenant_id=tenant_id, email_hash=email_hash, breach_name=breach, pwn_count=body.pwn_count)
    db.add(leak)
    db.flush()
    db.refresh(leak)
    return leak


@router.delete("/tenants/{tenant_id}/darkweb/leaks/{leak_id}", status_code=204)
def delete_leak(
    tenant_id: uuid.UUID,
    leak_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(*_WRITERS)),
):
    res = db.execute(delete(Leak).where(Leak.id == leak_id, Leak.tenant_id == tenant_id))
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail=error_response("NOT_FOUND", "Leak not found"))
