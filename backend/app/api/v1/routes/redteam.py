"""Red Team Operations: engagement governance stubs.

Governance rules (enforced at every endpoint):
  1. Explicit written authorization required before any run.
  2. Scope must be declared and stored before execution.
  3. Kill-switch: tenant_admin or super_admin can halt any active engagement.
  4. All activity is recorded in the audit log.
  5. Actual execution engines are not yet wired.
"""
import uuid
from typing import Literal

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.v1.deps import get_scoped_db
from app.auth.roles import Role, require_roles
from app.core.errors import error_response

router = APIRouter()

_ADMINS = (Role.tenant_admin, Role.super_admin)
_ANALYSTS = (Role.tenant_admin, Role.super_admin, Role.analyst)

EngagementStatus = Literal["draft", "authorized", "active", "paused", "completed", "cancelled"]


class EngagementOut(BaseModel):
    id: str
    tenant_id: str
    name: str
    status: EngagementStatus
    authorized_by: str | None
    scope_summary: str | None
    created_at: str


class EngagementIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    scope_summary: str = Field(..., min_length=10, max_length=4000)
    authorized_by: str = Field(..., min_length=1, max_length=255,
                               description="Name/role of the person who gave written authorization")


def _err(status: int, code: str, msg: str) -> HTTPException:
    return HTTPException(status_code=status, detail=error_response(code, msg))


@router.get("/tenants/{tenant_id}/redteam/engagements", response_model=list[EngagementOut])
def list_engagements(
    tenant_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    _token: dict = Depends(require_roles(*_ANALYSTS)),
):
    return []


@router.post("/tenants/{tenant_id}/redteam/engagements", response_model=EngagementOut, status_code=201)
def create_engagement(
    tenant_id: uuid.UUID,
    body: EngagementIn = Body(...),
    db: Session = Depends(get_scoped_db),
    _token: dict = Depends(require_roles(*_ADMINS)),
):
    raise _err(501, "NOT_IMPLEMENTED", "Red Team execution engine coming soon")


@router.post("/tenants/{tenant_id}/redteam/engagements/{engagement_id}/halt", status_code=200)
def halt_engagement(
    tenant_id: uuid.UUID,
    engagement_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    _token: dict = Depends(require_roles(*_ADMINS)),
):
    """Kill-switch: immediately halt an active engagement."""
    raise _err(501, "NOT_IMPLEMENTED", "Red Team execution engine coming soon")
