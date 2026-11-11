"""Security Scanner: scan configuration and results stubs.

Actual scan execution (Tenable/Qualys/Nessus/Nuclei) is not yet implemented.
These routes define the data contracts so the frontend can be built against them.
"""
import uuid
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.v1.deps import get_scoped_db
from app.auth.roles import Role, require_roles
from app.core.errors import error_response

router = APIRouter()

_WRITERS = (Role.tenant_admin, Role.super_admin, Role.analyst)
_ADMINS = (Role.tenant_admin, Role.super_admin)

ScanEngine = Literal["tenable", "qualys", "nessus", "nuclei", "openvas"]
ScanStatus = Literal["pending", "running", "completed", "failed", "cancelled"]


class ScanProfile(BaseModel):
    id: str
    tenant_id: str
    name: str
    engine: ScanEngine
    targets: list[str]
    created_at: str


class ScanRun(BaseModel):
    id: str
    profile_id: str
    status: ScanStatus
    started_at: str | None
    finished_at: str | None
    findings_count: int


class ScanProfileIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    engine: ScanEngine
    targets: list[str] = Field(..., min_length=1)


def _err(status: int, code: str, msg: str) -> HTTPException:
    return HTTPException(status_code=status, detail=error_response(code, msg))


@router.get("/tenants/{tenant_id}/scanner/profiles", response_model=list[ScanProfile])
def list_profiles(
    tenant_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    _token: dict = Depends(require_roles(*_WRITERS)),
):
    # stub: no profiles yet
    return []


@router.post("/tenants/{tenant_id}/scanner/profiles", response_model=ScanProfile, status_code=201)
def create_profile(
    tenant_id: uuid.UUID,
    body: ScanProfileIn = Body(...),
    db: Session = Depends(get_scoped_db),
    _token: dict = Depends(require_roles(*_ADMINS)),
):
    raise _err(501, "NOT_IMPLEMENTED", "Scan engine integration coming soon")


@router.get("/tenants/{tenant_id}/scanner/runs", response_model=list[ScanRun])
def list_runs(
    tenant_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    _token: dict = Depends(require_roles(*_WRITERS)),
):
    return []


@router.post("/tenants/{tenant_id}/scanner/profiles/{profile_id}/run", status_code=202)
def trigger_run(
    tenant_id: uuid.UUID,
    profile_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    _token: dict = Depends(require_roles(*_ADMINS)),
):
    raise _err(501, "NOT_IMPLEMENTED", "Scan engine integration coming soon")
