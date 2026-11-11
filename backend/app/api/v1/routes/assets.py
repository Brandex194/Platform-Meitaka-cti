import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.v1.deps import get_scoped_db
from app.api.v1.pagination import PageParams, page_params, paginate
from app.api.v1.schemas import AssetOut, Page, SoftwareOut
from app.auth.roles import Role, require_roles
from app.core.errors import error_response
from app.db.models import Asset, Software

router = APIRouter()

_ASSET_WRITERS = (Role.super_admin, Role.tenant_admin, Role.api_user)


Exposure = Literal["internal", "dmz", "internet"]  # Architettura §5.2 E_exposure
Impact = Literal["low", "business", "critical"]  # Architettura §5.2 I_impact


class AssetIn(BaseModel):
    hostname: str | None = Field(None, max_length=255)
    ip: str | None = Field(None, max_length=45)
    exposure: Exposure | None = None
    impact: Impact | None = None


class AssetUpdate(BaseModel):
    """Only the fields sent are changed; send null to clear a classification."""
    hostname: str | None = Field(None, max_length=255)
    ip: str | None = Field(None, max_length=45)
    exposure: Exposure | None = None
    impact: Impact | None = None


class SoftwareIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    version: str | None = Field(None, max_length=100)
    # CPE 2.3, e.g. cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
    # Without a CPE the correlation engine cannot match this software against CVEs.
    cpe: str | None = Field(None, max_length=512)

    @field_validator("cpe")
    @classmethod
    def _check_cpe(cls, v: str | None) -> str | None:
        if v is not None and (not v.startswith("cpe:2.3:") or len(v.split(":")) < 6):
            raise ValueError("cpe must be a CPE 2.3 string (cpe:2.3:part:vendor:product:version:...)")
        return v


def _get_asset(db: Session, tenant_id: uuid.UUID, asset_id: uuid.UUID) -> Asset:
    asset = db.execute(
        select(Asset).where(Asset.id == asset_id, Asset.tenant_id == tenant_id)
    ).scalar_one_or_none()
    if asset is None:
        raise HTTPException(status_code=404, detail=error_response("NOT_FOUND", "Asset not found"))
    return asset


@router.get("/tenants/{tenant_id}/assets", response_model=Page[AssetOut])
def list_assets(
    tenant_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    params: PageParams = Depends(page_params),
):
    stmt = select(Asset).where(Asset.tenant_id == tenant_id).order_by(Asset.created_at.desc(), Asset.id)
    return paginate(db, stmt, params, AssetOut)


@router.post("/tenants/{tenant_id}/assets", status_code=201, response_model=AssetOut)
def create_asset(
    tenant_id: uuid.UUID,
    body: AssetIn,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(*_ASSET_WRITERS)),
):
    asset = Asset(tenant_id=tenant_id, **body.model_dump())
    db.add(asset)
    db.flush()
    db.refresh(asset)
    return asset


@router.patch("/tenants/{tenant_id}/assets/{asset_id}", response_model=AssetOut)
def update_asset(
    tenant_id: uuid.UUID,
    asset_id: uuid.UUID,
    body: AssetUpdate,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(*_ASSET_WRITERS)),
):
    """Set hostname, IP or the §5.2 context. The new context counts from the next score computation."""
    asset = _get_asset(db, tenant_id, asset_id)
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(asset, field, value)
    db.flush()
    db.refresh(asset)
    return asset


@router.get("/tenants/{tenant_id}/assets/{asset_id}/software", response_model=Page[SoftwareOut])
def list_software(
    tenant_id: uuid.UUID,
    asset_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    params: PageParams = Depends(page_params),
):
    _get_asset(db, tenant_id, asset_id)
    stmt = (
        select(Software)
        .where(Software.tenant_id == tenant_id, Software.asset_id == asset_id)
        .order_by(Software.name, Software.id)
    )
    return paginate(db, stmt, params, SoftwareOut)


@router.post("/tenants/{tenant_id}/assets/{asset_id}/software", status_code=201, response_model=SoftwareOut)
def create_software(
    tenant_id: uuid.UUID,
    asset_id: uuid.UUID,
    body: SoftwareIn,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(*_ASSET_WRITERS)),
):
    _get_asset(db, tenant_id, asset_id)
    sw = Software(tenant_id=tenant_id, asset_id=asset_id, name=body.name, version=body.version, cpe=body.cpe)
    db.add(sw)
    db.flush()
    return sw


@router.delete("/tenants/{tenant_id}/assets/{asset_id}/software/{software_id}", status_code=204)
def delete_software(
    tenant_id: uuid.UUID,
    asset_id: uuid.UUID,
    software_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(*_ASSET_WRITERS)),
):
    sw = db.execute(
        select(Software).where(
            Software.id == software_id, Software.asset_id == asset_id, Software.tenant_id == tenant_id
        )
    ).scalar_one_or_none()
    if sw is None:
        raise HTTPException(status_code=404, detail=error_response("NOT_FOUND", "Software not found"))
    db.delete(sw)
    db.flush()
