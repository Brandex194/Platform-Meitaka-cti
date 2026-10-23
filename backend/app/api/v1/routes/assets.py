import uuid
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.v1.deps import get_scoped_db
from app.auth.roles import Role, require_roles
from app.db.models import Asset

router = APIRouter()


class AssetIn(BaseModel):
    hostname: Optional[str] = None
    ip: Optional[str] = None


@router.get("/tenants/{tenant_id}/assets")
def list_assets(
    tenant_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
):
    assets = db.execute(
        select(Asset).where(Asset.tenant_id == tenant_id)
    ).scalars().all()
    return [{"id": str(a.id), "hostname": a.hostname, "ip": a.ip} for a in assets]


@router.post("/tenants/{tenant_id}/assets", status_code=201)
def create_asset(
    tenant_id: uuid.UUID,
    body: AssetIn,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(Role.super_admin, Role.tenant_admin, Role.api_user)),
):
    asset = Asset(tenant_id=tenant_id, hostname=body.hostname, ip=body.ip)
    db.add(asset)
    db.flush()
    return {"id": str(asset.id), "hostname": asset.hostname, "ip": asset.ip}
