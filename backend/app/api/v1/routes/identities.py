import uuid

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.v1.deps import get_scoped_db
from app.api.v1.pagination import PageParams, page_params, paginate
from app.api.v1.schemas import IdentityOut, Page
from app.auth.roles import Role, require_roles
from app.db.models import Identity

router = APIRouter()


class IdentityIn(BaseModel):
    email: str | None = Field(None, max_length=320, pattern=r"^[^@\s]+@[^@\s]+$")
    name: str | None = Field(None, max_length=255)


@router.get("/tenants/{tenant_id}/identities", response_model=Page[IdentityOut])
def list_identities(
    tenant_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    params: PageParams = Depends(page_params),
):
    stmt = select(Identity).where(Identity.tenant_id == tenant_id).order_by(Identity.created_at.desc(), Identity.id)
    return paginate(db, stmt, params, IdentityOut)


@router.post("/tenants/{tenant_id}/identities", status_code=201, response_model=IdentityOut)
def create_identity(
    tenant_id: uuid.UUID,
    body: IdentityIn,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(Role.super_admin, Role.tenant_admin, Role.analyst)),
):
    identity = Identity(tenant_id=tenant_id, email=body.email, name=body.name)
    db.add(identity)
    db.flush()
    db.refresh(identity)
    return identity
