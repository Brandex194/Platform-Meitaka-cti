"""Management (passo 8): API keys, audit log and tenants.

- API keys and audit log: per tenant, `tenant_admin` and `super_admin` only.
- Tenants: `super_admin` only; they see every tenant (RLS bypass session).
Users and their roles stay in Keycloak (see docs/AUTH.md); there is no user table here.
"""
import re
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field, computed_field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.v1.deps import get_admin_db, get_scoped_db
from app.api.v1.pagination import PageParams, page_params, paginate
from app.api.v1.schemas import Page
from app.auth.api_keys import generate_key, key_status
from app.auth.roles import Role, require_roles
from app.core.errors import error_response
from app.db.models import ApiKey, AuditLog, Tenant

router = APIRouter()

_ADMINS = (Role.tenant_admin, Role.super_admin)
_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def _not_found(what: str) -> HTTPException:
    return HTTPException(status_code=404, detail=error_response("NOT_FOUND", f"{what} not found"))


def _actor(token: dict) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(token.get("sub")))
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------


class ApiKeyOut(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    name: str
    prefix: str
    created_by: uuid.UUID | None
    created_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None
    last_used_at: datetime | None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def status(self) -> str:
        return key_status(self)  # type: ignore[arg-type]


class ApiKeyCreated(ApiKeyOut):
    key: str  # the only time the full key is returned


class ApiKeyIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    expires_in_days: int | None = Field(None, ge=1, le=730)

    @field_validator("name")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name must not be blank")
        return v


@router.get("/tenants/{tenant_id}/api-keys", response_model=Page[ApiKeyOut])
def list_api_keys(
    tenant_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    params: PageParams = Depends(page_params),
    _: dict = Depends(require_roles(*_ADMINS)),
):
    stmt = (
        select(ApiKey)
        .where(ApiKey.tenant_id == tenant_id)
        .order_by(ApiKey.created_at.desc(), ApiKey.id)
    )
    return paginate(db, stmt, params, ApiKeyOut)


@router.post("/tenants/{tenant_id}/api-keys", status_code=201, response_model=ApiKeyCreated)
def create_api_key(
    tenant_id: uuid.UUID,
    body: ApiKeyIn,
    db: Session = Depends(get_scoped_db),
    token: dict = Depends(require_roles(*_ADMINS)),
):
    raw, prefix, digest = generate_key()
    now = datetime.now(UTC)
    key = ApiKey(
        tenant_id=tenant_id,
        name=body.name,
        prefix=prefix,
        key_hash=digest,
        created_by=_actor(token),
        created_at=now,
        expires_at=now + timedelta(days=body.expires_in_days) if body.expires_in_days else None,
    )
    db.add(key)
    db.flush()
    return ApiKeyCreated(**ApiKeyOut.model_validate(key).model_dump(exclude={"status"}), key=raw)


@router.delete("/tenants/{tenant_id}/api-keys/{key_id}", status_code=204)
def revoke_api_key(
    tenant_id: uuid.UUID,
    key_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(*_ADMINS)),
):
    """Revoke, not delete: the row stays so the audit trail still shows the key existed."""
    key = db.execute(
        select(ApiKey).where(ApiKey.id == key_id, ApiKey.tenant_id == tenant_id)
    ).scalar_one_or_none()
    if key is None:
        raise _not_found("API key")
    if key.revoked_at is None:
        key.revoked_at = datetime.now(UTC)
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Audit log (read only)
# ---------------------------------------------------------------------------


class AuditOut(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    actor_id: uuid.UUID | None
    action: str
    resource_type: str | None
    resource_id: uuid.UUID | None
    ip: str | None
    status_code: int | None
    payload: dict | None
    created_at: datetime


@router.get("/tenants/{tenant_id}/audit-logs", response_model=Page[AuditOut])
def list_audit_logs(
    tenant_id: uuid.UUID,
    q: str | None = Query(None, max_length=100, description="text contained in the action"),
    db: Session = Depends(get_scoped_db),
    params: PageParams = Depends(page_params),
    _: dict = Depends(require_roles(*_ADMINS)),
):
    stmt = select(AuditLog).where(AuditLog.tenant_id == tenant_id)
    if q:
        escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        stmt = stmt.where(AuditLog.action.ilike(f"%{escaped}%", escape="\\"))
    stmt = stmt.order_by(AuditLog.created_at.desc(), AuditLog.id)
    return paginate(db, stmt, params, AuditOut)


# ---------------------------------------------------------------------------
# Tenants (super_admin)
# ---------------------------------------------------------------------------


class TenantOut(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    name: str
    slug: str
    sector: str | None
    created_at: datetime


class TenantIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    slug: str = Field(..., min_length=2, max_length=100)
    sector: str | None = Field(None, max_length=100)

    @field_validator("name")
    @classmethod
    def _strip_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name must not be blank")
        return v

    @field_validator("slug")
    @classmethod
    def _check_slug(cls, v: str) -> str:
        v = v.strip().lower()
        if not _SLUG_RE.match(v):
            raise ValueError("slug: lowercase letters, digits and single dashes only")
        return v


class TenantPatch(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    sector: str | None = Field(None, max_length=100)

    @field_validator("name")
    @classmethod
    def _strip_name(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        if not v:
            raise ValueError("name must not be blank")
        return v


@router.get("/admin/tenants", response_model=Page[TenantOut])
def list_tenants(
    db: Session = Depends(get_admin_db),
    params: PageParams = Depends(page_params),
    _: dict = Depends(require_roles(Role.super_admin)),
):
    return paginate(db, select(Tenant).order_by(Tenant.name, Tenant.id), params, TenantOut)


@router.post("/admin/tenants", status_code=201, response_model=TenantOut)
def create_tenant(
    body: TenantIn,
    db: Session = Depends(get_admin_db),
    _: dict = Depends(require_roles(Role.super_admin)),
):
    if db.execute(select(Tenant.id).where(Tenant.slug == body.slug)).first():
        raise HTTPException(status_code=409, detail=error_response("CONFLICT", "slug already in use"))
    tenant = Tenant(name=body.name, slug=body.slug, sector=body.sector)
    db.add(tenant)
    try:
        db.flush()
    except IntegrityError as exc:  # two creates racing on the same slug
        raise HTTPException(
            status_code=409, detail=error_response("CONFLICT", "slug already in use")
        ) from exc
    return tenant


@router.patch("/admin/tenants/{tenant_id}", response_model=TenantOut)
def update_tenant(
    tenant_id: uuid.UUID,
    body: TenantPatch,
    db: Session = Depends(get_admin_db),
    _: dict = Depends(require_roles(Role.super_admin)),
):
    """Name and sector only: the slug is an identifier and does not change."""
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise _not_found("Tenant")
    data = body.model_dump(exclude_unset=True)
    if data.get("name") is None:
        data.pop("name", None)
    for field, value in data.items():
        setattr(tenant, field, value)
    db.flush()
    return tenant
