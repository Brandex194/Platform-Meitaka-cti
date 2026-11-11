"""Third-party integrations (passo 10): API keys that cannot be read back, and indicator enrichment.

- Keys: `tenant_admin` and `super_admin` can set, replace and delete a tenant's key. The key is
  encrypted before it is stored (app/core/vault.py) and no route ever returns it: the list only says
  whether a key is configured and when it was last changed.
- Enrichment: `analyst` and admins ask VirusTotal about one indicator; the platform uses the stored
  key on their behalf and keeps only the verdict numbers.
"""
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Body, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.v1.deps import get_scoped_db
from app.api.v1.pagination import PageParams, page_params, paginate
from app.api.v1.schemas import Page
from app.auth.roles import Role, require_roles
from app.core.errors import error_response
from app.core.vault import VaultDecryptError, VaultNotConfigured, decrypt, encrypt
from app.db.models import Indicator, IndicatorEnrichment, IntegrationKey
from app.integrations import virustotal as vt

router = APIRouter()

_ADMINS = (Role.tenant_admin, Role.super_admin)
_WRITERS = (Role.super_admin, Role.tenant_admin, Role.analyst)

# provider id -> (label, how to check the format of its key)
PROVIDERS = {vt.PROVIDER: ("VirusTotal", vt.KEY_RE)}


def _err(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status, detail=error_response(code, message))


def _actor(token: dict) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(token.get("sub")))
    except ValueError:
        return None


def _provider(provider: str):
    if provider not in PROVIDERS:
        raise _err(404, "NOT_FOUND", "Unknown integration")
    return PROVIDERS[provider]


# ---------------------------------------------------------------------------
# Keys (write-only)
# ---------------------------------------------------------------------------


class IntegrationOut(BaseModel):
    provider: str
    label: str
    configured: bool
    updated_at: datetime | None


@router.get("/tenants/{tenant_id}/integrations", response_model=list[IntegrationOut])
def list_integrations(
    tenant_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(*_ADMINS)),
):
    rows = {
        k.provider: k
        for k in db.execute(select(IntegrationKey).where(IntegrationKey.tenant_id == tenant_id)).scalars()
    }
    return [
        IntegrationOut(
            provider=pid,
            label=label,
            configured=pid in rows,
            updated_at=rows[pid].updated_at if pid in rows else None,
        )
        for pid, (label, _fmt) in PROVIDERS.items()
    ]


@router.put("/tenants/{tenant_id}/integrations/{provider}", response_model=IntegrationOut)
def set_integration_key(
    tenant_id: uuid.UUID,
    provider: str,
    # a plain dict on purpose: a validation error would echo the submitted value back
    body: dict = Body(...),
    db: Session = Depends(get_scoped_db),
    token: dict = Depends(require_roles(*_ADMINS)),
):
    label, fmt = _provider(provider)
    api_key = body.get("api_key")
    if not isinstance(api_key, str) or not api_key.strip():
        raise _err(422, "VALIDATION_ERROR", "api_key is required")
    api_key = api_key.strip()
    if not fmt.match(api_key):
        raise _err(422, "VALIDATION_ERROR", f"This does not look like a {label} API key")
    try:
        cipher = encrypt(api_key)
    except VaultNotConfigured as exc:
        raise _err(
            503,
            "SERVICE_UNAVAILABLE",
            "Storing keys is not configured on this server (SECRETS_ENCRYPTION_KEY is missing)",
        ) from exc

    row = db.execute(
        select(IntegrationKey).where(IntegrationKey.tenant_id == tenant_id, IntegrationKey.provider == provider)
    ).scalar_one_or_none()
    now = datetime.now(UTC)
    if row is None:
        row = IntegrationKey(tenant_id=tenant_id, provider=provider, ciphertext=cipher)
        db.add(row)
    row.ciphertext = cipher
    row.updated_by = _actor(token)
    row.updated_at = now
    db.flush()
    return IntegrationOut(provider=provider, label=label, configured=True, updated_at=now)


@router.delete("/tenants/{tenant_id}/integrations/{provider}", status_code=204)
def delete_integration_key(
    tenant_id: uuid.UUID,
    provider: str,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(*_ADMINS)),
):
    _provider(provider)
    row = db.execute(
        select(IntegrationKey).where(IntegrationKey.tenant_id == tenant_id, IntegrationKey.provider == provider)
    ).scalar_one_or_none()
    if row is not None:
        db.delete(row)
        db.flush()
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------


class EnrichmentOut(BaseModel):
    model_config = {"from_attributes": True}

    indicator_id: uuid.UUID
    provider: str
    status: str
    malicious: int | None
    suspicious: int | None
    harmless: int | None
    undetected: int | None
    reputation: int | None
    analysis_date: datetime | None
    permalink: str | None
    fetched_at: datetime


@router.get("/tenants/{tenant_id}/enrichments", response_model=Page[EnrichmentOut])
def list_enrichments(
    tenant_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    params: PageParams = Depends(page_params),
):
    stmt = (
        select(IndicatorEnrichment)
        .where(IndicatorEnrichment.tenant_id == tenant_id)
        .order_by(IndicatorEnrichment.fetched_at.desc(), IndicatorEnrichment.id)
    )
    return paginate(db, stmt, params, EnrichmentOut)


@router.post("/tenants/{tenant_id}/indicators/{indicator_id}/enrich", response_model=EnrichmentOut)
def enrich_indicator(
    tenant_id: uuid.UUID,
    indicator_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(*_WRITERS)),
):
    """Ask VirusTotal about one indicator the tenant can see (its own or a shared one)."""
    ind = db.execute(
        select(Indicator).where(
            Indicator.id == indicator_id,
            or_(Indicator.tenant_id.is_(None), Indicator.tenant_id == tenant_id),
        )
    ).scalar_one_or_none()
    if ind is None:
        raise _err(404, "NOT_FOUND", "Indicator not found")

    key_row = db.execute(
        select(IntegrationKey).where(
            IntegrationKey.tenant_id == tenant_id, IntegrationKey.provider == vt.PROVIDER
        )
    ).scalar_one_or_none()
    if key_row is None:
        raise _err(409, "CONFLICT", "No VirusTotal key is configured. An administrator can add one in Management → Integrations.")
    try:
        api_key = decrypt(key_row.ciphertext)
    except (VaultDecryptError, VaultNotConfigured) as exc:
        raise _err(409, "CONFLICT", "The stored VirusTotal key cannot be used any more; an administrator must enter it again.") from exc

    try:
        result = vt.lookup(ind.ioc_type, ind.value, api_key)
    except vt.VirusTotalError as exc:
        raise _err(exc.status, "UPSTREAM_ERROR", exc.message) from exc

    row = db.execute(
        select(IndicatorEnrichment).where(
            IndicatorEnrichment.indicator_id == ind.id,
            IndicatorEnrichment.tenant_id == tenant_id,
            IndicatorEnrichment.provider == vt.PROVIDER,
        )
    ).scalar_one_or_none()
    if row is None:
        row = IndicatorEnrichment(tenant_id=tenant_id, indicator_id=ind.id, provider=vt.PROVIDER, status=result.status)
        db.add(row)
    for field in ("status", "malicious", "suspicious", "harmless", "undetected", "reputation", "analysis_date", "permalink"):
        setattr(row, field, getattr(result, field))
    row.fetched_at = datetime.now(UTC)
    db.flush()
    return row
