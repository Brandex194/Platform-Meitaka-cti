"""CTI platform connectors: MISP, OpenCTI, TheHive, TAXII 2.1, SIEM push.

Stub phase: configuration is stored (vault-encrypted like IntegrationKey) but
actual sync/push jobs are not yet implemented. Each connector returns its current
status and when it was last configured.
"""
import uuid
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel, HttpUrl
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.v1.deps import get_scoped_db
from app.auth.roles import Role, require_roles
from app.core.errors import error_response
from app.core.vault import VaultNotConfigured, decrypt, encrypt
from app.db.models import IntegrationKey

router = APIRouter()

_ADMINS = (Role.tenant_admin, Role.super_admin)

CONNECTORS: dict[str, str] = {
    "misp": "MISP",
    "opencti": "OpenCTI",
    "thehive": "TheHive",
    "taxii": "TAXII 2.1",
    "splunk": "Splunk",
    "qradar": "IBM QRadar",
    "sentinel": "Microsoft Sentinel",
}


class ConnectorStatus(BaseModel):
    provider: str
    label: str
    configured: bool
    updated_at: str | None


class ConnectorIn(BaseModel):
    url: str
    api_key: str


def _err(status: int, code: str, msg: str) -> HTTPException:
    return HTTPException(status_code=status, detail=error_response(code, msg))


@router.get("/tenants/{tenant_id}/connectors", response_model=list[ConnectorStatus])
def list_connectors(
    tenant_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    _token: dict = Depends(require_roles(*_ADMINS)),
):
    rows = {
        row.provider: row
        for row in db.execute(
            select(IntegrationKey).where(
                IntegrationKey.tenant_id == tenant_id,
                IntegrationKey.provider.in_(CONNECTORS),
            )
        ).scalars().all()
    }
    return [
        ConnectorStatus(
            provider=p,
            label=label,
            configured=p in rows,
            updated_at=rows[p].updated_at.isoformat() if p in rows else None,
        )
        for p, label in CONNECTORS.items()
    ]


@router.put("/tenants/{tenant_id}/connectors/{provider}", response_model=ConnectorStatus)
def set_connector(
    tenant_id: uuid.UUID,
    provider: str,
    body: ConnectorIn = Body(...),
    db: Session = Depends(get_scoped_db),
    _token: dict = Depends(require_roles(*_ADMINS)),
):
    if provider not in CONNECTORS:
        raise _err(404, "NOT_FOUND", "Unknown connector")
    secret = f"{body.url}|||{body.api_key}"
    try:
        encrypted = encrypt(secret)
    except VaultNotConfigured as exc:
        raise _err(503, "VAULT_NOT_CONFIGURED", str(exc)) from exc

    row = db.execute(
        select(IntegrationKey).where(
            IntegrationKey.tenant_id == tenant_id,
            IntegrationKey.provider == provider,
        )
    ).scalar_one_or_none()

    now = datetime.now(UTC)
    if row:
        row.encrypted_key = encrypted
        row.updated_at = now
    else:
        db.add(IntegrationKey(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            provider=provider,
            encrypted_key=encrypted,
            created_at=now,
            updated_at=now,
        ))
    db.commit()
    return ConnectorStatus(provider=provider, label=CONNECTORS[provider], configured=True, updated_at=now.isoformat())


@router.delete("/tenants/{tenant_id}/connectors/{provider}", status_code=204)
def delete_connector(
    tenant_id: uuid.UUID,
    provider: str,
    db: Session = Depends(get_scoped_db),
    _token: dict = Depends(require_roles(*_ADMINS)),
):
    if provider not in CONNECTORS:
        raise _err(404, "NOT_FOUND", "Unknown connector")
    row = db.execute(
        select(IntegrationKey).where(
            IntegrationKey.tenant_id == tenant_id,
            IntegrationKey.provider == provider,
        )
    ).scalar_one_or_none()
    if row:
        db.delete(row)
        db.commit()
