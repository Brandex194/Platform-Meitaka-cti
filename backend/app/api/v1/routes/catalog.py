"""Shared CTI catalog: threat actors and campaigns.

Both tables have no RLS: a row with tenant_id NULL is shared, otherwise it belongs to one tenant.
The tenant filter in these routes is the only isolation, so every query below has it.
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, or_, select, update
from sqlalchemy.orm import Session

from app.api.v1.deps import get_scoped_db
from app.api.v1.pagination import PageParams, page_params, paginate
from app.api.v1.schemas import CampaignOut, Page, ThreatActorOut
from app.auth.jwks import decode_token
from app.auth.roles import Role, require_roles
from app.core.errors import error_response
from app.db.models import Campaign, CampaignIndicator, ThreatActor
from app.db.session import get_db

router = APIRouter()

_WRITERS = (Role.super_admin, Role.tenant_admin, Role.analyst)


def _roles(token: dict) -> list:
    return token.get("roles") or token.get("realm_access", {}).get("roles", [])


def _token_tenant(token: dict) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(token.get("tenant_id")))
    except ValueError:
        return None


def _visible(model, token: dict):
    """Shared rows plus the caller's tenant; super_admin sees everything."""
    if Role.super_admin.value in _roles(token):
        return None
    tenant_id = _token_tenant(token)
    if tenant_id is None:
        return model.tenant_id.is_(None)
    return or_(model.tenant_id.is_(None), model.tenant_id == tenant_id)


def _not_found(what: str) -> HTTPException:
    return HTTPException(status_code=404, detail=error_response("NOT_FOUND", f"{what} not found"))


class ActorIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    aliases: list[str] | None = Field(None, max_length=20)
    description: str | None = Field(None, max_length=10000)

    @field_validator("name")
    @classmethod
    def _strip_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name must not be blank")
        return v

    @field_validator("aliases")
    @classmethod
    def _clean_aliases(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        cleaned = [a.strip() for a in v if a.strip()]
        if any(len(a) > 100 for a in cleaned):
            raise ValueError("each alias must be at most 100 characters")
        return cleaned


class ActorUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    aliases: list[str] | None = Field(None, max_length=20)
    description: str | None = Field(None, max_length=10000)

    _strip_name = field_validator("name")(ActorIn._strip_name.__func__)
    _clean_aliases = field_validator("aliases")(ActorIn._clean_aliases.__func__)


class CampaignIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    threat_actor_id: uuid.UUID | None = None
    description: str | None = Field(None, max_length=10000)

    _strip_name = field_validator("name")(ActorIn._strip_name.__func__)


class CampaignUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    threat_actor_id: uuid.UUID | None = None
    description: str | None = Field(None, max_length=10000)

    _strip_name = field_validator("name")(ActorIn._strip_name.__func__)


# ---------------------------------------------------------------------------
# Threat actors
# ---------------------------------------------------------------------------


@router.get("/threat-actors", response_model=Page[ThreatActorOut])
def list_threat_actors(
    db: Session = Depends(get_db),
    token: dict = Depends(decode_token),
    params: PageParams = Depends(page_params),
):
    stmt = select(ThreatActor)
    cond = _visible(ThreatActor, token)
    if cond is not None:
        stmt = stmt.where(cond)
    stmt = stmt.order_by(ThreatActor.name, ThreatActor.id)
    return paginate(db, stmt, params, ThreatActorOut)


def _own_actor(db: Session, tenant_id: uuid.UUID, actor_id: uuid.UUID) -> ThreatActor:
    actor = db.execute(
        select(ThreatActor).where(ThreatActor.id == actor_id, ThreatActor.tenant_id == tenant_id)
    ).scalar_one_or_none()
    if actor is None:
        raise _not_found("Threat actor")
    return actor


@router.post("/tenants/{tenant_id}/threat-actors", status_code=201, response_model=ThreatActorOut)
def create_threat_actor(
    tenant_id: uuid.UUID,
    body: ActorIn,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(*_WRITERS)),
):
    actor = ThreatActor(
        tenant_id=tenant_id, name=body.name, aliases=body.aliases, description=body.description
    )
    db.add(actor)
    db.flush()
    db.refresh(actor)
    return actor


@router.patch("/tenants/{tenant_id}/threat-actors/{actor_id}", response_model=ThreatActorOut)
def update_threat_actor(
    tenant_id: uuid.UUID,
    actor_id: uuid.UUID,
    body: ActorUpdate,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(*_WRITERS)),
):
    """Only the tenant's own actors: shared catalog entries are not editable from a tenant."""
    actor = _own_actor(db, tenant_id, actor_id)
    for field, value in body.model_dump(exclude_unset=True).items():
        if field == "name" and value is None:
            continue
        setattr(actor, field, value)
    db.flush()
    db.refresh(actor)
    return actor


@router.delete("/tenants/{tenant_id}/threat-actors/{actor_id}", status_code=204)
def delete_threat_actor(
    tenant_id: uuid.UUID,
    actor_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(*_WRITERS)),
):
    actor = _own_actor(db, tenant_id, actor_id)
    # Postgres does this through ON DELETE SET NULL; doing it here keeps it true on any database.
    db.execute(update(Campaign).where(Campaign.threat_actor_id == actor.id).values(threat_actor_id=None))
    db.delete(actor)
    db.flush()


# ---------------------------------------------------------------------------
# Campaigns
# ---------------------------------------------------------------------------


@router.get("/campaigns", response_model=Page[CampaignOut])
def list_campaigns(
    db: Session = Depends(get_db),
    token: dict = Depends(decode_token),
    params: PageParams = Depends(page_params),
):
    """Global campaigns plus those of the caller's tenant: super_admin sees everything."""
    stmt = select(Campaign)
    cond = _visible(Campaign, token)
    if cond is not None:
        stmt = stmt.where(cond)
    stmt = stmt.order_by(Campaign.created_at.desc(), Campaign.id)
    return paginate(db, stmt, params, CampaignOut)


def _own_campaign(db: Session, tenant_id: uuid.UUID, campaign_id: uuid.UUID) -> Campaign:
    campaign = db.execute(
        select(Campaign).where(Campaign.id == campaign_id, Campaign.tenant_id == tenant_id)
    ).scalar_one_or_none()
    if campaign is None:
        raise _not_found("Campaign")
    return campaign


def _check_actor_usable(db: Session, tenant_id: uuid.UUID, actor_id: uuid.UUID | None) -> None:
    """A campaign may point to a shared actor or one of the tenant's own, never to another tenant's."""
    if actor_id is None:
        return
    found = db.execute(
        select(ThreatActor.id).where(
            ThreatActor.id == actor_id,
            or_(ThreatActor.tenant_id.is_(None), ThreatActor.tenant_id == tenant_id),
        )
    ).scalar_one_or_none()
    if found is None:
        raise _not_found("Threat actor")


@router.post("/tenants/{tenant_id}/campaigns", status_code=201, response_model=CampaignOut)
def create_campaign(
    tenant_id: uuid.UUID,
    body: CampaignIn,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(*_WRITERS)),
):
    _check_actor_usable(db, tenant_id, body.threat_actor_id)
    campaign = Campaign(
        tenant_id=tenant_id,
        name=body.name,
        threat_actor_id=body.threat_actor_id,
        description=body.description,
    )
    db.add(campaign)
    db.flush()
    db.refresh(campaign)
    return campaign


@router.patch("/tenants/{tenant_id}/campaigns/{campaign_id}", response_model=CampaignOut)
def update_campaign(
    tenant_id: uuid.UUID,
    campaign_id: uuid.UUID,
    body: CampaignUpdate,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(*_WRITERS)),
):
    campaign = _own_campaign(db, tenant_id, campaign_id)
    data = body.model_dump(exclude_unset=True)
    if "threat_actor_id" in data:
        _check_actor_usable(db, tenant_id, data["threat_actor_id"])
    for field, value in data.items():
        if field == "name" and value is None:
            continue
        setattr(campaign, field, value)
    db.flush()
    db.refresh(campaign)
    return campaign


@router.delete("/tenants/{tenant_id}/campaigns/{campaign_id}", status_code=204)
def delete_campaign(
    tenant_id: uuid.UUID,
    campaign_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(*_WRITERS)),
):
    campaign = _own_campaign(db, tenant_id, campaign_id)
    # explicit: the database cascades too, but SQLite (tests) does not enforce foreign keys
    db.execute(delete(CampaignIndicator).where(CampaignIndicator.campaign_id == campaign.id))
    db.delete(campaign)
    db.flush()
