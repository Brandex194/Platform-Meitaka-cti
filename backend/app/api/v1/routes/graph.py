"""Knowledge Graph (passo 11): threat actors, campaigns and the indicators seen in them.

Edges: campaign --attributed-to--> threat actor (campaigns.threat_actor_id) and
indicator --indicates--> campaign (campaign_indicators, one row per link, owned by a tenant).
Actors, campaigns and indicators have no RLS (shared rows have tenant_id NULL), so every query
here filters by hand: shared rows plus the caller's tenant, never another tenant's.
"""
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.v1.deps import get_scoped_db
from app.auth.roles import Role, require_roles
from app.core.errors import error_response
from app.db.models import Campaign, CampaignIndicator, Indicator, ThreatActor

router = APIRouter()

_WRITERS = (Role.super_admin, Role.tenant_admin, Role.analyst)
MAX_INDICATOR_NODES = 500


def _visible(model, tenant_id: uuid.UUID):
    return or_(model.tenant_id.is_(None), model.tenant_id == tenant_id)


def _not_found(what: str) -> HTTPException:
    return HTTPException(status_code=404, detail=error_response("NOT_FOUND", f"{what} not found"))


class Node(BaseModel):
    id: uuid.UUID
    type: Literal["threat_actor", "campaign", "indicator"]
    label: str
    own: bool  # created by this tenant (False = shared catalog / feed)
    detail: str | None = None  # indicator type for indicators


class Edge(BaseModel):
    source: uuid.UUID
    target: uuid.UUID
    type: Literal["attributed-to", "indicates"]


class GraphOut(BaseModel):
    nodes: list[Node]
    edges: list[Edge]
    indicators_total: int  # linked indicators in this tenant
    truncated: bool  # more linked indicators than MAX_INDICATOR_NODES were left out


@router.get("/tenants/{tenant_id}/graph", response_model=GraphOut)
def knowledge_graph(tenant_id: uuid.UUID, db: Session = Depends(get_scoped_db)):
    actors = db.execute(
        select(ThreatActor).where(_visible(ThreatActor, tenant_id)).order_by(ThreatActor.name, ThreatActor.id)
    ).scalars().all()
    campaigns = db.execute(
        select(Campaign).where(_visible(Campaign, tenant_id)).order_by(Campaign.name, Campaign.id)
    ).scalars().all()
    campaign_ids = {c.id for c in campaigns}
    actor_ids = {a.id for a in actors}

    links = [
        link
        for link in db.execute(
            select(CampaignIndicator)
            .where(CampaignIndicator.tenant_id == tenant_id)
            .order_by(CampaignIndicator.created_at, CampaignIndicator.id)
        ).scalars()
        if link.campaign_id in campaign_ids
    ]
    linked_ids = list(dict.fromkeys(link.indicator_id for link in links))
    shown_ids = linked_ids[:MAX_INDICATOR_NODES]
    indicators = (
        db.execute(
            select(Indicator).where(Indicator.id.in_(shown_ids), _visible(Indicator, tenant_id))
        ).scalars().all()
        if shown_ids
        else []
    )
    by_id = {i.id: i for i in indicators}

    nodes = [Node(id=a.id, type="threat_actor", label=a.name, own=a.tenant_id is not None) for a in actors]
    nodes += [Node(id=c.id, type="campaign", label=c.name, own=c.tenant_id is not None) for c in campaigns]
    nodes += [
        Node(id=i.id, type="indicator", label=i.value, own=i.tenant_id is not None, detail=i.ioc_type)
        for i in sorted(indicators, key=lambda x: (x.ioc_type, x.value))
    ]
    edges = [
        Edge(source=c.id, target=c.threat_actor_id, type="attributed-to")
        for c in campaigns
        if c.threat_actor_id in actor_ids
    ]
    edges += [
        Edge(source=link.indicator_id, target=link.campaign_id, type="indicates")
        for link in links
        if link.indicator_id in by_id
    ]
    return GraphOut(
        nodes=nodes,
        edges=edges,
        indicators_total=len(linked_ids),
        truncated=len(linked_ids) > len(shown_ids),
    )


class LinkIn(BaseModel):
    indicator_id: uuid.UUID


def _campaign(db: Session, tenant_id: uuid.UUID, campaign_id: uuid.UUID) -> Campaign:
    c = db.execute(
        select(Campaign).where(Campaign.id == campaign_id, _visible(Campaign, tenant_id))
    ).scalar_one_or_none()
    if c is None:
        raise _not_found("Campaign")
    return c


@router.post("/tenants/{tenant_id}/campaigns/{campaign_id}/indicators", status_code=201)
def link_indicator(
    tenant_id: uuid.UUID,
    campaign_id: uuid.UUID,
    body: LinkIn,
    response: Response,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(*_WRITERS)),
):
    """Say that an indicator is seen in a campaign. Both can be shared; the link is the tenant's.
    Linking twice is not an error: the second call answers 200 and changes nothing."""
    _campaign(db, tenant_id, campaign_id)
    indicator = db.execute(
        select(Indicator.id).where(Indicator.id == body.indicator_id, _visible(Indicator, tenant_id))
    ).first()
    if indicator is None:
        raise _not_found("Indicator")
    existing = db.execute(
        select(CampaignIndicator.id).where(
            CampaignIndicator.tenant_id == tenant_id,
            CampaignIndicator.campaign_id == campaign_id,
            CampaignIndicator.indicator_id == body.indicator_id,
        )
    ).first()
    if existing is not None:
        response.status_code = 200
        return {"campaign_id": campaign_id, "indicator_id": body.indicator_id, "created": False}
    db.add(CampaignIndicator(tenant_id=tenant_id, campaign_id=campaign_id, indicator_id=body.indicator_id))
    try:
        db.flush()
    except IntegrityError:  # a second request got there first
        db.rollback()
        response.status_code = 200
        return {"campaign_id": campaign_id, "indicator_id": body.indicator_id, "created": False}
    return {"campaign_id": campaign_id, "indicator_id": body.indicator_id, "created": True}


@router.delete("/tenants/{tenant_id}/campaigns/{campaign_id}/indicators/{indicator_id}", status_code=204)
def unlink_indicator(
    tenant_id: uuid.UUID,
    campaign_id: uuid.UUID,
    indicator_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(*_WRITERS)),
):
    link = db.execute(
        select(CampaignIndicator).where(
            CampaignIndicator.tenant_id == tenant_id,
            CampaignIndicator.campaign_id == campaign_id,
            CampaignIndicator.indicator_id == indicator_id,
        )
    ).scalar_one_or_none()
    if link is None:
        raise _not_found("Link")
    db.delete(link)
    db.flush()
    return Response(status_code=204)
