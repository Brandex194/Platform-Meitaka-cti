"""STIX 2.1 import and export (passo 9).

Export: a bundle with the tenant's visible indicators, threat actors and campaigns.
Import: the same kinds of object; everything created belongs to the importing tenant, duplicates
are counted but not touched, and whatever cannot be stored is listed with the reason.
"""
import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.v1.deps import get_scoped_db
from app.auth.roles import Role, require_roles
from app.core.errors import error_response
from app.db.models import Campaign, CampaignIndicator, Indicator, ThreatActor
from app.stix.export import build_bundle
from app.stix.parse import BundleError, parse_bundle

router = APIRouter()

_ALLOWED = (Role.super_admin, Role.tenant_admin, Role.analyst, Role.api_user)
MAX_BODY_BYTES = 10 * 1024 * 1024
MAX_SKIPPED_LISTED = 100
STIX_MEDIA_TYPE = "application/stix+json;version=2.1"


def _visible(model, tenant_id: uuid.UUID, own_only: bool):
    if own_only:
        return model.tenant_id == tenant_id
    return or_(model.tenant_id.is_(None), model.tenant_id == tenant_id)


@router.get("/tenants/{tenant_id}/stix/export")
def export_bundle(
    tenant_id: uuid.UUID,
    own_only: bool = Query(False, description="only what this tenant created, not the shared catalog"),
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(*_ALLOWED)),
):
    indicators = db.execute(
        select(Indicator).where(_visible(Indicator, tenant_id, own_only)).order_by(Indicator.created_at, Indicator.id)
    ).scalars().all()
    actors = db.execute(
        select(ThreatActor).where(_visible(ThreatActor, tenant_id, own_only)).order_by(ThreatActor.name, ThreatActor.id)
    ).scalars().all()
    campaigns = db.execute(
        select(Campaign).where(_visible(Campaign, tenant_id, own_only)).order_by(Campaign.name, Campaign.id)
    ).scalars().all()
    links = [
        (link.indicator_id, link.campaign_id)
        for link in db.execute(
            select(CampaignIndicator).where(CampaignIndicator.tenant_id == tenant_id)
        ).scalars()
    ]
    bundle, notes = build_bundle(list(indicators), list(actors), list(campaigns), links)
    return Response(
        content=json.dumps(bundle, ensure_ascii=False),
        media_type=STIX_MEDIA_TYPE,
        headers={
            "Content-Disposition": 'attachment; filename="meitaka-stix-bundle.json"',
            "X-Stix-Skipped": str(len(notes)),
        },
    )


class Counts(BaseModel):
    indicators: int = 0
    threat_actors: int = 0
    campaigns: int = 0
    links: int = 0  # indicator <-> campaign


class SkippedOut(BaseModel):
    id: str
    type: str
    reason: str


class ImportResult(BaseModel):
    created: Counts
    duplicates: Counts
    skipped_total: int
    skipped: list[SkippedOut]  # first MAX_SKIPPED_LISTED only


def _bad_request(message: str, status: int = 400) -> HTTPException:
    return HTTPException(status_code=status, detail=error_response("BAD_REQUEST", message))


@router.post("/tenants/{tenant_id}/stix/import", response_model=ImportResult)
async def import_bundle(
    tenant_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(*_ALLOWED)),
):
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise _bad_request("bundle too large (10 MB maximum)", 413)
    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES:
        raise _bad_request("bundle too large (10 MB maximum)", 413)
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise _bad_request("the body is not valid JSON") from exc
    try:
        parsed = parse_bundle(data)
    except BundleError as exc:
        raise _bad_request(str(exc)) from exc
    return _store(db, tenant_id, parsed)


def _store(db: Session, tenant_id: uuid.UUID, parsed) -> ImportResult:
    created, dupes = Counts(), Counts()

    # --- indicators: same (type, value) already visible to this tenant = duplicate
    known = {
        (t, v): iid
        for iid, t, v in db.execute(
            select(Indicator.id, Indicator.ioc_type, Indicator.value).where(
                or_(Indicator.tenant_id.is_(None), Indicator.tenant_id == tenant_id)
            )
        ).all()
    }
    indicator_ids: dict[str, uuid.UUID] = {}  # stix id -> our id
    for ind in parsed.indicators:
        key = (ind.ioc_type, ind.value)
        if key in known:
            indicator_ids[ind.stix_id] = known[key]
            dupes.indicators += 1
            continue
        row = Indicator(tenant_id=tenant_id, ioc_type=ind.ioc_type, value=ind.value, confidence=ind.confidence)
        db.add(row)
        db.flush()
        known[key] = row.id
        indicator_ids[ind.stix_id] = row.id
        created.indicators += 1

    # --- actors: match by name (case-insensitive) among shared + own
    actor_by_name: dict[str, uuid.UUID] = {
        name.lower(): aid
        for aid, name in db.execute(
            select(ThreatActor.id, ThreatActor.name).where(
                or_(ThreatActor.tenant_id.is_(None), ThreatActor.tenant_id == tenant_id)
            )
        ).all()
    }
    actor_ids: dict[str, uuid.UUID] = {}  # stix id -> our id
    for a in parsed.actors:
        existing = actor_by_name.get(a.name.lower())
        if existing is not None:
            actor_ids[a.stix_id] = existing
            dupes.threat_actors += 1
            continue
        row = ThreatActor(
            tenant_id=tenant_id, name=a.name, aliases=a.aliases or None, description=a.description
        )
        db.add(row)
        db.flush()
        actor_by_name[a.name.lower()] = row.id
        actor_ids[a.stix_id] = row.id
        created.threat_actors += 1

    # --- campaigns: match by name among shared + own; link to the actor when the bundle says so
    campaign_by_name: dict[str, uuid.UUID] = {
        n.lower(): cid
        for cid, n in db.execute(
            select(Campaign.id, Campaign.name).where(or_(Campaign.tenant_id.is_(None), Campaign.tenant_id == tenant_id))
        ).all()
    }
    campaign_ids: dict[str, uuid.UUID] = {}  # stix id -> our id
    for c in parsed.campaigns:
        existing_campaign = campaign_by_name.get(c.name.lower())
        if existing_campaign is not None:
            campaign_ids[c.stix_id] = existing_campaign
            dupes.campaigns += 1
            continue
        actor_ref = parsed.attributions.get(c.stix_id)
        row = Campaign(
            tenant_id=tenant_id,
            name=c.name,
            description=c.description,
            threat_actor_id=actor_ids.get(actor_ref) if actor_ref else None,
        )
        db.add(row)
        db.flush()
        campaign_by_name[c.name.lower()] = row.id
        campaign_ids[c.stix_id] = row.id
        created.campaigns += 1

    # --- indicator --indicates--> campaign, when both ends resolved to a record the tenant can see
    present = {
        (cid, iid)
        for cid, iid in db.execute(
            select(CampaignIndicator.campaign_id, CampaignIndicator.indicator_id).where(
                CampaignIndicator.tenant_id == tenant_id
            )
        ).all()
    }
    unresolved: list[SkippedOut] = []
    for ind_ref, camp_ref in parsed.indications:
        iid, cid = indicator_ids.get(ind_ref), campaign_ids.get(camp_ref)
        if iid is None or cid is None:
            unresolved.append(
                SkippedOut(id=ind_ref, type="relationship", reason="the indicator or the campaign was not imported")
            )
            continue
        if (cid, iid) in present:
            dupes.links += 1
            continue
        present.add((cid, iid))
        db.add(CampaignIndicator(tenant_id=tenant_id, campaign_id=cid, indicator_id=iid))
        created.links += 1

    db.flush()
    every = [SkippedOut(id=s.stix_id, type=s.stix_type, reason=s.reason) for s in parsed.skipped] + unresolved
    return ImportResult(created=created, duplicates=dupes, skipped_total=len(every), skipped=every[:MAX_SKIPPED_LISTED])


