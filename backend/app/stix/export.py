"""Build a STIX 2.1 bundle from our indicators, threat actors and campaigns.

Object ids reuse our own UUIDs (`indicator--<id>`), so exporting twice gives the same ids and a
receiver can merge instead of duplicating.
"""
import uuid
from datetime import UTC, datetime

from app.db.models import Campaign, Indicator, ThreatActor
from app.stix.patterns import to_pattern

SPEC_VERSION = "2.1"
_REL_NS = uuid.UUID("6f1c2f1e-3f55-4a7e-9b52-0f3a5b1d7c10")  # fixed: relationship ids stay stable


def _ts(dt: datetime | None) -> str:
    dt = dt or datetime.now(UTC)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _base(kind: str, obj_id: uuid.UUID, created: datetime | None) -> dict:
    ts = _ts(created)
    return {"type": kind, "spec_version": SPEC_VERSION, "id": f"{kind}--{obj_id}", "created": ts, "modified": ts}


def indicator_object(i: Indicator) -> tuple[dict | None, str | None]:
    """(STIX object, None) or (None, reason) when the observable cannot be written as a pattern."""
    pattern = to_pattern(i.ioc_type, i.value)
    if pattern is None:
        return None, f"{i.ioc_type} '{i.value[:40]}' cannot be written as a STIX pattern"
    obj = _base("indicator", i.id, i.created_at)
    obj.update(
        {
            "name": f"{i.ioc_type}: {i.value}"[:250],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": obj["created"],
            "indicator_types": ["malicious-activity"],
        }
    )
    if i.confidence is not None:
        obj["confidence"] = round(i.confidence * 100)
    return obj, None


def build_bundle(
    indicators: list[Indicator],
    actors: list[ThreatActor],
    campaigns: list[Campaign],
    links: list[tuple[uuid.UUID, uuid.UUID]] | None = None,
) -> tuple[dict, list[str]]:
    """(bundle, notes). Notes list what was left out and why."""
    objects: list[dict] = []
    notes: list[str] = []
    actor_ids = {a.id for a in actors}

    for a in actors:
        o = _base("threat-actor", a.id, a.created_at)
        o["name"] = a.name
        o["threat_actor_types"] = ["unknown"]
        if a.aliases:
            o["aliases"] = [x for x in a.aliases if isinstance(x, str)]
        if a.description:
            o["description"] = a.description
        objects.append(o)

    for c in campaigns:
        o = _base("campaign", c.id, c.created_at)
        o["name"] = c.name
        if c.description:
            o["description"] = c.description
        objects.append(o)
        if c.threat_actor_id and c.threat_actor_id in actor_ids:
            rel = _base(
                "relationship",
                uuid.uuid5(_REL_NS, f"{c.id}:attributed-to:{c.threat_actor_id}"),
                c.created_at,
            )
            rel.update(
                {
                    "relationship_type": "attributed-to",
                    "source_ref": f"campaign--{c.id}",
                    "target_ref": f"threat-actor--{c.threat_actor_id}",
                }
            )
            objects.append(rel)

    written: set[uuid.UUID] = set()
    for i in indicators:
        obj, reason = indicator_object(i)
        if obj is None:
            notes.append(reason or "indicator skipped")
        else:
            objects.append(obj)
            written.add(i.id)

    # indicator --indicates--> campaign, only when both ends are in the bundle
    campaign_ids = {c.id for c in campaigns}
    for indicator_id, campaign_id in links or []:
        if indicator_id in written and campaign_id in campaign_ids:
            rel = _base("relationship", uuid.uuid5(_REL_NS, f"{indicator_id}:indicates:{campaign_id}"), None)
            rel.update(
                {
                    "relationship_type": "indicates",
                    "source_ref": f"indicator--{indicator_id}",
                    "target_ref": f"campaign--{campaign_id}",
                }
            )
            objects.append(rel)

    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}, notes
