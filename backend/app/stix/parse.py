"""Read a STIX 2.1 bundle into the records we can store, and say what we skipped and why."""
import ipaddress
import re
import uuid
from dataclasses import dataclass, field

from app.stix.patterns import PatternError, from_pattern

MAX_OBJECTS = 5000
_NAME_MAX = 255
_VALUE_MAX = 512
_ID_RE = re.compile(r"^([a-z][a-z0-9-]*)--([0-9a-fA-F-]{36})$")
_NORMALISED = ("domain", "email", "hash")


@dataclass
class ParsedIndicator:
    stix_id: str
    ioc_type: str
    value: str
    confidence: float | None


@dataclass
class ParsedActor:
    stix_id: str
    name: str
    aliases: list[str]
    description: str | None


@dataclass
class ParsedCampaign:
    stix_id: str
    name: str
    description: str | None


@dataclass
class Skipped:
    stix_id: str
    stix_type: str
    reason: str


@dataclass
class ParsedBundle:
    indicators: list[ParsedIndicator] = field(default_factory=list)
    actors: list[ParsedActor] = field(default_factory=list)
    campaigns: list[ParsedCampaign] = field(default_factory=list)
    # campaign stix id -> actor stix id, from `attributed-to` relationships
    attributions: dict[str, str] = field(default_factory=dict)
    # (indicator stix id, campaign stix id), from `indicates` relationships
    indications: list[tuple[str, str]] = field(default_factory=list)
    skipped: list[Skipped] = field(default_factory=list)


class BundleError(ValueError):
    """The document is not a usable STIX 2.1 bundle at all."""


def _clean_text(value: object, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value[:limit] if value else None


def _valid_id(value: object, expected_type: str | None = None) -> bool:
    m = _ID_RE.match(value) if isinstance(value, str) else None
    if not m or (expected_type and m.group(1) != expected_type):
        return False
    try:
        uuid.UUID(m.group(2))
    except ValueError:
        return False
    return True


def parse_bundle(data: object) -> ParsedBundle:
    if not isinstance(data, dict) or data.get("type") != "bundle":
        raise BundleError('not a STIX bundle (expected {"type": "bundle", ...})')
    objects = data.get("objects")
    if objects is None:
        objects = []
    if not isinstance(objects, list):
        raise BundleError('"objects" must be a list')
    if len(objects) > MAX_OBJECTS:
        raise BundleError(f"too many objects ({len(objects)}); the limit is {MAX_OBJECTS} per bundle")

    out = ParsedBundle()
    for raw in objects:
        if not isinstance(raw, dict):
            out.skipped.append(Skipped("?", "?", "not an object"))
            continue
        kind = str(raw.get("type", "?"))
        sid = str(raw.get("id", "?"))
        if not _valid_id(raw.get("id"), kind):
            out.skipped.append(Skipped(sid[:80], kind[:40], "invalid id"))
            continue
        if raw.get("revoked") is True:
            out.skipped.append(Skipped(sid, kind, "revoked"))
            continue
        if kind == "indicator":
            _indicator(raw, sid, out)
        elif kind == "threat-actor":
            name = _clean_text(raw.get("name"), _NAME_MAX)
            if not name:
                out.skipped.append(Skipped(sid, kind, "missing name"))
                continue
            aliases = [a.strip() for a in raw.get("aliases", []) if isinstance(a, str) and a.strip()]
            out.actors.append(ParsedActor(sid, name, aliases[:50], _clean_text(raw.get("description"), 10000)))
        elif kind == "campaign":
            name = _clean_text(raw.get("name"), _NAME_MAX)
            if not name:
                out.skipped.append(Skipped(sid, kind, "missing name"))
                continue
            out.campaigns.append(ParsedCampaign(sid, name, _clean_text(raw.get("description"), 10000)))
        elif kind == "relationship":
            if (
                raw.get("relationship_type") == "attributed-to"
                and str(raw.get("source_ref", "")).startswith("campaign--")
                and str(raw.get("target_ref", "")).startswith("threat-actor--")
            ):
                out.attributions[str(raw["source_ref"])] = str(raw["target_ref"])
            elif (
                raw.get("relationship_type") == "indicates"
                and str(raw.get("source_ref", "")).startswith("indicator--")
                and str(raw.get("target_ref", "")).startswith("campaign--")
            ):
                out.indications.append((str(raw["source_ref"]), str(raw["target_ref"])))
            else:
                out.skipped.append(
                    Skipped(sid, kind, f"relationship '{raw.get('relationship_type')}' is not stored yet")
                )
        else:
            out.skipped.append(Skipped(sid, kind[:40], f"type '{kind[:40]}' is not supported yet"))
    return out


def _indicator(raw: dict, sid: str, out: ParsedBundle) -> None:
    if raw.get("pattern_type", "stix") != "stix":
        out.skipped.append(Skipped(sid, "indicator", f"pattern type '{str(raw.get('pattern_type'))[:20]}' not supported"))
        return
    try:
        ioc_type, value = from_pattern(str(raw.get("pattern", "")))
    except PatternError as exc:
        out.skipped.append(Skipped(sid, "indicator", str(exc)))
        return
    value = value.strip()
    if not value or len(value) > _VALUE_MAX:
        out.skipped.append(Skipped(sid, "indicator", "empty or too long value"))
        return
    if ioc_type == "ip":
        try:
            ipaddress.ip_address(value)
        except ValueError:
            out.skipped.append(Skipped(sid, "indicator", f"'{value[:40]}' is not a valid IP address"))
            return
    if ioc_type in _NORMALISED:
        value = value.lower()
    conf = raw.get("confidence")
    confidence = None
    if isinstance(conf, int | float) and not isinstance(conf, bool) and 0 <= conf <= 100:
        confidence = conf / 100
    out.indicators.append(ParsedIndicator(sid, ioc_type, value, confidence))
