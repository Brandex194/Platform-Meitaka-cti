"""STIX patterns, export and parsing (pure code, no database)."""
import json
import uuid
from datetime import UTC, datetime

import pytest

from app.db.models import Campaign, Indicator, ThreatActor
from app.stix.export import build_bundle
from app.stix.parse import MAX_OBJECTS, BundleError, parse_bundle
from app.stix.patterns import PatternError, from_pattern, to_pattern

SHA256 = "a" * 64


@pytest.mark.parametrize(
    ("ioc_type", "value", "expected"),
    [
        ("ip", "203.0.113.5", "[ipv4-addr:value = '203.0.113.5']"),
        ("ip", "2001:db8::1", "[ipv6-addr:value = '2001:db8::1']"),
        ("domain", "evil.example", "[domain-name:value = 'evil.example']"),
        ("url", "http://x.test/a?b=1", "[url:value = 'http://x.test/a?b=1']"),
        ("email", "a@b.test", "[email-addr:value = 'a@b.test']"),
        ("hash", "d" * 32, f"[file:hashes.'MD5' = '{'d' * 32}']"),
        ("hash", "d" * 40, f"[file:hashes.'SHA-1' = '{'d' * 40}']"),
        ("hash", SHA256, f"[file:hashes.'SHA-256' = '{SHA256}']"),
    ],
)
def test_pattern_round_trip(ioc_type, value, expected):
    assert to_pattern(ioc_type, value) == expected
    assert from_pattern(expected) == (ioc_type, value)


def test_pattern_cannot_be_written():
    assert to_pattern("ip", "not-an-ip") is None
    assert to_pattern("hash", "abc") is None
    assert to_pattern("mutex", "x") is None


def test_quotes_and_backslashes_are_escaped_and_restored():
    value = "http://x.test/it's\\ok"
    pattern = to_pattern("url", value)
    assert "\\'" in pattern and "\\\\" in pattern
    assert from_pattern(pattern) == ("url", value)


def test_injection_in_value_cannot_widen_the_pattern():
    """A value with a quote must stay inside one comparison, never become `AND ...`."""
    pattern = to_pattern("domain", "a' OR [url:value = 'b")
    assert from_pattern(pattern) == ("domain", "a' OR [url:value = 'b")


@pytest.mark.parametrize(
    "pattern",
    [
        "[ipv4-addr:value = '1.1.1.1' AND domain-name:value = 'x.test']",
        "[ipv4-addr:value = '1.1.1.1'] OR [domain-name:value = 'x.test']",
        "[ipv4-addr:value = '1.1.1.1'] FOLLOWEDBY [url:value = 'http://a']",
        "[ipv4-addr:value LIKE '1.%']",
        "[ipv4-addr:value IN ('1.1.1.1')]",
        "[process:name = 'cmd.exe']",
        "[file:hashes.'SSDEEP' = 'abc']",
        "",
        "not a pattern",
    ],
)
def test_unsupported_patterns_are_refused(pattern):
    with pytest.raises(PatternError):
        from_pattern(pattern)


def _bundle(*objs):
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": list(objs)}


def _ind(pattern, **extra):
    return {"type": "indicator", "id": f"indicator--{uuid.uuid4()}", "pattern": pattern, "pattern_type": "stix", **extra}


def test_export_shapes_and_ids():
    now = datetime(2026, 11, 9, 10, 0, 0, 123000, tzinfo=UTC)
    actor = ThreatActor(id=uuid.uuid4(), name="APT-X", aliases=["X1", "X2"], description="d", created_at=now)
    camp = Campaign(id=uuid.uuid4(), name="Op Y", threat_actor_id=actor.id, created_at=now)
    ind = Indicator(id=uuid.uuid4(), ioc_type="domain", value="evil.example", confidence=0.85, created_at=now)
    bad = Indicator(id=uuid.uuid4(), ioc_type="hash", value="xyz", created_at=now)
    bundle, notes = build_bundle([ind, bad], [actor], [camp])
    assert bundle["type"] == "bundle" and bundle["id"].startswith("bundle--")
    by_type = {o["type"]: o for o in bundle["objects"]}
    assert set(by_type) == {"threat-actor", "campaign", "relationship", "indicator"}
    i = by_type["indicator"]
    assert i["id"] == f"indicator--{ind.id}" and i["spec_version"] == "2.1"
    assert i["confidence"] == 85 and i["valid_from"] == "2026-11-09T10:00:00.123Z"
    assert i["pattern"] == "[domain-name:value = 'evil.example']"
    rel = by_type["relationship"]
    assert rel["source_ref"] == f"campaign--{camp.id}" and rel["target_ref"] == f"threat-actor--{actor.id}"
    assert by_type["threat-actor"]["aliases"] == ["X1", "X2"]
    assert len(notes) == 1 and "xyz" in notes[0]
    json.dumps(bundle)  # serialisable


def test_export_relationship_ids_are_stable():
    actor = ThreatActor(id=uuid.uuid4(), name="A")
    camp = Campaign(id=uuid.uuid4(), name="C", threat_actor_id=actor.id)
    first = [o for o in build_bundle([], [actor], [camp])[0]["objects"] if o["type"] == "relationship"][0]["id"]
    second = [o for o in build_bundle([], [actor], [camp])[0]["objects"] if o["type"] == "relationship"][0]["id"]
    assert first == second


def test_export_omits_attribution_when_actor_not_in_bundle():
    camp = Campaign(id=uuid.uuid4(), name="C", threat_actor_id=uuid.uuid4())
    objs = build_bundle([], [], [camp])[0]["objects"]
    assert [o["type"] for o in objs] == ["campaign"]


def test_parse_collects_supported_objects():
    aid, cid = f"threat-actor--{uuid.uuid4()}", f"campaign--{uuid.uuid4()}"
    b = _bundle(
        _ind("[domain-name:value = 'Evil.Example']", confidence=70),
        _ind("[ipv4-addr:value = '203.0.113.9']"),
        {"type": "threat-actor", "id": aid, "name": " APT-X ", "aliases": ["a", 3, " "]},
        {"type": "campaign", "id": cid, "name": "Op Y"},
        {"type": "relationship", "id": f"relationship--{uuid.uuid4()}", "relationship_type": "attributed-to",
         "source_ref": cid, "target_ref": aid},
    )
    p = parse_bundle(b)
    assert [(i.ioc_type, i.value, i.confidence) for i in p.indicators] == [
        ("domain", "evil.example", 0.7), ("ip", "203.0.113.9", None)]
    assert p.actors[0].name == "APT-X" and p.actors[0].aliases == ["a"]
    assert p.attributions == {cid: aid} and p.skipped == []


def test_parse_skips_with_reasons():
    rev = _ind("[ipv4-addr:value = '1.2.3.4']", revoked=True)
    objs = [
        rev,
        _ind("[ipv4-addr:value = '999.1.1.1']"),
        _ind("[ipv4-addr:value = '1.1.1.1' AND url:value = 'http://a']"),
        _ind("[ipv4-addr:value = '1.1.1.1']", pattern_type="sigma"),
        {"type": "malware", "id": f"malware--{uuid.uuid4()}", "name": "m"},
        {"type": "threat-actor", "id": f"threat-actor--{uuid.uuid4()}"},
        {"type": "indicator", "id": "indicator--not-a-uuid", "pattern": "[url:value = 'http://a']"},
        {"type": "relationship", "id": f"relationship--{uuid.uuid4()}", "relationship_type": "uses",
         "source_ref": "a--b", "target_ref": "c--d"},
        "garbage",
    ]
    reasons = [s.reason for s in parse_bundle(_bundle(*objs)).skipped]
    assert len(reasons) == len(objs)
    assert "revoked" in reasons[0] and "not a valid IP" in reasons[1]
    assert any("single comparison" in r for r in reasons)
    assert any("not supported yet" in r for r in reasons) and "missing name" in reasons
    assert "invalid id" in reasons and "not an object" in reasons


@pytest.mark.parametrize("doc", [None, [], "x", {"type": "indicator"}, {"type": "bundle", "objects": "no"}])
def test_not_a_bundle(doc):
    with pytest.raises(BundleError):
        parse_bundle(doc)


def test_empty_bundle_is_fine_and_limit_enforced():
    assert parse_bundle({"type": "bundle"}).indicators == []
    big = _bundle(*[{"type": "malware", "id": f"malware--{uuid.uuid4()}"} for _ in range(MAX_OBJECTS + 1)])
    with pytest.raises(BundleError):
        parse_bundle(big)


def test_confidence_out_of_range_or_bool_is_ignored():
    for conf in (150, -1, True, "high"):
        p = parse_bundle(_bundle(_ind("[ipv4-addr:value = '1.1.1.1']", confidence=conf)))
        assert p.indicators[0].confidence is None
