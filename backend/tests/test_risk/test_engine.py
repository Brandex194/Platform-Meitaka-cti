"""Integration tests for risk engine — uses in-memory SQLite via conftest fixtures."""
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.db.models import Asset, CorrelationEvent, Score


def test_run_for_tenant_empty(db_session, tenant):
    from app.risk.engine import run_for_tenant

    result = run_for_tenant(tenant.id, db=db_session)
    assert result == {"tenant_id": str(tenant.id), "scores_computed": 0}


def test_run_for_tenant_creates_score(db_session, tenant, asset):
    from app.risk.engine import run_for_tenant

    e = CorrelationEvent(
        tenant_id=tenant.id,
        asset_id=asset.id,
        rule_name="test_vuln",
        s_context=0.8,
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(e)
    db_session.flush()

    result = run_for_tenant(tenant.id, db=db_session)

    assert result["scores_computed"] == 1
    score = db_session.execute(
        select(Score).where(Score.tenant_id == tenant.id, Score.asset_id == asset.id)
    ).scalar_one()
    assert score.value > 0


def test_score_decreases_after_resolve(db_session, tenant, asset):
    from app.risk.engine import run_for_tenant

    e1 = CorrelationEvent(
        tenant_id=tenant.id, asset_id=asset.id, rule_name="r1",
        s_context=0.9, is_active=True, created_at=datetime.now(timezone.utc),
    )
    e2 = CorrelationEvent(
        tenant_id=tenant.id, asset_id=asset.id, rule_name="r2",
        s_context=0.9, is_active=True, created_at=datetime.now(timezone.utc),
    )
    db_session.add_all([e1, e2])
    db_session.flush()

    run_for_tenant(tenant.id, db=db_session)
    before = db_session.execute(
        select(Score)
        .where(Score.tenant_id == tenant.id, Score.asset_id == asset.id)
        .order_by(Score.computed_at.desc())
        .limit(1)
    ).scalar_one().value

    e1.is_active = False
    db_session.flush()

    run_for_tenant(tenant.id, db=db_session)
    after = db_session.execute(
        select(Score)
        .where(Score.tenant_id == tenant.id, Score.asset_id == asset.id)
        .order_by(Score.computed_at.desc())
        .limit(1)
    ).scalar_one().value

    assert after < before


def test_fully_resolved_asset_gets_zero_score(db_session, tenant, asset):
    from app.risk.engine import run_for_tenant

    e = CorrelationEvent(
        tenant_id=tenant.id, asset_id=asset.id, rule_name="r1",
        s_context=0.9, is_active=True, created_at=datetime.now(timezone.utc),
    )
    db_session.add(e)
    db_session.flush()

    run_for_tenant(tenant.id, db=db_session)

    e.is_active = False
    db_session.flush()

    run_for_tenant(tenant.id, db=db_session)  # run 2: inserts Score(0.0)
    scores = db_session.execute(
        select(Score).where(Score.tenant_id == tenant.id, Score.asset_id == asset.id)
    ).scalars().all()
    assert any(s.value == 0.0 for s in scores)
    assert len(scores) == 2  # run 1 (active) + run 2 (resolved)

    run_for_tenant(tenant.id, db=db_session)  # run 3: must NOT insert again
    scores = db_session.execute(
        select(Score).where(Score.tenant_id == tenant.id, Score.asset_id == asset.id)
    ).scalars().all()
    assert len(scores) == 2  # still 2 — no unbounded growth


# --- Architettura §5 engine behaviour (passo 4, 09/11/2026) -------------------------------------


def _vuln_event(db_session, tenant, asset, cvss, cve_id, conf=0.9):
    from app.db.models import Vulnerability

    v = Vulnerability(cve_id=cve_id, cvss_score=cvss)
    db_session.add(v)
    db_session.flush()
    e = CorrelationEvent(
        tenant_id=tenant.id, asset_id=asset.id, rule_name="vuln_software", vulnerability_id=v.id,
        s_context=conf, is_active=True, created_at=datetime.now(timezone.utc),
    )
    db_session.add(e)
    db_session.flush()
    return v


def _latest(db_session, tenant, asset):
    return db_session.execute(
        select(Score).where(Score.tenant_id == tenant.id, Score.asset_id == asset.id)
        .order_by(Score.computed_at.desc()).limit(1)
    ).scalar_one()


def test_context_of_the_asset_scales_the_score(db_session, tenant):
    from app.risk.engine import run_for_tenant

    exposed = Asset(tenant_id=tenant.id, hostname="web", exposure="internet", impact="critical")
    internal = Asset(tenant_id=tenant.id, hostname="lab", exposure="internal", impact="low")
    db_session.add_all([exposed, internal])
    db_session.flush()
    _vuln_event(db_session, tenant, exposed, 9.8, "CVE-2099-0001")
    _vuln_event(db_session, tenant, internal, 9.8, "CVE-2099-0002")

    run_for_tenant(tenant.id, db=db_session)

    # multiplicative default: S_base = 0.98 × (0.3×0.9 + 0.3×1.0 + 0.4×0) = 0.5586
    assert _latest(db_session, tenant, exposed).value == pytest.approx(0.5586)
    assert _latest(db_session, tenant, exposed).level == "high"
    assert _latest(db_session, tenant, internal).value == pytest.approx(0.5586 * 0.3 * 0.4)
    assert _latest(db_session, tenant, internal).level == "low"


def test_kev_raises_confidence_to_1(db_session, tenant, asset):
    from app.db.models import KevCatalog
    from app.risk.engine import run_for_tenant

    _vuln_event(db_session, tenant, asset, 5.0, "CVE-2099-0003", conf=0.5)
    db_session.add(KevCatalog(cve_id="CVE-2099-0003"))
    db_session.flush()

    run_for_tenant(tenant.id, db=db_session)
    # unclassified asset → default factors 1.0; 0.5 × (0.3×1.0 + 0.3×1.0)
    assert _latest(db_session, tenant, asset).value == pytest.approx(0.3)


def test_score_is_capped_and_records_the_rule(db_session, tenant, asset):
    from app.db.models import ScoreRule
    from app.risk.engine import run_for_tenant

    rule = ScoreRule(tenant_id=None, version=7, parameters={"formula": "architettura-5"})
    db_session.add(rule)
    db_session.flush()
    for i in range(4):
        _vuln_event(db_session, tenant, asset, 9.0, f"CVE-2099-01{i}")

    run_for_tenant(tenant.id, db=db_session)
    score = _latest(db_session, tenant, asset)
    assert score.value == 1.0
    assert (score.score_rule_id, score.score_rule_version) == (rule.id, 7)


def test_legacy_rule_without_formula_is_ignored(db_session, tenant, asset):
    """A rule written for the old formula (weights 0.45/0.27/0.18/0.10) must not drive §5."""
    from app.db.models import ScoreRule
    from app.risk.engine import run_for_tenant

    legacy = ScoreRule(tenant_id=tenant.id, version=3,
                       weights={"severity": 0.1, "confidence": 0.1, "recency": 0.1, "epss": 0.7})
    db_session.add(legacy)
    db_session.flush()
    _vuln_event(db_session, tenant, asset, 6.0, "CVE-2099-0200", conf=0.9)

    run_for_tenant(tenant.id, db=db_session)
    score = _latest(db_session, tenant, asset)
    assert score.value == pytest.approx(0.6 * (0.3 * 0.9 + 0.3))  # code defaults, multiplicative
    assert score.score_rule_id is None


def test_additive_rule_still_applies(db_session, tenant, asset):
    """A rule pinned to the passo-4 formula keeps computing it, with its own defaults."""
    from app.db.models import ScoreRule
    from app.risk.engine import run_for_tenant

    db_session.add(ScoreRule(tenant_id=tenant.id, version=1,
                             weights={"severity": 0.5, "confidence": 0.3, "recency": 0.2, "epss": 0.0},
                             parameters={"formula": "architettura-5"}))
    asset.exposure, asset.impact = "dmz", "business"
    db_session.flush()
    _vuln_event(db_session, tenant, asset, 6.0, "CVE-2099-0400", conf=0.9)

    run_for_tenant(tenant.id, db=db_session)
    assert _latest(db_session, tenant, asset).value == pytest.approx((0.3 + 0.27 + 0.2) * 0.5 * 0.6)


def test_tenant_rule_overrides_default_context(db_session, tenant, asset):
    from app.db.models import ScoreRule
    from app.risk.engine import run_for_tenant

    db_session.add(ScoreRule(tenant_id=tenant.id, version=1,
                             parameters={"formula": "architettura-5", "default_exposure": 0.5, "default_impact": 0.6}))
    db_session.flush()
    _vuln_event(db_session, tenant, asset, 6.0, "CVE-2099-0300", conf=0.9)

    run_for_tenant(tenant.id, db=db_session)
    assert _latest(db_session, tenant, asset).value == pytest.approx((0.3 + 0.27 + 0.2) * 0.3)


def test_v3_scenario_6_kev_on_internal_low_asset_is_medium(db_session, tenant):
    from app.db.models import KevCatalog
    from app.risk.engine import run_for_tenant

    lab = Asset(tenant_id=tenant.id, hostname="lab", exposure="internal", impact="low")
    db_session.add(lab)
    db_session.flush()
    _vuln_event(db_session, tenant, lab, 9.8, "CVE-2099-0600")
    db_session.add(KevCatalog(cve_id="CVE-2099-0600"))
    db_session.flush()

    run_for_tenant(tenant.id, db=db_session)
    score = _latest(db_session, tenant, lab)
    assert score.value == pytest.approx(0.25) and score.level == "medium"


def test_v3_scenario_5_many_medium_findings_stay_high(db_session, tenant):
    from app.risk.engine import run_for_tenant

    web = Asset(tenant_id=tenant.id, hostname="web", exposure="internet", impact="critical")
    db_session.add(web)
    db_session.flush()
    for i in range(5):
        _vuln_event(db_session, tenant, web, 5.0, f"CVE-2099-05{i}", conf=0.9)

    run_for_tenant(tenant.id, db=db_session)
    score = _latest(db_session, tenant, web)
    assert score.level == "high" and score.value < 0.7


def test_rule_on_the_older_formula_keeps_the_plain_sum_and_no_floor(db_session, tenant):
    from app.db.models import KevCatalog, ScoreRule
    from app.risk.engine import run_for_tenant

    db_session.add(ScoreRule(tenant_id=tenant.id, version=3, parameters={"formula": "architettura-5-moltiplicativa"}))
    lab = Asset(tenant_id=tenant.id, hostname="lab", exposure="internal", impact="low")
    db_session.add(lab)
    db_session.flush()
    _vuln_event(db_session, tenant, lab, 9.8, "CVE-2099-0700")
    db_session.add(KevCatalog(cve_id="CVE-2099-0700"))
    db_session.flush()

    run_for_tenant(tenant.id, db=db_session)
    assert _latest(db_session, tenant, lab).level == "low"  # no KEV floor under the older formula


def test_explanation_total_equals_the_stored_score(db_session, tenant, asset):
    from app.risk.engine import explain_asset, run_for_tenant

    for i, ctx in enumerate((0.9, 0.6, 0.3)):
        db_session.add(CorrelationEvent(
            tenant_id=tenant.id, asset_id=asset.id, rule_name="vuln_software",
            s_context=ctx, is_active=True, created_at=datetime.now(timezone.utc),
        ))
    db_session.flush()
    run_for_tenant(tenant.id, db=db_session)
    stored = db_session.execute(
        select(Score).where(Score.tenant_id == tenant.id, Score.asset_id == asset.id)
    ).scalar_one()

    out = explain_asset(tenant.id, asset.id, db_session)
    assert out["total"] == pytest.approx(stored.value)
    assert out["level"] == stored.level
    assert [f["rank"] for f in out["findings"]] == [0, 1, 2]
    contributions = [f["contribution"] for f in out["findings"]]
    assert contributions == sorted(contributions, reverse=True)
    assert out["raw_sum"] == pytest.approx(sum(f["counted"] for f in out["findings"]))
    assert out["total"] == pytest.approx(min(1.0, out["raw_sum"]))


def test_explanation_of_unknown_asset_is_none(db_session, tenant):
    import uuid

    from app.risk.engine import explain_asset

    assert explain_asset(tenant.id, uuid.uuid4(), db_session) is None
