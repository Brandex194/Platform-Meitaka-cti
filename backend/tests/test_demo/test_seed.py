from sqlalchemy import func, select

from app.db.models import Asset, Case, CorrelationEvent, Identity, Leak, Score, Vulnerability
from app.demo.seed import load_demo, remove_demo


def _count(db, model, tenant):
    return db.execute(select(func.count()).select_from(model).where(model.tenant_id == tenant.id)).scalar_one()


def test_load_builds_findings_and_scores_through_the_real_engines(db_session, tenant):
    out = load_demo(db_session, tenant.id)
    assert out["assets"] == 8 and out["findings"] > 5
    rules = {r for (r,) in db_session.execute(select(CorrelationEvent.rule_name).distinct())}
    assert {"vuln_software", "ioc_asset", "leak_identity"} <= rules
    levels = {lv for (lv,) in db_session.execute(select(Score.level).distinct())}
    assert {"critical", "low"} <= levels or len(levels) >= 3
    assert _count(db_session, Case, tenant) == 5


def test_load_twice_does_nothing_the_second_time(db_session, tenant):
    load_demo(db_session, tenant.id)
    n = _count(db_session, Asset, tenant)
    assert "skipped" in load_demo(db_session, tenant.id)
    assert _count(db_session, Asset, tenant) == n


def test_remove_deletes_only_demo_rows(db_session, tenant, asset):
    db_session.add(Identity(tenant_id=tenant.id, email="real.person@company.test", name="Real"))
    db_session.add(Leak(tenant_id=tenant.id, email_hash="c" * 64, breach_name="Real breach"))
    db_session.add(Vulnerability(cve_id="CVE-2021-0001", cvss_score=5.0))
    db_session.flush()
    load_demo(db_session, tenant.id)
    remove_demo(db_session, tenant.id)
    assert [a.hostname for a in db_session.execute(select(Asset)).scalars()] == ["test-host"]
    assert _count(db_session, Identity, tenant) == 1
    assert _count(db_session, Leak, tenant) == 1
    assert db_session.execute(select(func.count()).select_from(Vulnerability)).scalar_one() == 1
    assert _count(db_session, Case, tenant) == 0
    assert _count(db_session, CorrelationEvent, tenant) == 0


def test_reset_gives_the_same_amount_of_data(db_session, tenant):
    load_demo(db_session, tenant.id)
    first = _count(db_session, CorrelationEvent, tenant)
    remove_demo(db_session, tenant.id)
    load_demo(db_session, tenant.id)
    assert _count(db_session, CorrelationEvent, tenant) == first


def test_event_contexts_stay_between_zero_and_one(db_session, tenant):
    load_demo(db_session, tenant.id)
    values = [v for (v,) in db_session.execute(select(CorrelationEvent.s_context)) if v is not None]
    assert values and all(0 <= v <= 1 for v in values)
