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

    run_for_tenant(tenant.id, db=db_session)
    scores = db_session.execute(
        select(Score).where(Score.tenant_id == tenant.id, Score.asset_id == asset.id)
    ).scalars().all()
    # After full resolve, a Score(0.0) must exist for this asset
    assert any(s.value == 0.0 for s in scores)
