"""Risk engine: compute per-asset scores and alert on threshold crossings."""
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import CorrelationEvent, KevCatalog, Score, ScoreRule, Vulnerability
from app.risk.formulas import DEFAULT_WEIGHTS, level_from_score, s_base

logger = logging.getLogger(__name__)

_DEFAULT_THRESHOLDS = {"high": 0.7, "medium": 0.4}


def check_and_notify(tenant_id, asset_id, old_score: Optional[float], new_score: float, db) -> None:
    # Phase 1: log only; Slack/email in Phase 3
    if new_score >= 0.7 and (old_score is None or old_score < 0.7):
        logger.warning("HIGH RISK alert: tenant=%s asset=%s score=%.3f", tenant_id, asset_id, new_score)
    elif old_score is not None and old_score >= 0.3 and new_score < 0.3:
        logger.info("RISK DECREASED: tenant=%s asset=%s score=%.3f", tenant_id, asset_id, new_score)


def run_for_tenant(tenant_id, db: Optional[Session] = None, r=None) -> dict:
    if db is not None:
        return _compute(tenant_id, db)

    from app.db.session import bypass_session  # lazy: avoids Settings() at import time

    gen = bypass_session()
    session = next(gen)
    try:
        result = _compute(tenant_id, session)
    except Exception:
        try:
            next(gen)
        except Exception:
            pass
        raise
    try:
        next(gen)
    except StopIteration:
        pass
    return result


def _compute(tenant_id, db: Session) -> dict:
    # 1. Active ScoreRule: tenant-specific wins over global (tenant_id IS NULL)
    rule = db.execute(
        select(ScoreRule)
        .where((ScoreRule.tenant_id == tenant_id) | (ScoreRule.tenant_id == None))
        .order_by(ScoreRule.version.desc())
        .limit(1)
    ).scalar_one_or_none()
    weights = rule.weights if rule else DEFAULT_WEIGHTS
    thresholds = rule.thresholds if rule else _DEFAULT_THRESHOLDS

    # 2. Active CorrelationEvents
    events = db.execute(
        select(CorrelationEvent).where(
            CorrelationEvent.tenant_id == tenant_id,
            CorrelationEvent.is_active == True,
        )
    ).scalars().all()

    if not events:
        return {"tenant_id": str(tenant_id), "scores_computed": 0}

    # 3. KEV vuln IDs: set of UUID strings for vulns whose cve_id is in KEV
    kev_cve_ids = {row.cve_id for row in db.execute(select(KevCatalog)).scalars().all()}
    kev_vuln_ids: set = set()
    if kev_cve_ids:
        kev_vuln_ids = {
            str(v)
            for v in db.execute(
                select(Vulnerability.id).where(Vulnerability.cve_id.in_(kev_cve_ids))
            ).scalars().all()
        }

    # 4. Bulk-load all referenced vulnerabilities
    vuln_ids = {e.vulnerability_id for e in events if e.vulnerability_id}
    vuln_map: dict = {}
    if vuln_ids:
        for v in db.execute(select(Vulnerability).where(Vulnerability.id.in_(vuln_ids))).scalars().all():
            vuln_map[v.id] = v

    # 5. Score each asset
    by_asset: dict = {}
    for e in events:
        by_asset.setdefault(e.asset_id, []).append(e)

    count = 0
    now = datetime.now(timezone.utc)
    for asset_id, asset_events in by_asset.items():
        vulns = [vuln_map[e.vulnerability_id] for e in asset_events if e.vulnerability_id and e.vulnerability_id in vuln_map]
        vuln_epss = max((v.epss_score for v in vulns if v.epss_score is not None), default=None)
        vuln_score = max((v.cvss_score for v in vulns if v.cvss_score is not None), default=None)

        total = sum(s_base(e, kev_vuln_ids, vuln_epss, vuln_score, weights) for e in asset_events)

        prev = db.execute(
            select(Score)
            .where(Score.tenant_id == tenant_id, Score.asset_id == asset_id, Score.score_type == "asset")
            .order_by(Score.computed_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        old_val = prev.value if prev else None

        db.add(Score(
            tenant_id=tenant_id,
            asset_id=asset_id,
            score_type="asset",
            value=total,
            level=level_from_score(total, thresholds),
            computed_at=now,
        ))
        count += 1
        check_and_notify(tenant_id, asset_id, old_val, total, db)

    db.flush()
    return {"tenant_id": str(tenant_id), "scores_computed": count}
