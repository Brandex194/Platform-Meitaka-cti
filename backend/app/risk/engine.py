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
        session.flush()
    except Exception:
        session.rollback()
        try:
            next(gen)
        except Exception:
            pass
        raise
    try:
        next(gen)  # commit — StopIteration is normal
    except StopIteration:
        pass
    return result


def _compute(tenant_id, db: Session) -> dict:
    # 1. Active ScoreRule: prefer tenant-specific (highest version), fall back to global
    rule = (
        db.query(ScoreRule)
        .filter(ScoreRule.tenant_id == tenant_id)
        .order_by(ScoreRule.version.desc())
        .first()
    )
    if not rule:
        rule = (
            db.query(ScoreRule)
            .filter(ScoreRule.tenant_id.is_(None))
            .order_by(ScoreRule.version.desc())
            .first()
        )
    weights = rule.weights if rule else DEFAULT_WEIGHTS
    thresholds = rule.thresholds if rule else _DEFAULT_THRESHOLDS

    # 2. Active CorrelationEvents
    events = db.execute(
        select(CorrelationEvent).where(
            CorrelationEvent.tenant_id == tenant_id,
            CorrelationEvent.is_active == True,
        )
    ).scalars().all()

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

    # 4. Previous scores (for change detection and fully-resolved asset handling)
    prev_scores: dict = {}
    for s in db.execute(select(Score).where(Score.tenant_id == tenant_id, Score.score_type == "asset")).scalars().all():
        # Keep only the most recent per asset
        if s.asset_id not in prev_scores or s.computed_at > prev_scores[s.asset_id].computed_at:
            prev_scores[s.asset_id] = s

    # 5. Bulk-load all referenced vulnerabilities (Fix 2: per-event lookup via map)
    vuln_ids = {e.vulnerability_id for e in events if e.vulnerability_id}
    vuln_map: dict = {}
    if vuln_ids:
        for v in db.execute(select(Vulnerability).where(Vulnerability.id.in_(vuln_ids))).scalars().all():
            vuln_map[v.id] = v

    # 6. Group active events by asset, score each event against its own vulnerability
    by_asset: dict = {}
    for e in events:
        by_asset.setdefault(e.asset_id, []).append(e)

    count = 0
    now = datetime.now(timezone.utc)

    for asset_id, asset_events in by_asset.items():
        # Fix 2: each event uses its own vulnerability's EPSS/CVSS
        total = 0.0
        for e in asset_events:
            vuln = vuln_map.get(e.vulnerability_id) if e.vulnerability_id else None
            vuln_epss = vuln.epss_score if vuln else None
            vuln_score = vuln.cvss_score if vuln else None
            total += s_base(e, kev_vuln_ids, vuln_epss, vuln_score, weights)

        old_val = prev_scores[asset_id].value if asset_id in prev_scores else None

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

    # Fix 1: assets with prior scores but no active events now → insert Score(0.0)
    # Fix 2 (round 2): skip if already at 0.0 to avoid unbounded row growth
    active_asset_ids = set(by_asset.keys())
    for asset_id, prev in prev_scores.items():
        if asset_id not in active_asset_ids:
            if prev.value == 0.0:
                continue  # already resolved to 0.0, no re-insert
            db.add(Score(
                tenant_id=tenant_id,
                asset_id=asset_id,
                score_type="asset",
                value=0.0,
                level="low",
                computed_at=now,
            ))
            count += 1
            check_and_notify(tenant_id, asset_id, prev.value, 0.0, db)

    db.flush()
    return {"tenant_id": str(tenant_id), "scores_computed": count}
