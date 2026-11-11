"""Risk engine: compute per-asset scores and alert on threshold crossings."""
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import (
    Asset,
    CorrelationEvent,
    KevCatalog,
    Score,
    ScoreRule,
    Vulnerability,
)
from app.risk.formulas import (
    DEFAULT_THRESHOLDS,
    KNOWN_FORMULAS,
    WEIGHTS_BY_FORMULA,
    aggregate,
    alpha,
    apply_kev_floor,
    exposure_factor,
    f_confidence,
    f_recency,
    f_severity,
    impact_factor,
    level_from_score,
    merged_parameters,
    s_base,
)

logger = logging.getLogger(__name__)


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


def _is_current(rule: ScoreRule) -> bool:
    """Rules written for the pre-09/11/2026 formula have no `parameters.formula`: never apply them
    to the §5 formula, their weights mean something else."""
    return (rule.parameters or {}).get("formula") in KNOWN_FORMULAS


def _active_rule(tenant_id, db: Session) -> Optional[ScoreRule]:
    """Highest-version §5 rule of the tenant, else the highest-version global one, else None (defaults)."""
    for scope in (ScoreRule.tenant_id == tenant_id, ScoreRule.tenant_id.is_(None)):
        for rule in db.query(ScoreRule).filter(scope).order_by(ScoreRule.version.desc()).all():
            if _is_current(rule):
                return rule
    return None


def asset_breakdown(asset, asset_events, vuln_map, kev_cve_ids, params, weights, now) -> dict:
    """Everything that makes up one asset's score, finding by finding.

    This is the single place the score is computed: `_compute` stores `total`, and the explanation
    endpoint returns the whole structure, so what is explained is exactly what is stored.
    """
    exposure_value = asset.exposure if asset else None
    impact_value = asset.impact if asset else None
    e_factor = exposure_factor(exposure_value, params)
    i_factor = impact_factor(impact_value, params)
    context = e_factor * i_factor

    findings = []
    for e in asset_events:
        vuln = vuln_map.get(e.vulnerability_id) if e.vulnerability_id else None
        in_kev = bool(vuln and vuln.cve_id in kev_cve_ids)
        sev = f_severity(vuln.cvss_score if vuln else None, params)
        conf = f_confidence(e.s_context, in_kev, params)
        rec = f_recency(e.created_at, params, now)
        base = s_base(sev, conf, rec, vuln.epss_score if vuln else None, weights, params["formula"])
        in_context = base * context
        floored = apply_kev_floor(in_context, in_kev, params)
        a = alpha(e.rule_name, params)
        findings.append({
            "event_id": e.id,
            "rule_name": e.rule_name,
            "cve_id": vuln.cve_id if vuln else None,
            "cvss": vuln.cvss_score if vuln else None,
            "epss": vuln.epss_score if vuln else None,
            "in_kev": in_kev,
            "f_severity": sev,
            "f_confidence": conf,
            "f_recency": rec,
            "s_base": base,
            "s_context": in_context,
            "kev_floor_applied": floored > in_context,
            "alpha": a,
            "contribution": floored * a,
        })

    findings.sort(key=lambda f: f["contribution"], reverse=True)
    decay = params.get("aggregation_decay")
    for rank, f in enumerate(findings):
        f["rank"] = rank
        f["weight"] = decay**rank if decay else 1.0
        f["counted"] = f["contribution"] * f["weight"]
    total = aggregate([f["contribution"] for f in findings], params)
    return {
        "exposure": exposure_value,
        "exposure_factor": e_factor,
        "impact": impact_value,
        "impact_factor": i_factor,
        "context_factor": context,
        "findings": findings,
        "aggregation": "decay" if decay else "sum",
        "decay": decay,
        "raw_sum": sum(f["counted"] for f in findings),
        "total": total,
    }


def resolve_rule(tenant_id, db: Session):
    """(rule or None, params, weights, thresholds) the engine would use for this tenant now."""
    rule = _active_rule(tenant_id, db)
    params = merged_parameters(rule.parameters if rule else None)
    weights = (rule.weights if rule else None) or WEIGHTS_BY_FORMULA[params["formula"]]
    thresholds = (rule.thresholds if rule else None) or DEFAULT_THRESHOLDS
    return rule, params, weights, thresholds


def explain_asset(tenant_id, asset_id, db: Session) -> dict | None:
    """Read-only breakdown of one asset's score with the rule the engine would use right now."""
    asset = db.execute(
        select(Asset).where(Asset.id == asset_id, Asset.tenant_id == tenant_id)
    ).scalar_one_or_none()
    if asset is None:
        return None
    rule, params, weights, thresholds = resolve_rule(tenant_id, db)
    events = db.execute(
        select(CorrelationEvent).where(
            CorrelationEvent.tenant_id == tenant_id,
            CorrelationEvent.asset_id == asset_id,
            CorrelationEvent.is_active == True,  # noqa: E712
        )
    ).scalars().all()
    kev_cve_ids = {row.cve_id for row in db.execute(select(KevCatalog)).scalars().all()}
    vuln_ids = {e.vulnerability_id for e in events if e.vulnerability_id}
    vuln_map = {}
    if vuln_ids:
        vuln_map = {
            v.id: v
            for v in db.execute(select(Vulnerability).where(Vulnerability.id.in_(vuln_ids))).scalars().all()
        }
    b = asset_breakdown(asset, events, vuln_map, kev_cve_ids, params, weights, datetime.now(timezone.utc))
    b.update({
        "asset_id": asset.id,
        "hostname": asset.hostname,
        "ip": asset.ip,
        "formula": params["formula"],
        "rule_id": rule.id if rule else None,
        "rule_version": rule.version if rule else None,
        "kev_floor": params.get("kev_floor"),
        "thresholds": {**DEFAULT_THRESHOLDS, **(thresholds or {})},
        "level": level_from_score(b["total"], thresholds),
    })
    return b


def _compute(tenant_id, db: Session) -> dict:
    rule, params, weights, thresholds = resolve_rule(tenant_id, db)

    events = db.execute(
        select(CorrelationEvent).where(
            CorrelationEvent.tenant_id == tenant_id,
            CorrelationEvent.is_active == True,
        )
    ).scalars().all()

    kev_cve_ids = {row.cve_id for row in db.execute(select(KevCatalog)).scalars().all()}

    prev_scores: dict = {}
    for s in db.execute(select(Score).where(Score.tenant_id == tenant_id, Score.score_type == "asset")).scalars().all():
        if s.asset_id not in prev_scores or s.computed_at > prev_scores[s.asset_id].computed_at:
            prev_scores[s.asset_id] = s

    vuln_ids = {e.vulnerability_id for e in events if e.vulnerability_id}
    vuln_map: dict = {}
    if vuln_ids:
        for v in db.execute(select(Vulnerability).where(Vulnerability.id.in_(vuln_ids))).scalars().all():
            vuln_map[v.id] = v

    asset_ids = {e.asset_id for e in events if e.asset_id}
    asset_map: dict = {}
    if asset_ids:
        for a in db.execute(
            select(Asset).where(Asset.id.in_(asset_ids), Asset.tenant_id == tenant_id)
        ).scalars().all():
            asset_map[a.id] = a

    by_asset: dict = {}
    for e in events:
        by_asset.setdefault(e.asset_id, []).append(e)

    count = 0
    now = datetime.now(timezone.utc)
    rule_id = rule.id if rule else None
    rule_version = rule.version if rule else None

    for asset_id, asset_events in by_asset.items():
        asset = asset_map.get(asset_id)
        total = asset_breakdown(asset, asset_events, vuln_map, kev_cve_ids, params, weights, now)["total"]

        old_val = prev_scores[asset_id].value if asset_id in prev_scores else None
        db.add(Score(
            tenant_id=tenant_id,
            asset_id=asset_id,
            score_type="asset",
            value=total,
            level=level_from_score(total, thresholds),
            computed_at=now,
            score_rule_id=rule_id,
            score_rule_version=rule_version,
        ))
        count += 1
        check_and_notify(tenant_id, asset_id, old_val, total, db)

    # Assets with prior scores but no active events now → Score(0.0), once.
    active_asset_ids = set(by_asset.keys())
    for asset_id, prev in prev_scores.items():
        if asset_id not in active_asset_ids:
            if prev.value == 0.0:
                continue
            db.add(Score(
                tenant_id=tenant_id,
                asset_id=asset_id,
                score_type="asset",
                value=0.0,
                level=level_from_score(0.0, thresholds),
                computed_at=now,
                score_rule_id=rule_id,
                score_rule_version=rule_version,
            ))
            count += 1
            check_and_notify(tenant_id, asset_id, prev.value, 0.0, db)

    db.flush()
    return {"tenant_id": str(tenant_id), "scores_computed": count}
