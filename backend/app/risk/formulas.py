"""Risk scoring formulas for Sentinel AI CTI."""
from datetime import datetime, timezone
from typing import Optional

DEFAULT_WEIGHTS = {"severity": 0.45, "confidence": 0.27, "recency": 0.18, "epss": 0.10}

_DEFAULT_THRESHOLDS = {"high": 0.7, "medium": 0.4}


def f_severity(event, kev_ids: set, vuln_score: Optional[float]) -> float:
    """1.0 if vulnerability is in KEV (kev_ids = set of vuln UUID strings), else cvss/10 or 0.5."""
    if event.vulnerability_id and str(event.vulnerability_id) in kev_ids:
        return 1.0
    return vuln_score / 10.0 if vuln_score is not None else 0.5


def f_confidence(event) -> float:
    return float(event.s_context) if event.s_context is not None else 0.5


def f_recency(event) -> float:
    """Decays linearly from 1.0 to 0.0 over 90 days."""
    if not event.created_at:
        return 0.5
    now = datetime.now(timezone.utc)
    ca = event.created_at
    if ca.tzinfo is None:
        ca = ca.replace(tzinfo=timezone.utc)  # SQLite returns naive UTC
    age_days = (now - ca).days
    return min(1.0, max(0.0, 1.0 - age_days / 90.0))


def epss_boost(score: Optional[float]) -> float:
    return 0.0 if score is None else min(score * 2.0, 0.3)


def s_base(
    event,
    kev_ids: set,
    vuln_epss: Optional[float],
    vuln_score: Optional[float],
    weights: dict,
) -> float:
    w = weights or DEFAULT_WEIGHTS
    sev = f_severity(event, kev_ids, vuln_score)
    conf = f_confidence(event)
    rec = f_recency(event)
    boost = epss_boost(vuln_epss)
    return (
        sev * w["severity"]
        + conf * w["confidence"]
        + rec * w["recency"]
        + boost * w["epss"]
    )


def level_from_score(value: float, thresholds: dict) -> str:
    t = thresholds or _DEFAULT_THRESHOLDS
    if value >= 0.9:
        return "critical"
    if value >= t.get("high", 0.7):
        return "high"
    if value >= t.get("medium", 0.4):
        return "medium"
    return "low"
