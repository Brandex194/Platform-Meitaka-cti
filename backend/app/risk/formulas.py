"""Risk scoring formulas — Architettura.md §5.

Two formulas, chosen by the active ScoreRule through `parameters.formula`:

- "architettura-5" (passo 4, 09/11/2026): §5.1 as originally written, terms added up.
    S_base = f_sev × w_sev + f_conf × w_conf + f_rec × w_rec (+ epss_boost × w_epss)
- "architettura-5-moltiplicativa" (passo 5, 09/11/2026, the default): severity multiplies the rest,
  so a weak CVE stays weak even when fresh. Chosen by the project owner after the tuning on 12
  scenarios (doc "Taratura dello scoring Sentinel").
    S_base = f_sev × (w_sev + f_conf × w_conf + f_rec × w_rec + epss_norm × w_epss),
    epss_norm = min(EPSS × 2, 0.3) / 0.3

- "architettura-5-moltiplicativa-v3" (passo 11, 09/11/2026, the default): same S_base as the
  multiplicative one, plus the two changes that close the open tuning scenarios 5 and 6:
    * aggregation with decreasing weights instead of a plain sum (§5.3 revised): contributions are
      sorted from the largest and the i-th counts decay^i (decay 0.5), so many medium findings
      stay "high" and only strong ones reach "critical";
    * KEV floor: a CVE in CISA KEV (exploited in the wild) contributes at least kev_floor (0.25 =
      medium) even on an internal, low-impact asset.

The two older formulas apply §5.2 and §5.3 unchanged:
  S_context(i,a) = S_base(i) × E_exposure(a) × I_impact(a)
  R_asset(a)     = min(1, Σ S_context(i,a) × α_i)

Every number below is a default: the active ScoreRule can override weights, thresholds and
any key of the parameters. Change them only with a new ScoreRule version, never in this file.
"""
from datetime import UTC, datetime

FORMULA_ADDITIVE = "architettura-5"
FORMULA_MULTIPLICATIVE = "architettura-5-moltiplicativa"
FORMULA_V3 = "architettura-5-moltiplicativa-v3"
FORMULA = FORMULA_V3  # used when no ScoreRule applies, and for new rules by default
KNOWN_FORMULAS = (FORMULA_ADDITIVE, FORMULA_MULTIPLICATIVE, FORMULA_V3)

# §5.3 level mapping, stored as the upper bound of each level: < low → low, < medium → medium,
# < high → high, otherwise critical. Same keys the ScoreRule always had.
DEFAULT_THRESHOLDS = {"low": 0.2, "medium": 0.4, "high": 0.7}

_COMMON_PARAMETERS: dict = {
    # Asset not classified yet: assume the worst case, so nothing is under-reported.
    "default_exposure": 1.0,
    "default_impact": 1.0,
    # §5.3 domain weights α, by correlation rule name
    "alpha": {
        "vuln_software": 1.0,
        "leak_identity": 0.8,
        "ioc_asset": 0.5,
        "phishing_brand": 0.4,
        "default": 0.2,
    },
    # §5.1 f_recency steps: < 7 days → 1.0, 7–30 days → 0.5, > 30 days → 0.2
    "recency_steps": [[7, 1.0], [30, 0.5]],
    "recency_floor": 0.2,
    # §5.1 f_confidence 1.0 = "confermata in incidenti reali": a CVE in CISA KEV.
    "kev_confidence": 1.0,
    # §5.1 f_severity for IoC/leak/phishing without a rating: Media.
    "default_severity": 0.6,
}

WEIGHTS_BY_FORMULA = {
    # §5.1 as written; `epss` at 0 keeps the 4-weights-sum-to-1 schema.
    FORMULA_ADDITIVE: {"severity": 0.5, "confidence": 0.3, "recency": 0.2, "epss": 0.0},
    FORMULA_MULTIPLICATIVE: {"severity": 0.0, "confidence": 0.3, "recency": 0.3, "epss": 0.4},
    FORMULA_V3: {"severity": 0.0, "confidence": 0.3, "recency": 0.3, "epss": 0.4},
}

PARAMETERS_BY_FORMULA = {
    FORMULA_ADDITIVE: {
        **_COMMON_PARAMETERS,
        "exposure": {"internal": 0.2, "dmz": 0.5, "internet": 1.0},
        "impact": {"low": 0.3, "business": 0.6, "critical": 1.0},
    },
    FORMULA_MULTIPLICATIVE: {
        **_COMMON_PARAMETERS,
        "exposure": {"internal": 0.3, "dmz": 0.7, "internet": 1.0},
        "impact": {"low": 0.4, "business": 0.7, "critical": 1.0},
    },
    FORMULA_V3: {
        **_COMMON_PARAMETERS,
        "exposure": {"internal": 0.3, "dmz": 0.7, "internet": 1.0},
        "impact": {"low": 0.4, "business": 0.7, "critical": 1.0},
        # i-th largest contribution counts decay^i; absent = plain sum (older formulas)
        "aggregation_decay": 0.5,
        # a KEV CVE contributes at least this much, whatever the asset context; absent = no floor
        "kev_floor": 0.25,
    },
}

DEFAULT_WEIGHTS = WEIGHTS_BY_FORMULA[FORMULA]
DEFAULT_PARAMETERS: dict = {**PARAMETERS_BY_FORMULA[FORMULA], "formula": FORMULA}

EXPOSURE_VALUES = tuple(DEFAULT_PARAMETERS["exposure"])
IMPACT_VALUES = tuple(DEFAULT_PARAMETERS["impact"])


def merged_parameters(overrides: dict | None) -> dict:
    """Defaults of the formula named in `overrides` (FORMULA if none), with the overrides on top."""
    formula = (overrides or {}).get("formula") or FORMULA
    base = {**PARAMETERS_BY_FORMULA[formula], "formula": formula}
    params = {k: (dict(v) if isinstance(v, dict) else v) for k, v in base.items()}
    for key, value in (overrides or {}).items():
        if isinstance(value, dict) and isinstance(params.get(key), dict):
            params[key].update(value)
        else:
            params[key] = value
    return params


def f_severity(cvss: float | None, params: dict) -> float:
    """§5.1: CVSS/10 for a CVE; the 'Media' rating when there is no CVSS (IoC, leak, phishing)."""
    if cvss is None:
        return float(params["default_severity"])
    return max(0.0, min(1.0, cvss / 10.0))


def f_confidence(match_confidence: float | None, in_kev: bool, params: dict) -> float:
    """§5.1: a CVE exploited in the wild (KEV) is confirmed; otherwise the CPE match confidence."""
    if in_kev:
        return float(params["kev_confidence"])
    return float(match_confidence) if match_confidence is not None else 0.5


def f_recency(created_at: datetime | None, params: dict, now: datetime | None = None) -> float:
    """§5.1 step function on the age of the evidence (when the exposure was detected)."""
    if created_at is None:
        return float(params["recency_floor"])
    now = now or datetime.now(UTC)
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)  # SQLite returns naive UTC
    age_days = (now - created_at).total_seconds() / 86400
    for max_days, value in params["recency_steps"]:
        if age_days < max_days:
            return float(value)
    return float(params["recency_floor"])


def epss_boost(epss: float | None) -> float:
    return 0.0 if epss is None else min(epss * 2.0, 0.3)


def s_base(
    severity: float,
    confidence: float,
    recency: float,
    epss: float | None,
    weights: dict,
    formula: str = FORMULA,
) -> float:
    w = weights or WEIGHTS_BY_FORMULA[formula]
    if formula == FORMULA_ADDITIVE:
        return (
            severity * w["severity"]
            + confidence * w["confidence"]
            + recency * w["recency"]
            + epss_boost(epss) * w.get("epss", 0.0)
        )
    return severity * (
        w["severity"]
        + confidence * w["confidence"]
        + recency * w["recency"]
        + epss_boost(epss) / 0.3 * w.get("epss", 0.0)
    )


def exposure_factor(exposure: str | None, params: dict) -> float:
    return float(params["exposure"].get(exposure or "", params["default_exposure"]))


def impact_factor(impact: str | None, params: dict) -> float:
    return float(params["impact"].get(impact or "", params["default_impact"]))


def alpha(rule_name: str | None, params: dict) -> float:
    table = params["alpha"]
    return float(table.get(rule_name or "", table["default"]))


def r_asset(contributions: list[float]) -> float:
    """§5.3: contributions are S_context × α already; capped at 1."""
    return min(1.0, sum(contributions))


def apply_kev_floor(context_score: float, in_kev: bool, params: dict) -> float:
    """A CVE exploited in the wild never counts for less than `kev_floor` (formula v3 and later)."""
    floor = params.get("kev_floor")
    if in_kev and floor:
        return max(context_score, float(floor))
    return context_score


def aggregate(contributions: list[float], params: dict) -> float:
    """R_asset from the contributions (S_context × α each). With `aggregation_decay` the largest
    counts fully, the next one decay, then decay², ...; without it, the plain §5.3 sum. Capped at 1."""
    decay = params.get("aggregation_decay")
    if not decay:
        return r_asset(contributions)
    ordered = sorted(contributions, reverse=True)
    return min(1.0, sum(c * decay**i for i, c in enumerate(ordered)))


def level_from_score(value: float, thresholds: dict | None) -> str:
    t = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    if value < t["low"]:
        return "low"
    if value < t["medium"]:
        return "medium"
    if value < t["high"]:
        return "high"
    return "critical"
