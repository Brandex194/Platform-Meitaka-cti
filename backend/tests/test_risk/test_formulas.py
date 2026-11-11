"""Unit tests for the Architettura §5 formulas — no DB required."""
from datetime import UTC, datetime, timedelta

import pytest

from app.risk.formulas import (
    DEFAULT_PARAMETERS,
    DEFAULT_THRESHOLDS,
    DEFAULT_WEIGHTS,
    FORMULA,
    FORMULA_ADDITIVE,
    FORMULA_MULTIPLICATIVE,
    FORMULA_V3,
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
    r_asset,
    s_base,
)

P = merged_parameters(None)  # the default: formula v3
P_MUL = merged_parameters({"formula": FORMULA_MULTIPLICATIVE})  # passo 5, kept for older rules
P_ADD = merged_parameters({"formula": FORMULA_ADDITIVE})
W_ADD = WEIGHTS_BY_FORMULA[FORMULA_ADDITIVE]
NOW = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)


def _ago(days):
    return NOW - timedelta(days=days)


def test_default_is_formula_v3_with_the_multiplicative_weights():
    assert FORMULA == FORMULA_V3
    assert P["formula"] == FORMULA_V3
    assert P["aggregation_decay"] == 0.5 and P["kev_floor"] == 0.25
    assert "aggregation_decay" not in P_MUL and "kev_floor" not in P_MUL  # older rules keep the plain sum
    assert DEFAULT_WEIGHTS == {"severity": 0.0, "confidence": 0.3, "recency": 0.3, "epss": 0.4}


@pytest.mark.parametrize("weights", list(WEIGHTS_BY_FORMULA.values()))
def test_weights_sum_to_1(weights):
    assert abs(sum(weights.values()) - 1.0) < 1e-9


def test_severity_is_cvss_over_10_without_kev_bonus():
    assert f_severity(9.8, P) == pytest.approx(0.98)
    assert f_severity(None, P) == 0.6  # IoC/leak/phishing without rating = Media


def test_confidence_kev_is_confirmed_otherwise_match_confidence():
    assert f_confidence(0.7, True, P) == 1.0
    assert f_confidence(0.7, False, P) == 0.7
    assert f_confidence(None, False, P) == 0.5


@pytest.mark.parametrize(("days", "expected"), [(0, 1.0), (6.9, 1.0), (7, 0.5), (29, 0.5), (30, 0.2), (365, 0.2)])
def test_recency_steps(days, expected):
    assert f_recency(_ago(days), P, NOW) == expected


def test_recency_naive_datetime_is_utc():
    assert f_recency(_ago(1).replace(tzinfo=None), P, NOW) == 1.0


# --- additive (§5.1 as written) -----------------------------------------------------------------

def test_additive_s_base_section_5_1():
    assert s_base(0.6, 0.0, 0.0, None, W_ADD, FORMULA_ADDITIVE) == pytest.approx(0.3)
    assert s_base(1.0, 1.0, 1.0, 0.9, W_ADD, FORMULA_ADDITIVE) == pytest.approx(1.0)  # EPSS weight 0


def test_additive_epss_counts_only_when_the_rule_gives_it_weight():
    w = {"severity": 0.5, "confidence": 0.2, "recency": 0.2, "epss": 0.1}
    assert s_base(0, 0, 0, 0.5, w, FORMULA_ADDITIVE) == pytest.approx(0.03)  # min(0.5*2, 0.3) * 0.1


# --- multiplicative (passo 5) -------------------------------------------------------------------

def test_multiplicative_severity_scales_everything():
    # 0.5 × (0.3×0.9 + 0.3×1.0 + 0.4×(min(0.02×2, 0.3)/0.3))
    expected = 0.5 * (0.27 + 0.3 + 0.4 * (0.04 / 0.3))
    assert s_base(0.5, 0.9, 1.0, 0.02, DEFAULT_WEIGHTS) == pytest.approx(expected)
    assert s_base(0.0, 1.0, 1.0, 0.9, DEFAULT_WEIGHTS) == 0.0  # no severity, no score


def test_multiplicative_epss_saturates_at_0_15():
    assert s_base(1.0, 0, 0, 0.15, DEFAULT_WEIGHTS) == pytest.approx(0.4)
    assert s_base(1.0, 0, 0, 0.9, DEFAULT_WEIGHTS) == pytest.approx(0.4)
    assert s_base(1.0, 0, 0, None, DEFAULT_WEIGHTS) == 0.0


@pytest.mark.parametrize(
    ("params", "exposure", "impact", "expected"),
    [
        (P, "internet", "critical", 1.0),
        (P, "dmz", "business", 0.49),
        (P, "internal", "low", 0.12),
        (P, None, None, 1.0),
        (P_ADD, "dmz", "business", 0.3),
        (P_ADD, "internal", "low", 0.06),
    ],
)
def test_context_factors(params, exposure, impact, expected):
    assert exposure_factor(exposure, params) * impact_factor(impact, params) == pytest.approx(expected)


def test_alpha_by_rule():
    assert alpha("vuln_software", P) == 1.0
    assert alpha("leak_identity", P) == 0.8
    assert alpha("ioc_asset", P) == 0.5
    assert alpha("something_else", P) == 0.2


def test_r_asset_is_capped_at_1():
    assert r_asset([0.6, 0.6, 0.6]) == 1.0
    assert r_asset([]) == 0.0


@pytest.mark.parametrize(
    ("value", "level"),
    [(0.0, "low"), (0.19, "low"), (0.2, "medium"), (0.39, "medium"), (0.4, "high"), (0.69, "high"), (0.7, "critical"), (1.0, "critical")],
)
def test_levels_section_5_3(value, level):
    assert level_from_score(value, DEFAULT_THRESHOLDS) == level


def test_rule_overrides_are_merged_not_replaced():
    params = merged_parameters({"exposure": {"internal": 0.1}, "default_impact": 0.6})
    assert params["exposure"] == {"internal": 0.1, "dmz": 0.7, "internet": 1.0}
    assert params["default_impact"] == 0.6
    assert DEFAULT_PARAMETERS["exposure"]["internal"] == 0.3  # defaults untouched


def _score(events, exposure, impact, params, weights):
    context = exposure_factor(exposure, params) * impact_factor(impact, params)
    contributions = [
        apply_kev_floor(
            s_base(f_severity(cvss, params), f_confidence(conf, kev, params), f_recency(_ago(age), params, NOW),
                   epss, weights, params["formula"])
            * context,
            kev,
            params,
        )
        * alpha("vuln_software", params)
        for cvss, kev, epss, conf, age in events
    ]
    return aggregate(contributions, params)


# --- Regression: the 7 scenarios of the A/B comparison, additive formula -------------------------
# Inputs are test values, not real CVE data. (cvss, in_kev, epss, match_confidence, age_days)
_KEV = (9.8, True, 0.9, 0.9, 0)
ADDITIVE_SCENARIOS = [
    ("1 internet+critical, KEV today", [_KEV], "internet", "critical", 0.99, "critical"),
    ("2 same, 60 days old", [(9.8, True, 0.9, 0.9, 60)], "internet", "critical", 0.83, "critical"),
    ("3 CVSS 5.3 today", [(5.3, False, 0.02, 0.9, 0)], "internet", "critical", 0.74, "critical"),
    ("4 CVSS 7.5, version unknown", [(7.5, False, 0.4, 0.7, 0)], "internet", "critical", 0.78, "critical"),
    ("5 five CVSS 5.0, 10 days", [(5.0, False, 0.01, 0.9, 10)] * 5, "internet", "critical", 1.0, "critical"),
    ("6 internal+low, KEV", [_KEV], "internal", "low", 0.06, "low"),
    ("7 dmz+business, KEV", [_KEV], "dmz", "business", 0.30, "medium"),
]


@pytest.mark.parametrize(("name", "events", "exposure", "impact", "value", "level"), ADDITIVE_SCENARIOS)
def test_additive_comparison_scenarios(name, events, exposure, impact, value, level):
    total = _score(events, exposure, impact, P_ADD, W_ADD)
    assert total == pytest.approx(value, abs=0.005)
    assert level_from_score(total, DEFAULT_THRESHOLDS) == level


# --- Regression: the 12 tuning scenarios, multiplicative formula (doc "Taratura dello scoring") --
# Expected levels approved by the project owner on 09/11/2026. Scenarios 5 and 6 are known misses
# (expected high / medium): they need a change to §5.3 aggregation or a KEV floor, not weights.
TUNING_SCENARIOS = [
    ("1 KEV 9.8 internet+critical today", [_KEV], "internet", "critical", 0.98, "critical"),
    ("2 KEV 9.8 internet+critical 60d", [(9.8, True, 0.9, 0.9, 60)], "internet", "critical", 0.74, "critical"),
    ("3 CVSS 5.3 internet+critical", [(5.3, False, 0.02, 0.9, 0)], "internet", "critical", 0.33, "medium"),
    ("4 CVSS 7.5 version unknown", [(7.5, False, 0.4, 0.7, 0)], "internet", "critical", 0.68, "high"),
    ("5 five CVSS 5.0 (known miss)", [(5.0, False, 0.01, 0.9, 10)] * 5, "internet", "critical", 1.0, "critical"),
    ("6 KEV internal+low (known miss)", [_KEV], "internal", "low", 0.12, "low"),
    ("7 KEV dmz+business", [_KEV], "dmz", "business", 0.48, "high"),
    ("8 CVSS 9.8 not KEV", [(9.8, False, 0.01, 0.9, 0)], "internet", "critical", 0.58, "high"),
    ("9 CVSS 3.1", [(3.1, False, 0.01, 0.9, 0)], "internet", "critical", 0.18, "low"),
    ("10 CVSS 7.5 internal+business", [(7.5, False, 0.4, 0.9, 0)], "internal", "business", 0.15, "low"),
    ("11 CVSS 9.8 not KEV dmz+business", [(9.8, False, 0.05, 0.9, 0)], "dmz", "business", 0.34, "medium"),
    ("12 unclassified CVSS 5.3", [(5.3, False, 0.02, 0.9, 0)], None, None, 0.33, "medium"),
]


@pytest.mark.parametrize(("name", "events", "exposure", "impact", "value", "level"), TUNING_SCENARIOS)
def test_tuning_scenarios(name, events, exposure, impact, value, level):
    total = _score(events, exposure, impact, P_MUL, WEIGHTS_BY_FORMULA[FORMULA_MULTIPLICATIVE])
    assert total == pytest.approx(value, abs=0.005)
    assert level_from_score(total, DEFAULT_THRESHOLDS) == level


# --- Formula v3 (passo 11): all 12 tuning scenarios at the level the project owner approved ------
# Expected: 5 five CVSS 5.0 -> high (was critical), 6 KEV on internal+low -> medium (was low).
APPROVED_LEVELS = ["critical", "critical", "medium", "high", "high", "medium", "high", "high", "low", "low", "medium", "medium"]


@pytest.mark.parametrize(("scenario", "approved"), list(zip(TUNING_SCENARIOS, APPROVED_LEVELS, strict=True)))
def test_v3_reaches_every_approved_level(scenario, approved):
    name, events, exposure, impact, _value, _old = scenario
    total = _score(events, exposure, impact, P, DEFAULT_WEIGHTS)
    assert level_from_score(total, DEFAULT_THRESHOLDS) == approved, name


def test_v3_scenario_5_and_6_values():
    five = _score([(5.0, False, 0.01, 0.9, 10)] * 5, "internet", "critical", P, DEFAULT_WEIGHTS)
    assert five == pytest.approx(0.433, abs=0.005)
    assert _score([_KEV], "internal", "low", P, DEFAULT_WEIGHTS) == pytest.approx(0.25)


def test_aggregate_decays_by_rank_and_is_capped():
    assert aggregate([0.2, 0.4], {"aggregation_decay": 0.5}) == pytest.approx(0.4 + 0.2 * 0.5)  # order does not matter
    assert aggregate([0.9, 0.9, 0.9], {"aggregation_decay": 0.5}) == 1.0
    assert aggregate([], {"aggregation_decay": 0.5}) == 0.0
    assert aggregate([0.6, 0.6, 0.6], {}) == 1.0  # no decay key = the old plain sum
    assert aggregate([0.2, 0.2], {"aggregation_decay": 0.5}) < aggregate([0.2, 0.2], {})


def test_many_weak_findings_never_beat_one_strong_one_by_much():
    """With decay 0.5 the total of any number of findings is at most twice the largest."""
    weak = [0.15] * 50
    assert aggregate(weak, P) <= 2 * 0.15 + 1e-9
    assert aggregate(weak, P) < aggregate([0.5], P)


def test_kev_floor_only_lifts_kev_findings():
    assert apply_kev_floor(0.05, True, P) == 0.25
    assert apply_kev_floor(0.05, False, P) == 0.05
    assert apply_kev_floor(0.9, True, P) == 0.9  # never lowers
    assert apply_kev_floor(0.05, True, P_MUL) == 0.05  # older formulas have no floor
