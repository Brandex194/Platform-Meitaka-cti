"""Unit tests for risk formulas — no DB required."""
import uuid
from datetime import datetime, timedelta, timezone

from app.risk.formulas import DEFAULT_WEIGHTS, f_recency, f_severity, s_base


class _E:
    """Minimal CorrelationEvent stand-in."""
    def __init__(self, vulnerability_id=None, s_context=0.8, created_at=None):
        self.vulnerability_id = vulnerability_id
        self.s_context = s_context
        self.created_at = created_at or datetime.now(timezone.utc)


def test_default_weights_sum_to_1():
    assert abs(sum(DEFAULT_WEIGHTS.values()) - 1.0) < 0.001


def test_f_severity_kev():
    vid = uuid.uuid4()
    assert f_severity(_E(vulnerability_id=vid), {str(vid)}, 5.0) == 1.0


def test_f_severity_non_kev():
    result = f_severity(_E(vulnerability_id=uuid.uuid4()), set(), 8.0)
    assert abs(result - 0.8) < 0.001


def test_f_recency_fresh():
    assert f_recency(_E(created_at=datetime.now(timezone.utc))) >= 0.99


def test_f_recency_old():
    old = datetime.now(timezone.utc) - timedelta(days=91)
    assert f_recency(_E(created_at=old)) == 0.0


def test_s_base_sums():
    # s_context=0 → conf=0, old event → rec=0, no epss → boost=0
    # only severity contributes: cvss=6.0 → sev=0.6 * 0.45 = 0.27
    e = _E(
        vulnerability_id=uuid.uuid4(),
        s_context=0.0,
        created_at=datetime.now(timezone.utc) - timedelta(days=91),
    )
    result = s_base(e, set(), None, 6.0, DEFAULT_WEIGHTS)
    assert abs(result - 0.6 * DEFAULT_WEIGHTS["severity"]) < 0.001
