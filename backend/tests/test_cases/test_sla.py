from datetime import UTC, datetime, timedelta

import pytest

from app.cases.sla import SLA_HOURS, due_at_for, sla_status

T0 = datetime(2026, 11, 9, 8, 0, tzinfo=UTC)


@pytest.mark.parametrize("severity,hours", [("critical", 4), ("high", 24), ("medium", 72), ("low", 168)])
def test_due_at_by_severity(severity, hours):
    assert SLA_HOURS[severity] == hours
    assert due_at_for(severity, T0) == T0 + timedelta(hours=hours)


def test_unknown_severity_gets_the_medium_window():
    assert due_at_for("weird", T0) == T0 + timedelta(hours=72)


def test_naive_datetimes_from_sqlite_are_treated_as_utc():
    naive = datetime(2026, 11, 9, 8, 0)
    assert due_at_for("high", naive) == T0 + timedelta(hours=24)


def _status(status, now_offset_h, *, severity="high", closed_after_h=None, due=True):
    due_at = due_at_for(severity, T0) if due else None
    closed_at = T0 + timedelta(hours=closed_after_h) if closed_after_h is not None else None
    return sla_status(status, T0, due_at, closed_at, now=T0 + timedelta(hours=now_offset_h))


def test_open_case_on_track_then_at_risk_then_breached():
    # high = 24h window; the last quarter starts at 18h
    assert _status("open", 1) == "on_track"
    assert _status("open", 17.9) == "on_track"
    assert _status("open", 18) == "at_risk"
    assert _status("in_progress", 23.9) == "at_risk"
    assert _status("open", 24) == "at_risk"  # exactly on the deadline is not late yet
    assert _status("open", 24.1) == "breached"


def test_closed_case_is_met_or_breached_by_the_closing_time_not_by_now():
    assert _status("closed", 500, closed_after_h=20) == "met"
    assert _status("closed", 500, closed_after_h=24) == "met"
    assert _status("closed", 500, closed_after_h=30) == "breached"
    assert _status("false_positive", 500, closed_after_h=2) == "met"


def test_closed_without_a_closing_time_counts_as_met():
    assert _status("closed", 500) == "met"


def test_no_deadline_means_none():
    assert _status("open", 1000, due=False) == "none"
