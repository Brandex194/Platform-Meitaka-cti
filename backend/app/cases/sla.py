"""SLA of a case: how long the team has to close it, by severity.

The hours are a product rule, not data from outside: they were chosen when the case workspace was
built (09/11/2026) and are meant to be agreed with each customer. Change them here and add a
migration for the cases already open; nothing else depends on the numbers.
"""
from datetime import UTC, datetime, timedelta

SLA_HOURS = {"critical": 4, "high": 24, "medium": 72, "low": 168}

OPEN_STATUSES = ("open", "in_progress")
CLOSED_STATUSES = ("closed", "false_positive")

# An open case is "at risk" when this share of its window (or less) is left.
AT_RISK_SHARE = 0.25


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)  # SQLite returns naive UTC


def due_at_for(severity: str, created_at: datetime) -> datetime:
    """Deadline of a case: creation time plus the hours of its severity (medium if unknown)."""
    hours = SLA_HOURS.get(severity, SLA_HOURS["medium"])
    return _aware(created_at) + timedelta(hours=hours)


def sla_status(
    status: str,
    created_at: datetime,
    due_at: datetime | None,
    closed_at: datetime | None,
    now: datetime | None = None,
) -> str:
    """none | on_track | at_risk | breached | met.

    A closed case is `met` if it was closed by the deadline, otherwise `breached`. An open case is
    `breached` once the deadline has passed, `at_risk` in the last quarter of its window.
    """
    if due_at is None:
        return "none"
    due = _aware(due_at)
    if status in CLOSED_STATUSES:
        closed = _aware(closed_at) if closed_at is not None else due
        return "met" if closed <= due else "breached"
    now = _aware(now or datetime.now(UTC))
    if now > due:
        return "breached"
    window = (due - _aware(created_at)).total_seconds()
    if window > 0 and (due - now).total_seconds() <= window * AT_RISK_SHARE:
        return "at_risk"
    return "on_track"
