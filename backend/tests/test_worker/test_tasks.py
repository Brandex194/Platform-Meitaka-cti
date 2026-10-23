"""Tests for Celery worker tasks and beat schedule."""
from unittest.mock import MagicMock, patch


def test_required_tasks_registered():
    """All 6 required task names are registered in the celery app."""
    import app.worker.tasks  # noqa: F401 — side-effect: registers tasks
    from app.worker.celery_app import celery_app

    names = set(celery_app.tasks.keys())
    required = [
        "sentinel.tasks.collect_nvd",
        "sentinel.tasks.collect_kev",
        "sentinel.tasks.normalize",
        "sentinel.tasks.enrich",
        "sentinel.tasks.correlate",
        "sentinel.tasks.risk_and_alert",
    ]
    for name in required:
        assert name in names, f"Task {name!r} not registered"


def test_normalize_fires_before_enrich():
    """normalize schedule has a lower minimum minute than enrich."""
    import app.worker.beat  # noqa: F401 — side-effect: sets beat_schedule
    from app.worker.celery_app import celery_app

    sched = celery_app.conf.beat_schedule
    norm_minutes = set(sched["normalize"]["schedule"].minute)
    enrich_minutes = set(sched["enrich"]["schedule"].minute)
    assert min(norm_minutes) < min(enrich_minutes)


def test_beat_schedule_has_all_tasks():
    """All 10 scheduled task names are present in beat_schedule."""
    import app.worker.beat  # noqa: F401
    from app.worker.celery_app import celery_app

    sched = celery_app.conf.beat_schedule
    expected = {
        "collect_nvd",
        "collect_ioc",
        "collect_leak",
        "collect_phishing",
        "collect_attack_techniques",
        "collect_kev",
        "normalize",
        "enrich",
        "correlate",
        "risk_and_alert",
    }
    assert expected == set(sched.keys())


def test_collect_leak_skips_when_disabled():
    """collect_leak returns 0 immediately when leak_collector_enabled is False."""
    mock_settings = MagicMock()
    mock_settings.leak_collector_enabled = False

    with patch("app.worker.tasks.get_settings", return_value=mock_settings), \
         patch("app.worker.tasks.fetch_hibp_for_tenant") as mock_hibp:
        from app.worker.tasks import collect_leak
        result = collect_leak()

    assert result == 0
    mock_hibp.assert_not_called()
