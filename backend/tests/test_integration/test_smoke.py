"""Integration smoke tests — verify the full pipeline is importable and wired correctly."""


def test_all_pipeline_modules_importable():
    from app.collectors.nvd import fetch_nvd  # noqa: F401
    from app.collectors.kev import fetch_kev  # noqa: F401
    from app.normalize.engine import normalize_batch  # noqa: F401
    from app.enrichment.engine import enrich_batch  # noqa: F401
    from app.correlation.engine import CorrelationEngine  # noqa: F401
    from app.risk.engine import run_for_tenant  # noqa: F401
    from app.worker.tasks import collect_nvd, normalize, correlate, risk_and_alert  # noqa: F401
    from app.main import app

    assert app is not None


def test_health_endpoint():
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_pipeline_stream_names_correct():
    # normalize reads CURSOR_STREAM ("raw-observations"), writes OUTPUT_STREAM ("enriched-entities")
    # enrichment reads CURSOR_STREAM ("enriched-entities")
    from app.normalize.engine import CURSOR_STREAM as NORM_IN, OUTPUT_STREAM as NORM_OUT
    from app.enrichment.engine import CURSOR_STREAM as ENRICH_IN

    assert NORM_IN == "raw-observations"
    assert NORM_OUT == "enriched-entities"
    assert ENRICH_IN == "enriched-entities"


def test_default_weights_sum_to_one():
    from app.risk.formulas import DEFAULT_WEIGHTS

    total = sum(DEFAULT_WEIGHTS.values())
    assert abs(total - 1.0) < 1e-9


def test_beat_schedule_pipeline_stagger():
    from app.worker.celery_app import celery_app

    schedule = celery_app.conf.beat_schedule
    # Pipeline offset: collect :00, normalize :01, enrich :02, correlate :03, risk_and_alert :04
    for task_name, minute in [
        ("collect_nvd", 0),
        ("normalize", 1),
        ("enrich", 2),
        ("correlate", 3),
        ("risk_and_alert", 4),
    ]:
        assert task_name in schedule, f"{task_name} missing from beat schedule"
        cron = schedule[task_name]["schedule"]
        # crontab.minute is a set; pipeline tasks repeat every 5 min so the set has many values
        assert minute in cron.minute, f"{task_name} should include :{minute:02d} in its minute set"


def test_error_response_shape():
    from app.core.errors import error_response

    r = error_response("TEST_CODE", "test message", {"key": "val"})
    assert r == {"error": {"code": "TEST_CODE", "message": "test message", "detail": {"key": "val"}}}


def test_cpe_match_returns_correct_types():
    from app.enrichment.cpe import match_cpe

    result = match_cpe(None, [])
    assert result == (False, 0.0)

    result2 = match_cpe("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", [])
    assert isinstance(result2, tuple)
    assert isinstance(result2[0], bool)
    assert isinstance(result2[1], float)
