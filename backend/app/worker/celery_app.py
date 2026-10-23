from celery import Celery
from celery.schedules import crontab

from app.core.config import get_settings


def make_celery() -> Celery:
    settings = get_settings()
    app = Celery("sentinel", broker=settings.redis_url, backend=settings.redis_url)
    app.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
        task_default_queue="sentinel",
        worker_prefetch_multiplier=1,
    )
    app.autodiscover_tasks(["app.worker"])
    return app


celery_app = make_celery()

# Beat schedule lives here so `celery -A app.worker.celery_app beat` picks it up.
celery_app.conf.beat_schedule = {
    # --- Collectors ---
    "collect_nvd": {
        "task": "sentinel.tasks.collect_nvd",
        "schedule": crontab(minute=0),
    },
    "collect_ioc": {
        "task": "sentinel.tasks.collect_ioc",
        "schedule": crontab(minute=15),
    },
    "collect_leak": {
        "task": "sentinel.tasks.collect_leak",
        "schedule": crontab(hour=3, minute=0),
    },
    "collect_phishing": {
        "task": "sentinel.tasks.collect_phishing",
        "schedule": crontab(minute=0, hour="*/6"),
    },
    "collect_attack_techniques": {
        "task": "sentinel.tasks.collect_attack_techniques",
        "schedule": crontab(hour=4, minute=30),
    },
    "collect_kev": {
        "task": "sentinel.tasks.collect_kev",
        "schedule": crontab(hour=5, minute=0),
    },
    # --- Pipeline (staggered every 5 min, offset :01/:02/:03/:04) ---
    "normalize": {
        "task": "sentinel.tasks.normalize",
        "schedule": crontab(minute="1,6,11,16,21,26,31,36,41,46,51,56"),
    },
    "enrich": {
        "task": "sentinel.tasks.enrich",
        "schedule": crontab(minute="2,7,12,17,22,27,32,37,42,47,52,57"),
    },
    "correlate": {
        "task": "sentinel.tasks.correlate",
        "schedule": crontab(minute="3,8,13,18,23,28,33,38,43,48,53,58"),
    },
    "risk_and_alert": {
        "task": "sentinel.tasks.risk_and_alert",
        "schedule": crontab(minute="4,9,14,19,24,29,34,39,44,49,54,59"),
    },
}
