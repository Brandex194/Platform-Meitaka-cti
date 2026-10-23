from celery import Celery

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
        task_queue="sentinel",
        worker_prefetch_multiplier=1,
    )
    app.autodiscover_tasks(["app.worker"])
    return app


celery_app = make_celery()
