# Beat schedule is defined in celery_app.py.
# This file exists so `celery -A app.worker.beat beat` also works.
from app.worker.celery_app import celery_app  # noqa: F401
