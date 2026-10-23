"""Celery tasks for Sentinel AI CTI background workers."""
import logging

from sqlalchemy import select

from app.collectors.attack import fetch_attack
from app.collectors.hibp import fetch_hibp_for_tenant
from app.collectors.ioc import fetch_ioc
from app.collectors.kev import fetch_kev
from app.collectors.nvd import fetch_nvd
from app.collectors.phishing import fetch_phishing
from app.core.config import get_settings
from app.correlation.engine import CorrelationEngine
from app.db.models import Tenant
from app.db.session import bypass_session
from app.enrichment.engine import enrich_batch
from app.normalize.engine import normalize_batch
from app.risk.engine import run_for_tenant as risk_run_for_tenant
from app.streams.client import get_redis
from app.worker.celery_app import celery_app

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _all_tenant_ids():
    """Load all tenant IDs in a bypass_session, return list of UUIDs."""
    gen = bypass_session()
    db = next(gen)
    try:
        ids = db.execute(select(Tenant.id)).scalars().all()
    except Exception:
        db.rollback()
        try:
            next(gen)
        except Exception:
            pass
        raise
    try:
        next(gen)
    except StopIteration:
        pass
    return ids


def _run_with_db_and_redis(fn):
    """Open bypass_session + redis, call fn(db, r), commit, save cursor, publish, return count."""
    r = get_redis()
    gen = bypass_session()
    db = next(gen)
    try:
        result = fn(db, r)
        db.flush()
    except Exception:
        db.rollback()
        try:
            next(gen)
        except Exception:
            pass
        raise
    try:
        next(gen)  # commit
    except StopIteration:
        pass
    # After commit: publish FIRST (failure retries the task), then save cursor
    if isinstance(result, tuple):
        from app.streams.streams import publish, save_cursor
        count = result[0]
        last_msg_id = result[1] if len(result) > 1 else None
        pending = result[2] if len(result) > 2 else []
        cursor_stream = fn.__globals__.get("CURSOR_STREAM")
        for stream, payload in pending:
            publish(stream, payload, r=r)  # propagate — Celery retries; DB upserts are idempotent
        if last_msg_id and cursor_stream:
            save_cursor(cursor_stream, last_msg_id, r)
        return count
    return result


# ---------------------------------------------------------------------------
# Collector tasks
# ---------------------------------------------------------------------------

@celery_app.task(name="sentinel.tasks.collect_nvd")
def collect_nvd() -> int:
    return fetch_nvd(r=get_redis())


@celery_app.task(name="sentinel.tasks.collect_kev")
def collect_kev() -> int:
    return fetch_kev()


@celery_app.task(name="sentinel.tasks.collect_attack_techniques")
def collect_attack_techniques() -> int:
    return fetch_attack()


@celery_app.task(name="sentinel.tasks.collect_phishing")
def collect_phishing() -> int:
    return fetch_phishing(r=get_redis())


@celery_app.task(name="sentinel.tasks.collect_ioc")
def collect_ioc() -> int:
    # fetch_ioc already gates on ioc_collector_enabled
    return fetch_ioc()


@celery_app.task(name="sentinel.tasks.collect_leak")
def collect_leak() -> int:
    if not get_settings().leak_collector_enabled:
        return 0
    r = get_redis()
    return sum(fetch_hibp_for_tenant(tid, r=r) for tid in _all_tenant_ids())


# ---------------------------------------------------------------------------
# Pipeline tasks
# ---------------------------------------------------------------------------

@celery_app.task(name="sentinel.tasks.normalize")
def normalize() -> int:
    return _run_with_db_and_redis(normalize_batch)


@celery_app.task(name="sentinel.tasks.enrich")
def enrich() -> int:
    return _run_with_db_and_redis(enrich_batch)


@celery_app.task(name="sentinel.tasks.correlate")
def correlate() -> dict:
    tenant_ids = _all_tenant_ids()
    engine = CorrelationEngine()
    failures = 0
    for tid in tenant_ids:
        try:
            engine.run_for_tenant(tid)
        except Exception as exc:
            logger.exception("correlate: failed for tenant %s: %s", tid, exc)
            failures += 1
    return {"tenants": len(tenant_ids), "failures": failures}


@celery_app.task(name="sentinel.tasks.risk_and_alert")
def risk_and_alert() -> dict:
    tenant_ids = _all_tenant_ids()
    failures = 0
    scores = 0
    for tid in tenant_ids:
        try:
            result = risk_run_for_tenant(tid)
            scores += result.get("scores_computed", 0)
        except Exception as exc:
            logger.exception("risk_and_alert: failed for tenant %s: %s", tid, exc)
            failures += 1
    return {"tenants": len(tenant_ids), "scores_computed": scores, "failures": failures}
