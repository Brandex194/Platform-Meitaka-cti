"""Correlation engine: runs all 5 rules for a tenant and upserts CorrelationEvent rows."""
import logging

from app.db.models import CorrelationEvent, ExposureMatch

from .rules import (
    correlate_campaign_asset,
    correlate_ioc_asset,
    correlate_leak_identity,
    correlate_phishing_brand,
    correlate_vuln_software,
)

logger = logging.getLogger(__name__)

_RULES = [
    correlate_vuln_software,
    correlate_ioc_asset,
    correlate_leak_identity,
    correlate_phishing_brand,
    correlate_campaign_asset,
]


def _event_exists(session, event: CorrelationEvent) -> bool:
    """Check if a matching CorrelationEvent already exists (dedup by rule + linked ids)."""
    q = session.query(CorrelationEvent).filter_by(
        tenant_id=event.tenant_id,
        rule_name=event.rule_name,
        asset_id=event.asset_id,
        vulnerability_id=event.vulnerability_id,
        indicator_id=event.indicator_id,
        identity_id=event.identity_id,
    )
    return q.first() is not None


class CorrelationEngine:
    def run_for_tenant(self, tenant_id, session=None) -> int:
        """Run all correlation rules for *tenant_id*. Returns count of new events created.

        Pass *session* in tests to avoid touching the real DB.
        """
        if session is not None:
            return self._run(session, tenant_id)
        from app.db.session import bypass_session  # lazy: avoids Settings() at import time
        gen = bypass_session()
        db = next(gen)
        try:
            return self._run(db, tenant_id)
        finally:
            try:
                next(gen)
            except StopIteration:
                pass

    def _run(self, session, tenant_id) -> int:
        count = 0
        for rule_fn in _RULES:
            try:
                candidates = rule_fn(session, tenant_id)
            except Exception as exc:
                logger.warning("correlate: rule %s failed for tenant %s: %s", rule_fn.__name__, tenant_id, exc)
                continue
            for event in candidates:
                if _event_exists(session, event):
                    continue
                session.add(event)
                session.flush()
                session.add(
                    ExposureMatch(
                        tenant_id=tenant_id,
                        correlation_event_id=event.id,
                    )
                )
                count += 1
        session.flush()
        return count
