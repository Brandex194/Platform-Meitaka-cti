"""Correlation rules: each function matches a threat class against tenant assets/identities."""
import hashlib
import ipaddress
import logging

from sqlalchemy import or_

from app.db.models import (
    Asset,
    CorrelationEvent,
    Identity,
    Indicator,
    Leak,
    Software,
    Vulnerability,
)
from app.enrichment.cpe import match_cpe

logger = logging.getLogger(__name__)


def correlate_vuln_software(session, tenant_id) -> list[CorrelationEvent]:
    """Match Software CPEs against all Vulnerability CPE configurations."""
    software_rows = (
        session.query(Software)
        .filter(Software.tenant_id == tenant_id, Software.cpe.isnot(None))
        .all()
    )
    if not software_rows:
        return []
    vulns = session.query(Vulnerability).all()
    events = []
    for sw in software_rows:
        for vuln in vulns:
            matched, confidence = match_cpe(sw.cpe, vuln.cpe_nodes or [])
            if matched:
                events.append(
                    CorrelationEvent(
                        tenant_id=tenant_id,
                        rule_name="vuln_software",
                        asset_id=sw.asset_id,
                        vulnerability_id=vuln.id,
                        s_context=confidence,
                    )
                )
    return events


def _ip_matches(asset_ip: str, ioc_value: str) -> bool:
    try:
        return ipaddress.ip_address(asset_ip) in ipaddress.ip_network(ioc_value, strict=False)
    except ValueError:
        return asset_ip == ioc_value


def correlate_ioc_asset(session, tenant_id) -> list[CorrelationEvent]:
    """Exact IP/CIDR match and domain suffix match for IoC indicators vs tenant assets."""
    assets = session.query(Asset).filter_by(tenant_id=tenant_id).all()
    if not assets:
        return []
    indicators = session.query(Indicator).filter(
        or_(Indicator.tenant_id.is_(None), Indicator.tenant_id == tenant_id)
    ).all()
    events = []
    for asset in assets:
        for ioc in indicators:
            matched = False
            if ioc.ioc_type == "ip" and asset.ip:
                matched = _ip_matches(asset.ip, ioc.value)
            elif ioc.ioc_type == "domain" and asset.hostname:
                matched = asset.hostname == ioc.value or asset.hostname.endswith("." + ioc.value)
            if matched:
                events.append(
                    CorrelationEvent(
                        tenant_id=tenant_id,
                        rule_name="ioc_asset",
                        asset_id=asset.id,
                        indicator_id=ioc.id,
                        s_context=ioc.confidence,
                    )
                )
    return events


def correlate_leak_identity(session, tenant_id) -> list[CorrelationEvent]:
    """Match Leak.email_hash against SHA-256 of Identity.email for the tenant."""
    identities = session.query(Identity).filter_by(tenant_id=tenant_id).all()
    leaks = session.query(Leak).filter_by(tenant_id=tenant_id).all()
    if not identities or not leaks:
        return []
    leak_hash_set = {leak.email_hash for leak in leaks}
    events = []
    for identity in identities:
        if not identity.email:
            continue
        email_hash = hashlib.sha256(identity.email.lower().encode()).hexdigest()
        if email_hash in leak_hash_set:
            events.append(
                CorrelationEvent(
                    tenant_id=tenant_id,
                    rule_name="leak_identity",
                    identity_id=identity.id,
                )
            )
    return events


def correlate_phishing_brand(session, tenant_id) -> list[CorrelationEvent]:
    # shortcut: requires PhishingDomain.target_brand and Tenant.domains columns; add in Phase 2
    return []


def correlate_campaign_asset(session, tenant_id) -> list[CorrelationEvent]:
    # shortcut: requires Campaign.target_sectors column; add in Phase 2
    return []
