"""Demo data for a development tenant: fictitious assets, vulnerabilities, cases, actors, leaks...

Run:  python -m app.demo.seed            (load; does nothing if the demo data is already there)
      python -m app.demo.seed --reset    (remove the demo data, then load it again)
      python -m app.demo.seed --remove   (remove the demo data only)

Everything is invented and marked: hostnames `demo-*`, CVE ids `CVE-2099-D*`, vendor `demovendor`,
addresses in the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), domains
`*.example`, names starting with "DEMO". Findings, exposures and scores are not typed in: the
correlation engine and the risk engine of the platform produce them from the data below, so the
demo also exercises the real pipeline. Only rows with these markers are ever removed.
Never run it against a production database.
"""
import argparse
import hashlib
import sys
import uuid
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import delete, or_, select, text
from sqlalchemy.orm import Session

from app.cases.sla import due_at_for
from app.correlation.engine import CorrelationEngine
from app.db.models import (
    Asset, Campaign, CampaignIndicator, Case, CaseEvent, CaseNote, CorrelationEvent, ExposureMatch,
    Identity, Indicator, KevCatalog, Leak, Observation, Score, Software, Tenant, ThreatActor, Vulnerability,
)
from app.risk.engine import run_for_tenant

DEMO_TENANT_ID = uuid.UUID("00000000-0000-4000-8000-000000000001")
CVE_PREFIX = "CVE-2099-D"
VENDOR = "demovendor"


def _cpe(product: str, version: str) -> str:
    return f"cpe:2.3:a:{VENDOR}:{product}:{version}:*:*:*:*:*:*:*"


def _crit(product: str, **rng) -> dict:
    return {"criteria": f"cpe:2.3:a:{VENDOR}:{product}:*:*:*:*:*:*:*:*", "vulnerable": True, **rng}


ASSETS = [  # hostname, ip, exposure, impact, [(software name, product, version)]
    ("demo-web-01", "192.0.2.10", "internet", "critical", [("DemoHTTP", "httpd", "2.4.1"), ("DemoCMS", "cms", "5.2")]),
    ("demo-api-01", "192.0.2.11", "internet", "business", [("DemoAPI Gateway", "gateway", "1.8")]),
    ("demo-vpn-gw", "198.51.100.23", "internet", "critical", [("DemoVPN", "vpn", "9.1")]),
    ("demo-mail-01", "192.0.2.20", "dmz", "business", [("DemoMail", "mailserver", "7.0")]),
    ("demo-db-01", "10.20.0.5", "internal", "critical", [("DemoSQL", "sql", "12.3")]),
    ("demo-files-01", "10.20.0.8", "internal", "business", [("DemoShare", "share", "4.0")]),
    ("demo-dev-01", "10.20.1.30", "internal", "low", [("DemoHTTP", "httpd", "2.4.1")]),
    ("demo-hr-pc", "10.20.2.14", "internal", "low", [("DemoOffice", "office", "2019")]),
]

VULNS = [  # suffix, cvss, epss, in_kev, product, range, description
    ("0001", 9.8, 0.94, True, "vpn", {"versionEndExcluding": "9.5"}, "Remote code execution in the VPN gateway login."),
    ("0002", 9.1, 0.62, False, "httpd", {"versionEndExcluding": "2.4.9"}, "Path traversal in the web server."),
    ("0003", 8.8, 0.31, False, "cms", {"versionEndExcluding": "5.4"}, "Authenticated file upload leads to code execution."),
    ("0004", 7.5, 0.12, False, "gateway", {"versionEndExcluding": "2.0"}, "Missing rate limit allows credential stuffing."),
    ("0005", 8.1, 0.45, True, "mailserver", {"versionEndExcluding": "7.2"}, "Pre-auth injection in the mail server."),
    ("0006", 6.5, 0.04, False, "sql", {"versionEndExcluding": "12.5"}, "Privilege escalation for local users."),
    ("0007", 5.3, 0.02, False, "share", {"versionEndExcluding": "4.2"}, "Information disclosure over the file share protocol."),
    ("0008", 4.3, 0.01, False, "office", {"versionEndExcluding": "2021"}, "Macro warning bypass."),
]

INDICATORS = [  # type, value, confidence (0 to 1, as the API stores it)
    ("ip", "198.51.100.23", 0.9),   # same address as demo-vpn-gw: produces an ioc_asset finding
    ("ip", "203.0.113.45", 0.8),
    ("domain", "login-portal-update.example", 0.85),
    ("domain", "cdn-assets-mirror.example", 0.6),
    ("hash", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", 0.95),
    ("email", "billing@invoice-notice.example", 0.7),
]

ACTORS = [
    ("DEMO Crimson Mantis", ["Mantis-7"], "Financially motivated group that targets VPN appliances."),
    ("DEMO Pale Lantern", None, "Phishing operators active against the finance sector."),
    ("DEMO Iron Weaver", ["Weaver"], "Espionage-oriented group, patient and low noise."),
]
CAMPAIGNS = [  # name, actor index, description, indicator indexes
    ("DEMO Operation Quiet Gate", 0, "Exploitation of VPN gateways followed by data theft.", [0, 1]),
    ("DEMO Invoice Wave", 1, "Fake invoices pointing to look-alike portals.", [2, 3, 5]),
    ("DEMO Long Thread", 2, "Slow lateral movement and document collection.", [4]),
]

IDENTITIES = [("Anna Bianchi", "anna.bianchi"), ("Marco Conti", "marco.conti"), ("Sara Greco", "sara.greco"),
              ("Paolo Riva", "paolo.riva"), ("Elena Fabbri", "elena.fabbri")]
LEAKED = [("anna.bianchi", "DEMO Breach 2024 Shop", 1_200_000), ("marco.conti", "DEMO Breach 2023 Forum", 480_000)]

FINDINGS = [  # source, context, severity, status
    ("demo-forum.example", "Offer to sell VPN access to a company in the retail sector.", "high", "new"),
    ("demo-paste.example", "Dump with 300 corporate emails and password hashes.", "critical", "new"),
    ("demo-market.example", "Ad for a phishing kit that imitates the company login page.", "medium", "reviewed"),
    ("demo-chat.example", "Generic mention of the company name, no data shown.", "low", "dismissed"),
]

CASES = [  # title, severity, status, hours since created, description
    ("[DEMO] Possible exploitation of the VPN gateway", "critical", "in_progress", 3, "Unusual logins from a flagged address."),
    ("[DEMO] Phishing wave on the finance team", "high", "open", 30, "Five users received the same fake invoice."),
    ("[DEMO] Leaked credentials found", "medium", "open", 20, "Two corporate emails appear in a public breach."),
    ("[DEMO] Outdated CMS on the public site", "medium", "closed", 120, "Patched and verified."),
    ("[DEMO] Alert from the dev server", "low", "false_positive", 200, "Test traffic, nothing to do."),
]


def remove_demo(db: Session, tenant_id: uuid.UUID) -> dict:
    assets = db.execute(select(Asset.id).where(Asset.tenant_id == tenant_id, Asset.hostname.like("demo-%"))).scalars().all()
    vulns = db.execute(select(Vulnerability.id).where(Vulnerability.cve_id.like(f"{CVE_PREFIX}%"))).scalars().all()
    ident = db.execute(select(Identity.id).where(Identity.tenant_id == tenant_id, Identity.email.like("%@demo.example"))).scalars().all()
    ind_values = [v for _, v, _ in INDICATORS]
    inds = db.execute(select(Indicator.id).where(Indicator.tenant_id == tenant_id, Indicator.value.in_(ind_values))).scalars().all()
    actors = db.execute(select(ThreatActor.id).where(ThreatActor.tenant_id == tenant_id, ThreatActor.name.like("DEMO %"))).scalars().all()
    camps = db.execute(select(Campaign.id).where(Campaign.tenant_id == tenant_id, Campaign.name.like("DEMO %"))).scalars().all()
    cases = db.execute(select(Case.id).where(Case.tenant_id == tenant_id, Case.title.like("[DEMO]%"))).scalars().all()

    conds = []
    if assets:
        conds.append(CorrelationEvent.asset_id.in_(assets))
    if vulns:
        conds.append(CorrelationEvent.vulnerability_id.in_(vulns))
    if ident:
        conds.append(CorrelationEvent.identity_id.in_(ident))
    if inds:
        conds.append(CorrelationEvent.indicator_id.in_(inds))
    events = []
    if conds:
        events = db.execute(select(CorrelationEvent.id).where(CorrelationEvent.tenant_id == tenant_id, or_(*conds))).scalars().all()
    if events:
        db.execute(delete(ExposureMatch).where(ExposureMatch.correlation_event_id.in_(events)))
        db.execute(delete(CorrelationEvent).where(CorrelationEvent.id.in_(events)))
    if assets:
        db.execute(delete(Score).where(Score.tenant_id == tenant_id, Score.asset_id.in_(assets)))
        db.execute(delete(Software).where(Software.asset_id.in_(assets)))
        db.execute(delete(Observation).where(Observation.asset_id.in_(assets)))
        db.execute(delete(Asset).where(Asset.id.in_(assets)))
    if cases:
        db.execute(delete(CaseNote).where(CaseNote.case_id.in_(cases)))
        db.execute(delete(CaseEvent).where(CaseEvent.case_id.in_(cases)))
        db.execute(delete(Case).where(Case.id.in_(cases)))
    if camps:
        db.execute(delete(CampaignIndicator).where(CampaignIndicator.campaign_id.in_(camps)))
        db.execute(delete(Campaign).where(Campaign.id.in_(camps)))
    if actors:
        db.execute(delete(ThreatActor).where(ThreatActor.id.in_(actors)))
    if inds:
        db.execute(delete(CampaignIndicator).where(CampaignIndicator.indicator_id.in_(inds)))
        db.execute(delete(Indicator).where(Indicator.id.in_(inds)))
    if ident:
        db.execute(delete(Identity).where(Identity.id.in_(ident)))
    db.execute(delete(Leak).where(Leak.tenant_id == tenant_id, Leak.breach_name.like("DEMO %")))
    for o in db.execute(select(Observation).where(Observation.tenant_id == tenant_id, Observation.event_type == "darkweb")).scalars():
        if (o.payload or {}).get("demo"):
            db.delete(o)
    if vulns:
        db.execute(delete(Vulnerability).where(Vulnerability.id.in_(vulns)))
    db.execute(delete(KevCatalog).where(KevCatalog.cve_id.like(f"{CVE_PREFIX}%")))
    db.flush()
    return {"assets": len(assets), "vulnerabilities": len(vulns), "cases": len(cases)}


def load_demo(db: Session, tenant_id: uuid.UUID, now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    if db.execute(select(Asset.id).where(Asset.tenant_id == tenant_id, Asset.hostname == "demo-web-01")).first():
        return {"skipped": "demo data already present (use --reset to reload it)"}

    if db.get(Tenant, tenant_id) is None:
        db.add(Tenant(id=tenant_id, name="Tenant demo", slug="demo", sector="technology"))
        db.flush()

    asset_ids = {}
    for host, ip, exposure, impact, software in ASSETS:
        a = Asset(tenant_id=tenant_id, hostname=host, ip=ip, exposure=exposure, impact=impact,
                  created_at=now - timedelta(days=30))
        db.add(a)
        db.flush()
        asset_ids[host] = a.id
        for name, product, version in software:
            db.add(Software(tenant_id=tenant_id, asset_id=a.id, name=name, version=version, cpe=_cpe(product, version)))

    for suffix, cvss, epss, in_kev, product, rng, desc in VULNS:
        cve = f"{CVE_PREFIX}{suffix}"
        db.add(Vulnerability(
            cve_id=cve, cvss_score=cvss, epss_score=epss, description=f"[DEMO] {desc}",
            kev_date_added=date.today() - timedelta(days=20) if in_kev else None,
            cpe_nodes=[_crit(product, **rng)],
        ))
        if in_kev:
            db.add(KevCatalog(cve_id=cve, date_added=date.today() - timedelta(days=20)))

    indicators = []
    for ioc_type, value, conf in INDICATORS:
        i = Indicator(tenant_id=tenant_id, ioc_type=ioc_type, value=value, confidence=conf)
        db.add(i)
        indicators.append(i)
    actors = []
    for name, aliases, desc in ACTORS:
        t = ThreatActor(tenant_id=tenant_id, name=name, aliases=aliases, description=desc)
        db.add(t)
        actors.append(t)
    db.flush()
    for name, actor_idx, desc, links in CAMPAIGNS:
        c = Campaign(tenant_id=tenant_id, name=name, threat_actor_id=actors[actor_idx].id, description=desc)
        db.add(c)
        db.flush()
        for idx in links:
            db.add(CampaignIndicator(tenant_id=tenant_id, campaign_id=c.id, indicator_id=indicators[idx].id))

    for name, local in IDENTITIES:
        db.add(Identity(tenant_id=tenant_id, name=name, email=f"{local}@demo.example"))
    for local, breach, count in LEAKED:
        email_hash = hashlib.sha256(f"{local}@demo.example".encode()).hexdigest()
        db.add(Leak(tenant_id=tenant_id, email_hash=email_hash, breach_name=breach, pwn_count=count))
    for source, context, severity, status in FINDINGS:
        db.add(Observation(tenant_id=tenant_id, event_type="darkweb",
                           payload={"source": source, "context": context, "severity": severity,
                                    "status": status, "demo": True}))

    for title, severity, status, hours, desc in CASES:
        created = now - timedelta(hours=hours)
        closed = created + timedelta(hours=2) if status in ("closed", "false_positive") else None
        case = Case(tenant_id=tenant_id, title=title, description=desc, status=status, severity=severity,
                    created_at=created, updated_at=closed or created, due_at=due_at_for(severity, created),
                    closed_at=closed)
        db.add(case)
        db.flush()
        db.add(CaseEvent(tenant_id=tenant_id, case_id=case.id, event_type="created", created_at=created,
                         payload={"severity": severity}))
        if status != "open":
            db.add(CaseEvent(tenant_id=tenant_id, case_id=case.id, event_type="status_changed",
                             created_at=closed or created + timedelta(minutes=30), payload={"to": status}))
        if status in ("in_progress", "closed"):
            db.add(CaseNote(tenant_id=tenant_id, case_id=case.id, body="Checked the logs and contacted the owner.",
                            created_at=created + timedelta(minutes=45)))
    db.flush()

    # Findings and scores come from the real engines.
    found = CorrelationEngine().run_for_tenant(tenant_id, session=db, r=_NoRedis())
    scored = run_for_tenant(tenant_id, db=db)

    # A short history, so the trend chart and the sparklines have something to show.
    latest = db.execute(select(Score).where(Score.tenant_id == tenant_id, Score.asset_id.in_(asset_ids.values()))).scalars().all()
    for s in latest:
        for days_ago, factor in ((14, 0.55), (10, 0.7), (6, 0.8), (3, 0.92)):
            v = round(min(1.0, s.value * factor), 4)
            db.add(Score(tenant_id=tenant_id, asset_id=s.asset_id, score_type="asset", value=v, level=s.level
                         if factor > 0.9 else _level(v), computed_at=now - timedelta(days=days_ago),
                         score_rule_id=s.score_rule_id, score_rule_version=s.score_rule_version))
    db.flush()
    return {"assets": len(ASSETS), "findings": found, "scores": scored.get("scores_computed")}


def _level(v: float) -> str:
    return "low" if v < 0.2 else "medium" if v < 0.4 else "high" if v < 0.7 else "critical"


class _NoRedis:
    """The demo does not need the event stream: swallow the publish calls."""

    def __getattr__(self, name):
        return lambda *a, **k: None


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--reset", action="store_true", help="remove the demo data and load it again")
    p.add_argument("--remove", action="store_true", help="only remove the demo data")
    p.add_argument("--tenant-id", default=str(DEMO_TENANT_ID))
    args = p.parse_args(argv)
    tenant_id = uuid.UUID(args.tenant_id)

    from app.db.session import SessionLocal

    with SessionLocal() as db, db.begin():
        db.execute(text("SET LOCAL app.bypass_tenant_scope = 'on'"))
        if args.reset or args.remove:
            print("removed:", remove_demo(db, tenant_id))
        if not args.remove:
            print("loaded:", load_demo(db, tenant_id))
    return 0


if __name__ == "__main__":
    sys.exit(main())
