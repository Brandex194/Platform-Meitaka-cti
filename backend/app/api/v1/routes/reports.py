import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.v1.deps import get_scoped_db
from app.api.v1.queries import latest_asset_scores
from app.api.v1.schemas import QuickReportOut, TopAssetOut, TrendPoint, VulnerabilityOut
from app.cases.sla import OPEN_STATUSES, sla_status
from app.db.models import Asset, Case, CorrelationEvent, KevCatalog, Leak, Observation, Score, Vulnerability

router = APIRouter()

TOP_VULNS = 10
TREND_DAYS = 30
TOP_ASSETS = 5
LEVELS = ("critical", "high", "medium", "low")


@router.get("/tenants/{tenant_id}/reports/quick", response_model=QuickReportOut)
def quick_report(tenant_id: uuid.UUID, db: Session = Depends(get_scoped_db)):
    now = datetime.now(UTC)

    total_assets = db.execute(
        select(func.count()).select_from(Asset).where(Asset.tenant_id == tenant_id)
    ).scalar_one()

    latest = latest_asset_scores(tenant_id).subquery()
    critical_assets = db.execute(
        select(func.count()).select_from(latest).where(latest.c.level == "critical")
    ).scalar_one()

    by_level = dict.fromkeys(LEVELS, 0)
    for level, n in db.execute(select(latest.c.level, func.count()).group_by(latest.c.level)).all():
        if level in by_level:
            by_level[level] = n
    unscored = max(total_assets - sum(by_level.values()), 0)

    top_rows = db.execute(
        select(Asset.id, Asset.hostname, Asset.ip, latest.c.value, latest.c.level)
        .join(latest, latest.c.asset_id == Asset.id)
        .where(Asset.tenant_id == tenant_id)
        .order_by(latest.c.value.desc(), Asset.id)
        .limit(TOP_ASSETS)
    ).all()

    open_case_rows = db.execute(
        select(Case).where(Case.tenant_id == tenant_id, Case.status.in_(OPEN_STATUSES))
    ).scalars().all()
    open_cases = len(open_case_rows)
    sla = [sla_status(c.status, c.created_at, c.due_at, c.closed_at, now) for c in open_case_rows]

    leaks_total = db.execute(
        select(func.count()).select_from(Leak).where(Leak.tenant_id == tenant_id)
    ).scalar_one()
    darkweb_new = sum(
        1
        for (payload,) in db.execute(
            select(Observation.payload).where(
                Observation.tenant_id == tenant_id, Observation.event_type == "darkweb"
            )
        ).all()
        if (payload or {}).get("status", "new") == "new"
    )

    # Vulnerabilities behind the tenant's active correlation events:
    # in CISA KEV first, then by EPSS, then by CVSS.
    vuln_ids = (
        select(CorrelationEvent.vulnerability_id)
        .where(
            CorrelationEvent.tenant_id == tenant_id,
            CorrelationEvent.is_active.is_(True),
            CorrelationEvent.vulnerability_id.isnot(None),
        )
        .distinct()
    )
    vulns = db.execute(
        select(Vulnerability)
        .where(Vulnerability.id.in_(vuln_ids))
        .order_by(
            Vulnerability.kev_date_added.is_(None),
            Vulnerability.epss_score.desc().nulls_last(),
            Vulnerability.cvss_score.desc().nulls_last(),
            Vulnerability.cve_id,
        )
        .limit(TOP_VULNS)
    ).scalars().all()

    kev_count = db.execute(
        select(func.count()).select_from(Vulnerability).where(
            Vulnerability.id.in_(vuln_ids),
            (Vulnerability.kev_date_added.isnot(None))
            | Vulnerability.cve_id.in_(select(KevCatalog.cve_id)),
        )
    ).scalar_one()

    # Daily average of the asset scores computed in the last 30 days
    day = func.date(Score.computed_at)
    trend_rows = db.execute(
        select(day.label("d"), func.avg(Score.value))
        .where(
            Score.tenant_id == tenant_id,
            Score.score_type == "asset",
            Score.computed_at >= now - timedelta(days=TREND_DAYS),
        )
        .group_by(day)
        .order_by(day)
    ).all()

    return QuickReportOut(
        tenant_id=tenant_id,
        generated_at=now,
        total_assets=total_assets,
        critical_assets=critical_assets,
        open_cases=open_cases,
        assets_by_level=by_level,
        unscored_assets=unscored,
        top_assets=[
            TopAssetOut(asset_id=i, hostname=h, ip=ip, value=round(float(v), 4), level=lv)
            for i, h, ip, v, lv in top_rows
        ],
        sla_breached_cases=sla.count("breached"),
        sla_at_risk_cases=sla.count("at_risk"),
        kev_vulnerabilities=kev_count,
        leaks_total=leaks_total,
        darkweb_findings_new=darkweb_new,
        top_vulnerabilities=[VulnerabilityOut.model_validate(v) for v in vulns],
        risk_trend=[TrendPoint(date=d, avg_score=round(float(avg), 4)) for d, avg in trend_rows],
    )
