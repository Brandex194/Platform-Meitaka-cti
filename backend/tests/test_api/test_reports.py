from datetime import UTC, date, datetime, timedelta


def test_quick_report_empty_tenant(viewer_client, tenant):
    body = viewer_client.get(f"/api/v1/tenants/{tenant.id}/reports/quick").json()
    assert body["tenant_id"] == str(tenant.id)
    assert body["total_assets"] == 0
    assert body["top_vulnerabilities"] == []
    assert body["risk_trend"] == []


def test_quick_report_orders_kev_first_then_epss(viewer_client, db_session, tenant, asset):
    """CVE ids and KEV date are real (CVE-2021-41773 is in CISA KEV since 2021-11-03);
    EPSS/CVSS values here are test inputs, not claims about the live feeds."""
    from app.db.models import CorrelationEvent, Score, Vulnerability

    kev = Vulnerability(cve_id="CVE-2021-41773", cvss_score=7.5, epss_score=0.5, kev_date_added=date(2021, 11, 3))
    high_epss = Vulnerability(cve_id="CVE-2023-0001", cvss_score=9.8, epss_score=0.9)
    resolved = Vulnerability(cve_id="CVE-2023-0002", cvss_score=10.0, epss_score=0.99)
    db_session.add_all([kev, high_epss, resolved])
    db_session.flush()
    db_session.add_all([
        CorrelationEvent(tenant_id=tenant.id, rule_name="vuln_software", asset_id=asset.id, vulnerability_id=kev.id),
        CorrelationEvent(tenant_id=tenant.id, rule_name="vuln_software", asset_id=asset.id, vulnerability_id=high_epss.id),
        CorrelationEvent(tenant_id=tenant.id, rule_name="vuln_software", asset_id=asset.id,
                         vulnerability_id=resolved.id, is_active=False),
    ])
    now = datetime.now(UTC)
    db_session.add(Score(tenant_id=tenant.id, asset_id=asset.id, score_type="asset", value=0.95,
                         level="critical", computed_at=now - timedelta(hours=1)))
    db_session.flush()

    body = viewer_client.get(f"/api/v1/tenants/{tenant.id}/reports/quick").json()
    assert [v["cve_id"] for v in body["top_vulnerabilities"]] == ["CVE-2021-41773", "CVE-2023-0001"]
    assert body["total_assets"] == 1
    assert body["critical_assets"] == 1
    assert len(body["risk_trend"]) == 1 and body["risk_trend"][0]["avg_score"] == 0.95


def test_quick_report_summary_sections(viewer_client, db_session, tenant, asset):
    from app.db.models import Case, KevCatalog, Leak, Observation, Score, Vulnerability, CorrelationEvent

    now = datetime.now(UTC)
    db_session.add(Score(tenant_id=tenant.id, asset_id=asset.id, score_type="asset", value=0.5,
                         level="high", computed_at=now))
    # one open case past its deadline, one still within it, one closed
    db_session.add_all([
        Case(tenant_id=tenant.id, title="late", status="open", severity="high",
             created_at=now - timedelta(days=3), due_at=now - timedelta(days=2)),
        Case(tenant_id=tenant.id, title="fine", status="open", severity="low",
             created_at=now, due_at=now + timedelta(days=7)),
        Case(tenant_id=tenant.id, title="done", status="closed", severity="high",
             created_at=now - timedelta(days=3), due_at=now - timedelta(days=2), closed_at=now),
    ])
    v = Vulnerability(cve_id="CVE-2024-9999", cvss_score=7.0)  # not flagged on the row itself
    db_session.add(v)
    db_session.flush()
    db_session.add(KevCatalog(cve_id="CVE-2024-9999"))
    db_session.add(CorrelationEvent(tenant_id=tenant.id, rule_name="vuln_software", asset_id=asset.id,
                                    vulnerability_id=v.id))
    db_session.add_all([
        Leak(tenant_id=tenant.id, email_hash="a" * 64, breach_name="B"),
        Observation(tenant_id=tenant.id, event_type="darkweb", payload={"status": "new"}),
        Observation(tenant_id=tenant.id, event_type="darkweb", payload={"status": "dismissed"}),
        Observation(tenant_id=tenant.id, event_type="scan", payload={}),
    ])
    db_session.flush()

    body = viewer_client.get(f"/api/v1/tenants/{tenant.id}/reports/quick").json()
    assert body["assets_by_level"] == {"critical": 0, "high": 1, "medium": 0, "low": 0}
    assert body["unscored_assets"] == 0
    assert [a["asset_id"] for a in body["top_assets"]] == [str(asset.id)]
    assert body["top_assets"][0]["value"] == 0.5
    assert body["open_cases"] == 2
    assert body["sla_breached_cases"] == 1
    assert body["kev_vulnerabilities"] == 1
    assert body["leaks_total"] == 1
    assert body["darkweb_findings_new"] == 1


def test_quick_report_does_not_count_other_tenants(viewer_client, db_session, tenant):
    import uuid

    from app.db.models import Leak, Tenant

    other = Tenant(id=uuid.uuid4(), name="other", slug="other", sector="technology")
    db_session.add(other)
    db_session.flush()
    db_session.add(Leak(tenant_id=other.id, email_hash="b" * 64, breach_name="B"))
    db_session.flush()
    body = viewer_client.get(f"/api/v1/tenants/{tenant.id}/reports/quick").json()
    assert body["leaks_total"] == 0
    assert body["assets_by_level"] == {"critical": 0, "high": 0, "medium": 0, "low": 0}
