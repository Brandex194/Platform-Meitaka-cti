"""Case workspace: SLA, notes, timeline (passo 7)."""
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.api.v1.deps import get_scoped_db
from app.auth.jwks import decode_token
from app.db.models import Case, CaseEvent, CaseNote, Tenant
from app.db.session import get_db
from app.main import create_app


def _client_as(db_session, roles, tenant, sub=None):
    """Like the shared fixtures, but the token carries a real user id (the notes keep an author)."""
    app = create_app()
    user_id = sub or str(uuid.uuid4())  # fixed per client: the same user on every request
    app.dependency_overrides[decode_token] = lambda: {
        "sub": user_id,
        "roles": roles,
        "tenant_id": str(tenant.id),
    }
    app.dependency_overrides[get_scoped_db] = lambda: db_session
    app.dependency_overrides[get_db] = lambda: db_session
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def analyst_client(db_session, tenant):
    return _client_as(db_session, ["analyst"], tenant)


def _base(tenant):
    return f"/api/v1/tenants/{tenant.id}/cases"


def _create(client, tenant, **body):
    r = client.post(_base(tenant), json={"title": "Phishing su HR", **body})
    assert r.status_code == 201, r.text
    return r.json()


def _timeline(client, tenant, case_id):
    r = client.get(f"{_base(tenant)}/{case_id}/timeline")
    assert r.status_code == 200
    return list(reversed(r.json()["items"]))  # oldest first, easier to read in assertions


@pytest.mark.parametrize("severity,hours", [("critical", 4), ("high", 24), ("medium", 72), ("low", 168)])
def test_new_case_gets_a_deadline_from_its_severity(analyst_client, tenant, severity, hours):
    case = _create(analyst_client, tenant, severity=severity)
    created = datetime.fromisoformat(case["created_at"])
    due = datetime.fromisoformat(case["due_at"])
    assert due - created == timedelta(hours=hours)
    assert case["sla_status"] == "on_track"
    assert case["closed_at"] is None


def test_changing_severity_moves_the_deadline_and_is_logged(analyst_client, tenant):
    case = _create(analyst_client, tenant, severity="low")
    r = analyst_client.patch(f"{_base(tenant)}/{case['id']}", json={"severity": "critical"})
    assert r.status_code == 200
    created = datetime.fromisoformat(r.json()["created_at"])
    assert datetime.fromisoformat(r.json()["due_at"]) - created == timedelta(hours=4)
    event = _timeline(analyst_client, tenant, case["id"])[-1]
    assert event["event_type"] == "severity_changed"
    assert event["payload"] == {"from": "low", "to": "critical"}


@pytest.mark.parametrize("final", ["closed", "false_positive"])
def test_closing_sets_closed_at_and_reopening_clears_it(analyst_client, tenant, final):
    case = _create(analyst_client, tenant)
    url = f"{_base(tenant)}/{case['id']}"
    closed = analyst_client.patch(url, json={"status": final}).json()
    assert closed["closed_at"] is not None and closed["sla_status"] == "met"
    reopened = analyst_client.patch(url, json={"status": "open"}).json()
    assert reopened["closed_at"] is None and reopened["sla_status"] == "on_track"


def test_overdue_open_case_is_breached(analyst_client, db_session, tenant):
    past = datetime.now(UTC) - timedelta(days=10)
    case = Case(tenant_id=tenant.id, title="old", severity="high", created_at=past, due_at=past + timedelta(hours=24))
    db_session.add(case)
    db_session.flush()
    r = analyst_client.get(f"{_base(tenant)}/{case.id}")
    assert r.json()["sla_status"] == "breached"


def test_timeline_records_what_happened_in_order(analyst_client, tenant):
    case = _create(analyst_client, tenant, severity="medium")
    url = f"{_base(tenant)}/{case['id']}"
    analyst_client.patch(url, json={"status": "in_progress"})
    analyst_client.patch(url, json={"title": "Nuovo titolo"})
    analyst_client.post(f"{url}/notes", json={"body": "Sentito il referente"})
    analyst_client.patch(url, json={"status": "closed"})

    events = _timeline(analyst_client, tenant, case["id"])
    assert [e["event_type"] for e in events] == [
        "created", "status_changed", "edited", "note_added", "status_changed",
    ]
    assert events[1]["payload"] == {"from": "open", "to": "in_progress"}
    assert events[2]["payload"] == {"fields": ["title"]}
    assert events[4]["payload"] == {"from": "in_progress", "to": "closed"}
    assert all(e["actor_id"] for e in events)


def test_patch_with_no_real_change_adds_no_event(analyst_client, tenant):
    case = _create(analyst_client, tenant)
    url = f"{_base(tenant)}/{case['id']}"
    analyst_client.patch(url, json={"status": "open", "title": case["title"]})
    assert len(_timeline(analyst_client, tenant, case["id"])) == 1


def test_notes_add_list_and_delete(analyst_client, tenant):
    case = _create(analyst_client, tenant)
    url = f"{_base(tenant)}/{case['id']}/notes"
    r = analyst_client.post(url, json={"body": "  **Prima** nota  "})
    assert r.status_code == 201
    note = r.json()
    assert note["body"] == "**Prima** nota" and note["author_id"]
    analyst_client.post(url, json={"body": "Seconda"})

    items = analyst_client.get(url).json()["items"]
    assert [n["body"] for n in items] == ["Seconda", "**Prima** nota"]  # newest first

    assert analyst_client.delete(f"{url}/{note['id']}").status_code == 204
    assert analyst_client.get(url).json()["total"] == 1
    assert _timeline(analyst_client, tenant, case["id"])[-1]["event_type"] == "note_deleted"


def test_blank_or_huge_note_rejected(analyst_client, tenant):
    case = _create(analyst_client, tenant)
    url = f"{_base(tenant)}/{case['id']}/notes"
    assert analyst_client.post(url, json={"body": "   "}).status_code == 422
    assert analyst_client.post(url, json={"body": "x" * 20001}).status_code == 422


def test_viewer_reads_but_cannot_write_notes(viewer_client, analyst_client, tenant):
    case = _create(analyst_client, tenant)
    url = f"{_base(tenant)}/{case['id']}"
    assert viewer_client.get(f"{url}/notes").status_code == 200
    assert viewer_client.get(f"{url}/timeline").status_code == 200
    assert viewer_client.post(f"{url}/notes", json={"body": "x"}).status_code == 403


def test_only_author_or_admin_can_delete_a_note(analyst_client, db_session, tenant):
    tenant_admin_client = _client_as(db_session, ["tenant_admin"], tenant)
    case = _create(analyst_client, tenant)
    # a note written by somebody else
    other = CaseNote(
        tenant_id=tenant.id, case_id=uuid.UUID(case["id"]), author_id=uuid.uuid4(), body="altrui"
    )
    db_session.add(other)
    db_session.flush()
    url = f"{_base(tenant)}/{case['id']}/notes/{other.id}"
    assert analyst_client.delete(url).status_code == 403
    assert tenant_admin_client.delete(url).status_code == 204


def test_notes_and_timeline_of_another_tenants_case_are_not_found(analyst_client, db_session, tenant):
    other = Tenant(name="Other", slug="other-notes")
    db_session.add(other)
    db_session.flush()
    foreign = Case(tenant_id=other.id, title="secret")
    db_session.add(foreign)
    db_session.flush()
    url = f"{_base(tenant)}/{foreign.id}"
    assert analyst_client.get(url).status_code == 404
    assert analyst_client.get(f"{url}/notes").status_code == 404
    assert analyst_client.get(f"{url}/timeline").status_code == 404
    assert analyst_client.post(f"{url}/notes", json={"body": "x"}).status_code == 404


def test_deleting_a_case_removes_its_notes_and_timeline(analyst_client, db_session, tenant):
    case = _create(analyst_client, tenant)
    analyst_client.post(f"{_base(tenant)}/{case['id']}/notes", json={"body": "n"})
    assert analyst_client.delete(f"{_base(tenant)}/{case['id']}").status_code == 204
    assert db_session.query(CaseNote).count() == 0
    assert db_session.query(CaseEvent).count() == 0


def test_list_can_filter_by_status(analyst_client, tenant):
    a = _create(analyst_client, tenant, severity="low")
    _create(analyst_client, tenant, severity="high")
    analyst_client.patch(f"{_base(tenant)}/{a['id']}", json={"status": "false_positive"})
    body = analyst_client.get(f"{_base(tenant)}?status=false_positive").json()
    assert body["total"] == 1 and body["items"][0]["id"] == a["id"]
    assert analyst_client.get(f"{_base(tenant)}?status=banana").status_code == 422


def test_in_progress_cases_still_count_as_open_on_the_dashboard(analyst_client, tenant):
    a = _create(analyst_client, tenant)
    _create(analyst_client, tenant)
    analyst_client.patch(f"{_base(tenant)}/{a['id']}", json={"status": "in_progress"})
    dash = analyst_client.get(f"/api/v1/tenants/{tenant.id}/dashboard").json()
    assert dash["open_cases"] == 2
