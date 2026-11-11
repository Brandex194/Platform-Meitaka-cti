import uuid
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.api.v1.deps import get_scoped_db
from app.api.v1.pagination import PageParams, page_params, paginate
from app.api.v1.schemas import CaseEventOut, CaseNoteOut, CaseOut, Page
from app.auth.roles import Role, require_roles
from app.cases.sla import CLOSED_STATUSES, due_at_for
from app.core.errors import error_response
from app.db.models import Case, CaseEvent, CaseNote

router = APIRouter()

_CASE_WRITERS = (Role.super_admin, Role.tenant_admin, Role.analyst)
Severity = Literal["low", "medium", "high", "critical"]
Status = Literal["open", "in_progress", "closed", "false_positive"]


class CaseIn(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    description: str | None = Field(None, max_length=10000)
    severity: Severity = "medium"


class CaseUpdate(BaseModel):
    title: str | None = Field(None, min_length=1, max_length=500)
    description: str | None = Field(None, max_length=10000)
    severity: Severity | None = None
    status: Status | None = None


class NoteIn(BaseModel):
    body: str = Field(..., min_length=1, max_length=20000)

    @field_validator("body")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("note must not be blank")
        return v.strip()


def _actor_id(token: dict) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(token.get("sub")))
    except (ValueError, TypeError):
        return None


def _roles(token: dict) -> list:
    return token.get("roles") or token.get("realm_access", {}).get("roles", [])


def _get_case(db: Session, tenant_id: uuid.UUID, case_id: uuid.UUID) -> Case:
    case = db.execute(
        select(Case).where(Case.id == case_id, Case.tenant_id == tenant_id)
    ).scalar_one_or_none()
    if case is None:
        raise HTTPException(status_code=404, detail=error_response("NOT_FOUND", "Case not found"))
    return case


def _log(db: Session, case: Case, actor: uuid.UUID | None, event_type: str, payload: dict | None = None) -> None:
    db.add(
        CaseEvent(
            tenant_id=case.tenant_id,
            case_id=case.id,
            actor_id=actor,
            event_type=event_type,
            payload=payload,
            created_at=datetime.now(UTC),
        )
    )


@router.get("/tenants/{tenant_id}/cases", response_model=Page[CaseOut])
def list_cases(
    tenant_id: uuid.UUID,
    status: Status | None = Query(None),
    db: Session = Depends(get_scoped_db),
    params: PageParams = Depends(page_params),
):
    stmt = select(Case).where(Case.tenant_id == tenant_id)
    if status:
        stmt = stmt.where(Case.status == status)
    stmt = stmt.order_by(Case.created_at.desc(), Case.id)
    return paginate(db, stmt, params, CaseOut)


@router.get("/tenants/{tenant_id}/cases/{case_id}", response_model=CaseOut)
def get_case(
    tenant_id: uuid.UUID,
    case_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
):
    return _get_case(db, tenant_id, case_id)


@router.post("/tenants/{tenant_id}/cases", status_code=201, response_model=CaseOut)
def create_case(
    tenant_id: uuid.UUID,
    body: CaseIn,
    db: Session = Depends(get_scoped_db),
    token: dict = Depends(require_roles(*_CASE_WRITERS)),
):
    now = datetime.now(UTC)
    case = Case(
        tenant_id=tenant_id,
        title=body.title,
        description=body.description,
        severity=body.severity,
        status="open",
        created_by=_actor_id(token),
        created_at=now,
        updated_at=now,
        due_at=due_at_for(body.severity, now),
    )
    db.add(case)
    db.flush()
    _log(db, case, _actor_id(token), "created", {"severity": case.severity})
    db.flush()
    db.refresh(case)
    return case


@router.patch("/tenants/{tenant_id}/cases/{case_id}", response_model=CaseOut)
def update_case(
    tenant_id: uuid.UUID,
    case_id: uuid.UUID,
    body: CaseUpdate,
    db: Session = Depends(get_scoped_db),
    token: dict = Depends(require_roles(*_CASE_WRITERS)),
):
    case = _get_case(db, tenant_id, case_id)
    actor = _actor_id(token)
    now = datetime.now(UTC)
    changes = {k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None}

    old_status, old_severity = case.status, case.severity
    edited = [f for f in ("title", "description") if f in changes and changes[f] != getattr(case, f)]
    for field, value in changes.items():
        setattr(case, field, value)

    if case.status != old_status:
        _log(db, case, actor, "status_changed", {"from": old_status, "to": case.status})
        if case.status in CLOSED_STATUSES:
            case.closed_at = now
        else:
            case.closed_at = None  # reopened: the SLA counts again
    if case.severity != old_severity:
        _log(db, case, actor, "severity_changed", {"from": old_severity, "to": case.severity})
        case.due_at = due_at_for(case.severity, case.created_at)
    if edited:
        _log(db, case, actor, "edited", {"fields": edited})

    case.updated_at = now
    db.flush()
    db.refresh(case)
    return case


@router.delete("/tenants/{tenant_id}/cases/{case_id}", status_code=204)
def delete_case(
    tenant_id: uuid.UUID,
    case_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(*_CASE_WRITERS)),
):
    case = _get_case(db, tenant_id, case_id)
    # Postgres cascades through the foreign keys; deleting here keeps it true on any database.
    db.execute(delete(CaseNote).where(CaseNote.case_id == case.id))
    db.execute(delete(CaseEvent).where(CaseEvent.case_id == case.id))
    db.delete(case)
    db.flush()


# ---------------------------------------------------------------------------
# Notes and timeline
# ---------------------------------------------------------------------------


@router.get("/tenants/{tenant_id}/cases/{case_id}/notes", response_model=Page[CaseNoteOut])
def list_notes(
    tenant_id: uuid.UUID,
    case_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    params: PageParams = Depends(page_params),
):
    _get_case(db, tenant_id, case_id)
    stmt = (
        select(CaseNote)
        .where(CaseNote.case_id == case_id, CaseNote.tenant_id == tenant_id)
        .order_by(CaseNote.created_at.desc(), CaseNote.id)
    )
    return paginate(db, stmt, params, CaseNoteOut)


@router.post("/tenants/{tenant_id}/cases/{case_id}/notes", status_code=201, response_model=CaseNoteOut)
def add_note(
    tenant_id: uuid.UUID,
    case_id: uuid.UUID,
    body: NoteIn,
    db: Session = Depends(get_scoped_db),
    token: dict = Depends(require_roles(*_CASE_WRITERS)),
):
    case = _get_case(db, tenant_id, case_id)
    note = CaseNote(
        tenant_id=tenant_id,
        case_id=case.id,
        author_id=_actor_id(token),
        body=body.body,
        created_at=datetime.now(UTC),
    )
    db.add(note)
    db.flush()
    _log(db, case, _actor_id(token), "note_added", {"note_id": str(note.id)})
    db.flush()
    db.refresh(note)
    return note


@router.delete("/tenants/{tenant_id}/cases/{case_id}/notes/{note_id}", status_code=204)
def delete_note(
    tenant_id: uuid.UUID,
    case_id: uuid.UUID,
    note_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    token: dict = Depends(require_roles(*_CASE_WRITERS)),
):
    """The author removes their own note; tenant_admin and super_admin can remove any."""
    case = _get_case(db, tenant_id, case_id)
    note = db.execute(
        select(CaseNote).where(CaseNote.id == note_id, CaseNote.case_id == case.id, CaseNote.tenant_id == tenant_id)
    ).scalar_one_or_none()
    if note is None:
        raise HTTPException(status_code=404, detail=error_response("NOT_FOUND", "Note not found"))
    roles = _roles(token)
    is_admin = Role.tenant_admin.value in roles or Role.super_admin.value in roles
    if not is_admin and note.author_id != _actor_id(token):
        raise HTTPException(
            status_code=403,
            detail=error_response("FORBIDDEN", "Only the author or an admin can delete this note"),
        )
    db.delete(note)
    _log(db, case, _actor_id(token), "note_deleted", {"note_id": str(note_id)})
    db.flush()


@router.get("/tenants/{tenant_id}/cases/{case_id}/timeline", response_model=Page[CaseEventOut])
def case_timeline(
    tenant_id: uuid.UUID,
    case_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    params: PageParams = Depends(page_params),
):
    _get_case(db, tenant_id, case_id)
    stmt = (
        select(CaseEvent)
        .where(CaseEvent.case_id == case_id, CaseEvent.tenant_id == tenant_id)
        .order_by(CaseEvent.created_at.desc(), CaseEvent.id)
    )
    return paginate(db, stmt, params, CaseEventOut)
