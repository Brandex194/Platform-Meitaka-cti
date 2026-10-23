import uuid
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.roles import Role, require_roles
from app.db.models import AuditLog, ScoreRule
from app.db.session import get_db

router = APIRouter()


class ScoreRuleIn(BaseModel):
    weights: Optional[dict] = None
    thresholds: Optional[dict] = None


@router.post("/tenants/{tenant_id}/score-rules", status_code=201)
def create_score_rule(
    tenant_id: uuid.UUID,
    body: ScoreRuleIn,
    db: Session = Depends(get_db),
    payload: dict = Depends(require_roles(Role.super_admin)),
):
    # Auto-increment version per tenant
    max_ver = db.execute(
        select(ScoreRule.version)
        .where((ScoreRule.tenant_id == tenant_id) | (ScoreRule.tenant_id == None))
        .order_by(ScoreRule.version.desc())
        .limit(1)
    ).scalar_one_or_none()
    version = (max_ver or 0) + 1

    kwargs: dict = {"tenant_id": tenant_id, "version": version}
    if body.weights is not None:
        kwargs["weights"] = body.weights
    if body.thresholds is not None:
        kwargs["thresholds"] = body.thresholds
    rule = ScoreRule(**kwargs)
    db.add(rule)
    db.flush()

    db.add(AuditLog(
        tenant_id=tenant_id,
        action="create_score_rule",
        resource_type="score_rule",
        resource_id=rule.id,
        payload={"version": version},
    ))
    db.flush()

    return {"id": str(rule.id), "version": rule.version, "weights": rule.weights, "thresholds": rule.thresholds}
