import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.v1.deps import get_scoped_db
from app.auth.roles import Role, require_roles
from app.core.errors import error_response
from app.db.models import AuditLog, ScoreRule

router = APIRouter()


class ScoreRuleWeights(BaseModel):
    severity: float
    confidence: float
    recency: float
    epss: float

    @model_validator(mode="after")
    def check_sum(self) -> "ScoreRuleWeights":
        total = self.severity + self.confidence + self.recency + self.epss
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"weights must sum to 1.0, got {total}")
        return self


class ScoreRuleIn(BaseModel):
    weights: Optional[ScoreRuleWeights] = None
    thresholds: Optional[dict] = None


class ScoreRuleUpdate(BaseModel):
    weights: Optional[ScoreRuleWeights] = None
    thresholds: Optional[dict] = None


def _rule_to_dict(rule: ScoreRule) -> dict:
    return {"id": str(rule.id), "version": rule.version, "weights": rule.weights, "thresholds": rule.thresholds}


@router.post("/tenants/{tenant_id}/score-rules", status_code=201)
def create_score_rule(
    tenant_id: uuid.UUID,
    body: ScoreRuleIn,
    db: Session = Depends(get_scoped_db),
    payload: dict = Depends(require_roles(Role.super_admin)),
):
    max_ver = db.execute(
        select(ScoreRule.version)
        .where((ScoreRule.tenant_id == tenant_id) | (ScoreRule.tenant_id == None))
        .order_by(ScoreRule.version.desc())
        .limit(1)
    ).scalar_one_or_none()
    version = (max_ver or 0) + 1

    kwargs: dict = {"tenant_id": tenant_id, "version": version}
    if body.weights is not None:
        kwargs["weights"] = body.weights.model_dump()
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
    return _rule_to_dict(rule)


@router.patch("/tenants/{tenant_id}/score-rules/{rule_id}")
def patch_score_rule(
    tenant_id: uuid.UUID,
    rule_id: uuid.UUID,
    body: ScoreRuleUpdate,
    db: Session = Depends(get_scoped_db),
    payload: dict = Depends(require_roles(Role.super_admin)),
):
    rule = db.execute(
        select(ScoreRule).where(ScoreRule.id == rule_id, ScoreRule.tenant_id == tenant_id)
    ).scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail=error_response("NOT_FOUND", "ScoreRule not found"))

    if body.weights is not None:
        rule.weights = body.weights.model_dump()
    if body.thresholds is not None:
        rule.thresholds = body.thresholds
    rule.version += 1

    db.add(AuditLog(
        tenant_id=tenant_id,
        action="update_score_rule",
        resource_type="score_rule",
        resource_id=rule.id,
        payload={"version": rule.version},
    ))
    db.flush()
    return _rule_to_dict(rule)
