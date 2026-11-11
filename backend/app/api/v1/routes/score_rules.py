import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.v1.deps import get_scoped_db
from app.auth.roles import Role, require_roles
from app.core.errors import error_response
from app.db.models import AuditLog, ScoreRule
from app.risk.formulas import (
    DEFAULT_PARAMETERS,
    FORMULA,
    KNOWN_FORMULAS,
    WEIGHTS_BY_FORMULA,
)

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


class ScoreRuleThresholds(BaseModel):
    """Upper bound of each level (Architettura §5.3): below `low` → low, … , from `high` → critical."""
    low: float = Field(..., gt=0, lt=1)
    medium: float = Field(..., gt=0, lt=1)
    high: float = Field(..., gt=0, lt=1)

    @model_validator(mode="after")
    def check_order(self) -> "ScoreRuleThresholds":
        if not (self.low < self.medium < self.high):
            raise ValueError("thresholds must satisfy low < medium < high")
        return self


def _check_factor(name: str, value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
        raise ValueError(f"{name} must be a number between 0 and 1")


class ScoreRuleIn(BaseModel):
    weights: Optional[ScoreRuleWeights] = None
    thresholds: Optional[ScoreRuleThresholds] = None
    # Overrides of app.risk.formulas.DEFAULT_PARAMETERS (exposure/impact factors, α, defaults...)
    parameters: Optional[dict] = None

    @field_validator("parameters")
    @classmethod
    def check_parameters(cls, v: Optional[dict]) -> Optional[dict]:
        if v is None:
            return v
        for key, value in v.items():
            if key == "formula":
                if value not in KNOWN_FORMULAS:
                    raise ValueError(f"formula must be one of {', '.join(KNOWN_FORMULAS)}")
                continue
            if key not in DEFAULT_PARAMETERS:
                raise ValueError(f"unknown parameter {key!r}")
            default = DEFAULT_PARAMETERS[key]
            if isinstance(default, dict):
                if not isinstance(value, dict):
                    raise ValueError(f"{key} must be an object")
                for sub, factor in value.items():
                    _check_factor(f"{key}.{sub}", factor)
            elif key == "recency_steps":
                ok = isinstance(value, list) and all(
                    isinstance(step, list) and len(step) == 2 and isinstance(step[0], (int, float)) and step[0] > 0
                    for step in value
                )
                if not ok:
                    raise ValueError("recency_steps must be a list of [max_days, value]")
                for step in value:
                    _check_factor("recency_steps value", step[1])
            else:
                _check_factor(key, value)
        return v


class ScoreRuleUpdate(ScoreRuleIn):
    pass


def _parameters(body_params: Optional[dict], current: Optional[dict] = None) -> dict:
    """Keep the rule's formula unless the body names another; rules without one get the default."""
    params = {**(current or {}), **(body_params or {})}
    if params.get("formula") not in KNOWN_FORMULAS:
        params["formula"] = FORMULA
    return params


def _rule_to_dict(rule: ScoreRule) -> dict:
    return {
        "id": str(rule.id),
        "tenant_id": str(rule.tenant_id) if rule.tenant_id else None,
        "version": rule.version,
        "weights": rule.weights,
        "thresholds": rule.thresholds,
        "parameters": rule.parameters,
    }


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
        kwargs["thresholds"] = body.thresholds.model_dump()
    kwargs["parameters"] = _parameters(body.parameters)
    kwargs.setdefault("weights", dict(WEIGHTS_BY_FORMULA[kwargs["parameters"]["formula"]]))
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
        rule.thresholds = body.thresholds.model_dump()
    rule.parameters = _parameters(body.parameters, rule.parameters)
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
