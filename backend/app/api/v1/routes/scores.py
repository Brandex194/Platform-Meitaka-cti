import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.v1.deps import get_scoped_db
from app.api.v1.pagination import PageParams, page_params, paginate
from app.api.v1.queries import latest_asset_scores
from app.api.v1.schemas import Page, ScoreOut
from app.auth.roles import Role, require_roles
from app.db.models import Score
from app.core.errors import error_response
from app.risk.engine import explain_asset, run_for_tenant

router = APIRouter()


@router.get("/tenants/{tenant_id}/scores", response_model=Page[ScoreOut])
def list_scores(
    tenant_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    params: PageParams = Depends(page_params),
):
    """Latest score per asset (not the full history), highest first."""
    stmt = latest_asset_scores(tenant_id).order_by(Score.value.desc(), Score.id)
    return paginate(db, stmt, params, ScoreOut)


@router.post("/tenants/{tenant_id}/scores/compute")
def compute_scores(
    tenant_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
    _: dict = Depends(require_roles(Role.super_admin, Role.tenant_admin, Role.analyst)),
):
    return run_for_tenant(tenant_id, db=db)


@router.get("/tenants/{tenant_id}/assets/{asset_id}/score-explanation")
def score_explanation(
    tenant_id: uuid.UUID,
    asset_id: uuid.UUID,
    db: Session = Depends(get_scoped_db),
):
    """Why an asset has its score: context factors and every finding with its contribution."""
    out = explain_asset(tenant_id, asset_id, db)
    if out is None:
        raise HTTPException(status_code=404, detail=error_response("NOT_FOUND", "Asset not found"))
    return out
