from fastapi import APIRouter

from app.api.v1.routes import assets, dashboard, exposure, health, score_rules, scores

api_router = APIRouter()

api_router.include_router(health.router)
api_router.include_router(assets.router)
api_router.include_router(scores.router)
api_router.include_router(exposure.router)
api_router.include_router(score_rules.router)
api_router.include_router(dashboard.router)
