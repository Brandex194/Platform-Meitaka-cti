from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException

from app.api.v1.errors import http_exception_handler, validation_exception_handler
from app.api.v1.router import api_router
from app.core.middleware import setup_middleware


def create_app() -> FastAPI:
    app = FastAPI(title="Sentinel AI", version="1.0.0")
    setup_middleware(app)
    app.include_router(api_router, prefix="/api/v1")
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    return app


app = create_app()
