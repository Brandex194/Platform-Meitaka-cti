from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from app.core.errors import error_response

__all__ = ["error_response"]


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    # Preserve error model if already wrapped
    if isinstance(exc.detail, dict) and "error" in exc.detail:
        content = exc.detail
    else:
        content = error_response("HTTP_ERROR", str(exc.detail))
    return JSONResponse(status_code=exc.status_code, content=content)


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content=error_response("VALIDATION_ERROR", "Request validation failed", {"errors": exc.errors()}),
    )
