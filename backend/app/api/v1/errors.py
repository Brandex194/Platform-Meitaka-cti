from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from app.core.errors import error_response

__all__ = ["error_response"]

_CODE_MAP = {
    401: "UNAUTHORIZED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    422: "VALIDATION_ERROR",
    429: "RATE_LIMIT_EXCEEDED",
}


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    # Preserve already-wrapped error model
    if isinstance(exc.detail, dict) and "error" in exc.detail:
        return JSONResponse(status_code=exc.status_code, content=exc.detail)
    code = _CODE_MAP.get(exc.status_code, "HTTP_ERROR")
    return JSONResponse(status_code=exc.status_code, content=error_response(code, str(exc.detail)))


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content=error_response("VALIDATION_ERROR", "Request validation failed", {"errors": exc.errors()}),
    )
