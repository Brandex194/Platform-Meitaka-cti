import uuid

from fastapi import HTTPException

from app.core.errors import error_response

_WINDOW_SECONDS = 60
_MAX_REQUESTS = 100


def check_rate_limit(tenant_id: uuid.UUID, redis_client) -> None:
    key = f"rl:{tenant_id}"
    count = redis_client.incr(key)
    if count == 1:
        redis_client.expire(key, _WINDOW_SECONDS)
    if count > _MAX_REQUESTS:
        raise HTTPException(
            status_code=429,
            detail=error_response("RATE_LIMIT_EXCEEDED", "Rate limit exceeded"),
        )
