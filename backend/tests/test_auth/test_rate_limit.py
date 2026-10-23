import uuid
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from app.auth.rate_limit import check_rate_limit


def _mock_redis(incr_value: int) -> MagicMock:
    r = MagicMock()
    r.incr.return_value = incr_value
    return r


def test_rate_limit_allows_under_limit():
    check_rate_limit(uuid.uuid4(), _mock_redis(50))  # should not raise


def test_rate_limit_blocks_over_limit():
    with pytest.raises(HTTPException) as exc_info:
        check_rate_limit(uuid.uuid4(), _mock_redis(101))
    assert exc_info.value.status_code == 429
