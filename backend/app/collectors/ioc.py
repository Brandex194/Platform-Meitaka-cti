"""IoC collector stub."""
import logging

from app.core.config import get_settings

logger = logging.getLogger(__name__)


def fetch_ioc() -> int:
    """Returns 0 if disabled; logs and returns 0 when enabled (not yet implemented)."""
    if not get_settings().ioc_collector_enabled:
        return 0
    logger.info("IoC collector not implemented")
    return 0
