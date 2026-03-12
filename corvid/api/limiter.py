"""Shared slowapi rate limiter instance.

Defined here to avoid circular imports between main.py (which registers
the exception handler) and route modules (which apply per-endpoint limits).
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

from corvid.config import settings

# Single shared limiter used by all route modules.
# The default_limits applies to every endpoint unless overridden with @limiter.limit(...).
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[f"{settings.rate_limit_per_minute}/minute"],
)
