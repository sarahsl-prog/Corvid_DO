"""Shared FastAPI dependencies (DB sessions, auth, etc.).

The get_db dependency is defined in corvid.db.session and re-exported here
for convenience. Additional dependencies (auth, rate limiting) will be added
in later phases.
"""

from corvid.db.session import get_db

__all__ = ["get_db"]
