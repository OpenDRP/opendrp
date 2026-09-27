"""Dependency probes behind the readiness endpoint.

The probes live outside the HTTP layer so a test can replace one probe instead
of stubbing a database engine or a Redis client.
"""

from __future__ import annotations

from sqlalchemy import text

from app.core import database
from app.core.config import settings

# A readiness probe must answer faster than the orchestrator's own timeout,
# otherwise a replica is restarted while its probe is still blocked.
_PROBE_TIMEOUT_SECONDS = 1.5


async def check_database() -> None:
    """Raise when the database cannot answer a trivial statement.

    ``database.engine`` is read at call time (not imported as an object) so the
    test suite can swap the engine per test.
    """
    async with database.engine.connect() as connection:
        await connection.execute(text("SELECT 1"))


async def check_redis() -> None:
    """Raise when Redis cannot answer PING."""
    from redis.asyncio import Redis

    client = Redis.from_url(
        settings.REDIS_URL,
        socket_timeout=_PROBE_TIMEOUT_SECONDS,
        socket_connect_timeout=_PROBE_TIMEOUT_SECONDS,
    )
    try:
        await client.ping()
    finally:
        await client.aclose()
