"""Dependency probes behind the readiness endpoint.

The probes live outside the HTTP layer so a test can replace one probe instead
of stubbing a database engine or a Redis client.
"""

from __future__ import annotations

import asyncio

from sqlalchemy import text

from app.core import database
from app.core.config import settings

# A readiness probe must answer faster than the orchestrator's own timeout,
# otherwise a replica is restarted while its probe is still blocked.
_PROBE_TIMEOUT_SECONDS = 1.5


async def _ping_database() -> None:
    # ``database.engine`` is read at call time (not imported as an object) so the
    # test suite can swap the engine per test.
    async with database.engine.connect() as connection:
        await connection.execute(text("SELECT 1"))


async def check_database() -> None:
    """Raise when the database cannot answer a trivial statement, within bounds.

    Bounded because both of the driver's own waits are longer than a probe may
    take: a server that accepts the TCP connection and then never answers is
    covered by ``DB_STATEMENT_TIMEOUT_MS`` (30s by default), and an unreachable
    host by the OS connect timeout, while the pool itself waits
    ``DB_POOL_TIMEOUT_SECONDS`` (30s) for a free connection. ``/api/v1/ready``
    would hold the load balancer's request for that whole time and report nothing,
    which is the one outcome a probe must not produce.

    A saturated pool therefore counts as unready, and deliberately so: an instance
    that cannot obtain a connection within the bound is not able to serve the
    request the balancer is about to send it.
    """
    await asyncio.wait_for(_ping_database(), timeout=_PROBE_TIMEOUT_SECONDS)


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
