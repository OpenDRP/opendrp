"""Distributed admission control for external-provider scans.

Manual user throttles are not enough: two users, the scheduler and several API
replicas can otherwise enqueue the same provider work at the same time. This
small Redis-backed guard coalesces work per connector while keeping the core
stateless. The guard is fail-closed outside tests because allowing a scan during
a Redis outage can spend a provider quota repeatedly.
"""

from __future__ import annotations

import os
import secrets
from typing import Any, Awaitable, cast

from fastapi import HTTPException

from app.core.exceptions import BadRequestException
from app.core.rate_limit import RateLimiter

SCAN_ADMISSION_PREFIX = "scan:admission:"


class NoEnabledConnector(BadRequestException):
    """The requested connector is not registered and enabled."""


class ScanAlreadyRunning(HTTPException):
    """The connector already has pending or running scan work."""

    def __init__(self, connector: str):
        self.connector = connector
        super().__init__(
            status_code=409,
            detail=(
                f"A scan for connector '{connector}' is already pending or running. "
                "Use Jobs history to follow it instead of starting another scan."
            ),
        )


class ScanAdmissionUnavailable(HTTPException):
    """Redis cannot enforce the provider-credit safety guard."""

    def __init__(self):
        super().__init__(
            status_code=503,
            detail=(
                "Scan admission control is temporarily unavailable. "
                "Retry after Redis connectivity is restored."
            ),
            headers={"Retry-After": "10"},
        )


def _testing_mode() -> bool:
    return os.environ.get("TESTING") == "1" or os.environ.get("APP_ENV") == "test"


def admission_key(connector: str) -> str:
    return f"{SCAN_ADMISSION_PREFIX}{connector}"


async def acquire(connector: str, ttl_seconds: int) -> str | None:
    """Acquire a connector scan slot, or raise when it cannot be acquired.

    Tests deliberately bypass Redis because their fixtures do not run a broker;
    the database job assertions still exercise the enqueue path. Production and
    development installations fail closed when Redis is unavailable.
    """
    if _testing_mode():
        return None
    client = RateLimiter._get_client()
    if client is None:
        raise ScanAdmissionUnavailable()
    token = secrets.token_urlsafe(24)
    try:
        claimed = await client.set(
            admission_key(connector), token, nx=True, ex=max(300, int(ttl_seconds))
        )
    except Exception as exc:
        RateLimiter._reset_client()
        raise ScanAdmissionUnavailable() from exc
    if not claimed:
        raise ScanAlreadyRunning(connector)
    return token


async def release(connector: str, token: str | None = None) -> None:
    """Release a slot only if this process still owns it."""
    if _testing_mode():
        return
    client = RateLimiter._get_client()
    if client is None or not token:
        return
    try:
        await cast(
            Awaitable[Any],
            client.eval(
                "if redis.call('get', KEYS[1]) == ARGV[1] then "
                "return redis.call('del', KEYS[1]) else return 0 end",
                1,
                admission_key(connector),
                token,
            ),
        )
    except Exception:
        # TTL is the recovery path. Do not turn a completed provider scan into
        # an API failure merely because cleanup could not reach Redis.
        RateLimiter._reset_client()
