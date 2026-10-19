"""A short-lived, shared cache for the alert-channel health probes.

Every load of the dashboard used to dial SMTP and Telegram. Two operators with
the page open meant two SMTP handshakes per refresh, and because the probe pool
holds four slots, a handful of people looking at the page could make the fifth
request report "busy" — a fact about the pool, not about the channel. The
question ("can this installation send mail right now?") also changes on the
scale of minutes, so answering it once per ``ALERT_HEALTH_CACHE_SECONDS`` is
enough.

The result is stored in Redis rather than in the process, for the same reason
the rate limiter is: the API runs as several replicas, and a per-process cache
would give each replica its own answer and its own probe (plan decision D6).
The key carries a fingerprint of the settings that decide the answer, so
changing the SMTP host or the Telegram token invalidates the entry without a
delete: the next request asks a different question and therefore has a
different key.

Concurrency is handled with ``SET NX``: the first request takes a short lock
and probes, later requests see the lock and wait for its result inside the same
budget the probe itself has. Without that, the first burst after the TTL expires
would perform one handshake per caller — the thundering herd the cache exists to
prevent.

Redis is never allowed to become a new failure mode (D6): a missing client, a
connection error or an unreadable entry all fall back to probing now, with
``from_cache: false``. The health page must answer even when the cache cannot.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

import structlog

from app.core.config import settings

log = structlog.get_logger()

_KEY_PREFIX = "alerts:health:v1:"
_LOCK_SUFFIX = ":probe"
# How often a waiter re-reads the entry while another request probes. Short
# enough that the answer arrives as soon as it is written, long enough not to
# hammer Redis for the duration of an 18-second SMTP budget.
_POLL_SECONDS = 0.05
_CLIENT_TTL_SECONDS = 30.0

def _testing_mode() -> bool:
    return os.environ.get("TESTING") == "1" or os.environ.get("APP_ENV") == "test"


def _redis_type() -> Any:
    """The Redis client class, or ``None`` in an installation without it.

    Imported lazily rather than at module import: a missing Redis package must
    not stop the API from starting, because the cache is optional by design.
    """
    try:  # pragma: no cover - redis is a runtime dependency
        from redis.asyncio import Redis
    except Exception:  # pragma: no cover - the fallback is "probe every time"
        return None
    return Redis


_CLIENT: Any = None
_CLIENT_TS = 0.0


def _client() -> Any:
    """One Redis client per process, or ``None`` when it cannot be built.

    Tests run without Redis: ``_testing_mode`` returns ``None`` here, and the
    cache tests install their own fake client through this function.
    """
    global _CLIENT, _CLIENT_TS
    if _testing_mode():
        return None
    redis_type = _redis_type()
    if redis_type is None:
        return None
    now = time.monotonic()
    if _CLIENT is not None and now - _CLIENT_TS < _CLIENT_TTL_SECONDS:
        return _CLIENT
    try:
        _CLIENT = redis_type.from_url(
            settings.REDIS_URL, socket_timeout=1.0, socket_connect_timeout=0.5
        )
        _CLIENT_TS = now
    except Exception as exc:
        log.warning("alert_health_cache_client_unavailable", err=str(exc)[:200])
        _CLIENT = None
    return _CLIENT


def reset_client_cache() -> None:
    global _CLIENT, _CLIENT_TS
    _CLIENT = None
    _CLIENT_TS = 0.0


@dataclass(frozen=True)
class ProbeOutcome:
    """What one channel's probe answered, and when.

    ``checked_at`` is when the *probe ran*, not when this response was built.
    The field it replaces was named ``last_checked_at`` but carried
    ``_now()`` — the time of the response — so it read "just checked" on every
    page load even when the last successful handshake was hours old (D7).
    ``from_cache`` says that the fields describe an earlier probe; together they
    make the age of the answer visible instead of implied.
    """

    health: str
    message: str
    latency_ms: int | None
    blocked_reason: str | None
    probe_state: str
    checked_at: str
    from_cache: bool = False


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def fingerprint(*parts: Any) -> str:
    """A stable digest of the settings a cached answer depends on.

    Secrets are hashed, never stored: only the digest reaches the key, so a
    Redis dump does not hand out the SMTP password or the bot token.
    """
    material = "\x1f".join(str(part) for part in parts).encode("utf-8")
    return hashlib.sha256(material).hexdigest()[:32]


def _outcome(result: Any, *, from_cache: bool, checked_at: str | None = None) -> ProbeOutcome:
    return ProbeOutcome(
        health=str(getattr(result, "health", "unknown")),
        message=str(getattr(result, "message", "")),
        latency_ms=getattr(result, "latency_ms", None),
        blocked_reason=getattr(result, "blocked_reason", None),
        probe_state=str(getattr(result, "probe_state", "ok") or "ok"),
        checked_at=checked_at or _now(),
        from_cache=from_cache,
    )


async def _read(client: Any, key: str) -> ProbeOutcome | None:
    try:
        raw = await client.get(key)
    except Exception as exc:
        log.warning("alert_health_cache_read_failed", err=str(exc)[:200])
        return None
    if raw is None:
        return None
    try:
        payload = json.loads(raw)
        # The stored entry was written as a fresh probe; the flag describes this
        # read, not the write, so it is not taken from the payload.
        payload.pop("from_cache", None)
        return ProbeOutcome(**payload, from_cache=True)
    except (ValueError, TypeError, AttributeError):
        # An entry this build cannot read (an older shape, or a corrupt value)
        # is treated as absent. It expires on its own.
        log.warning("alert_health_cache_entry_unreadable")
        return None


async def _write(client: Any, key: str, outcome: ProbeOutcome, ttl_seconds: int) -> None:
    try:
        await client.set(key, json.dumps(asdict(outcome)), ex=ttl_seconds)
    except Exception as exc:
        log.warning("alert_health_cache_write_failed", err=str(exc)[:200])


async def _acquire(client: Any, lock_key: str, ttl_seconds: int) -> bool:
    try:
        return bool(await client.set(lock_key, "1", nx=True, ex=ttl_seconds))
    except Exception as exc:
        # Without a lock every request probes for itself, which is exactly the
        # behaviour before the cache; that is safe, just more expensive.
        log.warning("alert_health_cache_lock_failed", err=str(exc)[:200])
        return False


async def _release(client: Any, lock_key: str) -> None:
    try:
        await client.delete(lock_key)
    except Exception as exc:
        # The lock has a TTL, so a failed delete delays the next probe rather
        # than wedging the channel.
        log.warning("alert_health_cache_unlock_failed", err=str(exc)[:200])


async def probe_with_cache(
    *,
    channel: str,
    fingerprint: str,
    ttl_seconds: int,
    wait_budget_seconds: float,
    probe: Callable[[], Awaitable[Any]],
) -> ProbeOutcome:
    """Return this channel's answer, probing only when the cache cannot."""
    client = _client()
    if client is None or ttl_seconds <= 0:
        return _outcome(await probe(), from_cache=False)

    key = f"{_KEY_PREFIX}{channel}:{fingerprint}"
    cached = await _read(client, key)
    if cached is not None:
        return cached

    lock_key = key + _LOCK_SUFFIX
    # The lock outlives the probe budget by a few seconds: a holder that dies
    # without releasing it must not leave later requests waiting forever.
    if await _acquire(client, lock_key, int(ttl_seconds + wait_budget_seconds) + 5):
        try:
            outcome = _outcome(await probe(), from_cache=False)
            await _write(client, key, outcome, ttl_seconds)
            return outcome
        finally:
            await _release(client, lock_key)

    deadline = time.monotonic() + wait_budget_seconds
    while time.monotonic() < deadline:
        await asyncio.sleep(_POLL_SECONDS)
        cached = await _read(client, key)
        if cached is not None:
            return cached

    # The holder outlived the budget (a hung socket, or a replica that died
    # mid-probe). Asking ourselves is what this endpoint did before the cache.
    return _outcome(await probe(), from_cache=False)
