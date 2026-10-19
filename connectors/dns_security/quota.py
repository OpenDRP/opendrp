"""Redis-shared request quota guard for VirusTotal public-tier use.

The API endpoint is the production authority so independently scaled connector
containers share the same Redis counters. This module keeps the Redis primitive
unit-testable and documents the window semantics used by that API.
"""
from __future__ import annotations

from datetime import datetime, timezone

SCRIPT = """
local minute = tonumber(redis.call('get', KEYS[1]) or '0')
local day = tonumber(redis.call('get', KEYS[2]) or '0')
if minute >= 4 then return {0, redis.call('ttl', KEYS[1]), 'minute'} end
if day >= 500 then return {0, redis.call('ttl', KEYS[2]), 'day'} end
minute = redis.call('incr', KEYS[1])
day = redis.call('incr', KEYS[2])
if minute == 1 then redis.call('expire', KEYS[1], 120) end
if day == 1 then redis.call('expire', KEYS[2], 90000) end
return {1, 0, 'ok'}
"""


def quota_keys(now: datetime | None = None) -> tuple[str, str]:
    instant = now or datetime.now(timezone.utc)
    return (
        f"quota:virustotal:minute:{instant.strftime('%Y%m%d%H%M')}",
        f"quota:virustotal:day:{instant.strftime('%Y%m%d')}",
    )
