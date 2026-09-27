"""Tests for the per-user manual-action throttle.

``users.rate_limit_minutes`` bounds how often one account may trigger a manual
Rescan or a report generation, and the window is counted separately per scope
(one per connector, one for the reports module). These tests pin:

* ``limit == 0`` disables throttling entirely (no Redis round-trip);
* the first action claims a ``SET NX EX`` window of ``limit * 60`` seconds and
  the second action inside that window reports the remaining wait;
* scopes are independent — a blocked breach rescan never blocks a report;
* Redis failures and a missing client are fail-open;
* ``enforce_manual_rate_limit`` raises 429 with ``Retry-After`` and records a
  ``rate_limit.manual_action_blocked`` audit row;
* the same behaviour end-to-end through the manual scan endpoints.
"""

from __future__ import annotations

import time

import pytest
from sqlalchemy import select

from app.core.audit import AuditLog
from app.core.exceptions import RateLimitException
from app.core.manual_rate_limit import (
    ManualRateLimiter,
    manual_rate_limit_key,
)
from app.core.rate_limit import RateLimiter


class _FakeRedis:
    """Minimal async-redis stand-in for the SET NX EX contract."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.ttls: dict[str, int] = {}
        self.set_calls: list[tuple[str, int, bool]] = []
        self.fail_set = False

    async def set(self, key, value, nx=False, ex=None):  # noqa: A002 - redis signature
        if self.fail_set:
            raise RuntimeError("redis down")
        window = int(ex or 0)
        self.set_calls.append((key, window, bool(nx)))
        if nx and key in self.store:
            return None
        self.store[key] = value
        self.ttls[key] = window
        return True

    async def ttl(self, key):
        return self.ttls.get(key, -1)

    async def delete(self, *keys):
        removed = 0
        for key in keys:
            if self.store.pop(key, None) is not None:
                removed += 1
            self.ttls.pop(key, None)
        return removed


def _activate_fake(monkeypatch: pytest.MonkeyPatch, fake: _FakeRedis) -> None:
    """Force the non-testing path with a fresh, pre-seeded client cache."""
    monkeypatch.setattr("app.core.rate_limit._testing_mode", lambda: False)
    monkeypatch.setattr(RateLimiter, "_CLIENT_CACHE", fake)
    monkeypatch.setattr(RateLimiter, "_CLIENT_TS", time.monotonic())


class TestManualRateLimiter:
    @pytest.mark.asyncio
    async def test_zero_limit_is_unlimited_and_makes_no_redis_call(self):
        # TESTING mode leaves the client at None; a zero limit must short-circuit
        # before that so an unlimited account never touches Redis.
        assert await ManualRateLimiter.acquire("user-1", "reports", 0) is None

    @pytest.mark.asyncio
    async def test_first_action_claims_window_and_second_is_blocked(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        fake = _FakeRedis()
        _activate_fake(monkeypatch, fake)

        assert await ManualRateLimiter.acquire("user-1", "reports", 5) is None
        assert fake.set_calls == [(manual_rate_limit_key("user-1", "reports"), 300, True)]

        remaining = await ManualRateLimiter.acquire("user-1", "reports", 5)
        assert remaining == 300
        # The blocked attempt must not extend or reset the window.
        assert len(fake.set_calls) == 2

    @pytest.mark.asyncio
    async def test_scopes_are_counted_separately(self, monkeypatch: pytest.MonkeyPatch):
        fake = _FakeRedis()
        _activate_fake(monkeypatch, fake)

        assert await ManualRateLimiter.acquire("user-1", "dnstwist", 10) is None
        # A different connector (and the report module) keep their own windows.
        assert await ManualRateLimiter.acquire("user-1", "shodan", 10) is None
        assert await ManualRateLimiter.acquire("user-1", "reports", 10) is None
        assert await ManualRateLimiter.acquire("user-1", "dnstwist", 10) == 600

    @pytest.mark.asyncio
    async def test_redis_failure_is_fail_open(self, monkeypatch: pytest.MonkeyPatch):
        fake = _FakeRedis()
        fake.fail_set = True
        _activate_fake(monkeypatch, fake)

        assert await ManualRateLimiter.acquire("user-1", "reports", 15) is None
        assert RateLimiter._CLIENT_CACHE is None  # broken client is dropped

    @pytest.mark.asyncio
    async def test_missing_client_is_fail_open(self):
        # TESTING=1 and no seeded cache -> no client -> allowed.
        assert await ManualRateLimiter.acquire("user-1", "reports", 60) is None

    @pytest.mark.asyncio
    async def test_reset_frees_the_window(self, monkeypatch: pytest.MonkeyPatch):
        fake = _FakeRedis()
        _activate_fake(monkeypatch, fake)

        assert await ManualRateLimiter.acquire("user-1", "reports", 5) is None
        await ManualRateLimiter.reset("user-1", "reports")
        assert await ManualRateLimiter.acquire("user-1", "reports", 5) is None


class TestEnforceManualRateLimit:
    @pytest.mark.asyncio
    async def test_second_action_raises_429_and_audits(
        self, monkeypatch: pytest.MonkeyPatch, db_session, test_viewer
    ):
        from app.core.manual_rate_limit import enforce_manual_rate_limit

        fake = _FakeRedis()
        _activate_fake(monkeypatch, fake)
        test_viewer.rate_limit_minutes = 2
        await db_session.commit()

        await enforce_manual_rate_limit(
            db=db_session,
            user=test_viewer,
            scope="reports",
            action="report.generate",
            ip_address="127.0.0.1",
        )

        with pytest.raises(RateLimitException) as exc_info:
            await enforce_manual_rate_limit(
                db=db_session,
                user=test_viewer,
                scope="reports",
                action="report.generate",
                ip_address="127.0.0.1",
            )
        exc = exc_info.value
        assert exc.status_code == 429
        assert exc.headers == {"Retry-After": "120"}
        assert "once every 2 minute(s)" in str(exc.detail)

        rows = list(
            (
                await db_session.execute(
                    select(AuditLog).where(
                        AuditLog.action == "rate_limit.manual_action_blocked"
                    )
                )
            ).scalars()
        )
        assert len(rows) == 1
        assert rows[0].details["scope"] == "reports"
        assert rows[0].details["limit_minutes"] == 2

    @pytest.mark.asyncio
    async def test_zero_limit_never_blocks(
        self, monkeypatch: pytest.MonkeyPatch, db_session, test_viewer
    ):
        from app.core.manual_rate_limit import enforce_manual_rate_limit

        _activate_fake(monkeypatch, _FakeRedis())
        test_viewer.rate_limit_minutes = 0
        await db_session.commit()
        for _ in range(3):
            await enforce_manual_rate_limit(
                db=db_session,
                user=test_viewer,
                scope="reports",
                action="report.generate",
                ip_address="127.0.0.1",
            )


class TestThrottledEndpoints:
    @pytest.mark.asyncio
    async def test_breach_rescan_is_throttled_for_the_module_scope(
        self,
        monkeypatch: pytest.MonkeyPatch,
        client,
        db_session,
        auth_headers_analyst,
        test_analyst,
    ):
        _activate_fake(monkeypatch, _FakeRedis())
        test_analyst.rate_limit_minutes = 1
        await db_session.commit()

        first = await client.post("/api/v1/breaches/scan", headers=auth_headers_analyst)
        assert first.status_code != 429, first.text

        second = await client.post("/api/v1/breaches/scan", headers=auth_headers_analyst)
        assert second.status_code == 429, second.text
        assert second.headers.get("retry-after") == "60"

        rows = list(
            (
                await db_session.execute(
                    select(AuditLog).where(
                        AuditLog.action == "rate_limit.manual_action_blocked"
                    )
                )
            ).scalars()
        )
        assert rows and rows[-1].details["scope"] == "breaches"

    @pytest.mark.asyncio
    async def test_report_generation_is_throttled_in_its_own_scope(
        self,
        monkeypatch: pytest.MonkeyPatch,
        client,
        db_session,
        auth_headers_analyst,
        test_analyst,
    ):
        from unittest.mock import MagicMock, patch

        _activate_fake(monkeypatch, _FakeRedis())
        test_analyst.rate_limit_minutes = 1
        await db_session.commit()

        mock_result = MagicMock()
        mock_result.id = "celery-task-rate-limit"
        with patch(
            "app.tasks.report_tasks.generate_report_task.apply_async",
            return_value=mock_result,
        ):
            first = await client.post(
                "/api/v1/reports/generate", json={}, headers=auth_headers_analyst
            )
            assert first.status_code == 202, first.text
            second = await client.post(
                "/api/v1/reports/generate", json={}, headers=auth_headers_analyst
            )
        assert second.status_code == 429, second.text
