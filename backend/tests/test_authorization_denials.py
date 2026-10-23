"""A refused authorization is a fact, but one fact per intent — not per request.

USR-07 in ``docs/internal/audit-2026-10-15_users-rbac_03``: every role gate
answered 403 and wrote nothing, so "an analyst tried to administer accounts" was
unanswerable from the trail. The fix cannot simply audit each refusal either — a
client that ignores 403 would then write its own load into the database — so the
row is deduplicated per account, method and route inside a window. These tests
pin both halves: the row exists, and repeated attempts do not multiply it.

The suite runs without Redis (``APP_ENV=test`` makes ``RateLimiter._get_client``
return ``None``), so what is exercised here is the in-process fallback — the path
that keeps the signal during a broker outage, which is also the path most likely
to be wrong.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.core import authorization_audit
from app.core.authorization_audit import reset_local_claims
from app.core.rate_limit import RateLimiter
from app.models.audit import AuditLog


@pytest.fixture(autouse=True)
def _fresh_claim_window():
    reset_local_claims()
    yield
    reset_local_claims()


async def _denials(db_session) -> list[AuditLog]:
    return list(
        (
            await db_session.execute(
                select(AuditLog)
                .where(AuditLog.action == "authz.denied")
                .order_by(AuditLog.seq)
            )
        ).scalars()
    )


@pytest.mark.asyncio
async def test_analyst_refused_an_admin_route_leaves_one_row(
    client, auth_headers_analyst, test_analyst, db_session
):
    r = await client.get("/api/v1/users", headers=auth_headers_analyst)
    assert r.status_code == 403, r.text

    rows = await _denials(db_session)
    assert len(rows) == 1
    row = rows[0]
    assert row.user_id == test_analyst.id
    assert row.details["path"] == "/api/v1/users"
    assert row.details["method"] == "GET"
    assert row.details["role"] == "analyst"
    assert row.details["required"] == "administer"
    assert row.ip_address


@pytest.mark.asyncio
async def test_repeated_attempts_in_the_window_stay_one_row(
    client, auth_headers_analyst, db_session
):
    """A client ignoring the 403 must not become the trail's biggest writer."""
    for _ in range(4):
        r = await client.get("/api/v1/users", headers=auth_headers_analyst)
        assert r.status_code == 403, r.text

    assert len(await _denials(db_session)) == 1


@pytest.mark.asyncio
async def test_a_different_route_is_a_different_denial(
    client, auth_headers_viewer, db_session
):
    """The window is per account *and* route: two intents are two events."""
    first = await client.get("/api/v1/users", headers=auth_headers_viewer)
    assert first.status_code == 403, first.text
    second = await client.get("/api/v1/audit/logs", headers=auth_headers_viewer)
    assert second.status_code == 403, second.text

    rows = await _denials(db_session)
    assert len(rows) == 2
    assert {row.details["path"] for row in rows} == {
        "/api/v1/users",
        "/api/v1/audit/logs",
    }


@pytest.mark.asyncio
async def test_analyst_gate_names_what_was_required(
    client, auth_headers_viewer, db_session
):
    """`required` lets a SIEM rule distinguish the analyst gate from the admin one."""
    r = await client.post(
        "/api/v1/assets",
        headers=auth_headers_viewer,
        json={"asset_type": "domain", "asset_value": "denied.example.com"},
    )
    assert r.status_code == 403, r.text

    rows = await _denials(db_session)
    assert len(rows) == 1
    assert rows[0].details["required"] == "analyse"
    assert rows[0].details["method"] == "POST"


@pytest.mark.asyncio
async def test_allowed_requests_do_not_write_denials(
    client, auth_headers_admin, db_session
):
    r = await client.get("/api/v1/users", headers=auth_headers_admin)
    assert r.status_code == 200, r.text
    assert await _denials(db_session) == []


class _FakeRedis:
    """The one command this module uses, with the window it models.

    `SET NX EX` is the whole contract: a key is free the first time and taken for
    the rest of the window. Standing in for it is not standing in for the code
    under test — it is the broker boundary, which the suite normally does not
    have (``APP_ENV=test`` makes ``RateLimiter._get_client`` answer ``None``).
    """

    def __init__(self, *, failing: bool = False) -> None:
        self.failing = failing
        self.keys: dict[str, int] = {}
        self.calls: list[tuple[str, int | None]] = []

    async def set(self, key, value, nx=False, ex=None):
        self.calls.append((key, ex))
        if self.failing:
            raise RuntimeError("broker down")
        if nx and key in self.keys:
            return None
        self.keys[key] = 1
        return True


@pytest.mark.asyncio
async def test_the_window_is_held_in_redis_when_the_broker_answers(
    client, auth_headers_analyst, db_session, monkeypatch
):
    """The dedup belongs to the shared store, so replicas agree on one row.

    The in-process map is the outage fallback; with Redis reachable it must not be
    the thing that suppresses the second refusal, or a second replica would write
    its own row for the same intent.
    """
    fake = _FakeRedis()
    monkeypatch.setattr(RateLimiter, "_get_client", staticmethod(lambda: fake))

    for _ in range(3):
        assert (
            await client.get("/api/v1/users", headers=auth_headers_analyst)
        ).status_code == 403

    assert len(await _denials(db_session)) == 1
    assert fake.calls, "the broker was never asked"
    assert all(
        key.startswith("rl:authz:") and ex == 300 for key, ex in fake.calls
    ), fake.calls


@pytest.mark.asyncio
async def test_a_broker_outage_falls_back_to_the_process_map_and_is_logged(
    client, auth_headers_analyst, db_session, monkeypatch
):
    """A broken broker must not silently switch the camera off.

    The fallback still deduplicates inside this process, and the client cache is
    dropped so the next request reconnects instead of reusing a broken handle.
    """
    fake = _FakeRedis(failing=True)
    monkeypatch.setattr(RateLimiter, "_get_client", staticmethod(lambda: fake))
    resets: list[bool] = []
    monkeypatch.setattr(
        RateLimiter, "_reset_client", classmethod(lambda cls: resets.append(True))
    )

    for _ in range(2):
        assert (
            await client.get("/api/v1/users", headers=auth_headers_analyst)
        ).status_code == 403

    assert len(await _denials(db_session)) == 1
    assert resets, "a failing broker must drop the cached client"


@pytest.mark.asyncio
async def test_a_refusal_about_a_named_account_records_which_account(
    client, auth_headers_analyst, db_session
):
    """The route names the account; the trail must carry that name.

    "An analyst was refused" is a fact about a role. Which account they were
    refused *about* is the fact an access review needs.
    """
    import uuid

    target = uuid.uuid4()
    r = await client.put(
        f"/api/v1/users/{target}",
        headers=auth_headers_analyst,
        json={"is_active": False},
    )
    assert r.status_code == 403, r.text

    rows = await _denials(db_session)
    assert len(rows) == 1
    assert rows[0].details["target_id"] == str(target)


def test_an_expired_claim_is_purged_before_the_new_one_is_taken(monkeypatch):
    """The fallback map is a window, so an expired key stops suppressing.

    Purging is what makes the map a cache rather than a set that only grows; a
    route refused yesterday must be recordable again today.
    """
    now = 5_000.0
    assert authorization_audit._claim_locally("old", now) is True

    # 301 seconds later the claim is outside the five-minute window.
    assert authorization_audit._claim_locally("new", now + 301) is True
    assert "old" not in authorization_audit._local_claims
    assert authorization_audit._claim_locally("old", now + 302) is True


def test_the_process_map_is_bounded(monkeypatch):
    """The fallback is a cache with a ceiling, not a leak.

    A refused flood is bounded by the account's request limit, but a process that
    has lost Redis must not grow a map keyed by every path anyone probes either.
    """
    monkeypatch.setattr(authorization_audit, "_LOCAL_MAX_ENTRIES", 2)
    now = 1_000.0

    assert authorization_audit._claim_locally("a", now) is True
    assert authorization_audit._claim_locally("b", now) is True
    # A third claim evicts the oldest one instead of growing the map.
    assert authorization_audit._claim_locally("c", now) is True
    assert authorization_audit._claim_locally("c", now) is False
    # The evicted key is claimable again: the map dropped its record, so a new
    # refusal for that route is recorded rather than silently suppressed.
    assert authorization_audit._claim_locally("a", now) is True
