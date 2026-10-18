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

from app.core.authorization_audit import reset_local_claims
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
