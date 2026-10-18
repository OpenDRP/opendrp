"""`GET /dashboard/overview`: one page load, one request, one audit row.

DHP-10 (``docs/internal/dashboard-health-remediation-plan-2026-10-18.md`` §4)
found the dashboard spending three HTTP requests, three transactions and three
acquisitions of the audit chain's advisory lock per load, and writing three
audit rows for one glance at one page. The chain lock is transactional
(``app/core/audit_chain.py``), so the rows are not merely noisy: each is its own
commit and therefore its own lock acquisition, and a page load contended with
every other audited write in the installation.

These tests pin the two properties that make the new endpoint worth having:

* the response carries the same three sections the page used to fetch, from the
  same functions the old endpoints call — so the numbers cannot fork;
* the load writes one ``dashboard.view`` naming those sections, while the old
  endpoints keep answering and keep their own audit rows for their own callers
  (the DNS page still reads ``/connectors/health``).

The request and lock counts are measured in ``tests/test_dashboard_overview.py``
as audit-row counts: one row per transaction is one acquisition, which is the
measurable half of the claim. A real Postgres measurement of
``pg_advisory_xact_lock`` is recorded in the plan's §9.6.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from app.models.audit import AuditLog


async def _count(db, action: str) -> int:
    return (
        await db.execute(select(func.count(AuditLog.id)).where(AuditLog.action == action))
    ).scalar_one()


@pytest.mark.asyncio
async def test_overview_returns_the_three_sections_the_page_used_to_fetch(
    client, auth_headers_viewer
):
    response = await client.get("/api/v1/dashboard/overview", headers=auth_headers_viewer)

    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {"summary", "connectors", "channels", "generated_at"}
    # The summary is the `/dashboard/stats` payload, unchanged and unabridged:
    # the page reads `kpi`, `timeline` and both breakdowns exactly as before.
    assert {"kpi", "timeline", "phishing_by_source", "assets_by_criticality", "platform"} <= set(
        body["summary"]
    )
    assert {"total_assets", "total_phishing", "total_breaches"} <= set(body["summary"]["kpi"])
    assert len(body["summary"]["timeline"]) == 30
    # The health sections are the endpoints' own envelopes, not a reshaped copy.
    assert set(body["connectors"]) == {"items", "generated_at"}
    assert set(body["channels"]) == {"items", "delivery_queue", "generated_at"}
    assert [item["channel"] for item in body["channels"]["items"]] == ["email", "telegram"]


@pytest.mark.asyncio
async def test_overview_and_the_old_endpoints_agree_on_every_section(
    client, auth_headers_viewer, db_session
):
    """The new path must not invent a second definition of any number."""
    from app.models.asset import Asset, AssetType

    db_session.add(
        Asset(
            asset_type=AssetType.domain,
            asset_value="overview.example",
            criticality="high",
            is_active=True,
        )
    )
    await db_session.commit()

    overview = (await client.get("/api/v1/dashboard/overview", headers=auth_headers_viewer)).json()
    stats = (await client.get("/api/v1/dashboard/stats", headers=auth_headers_viewer)).json()
    connectors = (await client.get("/api/v1/connectors/health", headers=auth_headers_viewer)).json()
    channels = (await client.get("/api/v1/alerts/health", headers=auth_headers_viewer)).json()

    assert overview["summary"]["kpi"] == stats["kpi"]
    assert overview["summary"]["timeline"] == stats["timeline"]
    assert overview["summary"]["platform"] == stats["platform"]
    assert overview["connectors"]["items"] == connectors["items"]
    assert overview["channels"]["items"] == channels["items"]
    assert overview["channels"]["delivery_queue"] == channels["delivery_queue"]


@pytest.mark.asyncio
async def test_one_page_load_writes_one_view_row_instead_of_three(
    client, auth_headers_viewer, db_session
):
    """The measurement DHP-10 asks for, in rows: 3 → 1.

    ``dashboard.view``, ``connectors.health.view`` and ``alerts.health.view``
    were one transaction each, so three rows meant three advisory-lock
    acquisitions per load. Counting rows is the same statement, and it can be
    asserted on SQLite as well as on PostgreSQL.
    """
    # What the page used to cost: three endpoints, three rows.
    for path in ("/api/v1/dashboard/stats", "/api/v1/connectors/health", "/api/v1/alerts/health"):
        assert (await client.get(path, headers=auth_headers_viewer)).status_code == 200

    before = await _count(db_session, "dashboard.view")
    assert before == 1
    assert await _count(db_session, "connectors.health.view") == 1
    assert await _count(db_session, "alerts.health.view") == 1
    disabled_email_views = await _count(db_session, "outbound.blocked")
    assert disabled_email_views == 0

    client.cookies.clear()
    response = await client.get("/api/v1/dashboard/overview", headers=auth_headers_viewer)

    assert response.status_code == 200, response.text
    assert await _count(db_session, "dashboard.view") == before + 1
    # One row for the whole page: the health sections are inside it.
    assert await _count(db_session, "dashboard.view") == 2
    assert await _count(db_session, "connectors.health.view") == 1
    assert await _count(db_session, "alerts.health.view") == 1


@pytest.mark.asyncio
async def test_the_view_row_names_the_sections_it_carried(client, auth_headers_viewer, db_session):
    response = await client.get("/api/v1/dashboard/overview", headers=auth_headers_viewer)
    assert response.status_code == 200, response.text

    row = (
        await db_session.execute(
            select(AuditLog)
            .where(AuditLog.action == "dashboard.view")
            .order_by(AuditLog.timestamp.desc())
        )
    ).scalars().first()
    assert row is not None
    # Specific enough to replace the two health view rows it absorbed: a reader
    # can still tell which sections an account saw in one look.
    assert row.details["sections"] == ["summary", "connectors", "channels"]
    assert "total_assets" in row.details
    # And still free of delivery identifiers: the queue is numbers only. The
    # actor's own address is the audit contract's business, not the queue's.
    serialized = str(row.details)
    assert "batch-" not in serialized
    assert "person@example.test" not in serialized


@pytest.mark.asyncio
async def test_a_refused_probe_is_still_a_security_event_on_the_overview_path(
    client, auth_headers_viewer, db_session
):
    """The absorbed view rows must not absorb the security record.

    A refused SMTP destination is not a view; it is an operator action that
    resolved into a network the probe may not touch. Losing that record because
    the page stopped calling `/alerts/health` would be a regression hidden inside
    a request-count win.
    """
    from app.api.v1.routers.alerts import ProbeResult
    from app.services.settings_service import SettingsService

    settings = await SettingsService(db_session).get_singleton()
    settings.email_alerts_enabled = True
    settings.smtp_host = "smtp.example.test"
    settings.smtp_port = 587
    # The column stores ciphertext; the setter is what a settings write uses.
    settings.smtp_from_email_decrypted = "alerts@example.test"
    await db_session.commit()

    def _refused(_s):
        return ProbeResult("failed", "SMTP destination refused (private_address)", 0, "private_address")

    import app.api.v1.routers.alerts as alerts_router

    original = alerts_router._smtp_probe
    alerts_router._smtp_probe = _refused
    try:
        response = await client.get("/api/v1/dashboard/overview", headers=auth_headers_viewer)
    finally:
        alerts_router._smtp_probe = original

    assert response.status_code == 200, response.text
    assert await _count(db_session, "dashboard.view") == 1
    assert await _count(db_session, "outbound.blocked") == 1
