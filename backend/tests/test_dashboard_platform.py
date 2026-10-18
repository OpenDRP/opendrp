"""The platform self-diagnostics block carried by `dashboard/stats`.

The point of the block is that the first screen answers the questions an operator
would otherwise have to visit `/ready`, the metrics endpoint and three pages to
ask. These tests pin the two properties that make it worth having: the numbers
come from the same rules as those sources, and the block adds no request, no
audit row and no identifier.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select

from app.api.v1.routers import dashboard as dashboard_router
from app.core import health
from app.models.alert_delivery import AlertDelivery, AlertRecipientState
from app.models.audit import AuditLog
from app.models.connector import Connector
from app.models.job import Job
from app.services.alert_delivery_service import AlertDeliveryService


def _connector(name: str, *, status: str = "enabled", age_seconds: int | None = 10, now: datetime) -> Connector:
    return Connector(
        name=name,
        connector_type="phishing",
        status=status,
        default_job_type=f"phishing.{name}",
        last_seen_at=None if age_seconds is None else now - timedelta(seconds=age_seconds),
    )


@pytest.mark.asyncio
async def test_platform_block_reports_dependencies_audit_and_queue_counts(
    client, auth_headers_viewer, db_session, monkeypatch
):
    async def _ok() -> None:
        return None

    async def _down() -> None:
        raise RuntimeError("not reachable")

    # The same functions `/ready` calls; here one is deliberately down.
    monkeypatch.setattr(health, "check_database", _ok)
    monkeypatch.setattr(health, "check_redis", _down)
    monkeypatch.setattr(dashboard_router, "audit_is_degraded", lambda: True)

    now = datetime.now(timezone.utc)
    db_session.add_all(
        [
            _connector("live", now=now),
            _connector("quiet", age_seconds=3 * 3600, now=now),
            _connector("never", age_seconds=None, now=now),
            _connector("off", status="disabled", age_seconds=3600, now=now),
            Job(job_type="system", status="running", created_at=now - timedelta(minutes=12)),
            AlertDelivery(
                threat_type="phishing",
                channel="email",
                payload={},
                status="ambiguous",
                created_at=now - timedelta(hours=2),
            ),
        ]
    )
    db_session.add(
        AlertRecipientState(
            key=AlertDeliveryService.recipient_key("email", "person@example.test"),
            next_send_at=now + timedelta(minutes=10),
        )
    )
    await db_session.commit()

    response = await client.get("/api/v1/dashboard/stats", headers=auth_headers_viewer)

    assert response.status_code == 200
    platform = response.json()["platform"]
    assert platform["database"] == "ok"
    assert platform["redis"] == "error"
    assert platform["audit_degraded"] is True
    assert platform["connectors"]["enabled"] == 3
    assert platform["connectors"]["disabled"] == 1
    # The disabled connector is not silent — it is not expected to check in.
    assert platform["connectors"]["silent"] == 2
    assert platform["connectors"]["longest_silence"] == {"name": "never", "seconds": None}
    assert 12 * 60 - 5 <= platform["oldest_running_job_seconds"] <= 12 * 60 + 60
    assert platform["deliveries"]["counts"]["ambiguous"] == 1
    assert platform["deliveries"]["stuck"] == 1
    assert platform["deliveries"]["waiting_recipients"] == 1


@pytest.mark.asyncio
async def test_platform_block_adds_no_audit_row_and_no_identifiers(
    client, auth_headers_viewer, db_session, monkeypatch
):
    async def _ok() -> None:
        return None

    monkeypatch.setattr(health, "check_database", _ok)
    monkeypatch.setattr(health, "check_redis", _ok)

    now = datetime.now(timezone.utc)
    db_session.add(
        AlertDelivery(
            threat_type="phishing",
            channel="email",
            payload={},
            status="pending",
            target="person@example.test",
            batch_id="batch-123",
            created_at=now - timedelta(minutes=1),
        )
    )
    await db_session.commit()

    before = (
        await db_session.execute(
            select(func.count(AuditLog.id)).where(AuditLog.action == "dashboard.view")
        )
    ).scalar_one()

    response = await client.get("/api/v1/dashboard/stats", headers=auth_headers_viewer)

    after = (
        await db_session.execute(
            select(func.count(AuditLog.id)).where(AuditLog.action == "dashboard.view")
        )
    ).scalar_one()
    assert after == before + 1
    assert platform_delivery_counts(response.json())["pending"] == 1
    serialized = json.dumps(response.json())
    assert "person@example.test" not in serialized
    assert "batch-123" not in serialized


def platform_delivery_counts(body: dict) -> dict:
    return body["platform"]["deliveries"]["counts"]
