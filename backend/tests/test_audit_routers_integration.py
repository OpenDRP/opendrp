from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.schemas.asset import AssetCreate


@pytest.mark.asyncio
async def test_login_success_writes_audit_row(
    client,
    db_session: AsyncSession,
):
    from app.core.security import hash_password
    from app.models.user import User

    u = User(
        email="audit-login@example.com",
        password_hash=hash_password("Password123!"),
        role="analyst",
        is_active=True,
    )
    db_session.add(u)
    await db_session.commit()
    await db_session.refresh(u)

    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "audit-login@example.com", "password": "Password123!"},
    )
    assert r.status_code == 200, r.text

    rows = (await db_session.execute(
        select(AuditLog).where(AuditLog.action == "auth.login.success")
    )).scalars().all()
    assert len(rows) == 1
    assert rows[0].user_id == u.id
    assert rows[0].details.get("email") == "audit-login@example.com"


@pytest.mark.asyncio
async def test_logout_writes_audit_row_when_authenticated(
    client,
    db_session: AsyncSession,
    auth_headers_analyst,
    analyst_user,
):
    r = await client.post("/api/v1/auth/logout", headers=auth_headers_analyst)
    assert r.status_code == 204

    rows = (await db_session.execute(
        select(AuditLog).where(AuditLog.action == "auth.logout")
    )).scalars().all()
    assert len(rows) == 1
    assert rows[0].user_id == analyst_user.id


@pytest.mark.asyncio
async def test_asset_create_update_delete_audit_integration(
    client,
    db_session: AsyncSession,
    auth_headers_analyst,
    admin_user,
    auth_headers_admin,
):
    create = AssetCreate(
        asset_type="domain",
        asset_value="audit-domain.example.com",
        criticality="medium",
        is_active=True,
    )
    r = await client.post(
        "/api/v1/assets",
        json=create.model_dump(mode="json"),
        headers=auth_headers_analyst,
    )
    assert r.status_code == 201, r.text
    data = r.json()
    asset_id = data["id"]

    r = await client.patch(
        f"/api/v1/assets/{asset_id}",
        json={"description": "patched"},
        headers=auth_headers_analyst,
    )
    assert r.status_code == 200, r.text

    r = await client.delete(
        f"/api/v1/assets/{asset_id}",
        headers=auth_headers_admin,
    )
    assert r.status_code == 204

    rows = (await db_session.execute(
        select(AuditLog).where(
            AuditLog.action.in_(["asset.create", "asset.update", "asset.delete"])
        ).order_by(AuditLog.timestamp.asc())
    )).scalars().all()
    actions = [r.action for r in rows]
    assert actions == ["asset.create", "asset.update", "asset.delete"]
    assert rows[0].details["asset_value"] == "audit-domain.example.com"
    assert "changed_fields" in rows[1].details
    assert rows[2].details["asset_id"] == asset_id


@pytest.mark.asyncio
async def test_asset_list_view_actions_write_audit(
    client,
    db_session: AsyncSession,
    auth_headers_viewer,
    seeded_asset,
):
    r_list = await client.get("/api/v1/assets", headers=auth_headers_viewer)
    assert r_list.status_code == 200, r_list.text

    r_view = await client.get(f"/api/v1/assets/{seeded_asset.id}", headers=auth_headers_viewer)
    assert r_view.status_code == 200, r_view.text

    import asyncio
    pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    await asyncio.gather(*pending, return_exceptions=True)
    await asyncio.sleep(0.05)

    rows = (await db_session.execute(
        select(AuditLog).where(
            AuditLog.action.in_(["asset.list", "asset.view"])
        )
    )).scalars().all()
    actions = sorted(r.action for r in rows)
    assert "asset.list" in actions
    assert "asset.view" in actions


@pytest.mark.asyncio
async def test_settings_update_writes_audit_row(
    client,
    db_session: AsyncSession,
    auth_headers_admin,
):
    r = await client.put(
        "/api/v1/settings",
        json={"smtp_port": 2525, "alert_recipient_email": "soc@example.com"},
        headers=auth_headers_admin,
    )
    assert r.status_code == 200, r.text
    rows = (await db_session.execute(
        select(AuditLog).where(AuditLog.action == "settings.update")
    )).scalars().all()
    assert len(rows) == 1
    assert set(rows[0].details["updated_fields"]) == {"smtp_port", "alert_recipient_email"}


@pytest.mark.asyncio
async def test_dashboard_view_writes_audit(
    client,
    db_session: AsyncSession,
    auth_headers_viewer,
):
    r = await client.get("/api/v1/dashboard/stats", headers=auth_headers_viewer)
    assert r.status_code == 200, r.text

    import asyncio
    pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    await asyncio.gather(*pending, return_exceptions=True)
    await asyncio.sleep(0.05)

    rows = (await db_session.execute(
        select(AuditLog).where(AuditLog.action == "dashboard.view")
    )).scalars().all()
    assert len(rows) == 1
    assert "total_assets" in rows[0].details
    assert "total_breaches" in rows[0].details


@pytest.mark.asyncio
async def test_report_generate_writes_audit(
    client,
    db_session: AsyncSession,
    auth_headers_analyst,
    monkeypatch,
):
    from app.tasks import report_tasks
    fake_result = MagicMock()
    fake_result.id = "task-report-123"
    with patch.object(report_tasks.generate_report_task, "apply_async", side_effect=RuntimeError("celery not available")):
        r = await client.post(
            "/api/v1/reports/generate",
            json={"report_name": "Audit Report One"},
            headers=auth_headers_analyst,
        )
    assert r.status_code == 503, r.text
    rows = (await db_session.execute(
        select(AuditLog).where(AuditLog.action == "report.generate")
    )).scalars().all()
    assert len(rows) == 1
    assert rows[0].details["report_name"] == "Audit Report One"
    assert rows[0].details["schedule_ok"] is False


@pytest.mark.asyncio
async def test_phishing_scan_shodan_writes_audit_when_no_connector(
    client,
    db_session: AsyncSession,
    auth_headers_analyst,
):
    # No connector registered: the endpoint still answers 202 with a clear
    # "no_connector" status and writes the audit event.
    r = await client.post("/api/v1/phishing/scan/shodan", headers=auth_headers_analyst)
    assert r.status_code == 202, r.text
    assert r.json()["status"] == "no_connector"

    rows = (await db_session.execute(
        select(AuditLog).where(AuditLog.action == "phishing.scan.shodan.start")
    )).scalars().all()
    assert len(rows) == 1
    assert rows[0].details["status"] == "no_connector"
