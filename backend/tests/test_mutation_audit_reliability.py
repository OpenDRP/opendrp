from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.models.phishing import PhishingDomain


@pytest.mark.asyncio
async def test_phishing_triage_rolls_back_with_unavailable_audit(client, db_session, auth_headers_analyst, monkeypatch):
    row = PhishingDomain(phishing_domain="lookalike.example", matched_asset="example.com", detection_source="dnstwist", status="active")
    db_session.add(row)
    await db_session.commit()
    identity = row.id
    async def fail(*args, **kwargs):
        raise RuntimeError("audit unavailable")
    monkeypatch.setattr("app.core.audit.prepare_entry", fail)
    response = await client.patch(f"/api/v1/phishing/threats/{identity}", headers=auth_headers_analyst, json={"status": "resolved"})
    assert response.status_code == 503
    await db_session.refresh(row)
    assert row.status == "active"


@pytest.mark.asyncio
async def test_module_toggle_rolls_back_with_unavailable_audit(client, db_session, auth_headers_admin, monkeypatch):
    from app.models.module import Module
    row = await db_session.get(Module, "phishing")
    assert row.enabled
    async def fail(*args, **kwargs):
        raise RuntimeError("audit unavailable")
    monkeypatch.setattr("app.core.audit.prepare_entry", fail)
    response = await client.patch("/api/v1/modules/phishing", headers=auth_headers_admin, json={"enabled": False})
    assert response.status_code == 503
    await db_session.refresh(row)
    assert row.enabled


@pytest.mark.asyncio
async def test_manual_scan_admission_leaves_no_job_without_its_audit(client, db_session, auth_headers_analyst, monkeypatch):
    """The queued Job and the event naming who asked for it share one commit."""
    from app.models import Asset, AssetType, Connector, Job
    from app.models.source_account import SourceAccount

    db_session.add(Asset(asset_type=AssetType.domain, asset_value="example.com", is_active=True, criticality="medium"))
    account = SourceAccount(source_id="netlas", name="default", policy={"approved": True, "requests_per_minute": 10, "daily_budget": 100})
    db_session.add(account)
    await db_session.flush()
    db_session.add(Connector(name="netlas-exposure", connector_type="exposure", default_job_type="exposure.netlas", status="enabled", provider="netlas", source_account_id=account.id, quota_group="default", last_seen_at=datetime.now(timezone.utc), readiness={"credentials_configured": True, "credential_state": "unknown", "capabilities": ["hostname"]}))
    await db_session.commit()

    async def fail(*args, **kwargs):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr("app.core.audit.prepare_entry", fail)
    response = await client.post("/api/v1/modules/exposure/scan", headers=auth_headers_analyst)
    assert response.status_code == 503
    assert (await db_session.execute(select(Job))).scalars().all() == []
