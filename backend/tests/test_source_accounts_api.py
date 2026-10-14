from datetime import datetime, timezone
import uuid

import pytest

from app.models import Asset, AssetType, Connector, Job
from app.models.audit import AuditLog
from app.models.source_account import SourceAccount


@pytest.mark.asyncio
async def test_source_account_lifecycle_is_admin_only_and_audited(
    client, db_session, auth_headers_admin, auth_headers_analyst
):
    assert (
        await client.get("/api/v1/connectors/accounts", headers=auth_headers_analyst)
    ).status_code == 403

    created = await client.post(
        "/api/v1/connectors/accounts",
        headers=auth_headers_admin,
        json={
            "source_id": "netlas",
            "name": "account-2",
            "credential_ref": "NETLAS_API_KEY_ACCOUNT2",
        },
    )
    assert created.status_code == 200
    account_id = created.json()["id"]
    assert "credential" not in str(created.json()).lower()

    accounts = await client.get(
        "/api/v1/connectors/accounts", headers=auth_headers_admin
    )
    account = next(row for row in accounts.json() if row["id"] == account_id)
    assert account["policy"] == {"approved": False}
    assert account["credential_ref"] == "NETLAS_API_KEY_ACCOUNT2"

    updated = await client.post(
        "/api/v1/connectors/accounts",
        headers=auth_headers_admin,
        json={
            "source_id": "netlas",
            "name": "account-2",
            "credential_ref": "NETLAS_API_KEY_V3",
        },
    )
    assert updated.status_code == 200 and updated.json()["id"] == account_id
    account = next(
        row
        for row in (
            await client.get("/api/v1/connectors/accounts", headers=auth_headers_admin)
        ).json()
        if row["id"] == account_id
    )
    assert account["credential_ref"] == "NETLAS_API_KEY_V3"

    invalid = await client.patch(
        f"/api/v1/connectors/accounts/{account_id}/policy",
        headers=auth_headers_admin,
        json={"approved": 1, "requests_per_minute": 10, "daily_budget": 100},
    )
    assert invalid.status_code == 422
    approved = await client.patch(
        f"/api/v1/connectors/accounts/{account_id}/policy",
        headers=auth_headers_admin,
        json={"approved": True, "requests_per_minute": 10, "daily_budget": 100},
    )
    assert approved.status_code == 200
    assert approved.json()["policy"] == {
        "approved": True,
        "requests_per_minute": 10,
        "daily_budget": 100,
    }
    wrong_provider_history_cap = await client.patch(
        f"/api/v1/connectors/accounts/{account_id}/policy",
        headers=auth_headers_admin,
        json={
            "approved": True,
            "requests_per_minute": 10,
            "daily_budget": 100,
            "max_certificate_history_credits": 3,
        },
    )
    # The history-credit field is no longer part of the account policy schema.
    assert wrong_provider_history_cap.status_code == 422
    assert (
        await client.patch(
            f"/api/v1/connectors/accounts/{account_id}/policy",
            headers=auth_headers_analyst,
            json={"approved": False, "requests_per_minute": 10, "daily_budget": 100},
        )
    ).status_code == 403

    connector = Connector(
        name="netlas-exposure-default",
        connector_type="exposure",
        default_job_type="exposure.netlas",
        status="enabled",
        provider="netlas",
        readiness={
            "credentials_configured": True,
            "credential_state": "unknown",
            "capabilities": ["hostname"],
        },
        last_seen_at=datetime.now(timezone.utc),
    )
    db_session.add(
        Asset(
            asset_type=AssetType.domain,
            asset_value="example.com",
            criticality="medium",
            is_active=True,
        )
    )
    db_session.add(connector)
    await db_session.commit()

    mismatch = SourceAccount(
        source_id="unknown-provider",
        name="wrong-provider",
        policy={"approved": False},
    )
    db_session.add(mismatch)
    await db_session.commit()
    assert (
        await client.patch(
            f"/api/v1/connectors/{connector.id}/account?account_id={mismatch.id}",
            headers=auth_headers_admin,
        )
    ).status_code == 400

    bound = await client.patch(
        f"/api/v1/connectors/{connector.id}/account?account_id={account_id}",
        headers=auth_headers_admin,
    )
    assert bound.status_code == 200
    assert bound.json()["source_account_id"] == account_id
    assert bound.json()["provider"] == "netlas"
    created_response = await client.post(
        "/api/v1/modules/exposure/scan", headers=auth_headers_analyst
    )
    assert created_response.status_code == 202, created_response.text
    created_job = created_response.json()
    assert len(created_job["job_ids"]) == 1
    job = await db_session.get(Job, uuid.UUID(created_job["job_ids"][0]))
    assert job.params["source_account_id"] == account_id
    assert job.params["config_snapshot"]["requests_per_minute"] == 10

    wrong_provider = await client.post(
        "/api/v1/connectors/accounts",
        headers=auth_headers_admin,
        json={"source_id": "invalid provider", "name": "oops"},
    )
    assert wrong_provider.status_code == 422

    # Query through the ORM so this also asserts audit rows committed with the
    # corresponding operator actions.
    from sqlalchemy import select

    audit_rows = list((await db_session.execute(select(AuditLog))).scalars())
    assert {row.action for row in audit_rows} >= {
        "source_account.provisioned",
        "source_account.policy.updated",
        "connector.account.bound",
    }
    assert all(row.user_id is not None and row.ip_address for row in audit_rows)
