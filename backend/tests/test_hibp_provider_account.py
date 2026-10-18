"""HIBP is a provider-backed connector, and its account is what says so.

The audit found the breach worker outside the mechanism every other provider
worker uses: its row declared no `provider`, so the core could not gate a scan on
readiness, could not draw the requests from an account budget, and had no reason
to name a refusal — a revoked key looked like a domain with no breaches. These
tests pin the two halves of the fix: the scan waits for an approved account, and
the queued job carries the account it may spend.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.models import Asset, Connector, Job, SourceAccount
from app.services.connector_service import ConnectorService

pytestmark = pytest.mark.usefixtures("without_testing_switch")


def _hibp_connector(account: SourceAccount) -> Connector:
    return Connector(
        name="breaches-hibp",
        connector_type="breaches",
        default_job_type="breaches.hibp",
        provider="hibp",
        quota_group="default",
        status="enabled",
        source_account_id=account.id,
        readiness={
            "credentials_configured": True,
            "credential_state": "valid",
            "capabilities": ["email_account", "domain", "catalogue"],
            "operations": ["lookup", "catalogue"],
        },
        last_seen_at=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
async def test_a_scan_waits_for_an_approved_hibp_account(db_session):
    """An unapproved account is a named refusal, not an empty scan.

    The row ships unapproved like every other provider account: it declares that
    the provider exists, while an operator decides whether scans may spend it.
    What matters is that the request says why nothing was queued.
    """
    account = SourceAccount(
        source_id="hibp", name="default", policy={"approved": False}
    )
    db_session.add(account)
    await db_session.flush()
    db_session.add(_hibp_connector(account))
    db_session.add(Asset(asset_type="email_account", asset_value="user@example.com"))
    await db_session.commit()

    result = await ConnectorService(db_session).enqueue_ready_sources(
        connector_type="breaches", created_by=None, title="Breach scan"
    )

    assert result["status"] == "blocked"
    assert result["job_ids"] == []
    assert result["sources"] == [
        {"connector": "breaches-hibp", "status": "account_policy_unapproved"}
    ]


@pytest.mark.asyncio
async def test_a_scan_from_an_approved_account_carries_it(db_session):
    """The job names the account, which is what the quota reservation charges."""
    account = SourceAccount(
        source_id="hibp",
        name="default",
        policy={"approved": True, "requests_per_minute": 10, "daily_budget": 200},
    )
    db_session.add(account)
    await db_session.flush()
    db_session.add(_hibp_connector(account))
    db_session.add(Asset(asset_type="email_account", asset_value="user@example.com"))
    await db_session.commit()

    result = await ConnectorService(db_session).enqueue_ready_sources(
        connector_type="breaches", created_by=None, title="Breach scan"
    )

    assert result["status"] == "scheduled", result
    job = (
        await db_session.execute(
            select(Job).where(Job.id == uuid.UUID(result["job_ids"][0]))
        )
    ).scalar_one()
    assert job.params["source_account_id"] == str(account.id)
    assert job.connector_id is not None
