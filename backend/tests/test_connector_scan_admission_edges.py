"""Scan admission for provider-bound connectors, from the service boundary.

Coverage batch 03. A provider connector may only be scanned when its source
account is the one bound to it, is approved, has credentials, and holds an
asset the connector's capabilities can use. Each refusal is a different answer
to an operator, so each test names the fact it pins.
"""

from __future__ import annotations

import pytest

from app.core.exceptions import BadRequestException
from app.models import Asset, AssetType, Connector, SourceAccount
from app.services.connector_service import ConnectorService


def _connector(name: str, *, connector_type: str, **fields) -> Connector:
    return Connector(
        name=name,
        connector_type=connector_type,
        default_job_type=f"{connector_type}.{name}",
        status="enabled",
        aliases=[],
        **fields,
    )


async def _account(db, source_id: str, *, approved: bool = True) -> SourceAccount:
    account = SourceAccount(source_id=source_id, name="default", policy={"approved": approved})
    db.add(account)
    await db.commit()
    return account


async def _asset(db, asset_type: AssetType, value: str) -> None:
    db.add(Asset(asset_type=asset_type, asset_value=value, criticality="medium", is_active=True))
    await db.commit()


def _ready(**extra) -> dict:
    return {"credentials_configured": True, "capabilities": ["hostname"], **extra}


class TestProviderAccountBinding:
    @pytest.mark.asyncio
    async def test_a_worker_bound_to_another_sources_account_is_refused(self, db_session):
        wrong = await _account(db_session, "hibp")
        connector = _connector(
            "mismatch-worker",
            connector_type="dns",
            provider="netlas",
            source_account_id=wrong.id,
            readiness=_ready(),
        )
        db_session.add(connector)
        await db_session.commit()
        await _asset(db_session, AssetType.domain, "example.com")

        with pytest.raises(BadRequestException, match="Matching provider account required"):
            await ConnectorService(db_session).enqueue_module_scan(
                connector_type="dns", created_by=None, title="T", connector_name=connector.name
            )

    @pytest.mark.asyncio
    async def test_a_worker_whose_credentials_are_not_ready_is_refused(self, db_session):
        account = await _account(db_session, "netlas")
        connector = _connector(
            "unconfigured-scan-worker",
            connector_type="dns",
            provider="netlas",
            source_account_id=account.id,
            readiness={"credentials_configured": False, "capabilities": ["hostname"]},
        )
        db_session.add(connector)
        await db_session.commit()
        await _asset(db_session, AssetType.domain, "example.com")

        with pytest.raises(BadRequestException, match="Source credentials are not ready"):
            await ConnectorService(db_session).enqueue_module_scan(
                connector_type="dns", created_by=None, title="T", connector_name=connector.name
            )

    @pytest.mark.asyncio
    async def test_an_unapproved_account_is_refused_at_admission(self, db_session):
        account = await _account(db_session, "netlas", approved=False)
        connector = _connector(
            "unapproved-scan-worker",
            connector_type="dns",
            provider="netlas",
            source_account_id=account.id,
            readiness=_ready(),
        )
        db_session.add(connector)
        await db_session.commit()
        await _asset(db_session, AssetType.domain, "example.com")

        with pytest.raises(
            BadRequestException, match="Operator-approved source account policy required"
        ):
            await ConnectorService(db_session).enqueue_module_scan(
                connector_type="dns", created_by=None, title="T", connector_name=connector.name
            )


class TestScheduledOccurrence:
    @pytest.mark.asyncio
    async def test_a_scheduled_slot_is_queued_once_and_replayed(self, db_session):
        account = await _account(db_session, "netlas")
        connector = _connector(
            "scheduled-worker",
            connector_type="dns",
            provider="netlas",
            source_account_id=account.id,
            readiness=_ready(),
        )
        db_session.add(connector)
        await db_session.commit()
        await _asset(db_session, AssetType.domain, "example.com")
        svc = ConnectorService(db_session)
        params = {"trigger": "scheduler", "scheduled_at": "2026-10-19T10:00:00+00:00"}

        first = await svc.enqueue_module_scan(
            connector_type="dns", created_by=None, title="T", params=dict(params),
            connector_name=connector.name,
        )
        again = await svc.enqueue_module_scan(
            connector_type="dns", created_by=None, title="T", params=dict(params),
            connector_name=connector.name,
        )

        assert len(first) == 1
        assert [job.id for job in again] == [job.id for job in first]


class TestCapabilityMatching:
    @pytest.mark.asyncio
    async def test_an_asset_the_worker_cannot_use_is_refused(self, db_session):
        account = await _account(db_session, "netlas")
        connector = _connector(
            "no-usable-worker",
            connector_type="dns",
            provider="netlas",
            source_account_id=account.id,
            readiness=_ready(capabilities=["unrelated"]),
        )
        db_session.add(connector)
        await db_session.commit()
        await _asset(db_session, AssetType.domain, "example.com")

        with pytest.raises(BadRequestException, match="No active assets or capabilities match"):
            await ConnectorService(db_session).enqueue_module_scan(
                connector_type="dns", created_by=None, title="T", connector_name=connector.name
            )

    @pytest.mark.asyncio
    async def test_a_matching_host_asset_queues_the_scan(self, db_session):
        account = await _account(db_session, "netlas")
        connector = _connector(
            "usable-worker",
            connector_type="dns",
            provider="netlas",
            source_account_id=account.id,
            readiness=_ready(),
        )
        db_session.add(connector)
        await db_session.commit()
        await _asset(db_session, AssetType.domain, "example.com")

        jobs = await ConnectorService(db_session).enqueue_module_scan(
            connector_type="dns", created_by=None, title="T", connector_name=connector.name
        )

        assert len(jobs) == 1
        assert jobs[0].connector_id == connector.id
        assert jobs[0].params["source_account_id"] == str(account.id)

    @pytest.mark.asyncio
    async def test_a_breach_worker_is_usable_by_an_email_account(self, db_session):
        account = await _account(db_session, "hibp")
        connector = _connector(
            "breach-email-worker",
            connector_type="breaches",
            provider="hibp",
            source_account_id=account.id,
            readiness={
                "credentials_configured": True,
                "capabilities": ["email_account"],
            },
        )
        db_session.add(connector)
        await db_session.commit()
        await _asset(db_session, AssetType.email_account, "analyst@example.com")

        jobs = await ConnectorService(db_session).enqueue_module_scan(
            connector_type="breaches", created_by=None, title="T", connector_name=connector.name
        )

        assert len(jobs) == 1
        assert jobs[0].params["emails"] == ["analyst@example.com"]

    @pytest.mark.asyncio
    async def test_a_breach_catalogue_worker_is_handed_the_catalogue_window(self, db_session):
        account = await _account(db_session, "hibp")
        connector = _connector(
            "breach-catalogue-worker",
            connector_type="breaches",
            provider="hibp",
            source_account_id=account.id,
            readiness={"credentials_configured": True, "capabilities": ["catalogue"]},
        )
        db_session.add(connector)
        await db_session.commit()
        await _asset(db_session, AssetType.domain, "example.com")

        jobs = await ConnectorService(db_session).enqueue_module_scan(
            connector_type="breaches", created_by=None, title="T", connector_name=connector.name
        )

        assert len(jobs) == 1
        assert "catalogue" in jobs[0].params
        assert "stealer_logs" in jobs[0].params

    @pytest.mark.asyncio
    async def test_a_breach_worker_without_its_capability_is_refused(self, db_session):
        account = await _account(db_session, "hibp")
        connector = _connector(
            "breach-no-capability-worker",
            connector_type="breaches",
            provider="hibp",
            source_account_id=account.id,
            readiness={"credentials_configured": True, "capabilities": ["hostname"]},
        )
        db_session.add(connector)
        await db_session.commit()
        await _asset(db_session, AssetType.email_account, "analyst@example.com")

        with pytest.raises(BadRequestException, match="No active assets or capabilities match"):
            await ConnectorService(db_session).enqueue_module_scan(
                connector_type="breaches", created_by=None, title="T", connector_name=connector.name
            )
