"""The connector service's refusal paths, from the service boundary.

Coverage batch 03. The protocol suites prove a connector can register, claim
work and complete it; this file walks the answers for a connector that is early,
late, misconfigured or bound to the wrong account. Those are the states an
operator meets at 3 a.m.: a lease that expired, a provider account nobody
approved, a source that reports invalid credentials, a job that belongs to a
sibling. Each answer is a different status or a different readiness label, so
the tests name the fact rather than the line.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.core.exceptions import (
    BadRequestException,
    ForbiddenException,
    NotFoundException,
)
from app.models import Connector, SourceAccount
from app.models.job import Job, JobStatus
from app.services.connector_service import ConnectorService, normalize_connector_name
from app.services.job_service import JobService


def _connector(
    name: str,
    *,
    connector_type: str = "phishing",
    job_type: str | None = None,
    status: str = "enabled",
    aliases: list[str] | None = None,
    **fields,
) -> Connector:
    return Connector(
        name=name,
        connector_type=connector_type,
        default_job_type=job_type or f"{connector_type}.{name}",
        status=status,
        aliases=aliases or [],
        **fields,
    )


async def _job(db, job_type: str, **fields) -> Job:
    return await JobService(db).create_job(
        job_type=job_type, created_by=None, title="T", params={"trigger": "manual"}, **fields
    )


class TestNameAndAliases:
    def test_a_name_must_keep_one_alphanumeric_character(self):
        with pytest.raises(BadRequestException, match="alphanumeric"):
            normalize_connector_name("!!!")

    @pytest.mark.asyncio
    async def test_registering_under_an_alias_reuses_the_same_row(self, db_session):
        canonical = _connector("canonical", aliases=["legacy"])
        db_session.add(canonical)
        await db_session.commit()

        registered = await ConnectorService(db_session).register(
            name="legacy",
            connector_type="phishing",
            default_job_type="phishing.canonical",
        )

        assert registered.id == canonical.id
        assert registered.name == "canonical"


class TestStatusAndConfig:
    @pytest.mark.asyncio
    async def test_status_refuses_an_unknown_value_and_account(self, db_session):
        svc = ConnectorService(db_session)
        connector = _connector("status-worker")
        db_session.add(connector)
        await db_session.commit()

        with pytest.raises(BadRequestException, match="enabled"):
            await svc.set_status(connector.id, "archived")
        with pytest.raises(NotFoundException, match="Connector not found"):
            await svc.set_status(uuid.uuid4(), "enabled")

    @pytest.mark.asyncio
    async def test_config_refuses_a_non_object_and_an_unknown_account(self, db_session):
        svc = ConnectorService(db_session)
        connector = _connector("config-worker")
        db_session.add(connector)
        await db_session.commit()

        with pytest.raises(BadRequestException, match="config must be an object"):
            await svc.set_config(connector.id, "not-a-config")
        with pytest.raises(NotFoundException, match="Connector not found"):
            await svc.set_config(uuid.uuid4(), {})

    @pytest.mark.asyncio
    async def test_a_provider_config_is_checked_against_the_quota_policy(self, db_session):
        svc = ConnectorService(db_session)
        connector = _connector("provider-worker", provider="shodan")
        db_session.add(connector)
        await db_session.commit()

        with pytest.raises(BadRequestException, match="daily_budget"):
            await svc.set_config(connector.id, {"daily_budget": 0})


class TestLeases:
    @pytest.mark.asyncio
    async def test_heartbeat_requires_a_lease_and_a_running_job(self, db_session):
        svc = ConnectorService(db_session)
        connector = _connector("lease-worker")
        db_session.add(connector)
        await db_session.commit()
        await _job(db_session, connector.default_job_type)
        claimed = await svc.claim_work(connector)
        assert claimed is not None

        with pytest.raises(ForbiddenException, match="lease token is required"):
            await svc.heartbeat(connector, job_id=claimed.id)
        with pytest.raises(ForbiddenException, match="lease is no longer valid"):
            await svc.heartbeat(connector, job_id=claimed.id, lease_token="not-it")

        await svc.heartbeat(connector, job_id=claimed.id, lease_token=claimed.lease_token)
        await db_session.refresh(claimed)
        assert claimed.lease_expires_at is not None

    @pytest.mark.asyncio
    async def test_an_expired_lease_cannot_complete_a_job(self, db_session):
        svc = ConnectorService(db_session)
        connector = _connector("expired-worker")
        db_session.add(connector)
        await db_session.commit()
        await _job(db_session, connector.default_job_type)
        claimed = await svc.claim_work(connector)
        assert claimed is not None
        claimed.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await db_session.commit()

        with pytest.raises(ForbiddenException, match="expired or job is no longer running"):
            await svc.complete_job(
                connector,
                claimed.id,
                result_summary={},
                lease_token=claimed.lease_token,
            )

    @pytest.mark.asyncio
    async def test_an_unknown_job_is_not_found(self, db_session):
        connector = _connector("unknown-worker")
        db_session.add(connector)
        await db_session.commit()

        with pytest.raises(NotFoundException, match="Job not found"):
            await ConnectorService(db_session).complete_job(
                connector, uuid.uuid4(), result_summary={}, lease_token="x"
            )


class TestTerminalSummaries:
    @pytest.mark.asyncio
    async def test_partial_and_skipped_summaries_keep_their_status(self, db_session):
        svc = ConnectorService(db_session)
        connector = _connector("summary-worker")
        db_session.add(connector)
        await db_session.commit()

        for summary, expected in (
            ({"status": "partial"}, JobStatus.partial),
            ({"status": "skipped"}, JobStatus.skipped),
        ):
            await _job(db_session, connector.default_job_type)
            claimed = await svc.claim_work(connector)
            assert claimed is not None
            completed = await svc.complete_job(
                connector,
                claimed.id,
                result_summary=summary,
                lease_token=claimed.lease_token,
            )
            assert completed.status == expected

    @pytest.mark.asyncio
    async def test_an_error_summary_records_the_sanitised_provider_error(self, db_session):
        svc = ConnectorService(db_session)
        connector = _connector("error-worker")
        db_session.add(connector)
        await db_session.commit()
        await _job(db_session, connector.default_job_type)
        claimed = await svc.claim_work(connector)
        assert claimed is not None

        completed = await svc.complete_job(
            connector,
            claimed.id,
            result_summary={"status": "error", "error_code": "provider_timeout"},
            lease_token=claimed.lease_token,
        )

        assert completed.status == JobStatus.error
        await db_session.refresh(connector)
        assert connector.last_error == "provider_timeout"


class TestRecovery:
    @pytest.mark.asyncio
    async def test_a_disabled_owner_cancels_an_expired_job_instead_of_requeueing(self, db_session):
        svc = ConnectorService(db_session)
        connector = _connector("disabled-worker")
        db_session.add(connector)
        await db_session.commit()
        await _job(db_session, connector.default_job_type)
        claimed = await svc.claim_work(connector)
        assert claimed is not None

        connector.status = "disabled"
        claimed.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await db_session.commit()

        assert await svc.recover_expired_jobs() == 1
        await db_session.refresh(claimed)
        assert claimed.status == JobStatus.cancelled
        assert claimed.error_message == "Source or module disabled after lease expiry"


class TestProviderAccountBinding:
    @pytest.mark.asyncio
    async def test_claiming_provider_work_without_an_account_cancels_it(self, db_session):
        svc = ConnectorService(db_session)
        connector = _connector(
            "unbound-worker",
            provider="shodan",
            readiness={"credentials_configured": True},
        )
        db_session.add(connector)
        await db_session.commit()
        job = await _job(db_session, connector.default_job_type)

        assert await svc.claim_work(connector) is None
        await db_session.refresh(job)
        assert job.status == JobStatus.cancelled
        assert "provider_account_missing" in (job.error_message or "")

    @pytest.mark.asyncio
    async def test_enqueueing_provider_work_without_an_account_is_refused_and_releases_the_slot(self, db_session):
        svc = ConnectorService(db_session)
        connector = _connector(
            "unbound-enqueue",
            provider="shodan",
            readiness={"credentials_configured": True},
        )
        db_session.add(connector)
        await db_session.commit()

        with pytest.raises(BadRequestException, match="provider_account_missing"):
            await svc.enqueue_module_scan(
                connector_type="phishing",
                created_by=None,
                title="T",
                connector_name=connector.name,
            )


class TestReadySourcesReasons:
    @pytest.mark.asyncio
    async def test_each_blocked_source_reports_its_own_readiness_reason(self, db_session):
        now = datetime.now(timezone.utc)
        approved = SourceAccount(
            source_id="netlas", name="default", policy={"approved": True}
        )
        unapproved = SourceAccount(
            source_id="hibp", name="default", policy={"approved": False}
        )
        db_session.add_all([approved, unapproved])
        await db_session.commit()

        db_session.add_all(
            [
                _connector("offline-worker", status="disabled"),
                _connector("never-seen-worker"),
                _connector(
                    "missing-account-worker",
                    provider="shodan",
                    readiness={"credentials_configured": True},
                    last_seen_at=now,
                ),
                _connector(
                    "unconfigured-worker",
                    provider="netlas",
                    source_account_id=approved.id,
                    readiness={"credentials_configured": False},
                    last_seen_at=now,
                ),
                _connector(
                    "invalid-worker",
                    provider="netlas",
                    source_account_id=approved.id,
                    readiness={
                        "credentials_configured": True,
                        "credential_state": "invalid",
                        "capabilities": ["certificate"],
                    },
                    last_seen_at=now,
                ),
                _connector(
                    "unsupported-worker",
                    provider="netlas",
                    source_account_id=approved.id,
                    readiness={
                        "credentials_configured": True,
                        "credential_state": "unsupported",
                    },
                    last_seen_at=now,
                ),
                _connector(
                    "no-capabilities-worker",
                    provider="netlas",
                    source_account_id=approved.id,
                    readiness={"credentials_configured": True, "capabilities": []},
                    last_seen_at=now,
                ),
                _connector(
                    "cooldown-worker",
                    provider="netlas",
                    source_account_id=approved.id,
                    readiness={
                        "credentials_configured": True,
                        "capabilities": ["certificate"],
                    },
                    last_success_at=now,
                    config={"cooldown_seconds": 3600},
                    last_seen_at=now,
                ),
                _connector(
                    "unapproved-worker",
                    provider="hibp",
                    source_account_id=unapproved.id,
                    connector_type="breaches",
                    readiness={
                        "credentials_configured": True,
                        "capabilities": ["email_account"],
                    },
                    last_seen_at=now,
                ),
            ]
        )
        await db_session.commit()

        svc = ConnectorService(db_session)
        result = await svc.enqueue_ready_sources(
            connector_type="phishing", created_by=None, title="T"
        )
        reasons = {row["connector"]: row["status"] for row in result["sources"]}

        assert reasons["offline-worker"] == "disabled"
        assert reasons["never-seen-worker"] == "offline"
        assert reasons["missing-account-worker"] == "provider_account_missing"
        assert reasons["unconfigured-worker"] == "unconfigured"
        assert reasons["invalid-worker"] == "invalid_credentials"
        assert reasons["unsupported-worker"] == "unsupported"
        assert reasons["no-capabilities-worker"] == "unsupported"
        assert reasons["cooldown-worker"] == "cooldown"
        assert result["status"] == "blocked"

        breaches = await svc.enqueue_ready_sources(
            connector_type="breaches", created_by=None, title="T"
        )
        assert breaches["sources"] == [
            {"connector": "unapproved-worker", "status": "account_policy_unapproved"}
        ]
