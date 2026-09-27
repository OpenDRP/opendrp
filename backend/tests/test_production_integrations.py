"""Opt-in integration tests for the production infrastructure boundary.

Run with real services, for example:

    INTEGRATION_DATABASE_URL=postgresql+asyncpg://... \
    INTEGRATION_REDIS_URL=redis://... \
    pytest -q tests/test_production_integrations.py

The normal SQLite suite deliberately remains fast and isolated. These tests
cover behavior SQLite cannot faithfully model: PostgreSQL row locking,
PostgreSQL enum/UUID/JSON columns, async connection pooling, and Redis atomic
NX/TTL operations.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.core.database import Base
from app.models import Connector, Job


_DATABASE_URL = os.environ.get("INTEGRATION_DATABASE_URL")
_REDIS_URL = os.environ.get("INTEGRATION_REDIS_URL")

_MISSING_ENV = [
    name
    for name, value in (
        ("INTEGRATION_DATABASE_URL", _DATABASE_URL),
        ("INTEGRATION_REDIS_URL", _REDIS_URL),
    )
    if not value
]

if _MISSING_ENV:
    # Skipping keeps local runs convenient, but in CI it would turn the
    # strongest gate in the pipeline into a silent no-op. REQUIRE_INTEGRATION=1
    # (set by the CI job) makes missing wiring a hard error instead.
    message = "set " + " and ".join(_MISSING_ENV) + " to run production integration tests"
    if os.environ.get("REQUIRE_INTEGRATION") == "1":
        raise RuntimeError(f"{message} — REQUIRE_INTEGRATION=1 forbids skipping")
    pytest.skip(message, allow_module_level=True)


# Function scope is required: ``pytest.ini`` sets
# ``asyncio_default_fixture_loop_scope = function``, so a module-scoped async
# fixture raises ``ScopeMismatch`` against the function-scoped event loop and
# the whole PostgreSQL boundary class errors out before running.
@pytest_asyncio.fixture(scope="function")
async def postgres_engine():
    engine = create_async_engine(
        _DATABASE_URL,
        pool_size=5,
        max_overflow=2,
        pool_pre_ping=True,
        pool_use_lifo=True,
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest_asyncio.fixture()
async def postgres_session(postgres_engine):
    session_factory = async_sessionmaker(
        postgres_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )
    async with session_factory() as session:
        yield session


@pytest.mark.integration
class TestPostgreSQLProductionBoundary:
    @pytest.mark.asyncio
    async def test_pool_is_bounded_and_pre_ping_enabled(self, postgres_engine):
        pool = postgres_engine.sync_engine.pool
        assert pool.size() == 5
        assert pool._max_overflow == 2
        assert pool._pre_ping is True

    @pytest.mark.asyncio
    async def test_postgres_schema_supports_uuid_enum_and_json(
        self, postgres_session
    ):
        suffix = uuid.uuid4().hex[:10]
        connector = Connector(
            name=f"pg-schema-{suffix}",
            connector_type="phishing",
            default_job_type="phishing.dnstwist",
            config={"scan_ssl_text": False, "nested": {"source": "test"}},
        )
        postgres_session.add(connector)
        await postgres_session.flush()

        job = Job(
            job_type="phishing.dnstwist",
            status="pending",
            title="PostgreSQL schema boundary",
            params={"connector": connector.name, "assets": ["example.com"]},
        )
        postgres_session.add(job)
        await postgres_session.commit()

        row = await postgres_session.get(Job, job.id)
        assert row is not None
        assert isinstance(row.id, uuid.UUID)
        assert row.job_type == "phishing.dnstwist"
        assert row.params == {"connector": connector.name, "assets": ["example.com"]}

        await postgres_session.execute(delete(Job).where(Job.id == job.id))
        await postgres_session.execute(delete(Connector).where(Connector.id == connector.id))
        await postgres_session.commit()

    @pytest.mark.asyncio
    async def test_select_for_update_skip_locked_claims_each_job_once(
        self, postgres_engine
    ):
        suffix = uuid.uuid4().hex[:10]
        names = [f"pg-claim-a-{suffix}", f"pg-claim-b-{suffix}"]
        session_factory = async_sessionmaker(
            postgres_engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )

        async with session_factory() as setup:
            connectors = [
                Connector(
                    name=name,
                    connector_type="phishing",
                    default_job_type="phishing.dnstwist",
                )
                for name in names
            ]
            setup.add_all(connectors)
            await setup.flush()
            jobs = [
                Job(
                    job_type="phishing.dnstwist",
                    status="pending",
                    title=f"concurrent claim {suffix}-{index}",
                    params={"sequence": index},
                )
                for index in range(2)
            ]
            setup.add_all(jobs)
            await setup.commit()
            connector_ids = [connector.id for connector in connectors]
            job_ids = {job.id for job in jobs}

        async def claim(connector_id):
            async with session_factory() as session:
                connector = await session.get(Connector, connector_id)
                assert connector is not None
                from app.services.connector_service import ConnectorService

                claimed = await ConnectorService(session).claim_work(connector)
                return claimed.id if claimed else None

        claimed_ids = await asyncio.gather(*(claim(cid) for cid in connector_ids))
        assert all(claimed_ids)
        assert len(set(claimed_ids)) == 2
        assert set(claimed_ids) == job_ids

        async with session_factory() as verify:
            rows = (
                await verify.execute(select(Job).where(Job.id.in_(job_ids)))
            ).scalars().all()
            assert {row.status for row in rows} == {"running"}
            assert {row.claimed_by_connector for row in rows} == set(names)
            await verify.execute(delete(Job).where(Job.id.in_(job_ids)))
            await verify.execute(delete(Connector).where(Connector.id.in_(connector_ids)))
            await verify.commit()

    @pytest.mark.asyncio
    async def test_select_for_update_skip_locked_scales_across_replicas(
        self, postgres_engine
    ):
        """A larger replica-shaped burst claims every pending job once."""
        suffix = uuid.uuid4().hex[:10]
        replica_count = 8
        names = [f"pg-replica-{suffix}-{index}" for index in range(replica_count)]
        session_factory = async_sessionmaker(
            postgres_engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )

        async with session_factory() as setup:
            connectors = [
                Connector(
                    name=name,
                    connector_type="phishing",
                    default_job_type="phishing.dnstwist",
                )
                for name in names
            ]
            jobs = [
                Job(
                    job_type="phishing.dnstwist",
                    status="pending",
                    title=f"replica burst {suffix}-{index}",
                    params={"sequence": index},
                )
                for index in range(replica_count)
            ]
            setup.add_all([*connectors, *jobs])
            await setup.commit()
            connector_ids = [connector.id for connector in connectors]
            job_ids = {job.id for job in jobs}

        async def claim(connector_id):
            async with session_factory() as session:
                connector = await session.get(Connector, connector_id)
                assert connector is not None
                from app.services.connector_service import ConnectorService

                claimed = await ConnectorService(session).claim_work(connector)
                return claimed.id if claimed else None

        claimed_ids = await asyncio.gather(*(claim(cid) for cid in connector_ids))
        assert all(claimed_ids)
        assert len(set(claimed_ids)) == replica_count
        assert set(claimed_ids) == job_ids

        async with session_factory() as verify:
            rows = (
                await verify.execute(select(Job).where(Job.id.in_(job_ids)))
            ).scalars().all()
            assert {row.status for row in rows} == {"running"}
            assert {row.claimed_by_connector for row in rows} == set(names)
            await verify.execute(delete(Job).where(Job.id.in_(job_ids)))
            await verify.execute(delete(Connector).where(Connector.id.in_(connector_ids)))
            await verify.commit()


    @pytest.mark.asyncio
    async def test_alert_queue_claim_is_single_winner_across_workers(self, postgres_engine):
        """PostgreSQL SKIP LOCKED must prevent duplicate alert delivery."""
        from app.models.alert_delivery import AlertDelivery, AlertDeliveryStatus
        from app.services.alert_delivery_service import AlertDeliveryService

        suffix = uuid.uuid4().hex[:10]
        session_factory = async_sessionmaker(
            postgres_engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        async with session_factory() as setup:
            job = Job(
                job_type="phishing.dnstwist",
                status="success",
                title=f"alert queue race {suffix}",
                params={},
            )
            setup.add(job)
            await setup.flush()
            rows = [
                AlertDelivery(
                    job_id=job.id,
                    threat_type="phishing",
                    channel="email",
                    target=f"integration-{index}-{suffix}@example.test",
                    payload={"phishing_domain": f"{index}-{suffix}.example"},
                    status=AlertDeliveryStatus.pending,
                    next_attempt_at=datetime.now(timezone.utc),
                )
                for index in range(3)
            ]
            setup.add_all(rows)
            await setup.commit()
            row_ids = {row.id for row in rows}
            job_id = job.id

        async def claim():
            async with session_factory() as session:
                claimed = await AlertDeliveryService(session).claim_group(limit=10)
                return {row.id for row in claimed}

        first, second = await asyncio.gather(claim(), claim())
        assert first and second == set()
        assert first == row_ids

        async with session_factory() as cleanup:
            await cleanup.execute(delete(AlertDelivery).where(AlertDelivery.id.in_(row_ids)))
            await cleanup.execute(delete(Job).where(Job.id == job_id))
            await cleanup.commit()


@pytest.mark.integration
class TestRedisProductionBoundary:
    @pytest.mark.asyncio
    async def test_rate_limiter_uses_atomic_counter_and_ttl(self, monkeypatch):
        from app.core.rate_limit import RateLimiter

        monkeypatch.setattr(settings, "REDIS_URL", _REDIS_URL)
        monkeypatch.delenv("TESTING", raising=False)
        monkeypatch.setenv("APP_ENV", "integration")
        RateLimiter.reset_client_cache()

        subject = f"integration-{uuid.uuid4().hex}"
        limiter = RateLimiter(max_fails=3)
        try:
            assert await limiter.incr_failure(subject) == 1
            assert await limiter.incr_failure(subject) == 2
            assert await limiter.is_locked(subject) is False
            assert await limiter.incr_failure(subject) == 3
            assert await limiter.is_locked(subject) is True
        finally:
            await limiter.reset(subject)
            RateLimiter.reset_client_cache()

    @pytest.mark.asyncio
    async def test_scheduler_dedup_is_atomic_and_expires(self, monkeypatch):
        import redis as redis_lib

        from app.tasks import scheduler_tasks

        monkeypatch.setattr(settings, "REDIS_URL", _REDIS_URL)
        module = f"integration-{uuid.uuid4().hex}"
        now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        key = scheduler_tasks._redis_dedup_key(module, now)
        client = redis_lib.Redis.from_url(_REDIS_URL, decode_responses=True)
        try:
            results = await asyncio.gather(
                asyncio.to_thread(scheduler_tasks._try_acquire_dedup, module, now),
                asyncio.to_thread(scheduler_tasks._try_acquire_dedup, module, now),
            )
            assert sorted(results) == [False, True]
            assert client.get(key)
            assert 0 < (client.ttl(key) or 0) <= 90
        finally:
            client.delete(key)
            client.close()

    @pytest.mark.asyncio
    async def test_scheduler_release_cannot_delete_new_owner(self, monkeypatch):
        """A stale dispatcher must not remove a newer replica's lock."""
        import redis as redis_lib

        from app.tasks import scheduler_tasks

        monkeypatch.setattr(settings, "REDIS_URL", _REDIS_URL)
        module = f"ownership-{uuid.uuid4().hex}"
        now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        key = scheduler_tasks._redis_dedup_key(module, now)
        client = redis_lib.Redis.from_url(_REDIS_URL, decode_responses=True)
        try:
            client.set(key, "new-owner", ex=90)
            scheduler_tasks._release_dedup(module, now, "stale-owner")
            assert client.get(key) == "new-owner"
        finally:
            client.delete(key)
            client.close()

    @pytest.mark.asyncio
    async def test_broker_refuses_a_client_without_the_password(self):
        """An unauthenticated client must be refused by the broker.

        This is a load-bearing property rather than a nicety: Redis is the Celery
        broker, so anything that can open a socket to it can publish a task the
        worker will execute with the platform's own database credentials, and can
        read the task payloads of every other participant. The integration Redis
        is started with `--requirepass` precisely so that this assertion can exist.

        The precondition is asserted rather than skipped: a URL without a password
        is the regression this test is about, and skipping it would report success
        for the configuration being fixed.
        """
        import redis as redis_lib
        from urllib.parse import urlsplit

        parsed = urlsplit(_REDIS_URL or "")
        assert parsed.password, (
            "the integration Redis must require a password — start it with "
            "--requirepass and put it in INTEGRATION_REDIS_URL"
        )

        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 6379
        database = (parsed.path or "/0").lstrip("/") or "0"
        no_credentials_url = f"redis://{host}:{port}/{database}"

        client = redis_lib.Redis.from_url(
            no_credentials_url, decode_responses=True, socket_connect_timeout=5
        )
        try:
            with pytest.raises(redis_lib.exceptions.RedisError) as excinfo:
                client.ping()
            assert "AUTH" in str(excinfo.value).upper()
        finally:
            client.close()

    @pytest.mark.asyncio
    async def test_scheduler_dedup_has_single_winner_across_many_replicas(self, monkeypatch):
        """Many beat replicas must produce exactly one winner per minute."""
        import redis as redis_lib

        from app.tasks import scheduler_tasks

        monkeypatch.setattr(settings, "REDIS_URL", _REDIS_URL)
        module = f"replicas-{uuid.uuid4().hex}"
        now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        key = scheduler_tasks._redis_dedup_key(module, now)
        client = redis_lib.Redis.from_url(_REDIS_URL, decode_responses=True)
        try:
            results = await asyncio.gather(
                *(
                    asyncio.to_thread(scheduler_tasks._try_acquire_dedup, module, now)
                    for _ in range(16)
                )
            )
            assert sum(results) == 1
            assert client.get(key)
        finally:
            client.delete(key)
            client.close()
