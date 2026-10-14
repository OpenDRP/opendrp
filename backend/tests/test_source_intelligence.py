from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.models import Connector, Job, JobStatus
from app.models.source_observation import SourceObservation
from app.services.provider_quota import reserve, validate_policy
from app.services.source_observations import persist


@pytest.mark.asyncio
async def test_evidence_refresh_preserves_triage_and_provider_isolation(db_session):
    finding = {
        "subject": "www.example.com",
        "matched_asset": "example.com",
        "port": 443,
        "metadata": {"capability": "hostname"},
    }
    assert await persist(
        db_session, module="exposure", source="netlas", finding=finding
    )
    row = (await db_session.execute(select(SourceObservation))).scalar_one()
    row.status = "investigating"
    first = row.first_seen_at
    await db_session.commit()
    assert not await persist(
        db_session, module="exposure", source="netlas", finding=finding
    )
    await persist(db_session, module="exposure", source="shodan", finding=finding)
    await db_session.refresh(row)
    assert row.status == "investigating" and row.first_seen_at == first
    assert (
        len(list((await db_session.execute(select(SourceObservation))).scalars())) == 2
    )


@pytest.mark.parametrize("value", [True, 0, 601, "10"])
def test_budget_validation(value):
    with pytest.raises(ValueError):
        validate_policy({"requests_per_minute": value})


@pytest.mark.asyncio
async def test_shared_account_budget_and_fail_closed(db_session, monkeypatch):
    from app.core.rate_limit import RateLimiter

    a = Connector(
        name="netlas-phishing",
        connector_type="phishing",
        default_job_type="phishing.netlas",
        provider="netlas",
        quota_group="default",
        status="enabled",
        config={"daily_budget": 90, "requests_per_minute": 50},
        readiness={"operations": ["search", "certificate"]},
    )
    b = Connector(
        name="netlas-exposure",
        connector_type="exposure",
        default_job_type="exposure.netlas",
        provider="netlas",
        quota_group="default",
        status="disabled",
        config={"daily_budget": 20, "requests_per_minute": 10},
    )
    from app.models.source_account import SourceAccount

    # The account is edited after this job is queued; active jobs must retain
    # their frozen limits while approval remains a live kill switch.
    account = SourceAccount(
        source_id="netlas",
        name="default",
        policy={"approved": True, "daily_budget": 500, "requests_per_minute": 300},
    )
    db_session.add(account)
    await db_session.flush()
    a.source_account_id = b.source_account_id = account.id
    db_session.add_all([a, b])
    await db_session.commit()
    redis = AsyncMock()
    redis.eval.return_value = [1, 0]
    monkeypatch.setattr(RateLimiter, "_get_client", lambda: redis)
    job = Job(
        job_type="phishing.netlas",
        status=JobStatus.running,
        connector_id=a.id,
        claimed_by_connector=a.name,
        started_at=datetime.now(timezone.utc),
        lease_expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        params={
            "source_account_id": str(account.id),
            "config_snapshot": {
                "daily_budget": 20,
                "requests_per_minute": 10,
                "max_requests": 50,
            },
        },
    )
    db_session.add(job)
    await db_session.commit()
    await reserve(db_session, a, "certificate", job=job)
    args = redis.eval.call_args.args
    # Account limits are frozen at enqueue time while all workers still share
    # the account's Redis buckets. Later policy increases apply to new jobs.
    key_count = args[1]
    limits_start = 2 + key_count + 1
    assert tuple(args[limits_start : limits_start + key_count]) == (
        "10",
        "20",
        "3",
        "50",
    )
    redis.eval.reset_mock()
    redis.eval.return_value = [1, 0]
    await reserve(db_session, a, "search", job=job)
    general_keys = redis.eval.call_args.args
    assert not any(
        ":cert-minute" in key for key in general_keys[2 : 2 + general_keys[1]]
    )
    monkeypatch.setattr(RateLimiter, "_get_client", lambda: None)
    with pytest.raises(HTTPException) as error:
        await reserve(db_session, a, "search", job=job)
    assert error.value.status_code == 503
    with pytest.raises(HTTPException) as error:
        await reserve(db_session, b, "search", job=job)
    assert error.value.status_code == 409
    job.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    with pytest.raises(HTTPException) as error:
        await reserve(db_session, a, "search", job=job)
    assert error.value.status_code == 403


@pytest.mark.asyncio
async def test_real_redis_atomic_account_and_job_limits(db_session):
    import os
    import uuid
    from redis.asyncio import Redis
    from app.services.provider_quota import SCRIPT

    client = Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
    prefix = "test:source-quota:" + uuid.uuid4().hex
    keys = [prefix + ":minute", prefix + ":day", prefix + ":job:one"]
    now = str(int(datetime.now(timezone.utc).timestamp() * 1000))
    try:
        await client.ping()
        first = await client.eval(SCRIPT, 3, *keys, now, "10", "10", "1", "one")
        blocked = await client.eval(SCRIPT, 3, *keys, now, "10", "10", "1", "two")
        assert first == [1, 0] and blocked[0] == 0
        assert [await client.zcard(key) for key in keys] == [1, 1, 1]
        other_job = prefix + ":job:two"
        keys.append(other_job)
        assert (
            await client.eval(
                SCRIPT, 3, keys[0], keys[1], other_job, now, "10", "1", "10", "three"
            )
        )[0] == 0
        assert await client.zcard(other_job) == 0
    finally:
        try:
            await client.delete(*keys)
        except Exception:
            pass
        await client.aclose()
