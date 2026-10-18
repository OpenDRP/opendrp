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
    # The script reads each window from the key's suffix, so the names are part of
    # the contract rather than decoration: a key renamed to `:daily` would be
    # charged as a minute one.
    quota_keys = general_keys[2 : 2 + general_keys[1]]
    assert quota_keys[0].endswith(":minute") and quota_keys[1].endswith(":day")
    assert any(":job:" in key for key in quota_keys)
    # What the account has left today is part of the answer, so a worker reports spend
    # as a remainder an operator can plan around instead of only as a ceiling.
    redis.eval.return_value = [1, 0, 7]
    payload = await reserve(db_session, a, "search", job=job)
    assert payload["remaining_today"] == 7
    assert payload["request_budget"] == 20
    # A quota backend that answered without the third value (an older script) is not a
    # failure: the ceiling is still reported and the remainder says it is unknown.
    redis.eval.return_value = [1, 0]
    assert (await reserve(db_session, a, "search", job=job))["remaining_today"] is None
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
async def test_real_redis_atomic_account_and_job_limits(db_session, live_redis):
    """The script's atomicity is the property under test.

    A real broker is what makes it assertable, and ``live_redis`` skips the test
    with a reason where there is none instead of failing on a connection.
    """
    import uuid
    from redis.asyncio import Redis
    from app.services.provider_quota import SCRIPT

    client = Redis.from_url(live_redis)
    prefix = "test:source-quota:" + uuid.uuid4().hex
    keys = [prefix + ":minute", prefix + ":day", prefix + ":job:one"]
    now = str(int(datetime.now(timezone.utc).timestamp() * 1000))
    try:
        await client.ping()
        first = await client.eval(SCRIPT, 3, *keys, now, "10", "10", "1", "one")
        blocked = await client.eval(SCRIPT, 3, *keys, now, "10", "10", "1", "two")
        # The third value is what the account has left today after this charge: the day
        # limit is ten, one request is now spent, so nine remain.
        assert first[0] == 1 and first[1] == 0 and first[2] == 9
        assert blocked[0] == 0
        assert [await client.zcard(key) for key in keys] == [1, 1, 1]
        other_job = prefix + ":job:two"
        keys.append(other_job)
        assert (
            await client.eval(
                SCRIPT, 3, keys[0], keys[1], other_job, now, "10", "1", "10", "three"
            )
        )[0] == 0
        assert await client.zcard(other_job) == 0

        # Key order is presentation, not meaning: the day bucket passed first is
        # still a day, and a fourth window does not push it into a minute.
        reordered = "test:source-quota:" + uuid.uuid4().hex
        reordered_keys = [
            reordered + ":day",
            reordered + ":minute",
            reordered + ":cert-minute",
            reordered + ":job:four",
        ]
        keys.extend(reordered_keys)
        first_reordered = await client.eval(
            SCRIPT, 4, *reordered_keys, now, "2", "10", "3", "5", "four-a"
        )
        assert first_reordered[0] == 1 and first_reordered[2] == 1
        second_reordered = await client.eval(
            SCRIPT, 4, *reordered_keys, now, "2", "10", "3", "5", "four-b"
        )
        assert second_reordered[0] == 1 and second_reordered[2] == 0
        blocked_by_day = await client.eval(
            SCRIPT, 4, *reordered_keys, now, "2", "10", "3", "5", "four-c"
        )
        # The retry delay is the proof: a day window answers ~86400 seconds, a
        # minute window at most 60. Positional selection would fail here.
        assert blocked_by_day[0] == 0 and int(blocked_by_day[1]) > 3600

        minute_only = "test:source-quota:" + uuid.uuid4().hex + ":minute"
        keys.append(minute_only)
        await client.eval(SCRIPT, 1, minute_only, now, "1", "m-a")
        minute_blocked = await client.eval(SCRIPT, 1, minute_only, now, "1", "m-b")
        assert minute_blocked[0] == 0 and 0 < int(minute_blocked[1]) <= 60
    finally:
        try:
            await client.delete(*keys)
        except Exception:
            pass
        await client.aclose()


def _phishing_connector(name, capabilities, account_id):
    return Connector(
        name=name,
        connector_type="phishing",
        default_job_type="phishing.netlas",
        provider="netlas",
        quota_group="default",
        status="enabled",
        source_account_id=account_id,
        config={"max_requests": 20},
        readiness={
            "credentials_configured": True,
            "credential_state": "valid",
            "capabilities": capabilities,
            "operations": ["search", "certificate"],
        },
        last_seen_at=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
async def test_confirmed_candidates_and_brands_reach_a_phishing_scan(db_session):
    import uuid

    from app.models import Asset
    from app.models.phishing import PhishingDomain
    from app.models.source_account import SourceAccount
    from app.services.connector_service import ConnectorService

    account = SourceAccount(
        source_id="netlas",
        name="default",
        policy={"approved": True, "daily_budget": 500, "requests_per_minute": 60},
    )
    db_session.add(account)
    await db_session.flush()
    db_session.add_all(
        [
            Asset(asset_type="domain", asset_value="acme.example"),
            Asset(asset_type="keyword_domain", asset_value="acme"),
            Asset(asset_type="keyword_title", asset_value="ACME portal"),
        ]
    )
    connector = _phishing_connector(
        "phishing-netlas",
        ["certificate", "certificate_brand", "body", "title", "hostname"],
        account.id,
    )
    db_session.add(connector)
    await db_session.flush()
    db_session.add_all(
        [
            # Only a verdict a person made qualifies: the platform asks the provider
            # again about a *confirmed* name, never about its own open guesses.
            PhishingDomain(
                phishing_domain="acme-login.example.net",
                matched_asset="acme",
                detection_source="dnstwist",
                verdict="confirmed",
                confidence=88,
            ),
            PhishingDomain(
                phishing_domain="acme-support.example.net",
                matched_asset="acme",
                detection_source="dnstwist",
                verdict=None,
                confidence=91,
            ),
            PhishingDomain(
                phishing_domain="acme.example",
                matched_asset="acme",
                detection_source="dnstwist",
                verdict="confirmed",
                confidence=99,
            ),
        ]
    )
    await db_session.commit()

    result = await ConnectorService(db_session).enqueue_ready_sources(
        connector_type="phishing", created_by=None, title="T"
    )
    assert result["status"] == "scheduled"
    params = (
        await db_session.execute(
            select(Job.params).where(Job.id == uuid.UUID(result["job_ids"][0]))
        )
    ).scalar_one()

    assert params["candidates"] == [
        {"value": "acme-login.example.net", "matched_asset": "acme"}
    ]
    # An owned name is never a candidate even when a verdict says so, and it stays in the
    # exclude list that keeps a brand scan from reporting us to ourselves.
    assert "acme.example" in params["exclude"]
    assert [item["value"] for item in params["keyword_domains"]] == [
        "acme.example",
        "acme",
    ]
    assert params["keyword_titles"] == ["ACME portal"]

    await db_session.delete(connector)
    await db_session.commit()


@pytest.mark.asyncio
async def test_a_brand_or_candidate_configuration_is_enough_to_scan(db_session):
    from app.models import Asset
    from app.models.phishing import PhishingDomain
    from app.models.source_account import SourceAccount
    from app.services.connector_service import ConnectorService

    account = SourceAccount(
        source_id="netlas",
        name="default",
        policy={"approved": True, "daily_budget": 500, "requests_per_minute": 60},
    )
    db_session.add(account)
    await db_session.flush()
    # No domain asset at all: the playlist here is a brand and a confirmed candidate.
    db_session.add(Asset(asset_type="keyword_domain", asset_value="acme"))
    connector = _phishing_connector(
        "phishing-netlas", ["certificate_brand", "body", "hostname"], account.id
    )
    db_session.add(connector)
    await db_session.flush()
    db_session.add(
        PhishingDomain(
            phishing_domain="acme-login.example.net",
            matched_asset="acme",
            detection_source="dnstwist",
            verdict="confirmed",
            confidence=88,
        )
    )
    await db_session.commit()

    result = await ConnectorService(db_session).enqueue_ready_sources(
        connector_type="phishing", created_by=None, title="T"
    )
    assert result["status"] == "scheduled"

    # The same installation with a connector that only knows the domain question has
    # nothing to scan, and says so instead of queueing an empty job.
    connector.readiness = {
        "credentials_configured": True,
        "credential_state": "valid",
        "capabilities": ["certificate"],
        "operations": ["search", "certificate"],
    }
    await db_session.delete(
        (
            await db_session.execute(
                select(PhishingDomain).where(
                    PhishingDomain.phishing_domain == "acme-login.example.net"
                )
            )
        ).scalar_one()
    )
    db_session.add(Asset(asset_type="keyword_domain", asset_value="acme"))
    await db_session.commit()
    blocked = await ConnectorService(db_session).enqueue_ready_sources(
        connector_type="phishing", created_by=None, title="T"
    )
    assert blocked["status"] == "blocked"
    assert blocked["sources"][0]["reason"] == (
        "No active assets or capabilities match this request"
    )

    await db_session.delete(connector)
    await db_session.commit()
