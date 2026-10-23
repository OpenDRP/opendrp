"""The refusals in front of a provider request, and the remainder behind it.

`test_source_intelligence.py` pins the frozen limits a queued job carries and the
key shape the reservation script reads. This file pins the guards that decide
whether a request is allowed at all — no account, a revoked approval, a lease that
expired while the worker was queued, an operation the provider does not offer — and
the two answers the health page gets when the budget cannot be measured.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.core.audit import AuditLog
from app.core.rate_limit import RateLimiter
from app.models import Connector, Job, JobStatus
from app.models.source_account import SourceAccount
from app.services.provider_quota import LIMITS, remaining_today, reserve, validate_policy



def now() -> datetime:
    """Read at call time, not at import: a full-suite run takes an hour.

    A module-level "now" would make every lease built here already expired by the
    time this file runs late in the collection, which is a property of the suite's
    length rather than of the code under test.
    """
    return datetime.now(timezone.utc)


def connector(**kwargs) -> Connector:
    values = {
        "name": f"quota-{uuid.uuid4().hex[:8]}",
        "connector_type": "phishing",
        "default_job_type": "phishing.quota",
        "provider": "netlas",
        "status": "enabled",
        "config": {"daily_budget": 90, "requests_per_minute": 30},
        "readiness": {"operations": ["search", "certificate"]},
    }
    values.update(kwargs)
    return Connector(**values)


def account(*, approved: bool = True, source_id: str = "netlas") -> SourceAccount:
    return SourceAccount(
        source_id=source_id,
        name=f"acct-{uuid.uuid4().hex[:8]}",
        policy={"approved": approved, "daily_budget": 90, "requests_per_minute": 30},
    )


async def running_job(db, caller: Connector, account_id, **kwargs) -> Job:
    values = {
        "job_type": "phishing.netlas",
        "status": JobStatus.running,
        "connector_id": caller.id,
        "claimed_by_connector": caller.name,
        "started_at": now(),
        "lease_expires_at": now() + timedelta(minutes=5),
        "params": {"source_account_id": str(account_id)},
    }
    values.update(kwargs)
    job = Job(**values)
    db.add(job)
    await db.commit()
    return job


async def ready(db, *, approved: bool = True, source_id: str = "netlas", **connector_kwargs):
    """A connector, its approved account and a running job, as a worker would hold them."""
    caller = connector(**connector_kwargs)
    owner = account(approved=approved, source_id=source_id)
    db.add_all([caller, owner])
    await db.flush()
    caller.source_account_id = owner.id
    await db.commit()
    job = await running_job(db, caller, owner.id)
    return caller, owner, job


# ---------------------------------------------------------------------------
# The guards
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_connector_without_a_provider_identity_never_reaches_the_budget(db_session):
    caller = connector(provider=None, source_account_id=None)
    db_session.add(caller)
    await db_session.commit()
    job = await running_job(db_session, caller, uuid.uuid4())

    with pytest.raises(HTTPException) as denied:
        await reserve(db_session, caller, "search", job=job)
    assert denied.value.status_code == 403
    assert "not provisioned" in denied.value.detail


@pytest.mark.asyncio
async def test_a_naive_lease_and_start_are_read_as_utc(db_session, monkeypatch):
    """SQLite drops the offset, so a lease read back from the row is naive.

    Reading it as local time would make a live lease look expired (or an expired
    one look live) depending on the deployment's timezone, which is why both
    timestamps are normalised before they are compared.
    """
    caller, _owner, job = await ready(db_session)
    moment = now()
    job.lease_expires_at = (moment + timedelta(minutes=5)).replace(tzinfo=None)
    job.started_at = moment.replace(tzinfo=None)
    await db_session.commit()

    redis = AsyncMock()
    redis.eval.return_value = [1, 0, 4]
    monkeypatch.setattr(RateLimiter, "_get_client", lambda: redis)

    payload = await reserve(db_session, caller, "search", job=job)
    assert payload["reserved"] is True and payload["remaining_today"] == 4


@pytest.mark.asyncio
async def test_a_queued_job_without_a_usable_account_identity_is_refused(db_session):
    caller, _owner, job = await ready(db_session)
    job.params = {"source_account_id": "not-a-uuid"}
    await db_session.commit()

    with pytest.raises(HTTPException) as denied:
        await reserve(db_session, caller, "search", job=job)
    assert denied.value.status_code == 403
    assert "no valid provider account identity" in denied.value.detail

    job.params = "not-a-dict"
    await db_session.commit()
    with pytest.raises(HTTPException) as denied:
        await reserve(db_session, caller, "search", job=job)
    assert denied.value.status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["revoked", "missing", "other_provider"])
async def test_an_account_the_operator_has_not_approved_is_refused_and_recorded(db_session, case, monkeypatch):
    """Approval is a live kill switch, and pulling it has to leave a trace.

    The audit row is written before the refusal because the worker's own logs are
    a different stream: "the platform stopped me because an operator revoked the
    account" belongs in the trail next to the revocation.
    """
    redis = AsyncMock()
    redis.eval.return_value = [1, 0, 1]
    monkeypatch.setattr(RateLimiter, "_get_client", lambda: redis)

    if case == "other_provider":
        caller, _owner, job = await ready(db_session, source_id="shodan")
    elif case == "revoked":
        caller, _owner, job = await ready(db_session, approved=False)
    else:
        # The job names an account that is not in the database. The connector keeps
        # a real one (the column is a foreign key); the queued identity is the
        # untrusted value the worker wrote.
        caller, _owner, job = await ready(db_session)
        job.params = {"source_account_id": str(uuid.uuid4())}
        await db_session.commit()

    with pytest.raises(HTTPException) as denied:
        await reserve(db_session, caller, "search", job=job)
    assert denied.value.status_code == 403
    assert "approved account policy" in denied.value.detail

    rows = (
        await db_session.execute(select(AuditLog).where(AuditLog.action == "source_account.quota_denied"))
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].details["reason"] == "approval_revoked_or_missing"
    assert rows[0].details["connector_id"] == str(caller.id)


@pytest.mark.asyncio
async def test_a_scan_past_its_deadline_cannot_spend_more_of_the_budget(db_session, monkeypatch):
    redis = AsyncMock()
    redis.eval.return_value = [1, 0, 1]
    monkeypatch.setattr(RateLimiter, "_get_client", lambda: redis)
    caller, _owner, job = await ready(db_session)
    job.started_at = now() - timedelta(seconds=LIMITS["scan_timeout_seconds"][2] + 1)
    await db_session.commit()

    with pytest.raises(HTTPException) as denied:
        await reserve(db_session, caller, "search", job=job)
    assert denied.value.status_code == 409
    assert "deadline" in denied.value.detail
    redis.eval.assert_not_awaited()


@pytest.mark.asyncio
async def test_an_operation_the_connector_does_not_declare_is_refused(db_session, monkeypatch):
    """The bucket names a provider endpoint, so a typo must not become a charge."""
    redis = AsyncMock()
    redis.eval.return_value = [1, 0, 1]
    monkeypatch.setattr(RateLimiter, "_get_client", lambda: redis)

    caller, _owner, job = await ready(db_session, readiness={"operations": ["search"]})
    with pytest.raises(HTTPException) as denied:
        await reserve(db_session, caller, "certificate", job=job)
    assert denied.value.status_code == 400
    assert "Unsupported operation bucket" in denied.value.detail

    # A connector that declares the operation is charged for it whatever provider
    # it names: the provider's cap is configuration now, not a branch in the core
    # (AUD-021). The declaration is still the only thing that admits the bucket.
    other, _owner, other_job = await ready(
        db_session,
        provider="shodan",
        source_id="shodan",
        readiness={"operations": ["certificate"]},
        config={"requests_per_minute": 30, "daily_budget": 90, "certificate_requests_per_minute": 2},
    )
    await reserve(db_session, other, "certificate", job=other_job)
    assert redis.eval.await_count == 1


@pytest.mark.asyncio
async def test_a_broker_that_cannot_answer_fails_closed(db_session, monkeypatch):
    caller, _owner, job = await ready(db_session)
    redis = AsyncMock()
    redis.eval.side_effect = RuntimeError("connection reset")
    monkeypatch.setattr(RateLimiter, "_get_client", lambda: redis)

    with pytest.raises(HTTPException) as denied:
        await reserve(db_session, caller, "search", job=job)
    assert denied.value.status_code == 503
    assert "quota backend unavailable" in denied.value.detail


@pytest.mark.asyncio
async def test_an_exhausted_budget_tells_the_worker_when_to_come_back(db_session, monkeypatch):
    caller, _owner, job = await ready(db_session)
    redis = AsyncMock()
    redis.eval.return_value = [0, 42]
    monkeypatch.setattr(RateLimiter, "_get_client", lambda: redis)

    with pytest.raises(HTTPException) as denied:
        await reserve(db_session, caller, "search", job=job)
    assert denied.value.status_code == 429
    assert denied.value.headers["Retry-After"] == "42"

    # A script that answered without a delay still gets a retryable answer rather
    # than a zero that would read as "retry immediately".
    redis.eval.return_value = [0]
    with pytest.raises(HTTPException) as denied:
        await reserve(db_session, caller, "search", job=job)
    assert denied.value.headers["Retry-After"] == "1"


# ---------------------------------------------------------------------------
# The remainder the health page prints
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_connector_without_an_account_has_no_remainder_to_report(db_session):
    caller = connector(provider=None, source_account_id=None)
    assert await remaining_today(db_session, caller) == {
        "remaining_today": None,
        "request_budget": None,
        "reason": "provider_account_missing",
    }


@pytest.mark.asyncio
async def test_a_budget_that_is_not_a_number_falls_back_to_the_configured_default(db_session, monkeypatch):
    redis = AsyncMock()
    redis.zcount.return_value = 0
    monkeypatch.setattr(RateLimiter, "_get_client", lambda: redis)
    caller = connector(config={"daily_budget": "plenty"}, source_account_id=uuid.uuid4())

    answer = await remaining_today(db_session, caller)
    assert answer["request_budget"] == LIMITS["daily_budget"][2]
    assert answer["remaining_today"] == LIMITS["daily_budget"][2]
    assert answer["reason"] is None


@pytest.mark.asyncio
async def test_a_missing_or_failing_broker_says_the_number_is_unknown(db_session, monkeypatch):
    """A missing number must not read as an exhausted budget."""
    caller = connector(source_account_id=uuid.uuid4())
    monkeypatch.setattr(RateLimiter, "_get_client", lambda: None)
    assert await remaining_today(db_session, caller) == {
        "remaining_today": None,
        "request_budget": 90,
        "reason": "quota_backend_unavailable",
    }

    redis = AsyncMock()
    redis.zcount.side_effect = RuntimeError("connection reset")
    monkeypatch.setattr(RateLimiter, "_get_client", lambda: redis)
    assert (await remaining_today(db_session, caller))["reason"] == "quota_backend_unavailable"


@pytest.mark.asyncio
async def test_the_remainder_is_the_budget_minus_what_the_day_bucket_holds(db_session, monkeypatch):
    redis = AsyncMock()
    redis.zcount.return_value = 37
    monkeypatch.setattr(RateLimiter, "_get_client", lambda: redis)
    caller = connector(config={"daily_budget": 90}, source_account_id=uuid.uuid4())

    answer = await remaining_today(db_session, caller)
    assert answer == {"remaining_today": 53, "request_budget": 90, "reason": None}
    key = redis.zcount.await_args.args[0]
    assert key == f"provider-quota:account:{caller.source_account_id}:day"

    # Spending past the budget is a negative remainder only if it is reported as
    # one; the page shows "none left", not a number below zero.
    redis.zcount.return_value = 120
    assert (await remaining_today(db_session, caller))["remaining_today"] == 0


@pytest.mark.asyncio
async def test_the_health_budget_is_the_accounts_approved_budget(db_session, monkeypatch):
    """AUD-020: the page prints the budget `reserve` enforces.

    `reserve` reads the queued job's snapshot, which is the connector's config
    with the account policy layered on top. The health answer read only the
    connector's own config, which carries no approved budget, so it printed
    "0 left of 100" beside a scan that was still admitted up to 500.
    """
    redis = AsyncMock()
    redis.zcount.return_value = 150
    monkeypatch.setattr(RateLimiter, "_get_client", lambda: redis)
    caller = connector(config={})
    owner = SourceAccount(
        source_id="netlas",
        name=f"acct-{uuid.uuid4().hex[:8]}",
        policy={"approved": True, "daily_budget": 500, "requests_per_minute": 30},
    )
    db_session.add_all([caller, owner])
    await db_session.flush()
    caller.source_account_id = owner.id
    await db_session.commit()

    assert await remaining_today(db_session, caller) == {
        "remaining_today": 350,
        "request_budget": 500,
        "reason": None,
    }


@pytest.mark.asyncio
async def test_a_connector_that_names_no_provider_gets_the_ceiling_it_declares(db_session, monkeypatch):
    """AUD-021: the cap is connector configuration, not a provider name.

    The core refused a per-request ceiling to every provider except the one it
    named, so a second provider onboarded as data had no cap it could set. The
    ceiling now comes from the connector's own config and applies to whatever
    provider the row names.
    """
    redis = AsyncMock()
    redis.eval.return_value = [1, 0, 10]
    monkeypatch.setattr(RateLimiter, "_get_client", lambda: redis)
    caller, _owner, job = await ready(
        db_session,
        source_id="acme",
        provider="acme",
        config={
            "requests_per_minute": 100,
            "daily_budget": 500,
            "requests_per_minute_ceiling": 40,
        },
    )

    await reserve(db_session, caller, "search", job=job)

    args = redis.eval.await_args.args
    key_count = int(args[1])
    limits = [int(value) for value in args[3 + key_count : -1]]
    assert limits[0] == 40, "the minute window is capped by the connector's declaration"


@pytest.mark.asyncio
async def test_the_certificate_bucket_answers_to_its_own_cap_not_the_provider_name(db_session, monkeypatch):
    """AUD-021: the certificate operation is gated by a declared cap.

    `bucket == "certificate"` was allowed for one provider by name and refused
    with 400 for every other; the operation the readiness row declares is the
    only thing that should decide, and its cap is configuration.
    """
    redis = AsyncMock()
    redis.eval.return_value = [1, 0, 10]
    monkeypatch.setattr(RateLimiter, "_get_client", lambda: redis)
    caller, _owner, job = await ready(
        db_session,
        source_id="acme",
        provider="acme",
        config={
            "requests_per_minute": 100,
            "daily_budget": 500,
            "certificate_requests_per_minute": 2,
        },
    )

    await reserve(db_session, caller, "certificate", job=job)

    args = redis.eval.await_args.args
    key_count = int(args[1])
    keys = list(args[2 : 2 + key_count])
    limits = [int(value) for value in args[3 + key_count : -1]]
    assert any(key.endswith(":cert-minute") for key in keys)
    assert limits[2] == 2

    # The declared cap is what the certificate bucket is capped at; a connector
    # that declares none keeps the default ceiling rather than an unbounded one.
    plain_caller, _owner2, plain_job = await ready(db_session, source_id="acme", provider="acme", config={"requests_per_minute": 100, "daily_budget": 500})
    await reserve(db_session, plain_caller, "certificate", job=plain_job)
    plain_args = redis.eval.await_args.args
    plain_limits = [int(value) for value in plain_args[3 + int(plain_args[1]) : -1]]
    assert plain_limits[2] == 3


def test_a_cap_outside_the_documented_range_is_refused():
    """A cap is a setting; a setting nobody validates is a number nobody can trust."""
    with pytest.raises(ValueError, match="certificate_requests_per_minute"):
        validate_policy({"certificate_requests_per_minute": 9999})
    with pytest.raises(ValueError, match="requests_per_minute_ceiling"):
        validate_policy({"requests_per_minute_ceiling": 0})
