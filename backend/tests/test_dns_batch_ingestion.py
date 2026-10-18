"""A DNS batch costs one upsert and one control read, not one per observation (F-17).

The worker submits observations in batches of 50 - that is the platform's own protocol -
but the core used to ingest them one at a time, so each observation ran its own upsert
and re-read the expiry control rows it feeds: a 500-observation scan was 500 of each.
These tests pin the batched shape against the statements a session actually sends, the
outcome accounting that has to survive it, and the property that matters to an analyst:
every arrival rule still sees the state that was stored *before* the batch.
"""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import event, select

from app.models import Connector, IngestionEvent
from app.models.asset import Asset, AssetType
from app.models.dns_expiry_monitor import DNSExpiryMonitor
from app.models.dns_observation import DNSObservation
from app.services.ingestion_service import ingest_findings

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def record_observation(index: int, address: str = "203.0.113.1") -> dict:
    subject = f"host{index}.example.com"
    return {
        "observation_type": "dns_record",
        "subject": subject,
        "record_type": "A",
        "value": address,
        "metadata": {"record_values": [address], "ttl": 300, "source_domain": subject},
    }


def registration_observation(subject: str) -> dict:
    return {
        "observation_type": "rdap",
        "subject": subject,
        "record_type": "RDAP",
        "value": subject,
        "expires_at": (NOW + timedelta(days=100)).isoformat(),
        "metadata": {"provider": "rdap", "epp_status": ["client transfer prohibited"]},
    }


async def dns_connector(db, *, name: str, source: str, asset: str | None = None) -> Connector:
    """A DNS worker whose observations carry the provider identity of its source."""
    if asset:
        db.add(Asset(asset_type=AssetType.domain, asset_value=asset, normalized_value=asset, is_active=True))
    connector = Connector(
        name=name,
        connector_type="dns",
        default_job_type=f"dns.{source}",
        status="enabled",
        aliases=[name, f"{source}-dns-security-default"],
    )
    db.add(connector)
    await db.flush()
    return connector


def statement_counter(db):
    """Record the SQL a session actually sends, in order."""
    bind = db.get_bind()
    engine = getattr(bind, "sync_engine", bind)
    seen: list[str] = []

    def record(conn, cursor, statement, parameters, context, executemany):
        seen.append(" ".join(statement.split()).lower())

    event.listen(engine, "before_cursor_execute", record)
    return seen, lambda: event.remove(engine, "before_cursor_execute", record)


def statements_for(seen: list[str], table: str, verb: str | None = None) -> list[str]:
    return [
        statement
        for statement in seen
        if table in statement and (verb is None or statement.startswith(verb))
    ]


@pytest.mark.asyncio
async def test_fifty_record_observations_are_one_upsert_and_one_control_read(db_session):
    connector = await dns_connector(db_session, name="dns-resolver", source="resolver")
    findings = [record_observation(index) for index in range(50)]
    seen, stop = statement_counter(db_session)
    try:
        result = await ingest_findings(db_session, connector=connector, job_id=None, findings=findings)
        await db_session.commit()
    finally:
        stop()

    assert result.created == 50 and result.rejected == 0
    assert len(list((await db_session.execute(select(DNSObservation))).scalars())) == 50

    # One INSERT ... ON CONFLICT for all fifty rows, and exactly two reads that do not
    # grow with the batch: the state each key had before it, and the control rows that
    # feed the expiry monitors.
    assert len(statements_for(seen, "dns_security_observations", "insert")) == 1
    assert len(statements_for(seen, "dns_security_observations", "select")) == 2
    assert len(statements_for(seen, "dns_security_observations")) == 3
    # Nothing here is a control observation, so no monitor row is touched at all.
    assert statements_for(seen, "dns_expiry_monitors") == []


@pytest.mark.asyncio
async def test_the_control_work_follows_control_rows_and_not_observation_count(db_session):
    """Storage is per batch; the expiry monitors are per control row, as designed."""
    connector = await dns_connector(db_session, name="dns-rdap", source="rdap")
    subjects = [f"site{index}.example.com" for index in range(5)]
    for subject in subjects:
        db_session.add(Asset(asset_type=AssetType.domain, asset_value=subject, normalized_value=subject, is_active=True))
    await db_session.commit()
    seen, stop = statement_counter(db_session)
    try:
        result = await ingest_findings(
            db_session,
            connector=connector,
            job_id=None,
            findings=[registration_observation(subject) for subject in subjects],
        )
        await db_session.commit()
    finally:
        stop()

    assert result.created == 5 and result.rejected == 0
    assert len(statements_for(seen, "dns_security_observations", "insert")) == 1
    assert len(statements_for(seen, "dns_security_observations", "select")) == 2
    # One control read for the whole batch, and monitor work bounded by the five control
    # rows rather than by the five submitted observations.
    assert sum(1 for statement in seen if "observation_type in" in statement) == 1
    monitors_seen = statements_for(seen, "dns_expiry_monitors")
    assert sum(1 for statement in monitors_seen if statement.startswith("insert")) == 5
    assert len(monitors_seen) <= 12, monitors_seen
    monitors = list((await db_session.execute(select(DNSExpiryMonitor))).scalars())
    assert len(monitors) == 5
    assert all(monitor.subject in subjects for monitor in monitors)
    assert all(monitor.state == "verified" and monitor.expires_at for monitor in monitors)


@pytest.mark.asyncio
async def test_the_batch_still_reports_arrivals_and_outcomes_per_observation(db_session):
    """Batching may not cost the module its per-observation verdicts (F-01, F-17)."""
    connector = await dns_connector(db_session, name="dns-resolver", source="resolver")
    initial = await ingest_findings(
        db_session, connector=connector, job_id=None, findings=[record_observation(1)]
    )
    await db_session.commit()
    assert initial.created == 1 and initial.updated == 0 and initial.unchanged == 0

    # An idempotent replay next to a new observation is reported per observation.
    replay = [record_observation(1), record_observation(2, "203.0.113.9")]
    second = await ingest_findings(db_session, connector=connector, job_id=None, findings=replay)
    await db_session.commit()
    assert second.unchanged == 1 and second.created == 1 and second.rejected == 0

    await ingest_findings(
        db_session,
        connector=connector,
        job_id=None,
        findings=[record_observation(2, "203.0.113.10"), record_observation(1)],
    )
    await db_session.commit()
    events = [
        event.payload
        for event in (await db_session.execute(select(IngestionEvent))).scalars()
        if event.kind == "notification"
    ]
    assert len(events) == 1
    assert events[0]["rule"] == "dns.record.changed"
    assert events[0]["host"] == "host2.example.com"
    assert events[0]["Previous values"] == "203.0.113.9"
    assert events[0]["Current values"] == "203.0.113.10"

    # One malformed observation is refused on its own instead of failing its
    # neighbours, exactly as the per-observation path refused it.
    mixed = [record_observation(3), {"observation_type": "dns_record", "subject": "https://not-a-name/"}]
    third = await ingest_findings(db_session, connector=connector, job_id=None, findings=mixed)
    await db_session.commit()
    assert third.created == 1 and third.rejected == 1
    assert third.errors == [{"index": 1, "code": "invalid_observation", "retryable": False}]
