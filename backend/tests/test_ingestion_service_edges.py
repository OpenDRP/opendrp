"""Characterization tests: ingestion edge branches.

Ingestion *enqueues* findings into the durable alert queue
(``AlertDeliveryService``), which a worker drains, so a provider outage cannot
delay, fail or roll back a finding that is already durable. The patches below
name the queue for that reason — they stand in for the handoff, not for a
delivery.

``app/services/ingestion_service.py`` edge branches:
* batch entry rejects non-list input and non-dict entries;
* the 500-findings batch cap is enforced;
* missing phishing domain / breach name / breach match are rejected;
* unknown connector type is rejected;
* defensive date parsing for HIBP metadata (ISO strings, 'Z' suffix,
  datetimes, garbage, epoch default);
* malformed date strings fall back instead of raising (pinned current
  behavior of the 1970-01-01 default);
* unknown connector type is rejected;
* data_classes is kept only when it is a real list.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime

import pytest
from sqlalchemy import select

from app.models.connector import Connector
from app.models.breach import Breach
from app.models.phishing import PhishingDomain
from app.services.ingestion_service import (
    ingest_phishing_finding,
    _MAX_FINDINGS_PER_BATCH,
    ingest_breach_finding,
    ingest_findings,
)


@pytest.fixture(autouse=True)
def _stub_whois(monkeypatch):
    """Whois enrichment is core-side best-effort; stub the subprocess out.

    ``ingest_phishing_finding`` imports ``WhoisService`` at call time, so
    patching the class attribute is picked up on every call (same approach as
    the connector protocol tests).
    """

    async def _noop(self, threat):  # noqa: ANN001
        return None

    monkeypatch.setattr(
        "app.services.phishing.whois_service.WhoisService.enrich", _noop
    )


@pytest.fixture
async def phishing_connector(db_session):
    c = Connector(
        name=f"conn-phish-{uuid.uuid4().hex[:8]}",
        connector_type="phishing",
        status="enabled",
        default_job_type="phishing.dnstwist",
    )
    db_session.add(c)
    await db_session.commit()
    await db_session.refresh(c)
    return c


@pytest.fixture
async def breaches_connector(db_session):
    c = Connector(
        name=f"conn-hibp-{uuid.uuid4().hex[:8]}",
        connector_type="breaches",
        status="enabled",
        default_job_type="breaches.hibp",
    )
    db_session.add(c)
    await db_session.commit()
    await db_session.refresh(c)
    return c


async def _count(db, model) -> int:
    from sqlalchemy import func

    return int((await db.execute(select(func.count(model.id)))).scalar_one() or 0)


# ---------------------------------------------------------------------------
# Ingestion edge branches
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_findings_rejects_non_list(
    db_session, phishing_connector, monkeypatch
):
    monkeypatch.setattr(
        "app.services.ingestion_service.AlertDeliveryService.enqueue",
        _never_called_patch,
    )
    accepted, rejected = await ingest_findings(
        db_session,
        connector=phishing_connector,
        job_id=uuid.uuid4(),
        findings="not-a-list",
        connector_name=phishing_connector.name,
        connector_type="phishing",
    )
    assert (accepted, rejected) == (0, 0)
    assert await _count(db_session, PhishingDomain) == 0


@pytest.mark.asyncio
async def test_ingest_batch_cap_enforced(
    db_session, phishing_connector, monkeypatch
):
    """Entries beyond the 500 cap are silently dropped (not counted)."""
    monkeypatch.setattr(
        "app.services.ingestion_service.AlertDeliveryService.enqueue",
        _no_alert,
    )
    oversized = [
        {"phishing_domain": f"cap-{i}.example.com"} for i in range(_MAX_FINDINGS_PER_BATCH + 5)
    ]
    accepted, rejected = await ingest_findings(
        db_session,
        connector=phishing_connector,
        job_id=uuid.uuid4(),
        findings=oversized,
        connector_name=phishing_connector.name,
        connector_type="phishing",
    )
    assert accepted == _MAX_FINDINGS_PER_BATCH
    assert rejected == 0
    assert await _count(db_session, PhishingDomain) == _MAX_FINDINGS_PER_BATCH


@pytest.mark.asyncio
async def test_ingest_mixed_valid_and_non_dict_entries(
    db_session, phishing_connector, monkeypatch
):
    monkeypatch.setattr(
        "app.services.ingestion_service.AlertDeliveryService.enqueue",
        _no_alert,
    )
    findings = [
        {"phishing_domain": "good.example.com"},
        "a-string-entry",
        42,
        None,
        {"phishing_domain": "  "},
    ]
    accepted, rejected = await ingest_findings(
        db_session,
        connector=phishing_connector,
        job_id=uuid.uuid4(),
        findings=findings,
        connector_name=phishing_connector.name,
        connector_type="phishing",
    )
    assert (accepted, rejected) == (1, 4)
    assert await _count(db_session, PhishingDomain) == 1


@pytest.mark.asyncio
async def test_ingest_unknown_connector_type_rejects_all(
    db_session, phishing_connector, monkeypatch
):
    monkeypatch.setattr(
        "app.services.ingestion_service.AlertDeliveryService.enqueue",
        _never_called_patch,
    )
    accepted, rejected = await ingest_findings(
        db_session,
        connector=phishing_connector,
        job_id=uuid.uuid4(),
        findings=[{"phishing_domain": "x.example.com"}],
        connector_name=phishing_connector.name,
        connector_type="brand-monitoring",
    )
    assert (accepted, rejected) == (0, 1)
    assert await _count(db_session, PhishingDomain) == 0


@pytest.mark.asyncio
async def test_ingest_breach_requires_name_and_match(
    db_session, breaches_connector, monkeypatch
):
    monkeypatch.setattr(
        "app.services.ingestion_service.AlertDeliveryService.enqueue",
        _never_called_patch,
    )
    ok1 = await ingest_breach_finding(db_session, breaches_connector, {"matched_email": "a@x.com"})
    ok2 = await ingest_breach_finding(db_session, breaches_connector, {"breach_name": "B"})
    ok3 = await ingest_breach_finding(
        db_session, breaches_connector, {"breach_name": "B3", "matched_email": "", "matched_domain": ""}
    )
    assert ok1 is False and ok2 is False and ok3 is False
    assert await _count(db_session, Breach) == 0


@pytest.mark.asyncio
async def test_ingest_breach_keeps_only_real_lists_and_defaults(
    db_session, breaches_connector, monkeypatch
):
    monkeypatch.setattr(
        "app.services.ingestion_service.AlertDeliveryService.enqueue",
        _no_alert,
    )
    ok = await ingest_breach_finding(
        db_session,
        breaches_connector,
        {
            "breach_name": "WeirdMeta",
            "matched_domain": "corp.example.com",
            "data_classes": "Emails,Passwords",
            "is_verified": 1,
            "breach_date": "2020-05-06",
        },
    )
    assert ok is True
    row = (
        await db_session.execute(select(Breach).where(Breach.breach_name == "WeirdMeta"))
    ).scalar_one()
    assert row.data_classes == []
    assert row.breach_date == date(2020, 5, 6)
    # A provider field outside ``attributes`` is not part of the protocol: it is
    # dropped rather than folded in, so what the connector sent is what was
    # stored.
    assert row.attributes == {}


@pytest.mark.asyncio
async def test_ingest_breach_non_numeric_pwn_count_is_safe(
    db_session, breaches_connector, monkeypatch
):
    """Malformed provider counters must not abort the whole ingestion job."""
    monkeypatch.setattr(
        "app.services.ingestion_service.AlertDeliveryService.enqueue",
        _no_alert,
    )
    ok = await ingest_breach_finding(
        db_session,
        breaches_connector,
        {
            "breach_name": "BadCount",
            "matched_domain": "corp.example.com",
            "pwn_count": "not-a-number",
        },
    )
    assert ok is True
    row = (
        await db_session.execute(select(Breach).where(Breach.breach_name == "BadCount"))
    ).scalar_one()
    assert row.pwn_count == 0


@pytest.mark.asyncio
async def test_ingest_breach_duplicate_email_pair_rejected(
    db_session, breaches_connector, monkeypatch
):
    monkeypatch.setattr(
        "app.services.ingestion_service.AlertDeliveryService.enqueue",
        _no_alert,
    )
    finding = {"breach_name": "DupPair", "matched_email": "dup@x.com"}
    first = await ingest_breach_finding(db_session, breaches_connector, finding)
    second = await ingest_breach_finding(db_session, breaches_connector, dict(finding))
    assert first is True and second is False
    assert await _count(db_session, Breach) == 1


@pytest.mark.asyncio
async def test_ingest_breach_keeps_same_breach_for_multiple_domain_aliases(
    db_session, breaches_connector, monkeypatch
):
    """A domain scan's affected email is the deduplication identity.

    HIBP can report Adobe for several aliases of one domain. The shared domain
    must not cause valid account-level findings to be discarded.
    """
    monkeypatch.setattr(
        "app.services.ingestion_service.AlertDeliveryService.enqueue",
        _no_alert,
    )
    common = {"breach_name": "Adobe", "matched_domain": "hibp-integration-tests.com"}
    first = await ingest_breach_finding(
        db_session,
        breaches_connector,
        {**common, "matched_email": "account-exists@hibp-integration-tests.com"},
    )
    second = await ingest_breach_finding(
        db_session,
        breaches_connector,
        {**common, "matched_email": "multiple-breaches@hibp-integration-tests.com"},
    )
    assert first is True and second is True
    rows = (
        await db_session.execute(
            select(Breach).where(Breach.breach_name == "Adobe")
        )
    ).scalars().all()
    assert {row.matched_email for row in rows} == {
        "account-exists@hibp-integration-tests.com",
        "multiple-breaches@hibp-integration-tests.com",
    }


@pytest.mark.asyncio
async def test_ingest_breach_domain_only_fallback_is_still_deduped(
    db_session, breaches_connector, monkeypatch
):
    """The fallback identity remains unique when no affected email exists."""
    monkeypatch.setattr(
        "app.services.ingestion_service.AlertDeliveryService.enqueue",
        _no_alert,
    )
    finding = {"breach_name": "DomainOnly", "matched_domain": "example.com"}
    first = await ingest_breach_finding(db_session, breaches_connector, finding)
    second = await ingest_breach_finding(db_session, breaches_connector, dict(finding))
    assert first is True and second is False
    assert await _count(db_session, Breach) == 1


# ---------------------------------------------------------------------------
# Failure isolation of the phishing write path (Step 5 resilience pins)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_phishing_persisted_when_whois_enrichment_fails(
    db_session, phishing_connector, monkeypatch
):
    """Best-effort enrichment must never block persistence (pinned)."""

    async def _boom(self, threat):  # noqa: ANN001
        raise RuntimeError("whois binary missing")

    monkeypatch.setattr(
        "app.services.phishing.whois_service.WhoisService.enrich", _boom
    )
    monkeypatch.setattr(
        "app.services.ingestion_service.AlertDeliveryService.enqueue", _no_alert
    )
    ok = await ingest_phishing_finding(
        db_session,
        phishing_connector,
        {"phishing_domain": "whois-boom.example.com"},
    )
    assert ok is True
    row = (
        await db_session.execute(
            select(PhishingDomain).where(
                PhishingDomain.phishing_domain == "whois-boom.example.com"
            )
        )
    ).scalar_one()
    assert row.status == "active"


@pytest.mark.asyncio
async def test_phishing_persisted_when_alert_fanout_fails(
    db_session, phishing_connector, monkeypatch
):
    """Alert-dispatch errors must not fail the ingestion result (pinned)."""

    async def _boom(*args, **kwargs):
        raise RuntimeError("redis down")

    monkeypatch.setattr(
        "app.services.ingestion_service.AlertDeliveryService.enqueue", _boom
    )
    ok = await ingest_phishing_finding(
        db_session,
        phishing_connector,
        {"phishing_domain": "alert-boom.example.com"},
    )
    assert ok is True
    assert await _count(db_session, PhishingDomain) == 1


# ---------------------------------------------------------------------------
# Pure date-parser pins (Step 5): edge behavior of the HIBP metadata parsing
# ---------------------------------------------------------------------------

async def _parse_date_via_ingest(db, connector, value, monkeypatch) -> date:
    """Drive _parse_date through the public path with a minimal finding."""
    monkeypatch.setattr(
        "app.services.ingestion_service.AlertDeliveryService.enqueue",
        _no_alert,
    )
    ok = await ingest_breach_finding(
        db,
        connector,
        {"breach_name": f"D{uuid.uuid4().hex[:6]}", "matched_domain": "d.example.com", "breach_date": value},
    )
    assert ok is True
    rows = list((await db.execute(select(Breach))).scalars())
    return rows[-1].breach_date


@pytest.mark.asyncio
async def test_parse_date_garbage_falls_back_to_epoch(
    db_session, breaches_connector, monkeypatch
):
    """TODO(refactor-step-5): pinned current fallback behavior.

    A malformed breach_date silently becomes 1970-01-01 instead of being
    rejected. Changing this to a validation error is a separately-reviewed
    behavior change.
    """
    d = await _parse_date_via_ingest(db_session, breaches_connector, "06/05/2020", monkeypatch)
    assert d == date(1970, 1, 1)


@pytest.mark.asyncio
async def test_parse_date_iso_string_accepted(db_session, breaches_connector, monkeypatch):
    d = await _parse_date_via_ingest(db_session, breaches_connector, "2021-11-03", monkeypatch)
    assert d == date(2021, 11, 3)


@pytest.mark.asyncio
async def test_parse_date_epoch_fallback_on_none(db_session, breaches_connector, monkeypatch):
    d = await _parse_date_via_ingest(db_session, breaches_connector, None, monkeypatch)
    assert d == date(1970, 1, 1)


# ---------------------------------------------------------------------------
# Batch-level pins: duplicates, alert task gather, batch fallback, breaches
# via the batch entry point
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_phishing_duplicate_rejected_without_alert(
    db_session, phishing_connector, monkeypatch
):
    """Unique(phishing_domain): duplicate skips quietly and never alerts."""
    calls: list[dict] = []

    async def _recording_alert(*args, **kwargs):
        calls.append({})
        return None

    monkeypatch.setattr(
        "app.services.ingestion_service.AlertDeliveryService.enqueue",
        _recording_alert,
    )
    first = await ingest_phishing_finding(
        db_session, phishing_connector, {"phishing_domain": "dup.example.com"}
    )
    second = await ingest_phishing_finding(
        db_session, phishing_connector, {"phishing_domain": "dup.example.com"}
    )
    assert first is True and second is False
    assert len(calls) == 1, "duplicate must not fan out an alert"
    assert await _count(db_session, PhishingDomain) == 1


@pytest.mark.asyncio
async def test_ingest_breach_via_batch_entry_alerts_once_per_finding(
    db_session, breaches_connector, monkeypatch
):
    """Batch entry passes findings through and enqueues one alert per finding."""
    calls: list[dict] = []

    async def _recording_alert(*args, **kwargs):
        calls.append({})
        return None

    monkeypatch.setattr(
        "app.services.ingestion_service.AlertDeliveryService.enqueue",
        _recording_alert,
    )
    accepted, rejected = await ingest_findings(
        db_session,
        connector=breaches_connector,
        job_id=uuid.uuid4(),
        findings=[
            {"breach_name": "BatchB1", "matched_email": "b1@x.com"},
            {"breach_name": "BatchB1", "matched_email": "b2@x.com"},
            {"breach_name": "BatchB1", "matched_email": ""},
        ],
        connector_name=breaches_connector.name,
        connector_type="breaches",
    )
    assert (accepted, rejected) == (2, 1)
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_ingest_batch_falls_back_to_connector_context(
    db_session, phishing_connector, monkeypatch
):
    """Direct callers may omit the request-context snapshots."""
    monkeypatch.setattr(
        "app.services.ingestion_service.AlertDeliveryService.enqueue", _no_alert
    )
    accepted, rejected = await ingest_findings(
        db_session,
        connector=phishing_connector,
        job_id=uuid.uuid4(),
        findings=[{"phishing_domain": "fallback.example.com"}],
    )
    assert (accepted, rejected) == (1, 0)


@pytest.mark.asyncio
async def test_ingest_source_timestamps_are_kept_verbatim(db_session, breaches_connector, monkeypatch):
    """A source's own catalog timestamps are opaque attributes, not parsed.

    The core does not second-guess one vendor's timestamp format: whatever the
    source reported is preserved for the analyst exactly as sent, inside the
    payload that belongs to the source.
    """
    monkeypatch.setattr(
        "app.services.ingestion_service.AlertDeliveryService.enqueue", _no_alert
    )
    for name, raw in (
        ("DtCheck", "2024-03-04T05:06:07Z"),
        ("DtGarbage", "04/03/2024 05:06"),
    ):
        ok = await ingest_breach_finding(
            db_session,
            breaches_connector,
            {
                "breach_name": name,
                "matched_domain": f"{name.lower()}.example.com",
                "attributes": {"added_date": raw},
            },
        )
        assert ok is True
        row = (
            await db_session.execute(
                select(Breach).where(Breach.breach_name == name)
            )
        ).scalar_one()
        assert row.attributes["added_date"] == raw


@pytest.mark.asyncio
async def test_ingest_types_core_fields_and_stores_only_declared_extras(
    db_session, breaches_connector, monkeypatch
):
    """A date on a core field is typed, and a source's own field is stored only
    where the source declared it (``attributes``) — it is never reinterpreted as
    a core field, and the wire protocol refuses it anywhere else."""
    monkeypatch.setattr(
        "app.services.ingestion_service.AlertDeliveryService.enqueue", _no_alert
    )
    name = "DtObjects"
    ok = await ingest_breach_finding(
        db_session,
        breaches_connector,
        {
            "breach_name": name,
            "matched_domain": "dto.example.com",
            "breach_date": date(2019, 7, 1),
            "attributes": {"source_updated": "2024-01-02 03:04:05"},
        },
    )
    assert ok is True
    row = (
        await db_session.execute(select(Breach).where(Breach.breach_name == name))
    ).scalar_one()
    assert row.breach_date == date(2019, 7, 1)
    assert row.attributes["source_updated"] == "2024-01-02 03:04:05"

    # A source field next to the neutral ones has no place to land: this layer
    # reads the neutral fields and the declared payload, so nothing is invented
    # from an unrecognised key.
    ok = await ingest_breach_finding(
        db_session,
        breaches_connector,
        {
            "breach_name": "DtTopLevel",
            "matched_domain": "toplevel.example.com",
            "added_date": "2024-01-02 03:04:05",
        },
    )
    assert ok is True
    stored = (
        await db_session.execute(
            select(Breach).where(Breach.breach_name == "DtTopLevel")
        )
    ).scalar_one()
    assert stored.attributes == {}


@pytest.mark.asyncio
async def test_ingest_serializes_attribute_values_the_payload_can_carry(
    db_session, breaches_connector, monkeypatch
):
    """Direct service callers may hand over native date/datetime instances, which
    are stringified into the attribute payload rather than dropped."""
    monkeypatch.setattr(
        "app.services.ingestion_service.AlertDeliveryService.enqueue", _no_alert
    )
    name = "DtAttribute"
    ok = await ingest_breach_finding(
        db_session,
        breaches_connector,
        {
            "breach_name": name,
            "matched_domain": "attr.example.com",
            "attributes": {"added_date": datetime(2024, 1, 2, 3, 4, 5)},
        },
    )
    assert ok is True
    row = (
        await db_session.execute(select(Breach).where(Breach.breach_name == name))
    ).scalar_one()
    assert row.attributes["added_date"] == "2024-01-02 03:04:05"


@pytest.mark.asyncio
async def test_phishing_db_failure_returns_false(
    db_session, phishing_connector, monkeypatch
):
    """Generic commit errors are swallowed: finding rejected, no raise."""
    from unittest.mock import AsyncMock

    monkeypatch.setattr(
        "app.services.ingestion_service.AlertDeliveryService.enqueue", _no_alert
    )
    original_commit = db_session.commit
    db_session.commit = AsyncMock(side_effect=RuntimeError("db gone"))
    try:
        ok = await ingest_phishing_finding(
            db_session, phishing_connector, {"phishing_domain": "dbfail.example.com"}
        )
    finally:
        db_session.commit = original_commit
    assert ok is False


@pytest.mark.asyncio
async def test_breach_db_failure_returns_false(
    db_session, breaches_connector, monkeypatch
):
    from unittest.mock import AsyncMock

    monkeypatch.setattr(
        "app.services.ingestion_service.AlertDeliveryService.enqueue", _no_alert
    )
    original_commit = db_session.commit
    db_session.commit = AsyncMock(side_effect=RuntimeError("db gone"))
    try:
        ok = await ingest_breach_finding(
            db_session,
            breaches_connector,
            {"breach_name": "DbFailB", "matched_domain": "dbfail.example.com"},
        )
    finally:
        db_session.commit = original_commit
    assert ok is False


@pytest.mark.asyncio
async def test_ingest_batch_without_connector_context_rejects_all(
    db_session, monkeypatch
):
    """Unusable connector context rejects the whole batch defensively."""
    accepted, rejected = await ingest_findings(
        db_session,
        connector=None,  # type: ignore[arg-type]
        job_id=uuid.uuid4(),
        findings=[{"phishing_domain": "x.example.com"}],
    )
    assert (accepted, rejected) == (0, 1)


@pytest.mark.asyncio
async def test_ingest_awaits_the_queue_handoff(
    db_session, phishing_connector, breaches_connector, monkeypatch
):
    """Both write paths await the queue handoff before returning.

    This replaces the "awaits the task handle the dispatcher returned" pin. The
    fire-and-forget hook that justified it is gone; what matters now is that
    ingestion does not report an accepted finding before its notification row is
    written, because a finding that is durable while its alert is dropped is
    exactly the failure the queue exists to prevent.
    """
    from app.services.alert_delivery_service import AlertDeliveryService

    handed_off: list[str] = []

    async def _record(self, *, threat_type, details, job_id=None):
        handed_off.append(threat_type)
        return None

    monkeypatch.setattr(AlertDeliveryService, "enqueue", _record)

    ok = await ingest_phishing_finding(
        db_session, phishing_connector, {"phishing_domain": "gather-p.example.com"}
    )
    assert ok is True

    ok = await ingest_breach_finding(
        db_session,
        breaches_connector,
        {"breach_name": "GatherB", "matched_domain": "gather.example.com"},
    )
    assert ok is True

    assert handed_off == ["phishing", "breach"]


@pytest.mark.asyncio
async def test_breach_alert_fanout_failure_does_not_fail_ingestion(
    db_session, breaches_connector, monkeypatch
):
    """Mirror of the phishing resilience pin, for the breach write path."""

    async def _boom(*args, **kwargs):
        raise RuntimeError("broker down")

    monkeypatch.setattr(
        "app.services.ingestion_service.AlertDeliveryService.enqueue", _boom
    )
    ok = await ingest_breach_finding(
        db_session,
        breaches_connector,
        {"breach_name": "AlertFailB", "matched_domain": "alertfail.example.com"},
    )
    assert ok is True


# ---------------------------------------------------------------------------
# Alert-mock helpers
# ---------------------------------------------------------------------------


async def _no_alert(*args, **kwargs):
    return None


async def _never_called_patch(*args, **kwargs):
    raise AssertionError("alert fan-out must not be reached in this test")
