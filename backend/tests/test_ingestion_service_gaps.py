"""The branches ingestion takes when its input or its storage is not ideal.

Coverage batch 05. ``test_ingestion_service_edges.py`` pins the contract
rejections; this file pins the helpers every finding passes through, the
refusals of the direct service entry points, and the two storage shapes a DNS
batch can take: one upsert, or one observation at a time after a uniqueness
race rolled the batch back.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from types import SimpleNamespace

import pytest
from sqlalchemy.exc import IntegrityError

from app.models import Asset, AssetType, Connector
from app.services import ingestion_service
from app.services.ingestion_service import (
    _json_safe,
    _parse_breach_date,
    _parse_date,
    dns_arrival,
    ingest_breach_finding,
    ingest_dns_observation_finding,
    ingest_findings,
    ingest_generic_finding,
)


def test_json_safe_stringifies_the_types_a_plugin_may_send():
    identifier = uuid.uuid4()
    value = _json_safe(
        {"at": datetime(2024, 1, 2, 3, 4, 5), "day": date(2024, 1, 2), "id": identifier}
    )

    assert value == {
        "at": "2024-01-02 03:04:05",
        "day": "2024-01-02",
        "id": str(identifier),
    }


def test_json_safe_refuses_a_value_it_cannot_carry():
    with pytest.raises(ValueError, match="not JSON serializable"):
        _json_safe({"x": object()})
    # NaN is not JSON; persisting it as a Python repr is the defect this guards.
    with pytest.raises(ValueError, match="not JSON serializable"):
        _json_safe({"x": float("nan")})


def test_parse_date_answers_a_usable_date_or_the_epoch():
    assert _parse_date("2024-01-02T03:04:05Z") == date(2024, 1, 2)
    assert _parse_date(date(2020, 5, 6)) == date(2020, 5, 6)
    assert _parse_date("nonsense") == date(1970, 1, 1)
    assert _parse_date(None) == date(1970, 1, 1)


def test_parse_breach_date_keeps_a_missing_date_missing():
    """A breach with no date is not a breach on 1970-01-01."""
    assert _parse_breach_date(date(2020, 5, 6)) == date(2020, 5, 6)
    assert _parse_breach_date(datetime(2020, 5, 6, 1, 2)) == date(2020, 5, 6)
    assert _parse_breach_date("nonsense") is None
    assert _parse_breach_date(None) is None


def test_an_rdap_arrival_without_a_subject_has_nothing_to_report():
    assert dns_arrival({"metadata": {}}, {"observation_type": "rdap"}, "netlas") is None


async def _breach_connector(db):
    connector = Connector(
        name=f"conn-breach-{uuid.uuid4().hex[:8]}",
        connector_type="breaches",
        default_job_type="breaches.hibp",
        status="enabled",
        aliases=["hibp"],
    )
    db.add(connector)
    await db.flush()
    return connector


@pytest.mark.asyncio
async def test_a_direct_ingest_without_a_connector_is_refused(db_session):
    """Every per-module entry point shares this guard."""
    assert await ingest_generic_finding(db_session, None, {"repository": "x"}) is False


@pytest.mark.asyncio
async def test_a_direct_ingest_naming_an_unknown_job_still_stores_the_finding(
    db_session, monkeypatch
):
    connector = await _breach_connector(db_session)

    async def _no_alert(*_args, **_kwargs):
        return None

    monkeypatch.setattr(
        "app.services.ingestion_service.AlertDeliveryService.enqueue", _no_alert
    )

    stored = await ingest_breach_finding(
        db_session,
        connector,
        {
            "breach_name": "DirectJob",
            "matched_domain": "direct.example.com",
            "breach_date": "2021-02-03",
        },
        job_id=uuid.uuid4(),
    )

    assert stored is True


@pytest.mark.asyncio
async def test_a_direct_ingest_refuses_a_spec_for_another_module(db_session):
    connector = await _breach_connector(db_session)
    refused = await ingest_breach_finding(
        db_session,
        connector,
        {"breach_name": "Nope", "matched_domain": "nope.example.com"},
        module_spec=SimpleNamespace(id="phishing"),
    )

    assert refused is False


async def _dns_connector(db, *, source: str = "netlas", asset: str = "example.com"):
    db.add(
        Asset(
            asset_type=AssetType.domain,
            asset_value=asset,
            normalized_value=asset,
            is_active=True,
        )
    )
    connector = Connector(
        name=f"conn-dns-{uuid.uuid4().hex[:8]}",
        connector_type="dns",
        default_job_type=f"dns.{source}",
        status="enabled",
        aliases=[source],
    )
    db.add(connector)
    await db.flush()
    return connector


def _dns_record(index: int) -> dict:
    subject = f"host{index}.example.com"
    return {
        "observation_type": "dns_record",
        "subject": subject,
        "record_type": "A",
        "value": "203.0.113.10",
        "metadata": {"record_values": ["203.0.113.10"]},
    }


@pytest.mark.asyncio
async def test_a_dns_batch_rejects_an_entry_that_is_not_an_observation(db_session):
    connector = await _dns_connector(db_session)

    result = await ingest_findings(
        db_session, connector=connector, findings=[42], job_id=None
    )

    assert result.rejected == 1
    assert result.errors[0] == {
        "index": 0,
        "code": "invalid_contract",
        "retryable": False,
    }


@pytest.mark.asyncio
async def test_a_uniqueness_race_falls_back_to_one_observation_at_a_time(
    db_session, monkeypatch
):
    """The batch savepoint rolls back; each observation is then retried alone."""
    connector = await _dns_connector(db_session)
    calls: list[int] = []
    real = ingestion_service.ingest_dns_observations

    async def _racing(db, *, source, findings, commit=False):
        calls.append(len(findings))
        if len(calls) == 1:
            raise IntegrityError("insert", {}, Exception("duplicate key"))
        return await real(db, source=source, findings=findings, commit=commit)

    monkeypatch.setattr(ingestion_service, "ingest_dns_observations", _racing)

    result = await ingest_findings(
        db_session,
        connector=connector,
        findings=[_dns_record(0), _dns_record(1)],
        job_id=None,
    )

    assert result.created == 2
    assert calls == [2, 1, 1]


@pytest.mark.asyncio
async def test_a_single_observation_is_created_and_then_unchanged(db_session):
    connector = await _dns_connector(db_session)
    observation = _dns_record(7)

    assert await ingest_dns_observation_finding(db_session, connector, observation) is True
    assert await ingest_dns_observation_finding(db_session, connector, observation) is False
