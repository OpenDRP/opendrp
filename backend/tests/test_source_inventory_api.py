from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.api.v1.routers.source_inventory import evidence_fields
from app.core.exceptions import ConflictException
from app.models import Asset, AssetType, Connector, PhishingDomain
from app.services.asset_service import AssetService
from app.services.source_observations import persist


@pytest.mark.asyncio
async def test_exposure_http_filters_sources_and_enforces_roles(client, db_session, auth_headers_viewer):
    await persist(db_session, module="exposure", source="netlas", finding={"subject": "www.example.com", "matched_asset": "example.com", "port": 443})
    await persist(db_session, module="exposure", source="shodan", finding={"subject": "example.com", "matched_asset": "example.com", "port": 80})
    response = await client.get("/api/v1/exposure/observations?source=netlas&size=1", headers=auth_headers_viewer)
    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["source"] == "netlas"
    assert (await client.post("/api/v1/modules/exposure/scan", headers=auth_headers_viewer)).status_code == 403


@pytest.mark.asyncio
async def test_the_inventory_page_answers_the_fields_it_declares(
    client, db_session, auth_headers_viewer
):
    """Plan 034: the page's five keys and the row's twelve, as the model declares them.

    The route used to build a dict, so the client's `ExposureObservation` described a
    payload nothing compared it with. The key sets are asserted whole rather than one
    field at a time: a field dropped from the model is then a failure here instead of
    a blank cell in a browser.
    """
    await persist(
        db_session,
        module="exposure",
        source="netlas",
        finding={
            "subject": "www.example.com",
            "matched_asset": "example.com",
            "port": 443,
            "transport": "tcp",
            "protocol": "https",
        },
    )

    response = await client.get("/api/v1/exposure/observations", headers=auth_headers_viewer)

    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {"items", "total", "page", "size", "pages"}
    assert body["total"] == 1 and body["pages"] == 1
    row = body["items"][0]
    assert set(row) == {
        "id",
        "source",
        "subject",
        "matched_asset",
        "first_seen_at",
        "last_seen_at",
        "observed_at",
        "status",
        "payload",
        "provenance",
        "connector_id",
        "source_account_id",
    }
    # The page reads its service cell out of `payload`, and the connector columns are
    # absent for a row written without a connector — absent, not dropped.
    assert row["payload"]["port"] == 443
    assert row["connector_id"] is None and row["source_account_id"] is None
    # A source that reports no observation time leaves `observed_at` null, which the
    # page renders as "Unknown" rather than as an epoch.
    assert row["observed_at"] is None
    assert isinstance(row["first_seen_at"], str) and isinstance(row["last_seen_at"], str)


@pytest.mark.asyncio
async def test_registry_independent_source_admission(client, db_session, auth_headers_analyst):
    db_session.add(Asset(asset_type=AssetType.domain, asset_value="example.com", is_active=True, criticality="medium"))
    from app.models.source_account import SourceAccount
    account = SourceAccount(source_id="netlas", name="default", policy={"approved": True, "requests_per_minute": 10, "daily_budget": 100})
    db_session.add(account)
    await db_session.flush()
    db_session.add_all([
        Connector(name="netlas-exposure", connector_type="exposure", default_job_type="exposure.netlas", status="enabled", provider="netlas", source_account_id=account.id, quota_group="default", last_seen_at=datetime.now(timezone.utc), readiness={"credentials_configured": True, "credential_state": "unknown", "capabilities": ["hostname"]}),
        Connector(name="shodan-exposure", connector_type="exposure", default_job_type="exposure.shodan", status="enabled", provider="shodan", quota_group="default", last_seen_at=datetime.now(timezone.utc), readiness={"credentials_configured": False}),
    ])
    await db_session.commit()
    response = await client.post("/api/v1/modules/exposure/scan", headers=auth_headers_analyst)
    assert response.status_code == 202
    body = response.json()
    assert len(body["job_ids"]) == 1
    states = {source["connector"]: source["status"] for source in body["sources"]}
    # The sibling has no account row at all, which the core reports before it
    # looks at credentials: nothing could be queued for it until one exists.
    assert states == {"shodan-exposure": "provider_account_missing", "netlas-exposure": "queued"}
    from app.models import Job
    from app.services.connector_service import ConnectorService
    from app.services.ingestion_service import ingest_exposure
    service = ConnectorService(db_session)
    connector = await service.get_by_name("netlas-exposure")
    import uuid
    job = await db_session.get(Job, uuid.UUID(body["job_ids"][0]))
    assert not await ingest_exposure(db_session, connector, {"subject": "foreign.example.net", "matched_asset": "example.com", "port": 443}, connector_name=connector.name, job_id=job.id)
    assert await ingest_exposure(db_session, connector, {"subject": "www.example.com", "matched_asset": "example.com", "port": 443}, connector_name=connector.name, job_id=job.id)


@pytest.mark.asyncio
async def test_exposure_triage_and_promotion(client, db_session, auth_headers_analyst, auth_headers_viewer):
    from app.models.source_observation import SourceObservation
    await persist(db_session, module="exposure", source="netlas", finding={"subject": "assets.example.com", "matched_asset": "example.com", "port": 8443})
    observation = (await db_session.execute(select(SourceObservation))).scalar_one()
    denied = await client.patch(f"/api/v1/exposure/observations/{observation.id}", json={"status": "resolved"}, headers=auth_headers_viewer)
    assert denied.status_code == 403
    invalid = await client.patch(f"/api/v1/exposure/observations/{observation.id}", json={"status": "resolved", "extra": True}, headers=auth_headers_analyst)
    assert invalid.status_code == 422
    updated = await client.patch(f"/api/v1/exposure/observations/{observation.id}", json={"status": "investigating"}, headers=auth_headers_analyst)
    assert updated.status_code == 200 and updated.json()["status"] == "investigating"
    # Plan 034: the triage answer is two fields, and the route says which.
    assert set(updated.json()) == {"id", "status"}
    promoted = await client.post(f"/api/v1/exposure/observations/{observation.id}/asset", headers=auth_headers_analyst)
    assert promoted.status_code == 201 and promoted.json()["already_exists"] is False
    promoted_again = await client.post(f"/api/v1/exposure/observations/{observation.id}/asset", headers=auth_headers_analyst)
    assert promoted_again.status_code == 201 and promoted_again.json()["already_exists"] is True


@pytest.mark.asyncio
async def test_candidate_evidence_keeps_multiple_sources(client, db_session, auth_headers_viewer):
    import uuid
    candidate = PhishingDomain(phishing_domain="lookalike.example.net", matched_asset="example.com", detection_source="netlas", status="investigating")
    db_session.add(candidate)
    await db_session.commit()
    for source in ("netlas", "shodan"):
        await persist(db_session, module="phishing", source=source, finding={"phishing_domain": candidate.phishing_domain, "matched_asset": "example.com"}, candidate_id=candidate.id)
    response = await client.get(f"/api/v1/phishing/threats/{candidate.id}/evidence", headers=auth_headers_viewer)
    assert response.status_code == 200
    assert {row["source"] for row in response.json()["items"]} == {"netlas", "shodan"}
    assert candidate.status == "investigating"
    assert (await client.get(f"/api/v1/phishing/threats/{uuid.uuid4()}/evidence", headers=auth_headers_viewer)).status_code == 404


@pytest.mark.asyncio
async def test_candidate_evidence_shows_the_facts_the_decisions_are_made_from(
    client, db_session, auth_headers_viewer
):
    """W2.5: the endpoint flattens an allowlisted half of the payload.

    A discovery and a fact about a name the platform already had reached the list as
    the same shape - a source and a timestamp - so the page could not tell a
    certificate claiming the brand from a registration record. The payload itself
    stays published for a reader that wants it whole; what is added is the named
    subset the module's own rules and alerts read.
    """
    candidate = PhishingDomain(
        phishing_domain="lookalike.example.net",
        matched_asset="example.com",
        detection_source="netlas",
        status="investigating",
    )
    db_session.add(candidate)
    await db_session.commit()
    await persist(
        db_session,
        module="phishing",
        source="netlas",
        finding={
            "phishing_domain": candidate.phishing_domain,
            "matched_asset": "example.com",
            "metadata": {
                "capability": "certificate_brand",
                "verdict": "candidate_not_verified",
                "title": "Sign in",
                "association": "hostname_match",
                # Not on the allowlist, and not published as a named field.
                "internal_notes": "do-not-publish",
            },
        },
        candidate_id=candidate.id,
    )
    await persist(
        db_session,
        module="phishing",
        source="netlas",
        finding={
            "phishing_domain": candidate.phishing_domain,
            "matched_asset": "example.com",
            "metadata": {
                "capability": "mx",
                "mail_capable": False,
                "association": "confirmed_candidate",
            },
        },
        candidate_id=candidate.id,
    )

    response = await client.get(
        f"/api/v1/phishing/threats/{candidate.id}/evidence",
        headers=auth_headers_viewer,
    )
    assert response.status_code == 200
    rows = {row["fields"].get("capability"): row for row in response.json()["items"]}
    # Plan 034: ten fields per sighting, the allowlisted `fields` map beside the whole
    # `payload` it was read from.
    assert set(rows["mx"]) == {
        "source",
        "matched_asset",
        "observed_at",
        "first_seen_at",
        "last_seen_at",
        "fields",
        "payload",
        "provenance",
        "connector_id",
        "source_account_id",
    }
    assert rows["certificate_brand"]["fields"]["title"] == "Sign in"
    assert rows["certificate_brand"]["fields"]["verdict"] == "candidate_not_verified"
    assert "internal_notes" not in rows["certificate_brand"]["fields"]
    # A negative answer is a fact: the look-alike receives no mail, and the row says so
    # rather than leaving the reader to read absence as "unknown".
    assert rows["mx"]["fields"]["mail_capable"] is False
    assert rows["mx"]["fields"]["association"] == "confirmed_candidate"


class TestEvidenceAllowlist:
    """What a connector's payload may publish, and in what shape.

    The payload is whatever a worker sent. The list republishes a named subset so
    that a new provider document cannot silently become a new API shape, and a
    value that is not a scalar is dropped rather than serialised whole.
    """

    def test_a_payload_that_is_not_an_object_publishes_nothing(self):
        assert evidence_fields(None) == {}
        assert evidence_fields("a string") == {}
        assert evidence_fields([("capability", "mx")]) == {}

    def test_a_nested_shape_is_dropped_rather_than_published(self):
        fields = evidence_fields(
            {
                "capability": "mx",
                # A dict, a tuple and a set have no stable JSON shape here.
                "evidence": {"nested": "object"},
                "issuer_dn": ("a", "b"),
                "subject_dn": {"a", "b"},
                # A list is fine when every member is a scalar, and not otherwise.
                "mx_hosts": ["mx1.example", "mx2.example"],
                "web_ports": [80, {"port": 443}],
            }
        )
        assert fields == {
            "capability": "mx",
            "mx_hosts": ["mx1.example", "mx2.example"],
        }

    def test_the_findings_own_fields_are_read_after_its_metadata(self):
        fields = evidence_fields(
            {"metadata": {"capability": "mx", "verdict": "candidate"}, "registrar": "ACME"}
        )
        assert fields == {"capability": "mx", "verdict": "candidate", "registrar": "ACME"}


@pytest.mark.asyncio
async def test_a_scan_with_nothing_to_queue_is_a_refusal(client, auth_headers_analyst):
    """`202` means work was accepted; with no ready source nothing was.

    Answering 202 with an empty job list would tell the client a scan started and
    leave the operator watching a jobs page that never changes.
    """
    response = await client.post("/api/v1/modules/exposure/scan", headers=auth_headers_analyst)
    assert response.status_code == 409, response.text
    body = response.json()["detail"]
    assert body["job_ids"] == []
    assert body["sources"] == []


@pytest.mark.asyncio
async def test_triage_and_promotion_refuse_an_observation_they_do_not_own(
    client, db_session, auth_headers_analyst
):
    """An unknown id and another module's observation answer the same way.

    Exposure's routes accept only exposure rows: a phishing observation promoted
    through this path would create an asset from a finding nobody triaged here.
    """
    import uuid

    from app.models.source_observation import SourceObservation

    await persist(
        db_session,
        module="phishing",
        source="netlas",
        finding={"phishing_domain": "lookalike.example.net", "matched_asset": "example.com"},
    )
    foreign = (await db_session.execute(select(SourceObservation))).scalar_one()

    for observation_id in (uuid.uuid4(), foreign.id):
        triage = await client.patch(
            f"/api/v1/exposure/observations/{observation_id}",
            json={"status": "resolved"},
            headers=auth_headers_analyst,
        )
        assert triage.status_code == 404, triage.text
        promoted = await client.post(
            f"/api/v1/exposure/observations/{observation_id}/asset",
            headers=auth_headers_analyst,
        )
        assert promoted.status_code == 404, promoted.text


@pytest.mark.asyncio
async def test_an_address_is_promoted_as_an_address_and_a_subject_that_is_not_one_is_refused(
    client, db_session, auth_headers_analyst
):
    """The subject decides the asset type, and a value that is neither is refused.

    `203.0.113.9` is an address, so the asset joins the ip_address scans rather
    than the domain ones. A subject with a space in it is neither, and answering
    `409` names the observation as the problem instead of storing a broken asset.
    """
    from app.models.source_observation import SourceObservation

    await persist(
        db_session,
        module="exposure",
        source="shodan",
        finding={"subject": "203.0.113.9", "matched_asset": "example.com", "port": 22},
    )
    # The ingestion path would refuse this subject today. A row written before the
    # subject rule existed, or by a later writer that skipped it, is exactly what
    # the promotion guard is for, so it is inserted directly rather than through
    # `persist`.
    now = datetime.now(timezone.utc)
    db_session.add(
        SourceObservation(
            module="exposure",
            source="shodan",
            observation_key="bad-subject",
            subject="not a host",
            matched_asset="example.com",
            first_seen_at=now,
            last_seen_at=now,
            status="observed",
            payload={},
            provenance={},
        )
    )
    await db_session.commit()
    rows = {
        row.subject: row
        for row in (await db_session.execute(select(SourceObservation))).scalars()
    }

    promoted = await client.post(
        f"/api/v1/exposure/observations/{rows['203.0.113.9'].id}/asset",
        headers=auth_headers_analyst,
    )
    assert promoted.status_code == 201, promoted.text
    assert promoted.json()["asset"]["asset_type"] == "ip_address"

    refused = await client.post(
        f"/api/v1/exposure/observations/{rows['not a host'].id}/asset",
        headers=auth_headers_analyst,
    )
    assert refused.status_code == 409, refused.text
    assert "cannot be promoted" in refused.text


@pytest.mark.asyncio
async def test_a_duplicate_created_between_the_check_and_the_write_is_not_a_500(
    client, db_session, auth_headers_analyst, monkeypatch
):
    """The pre-check and the insert are two statements, so the write can lose.

    When it does, the answer is the asset that won the race: the promotion still
    happened, the operator still sees it, and the audit row names the asset they
    can find rather than reporting a server error for a click that worked.
    """
    from app.models.source_observation import SourceObservation

    await persist(
        db_session,
        module="exposure",
        source="shodan",
        finding={"subject": "racing.example.com", "matched_asset": "example.com"},
    )
    observation = (await db_session.execute(select(SourceObservation))).scalar_one()

    async def _lose_the_race(self, payload, commit=True):
        winner = Asset(
            asset_type=AssetType.domain,
            asset_value="racing.example.com",
            normalized_value="racing.example.com",
            criticality="medium",
            is_active=True,
        )
        db_session.add(winner)
        await db_session.flush()
        raise ConflictException("already monitored")

    monkeypatch.setattr(AssetService, "create_asset", _lose_the_race)

    response = await client.post(
        f"/api/v1/exposure/observations/{observation.id}/asset",
        headers=auth_headers_analyst,
    )
    assert response.status_code == 201, response.text
    assert response.json()["already_exists"] is True
    assert response.json()["asset"]["asset_value"] == "racing.example.com"


@pytest.mark.asyncio
async def test_a_conflict_with_no_winner_is_reported_rather_than_invented(
    client, db_session, auth_headers_analyst, monkeypatch
):
    """The write failed and nothing exists: reporting success would be a lie.

    The fallback query only covers the case where another writer committed the
    asset. When it finds nothing, the conflict is a real inconsistency and is
    re-raised, so the operator sees the refusal instead of a fabricated row.
    """
    from app.models.source_observation import SourceObservation

    await persist(
        db_session,
        module="exposure",
        source="shodan",
        finding={"subject": "ghost.example.com", "matched_asset": "example.com"},
    )
    observation = (await db_session.execute(select(SourceObservation))).scalar_one()

    async def _refuse(self, payload, commit=True):
        raise ConflictException("already monitored")

    monkeypatch.setattr(AssetService, "create_asset", _refuse)

    response = await client.post(
        f"/api/v1/exposure/observations/{observation.id}/asset",
        headers=auth_headers_analyst,
    )
    assert response.status_code == 409, response.text
    assert response.json()["detail"] == "already monitored"
    assert (
        await db_session.execute(
            select(Asset).where(Asset.asset_value == "ghost.example.com")
        )
    ).scalar_one_or_none() is None
