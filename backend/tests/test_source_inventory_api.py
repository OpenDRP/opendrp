from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.models import Asset, AssetType, Connector, PhishingDomain
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
    assert rows["certificate_brand"]["fields"]["title"] == "Sign in"
    assert rows["certificate_brand"]["fields"]["verdict"] == "candidate_not_verified"
    assert "internal_notes" not in rows["certificate_brand"]["fields"]
    # A negative answer is a fact: the look-alike receives no mail, and the row says so
    # rather than leaving the reader to read absence as "unknown".
    assert rows["mx"]["fields"]["mail_capable"] is False
    assert rows["mx"]["fields"]["association"] == "confirmed_candidate"
