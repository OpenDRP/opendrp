from datetime import datetime, timedelta, timezone
import uuid

import pytest
from sqlalchemy import select

from app.models.asset import Asset, AssetType
from app.models.audit import AuditLog
from app.models.connector import Connector
from app.models.job import Job
from app.models.dns_observation import DNSObservation
from app.services.connector_service import ConnectorService


@pytest.mark.asyncio
async def test_inventory_splits_rrsets_groups_ct_and_tracks_assets(client, db_session, auth_headers_analyst):
    from app.services.dns_security_service import ingest_dns_observations
    db_session.add(Asset(asset_type=AssetType.domain, asset_value="example.com", normalized_value="example.com", is_active=False))
    await db_session.commit()
    await ingest_dns_observations(db_session, source="resolver", findings=[{"observation_type": "dns_record", "subject": "example.com", "record_type": "AAAA", "value": "2001:db8::1; 2001:db8::2", "metadata": {"record_values": ["2001:db8::1", "2001:db8::2"]}}])
    await ingest_dns_observations(db_session, source="ctlogs", findings=[{"observation_type": "certificate", "subject": "login.example.com", "value": "example.com", "metadata": {"id": cert}} for cert in ("a", "b")])
    url = "/api/v1/dns-security/observations"
    listed = (await client.get(url, headers=auth_headers_analyst)).json()
    assert listed["total"] == 3
    dns = [r for r in listed["items"] if r["source"] == "resolver"]
    assert {r["value"] for r in dns} == {"2001:db8::1", "2001:db8::2"}
    assert all(r["subject_in_assets"] and not r["value_in_assets"] for r in dns)
    ct = next(r for r in listed["items"] if r["source"] == "ctlogs")
    assert ct["evidence_count"] == 2
    paged = (await client.get(url, headers=auth_headers_analyst, params={"size": 1})).json()
    assert paged["total"] == 3 and paged["pages"] == 3 and len(paged["items"]) == 1
    promoted = await client.post(f"{url}/{dns[0]['id']}/asset", headers=auth_headers_analyst, json={"target": dns[0]["value"]})
    assert promoted.status_code == 201
    assert promoted.json()["asset"]["asset_type"] == "ip_address"
    bad = await client.post(f"{url}/{dns[0]['id']}/asset", headers=auth_headers_analyst, json={"target": "evil.test"})
    assert bad.status_code == 409
    updated = (await client.get(url, headers=auth_headers_analyst)).json()
    assert next(r for r in updated["items"] if r["value"] == dns[0]["value"])["value_in_assets"]
    deleted = await client.delete(f"{url}/{dns[0]['id']}", headers=auth_headers_analyst, params={"value": dns[0]["value"]})
    assert deleted.status_code == 204
    remaining = (await client.get(url, headers=auth_headers_analyst)).json()
    assert remaining["total"] == 2
    assert (await client.delete(f"{url}/{ct['id']}", headers=auth_headers_analyst)).status_code == 204
    raw_ct = list((await db_session.execute(select(DNSObservation).where(DNSObservation.source == "ctlogs"))).scalars())
    assert raw_ct == []
    audit = (await db_session.execute(select(AuditLog).where(AuditLog.action == "dns_security.observation.delete"))).scalars().all()
    assert len(audit) == 2 and all(a.user_id and a.ip_address for a in audit)


@pytest.mark.asyncio
async def test_observation_delete_permissions_missing_and_invalid_member(client, db_session, auth_headers_analyst, auth_headers_viewer):
    from app.services.dns_security_service import ingest_dns_observations
    await ingest_dns_observations(db_session, source="resolver", findings=[{"observation_type": "dns_record", "subject": "example.com", "record_type": "A", "value": "203.0.113.1"}])
    row = (await db_session.execute(select(DNSObservation))).scalar_one()
    url = f"/api/v1/dns-security/observations/{row.id}"
    assert (await client.delete(url)).status_code == 401
    assert (await client.delete(url, headers=auth_headers_viewer)).status_code == 403
    assert (await client.delete(url, headers=auth_headers_analyst, params={"value": "203.0.113.99"})).status_code == 404
    assert await db_session.get(DNSObservation, row.id) is not None
    assert (await client.delete(f"/api/v1/dns-security/observations/{uuid.uuid4()}", headers=auth_headers_analyst)).status_code == 404


@pytest.mark.asyncio
async def test_ct_group_keeps_wildcards_and_sources_separate(client, db_session, auth_headers_viewer, auth_headers_analyst):
    from app.services.dns_security_service import ingest_dns_observations
    for source in ("ctlogs", "netlas"):
        await ingest_dns_observations(db_session, source=source, findings=[{"observation_type": "certificate", "subject": "example.com", "value": "example.com", "metadata": {"id": cert, "wildcard": wildcard}} for cert, wildcard in (("a", False), ("b", False), ("c", True))])
    r = await client.get("/api/v1/dns-security/observations", headers=auth_headers_viewer)
    assert r.json()["total"] == 4
    assert sorted(x["evidence_count"] for x in r.json()["items"]) == [1, 1, 2, 2]
    raw = list((await db_session.execute(select(DNSObservation))).scalars())
    assert len(raw) == 6
    concrete = next(x for x in r.json()["items"] if x["source"] == "ctlogs" and not x["metadata"]["wildcard"])
    deleted = await client.delete(f"/api/v1/dns-security/observations/{concrete['id']}", headers=auth_headers_analyst)
    assert deleted.status_code == 204
    remaining = list((await db_session.execute(select(DNSObservation))).scalars())
    assert len(remaining) == 4
    assert sum(x.source == "netlas" for x in remaining) == 3
    assert next(x for x in remaining if x.source == "ctlogs").metadata_json["wildcard"] is True


@pytest.mark.asyncio
async def test_expiry_api_reports_control_and_deletion_invalidates_it(client, db_session, auth_headers_analyst):
    from app.services.dns_security_service import ingest_dns_observations
    from app.models.dns_expiry_monitor import DNSExpiryMonitor
    db_session.add(Asset(asset_type=AssetType.domain,asset_value="example.com",normalized_value="example.com"))
    await db_session.commit()
    now = datetime.now(timezone.utc)
    await ingest_dns_observations(db_session,source="ctlogs",findings=[{"subject":"example.com","observation_type":"certificate_check","expires_at":(now+timedelta(days=3)).isoformat(),"metadata":{"check_state":"verified","certificate_id":"new","not_before":(now-timedelta(days=1)).isoformat()}}])
    response=await client.get("/api/v1/dns-security/observations",headers=auth_headers_analyst)
    item=response.json()["items"][0]
    assert item["expiry_kind"]=="certificate"
    assert item["expiry_monitor"]["state"]=="verified"
    assert item["expiry_monitor"]["certificate_id"]=="new"
    assert (await client.delete(f"/api/v1/dns-security/observations/{item['id']}",headers=auth_headers_analyst)).status_code==204
    monitor=(await db_session.execute(select(DNSExpiryMonitor))).scalar_one()
    await db_session.refresh(monitor)
    assert monitor.state=="unverified" and monitor.observation_id is None


@pytest.mark.asyncio
async def test_certificate_group_uses_issue_date_not_ingestion_order(client, db_session, auth_headers_viewer):
    from app.services.dns_security_service import ingest_dns_observations
    for identity,issued in [("new","2026-01-01T00:00:00Z"),("old","2025-01-01T00:00:00Z")]:
        await ingest_dns_observations(db_session,source="ctlogs",findings=[{"subject":"example.com","observation_type":"certificate","metadata":{"id":identity,"not_before":issued}}])
    response=await client.get("/api/v1/dns-security/observations",headers=auth_headers_viewer)
    assert response.json()["total"]==1
    assert response.json()["items"][0]["metadata"]["id"]=="new"


@pytest.mark.asyncio
async def test_observations_require_viewer_and_apply_canonical_subject_filter(client, db_session, auth_headers_viewer):
    now = datetime.now(timezone.utc)
    db_session.add_all([
        DNSObservation(
            observation_key=f"{index:064x}",
            observation_type="dns_record",
            subject="www.example.com",
            record_type="A",
            value=f"203.0.113.{index}",
            source=source,
            first_seen_at=now,
            last_seen_at=now,
            status="current",
            metadata_json={},
            alerted_thresholds=[],
        )
        for index, source in enumerate(("resolver", "ctlogs"), 1)
    ])
    await db_session.commit()

    denied = await client.get("/api/v1/dns-security/observations")
    assert denied.status_code == 401

    response = await client.get(
        "/api/v1/dns-security/observations",
        headers=auth_headers_viewer,
        params={"subject": "WWW.Example.COM.", "source": "resolver"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert payload["items"][0]["subject"] == "www.example.com"
    assert payload["items"][0]["source"] == "resolver"


@pytest.mark.asyncio
async def test_scan_enqueues_each_dns_source_only_with_analyst_authorization(client, db_session, auth_headers_analyst, auth_headers_viewer):
    service = ConnectorService(db_session)
    for name, job_type in (
        ("dns-rdap", "dns.rdap"),
        ("dns-resolver", "dns.resolver"),
    ):
        await service.register(
            name=name,
            connector_type="dns",
            api_version="1",
            default_job_type=job_type,
            finding_kind="dns_observation",
            asset_types=["domain"],
        )
    await db_session.commit()

    denied = await client.post("/api/v1/dns-security/scan", headers=auth_headers_viewer)
    assert denied.status_code == 403
    response = await client.post("/api/v1/dns-security/scan", headers=auth_headers_analyst)
    assert response.status_code == 202
    assert len(response.json()["job_ids"]) == 2
    assert response.json()["offline_connectors"] == []


@pytest.mark.asyncio
async def test_scan_rejects_offline_workers_without_creating_jobs(client, db_session, auth_headers_analyst):
    db_session.add_all([
        Connector(name="dns-unregistered", connector_type="dns", default_job_type="dns.unregistered", status="enabled"),
        Connector(name="dns-stale", connector_type="dns", default_job_type="dns.stale", status="enabled", last_seen_at=datetime.now(timezone.utc) - timedelta(days=1)),
    ])
    await db_session.commit()
    response = await client.post("/api/v1/dns-security/scan", headers=auth_headers_analyst)
    assert response.status_code == 409
    assert response.json()["detail"]["status"] == "blocked"
    assert all(source["status"] == "offline" for source in response.json()["detail"]["sources"])
    assert list((await db_session.execute(select(Job))).scalars()) == []


@pytest.mark.asyncio
async def test_scan_queues_online_source_and_reports_offline_source(client, db_session, auth_headers_analyst):
    service = ConnectorService(db_session)
    await service.register(name="dns-live", connector_type="dns", default_job_type="dns.live", finding_kind="dns_observation", asset_types=["domain"])
    db_session.add(Connector(name="dns-offline", connector_type="dns", default_job_type="dns.offline", status="enabled"))
    await db_session.commit()
    response = await client.post("/api/v1/dns-security/scan", headers=auth_headers_analyst)
    assert response.status_code == 202
    assert response.json()["offline_connectors"] == ["dns-offline"]
    jobs = list((await db_session.execute(select(Job))).scalars())
    assert len(jobs) == 1
    assert jobs[0].job_type == "dns.live"
    assert jobs[0].status == "pending"
    assert jobs[0].started_at is None


@pytest.mark.asyncio
async def test_cleanup_is_admin_only_preserves_provenance_and_inactive_assets(client, db_session, auth_headers_admin, auth_headers_analyst, auth_headers_viewer):
    db_session.add_all([
        Asset(asset_type=AssetType.domain, asset_value="Example.COM.", normalized_value="example.com", is_active=False),
        Asset(asset_type=AssetType.ip_address, asset_value="203.0.113.10", normalized_value="203.0.113.10"),
        Asset(asset_type=AssetType.keyword_domain, asset_value="unrelated.test", normalized_value="unrelated.test"),
    ])
    now = datetime.now(timezone.utc)
    cases = [
        ("example.com", "rdap", "rdap", None, {}),
        ("example.com", "dns_record", "resolver", "192.0.2.1", {}),
        ("sub.example.com", "certificate", "ctlogs", "example.com", {}),
        ("192.0.2.2", "vt_resolution", "virustotal", None, {"source_domain": "example.com"}),
        ("203.0.113.10", "vt_resolution", "virustotal", None, {}),
        ("sub.example.com", "certificate", "ctlogs", "deleted.test", {}),
        ("gone.test", "dns_record", "resolver", "example.com", {}),
        ("unrelated.test", "rdap", "rdap", None, {}),
    ]
    observations = [DNSObservation(observation_key=f"{i:064x}", subject=subject, observation_type=kind, source=source, value=value, metadata_json=metadata, first_seen_at=now, last_seen_at=now, status="current") for i, (subject, kind, source, value, metadata) in enumerate(cases)]
    db_session.add_all(observations)
    await db_session.commit()
    for headers in (auth_headers_analyst, auth_headers_viewer):
        denied = await client.post("/api/v1/dns-security/observations/cleanup-orphans", headers=headers)
        assert denied.status_code == 403
    response = await client.post("/api/v1/dns-security/observations/cleanup-orphans", headers=auth_headers_admin)
    assert response.status_code == 200
    assert response.json()["deleted"] == 3
    remaining = list((await db_session.execute(select(DNSObservation.id))).scalars())
    assert set(remaining) == {row.id for row in observations[:5]}
    audit = (await db_session.execute(select(AuditLog).where(AuditLog.action == "dns_security.observation.orphans.cleaned"))).scalar_one()
    assert audit.details["deleted"] == 3
    assert audit.details["request_id"]
    assert len(audit.details["audit_hash"]) == 64
    assert audit.user_id is not None
    assert audit.ip_address
    repeated = await client.post("/api/v1/dns-security/observations/cleanup-orphans", headers=auth_headers_admin)
    assert repeated.json()["deleted"] == 0


@pytest.mark.asyncio
async def test_promotion_normalizes_and_deduplicates_asset(client, db_session, auth_headers_analyst):
    observation = DNSObservation(
        observation_key="a" * 64,
        observation_type="dns_record",
        subject="www.example.com",
        record_type="A",
        value="203.0.113.10",
        source="resolver",
        first_seen_at=datetime.now(timezone.utc),
        last_seen_at=datetime.now(timezone.utc),
        status="current",
        metadata_json={},
        alerted_thresholds=[],
    )
    db_session.add(observation)
    await db_session.commit()

    first = await client.post(
        f"/api/v1/dns-security/observations/{observation.id}/asset",
        headers=auth_headers_analyst,
    )
    assert first.status_code == 201
    assert first.json()["already_exists"] is False

    second = await client.post(
        f"/api/v1/dns-security/observations/{observation.id}/asset",
        headers=auth_headers_analyst,
    )
    assert second.status_code == 201
    assert second.json()["already_exists"] is True
    assets = list((await db_session.execute(select(Asset))).scalars().all())
    assert len(assets) == 1
    assert assets[0].asset_value == "www.example.com"


@pytest.mark.asyncio
async def test_wildcard_certificate_cannot_be_promoted_as_concrete_hostname(client, db_session, auth_headers_analyst):
    now = datetime.now(timezone.utc)
    row = DNSObservation(observation_key="f" * 64, observation_type="certificate", subject="prod.egov.kz", value="egov.kz", source="ctlogs", first_seen_at=now, last_seen_at=now, status="historical", metadata_json={"wildcard": True, "certificate_match": "*.prod.egov.kz"})
    db_session.add(row)
    await db_session.commit()
    response = await client.post(f"/api/v1/dns-security/observations/{row.id}/asset", headers=auth_headers_analyst)
    assert response.status_code == 409
    assert "Wildcard" in response.json()["detail"]
    assert list((await db_session.execute(select(Asset))).scalars()) == []


@pytest.mark.asyncio
async def test_dns_worker_protocol_claim_submit_complete_and_read(client, db_session, auth_headers_analyst, auth_headers_viewer):
    from app.services.connector_credentials import ConnectorCredentials

    service = ConnectorService(db_session)
    connector = await service.register(name="dns-ctlogs", connector_type="dns", api_version="1", default_job_type="dns.ctlogs", finding_kind="dns_observation", asset_types=["domain"])
    token, _ = await ConnectorCredentials(db_session).issue(connector)
    headers = {"X-Connector-Token": token}
    queued = await client.post("/api/v1/dns-security/scan", headers=auth_headers_analyst)
    assert queued.status_code == 202
    job_id = queued.json()["job_ids"][0]
    work = await client.get("/api/v1/connectors/me/work", headers=headers)
    assert work.status_code == 200
    assert work.json()["job_id"] == job_id
    lease = work.json()["lease_token"]
    observations = [
        {"observation_type": "certificate", "subject": "prod.egov.kz", "value": "egov.kz", "status": "historical", "expires_at": "2026-11-03T11:46:21Z", "metadata": {"id": "cert-a", "source_domain": "egov.kz", "wildcard": True, "certificate_match": "*.prod.egov.kz"}},
        {"observation_type": "certificate", "subject": "login.egov.kz", "value": "egov.kz", "status": "historical", "metadata": {"id": "cert-a", "source_domain": "egov.kz", "wildcard": False}},
    ]
    posted = await client.post(f"/api/v1/connectors/me/findings/{job_id}", headers={**headers, "X-Connector-Lease": lease}, json=observations)
    assert posted.status_code == 200
    assert posted.json() == {"accepted": 2, "rejected": 0, "received": 2, "created": 2, "updated": 0, "unchanged": 0, "errors": []}
    done = await client.post(f"/api/v1/connectors/me/complete/{job_id}", headers=headers, json={"ok": True, "lease_token": lease, "summary": {"status": "success", "observations": 2}})
    assert done.status_code == 200
    from uuid import UUID

    job = await db_session.get(Job, UUID(job_id))
    await db_session.refresh(job)
    assert job.status == "success"
    assert job.started_at is not None
    assert job.finished_at is not None
    listed = await client.get("/api/v1/dns-security/observations", headers=auth_headers_viewer, params={"source": "ctlogs"})
    assert listed.status_code == 200
    assert listed.json()["total"] == 2
    assert {row["subject"] for row in listed.json()["items"]} == {"prod.egov.kz", "login.egov.kz"}


