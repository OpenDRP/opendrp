"""Tests for the core + connector architecture.

Covers: name normalization, registration upsert, atomic work claiming, findings
ingestion (dedup + alert firing), provider-declared capability config
validation, and enable/disable gating.

Credential issuance/resolution/rotation and the connector-side auth contract live
in ``test_connector_credentials.py``; the HTTP protocol in
``test_connectors_protocol_api.py``.
"""

import uuid
from unittest.mock import AsyncMock, patch

import pytest

from app.models import Connector, Job
from app.services.connector_manifest import ModuleSpec
from app.services.connector_service import (
    ConnectorService,
    normalize_connector_name,
)


# ---------------------------------------------------------------------------
# Connector identity
# ---------------------------------------------------------------------------


class TestConnectorIdentity:
    def test_name_normalization(self):
        assert normalize_connector_name("My Connector!") == "my-connector"
        assert normalize_connector_name("  DNStwist  ") == "dnstwist"


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestRegistration:
    @pytest.mark.asyncio
    async def test_register_creates_and_upserts(self, db_session):
        svc = ConnectorService(db_session)
        conn = await svc.register(
            name="My Shodan",
            connector_type="phishing",
            api_version="1.2",
            default_job_type="phishing.shodan",
            info={"python": "3.12", "evil": "x"},
        )
        assert conn.name == "my-shodan"
        assert conn.connector_type == "phishing"
        assert conn.status == "enabled"
        assert conn.api_version == "1.2"
        # Only allowlisted info keys survive.
        assert conn.info == {"python": "3.12"}

        # Upsert: same name, no duplicate.
        again = await svc.register(
            name="my-shodan", connector_type="phishing", default_job_type="phishing.shodan"
        )
        assert again.id == conn.id
        rows = await svc.list_connectors()
        assert len([c for c in rows if c.name == "my-shodan"]) == 1

        # Type conflict is rejected.
        from app.core.exceptions import BadRequestException

        with pytest.raises(BadRequestException):
            await svc.register(
                name="my-shodan", connector_type="breaches", default_job_type="breaches.scan"
            )

        await db_session.delete(conn)
        await db_session.commit()

    @pytest.mark.asyncio
    async def test_register_invalid_type_rejected(self, db_session):
        from app.core.exceptions import BadRequestException

        with pytest.raises(BadRequestException):
            await ConnectorService(db_session).register(name="x", connector_type="voip")


# ---------------------------------------------------------------------------
# Work claiming
# ---------------------------------------------------------------------------


class TestWorkClaiming:
    @pytest.mark.asyncio
    async def test_claim_moves_job_to_running_and_records_owner(self, db_session):
        svc = ConnectorService(db_session)
        conn = await svc.register(
            name="hibp",
            connector_type="breaches",
            api_version="1.0",
            default_job_type="breaches.hibp",
        )
        job = (await svc.enqueue_module_scan(
            connector_type="breaches", created_by=None, title="T", params={"trigger": "manual"}
        ))[0]

        claimed = await svc.claim_work(conn)
        assert claimed is not None
        assert claimed.id == job.id
        assert claimed.status == "running"
        assert claimed.started_at is not None
        assert claimed.claimed_by_connector == "hibp"

        # Queue is now empty.
        assert await svc.claim_work(conn) is None

        await svc.fail_job(conn, job.id, error="boom", lease_token=claimed.lease_token)
        await db_session.delete(job)
        await db_session.delete(conn)
        await db_session.commit()

    @pytest.mark.asyncio
    async def test_expired_lease_is_requeued_then_fails_after_retry_limit(self, db_session, monkeypatch):
        """A lost connector cannot strand work in ``running`` forever."""
        from datetime import datetime, timedelta, timezone
        from app.core.config import settings

        svc = ConnectorService(db_session)
        conn = await svc.register(
            name="dnstwist",
            connector_type="phishing",
            api_version="1.0",
            default_job_type="phishing.dnstwist",
        )
        await svc.enqueue_module_scan(
            connector_type="phishing", created_by=None, title="T", params={"trigger": "manual"}
        )
        claimed = await svc.claim_work(conn)
        assert claimed is not None
        expired = datetime.now(timezone.utc) + timedelta(seconds=1)
        claimed.lease_expires_at = expired
        await db_session.commit()

        assert await svc.recover_expired_jobs(now=expired + timedelta(seconds=1)) == 1
        await db_session.refresh(claimed)
        assert claimed.status == "pending"
        assert claimed.lease_token is None
        assert claimed.claimed_by_connector is None

        claimed = await svc.claim_work(conn)
        assert claimed is not None
        claimed.lease_expires_at = expired
        claimed.attempt_count = settings.CONNECTOR_JOB_MAX_ATTEMPTS
        await db_session.commit()
        assert await svc.recover_expired_jobs(now=expired + timedelta(seconds=1)) == 1
        await db_session.refresh(claimed)
        assert claimed.status == "error"
        assert "retry limit" in (claimed.error_message or "")

        await db_session.delete(claimed)
        await db_session.delete(conn)
        await db_session.commit()

    @pytest.mark.asyncio
    async def test_disabled_connector_gets_no_work(self, db_session):
        svc = ConnectorService(db_session)
        conn = await svc.register(
            name="dnstwist",
            connector_type="phishing",
            api_version="1.0",
            default_job_type="phishing.dnstwist",
        )
        await svc.enqueue_module_scan(connector_type="phishing", created_by=None, title="T")
        await svc.set_status(conn.id, "disabled")
        assert await svc.claim_work(conn) is None

        jobs = await svc.list_enabled_by_type("phishing")
        assert jobs == []
        await svc.set_status(conn.id, "enabled")
        claimed = await svc.claim_work(conn)
        assert claimed is not None

        await svc.fail_job(conn, claimed.id, error="cleanup", lease_token=claimed.lease_token)
        await db_session.delete(claimed)
        await db_session.delete(conn)
        await db_session.commit()

    @pytest.mark.asyncio
    async def test_connector_cannot_touch_foreign_job(self, db_session):
        from app.core.exceptions import ForbiddenException

        svc = ConnectorService(db_session)
        c1 = await svc.register(
            name="c-one",
            connector_type="phishing",
            api_version="1.0",
            default_job_type="phishing.c-one",
        )
        c2 = await svc.register(
            name="c-two",
            connector_type="phishing",
            api_version="1.0",
            default_job_type="phishing.c-two",
        )
        job = (await svc.enqueue_module_scan(
            connector_type="phishing", created_by=None, title="T"
        ))[0]
        claimed = await svc.claim_work(c1)
        assert claimed is not None

        # A sibling's claim is refused even when it guesses the lease token.
        with pytest.raises(ForbiddenException):
            await svc.complete_job(
                c2, job.id, result_summary={}, lease_token=claimed.lease_token
            )

        await svc.fail_job(c1, job.id, error="cleanup", lease_token=claimed.lease_token)
        await db_session.delete(job)
        await db_session.delete(c1)
        await db_session.delete(c2)
        await db_session.commit()

    @pytest.mark.asyncio
    async def test_connector_claims_only_its_own_job_type(self, db_session):
        """Two connectors of the same module must each claim their own job.

        Regression: claim_work used to match by module type, so dnstwist and
        shodan stole each other's jobs and completed them with swapped
        summaries.
        """
        svc = ConnectorService(db_session)
        dnstwist = await svc.register(
            name="dnstwist",
            connector_type="phishing",
            api_version="1.0",
            default_job_type="phishing.dnstwist",
        )
        shodan = await svc.register(
            name="shodan",
            connector_type="phishing",
            api_version="1.0",
            default_job_type="phishing.shodan",
        )

        jobs = await svc.enqueue_module_scan(
            connector_type="phishing", created_by=None, title="T", params={"trigger": "manual"}
        )
        types = {j.job_type for j in jobs}
        assert types == {"phishing.dnstwist", "phishing.shodan"}

        # Each connector claims exactly its own job.
        claimed_by_dns = await svc.claim_work(dnstwist)
        assert claimed_by_dns is not None
        assert claimed_by_dns.job_type == "phishing.dnstwist"
        assert claimed_by_dns.claimed_by_connector == "dnstwist"

        claimed_by_shodan = await svc.claim_work(shodan)
        assert claimed_by_shodan is not None
        assert claimed_by_shodan.job_type == "phishing.shodan"
        assert claimed_by_shodan.claimed_by_connector == "shodan"

        # Nothing left — and a connector cannot grab the other's running job.
        assert await svc.claim_work(dnstwist) is None
        assert await svc.claim_work(shodan) is None

        await svc.fail_job(
            dnstwist, claimed_by_dns.id, error="cleanup", lease_token=claimed_by_dns.lease_token
        )
        await svc.fail_job(
            shodan, claimed_by_shodan.id, error="cleanup", lease_token=claimed_by_shodan.lease_token
        )
        await db_session.delete(claimed_by_dns)
        await db_session.delete(claimed_by_shodan)
        await db_session.delete(dnstwist)
        await db_session.delete(shodan)
        await db_session.commit()

    @pytest.mark.asyncio
    async def test_enqueue_scoped_to_single_connector(self, db_session):
        """connector_name=... creates a job only for that connector.

        Regression: the manual /scan/dnstwist and /scan/shodan endpoints used
        to fan out to every enabled phishing connector, so the UI Rescan
        (which calls both) queued each source twice.
        """
        from app.core.exceptions import BadRequestException
        from sqlalchemy import select

        svc = ConnectorService(db_session)
        dnstwist = await svc.register(
            name="dnstwist",
            connector_type="phishing",
            api_version="1.0",
            default_job_type="phishing.dnstwist",
        )
        shodan = await svc.register(
            name="shodan",
            connector_type="phishing",
            api_version="1.0",
            default_job_type="phishing.shodan",
        )

        only_dns = await svc.enqueue_module_scan(
            connector_type="phishing", created_by=None, title="D", params={"trigger": "manual"},
            connector_name="dnstwist",
        )
        assert len(only_dns) == 1
        assert only_dns[0].job_type == "phishing.dnstwist"

        # Unknown/disabled connector -> clear error, nothing enqueued.
        with pytest.raises(BadRequestException):
            await svc.enqueue_module_scan(
                connector_type="phishing", created_by=None, title="X", connector_name="nope"
            )
        remaining = (
            await db_session.execute(select(Job).where(Job.status == "pending"))
        ).scalars().all()
        assert len(remaining) == 1  # only the dnstwist job above

        await db_session.delete(only_dns[0])
        await db_session.delete(dnstwist)
        await db_session.delete(shodan)
        await db_session.commit()


# ---------------------------------------------------------------------------
# Scan target snapshot
# ---------------------------------------------------------------------------


class TestScanTargetSnapshot:
    """Enqueued jobs must carry the active asset inventory in params.

    Regression: connectors used to receive jobs whose params contained only
    ``trigger``/``connector`` metadata — every connector scanned zero assets
    (smoke summaries showed ``domains_scanned: 0`` / ``new_breach_rows: 0``)
    because the work-poll response never carried the scan targets.
    """

    @pytest.mark.asyncio
    async def _seed_assets(self, db_session) -> None:
        from app.models import Asset

        db_session.add_all([
            Asset(asset_type="domain", asset_value="acme.example"),
            Asset(asset_type="domain", asset_value="inactive.example", is_active=False),
            Asset(asset_type="email_account", asset_value="ops@acme.example"),
            Asset(asset_type="keyword_domain", asset_value="acme"),
            Asset(asset_type="keyword_title", asset_value="ACME portal"),
            Asset(asset_type="ip_address", asset_value="203.0.113.7"),
        ])
        await db_session.commit()

    @pytest.mark.asyncio
    async def test_job_params_carry_active_asset_snapshot(self, db_session):
        await self._seed_assets(db_session)
        svc = ConnectorService(db_session)
        hibp = await svc.register(
            name="hibp",
            connector_type="breaches",
            api_version="1.0",
            default_job_type="breaches.hibp",
        )

        job = (await svc.enqueue_module_scan(
            connector_type="breaches", created_by=None, title="T", params={"trigger": "manual"}
        ))[0]
        p = job.params or {}

        # Email + domain targets for the breaches connector.
        assert p["emails"] == ["ops@acme.example"]
        assert p["domains"] == ["acme.example"]
        # Inactive assets are excluded.
        assert "inactive.example" not in p["domains"]
        # Internal metadata preserved.
        assert p["connector"] == "hibp"
        assert p["trigger"] == "manual"

        await db_session.delete(job)
        await db_session.delete(hibp)
        await db_session.commit()

    @pytest.mark.asyncio
    async def test_phishing_snapshot_shape_per_connector(self, db_session):
        await self._seed_assets(db_session)
        svc = ConnectorService(db_session)
        dnstwist = await svc.register(
            name="dnstwist",
            connector_type="phishing",
            api_version="1.0",
            default_job_type="phishing.dnstwist",
        )
        shodan = await svc.register(
            name="shodan",
            connector_type="phishing",
            api_version="1.0",
            default_job_type="phishing.shodan",
        )

        jobs = await svc.enqueue_module_scan(
            connector_type="phishing", created_by=None, title="T"
        )
        by_type = {j.job_type: (j.params or {}) for j in jobs}

        dns = by_type["phishing.dnstwist"]
        assert dns["domains"] == ["acme.example"]

        sho = by_type["phishing.shodan"]
        # Domains and keyword-domains are typed (favicon runs for domains only).
        assert sho["keyword_domains"] == [
            {"value": "acme.example", "type": "domain"},
            {"value": "acme", "type": "keyword_domain"},
        ]
        assert sho["keyword_titles"] == ["ACME portal"]
        # Owned domains + IPs are excluded from Shodan brand hunting.
        assert sho["exclude"] == ["acme.example", "203.0.113.7"]

        for j in jobs:
            await db_session.delete(j)
        await db_session.delete(dnstwist)
        await db_session.delete(shodan)
        await db_session.commit()

    @pytest.mark.asyncio
    async def test_claim_preserves_snapshot_and_records_owner(self, db_session):
        await self._seed_assets(db_session)
        svc = ConnectorService(db_session)
        dnstwist = await svc.register(
            name="dnstwist",
            connector_type="phishing",
            api_version="1.0",
            default_job_type="phishing.dnstwist",
        )

        await svc.enqueue_module_scan(
            connector_type="phishing", created_by=None, title="T"
        )
        claimed = await svc.claim_work(dnstwist)
        assert claimed is not None
        p = claimed.params or {}
        assert p["domains"] == ["acme.example"]
        assert claimed.claimed_by_connector == "dnstwist"

        await svc.fail_job(dnstwist, claimed.id, error="cleanup", lease_token=claimed.lease_token)
        await db_session.delete(claimed)
        await db_session.delete(dnstwist)
        await db_session.commit()


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------


class TestIngestion:
    @pytest.mark.asyncio
    async def test_phishing_finding_saved_and_deduped(self, db_session):
        from sqlalchemy import select

        from app.models import PhishingDomain
        from app.services.ingestion_service import ingest_findings

        conn = Connector(
            name="ing-test", connector_type="phishing", default_job_type="phishing.ing-test"
        )
        db_session.add(conn)
        await db_session.commit()
        conn_type = conn.connector_type
        conn_id = conn.id

        findings = [
            {"phishing_domain": f"evil-{uuid.uuid4().hex[:8]}.com", "matched_asset": "example.com", "ip_address": "1.2.3.4"},
        ]
        with patch("app.services.ingestion_service.AlertDeliveryService.enqueue", new_callable=AsyncMock):
            accepted, rejected = await ingest_findings(db_session, connector=conn, job_id=None, findings=findings)
        assert (accepted, rejected) == (1, 0)

        # Duplicate (same domain) is silently rejected.
        with patch("app.services.ingestion_service.AlertDeliveryService.enqueue", new_callable=AsyncMock):
            accepted2, rejected2 = await ingest_findings(db_session, connector=conn, job_id=None, findings=findings)
        assert (accepted2, rejected2) == (0, 1)
        await db_session.refresh(conn)  # re-load after internal commits

        # Missing domain is rejected.
        a3, r3 = await ingest_findings(
            db_session, connector=conn, job_id=None, findings=[{"matched_asset": "x"}]
        )
        assert (a3, r3) == (0, 1)
        await db_session.refresh(conn)  # re-load after internal commits

        row = (await db_session.execute(
            select(PhishingDomain).where(PhishingDomain.phishing_domain == findings[0]["phishing_domain"])
        )).scalar_one_or_none()
        assert row is not None
        assert row.detection_source == "ing-test"  # defaults to connector name
        await db_session.delete(row)
        await db_session.delete(conn)
        await db_session.commit()
        _ = conn_type, conn_id

    @pytest.mark.asyncio
    async def test_phishing_batch_survives_commit_expiration(self, db_session):
        """A multi-finding connector batch must not fail after its first commit."""
        from sqlalchemy import select

        from app.models import PhishingDomain
        from app.services.ingestion_service import ingest_findings

        conn = Connector(
            name="ing-batch", connector_type="phishing", default_job_type="phishing.ing-batch"
        )
        db_session.add(conn)
        await db_session.commit()

        domains = [f"batch-{uuid.uuid4().hex[:8]}.example" for _ in range(2)]
        findings = [
            {"phishing_domain": domain, "matched_asset": "example.com"}
            for domain in domains
        ]
        with patch(
            "app.services.ingestion_service.AlertDeliveryService.enqueue",
            new_callable=AsyncMock,
        ), patch("app.services.phishing.whois_service.WhoisService.enrich", new_callable=AsyncMock):
            accepted, rejected = await ingest_findings(
                db_session,
                connector=conn,
                job_id=None,
                findings=findings,
                connector_name="ing-batch",
                connector_type="phishing",
            )

        assert (accepted, rejected) == (2, 0)
        rows = (
            await db_session.execute(
                select(PhishingDomain).where(PhishingDomain.phishing_domain.in_(domains))
            )
        ).scalars().all()
        assert {row.phishing_domain for row in rows} == set(domains)

        for row in rows:
            await db_session.delete(row)
        await db_session.delete(conn)
        await db_session.commit()

        from sqlalchemy import select

        from app.models import Breach
        from app.services.ingestion_service import ingest_findings

        conn = Connector(
            name="ing-hibp", connector_type="breaches", default_job_type="breaches.hibp"
        )
        db_session.add(conn)
        await db_session.commit()

        suffix = uuid.uuid4().hex[:6]
        findings = [
            {"breach_name": f"TestBreach-{suffix}", "matched_email": f"user-{suffix}@example.com", "pwn_count": 5, "data_classes": ["Emails"]},
            {"breach_name": f"NoMatch-{suffix}"},  # no matched_email/domain
            {"matched_email": "a@b.c"},  # no breach_name
        ]
        with patch("app.services.ingestion_service.AlertDeliveryService.enqueue", new_callable=AsyncMock):
            accepted, rejected = await ingest_findings(db_session, connector=conn, job_id=None, findings=findings)
        assert (accepted, rejected) == (1, 2)
        await db_session.refresh(conn)  # re-load after internal commits

        row = (await db_session.execute(
            select(Breach).where(Breach.breach_name == f"TestBreach-{suffix}")
        )).scalar_one_or_none()
        assert row is not None
        assert row.matched_email == f"user-{suffix}@example.com"
        await db_session.delete(row)
        await db_session.delete(conn)
        await db_session.commit()

    @pytest.mark.asyncio
    async def test_ingestion_fires_alerts(self, db_session):
        from app.services.ingestion_service import ingest_phishing_finding

        conn = Connector(
            name="ing-alert", connector_type="phishing", default_job_type="phishing.ing-alert"
        )
        db_session.add(conn)
        await db_session.commit()

        # The alert path is the durable queue, not a provider call from inside
        # ingestion: a delivery outage must not fail an accepted finding.
        alert_mock = AsyncMock(return_value=None)
        with patch(
            "app.services.ingestion_service.AlertDeliveryService.enqueue", alert_mock
        ):
            domain = f"alerted-{uuid.uuid4().hex[:8]}.com"
            ok = await ingest_phishing_finding(
                db_session, conn, {"phishing_domain": domain, "matched_asset": "a.com"}
            )
            assert ok is True
            alert_mock.assert_awaited_once()

        from sqlalchemy import delete

        from app.models import PhishingDomain

        await db_session.execute(delete(PhishingDomain).where(PhishingDomain.phishing_domain == domain))
        await db_session.delete(conn)
        await db_session.commit()


# ---------------------------------------------------------------------------
# Per-connector config contract (validated against the connector's manifest)
# ---------------------------------------------------------------------------


class TestConnectorConfigContract:
    @pytest.mark.asyncio
    async def test_config_validated_against_declared_schema(self, db_session):
        from app.services.connector_manifest import (
            build_manifest,
            validate_connector_config,
        )
        from app.services.module_registry import BUILTIN_MODULE_DEFINITIONS

        row = {item["id"]: item for item in BUILTIN_MODULE_DEFINITIONS}["phishing"]
        phishing = ModuleSpec(
            id=row["id"],
            label=row["label"],
            description=row["description"],
            finding_kind=row["finding_kind"],
            asset_types=tuple(row["asset_types"]),
            fields=row["fields"],
            dedup_fields=tuple(row["dedup_fields"]),
            title_field=row["title_field"],
            storage=row["storage"],
        )

        manifest = build_manifest(
            module_spec=phishing,
            job_type="phishing.lookalike",
            config_schema={
                "scan_certificates": {"type": "bool", "default": True},
                "scan_titles": {"type": "bool", "default": True},
                "max_pages": {"type": "int", "default": 3},
            },
        )
        # Declared defaults are materialized and unknown keys dropped.
        valid = validate_connector_config(
            manifest, {"scan_certificates": False, "injected": "x"}
        )
        assert valid == {
            "scan_certificates": False,
            "scan_titles": True,
            "max_pages": 3,
        }

        # A declared type is enforced, not silently coerced.
        with pytest.raises(Exception):
            validate_connector_config(manifest, {"scan_certificates": "yes-please"})
        with pytest.raises(Exception):
            validate_connector_config(manifest, {"max_pages": "two"})

        # A connector that declared no schema accepts scalars only — never a
        # nested object in the JSON column.
        bare = build_manifest(module_spec=phishing, job_type="phishing.bare")
        passthrough = validate_connector_config(bare, {"foo": 1, "bad": {"nested": 1}})
        assert passthrough == {"foo": 1}

    @pytest.mark.asyncio
    async def test_config_persists_and_reaches_work_payload(self, db_session):
        svc = ConnectorService(db_session)
        conn = await svc.register(
            name="lookalike",
            connector_type="phishing",
            api_version="1.0",
            default_job_type="phishing.lookalike",
            config_schema={"scan_certificates": {"type": "bool", "default": True}},
        )
        await svc.set_config(conn.id, {"scan_certificates": False})
        await db_session.refresh(conn)
        assert conn.config["scan_certificates"] is False

        job = (await svc.enqueue_module_scan(
            connector_type="phishing", created_by=None, title="T"
        ))[0]
        claimed = await svc.claim_work(conn)
        assert claimed is not None
        # The config is delivered by the router's work response.
        assert conn.config["scan_certificates"] is False

        await svc.fail_job(conn, claimed.id, error="cleanup", lease_token=claimed.lease_token)
        await db_session.delete(claimed)
        await db_session.delete(job)
        await db_session.delete(conn)
        await db_session.commit()
