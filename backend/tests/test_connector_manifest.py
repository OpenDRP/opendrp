"""Connector manifest protocol: the plugin boundary.

A connector declares itself at registration — module, job type, finding kind,
consumed asset sections and its own config schema — and the core stores that
declaration instead of carrying a hardcoded list of known connectors. These
tests pin the guarantees that make the platform actually plugin-driven:

* the declaration is required: a connector without a job type or a version is
  refused, because such a connector could claim nothing and could not be told
  apart from a silent one;
* a job type the core has never seen is accepted, and only one connector can
  own it (work distribution stays unambiguous);
* a declaration is coherent — the finding kind must belong to the module, and
  the module must be one the core can persist findings for;
* a connector can never claim work that was created for another connector or
  another module (the isolation guarantee the job type buys);
* a scan carries only the inventory sections the connector declared.
"""

import pytest
from sqlalchemy import select

from app.core.exceptions import BadRequestException
from app.models import Asset, AssetType, Connector, Job
from app.services.connector_manifest import ModuleSpec, build_manifest, resolve_manifest
from app.services.connector_service import ConnectorService
from app.services.job_service import JobService
from app.services.module_registry import BUILTIN_MODULE_DEFINITIONS

#: What a first-party connector image reports about itself; required, so every
#: registration call in this file declares one.
_API_VERSION = "1.2.0"

#: The built-in modules are data, so the tests read them from the same place the
#: application seeds them from instead of repeating (and drifting from) them.
_BUILTIN = {row["id"]: row for row in BUILTIN_MODULE_DEFINITIONS}


def _spec(module_id: str) -> ModuleSpec:
    row = _BUILTIN[module_id]
    return ModuleSpec(
        id=row["id"],
        label=row["label"],
        description=row["description"],
        finding_kind=row["finding_kind"],
        asset_types=tuple(row["asset_types"]),
        fields=row["fields"],
        dedup_fields=tuple(row["dedup_fields"]),
        title_field=row["title_field"],
        storage=row["storage"],
        enabled=True,
        builtin=True,
    )


async def _add_asset(db, asset_type: AssetType, value: str) -> Asset:
    asset = Asset(asset_type=asset_type, asset_value=value, criticality="medium", is_active=True)
    db.add(asset)
    await db.commit()
    return asset


# ---------------------------------------------------------------------------
# Self-declaration
# ---------------------------------------------------------------------------


class TestRegistrationDeclaration:
    @pytest.mark.asyncio
    async def test_connector_declares_a_job_type_the_core_has_never_seen(self, db_session):
        svc = ConnectorService(db_session)
        conn = await svc.register(
            name="lookalike",
            connector_type="phishing",
            api_version=_API_VERSION,
            default_job_type="phishing.lookalike",
            asset_types=["domain"],
        )
        assert conn.default_job_type == "phishing.lookalike"
        assert conn.manifest["job_type"] == "phishing.lookalike"
        assert conn.manifest["finding_kind"] == "phishing"
        assert conn.manifest["asset_types"] == ["domain"]

        # The declared job type is what the scan actually carries.
        jobs = await svc.enqueue_module_scan(
            connector_type="phishing", created_by=None, title="Scan"
        )
        assert [job.job_type for job in jobs] == ["phishing.lookalike"]

    def test_a_manifest_without_a_job_type_is_refused(self):
        """A declaration exists so the core knows who may claim what."""
        with pytest.raises(BadRequestException, match="job type is required"):
            build_manifest(module_spec=_spec("phishing"), job_type="")

    @pytest.mark.asyncio
    async def test_provisioning_reserves_a_job_type_until_the_connector_declares_one(
        self, db_session
    ):
        """Provisioning creates the row before the connector can authenticate.

        The reserved type is not a shared bucket: it is ``<module>.<name>``, which
        this connector alone owns, and the connector replaces it with its own
        declaration the first time it registers.
        """
        svc = ConnectorService(db_session)
        conn = await svc.register(
            name="silent", connector_type="phishing", api_version=_API_VERSION
        )
        assert conn.default_job_type == "phishing.silent"

        again = await svc.register(
            name="silent",
            connector_type="phishing",
            api_version=_API_VERSION,
            default_job_type="phishing.lookalike",
        )
        assert again.id == conn.id
        assert again.default_job_type == "phishing.lookalike"

    @pytest.mark.asyncio
    async def test_a_job_type_can_only_be_owned_by_one_connector(self, db_session):
        svc = ConnectorService(db_session)
        await svc.register(
            name="lookalike",
            connector_type="phishing",
            api_version=_API_VERSION,
            default_job_type="phishing.lookalike",
        )
        with pytest.raises(BadRequestException, match="already declared by connector"):
            await svc.register(
                name="other",
                connector_type="phishing",
                api_version=_API_VERSION,
                default_job_type="phishing.lookalike",
            )

    @pytest.mark.asyncio
    async def test_redeclaring_its_own_job_type_is_allowed(self, db_session):
        svc = ConnectorService(db_session)
        first = await svc.register(
            name="lookalike",
            connector_type="phishing",
            api_version=_API_VERSION,
            default_job_type="phishing.lookalike",
        )
        again = await svc.register(
            name="lookalike",
            connector_type="phishing",
            api_version="1.3.0",
            default_job_type="phishing.lookalike",
        )
        assert again.id == first.id
        assert again.api_version == "1.3.0"

    @pytest.mark.asyncio
    async def test_a_restarted_connector_keeps_the_version_it_reports(self, db_session):
        svc = ConnectorService(db_session)
        await svc.register(
            name="lookalike",
            connector_type="phishing",
            api_version=_API_VERSION,
            default_job_type="phishing.lookalike",
        )
        again = await svc.register(
            name="lookalike",
            connector_type="phishing",
            api_version=_API_VERSION,
            default_job_type="phishing.lookalike",
        )
        assert again.api_version == _API_VERSION

    @pytest.mark.asyncio
    async def test_finding_kind_must_match_the_modules_own_declaration(self, db_session):
        """A connector cannot attach its findings to another module's storage."""
        svc = ConnectorService(db_session)
        with pytest.raises(BadRequestException, match="declares finding_kind 'breach'"):
            await svc.register(
                name="mixed-up",
                connector_type="breaches",
                api_version=_API_VERSION,
                default_job_type="breaches.mixed",
                finding_kind="phishing",
            )

    @pytest.mark.asyncio
    async def test_unknown_module_is_rejected_with_the_supported_set(self, db_session):
        svc = ConnectorService(db_session)
        with pytest.raises(BadRequestException) as exc:
            await svc.register(
                name="voip",
                connector_type="voip",
                api_version=_API_VERSION,
                default_job_type="voip.calls",
            )
        assert "breaches" in str(exc.value) and "phishing" in str(exc.value)

    @pytest.mark.asyncio
    async def test_a_finding_kind_outside_the_module_is_rejected(self, db_session):
        svc = ConnectorService(db_session)
        with pytest.raises(BadRequestException) as exc:
            await svc.register(
                name="weird",
                connector_type="phishing",
                api_version=_API_VERSION,
                default_job_type="phishing.weird",
                finding_kind="ransomware",
            )
        # The error names both sides, so an operator can fix the declaration.
        assert "'phishing'" in str(exc.value) and "'ransomware'" in str(exc.value)

    @pytest.mark.asyncio
    async def test_core_owned_job_types_cannot_be_declared(self, db_session):
        svc = ConnectorService(db_session)
        with pytest.raises(BadRequestException, match="owned by the core"):
            await svc.register(
                name="impostor",
                connector_type="phishing",
                api_version=_API_VERSION,
                default_job_type="report.generate",
            )

    @pytest.mark.asyncio
    async def test_job_type_must_be_namespaced(self, db_session):
        svc = ConnectorService(db_session)
        with pytest.raises(BadRequestException, match="namespaced"):
            await svc.register(
                name="flat",
                connector_type="phishing",
                api_version=_API_VERSION,
                default_job_type="lookalike",
            )

    @pytest.mark.asyncio
    async def test_unknown_asset_type_is_rejected(self, db_session):
        svc = ConnectorService(db_session)
        with pytest.raises(BadRequestException, match="unknown asset type"):
            await svc.register(
                name="lookalike",
                connector_type="phishing",
                api_version=_API_VERSION,
                default_job_type="phishing.lookalike",
                asset_types=["crypto_wallet"],
            )


# ---------------------------------------------------------------------------
# Work isolation
# ---------------------------------------------------------------------------


class TestWorkIsolation:
    @pytest.mark.asyncio
    async def test_connector_cannot_claim_another_modules_work(self, db_session):
        svc = ConnectorService(db_session)
        phishing = await svc.register(
            name="lookalike",
            connector_type="phishing",
            api_version=_API_VERSION,
            default_job_type="phishing.lookalike",
        )
        breaches = await svc.register(
            name="exposure",
            connector_type="breaches",
            api_version=_API_VERSION,
            default_job_type="breaches.exposure",
        )

        await svc.enqueue_module_scan(connector_type="phishing", created_by=None, title="Scan")

        # The breaches connector must not see phishing work at all.
        assert await svc.claim_work(breaches) is None
        claimed = await svc.claim_work(phishing)
        assert claimed is not None and claimed.job_type == "phishing.lookalike"

    @pytest.mark.asyncio
    async def test_connector_cannot_claim_a_siblings_work(self, db_session):
        svc = ConnectorService(db_session)
        first = await svc.register(
            name="first",
            connector_type="phishing",
            api_version=_API_VERSION,
            default_job_type="phishing.first",
        )
        second = await svc.register(
            name="second",
            connector_type="phishing",
            api_version=_API_VERSION,
            default_job_type="phishing.second",
        )

        jobs = await svc.enqueue_module_scan(
            connector_type="phishing", created_by=None, title="Scan", connector_name="second"
        )
        assert len(jobs) == 1

        assert await svc.claim_work(first) is None
        claimed = await svc.claim_work(second)
        assert claimed is not None and claimed.id == jobs[0].id

    @pytest.mark.asyncio
    async def test_work_no_connector_declared_is_never_claimed(self, db_session):
        """There is no shared bucket: an unowned job type is unclaimable by all."""
        svc = ConnectorService(db_session)
        conn = await svc.register(
            name="lookalike",
            connector_type="phishing",
            api_version=_API_VERSION,
            default_job_type="phishing.lookalike",
        )
        await JobService(db_session).create_job(
            job_type="phishing.abandoned",
            created_by=None,
            title="Orphan",
            params={"module": "phishing"},
        )
        await db_session.commit()
        assert await svc.claim_work(conn) is None

    @pytest.mark.asyncio
    async def test_a_claim_carries_the_lease_and_the_owner(self, db_session):
        svc = ConnectorService(db_session)
        conn = await svc.register(
            name="lookalike",
            connector_type="phishing",
            api_version=_API_VERSION,
            default_job_type="phishing.lookalike",
        )
        await svc.enqueue_module_scan(connector_type="phishing", created_by=None, title="Scan")

        job = await svc.claim_work(conn)

        assert job is not None
        assert job.claimed_by_connector == conn.name
        assert job.lease_token and len(job.lease_token) >= 16
        assert job.lease_expires_at is not None

    @pytest.mark.asyncio
    async def test_jobs_record_the_module_they_belong_to(self, db_session):
        svc = ConnectorService(db_session)
        await svc.register(
            name="lookalike",
            connector_type="phishing",
            api_version=_API_VERSION,
            default_job_type="phishing.lookalike",
        )
        jobs = await svc.enqueue_module_scan(
            connector_type="phishing", created_by=None, title="Scan"
        )
        assert jobs[0].params["module"] == "phishing"


# ---------------------------------------------------------------------------
# Declared inventory appetite
# ---------------------------------------------------------------------------


class TestDeclaredInventory:
    @pytest.mark.asyncio
    async def test_scan_params_only_contain_declared_sections(self, db_session):
        await _add_asset(db_session, AssetType.domain, "corp.example")
        await _add_asset(db_session, AssetType.email_account, "analyst@corp.example")

        svc = ConnectorService(db_session)
        await svc.register(
            name="lookalike",
            connector_type="phishing",
            api_version=_API_VERSION,
            default_job_type="phishing.lookalike",
            asset_types=["domain"],
        )
        job = (
            await svc.enqueue_module_scan(connector_type="phishing", created_by=None, title="Scan")
        )[0]
        # The connector asked for domains only; it is not handed the account
        # inventory it has no use for. Keys stay present so connectors can
        # always read them.
        assert job.params["domains"] == ["corp.example"]
        assert job.params["emails"] == []
        assert job.params["keyword_titles"] == []
        assert job.params["exclude"] == ["corp.example"]

    @pytest.mark.asyncio
    async def test_a_connector_that_declared_no_sections_gets_the_full_inventory(self, db_session):
        await _add_asset(db_session, AssetType.domain, "corp.example")
        await _add_asset(db_session, AssetType.email_account, "analyst@corp.example")

        svc = ConnectorService(db_session)
        await svc.register(
            name="everything",
            connector_type="phishing",
            api_version=_API_VERSION,
            default_job_type="phishing.everything",
        )
        job = (
            await svc.enqueue_module_scan(connector_type="phishing", created_by=None, title="Scan")
        )[0]
        assert job.params["domains"] == ["corp.example"]
        assert job.params["emails"] == ["analyst@corp.example"]


# ---------------------------------------------------------------------------
# Registry reads and resolution
# ---------------------------------------------------------------------------


class TestRegistryReads:
    @pytest.mark.asyncio
    async def test_modules_report_declared_job_types_and_schemas(self, db_session):
        svc = ConnectorService(db_session)
        await svc.register(
            name="lookalike",
            connector_type="phishing",
            api_version=_API_VERSION,
            default_job_type="phishing.lookalike",
            asset_types=["domain"],
            config_schema={"scan_certificates": {"type": "bool", "label": "Certificate search"}},
        )
        modules = await svc.module_job_types()
        entry = modules["phishing"]
        assert entry["job_types"] == ["phishing.lookalike"]
        assert entry["finding_kind"] == "phishing"
        assert entry["connectors"][0]["config_schema"]["scan_certificates"]["label"] == (
            "Certificate search"
        )
        # An empty module still exists, so the UI can render it.
        assert modules["breaches"]["job_types"] == []

    @pytest.mark.asyncio
    async def test_registered_job_types_lists_every_connector_type(self, db_session):
        svc = ConnectorService(db_session)
        await svc.register(
            name="lookalike",
            connector_type="phishing",
            api_version=_API_VERSION,
            default_job_type="phishing.lookalike",
        )
        await svc.register(
            name="exposure",
            connector_type="breaches",
            api_version=_API_VERSION,
            default_job_type="breaches.exposure",
        )
        types = await svc.registered_job_types()
        assert set(types) == {"phishing.lookalike", "breaches.exposure"}


class TestManifestResolution:
    @pytest.mark.asyncio
    async def test_registration_and_resolution_agree_on_the_stored_row(self, db_session):
        """What the connectors API serves is what registration declared."""
        svc = ConnectorService(db_session)
        conn = await svc.register(
            name="exposure",
            connector_type="breaches",
            api_version=_API_VERSION,
            default_job_type="breaches.exposure",
            asset_types=["email_account"],
        )

        resolved = resolve_manifest(
            module_spec=_spec("breaches"),
            connector_type=conn.connector_type,
            default_job_type=conn.default_job_type,
            manifest=conn.manifest,
        )

        assert resolved == conn.manifest
        assert resolved["finding_kind"] == "breach"
        assert resolved["asset_types"] == ["email_account"]

    def test_the_column_wins_over_a_stale_manifest_copy(self):
        # ``default_job_type`` is what work claiming filters on, so the resolved
        # manifest must never disagree with it.
        manifest = resolve_manifest(
            module_spec=_spec("phishing"),
            connector_type="phishing",
            default_job_type="phishing.current",
            manifest={"module": "phishing", "job_type": "phishing.stale"},
        )
        assert manifest["job_type"] == "phishing.current"

    def test_a_row_from_a_newer_core_is_not_remapped(self):
        # A module this core does not know (written by a newer release) is
        # reported with no finding kind rather than silently remapped.
        manifest = resolve_manifest(
            module_spec=None,
            connector_type="supply_chain",
            default_job_type="supply_chain.repo",
            manifest=None,
        )
        assert manifest["finding_kind"] == ""
        assert manifest["job_type"] == "supply_chain.repo"

    def test_build_manifest_rejects_incoherent_declarations(self):
        with pytest.raises(BadRequestException):
            build_manifest(
                module_spec=_spec("phishing"),
                job_type="phishing.x",
                finding_kind="breach",
            )

    def test_a_modules_own_declaration_is_what_gets_validated(self):
        manifest = build_manifest(module_spec=_spec("breaches"), job_type="breaches.x")
        assert manifest["module"] == "breaches"
        assert manifest["finding_kind"] == "breach"


# ---------------------------------------------------------------------------
# Registry-driven admin surface
# ---------------------------------------------------------------------------


class TestRegistryDrivenAdminSurface:
    @pytest.mark.asyncio
    async def test_admin_job_list_covers_a_new_connectors_jobs(
        self, db_session, client, auth_headers_admin
    ):
        svc = ConnectorService(db_session)
        await svc.register(
            name="lookalike",
            connector_type="phishing",
            api_version=_API_VERSION,
            default_job_type="phishing.lookalike",
        )
        await svc.enqueue_module_scan(connector_type="phishing", created_by=None, title="Scan")

        resp = await client.get("/api/v1/connectors/jobs", headers=auth_headers_admin)
        assert resp.status_code == 200
        assert resp.json()["total"] == 1
        assert resp.json()["items"][0]["job_type"] == "phishing.lookalike"

    @pytest.mark.asyncio
    async def test_connector_registration_returns_the_manifest(
        self, db_session, client, auth_headers_admin
    ):
        await ConnectorService(db_session).register(
            name="lookalike",
            connector_type="phishing",
            api_version=_API_VERSION,
            default_job_type="phishing.lookalike",
            config_schema={"scan_certificates": {"type": "bool", "default": True}},
        )
        resp = await client.get("/api/v1/connectors", headers=auth_headers_admin)
        assert resp.status_code == 200
        body = [c for c in resp.json() if c["name"] == "lookalike"][0]
        assert body["manifest"]["finding_kind"] == "phishing"
        assert body["manifest"]["config_schema"]["scan_certificates"]["type"] == "bool"

    @pytest.mark.asyncio
    async def test_a_stored_row_is_served_with_its_resolved_manifest(
        self, db_session, client, auth_headers_admin
    ):
        db_session.add(
            Connector(
                name="exposure",
                connector_type="breaches",
                api_version=_API_VERSION,
                default_job_type="breaches.exposure",
                manifest={
                    "module": "breaches",
                    "job_type": "breaches.exposure",
                    "finding_kind": "breach",
                    "asset_types": ["email_account"],
                    "config_schema": {},
                },
            )
        )
        await db_session.commit()
        resp = await client.get("/api/v1/connectors", headers=auth_headers_admin)
        assert resp.status_code == 200
        body = [c for c in resp.json() if c["name"] == "exposure"][0]
        assert body["manifest"]["finding_kind"] == "breach"

    @pytest.mark.asyncio
    async def test_findings_are_dispatched_by_the_declared_finding_kind(self, db_session):
        from app.services.ingestion_service import ingest_findings

        svc = ConnectorService(db_session)
        conn = await svc.register(
            name="exposure",
            connector_type="breaches",
            api_version=_API_VERSION,
            default_job_type="breaches.exposure",
        )
        accepted, rejected = await ingest_findings(
            db_session,
            connector=conn,
            job_id=None,
            findings=[{"breach_name": "Leak", "matched_email": "user@corp.example"}],
            connector_name=conn.name,
            finding_kind="breach",
        )
        assert (accepted, rejected) == (1, 0)

    @pytest.mark.asyncio
    async def test_an_unsupported_finding_kind_rejects_the_batch(self, db_session):
        from app.services.ingestion_service import ingest_findings

        svc = ConnectorService(db_session)
        conn = await svc.register(
            name="exposure",
            connector_type="breaches",
            api_version=_API_VERSION,
            default_job_type="breaches.exposure",
        )
        accepted, rejected = await ingest_findings(
            db_session,
            connector=conn,
            job_id=None,
            findings=[{"breach_name": "Leak", "matched_email": "user@corp.example"}],
            connector_name=conn.name,
            finding_kind="ransomware",
        )
        assert (accepted, rejected) == (0, 1)

    @pytest.mark.asyncio
    async def test_no_stray_jobs_are_left_pending(self, db_session):
        # Guard against tests leaking queued work into each other.
        pending = (
            await db_session.execute(select(Job).where(Job.status == "pending"))
        ).scalars().all()
        assert pending == []
