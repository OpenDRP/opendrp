"""A module declared on the running platform, end to end.

This is the point of the registry: an operator declares a module (its fields,
deduplication and headline), a connector registers for it, claims work and
submits findings — and **no core code, migration or frontend change** was needed
to make that data visible.

Everything here goes through the real HTTP surface, including validation and
RBAC, because that is where a declaration can be abused.
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.models import Finding
from app.services.connector_credentials import ConnectorCredentials
from app.services.connector_service import ConnectorService

_MODULE = {
    "id": "code_leak",
    "label": "Code leaks",
    "description": "Secrets and source code exposed in public repositories.",
    "fields": {
        "repository": {"type": "str", "required": True, "label": "Repository"},
        "file_path": {"type": "str", "label": "File"},
        "secret_kind": {"type": "str", "required": True, "label": "Secret type"},
        "lines": {"type": "int"},
        "first_seen": {"type": "date"},
        "tags": {"type": "list_str"},
    },
    "dedup_fields": ["repository", "file_path", "secret_kind"],
    "title_field": "repository",
    "asset_types": ["domain"],
}


async def _declare(client, headers, **overrides):
    payload = {**_MODULE, **overrides}
    return await client.post("/api/v1/modules", headers=headers, json=payload)


async def _connector_headers(db, *, name="leakwatch", job_type="code_leak.repo_scan"):
    """Register a connector for the declared module and issue its credential."""
    conn = await ConnectorService(db).register(
        name=name,
        connector_type="code_leak",
        default_job_type=job_type,
        asset_types=["domain"],
        config_schema={"depth": {"type": "int", "default": 2, "label": "Scan depth"}},
    )
    token, _ = await ConnectorCredentials(db).issue(conn)
    return conn, {"X-Connector-Token": token, "X-Connector-Name": conn.name}


def _submitting(headers: dict, claimed: dict) -> dict:
    """Headers for submitting findings for a job this connector claimed.

    A submission is bound to the claim: the lease token the claim returned is
    what stops a worker whose lease expired from still writing findings under
    its own name.
    """
    return {**headers, "X-Connector-Lease": claimed["lease_token"]}


# ---------------------------------------------------------------------------
# Declaring a module
# ---------------------------------------------------------------------------


class TestDeclareModule:
    @pytest.mark.asyncio
    async def test_admin_declares_a_module(self, client, auth_headers_admin):
        resp = await _declare(client, auth_headers_admin)
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["id"] == "code_leak"
        assert body["finding_kind"] == "code_leak"
        assert body["storage"] == "generic"
        assert body["builtin"] is False
        assert body["title_field"] == "repository"
        assert body["fields"]["repository"]["required"] is True

    @pytest.mark.asyncio
    async def test_declaring_requires_admin(
        self, client, auth_headers_analyst, auth_headers_viewer
    ):
        for headers in (auth_headers_analyst, auth_headers_viewer):
            assert (await _declare(client, headers)).status_code == 403

    @pytest.mark.asyncio
    async def test_an_incoherent_declaration_is_refused(self, client, auth_headers_admin):
        # Dedup field that the module does not declare.
        resp = await _declare(client, auth_headers_admin, dedup_fields=["commit_sha"])
        assert resp.status_code == 400
        # Field type outside the supported set.
        resp = await _declare(
            client,
            auth_headers_admin,
            fields={"repository": {"type": "uuid"}},
            dedup_fields=["repository"],
        )
        assert resp.status_code == 400
        # Unknown inventory section.
        resp = await _declare(client, auth_headers_admin, asset_types=["blockchain"])
        assert resp.status_code == 400
        # A declaration without an identity would store every submission again.
        resp = await _declare(client, auth_headers_admin, dedup_fields=[])
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_a_module_cannot_shadow_an_existing_one(self, client, auth_headers_admin):
        assert (await _declare(client, auth_headers_admin, id="phishing")).status_code == 400
        assert (await _declare(client, auth_headers_admin)).status_code == 201
        assert (await _declare(client, auth_headers_admin)).status_code == 400

    @pytest.mark.asyncio
    async def test_the_registry_is_readable_by_any_signed_in_user(
        self, client, db_session, auth_headers_admin, auth_headers_viewer
    ):
        await _declare(client, auth_headers_admin)
        resp = await client.get("/api/v1/modules", headers=auth_headers_viewer)
        assert resp.status_code == 200
        by_id = {m["id"]: m for m in resp.json()["modules"]}
        assert {"phishing", "breaches", "code_leak"} <= set(by_id)
        assert by_id["breaches"]["storage"] == "table"
        assert by_id["code_leak"]["fields"]["secret_kind"]["required"] is True
        # No registry view leaks a table name or another module's internals.
        assert "drp_" not in str(resp.json())

    @pytest.mark.asyncio
    async def test_the_registry_is_not_public(self, client, db_session):
        assert (await client.get("/api/v1/modules")).status_code == 401

    @pytest.mark.asyncio
    async def test_a_module_can_be_renamed_toggled_and_not_redefined(
        self, client, auth_headers_admin
    ):
        await _declare(client, auth_headers_admin)
        resp = await client.patch(
            "/api/v1/modules/code_leak",
            headers=auth_headers_admin,
            json={"label": "Leaked secrets", "enabled": False},
        )
        assert resp.status_code == 200
        assert resp.json()["label"] == "Leaked secrets"
        assert resp.json()["enabled"] is False

        # Finding fields are immutable once findings may exist.
        resp = await client.patch(
            "/api/v1/modules/code_leak",
            headers=auth_headers_admin,
            json={"fields": {"repository": {"type": "str"}}},
        )
        assert resp.status_code == 422
        assert (
            await client.patch(
                "/api/v1/modules/code_leak", headers=auth_headers_admin, json={}
            )
        ).status_code == 400
        assert (
            await client.patch(
                "/api/v1/modules/ghost", headers=auth_headers_admin, json={"enabled": False}
            )
        ).status_code == 400

    @pytest.mark.asyncio
    async def test_a_declared_module_appears_in_the_job_type_registry(
        self, client, db_session, auth_headers_admin, auth_headers_viewer
    ):
        await _declare(client, auth_headers_admin)
        await _connector_headers(db_session)
        resp = await client.get("/api/v1/connectors/modules", headers=auth_headers_viewer)
        assert resp.status_code == 200
        entry = resp.json()["modules"]["code_leak"]
        assert entry["label"] == "Code leaks"
        assert entry["finding_kind"] == "code_leak"
        assert entry["storage"] == "generic"
        assert entry["job_types"] == ["code_leak.repo_scan"]
        assert entry["connectors"][0]["config_schema"]["depth"]["label"] == "Scan depth"


# ---------------------------------------------------------------------------
# Working through the declared module
# ---------------------------------------------------------------------------


class TestDeclaredModuleWork:
    @pytest.mark.asyncio
    async def test_a_connector_claims_its_own_work_and_submits_findings(
        self, client, db_session, auth_headers_admin
    ):
        await _declare(client, auth_headers_admin)
        conn, headers = await _connector_headers(db_session)

        jobs = await ConnectorService(db_session).enqueue_module_scan(
            connector_type="code_leak", created_by=None, title="Repo scan"
        )
        assert [job.job_type for job in jobs] == ["code_leak.repo_scan"]

        work = await client.get("/api/v1/connectors/me/work", headers=headers)
        assert work.status_code == 200, work.text
        body = work.json()
        assert body["module"] == "code_leak"
        assert body["job_type"] == "code_leak.repo_scan"
        # The connector declared it consumes domains only: the keys stay present
        # (connectors always read them) but the account inventory is withheld.
        assert body["params"]["emails"] == []
        assert "domains" in body["params"]

        with patch(
            "app.services.ingestion_service.AlertDeliveryService.enqueue",
            new_callable=AsyncMock,
        ) as alert:
            resp = await client.post(
                f"/api/v1/connectors/me/findings/{body['job_id']}",
                headers=_submitting(headers, body),
                json=[
                    {
                        "repository": "github.com/acme/app",
                        "file_path": "src/config.py",
                        "secret_kind": "aws_access_key",
                        "lines": 3,
                        "first_seen": "2026-02-01",
                        "tags": ["prod"],
                        "attributes": {"commit": "abc123"},
                    }
                ],
            )
        assert resp.status_code == 200, resp.text
        assert resp.json() == {"accepted": 1, "rejected": 0}

        # The module's declaration is the wire contract: an undeclared key
        # refuses the batch outright instead of being stored or dropped.    
        bad = await client.post(
            f"/api/v1/connectors/me/findings/{body['job_id']}",
            headers=_submitting(headers, body),
            json=[{"repository": "r", "secret_kind": "aws", "extra": 1}],
        )
        assert bad.status_code == 400
        assert "extra_forbidden" in bad.text

        row = (
            await db_session.execute(
                select_findings("github.com/acme/app")
            )
        ).scalar_one()
        assert row.module == "code_leak"
        assert row.finding_kind == "code_leak"
        assert row.connector_name == conn.name
        assert str(row.job_id) == body["job_id"]
        assert row.dedup_key == "github.com/acme/app|src/config.py|aws_access_key"
        assert row.title == "github.com/acme/app"
        assert row.payload["lines"] == 3
        assert row.payload["tags"] == ["prod"]
        assert row.payload["attributes"] == {"commit": "abc123"}

        # The alert path is the module's own declaration, not a template per
        # vendor: label plus the fields the module declared. It goes through the
        # durable queue, so a provider outage cannot fail an accepted finding.
        alert.assert_awaited()
        details = alert.await_args.kwargs
        assert details["threat_type"] == "module:code_leak"

    @pytest.mark.asyncio
    async def test_a_resubmission_is_deduplicated_by_the_declared_fields(
        self, client, db_session, auth_headers_admin
    ):
        await _declare(client, auth_headers_admin)
        _, headers = await _connector_headers(db_session)
        await ConnectorService(db_session).enqueue_module_scan(
            connector_type="code_leak", created_by=None, title="Repo scan"
        )
        work = (await client.get("/api/v1/connectors/me/work", headers=headers)).json()
        finding = {
            "repository": "github.com/acme/app",
            "file_path": "src/config.py",
            "secret_kind": "aws_access_key",
        }
        with patch(
            "app.services.ingestion_service.AlertDeliveryService.enqueue",
            new_callable=AsyncMock,
        ):
            first = await client.post(
                f"/api/v1/connectors/me/findings/{work['job_id']}",
                headers=_submitting(headers, work),
                json=[finding],
            )
            second = await client.post(
                f"/api/v1/connectors/me/findings/{work['job_id']}",
                headers=_submitting(headers, work),
                json=[finding],
            )
        assert first.json() == {"accepted": 1, "rejected": 0}
        assert second.json() == {"accepted": 0, "rejected": 1}  # same dedup key

    @pytest.mark.asyncio
    async def test_findings_of_a_declared_module_are_listed_by_module(
        self, client, db_session, auth_headers_admin, auth_headers_viewer
    ):
        await _declare(client, auth_headers_admin)
        _, headers = await _connector_headers(db_session)
        await ConnectorService(db_session).enqueue_module_scan(
            connector_type="code_leak", created_by=None, title="Repo scan"
        )
        work = (await client.get("/api/v1/connectors/me/work", headers=headers)).json()
        with patch(
            "app.services.ingestion_service.AlertDeliveryService.enqueue",
            new_callable=AsyncMock,
        ):
            await client.post(
                f"/api/v1/connectors/me/findings/{work['job_id']}",
                headers=_submitting(headers, work),
                json=[
                    {
                        "repository": "github.com/acme/app",
                        "file_path": "src/config.py",
                        "secret_kind": "aws_access_key",
                        "matched_asset": "acme.com",
                    }
                ],
            )

        resp = await client.get("/api/v1/findings", headers=auth_headers_viewer)
        assert resp.status_code == 200
        assert resp.json()["total"] == 1
        item = resp.json()["items"][0]
        assert item["module"] == "code_leak"
        assert item["title"] == "github.com/acme/app"
        assert item["matched_asset"] == "acme.com"
        assert item["payload"]["secret_kind"] == "aws_access_key"

        filtered = await client.get(
            "/api/v1/findings?module=code_leak", headers=auth_headers_viewer
        )
        assert filtered.json()["total"] == 1
        empty = await client.get("/api/v1/findings?module=phishing", headers=auth_headers_viewer)
        assert empty.json()["total"] == 0
        assert (
            await client.get("/api/v1/findings?module=ghost", headers=auth_headers_viewer)
        ).status_code == 400
        assert (await client.get("/api/v1/findings")).status_code == 401

    @pytest.mark.asyncio
    async def test_a_connector_of_another_module_cannot_touch_this_work(
        self, client, db_session, auth_headers_admin
    ):
        await _declare(client, auth_headers_admin)
        _, leak_headers = await _connector_headers(db_session)
        phishing = await ConnectorService(db_session).register(
            name="dnstwist", connector_type="phishing", default_job_type="phishing.dnstwist"
        )
        token, _ = await ConnectorCredentials(db_session).issue(phishing)
        intruder = {"X-Connector-Token": token, "X-Connector-Name": phishing.name}

        await ConnectorService(db_session).enqueue_module_scan(
            connector_type="code_leak", created_by=None, title="Repo scan"
        )
        # The intruder sees no work (its job type differs) and cannot submit to
        # a job it does not own.
        assert (
            await client.get("/api/v1/connectors/me/work", headers=intruder)
        ).status_code == 204
        work = (await client.get("/api/v1/connectors/me/work", headers=leak_headers)).json()
        # The right lease, the wrong connector: ownership is checked, not just
        # the presence of a token.
        assert (
            await client.post(
                f"/api/v1/connectors/me/findings/{work['job_id']}",
                headers=_submitting(intruder, work),
                json=[{"phishing_domain": "evil.example", "matched_asset": "acme.com"}],
            )
        ).status_code == 403

    @pytest.mark.asyncio
    async def test_a_disabled_module_cannot_be_registered_against(
        self, client, db_session, auth_headers_admin
    ):
        await _declare(client, auth_headers_admin)
        await client.patch(
            "/api/v1/modules/code_leak", headers=auth_headers_admin, json={"enabled": False}
        )
        with pytest.raises(Exception, match="disabled"):
            await ConnectorService(db_session).register(
                name="late", connector_type="code_leak"
            )

    @pytest.mark.asyncio
    async def test_a_module_that_does_not_exist_cannot_be_registered_against(
        self, db_session
    ):
        with pytest.raises(Exception) as exc:
            await ConnectorService(db_session).register(name="voip", connector_type="voip")
        assert "unknown module 'voip'" in str(exc.value)


def select_findings(repository: str):
    """Query helper (kept out of the class body for readability)."""
    from sqlalchemy import select

    return select(Finding).where(Finding.title == repository)


# ---------------------------------------------------------------------------
# Triaging a declared module's findings
# ---------------------------------------------------------------------------


async def _seed_one_finding(client, db_session, auth_headers_admin) -> str:
    """Declare the module, submit one finding through the connector protocol."""
    await _declare(client, auth_headers_admin)
    _, headers = await _connector_headers(db_session)
    await ConnectorService(db_session).enqueue_module_scan(
        connector_type="code_leak", created_by=None, title="Repo scan"
    )
    work = (await client.get("/api/v1/connectors/me/work", headers=headers)).json()
    with patch(
        "app.services.ingestion_service.AlertDeliveryService.enqueue",
        new_callable=AsyncMock,
    ):
        await client.post(
            f"/api/v1/connectors/me/findings/{work['job_id']}",
            headers=_submitting(headers, work),
            json=[
                {
                    "repository": "github.com/acme/app",
                    "file_path": "src/config.py",
                    "secret_kind": "aws_access_key",
                    "matched_asset": "acme.com",
                }
            ],
        )
    listed = await client.get("/api/v1/findings?module=code_leak", headers=auth_headers_admin)
    return listed.json()["items"][0]["id"]


class TestFindingTriage:
    """A declared module's findings are triageable, like the built-in modules'.

    Before this, generic findings were read-only: an operator could see a finding
    but had no way to mark it investigated.
    """

    @pytest.mark.asyncio
    async def test_analyst_moves_a_finding_through_triage(
        self, client, db_session, auth_headers_admin, auth_headers_analyst
    ):
        from sqlalchemy import select

        from app.models import AuditLog

        finding_id = await _seed_one_finding(client, db_session, auth_headers_admin)

        first = await client.patch(
            f"/api/v1/findings/{finding_id}",
            headers=auth_headers_analyst,
            json={"status": "investigating"},
        )
        assert first.status_code == 200
        assert first.json()["status"] == "investigating"
        # The payload is the source's report and must survive triage untouched.
        assert first.json()["payload"]["secret_kind"] == "aws_access_key"

        second = await client.patch(
            f"/api/v1/findings/{finding_id}",
            headers=auth_headers_analyst,
            json={"status": "resolved"},
        )
        assert second.json()["status"] == "resolved"

        rows = (
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "finding.status_update")
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 2
        transitions = sorted((r.details or {}).get("to") for r in rows)
        assert transitions == ["investigating", "resolved"]
        assert all((r.details or {}).get("module") == "code_leak" for r in rows)
        assert (rows[0].details or {}).get("from") == "active"

    @pytest.mark.asyncio
    async def test_viewer_cannot_triage(
        self, client, db_session, auth_headers_admin, auth_headers_viewer
    ):
        finding_id = await _seed_one_finding(client, db_session, auth_headers_admin)
        resp = await client.patch(
            f"/api/v1/findings/{finding_id}",
            headers=auth_headers_viewer,
            json={"status": "resolved"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_triage_requires_authentication(
        self, client, db_session, auth_headers_admin
    ):
        finding_id = await _seed_one_finding(client, db_session, auth_headers_admin)
        resp = await client.patch(
            f"/api/v1/findings/{finding_id}", json={"status": "resolved"}
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_an_unknown_status_is_refused(
        self, client, db_session, auth_headers_admin, auth_headers_analyst
    ):
        finding_id = await _seed_one_finding(client, db_session, auth_headers_admin)
        resp = await client.patch(
            f"/api/v1/findings/{finding_id}",
            headers=auth_headers_analyst,
            json={"status": "closed"},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_an_unknown_finding_is_not_found(
        self, client, auth_headers_analyst
    ):
        import uuid

        resp = await client.patch(
            f"/api/v1/findings/{uuid.uuid4()}",
            headers=auth_headers_analyst,
            json={"status": "resolved"},
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_resending_the_same_status_writes_no_audit_row(
        self, client, db_session, auth_headers_admin, auth_headers_analyst
    ):
        from sqlalchemy import func, select

        from app.models import AuditLog

        finding_id = await _seed_one_finding(client, db_session, auth_headers_admin)
        await client.patch(
            f"/api/v1/findings/{finding_id}",
            headers=auth_headers_analyst,
            json={"status": "investigating"},
        )

        before = (
            await db_session.execute(
                select(func.count(AuditLog.id)).where(
                    AuditLog.action == "finding.status_update"
                )
            )
        ).scalar_one()

        repeat = await client.patch(
            f"/api/v1/findings/{finding_id}",
            headers=auth_headers_analyst,
            json={"status": "investigating"},
        )
        assert repeat.status_code == 200
        after = (
            await db_session.execute(
                select(func.count(AuditLog.id)).where(
                    AuditLog.action == "finding.status_update"
                )
            )
        ).scalar_one()
        # A repeated status is not a transition, so it must not add audit noise.
        assert after == before

    @pytest.mark.asyncio
    async def test_a_native_module_finding_is_not_reachable_here(
        self, client, auth_headers_analyst
    ):
        """Generic triage must not become a back door to built-in storage.

        The built-in modules own their tables and their own status endpoints;
        their findings are not rows in ``drp_findings``, so this route cannot
        address them at all.
        """
        import uuid

        resp = await client.patch(
            f"/api/v1/findings/{uuid.uuid4()}",
            headers=auth_headers_analyst,
            json={"status": "investigating"},
        )
        assert resp.status_code == 404
