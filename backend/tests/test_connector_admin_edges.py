"""The connector router's refusals: what it does with a caller it does not trust.

``test_connectors_protocol_api`` pins the protocol's happy paths. This file pins
the other half — the branches that only run when a credential is stale, a header
contradicts the token, a readiness document is malformed, or an operator asks the
admin surface about a row that is not there. Each is a place where the core's
answer is what keeps a half-trusted caller from deciding something it may not.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.services.connector_credentials import ConnectorCredentials
from app.services.connector_service import ConnectorService

_TOKENS: dict[str, str] = {}


@pytest.fixture(autouse=True)
def _reset_tokens():
    _TOKENS.clear()


async def _auth(db, name: str, connector_type: str) -> dict[str, str]:
    token = _TOKENS.get(name)
    if token is None:
        svc = ConnectorService(db)
        conn = await svc.get_by_name(name)
        if conn is None:
            conn = await svc.register(
                name=name,
                connector_type=connector_type,
                api_version="1.0",
                default_job_type=f"{connector_type}.{name}",
            )
        token, _ = await ConnectorCredentials(db).issue(conn)
        _TOKENS[name] = token
    return {"X-Connector-Token": token, "X-Connector-Name": name}


class TestCredentialHeader:
    @pytest.mark.asyncio
    async def test_a_name_header_that_cannot_be_normalized_does_not_grant_identity(
        self, client, db_session
    ):
        """A malformed name is ignored, never compared as text.

        The header is advisory; the token is identity. Comparing a value the
        normalizer refused would turn a typo into a 403 on a request the
        credential already authorised, so the name is dropped instead.
        """
        headers = await _auth(db_session, "hibp", "breaches")

        response = await client.get(
            "/api/v1/connectors/me/work",
            headers={**headers, "X-Connector-Name": "***"},
        )

        assert response.status_code == 204

    @pytest.mark.asyncio
    async def test_the_rejection_diagnostic_cache_is_bounded(self, client, db_session):
        """A flood of made-up tokens must not grow the diagnostic map forever.

        The cache exists so one connector's stale token is reported once a
        minute. Starting from a full map, the next rejection clears it rather
        than letting an attacker's token labels decide the process's memory.
        """
        from app.api.v1.routers import connectors as router

        router._rejection_log_seen.clear()
        full = datetime.now(timezone.utc) - router._REJECTION_LOG_INTERVAL * 2
        for index in range(router._REJECTION_LOG_MAX_KEYS):
            router._rejection_log_seen[(f"connector-{index}", "198.51.100.1")] = full
        assert len(router._rejection_log_seen) == router._REJECTION_LOG_MAX_KEYS

        response = await client.get(
            "/api/v1/connectors/me/work",
            headers={"X-Connector-Token": "opendrp_ghost_" + "z" * 43},
        )

        assert response.status_code == 401
        # Cleared, then the current rejection recorded: bounded, not emptied.
        assert len(router._rejection_log_seen) == 1
        assert list(router._rejection_log_seen)[0][0] == "ghost"
        router._rejection_log_seen.clear()


class TestRegistrationValidation:
    @pytest.mark.asyncio
    async def test_control_characters_in_declared_metadata_are_refused(
        self, client, db_session
    ):
        """A manifest line feeds the audit trail and the UI; a newline splits both."""
        headers = await _auth(db_session, "hibp", "breaches")

        response = await client.post(
            "/api/v1/connectors/register",
            headers=headers,
            json={
                "name": "hibp\nforged",
                "connector_type": "breaches",
                "api_version": "1.0",
                "default_job_type": "breaches.hibp",
            },
        )

        assert response.status_code == 422
        assert (await ConnectorService(db_session).get_by_name("hibp")) is not None


class TestCompletion:
    @pytest.mark.asyncio
    async def test_a_completion_without_a_summary_is_accepted(self, client, db_session):
        """The summary is optional; the lease is the required part."""
        svc = ConnectorService(db_session)
        await svc.register(
            name="dnstwist",
            connector_type="phishing",
            api_version="1.0",
            default_job_type="phishing.dnstwist",
        )
        job = (
            await svc.enqueue_module_scan(
                connector_type="phishing", created_by=None, title="Scan"
            )
        )[0]
        headers = await _auth(db_session, "dnstwist", "phishing")
        work = await client.get("/api/v1/connectors/me/work", headers=headers)
        lease = work.json()["lease_token"]

        response = await client.post(
            f"/api/v1/connectors/me/complete/{job.id}",
            headers=headers,
            json={"ok": True, "lease_token": lease, "summary": None, "error": None},
        )

        assert response.status_code == 200, response.text
        assert response.json()["status"] == "success"

    @pytest.mark.asyncio
    async def test_an_error_with_a_newline_is_refused(self, client, db_session):
        """The failure text becomes one log line and one audit field."""
        svc = ConnectorService(db_session)
        await svc.register(
            name="dnstwist",
            connector_type="phishing",
            api_version="1.0",
            default_job_type="phishing.dnstwist",
        )
        headers = await _auth(db_session, "dnstwist", "phishing")

        response = await client.post(
            "/api/v1/connectors/me/complete/00000000-0000-0000-0000-000000000001",
            headers=headers,
            json={
                "ok": False,
                "error": "boom\nsecond line",
                "lease_token": "a" * 32,
            },
        )

        assert response.status_code == 422


class TestStatus:
    @pytest.mark.asyncio
    async def test_an_unknown_status_is_refused(self, client, db_session, auth_headers_admin):
        conn = await ConnectorService(db_session).register(
            name="hibp",
            connector_type="breaches",
            api_version="1.0",
            default_job_type="breaches.hibp",
        )

        response = await client.patch(
            f"/api/v1/connectors/{conn.id}/status",
            headers=auth_headers_admin,
            json={"status": "paused"},
        )

        assert response.status_code == 422


class TestReadinessDocument:
    @pytest.mark.asyncio
    async def test_labels_are_trimmed_and_deduplicated(self, client, db_session):
        """The provider's vocabulary is stored as it will be rendered."""
        headers = await _auth(db_session, "hibp", "breaches")
        conn = await ConnectorService(db_session).get_by_name("hibp")

        response = await client.post(
            "/api/v1/connectors/me/readiness",
            headers=headers,
            json={
                "credentials_configured": True,
                "data_class_labels": {" Email addresses ": " Email addresses"},
                "capabilities": ["breach_search", "breach_search"],
            },
        )

        assert response.status_code == 200, response.text
        await db_session.refresh(conn)
        assert conn.readiness["data_class_labels"] == {
            "Email addresses": "Email addresses"
        }
        assert conn.readiness["capabilities"] == ["breach_search"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "labels",
        [
            {f"class-{index}": "label" for index in range(201)},
            {"class": 5},
            {"   ": "label"},
            {"class": "x" * 257},
            {"x" * 129: "label"},
        ],
        ids=["too-many", "not-a-string", "empty-key", "label-too-long", "key-too-long"],
    )
    async def test_a_malformed_label_map_is_refused(self, client, db_session, labels):
        """The page renders these strings; a provider cannot choose their size."""
        headers = await _auth(db_session, "hibp", "breaches")

        response = await client.post(
            "/api/v1/connectors/me/readiness",
            headers=headers,
            json={"credentials_configured": True, "data_class_labels": labels},
        )

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_capability_identifiers_are_namespaced(self, client, db_session):
        headers = await _auth(db_session, "hibp", "breaches")

        response = await client.post(
            "/api/v1/connectors/me/readiness",
            headers=headers,
            json={"credentials_configured": True, "operations": ["Not Namespaced"]},
        )

        assert response.status_code == 422


class TestQuotaEndpoints:
    @pytest.mark.asyncio
    async def test_a_reservation_needs_the_lease_that_claimed_the_job(
        self, client, db_session
    ):
        """Quota is charged to a claim, not to a connector that merely exists."""
        svc = ConnectorService(db_session)
        conn = await svc.register(
            name="netlas",
            connector_type="exposure",
            api_version="1.0",
            default_job_type="exposure.netlas",
        )
        job = (
            await svc.enqueue_module_scan(
                connector_type="exposure", created_by=None, title="Scan"
            )
        )[0]
        headers = await _auth(db_session, "netlas", "exposure")
        stale = await client.post(
            f"/api/v1/connectors/me/quota/provider?job_id={job.id}",
            headers={**headers, "X-Connector-Lease": "s" * 32},
        )
        assert stale.status_code == 403

        work = await client.get("/api/v1/connectors/me/work", headers=headers)
        lease = work.json()["lease_token"]
        # The claim is valid, but the connector has no provider account bound:
        # the reservation is refused rather than charged to nobody.
        response = await client.post(
            f"/api/v1/connectors/me/quota/provider?job_id={job.id}",
            headers={**headers, "X-Connector-Lease": lease},
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "Provider quota identity is not provisioned"
        assert conn.provider is None

    @pytest.mark.asyncio
    async def test_the_legacy_virustotal_reservation_is_gone(self, client, db_session):
        """It reserved against a key that named no job, so it was withdrawn."""
        headers = await _auth(db_session, "hibp", "breaches")

        response = await client.post("/api/v1/connectors/me/quota/virustotal", headers=headers)

        assert response.status_code == 410
        assert "lease-bound" in response.json()["detail"]


class TestFindingsRefusals:
    async def _claimed(self, client, db_session, *, module: str) -> tuple:
        from app.models import Job
        from app.models.job import JobStatus

        svc = ConnectorService(db_session)
        conn = await svc.register(
            name="odd-module",
            connector_type="phishing",
            api_version="1.0",
            default_job_type="phishing.odd-module",
        )
        job = Job(
            job_type="phishing.odd-module",
            status=JobStatus.running,
            connector_id=conn.id,
            claimed_by_connector=conn.name,
            started_at=datetime.now(timezone.utc),
            params={"manifest_snapshot": {"module": module, "finding_kind": "domain"}},
            lease_token="lease-for-an-odd-module-0000",
        )
        from datetime import timedelta

        job.lease_expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        db_session.add(job)
        await db_session.commit()
        await db_session.refresh(job)
        token, _ = await ConnectorCredentials(db_session).issue(conn)
        _TOKENS[conn.name] = token
        headers = {"X-Connector-Token": token, "X-Connector-Lease": job.lease_token}
        return job, headers

    @pytest.mark.asyncio
    async def test_a_module_the_core_cannot_persist_is_refused(self, client, db_session):
        """The manifest is a promise about a shape the core has an adapter for."""
        job, headers = await self._claimed(
            client, db_session, module="no-such-module"
        )

        response = await client.post(
            f"/api/v1/connectors/me/findings/{job.id}",
            headers=headers,
            json=[{"subject": "example.com"}],
        )

        assert response.status_code == 400
        assert "cannot persist findings" in response.json()["detail"]


class TestHealthSurface:
    @pytest.mark.asyncio
    async def test_a_disabled_connector_is_reported_as_disabled(
        self, client, db_session, auth_headers_viewer
    ):
        """Liveness and enablement are separate answers, and this one is the badge."""
        svc = ConnectorService(db_session)
        conn = await svc.register(
            name="hibp",
            connector_type="breaches",
            api_version="1.0",
            default_job_type="breaches.hibp",
        )
        await svc.set_status(conn.id, "disabled")

        response = await client.get("/api/v1/connectors/health", headers=auth_headers_viewer)

        assert response.status_code == 200
        item = next(row for row in response.json()["items"] if row["name"] == "hibp")
        assert item["health"] == "disabled"
        assert item["status"] == "disabled"

    @pytest.mark.asyncio
    async def test_a_viewer_reads_no_admin_only_fields(
        self, client, db_session, auth_headers_viewer
    ):
        """The shape stays stable; the operator's fields are null for a viewer."""
        conn = await ConnectorService(db_session).register(
            name="hibp",
            connector_type="breaches",
            api_version="1.0",
            default_job_type="breaches.hibp",
        )
        conn.provider = "hibp"
        conn.last_error = "provider said token=secret"
        await db_session.commit()

        response = await client.get("/api/v1/connectors/health", headers=auth_headers_viewer)

        assert response.status_code == 200
        item = response.json()["items"][0]
        assert item["last_error"] is None
        assert item["quota_remaining"] is None
        assert item["blocked_reason"] is None
        assert item["readiness"] is None
        # All nineteen keys, on a viewer's row too. The nulls above are the point:
        # the route deliberately does not exclude them, so a page never has to ask
        # which keys this role received before reading one.
        assert set(item) == {
            "name",
            "connector_type",
            "status",
            "health",
            "online",
            "last_seen_at",
            "last_error",
            "blocked_reason",
            "quota_remaining",
            "quota_budget",
            "quota_reason",
            "credentials_configured",
            "credential_state",
            "provider_error",
            "checked_at",
            "last_success_at",
            "last_success_age_seconds",
            "readiness",
            "info",
        }


class TestAdminRegistry:
    @pytest.mark.asyncio
    async def test_configuring_an_unknown_connector_is_a_404(
        self, client, db_session, auth_headers_admin
    ):
        response = await client.patch(
            "/api/v1/connectors/00000000-0000-0000-0000-000000000001/config",
            headers=auth_headers_admin,
            json={},
        )

        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_binding_a_missing_account_is_refused(
        self, client, db_session, auth_headers_admin
    ):
        conn = await ConnectorService(db_session).register(
            name="netlas",
            connector_type="exposure",
            api_version="1.0",
            default_job_type="exposure.netlas",
        )

        response = await client.patch(
            f"/api/v1/connectors/{conn.id}/account"
            "?account_id=00000000-0000-0000-0000-000000000002",
            headers=auth_headers_admin,
        )

        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_a_connector_with_no_provider_cannot_infer_one(
        self, client, db_session, auth_headers_admin
    ):
        """Binding decides which provider a worker may call; a guess is not a decision."""
        conn = await ConnectorService(db_session).register(
            name="hibp",
            connector_type="breaches",
            api_version="1.0",
            default_job_type="breaches.hibp",
        )
        account = (
            await client.post(
                "/api/v1/connectors/accounts",
                headers=auth_headers_admin,
                json={"source_id": "hibp", "name": "primary"},
            )
        )
        assert account.status_code == 200, account.text

        response = await client.patch(
            f"/api/v1/connectors/{conn.id}/account?account_id={account.json()['id']}",
            headers=auth_headers_admin,
        )

        assert response.status_code == 400
        assert response.json()["detail"] == "Account provider cannot be inferred for this connector"

    @pytest.mark.asyncio
    async def test_binding_the_same_account_twice_is_idempotent(
        self, client, db_session, auth_headers_admin
    ):
        """The second call changes nothing, so it writes no second audit row."""
        conn = await ConnectorService(db_session).register(
            name="netlas",
            connector_type="exposure",
            api_version="1.0",
            default_job_type="exposure.netlas",
        )
        account = (
            await client.post(
                "/api/v1/connectors/accounts",
                headers=auth_headers_admin,
                json={"source_id": "netlas", "name": "primary"},
            )
        ).json()

        first = await client.patch(
            f"/api/v1/connectors/{conn.id}/account?account_id={account['id']}",
            headers=auth_headers_admin,
        )
        second = await client.patch(
            f"/api/v1/connectors/{conn.id}/account?account_id={account['id']}",
            headers=auth_headers_admin,
        )

        assert first.status_code == 200, first.text
        assert second.status_code == 200, second.text
        assert second.json()["source_account_id"] == account["id"]
        assert second.json()["provider"] == "netlas"
        assert second.json()["quota_group"] == "primary"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "name", ["hibp\nforged", "   "], ids=["control-character", "blank"]
    )
    async def test_provisioning_refuses_metadata_it_would_have_to_strip(
        self, client, db_session, auth_headers_admin, name
    ):
        response = await client.post(
            "/api/v1/connectors/provision",
            headers=auth_headers_admin,
            json={"name": name, "connector_type": "breaches"},
        )

        assert response.status_code == 422
