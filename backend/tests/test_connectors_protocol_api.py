"""Characterization tests: connector protocol HTTP layer.

These tests pin the *wire protocol* of ``app/api/v1/routers/connectors.py``:
per-connector credential auth, registration, atomic work claiming (204 when the
queue is empty), findings ingestion through the real endpoint (dedup included),
completion / failure reporting, heartbeat, credential provisioning/rotation, and
the admin-side registry endpoints with RBAC.

Service-layer semantics are covered in ``test_connectors.py``; this file
exercises the endpoints over HTTP so the router can be refactored without
changing observable behavior.

There is no platform-wide connector secret: identity is the credential, so every
connector here is provisioned (row + token) before it can call the core.
"""

import uuid
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select

from app.api.v1.routers import connectors as connectors_router
from app.models import Breach, Connector, Job, PhishingDomain
from app.services.connector_credentials import ConnectorCredentials
from app.services.connector_service import ConnectorService
from app.services.job_service import JobService

#: Tokens minted in the current test, keyed by connector name.
_TOKENS: dict[str, str] = {}


@pytest.fixture(autouse=True)
def _reset_tokens():
    """Credentials must not leak between tests: each test provisions its own."""
    _TOKENS.clear()


async def _auth(db, name: str, connector_type: str) -> dict[str, str]:
    """Headers carrying this connector's *own* credential.

    Minting happens once per test; repeated calls reuse the same token so a
    connector can poll, submit and complete with one credential. The core
    derives identity from the token alone, so no caller-supplied name can grant
    access to another connector's work.
    """
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

#: A syntactically valid lease that no claim ever handed out. Used where the
#: test needs to prove the *ownership* rule rather than the token rule.
_FOREIGN_LEASE = "foreign-lease-token-0000"


def _bogus_token(name: str | None = None) -> dict[str, str]:
    """Headers no connector may authenticate with (never-issued token)."""
    headers = {"X-Connector-Token": "never-issued-token"}
    if name is not None:
        headers["X-Connector-Name"] = name
    return headers


def _well_shaped_but_unknown_token(name: str) -> dict[str, str]:
    """A token in the core's own format that was simply never issued.

    This is the shape an operator actually hits: a credential copy-pasted into
    the wrong variable, or one left over from a database that was recreated.
    The label inside it is what the rejection diagnostic may report.
    """
    return {"X-Connector-Token": f"opendrp_{name}_{'z' * 43}", "X-Connector-Name": name}


async def _register_and_enqueue(
    db,
    *,
    name: str,
    connector_type: str,
    job_type: str,
) -> tuple[Connector, Job]:
    svc = ConnectorService(db)
    conn = await svc.register(
        name=name,
        connector_type=connector_type,
        api_version="1.0",
        default_job_type=job_type,
    )
    await db.commit()
    job = (
        await svc.enqueue_module_scan(
            connector_type=connector_type,
            created_by=None,
            title="Scan",
            params={"trigger": "manual"},
        )
    )[0]
    return conn, job


# ---------------------------------------------------------------------------
# Connector-side authentication
# ---------------------------------------------------------------------------


class TestConnectorAuth:
    @pytest.mark.asyncio
    async def test_register_requires_valid_token(self, client):
        payload = {
            "name": "hibp",
            "connector_type": "breaches",
            "api_version": "1.0",
            "default_job_type": "breaches.hibp",
        }
        # Missing token -> 401.
        resp = await client.post("/api/v1/connectors/register", json=payload)
        assert resp.status_code == 401
        # Wrong token -> 401.
        resp = await client.post(
            "/api/v1/connectors/register",
            headers={"X-Connector-Token": "wrong-token"},
            json=payload,
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_work_requires_valid_token(self, client, db_session):
        await ConnectorService(db_session).register(
            name="hibp", connector_type="breaches", default_job_type="breaches.hibp"
        )
        resp = await client.get(
            "/api/v1/connectors/me/work",
            headers={"X-Connector-Name": "hibp", "X-Connector-Token": "nope"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# A refused credential names itself in the platform's log
# ---------------------------------------------------------------------------


class TestRejectedCredentialDiagnosis:
    """The platform side of "my key stopped working".

    A stale credential used to leave the core answering a bare 401 while the
    connector retried it forever: the only explanation lived in the connector's
    own output, which a restart loop scrolls away, and the registry showed the
    connector as merely unseen. These tests pin the line that now says what was
    refused, without pretending the label it reads is an identity.
    """

    @pytest.fixture(autouse=True)
    def _fresh_throttle_window(self):
        """The throttle is process-wide state, so each test opens a new window."""
        connectors_router._rejection_log_seen.clear()
        yield
        connectors_router._rejection_log_seen.clear()

    @pytest.mark.asyncio
    async def test_a_never_issued_token_is_reported_with_its_own_label(self, client):
        with patch.object(connectors_router, "log") as fake_log:
            resp = await client.get(
                "/api/v1/connectors/me/work",
                headers=_well_shaped_but_unknown_token("shodan"),
            )
        assert resp.status_code == 401
        fake_log.warning.assert_called_once()
        event, fields = fake_log.warning.call_args[0][0], fake_log.warning.call_args[1]
        assert event == "connector_credential_rejected"
        assert fields["connector_name_hint"] == "shodan"
        assert fields["path"] == "/api/v1/connectors/me/work"
        assert "ip_address" in fields

    @pytest.mark.asyncio
    async def test_the_label_is_reported_but_never_authority(self, client, db_session):
        """A token cannot borrow a provisioned connector's name by *saying* it.

        Naming ``hibp`` in the header — a connector that does exist — neither
        authenticates the caller nor hides that a ``shodan``-labelled credential
        was the one refused.
        """
        await _auth(db_session, "hibp", "breaches")
        with patch.object(connectors_router, "log") as fake_log:
            resp = await client.get(
                "/api/v1/connectors/me/work",
                headers=_well_shaped_but_unknown_token("shodan") | {"X-Connector-Name": "hibp"},
            )
        assert resp.status_code == 401
        assert fake_log.warning.call_args[1]["connector_name_hint"] == "shodan"

    @pytest.mark.asyncio
    async def test_an_unlabelled_credential_is_still_reported(self, client):
        """A value pasted from somewhere else must not be swallowed silently."""
        with patch.object(connectors_router, "log") as fake_log:
            resp = await client.get(
                "/api/v1/connectors/me/work", headers={"X-Connector-Token": "wrong-token"}
            )
        assert resp.status_code == 401
        assert fake_log.warning.call_args[1]["connector_name_hint"] == "unlabelled"

    @pytest.mark.asyncio
    async def test_a_polling_connector_does_not_flood_the_log(self, client):
        """Connectors poll every few seconds; one line per situation is enough."""
        headers = _well_shaped_but_unknown_token("shodan")
        with patch.object(connectors_router, "log") as fake_log:
            for _ in range(5):
                resp = await client.get("/api/v1/connectors/me/work", headers=headers)
                assert resp.status_code == 401
        assert fake_log.warning.call_count == 1

    @pytest.mark.asyncio
    async def test_one_connectors_rejection_does_not_hide_anothers(self, client):
        with patch.object(connectors_router, "log") as fake_log:
            for name in ("shodan", "hibp"):
                await client.get(
                    "/api/v1/connectors/me/work",
                    headers=_well_shaped_but_unknown_token(name),
                )
        assert [call[1]["connector_name_hint"] for call in fake_log.warning.call_args_list] == [
            "shodan",
            "hibp",
        ]

    @pytest.mark.asyncio
    async def test_an_accepted_credential_writes_nothing(self, client, db_session):
        """The diagnostic is a warning: the happy path must stay quiet."""
        with patch.object(connectors_router, "log") as fake_log:
            resp = await client.get(
                "/api/v1/connectors/me/work",
                headers=await _auth(db_session, "hibp", "breaches"),
            )
        assert resp.status_code == 204
        fake_log.warning.assert_not_called()


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestRegister:
    @pytest.mark.asyncio
    async def test_register_declares_the_connectors_own_manifest(self, client, db_session):
        headers = await _auth(db_session, "my-shodan", "phishing")
        resp = await client.post(
            "/api/v1/connectors/register",
            headers=headers,
            json={
                "name": "My Shodan!",
                "connector_type": "phishing",
                "api_version": "1.2",
                "default_job_type": "phishing.shodan",
                "info": {"python": "3.12", "evil": "x"},
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["name"] == "my-shodan"
        assert body["connector_type"] == "phishing"
        assert body["status"] == "enabled"
        assert body["api_version"] == "1.2"
        # Only allowlisted info keys survive (same rule as the service).
        assert body["info"] == {"python": "3.12"}

    @pytest.mark.asyncio
    async def test_register_upserts_same_name(self, client, db_session):
        payload = {
            "name": "hibp",
            "connector_type": "breaches",
            "api_version": "1.0",
            "default_job_type": "breaches.hibp",
        }
        headers = await _auth(db_session, "hibp", "breaches")
        first = await client.post("/api/v1/connectors/register", headers=headers, json=payload)
        second = await client.post("/api/v1/connectors/register", headers=headers, json=payload)
        assert first.status_code == 200 and second.status_code == 200
        assert first.json()["id"] == second.json()["id"]
        rows = await ConnectorService(db_session).list_connectors()
        assert len([c for c in rows if c.name == "hibp"]) == 1

    @pytest.mark.asyncio
    async def test_register_invalid_type_400(self, client, db_session):
        """An unknown module is still refused with the connector's own token."""
        headers = await _auth(db_session, "voip", "phishing")
        resp = await client.post(
            "/api/v1/connectors/register",
            headers=headers,
            json={
                "name": "voip",
                "connector_type": "voip",
                "api_version": "1.0",
                "default_job_type": "voip.calls",
            },
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_register_cannot_create_another_connectors_row(self, client, db_session):
        """A valid credential must not be reusable as a different connector.

        Registration upserts by name, so without an explicit check a token for
        one connector could create (or rewrite) a sibling's registry row and
        then poll that sibling's queue.
        """
        headers = await _auth(db_session, "hibp", "breaches")
        resp = await client.post(
            "/api/v1/connectors/register",
            headers=headers,
            json={
                "name": "shodan",
                "connector_type": "phishing",
                "api_version": "1.0",
                "default_job_type": "phishing.shodan",
            },
        )
        assert resp.status_code == 403
        assert await ConnectorService(db_session).get_by_name("shodan") is None

    @pytest.mark.asyncio
    async def test_unprovisioned_connector_cannot_register(self, client, db_session):
        """Nothing is created implicitly: a row is provisioned together with a token."""
        resp = await client.post(
            "/api/v1/connectors/register",
            headers=_bogus_token("brand-new"),
            json={
                "name": "brand-new",
                "connector_type": "phishing",
                "api_version": "1.0",
                "default_job_type": "phishing.brand-new",
            },
        )
        assert resp.status_code == 401
        assert await ConnectorService(db_session).get_by_name("brand-new") is None


# ---------------------------------------------------------------------------
# Work claiming
# ---------------------------------------------------------------------------


class TestWork:
    @pytest.mark.asyncio
    async def test_work_empty_queue_returns_204(self, client, db_session):
        await ConnectorService(db_session).register(
            name="hibp", connector_type="breaches", default_job_type="breaches.hibp"
        )
        resp = await client.get("/api/v1/connectors/me/work", headers=await _auth(db_session, "hibp", "breaches"))
        assert resp.status_code == 204

    @pytest.mark.asyncio
    async def test_work_claims_pending_job_and_marks_running(self, client, db_session):
        _, job = await _register_and_enqueue(
            db_session, name="hibp", connector_type="breaches", job_type="breaches.hibp"
        )
        resp = await client.get("/api/v1/connectors/me/work", headers=await _auth(db_session, "hibp", "breaches"))
        assert resp.status_code == 200
        body = resp.json()
        assert body["job_id"] == str(job.id)
        assert body["job_type"] == "breaches.hibp"
        assert body["connector"] == "hibp"
        assert body["config"] == {}
        assert body["params"] is not None
        assert body["params"]["trigger"] == "manual"
        # The claim hands out the lease every later call has to prove.
        assert body["lease_token"] and len(body["lease_token"]) >= 16

        # HTTP handlers run in their own session (separate from the test
        # session), so refresh the identity-mapped object before asserting.
        fresh = await db_session.get(Job, job.id)
        await db_session.refresh(fresh)
        assert fresh.status == "running"
        assert fresh.claimed_by_connector == "hibp"

        # Queue is drained: second poll is a 204.
        resp2 = await client.get("/api/v1/connectors/me/work", headers=await _auth(db_session, "hibp", "breaches"))
        assert resp2.status_code == 204

    @pytest.mark.asyncio
    async def test_name_header_may_not_disagree_with_the_credential(self, client, db_session):
        """The name header is advisory: it can never redirect work."""
        headers = await _auth(db_session, "hibp", "breaches")
        await ConnectorService(db_session).register(
            name="dnstwist", connector_type="phishing", default_job_type="phishing.dnstwist"
        )

        # The header is optional — identity already comes from the token.
        ok = await client.get("/api/v1/connectors/me/work", headers=headers)
        assert ok.status_code == 204

        # Claiming to be a sibling connector is refused outright.
        spoofed = {**headers, "X-Connector-Name": "dnstwist"}
        resp = await client.get("/api/v1/connectors/me/work", headers=spoofed)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_work_without_any_credential_401(self, client):
        assert (await client.get("/api/v1/connectors/me/work")).status_code == 401

    @pytest.mark.asyncio
    async def test_work_unregistered_connector_401(self, client):
        resp = await client.get("/api/v1/connectors/me/work", headers=_bogus_token("ghost"))
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_work_disabled_connector_gets_none(self, client, db_session, auth_headers_admin):
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

        resp = await client.patch(
            f"/api/v1/connectors/{conn.id}/status",
            headers=auth_headers_admin,
            json={"status": "disabled"},
        )
        assert resp.status_code == 200

        work = await client.get("/api/v1/connectors/me/work", headers=await _auth(db_session, "dnstwist", "phishing"))
        assert work.status_code == 204

        # Re-enable: the pending job becomes claimable again.
        await client.patch(
            f"/api/v1/connectors/{conn.id}/status",
            headers=auth_headers_admin,
            json={"status": "enabled"},
        )
        work2 = await client.get("/api/v1/connectors/me/work", headers=await _auth(db_session, "dnstwist", "phishing"))
        assert work2.status_code == 200


# ---------------------------------------------------------------------------
# Findings ingestion
# ---------------------------------------------------------------------------


class TestTargetedScanContract:
    @pytest.mark.asyncio
    async def test_email_scan_creates_connector_job_without_provider_http(self, client, db_session, auth_headers_analyst):
        await ConnectorService(db_session).register(
            name="hibp",
            connector_type="breaches",
            api_version="1.0",
            default_job_type="breaches.hibp",
        )

        response = await client.post(
            "/api/v1/breaches/scan-email",
            headers=auth_headers_analyst,
            json={"email": "target@example.com"},
        )
        assert response.status_code == 202
        assert response.json()["status"] == "scheduled"
        assert response.json()["job_ids"]
        work = await client.get("/api/v1/connectors/me/work", headers=await _auth(db_session, "hibp", "breaches"))
        assert work.status_code == 200
        assert work.json()["params"]["emails"] == ["target@example.com"]
        assert work.json()["params"]["domains"] == []

    @pytest.mark.asyncio
    async def test_domain_scan_creates_connector_job_with_only_domain(self, client, db_session, auth_headers_analyst):
        await ConnectorService(db_session).register(
            name="hibp",
            connector_type="breaches",
            api_version="1.0",
            default_job_type="breaches.hibp",
        )

        response = await client.post(
            "/api/v1/breaches/scan-domain",
            headers=auth_headers_analyst,
            json={"domain": "example.com"},
        )
        assert response.status_code == 202
        assert response.json()["status"] == "scheduled"

        work = await client.get("/api/v1/connectors/me/work", headers=await _auth(db_session, "hibp", "breaches"))
        assert work.status_code == 200
        assert work.json()["params"]["emails"] == []
        assert work.json()["params"]["domains"] == ["example.com"]


class TestFindings:
    @pytest.mark.asyncio
    async def test_findings_ingest_phishing_batch_and_dedup(self, client, db_session):
        _, job = await _register_and_enqueue(
            db_session, name="dnstwist", connector_type="phishing", job_type="phishing.dnstwist"
        )
        work = await client.get(
            "/api/v1/connectors/me/work", headers=await _auth(db_session, "dnstwist", "phishing")
        )
        lease = work.json()["lease_token"]

        domain = f"evil-{uuid.uuid4().hex[:8]}.com"
        with patch(
            "app.services.ingestion_service.AlertDeliveryService.enqueue",
            new_callable=AsyncMock,
        ), patch(
            "app.services.phishing.whois_service.WhoisService.enrich",
            new_callable=AsyncMock,
        ):
            resp = await client.post(
                f"/api/v1/connectors/me/findings/{job.id}",
                headers={
                    **(await _auth(db_session, "dnstwist", "phishing")),
                    "X-Connector-Lease": lease,
                },
                json=[
                    {
                        "phishing_domain": domain,
                        "matched_asset": "example.com",
                        "ip_address": "1.2.3.4",
                    }
                ],
            )
        assert resp.status_code == 200
        assert resp.json() == {"accepted": 1, "rejected": 0}

        row = (
            await db_session.execute(
                select(PhishingDomain).where(PhishingDomain.phishing_domain == domain)
            )
        ).scalar_one_or_none()
        assert row is not None
        assert row.detection_source == "dnstwist"

        # Duplicate domain is silently rejected through the same endpoint.
        with patch(
            "app.services.ingestion_service.AlertDeliveryService.enqueue",
            new_callable=AsyncMock,
        ), patch(
            "app.services.phishing.whois_service.WhoisService.enrich",
            new_callable=AsyncMock,
        ):
            resp2 = await client.post(
                f"/api/v1/connectors/me/findings/{job.id}",
                headers={
                    **(await _auth(db_session, "dnstwist", "phishing")),
                    "X-Connector-Lease": lease,
                },
                json=[{"phishing_domain": domain, "matched_asset": "example.com"}],
            )
        assert resp2.json() == {"accepted": 0, "rejected": 1}

    @pytest.mark.asyncio
    async def test_findings_ingest_breach_batch(self, client, db_session):
        _, job = await _register_and_enqueue(
            db_session, name="hibp", connector_type="breaches", job_type="breaches.hibp"
        )
        work = await client.get(
            "/api/v1/connectors/me/work", headers=await _auth(db_session, "hibp", "breaches")
        )
        lease = work.json()["lease_token"]

        suffix = uuid.uuid4().hex[:6]
        with patch(
            "app.services.ingestion_service.AlertDeliveryService.enqueue",
            new_callable=AsyncMock,
        ):
            resp = await client.post(
                f"/api/v1/connectors/me/findings/{job.id}",
                headers={
                    **(await _auth(db_session, "hibp", "breaches")),
                    "X-Connector-Lease": lease,
                },
                json=[
                    {
                        "breach_name": f"TestBreach-{suffix}",
                        "matched_email": f"user-{suffix}@example.com",
                        "pwn_count": 5,
                        "data_classes": ["Emails"],
                    },
                    {"breach_name": f"NoMatch-{suffix}"},  # no matched email/domain
                ],
            )
        assert resp.status_code == 200
        assert resp.json() == {"accepted": 1, "rejected": 1}

        row = (
            await db_session.execute(
                select(Breach).where(Breach.breach_name == f"TestBreach-{suffix}")
            )
        ).scalar_one_or_none()
        assert row is not None
        assert row.matched_email == f"user-{suffix}@example.com"

    @pytest.mark.asyncio
    async def test_findings_unclaimed_job_403(self, client, db_session):
        _, job = await _register_and_enqueue(
            db_session, name="dnstwist", connector_type="phishing", job_type="phishing.dnstwist"
        )
        await ConnectorService(db_session).register(
            name="shodan", connector_type="phishing", default_job_type="phishing.shodan"
        )
        assert (
            await client.get(
                "/api/v1/connectors/me/work",
                headers=await _auth(db_session, "dnstwist", "phishing"),
            )
        ).status_code == 200

        # A sibling's job is refused on ownership, before the lease is even
        # compared — so a guessed token cannot help it either.
        resp = await client.post(
            f"/api/v1/connectors/me/findings/{job.id}",
            headers={
                **(await _auth(db_session, "shodan", "phishing")),
                "X-Connector-Lease": _FOREIGN_LEASE,
            },
            json=[{"phishing_domain": "evil.example"}],
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Completion / failure
# ---------------------------------------------------------------------------


class TestComplete:
    @pytest.mark.asyncio
    async def test_complete_success_marks_job_success(self, client, db_session):
        _, job = await _register_and_enqueue(
            db_session, name="hibp", connector_type="breaches", job_type="breaches.hibp"
        )
        work = await client.get(
            "/api/v1/connectors/me/work", headers=await _auth(db_session, "hibp", "breaches")
        )

        resp = await client.post(
            f"/api/v1/connectors/me/complete/{job.id}",
            headers=await _auth(db_session, "hibp", "breaches"),
            json={
                "ok": True,
                "summary": {"new_breach_rows": 3},
                "lease_token": work.json()["lease_token"],
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "success"

        fresh = await db_session.get(Job, job.id)
        await db_session.refresh(fresh)
        assert fresh.status == "success"
        assert fresh.result_summary == {"new_breach_rows": 3}
        assert fresh.finished_at is not None

    @pytest.mark.asyncio
    async def test_complete_failure_marks_job_error(self, client, db_session):
        _, job = await _register_and_enqueue(
            db_session, name="hibp", connector_type="breaches", job_type="breaches.hibp"
        )
        work = await client.get(
            "/api/v1/connectors/me/work", headers=await _auth(db_session, "hibp", "breaches")
        )

        resp = await client.post(
            f"/api/v1/connectors/me/complete/{job.id}",
            headers=await _auth(db_session, "hibp", "breaches"),
            json={
                "ok": False,
                "error": "boom",
                "lease_token": work.json()["lease_token"],
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "error"

        fresh = await db_session.get(Job, job.id)
        await db_session.refresh(fresh)
        assert fresh.status == "error"
        assert fresh.error_message == "boom"
        conn = await ConnectorService(db_session).get_by_name("hibp")
        assert conn is not None
        await db_session.refresh(conn)
        assert conn.last_error == "boom"

    @pytest.mark.asyncio
    async def test_complete_foreign_job_403(self, client, db_session):
        _, job = await _register_and_enqueue(
            db_session, name="dnstwist", connector_type="phishing", job_type="phishing.dnstwist"
        )
        await ConnectorService(db_session).register(
            name="shodan", connector_type="phishing", default_job_type="phishing.shodan"
        )
        await client.get(
            "/api/v1/connectors/me/work", headers=await _auth(db_session, "dnstwist", "phishing")
        )

        resp = await client.post(
            f"/api/v1/connectors/me/complete/{job.id}",
            headers=await _auth(db_session, "shodan", "phishing"),
            json={"ok": True, "summary": {}, "lease_token": _FOREIGN_LEASE},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_complete_without_a_lease_is_rejected(self, client, db_session):
        """The lease is what proves the claim is still the current one."""
        _, job = await _register_and_enqueue(
            db_session, name="hibp", connector_type="breaches", job_type="breaches.hibp"
        )
        await client.get(
            "/api/v1/connectors/me/work", headers=await _auth(db_session, "hibp", "breaches")
        )

        resp = await client.post(
            f"/api/v1/connectors/me/complete/{job.id}",
            headers=await _auth(db_session, "hibp", "breaches"),
            json={"ok": True, "summary": {}},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_complete_with_a_stale_lease_is_refused(self, client, db_session):
        """A worker whose lease was reclaimed must not finalize the job."""
        _, job = await _register_and_enqueue(
            db_session, name="hibp", connector_type="breaches", job_type="breaches.hibp"
        )
        await client.get(
            "/api/v1/connectors/me/work", headers=await _auth(db_session, "hibp", "breaches")
        )

        resp = await client.post(
            f"/api/v1/connectors/me/complete/{job.id}",
            headers=await _auth(db_session, "hibp", "breaches"),
            json={"ok": True, "summary": {}, "lease_token": _FOREIGN_LEASE},
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------


class TestHeartbeat:
    @pytest.mark.asyncio
    async def test_heartbeat_updates_last_seen(self, client, db_session):
        conn = await ConnectorService(db_session).register(
            name="hibp",
            connector_type="breaches",
            api_version="1.0",
            default_job_type="breaches.hibp",
        )
        # register() touches last_seen_at; capture it as the baseline.
        before = conn.last_seen_at
        assert before is not None

        resp = await client.post(
            "/api/v1/connectors/me/heartbeat", headers=await _auth(db_session, "hibp", "breaches"), json={}
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

        fresh = await db_session.get(Connector, conn.id)
        await db_session.refresh(fresh)
        assert fresh.last_seen_at is not None
        assert fresh.last_seen_at >= before


# ---------------------------------------------------------------------------
# Admin-side endpoints (RBAC)
# ---------------------------------------------------------------------------


class TestAdminEndpoints:
    @pytest.mark.asyncio
    async def test_list_connectors_admin_200_viewer_403(
        self, client, db_session, auth_headers_admin, auth_headers_viewer
    ):
        await ConnectorService(db_session).register(
            name="hibp", connector_type="breaches", default_job_type="breaches.hibp"
        )
        resp_viewer = await client.get("/api/v1/connectors", headers=auth_headers_viewer)
        assert resp_viewer.status_code == 403

        resp = await client.get("/api/v1/connectors", headers=auth_headers_admin)
        assert resp.status_code == 200
        names = [c["name"] for c in resp.json()]
        assert "hibp" in names

    @pytest.mark.asyncio
    async def test_patch_config_validated_against_declared_schema(
        self, client, db_session, auth_headers_admin
    ):
        # The connector declares its own settings; the core holds no per-vendor
        # config model, so this test uses a name the core has never heard of.
        conn = await ConnectorService(db_session).register(
            name="lookalike",
            connector_type="phishing",
            api_version="1.0",
            default_job_type="phishing.lookalike",
            config_schema={
                "scan_certificates": {"type": "bool", "default": True},
                "scan_titles": {"type": "bool", "default": True},
            },
        )
        resp = await client.patch(
            f"/api/v1/connectors/{conn.id}/config",
            headers=auth_headers_admin,
            json={"scan_certificates": False},
        )
        assert resp.status_code == 200
        # Declared defaults are materialized; undeclared keys are dropped.
        assert resp.json()["config"] == {"scan_certificates": False, "scan_titles": True}

        fresh = await db_session.get(Connector, conn.id)
        await db_session.refresh(fresh)
        assert fresh.config["scan_certificates"] is False

    @pytest.mark.asyncio
    async def test_patch_config_rejects_wrong_type(
        self, client, db_session, auth_headers_admin
    ):
        conn = await ConnectorService(db_session).register(
            name="lookalike",
            connector_type="phishing",
            default_job_type="phishing.lookalike",
            config_schema={"scan_certificates": {"type": "bool", "default": True}},
        )
        resp = await client.patch(
            f"/api/v1/connectors/{conn.id}/config",
            headers=auth_headers_admin,
            json={"scan_certificates": "yes-please"},
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_list_modules_exposes_declared_job_types(
        self, client, db_session, auth_headers_viewer
    ):
        await ConnectorService(db_session).register(
            name="lookalike",
            connector_type="phishing",
            default_job_type="phishing.lookalike",
            asset_types=["domain"],
        )
        resp = await client.get("/api/v1/connectors/modules", headers=auth_headers_viewer)
        assert resp.status_code == 200
        phishing = resp.json()["modules"]["phishing"]
        assert "phishing.lookalike" in phishing["job_types"]
        assert phishing["connectors"][0]["asset_types"] == ["domain"]

    @pytest.mark.asyncio
    async def test_patch_config_requires_admin(self, client, db_session, auth_headers_analyst):
        conn = await ConnectorService(db_session).register(
            name="shodan",
            connector_type="phishing",
            api_version="1.0",
            default_job_type="phishing.shodan",
        )
        resp = await client.patch(
            f"/api/v1/connectors/{conn.id}/config",
            headers=auth_headers_analyst,
            json={"scan_ssl_text": False},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_patch_status_requires_admin(self, client, db_session, auth_headers_viewer):
        conn = await ConnectorService(db_session).register(
            name="shodan",
            connector_type="phishing",
            api_version="1.0",
            default_job_type="phishing.shodan",
        )
        resp = await client.patch(
            f"/api/v1/connectors/{conn.id}/status",
            headers=auth_headers_viewer,
            json={"status": "disabled"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_connector_jobs_lists_only_declared_job_types(
        self, client, db_session, auth_headers_admin, auth_headers_viewer
    ):
        svc = ConnectorService(db_session)
        await svc.register(
            name="custom",
            connector_type="phishing",
            api_version="1.0",
            default_job_type="phishing.custom",
        )
        await JobService(db_session).create_job(
            job_type="phishing.custom", created_by=None, title="declared", params={}
        )
        # Core-owned work is not connector work, so it stays out of this list.
        await JobService(db_session).create_job(
            job_type="report.generate", created_by=None, title="core-owned", params={}
        )
        await db_session.commit()

        resp = await client.get("/api/v1/connectors/jobs", headers=auth_headers_admin)
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        assert body["items"][0]["title"] == "declared"

        # Non-admin is forbidden.
        resp2 = await client.get("/api/v1/connectors/jobs", headers=auth_headers_viewer)
        assert resp2.status_code == 403