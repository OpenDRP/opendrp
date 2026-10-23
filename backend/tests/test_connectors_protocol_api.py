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
from datetime import date
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select

from app.api import deps as api_deps
from app.api.v1.routers import connectors as connectors_router
from app.core.rate_limit import RateLimiter
from app.models import Breach, Connector, Job, PhishingDomain, SourceAccount
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
    async def test_readiness_accepts_safe_provider_error_and_preserves_until_success(self, client, db_session):
        conn = await ConnectorService(db_session).register(
            name="netlas", connector_type="exposure", default_job_type="exposure.netlas"
        )
        headers = await _auth(db_session, "netlas", "exposure")
        readiness_url = "/api/v1/connectors/me/readiness"
        base = {"credentials_configured": True, "credential_state": "unknown", "capabilities": ["ip"]}

        blocked = await client.post(readiness_url, headers=headers, json={**base, "provider_error": "ip_restricted"})
        assert blocked.status_code == 200
        await db_session.refresh(conn)
        invalid = await client.post(readiness_url, headers=headers, json={**base, "provider_error": "token=secret"})
        assert invalid.status_code == 422
        assert conn.readiness["provider_error"] == "ip_restricted"

        # An ordinary heartbeat must not erase a failure; a success state does.
        await client.post(readiness_url, headers=headers, json=base)
        await db_session.refresh(conn)
        assert conn.readiness["provider_error"] == "ip_restricted"
        await client.post(readiness_url, headers=headers, json={**base, "credential_state": "valid"})
        await db_session.refresh(conn)
        assert conn.readiness["provider_error"] is None

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

        # Re-enabling never resurrects cancelled work.
        await client.patch(
            f"/api/v1/connectors/{conn.id}/status",
            headers=auth_headers_admin,
            json={"status": "enabled"},
        )
        work2 = await client.get("/api/v1/connectors/me/work", headers=await _auth(db_session, "dnstwist", "phishing"))
        assert work2.status_code == 204
        from sqlalchemy import select
        from app.models import Job
        cancelled = (await db_session.execute(select(Job).where(Job.job_type == "phishing.dnstwist"))).scalar_one()
        assert cancelled.status == "cancelled" and cancelled.finished_at is not None
        await svc.enqueue_module_scan(connector_type="phishing", created_by=None, title="New scan")
        fresh = await client.get("/api/v1/connectors/me/work", headers=await _auth(db_session, "dnstwist", "phishing"))
        assert fresh.status_code == 200
        assert fresh.json()["job_id"] != str(cancelled.id)


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
            "app.services.ingestion_events.AlertDeliveryService.enqueue",
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
        assert resp.json() == {"received": 1, "created": 1, "updated": 0, "unchanged": 0, "accepted": 1, "rejected": 0, "errors": []}

        row = (
            await db_session.execute(
                select(PhishingDomain).where(PhishingDomain.phishing_domain == domain)
            )
        ).scalar_one_or_none()
        assert row is not None
        assert row.detection_source == "dnstwist"

        # Changed evidence refreshes the existing candidate without rejection.
        with patch(
            "app.services.ingestion_events.AlertDeliveryService.enqueue",
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
        assert resp2.json() == {"received": 1, "created": 0, "updated": 1, "unchanged": 0, "accepted": 1, "rejected": 0, "errors": []}

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
            "app.services.ingestion_events.AlertDeliveryService.enqueue",
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
                        # A date is part of the contract now: a finding with none is
                        # refused rather than stored with a made-up one, and the only
                        # row without a date is one whose reporter says its metadata
                        # did not arrive (F-02).
                        "breach_date": "2020-01-02",
                        "pwn_count": 5,
                        "data_classes": ["Emails"],
                    },
                    {"breach_name": f"NoMatch-{suffix}"},  # no matched email/domain
                ],
            )
        assert resp.status_code == 200
        assert resp.json() == {"received": 2, "created": 1, "updated": 0, "unchanged": 0, "accepted": 1, "rejected": 1, "errors": [{"index": 1, "code": "invalid_observation", "retryable": False}]}

        row = (
            await db_session.execute(
                select(Breach).where(Breach.breach_name == f"TestBreach-{suffix}")
            )
        ).scalar_one_or_none()
        assert row is not None
        assert row.matched_email == f"user-{suffix}@example.com"
        assert row.breach_date == date(2020, 1, 2)

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
        body = resp.json()
        # The map is keyed by module id because modules are data; the envelope is
        # the only key, and every entry carries the same nine, registry row or not.
        assert set(body) == {"modules"}
        phishing = body["modules"]["phishing"]
        assert set(phishing) == {
            "label",
            "description",
            "job_types",
            "connectors",
            "finding_kind",
            "asset_types",
            "storage",
            "builtin",
            "enabled",
        }
        assert "phishing.lookalike" in phishing["job_types"]
        assert phishing["connectors"][0]["asset_types"] == ["domain"]
        assert set(phishing["connectors"][0]) == {
            "name",
            "status",
            "job_type",
            "asset_types",
            "config_schema",
        }
        # A connector whose type no registry row declares is named after its type,
        # with an empty description: the metadata keys are present, never null.
        assert isinstance(phishing["label"], str) and isinstance(
            phishing["description"], str
        )
        assert phishing["connectors"][0]["status"] in {"enabled", "disabled"}

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


class TestScanAudit:
    """The audit rows a scan writes: who, how much, and bounded by the core."""

    @pytest.mark.asyncio
    async def test_completion_carries_the_connector_address(self, client, db_session):
        """`internal:connector` made the last row of a scan uncorrelatable.

        The batch rows always wrote the real address; the completion row wrote a
        placeholder, so the one event that says a scan ended could not be joined
        to the deliveries that belong to it by anything but the job id.
        """
        from app.models import AuditLog

        _, job = await _register_and_enqueue(
            db_session, name="hibp", connector_type="breaches", job_type="breaches.hibp"
        )
        work = await client.get(
            "/api/v1/connectors/me/work", headers=await _auth(db_session, "hibp", "breaches")
        )

        resp = await client.post(
            f"/api/v1/connectors/me/complete/{job.id}",
            headers=await _auth(db_session, "hibp", "breaches"),
            json={"ok": True, "summary": {"new_breach_rows": 3}, "lease_token": work.json()["lease_token"]},
        )
        assert resp.status_code == 200

        row = (
            await db_session.execute(
                select(AuditLog)
                .where(AuditLog.action == "connector.scan.completed")
                .order_by(AuditLog.timestamp.desc())
            )
        ).scalars().first()
        assert row is not None
        assert row.ip_address not in {None, "internal:connector"}
        assert row.details["summary"]["new_breach_rows"] == 3

    @pytest.mark.asyncio
    async def test_a_connector_summary_is_bounded_before_it_is_stored(
        self, client, db_session
    ):
        """Strings, lists and nesting are the core's to bound, not the worker's.

        The wire schema capped how many keys a summary may carry and nothing else,
        so a connector could put an arbitrarily long string into the job record and
        the immutable audit chain behind it.
        """
        from app.models import AuditLog

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
                "summary": {
                    "note": "x" * 1000,
                    "items": list(range(30)),
                    "nested": {"a": {"b": {"c": {"d": {"e": "deep"}}}}},
                },
                "lease_token": work.json()["lease_token"],
            },
        )
        assert resp.status_code == 200

        fresh = await db_session.get(Job, job.id)
        await db_session.refresh(fresh)
        assert len(fresh.result_summary["note"]) == 200
        assert len(fresh.result_summary["items"]) == 20
        assert fresh.result_summary["nested"] == "…" or "e" not in str(
            fresh.result_summary["nested"]
        )

        row = (
            await db_session.execute(
                select(AuditLog)
                .where(AuditLog.action == "connector.scan.completed")
                .order_by(AuditLog.timestamp.desc())
            )
        ).scalars().first()
        assert row is not None
        assert len(row.details["summary"]["note"]) == 200
        assert len(row.details["summary"]["items"]) == 20

    @pytest.mark.asyncio
    async def test_a_findings_batch_row_names_its_size(self, client, db_session):
        """Without a size, a row cannot say how much of the scan it accounts for."""
        from app.models import AuditLog

        _, job = await _register_and_enqueue(
            db_session, name="dnstwist", connector_type="phishing", job_type="phishing.dnstwist"
        )
        work = await client.get(
            "/api/v1/connectors/me/work", headers=await _auth(db_session, "dnstwist", "phishing")
        )
        domain = f"batch-{uuid.uuid4().hex[:8]}.com"

        with patch(
            "app.services.ingestion_events.AlertDeliveryService.enqueue",
            new_callable=AsyncMock,
        ):
            resp = await client.post(
                f"/api/v1/connectors/me/findings/{job.id}",
                headers={
                    **(await _auth(db_session, "dnstwist", "phishing")),
                    "X-Connector-Lease": work.json()["lease_token"],
                    "X-Connector-Batch-Index": "2",
                    "X-Connector-Batch-Total": "3",
                },
                json=[{"phishing_domain": domain, "matched_asset": "example.com"}],
            )
        assert resp.status_code == 200

        row = (
            await db_session.execute(
                select(AuditLog)
                .where(AuditLog.action == "connector.findings.ingested")
                .order_by(AuditLog.timestamp.desc())
            )
        ).scalars().first()
        assert row is not None
        assert row.details["job_id"] == str(job.id)
        assert row.details["batch_size"] == 1
        # The batch's place in the scan, so deliveries have an order and a
        # denominator instead of being indistinguishable rows.
        assert row.details["batch_index"] == 2
        assert row.details["batch_total"] == 3


# ---------------------------------------------------------------------------
# Per-address bound on the connector protocol
# ---------------------------------------------------------------------------


class _CountingPipeline:
    def __init__(self, owner: "_CountingRedis") -> None:
        self._owner = owner
        self._ops: list[tuple[str, str]] = []

    def incr(self, key: str) -> "_CountingPipeline":
        self._ops.append(("incr", key))
        return self

    def expire(self, key: str, ttl: int) -> "_CountingPipeline":
        self._ops.append(("expire", key))
        return self

    async def execute(self) -> list:
        out: list = []
        for op, key in self._ops:
            if op == "incr":
                self._owner.counts[key] = self._owner.counts.get(key, 0) + 1
                out.append(self._owner.counts[key])
            else:
                out.append(True)
        return out

    async def __aenter__(self) -> "_CountingPipeline":
        return self

    async def __aexit__(self, *_exc) -> bool:
        return False


class _CountingRedis:
    """Just enough Redis for the fixed-window limiter and the day counter."""

    def __init__(self) -> None:
        self.counts: dict[str, int | str] = {}
        self.used_today = 0

    def pipeline(self, transaction: bool = True) -> _CountingPipeline:
        return _CountingPipeline(self)

    async def set(self, key: str, value, nx: bool = False, ex: int | None = None):
        if nx and key in self.counts:
            return None
        self.counts[key] = value
        return True

    async def zcount(self, key: str, minimum: float, maximum: float) -> int:
        return self.used_today


@pytest.fixture
def fake_redis(monkeypatch):
    client = _CountingRedis()
    monkeypatch.setattr(RateLimiter, "_get_client", classmethod(lambda cls: client))
    return client


class TestConnectorProtocolRateLimit:
    @pytest.mark.asyncio
    async def test_one_address_exceeding_the_bound_gets_429(
        self, client, db_session, fake_redis, monkeypatch
    ):
        """A leaked or invented token must not buy unlimited work polls."""
        monkeypatch.setattr(api_deps, "CONNECTOR_PROTOCOL_RATE_LIMIT_PER_MINUTE", 2)
        await ConnectorService(db_session).register(
            name="hibp", connector_type="breaches", default_job_type="breaches.hibp"
        )
        headers = await _auth(db_session, "hibp", "breaches")

        for _ in range(2):
            assert (
                await client.get("/api/v1/connectors/me/control", headers=headers)
            ).status_code == 200

        blocked = await client.get("/api/v1/connectors/me/control", headers=headers)
        assert blocked.status_code == 429
        assert blocked.headers["Retry-After"]

    @pytest.mark.asyncio
    async def test_an_invented_token_is_bounded_before_the_credential_lookup(
        self, client, fake_redis, monkeypatch
    ):
        """The cheapest flood to mount still costs a database query without this."""
        monkeypatch.setattr(api_deps, "CONNECTOR_PROTOCOL_RATE_LIMIT_PER_MINUTE", 1)
        assert (
            await client.get("/api/v1/connectors/me/work", headers=_bogus_token())
        ).status_code == 401
        blocked = await client.get("/api/v1/connectors/me/work", headers=_bogus_token())
        assert blocked.status_code == 429

    @pytest.mark.asyncio
    async def test_normal_polling_is_not_throttled(self, client, db_session, fake_redis):
        """Twelve connectors polling every five seconds must fit comfortably."""
        # 12 workers / 5 s = 144 requests a minute; the bound leaves >4x that.
        assert api_deps.CONNECTOR_PROTOCOL_RATE_LIMIT_PER_MINUTE >= 144 * 4
        await ConnectorService(db_session).register(
            name="hibp", connector_type="breaches", default_job_type="breaches.hibp"
        )
        headers = await _auth(db_session, "hibp", "breaches")
        for _ in range(20):
            resp = await client.get("/api/v1/connectors/me/control", headers=headers)
            assert resp.status_code == 200, resp.text


# ---------------------------------------------------------------------------
# Remaining provider budget on the health page
# ---------------------------------------------------------------------------


class TestConnectorHealthQuota:
    async def _bound_connector(self, db_session, *, daily_budget: int = 50) -> Connector:
        # The binding is a real row, not a fabricated id: the column is a foreign
        # key, so a made-up uuid is a test that only passes where FK checks are off.
        account = SourceAccount(
            source_id="hibp",
            name="default",
            policy={"approved": True, "requests_per_minute": 10, "daily_budget": daily_budget},
        )
        db_session.add(account)
        await db_session.flush()
        conn = await ConnectorService(db_session).register(
            name="hibp", connector_type="breaches", default_job_type="breaches.hibp"
        )
        conn.provider = "hibp"
        conn.source_account_id = account.id
        conn.config = {"daily_budget": daily_budget}
        await db_session.commit()
        return conn

    @pytest.mark.asyncio
    async def test_health_reports_the_days_remainder_from_the_counter(
        self, client, db_session, auth_headers_admin, fake_redis
    ):
        conn = await self._bound_connector(db_session, daily_budget=50)
        fake_redis.used_today = 7

        resp = await client.get("/api/v1/connectors/health", headers=auth_headers_admin)
        assert resp.status_code == 200
        item = next(i for i in resp.json()["items"] if i["name"] == conn.name)
        assert item["quota_remaining"] == 43
        assert item["quota_budget"] == 50
        assert item["quota_reason"] is None

    @pytest.mark.asyncio
    async def test_an_unreadable_counter_is_null_with_a_reason(
        self, client, db_session, auth_headers_admin, monkeypatch
    ):
        """A missing number must not look like an exhausted budget."""
        await self._bound_connector(db_session)
        monkeypatch.setattr(RateLimiter, "_get_client", classmethod(lambda cls: None))

        resp = await client.get("/api/v1/connectors/health", headers=auth_headers_admin)
        assert resp.status_code == 200
        item = next(i for i in resp.json()["items"] if i["name"] == "hibp")
        assert item["quota_remaining"] is None
        assert item["quota_reason"] == "quota_backend_unavailable"

    @pytest.mark.asyncio
    async def test_a_connector_without_a_provider_account_says_so(
        self, client, db_session, auth_headers_admin, fake_redis
    ):
        await ConnectorService(db_session).register(
            name="dnstwist", connector_type="phishing", default_job_type="phishing.dnstwist"
        )

        resp = await client.get("/api/v1/connectors/health", headers=auth_headers_admin)
        item = next(i for i in resp.json()["items"] if i["name"] == "dnstwist")
        assert item["quota_remaining"] is None
        assert item["quota_reason"] == "provider_account_missing"
        # A worker that needs no provider key is not "blocked" by the core.
        assert item["blocked_reason"] is None


class TestConnectorHealthBlockedReason:
    """The core's own answer to "why can this source not scan?".

    ``readiness`` is the worker's report about its credential; when no account
    exists the worker cannot know that work will be refused, so the health page
    needs the core's decision beside it (WI-02).
    """

    @pytest.mark.asyncio
    async def test_a_provider_without_a_bound_account_names_the_reason(
        self, client, db_session, auth_headers_admin
    ):
        conn = await ConnectorService(db_session).register(
            name="hibp", connector_type="breaches", default_job_type="breaches.hibp"
        )
        conn.provider = "hibp"
        await db_session.commit()

        resp = await client.get("/api/v1/connectors/health", headers=auth_headers_admin)
        item = next(i for i in resp.json()["items"] if i["name"] == "hibp")
        assert item["blocked_reason"] == "provider_account_missing"

    @pytest.mark.asyncio
    async def test_an_account_found_by_provider_and_quota_group_counts(
        self, client, db_session, auth_headers_admin
    ):
        """Admission may bind an unbound connector to a group's account.

        The health answer must follow the same rule; otherwise it would report a
        block that the next scan does not meet.
        """
        account = SourceAccount(
            source_id="hibp", name="default", policy={"approved": True}
        )
        db_session.add(account)
        await db_session.flush()
        conn = await ConnectorService(db_session).register(
            name="hibp", connector_type="breaches", default_job_type="breaches.hibp"
        )
        conn.provider = "hibp"
        conn.quota_group = "default"
        await db_session.commit()

        resp = await client.get("/api/v1/connectors/health", headers=auth_headers_admin)
        item = next(i for i in resp.json()["items"] if i["name"] == "hibp")
        assert item["blocked_reason"] is None

    @pytest.mark.asyncio
    async def test_an_unapproved_account_and_an_approved_one(
        self, client, db_session, auth_headers_admin
    ):
        account = SourceAccount(
            source_id="hibp", name="default", policy={"approved": False}
        )
        db_session.add(account)
        await db_session.flush()
        conn = await ConnectorService(db_session).register(
            name="hibp", connector_type="breaches", default_job_type="breaches.hibp"
        )
        conn.provider = "hibp"
        conn.source_account_id = account.id
        await db_session.commit()

        resp = await client.get("/api/v1/connectors/health", headers=auth_headers_admin)
        item = next(i for i in resp.json()["items"] if i["name"] == "hibp")
        assert item["blocked_reason"] == "account_policy_unapproved"

        account.policy = {"approved": True, "daily_budget": 50}
        await db_session.commit()
        resp = await client.get("/api/v1/connectors/health", headers=auth_headers_admin)
        item = next(i for i in resp.json()["items"] if i["name"] == "hibp")
        assert item["blocked_reason"] is None

@pytest.mark.asyncio
async def test_the_health_answer_is_the_shape_the_client_declares(
    client, db_session, auth_headers_admin
):
    """The page's payload is a declaration, not a composed dict.

    Two things this asserts could be undone by a later "cleanup": the answer keeps
    all nineteen keys for every role (the admin fields as nulls, which is why the
    route does not exclude them), and `checked_at` is the worker's own text rather
    than a parsed timestamp — a `datetime` field would have normalized the offset
    the worker sent.
    """
    conn = await ConnectorService(db_session).register(
        name="hibp", connector_type="breaches", default_job_type="breaches.hibp"
    )
    conn.provider = "hibp"
    conn.readiness = {
        "credentials_configured": True,
        "credential_state": "valid",
        "checked_at": "2026-10-23T05:00:00.123456+02:00",
        "capabilities": ["email"],
    }
    await db_session.commit()

    resp = await client.get("/api/v1/connectors/health", headers=auth_headers_admin)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body) == {"items", "generated_at"}
    # `generated_at` is a timestamp the server just took, so it is a full
    # instant with a zone; the row's own heartbeat is registration time.
    assert body["generated_at"].endswith("Z") or "+" in body["generated_at"]

    item = next(i for i in body["items"] if i["name"] == "hibp")
    assert len(item) == 19
    assert item["status"] == "enabled"
    assert item["health"] == "healthy"
    assert item["credentials_configured"] is True
    assert item["credential_state"] == "valid"
    assert item["readiness"]["capabilities"] == ["email"]
    # Byte-for-byte: the worker's offset survives, which a datetime field would not.
    assert item["checked_at"] == "2026-10-23T05:00:00.123456+02:00"
