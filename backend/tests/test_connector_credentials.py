"""Per-connector credentials: issuance, resolution, rotation, revocation.

The connector protocol used to authenticate with one platform-wide secret, so
any container holding it could claim *any* connector's work and a leak could not
be contained. These tests pin the replacement guarantees:

* a credential is high-entropy and stored only as a digest;
* identity comes from the token, so naming another connector is refused;
* a refused credential names itself in the log, so an operator replacing a
  stale key learns *which* connector needs it;
* rotation and revocation are per connector and take effect immediately;
* the digest never leaves the core — the API exposes only a public prefix;
* provisioning is an admin action, and nothing is created implicitly.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.models import Connector
from app.services.connector_credentials import (
    TOKEN_PREFIX,
    TOKEN_PREFIX_LEN,
    ConnectorCredentials,
    connector_name_from_token,
    generate_token,
    hash_token,
)
from app.services.connector_service import ConnectorService


async def _provision(db, name: str, connector_type: str = "phishing") -> tuple[Connector, str]:
    """Create a connector row and issue its credential (as an operator would)."""
    conn = await ConnectorService(db).register(name=name, connector_type=connector_type)
    token, _ = await ConnectorCredentials(db).issue(conn)
    return conn, token


def _headers(token: str, name: str) -> dict[str, str]:
    return {"X-Connector-Token": token, "X-Connector-Name": name}


# ---------------------------------------------------------------------------
# Token material
# ---------------------------------------------------------------------------


class TestTokenMaterial:
    def test_token_is_prefixed_named_and_high_entropy(self):
        token = generate_token("connector-hibp")
        assert token.startswith(f"{TOKEN_PREFIX}_connector-hibp_")
        assert len(token.split("_", 2)[2]) >= 40

    def test_each_issuance_produces_a_distinct_token(self):
        assert generate_token("hibp") != generate_token("hibp")

    def test_unusual_names_still_produce_a_valid_token(self):
        # A name is cosmetic here; authority comes from the stored digest.
        token = generate_token("My Shodan! / ünïcode")
        assert token.startswith(f"{TOKEN_PREFIX}_") and " " not in token
        assert "/" not in token

    def test_digest_hides_the_plaintext_and_ignores_surrounding_whitespace(self):
        token = generate_token("hibp")
        digest = hash_token(token)
        assert digest != token
        assert len(digest) == 64
        # Connectors often pass env values with a trailing newline.
        assert hash_token(f"  {token}\n") == digest
        assert hash_token(token + "x") != digest

    def test_the_label_is_read_back_for_diagnostics_only(self):
        """The name inside a token is what a *rejected* credential reports.

        It is deliberately not an identity: this function must never be used to
        authorize anything, so the tests pin that it reads labels without
        validating them, and that a value it cannot read yields nothing rather
        than a guess.
        """
        assert connector_name_from_token(generate_token("connector-hibp")) == "connector-hibp"
        # Whitespace and case come from whatever the environment held.
        assert connector_name_from_token(f"  {generate_token('Shodan')}\n") == "shodan"
        # Never issued by this core, or not a credential at all.
        assert connector_name_from_token(f"{TOKEN_PREFIX}_ghost_{'z' * 43}") == "ghost"
        for unreadable in (None, "", "   ", "wrong-token", f"{TOKEN_PREFIX}_only", "shodan"):
            assert connector_name_from_token(unreadable) is None
        # An empty label segment is not a name either.
        assert connector_name_from_token(f"{TOKEN_PREFIX}__{'z' * 43}") is None


# ---------------------------------------------------------------------------
# Service layer
# ---------------------------------------------------------------------------


class TestCredentialService:
    @pytest.mark.asyncio
    async def test_resolve_maps_a_token_to_exactly_one_connector(self, db_session):
        conn, token = await _provision(db_session, "hibp", "breaches")
        credentials = ConnectorCredentials(db_session)
        assert (await credentials.resolve(token)).id == conn.id

    @pytest.mark.asyncio
    async def test_unknown_and_empty_tokens_resolve_to_nothing(self, db_session):
        await _provision(db_session, "hibp", "breaches")
        credentials = ConnectorCredentials(db_session)
        assert await credentials.resolve("never-issued") is None
        assert await credentials.resolve("") is None
        assert await credentials.resolve("   ") is None

    @pytest.mark.asyncio
    async def test_a_required_credential_is_created_by_issue(self, db_session):
        conn = await ConnectorService(db_session).register(name="hibp", connector_type="breaches")
        assert conn.has_token is False
        token, rotated = await ConnectorCredentials(db_session).issue(conn)
        assert rotated is False
        assert conn.has_token is True
        assert conn.token_prefix == token[:TOKEN_PREFIX_LEN]
        assert conn.token_created_at is not None
        # The prefix must stay far too short to be usable as a credential.
        assert conn.token_prefix != token

    @pytest.mark.asyncio
    async def test_rotation_invalidates_the_previous_token(self, db_session):
        conn, first = await _provision(db_session, "hibp", "breaches")
        credentials = ConnectorCredentials(db_session)
        second, rotated = await credentials.issue(conn)
        assert rotated is True and second != first
        assert await credentials.resolve(first) is None
        assert (await credentials.resolve(second)).id == conn.id

    @pytest.mark.asyncio
    async def test_revocation_keeps_the_connector_but_drops_its_credential(self, db_session):
        conn, token = await _provision(db_session, "hibp", "breaches")
        credentials = ConnectorCredentials(db_session)
        await credentials.revoke(conn)
        assert await credentials.resolve(token) is None
        assert conn.has_token is False
        assert conn.token_prefix is None
        assert conn.token_created_at is None
        # Registry row, module and history survive revocation.
        again = await ConnectorService(db_session).get_by_name("hibp")
        assert again is not None and again.connector_type == "breaches"

    @pytest.mark.asyncio
    async def test_ambiguous_digest_is_refused_rather_than_guessed(self, db_session, monkeypatch):
        """Two rows claiming one digest must not resolve to an arbitrary one."""
        rows = [
            Connector(name="a", connector_type="phishing", default_job_type="phishing.a"),
            Connector(name="b", connector_type="phishing", default_job_type="phishing.b"),
        ]

        class _FakeResult:
            def scalars(self):
                return self

            def all(self):
                return rows

        async def _fake_execute(_stmt):
            return _FakeResult()

        monkeypatch.setattr(db_session, "execute", _fake_execute)
        assert await ConnectorCredentials(db_session).resolve("shared-secret") is None

    @pytest.mark.asyncio
    async def test_last_used_is_throttled_to_one_write_per_minute(self, db_session, monkeypatch):
        conn, _token = await _provision(db_session, "hibp", "breaches")
        credentials = ConnectorCredentials(db_session)
        commits = {"n": 0}

        async def _counting_commit():
            commits["n"] += 1

        monkeypatch.setattr(db_session, "commit", _counting_commit)

        conn.token_last_used_at = datetime.now(timezone.utc)
        await credentials.touch_last_used(conn)
        assert commits["n"] == 0  # inside the throttle window

        conn.token_last_used_at = datetime.now(timezone.utc) - timedelta(minutes=5)
        await credentials.touch_last_used(conn)
        assert commits["n"] == 1  # stale timestamp is refreshed

    def test_digest_is_unique_per_connector_at_the_schema_level(self):
        """One credential identifies one connector; the DB enforces it."""
        assert Connector.__table__.c.token_hash.unique is True


# ---------------------------------------------------------------------------
# Admin API (provision / rotate / revoke)
# ---------------------------------------------------------------------------


class TestCredentialAdminApi:
    @pytest.mark.asyncio
    async def test_provision_creates_the_row_and_returns_the_token_once(
        self, client, db_session, auth_headers_admin
    ):
        resp = await client.post(
            "/api/v1/connectors/provision",
            headers=auth_headers_admin,
            json={"name": "connector-hibp", "connector_type": "breaches"},
        )
        assert resp.status_code == 200
        body = resp.json()
        token = body["token"]
        assert token.startswith(f"{TOKEN_PREFIX}_connector-hibp_")
        assert body["rotated"] is False
        assert body["connector"]["name"] == "connector-hibp"
        assert body["connector"]["has_token"] is True
        assert body["connector"]["token_prefix"] == token[:TOKEN_PREFIX_LEN]
        # The freshly issued token authenticates the connector straight away.
        poll = await client.get(
            "/api/v1/connectors/me/work", headers=_headers(token, "connector-hibp")
        )
        assert poll.status_code == 204
        db_conn = await ConnectorService(db_session).get_by_name("connector-hibp")
        assert db_conn.token_hash == hash_token(token)  # only the digest is stored

    @pytest.mark.asyncio
    async def test_provision_rejects_an_unknown_module(
        self, client, auth_headers_admin
    ):
        resp = await client.post(
            "/api/v1/connectors/provision",
            headers=auth_headers_admin,
            json={"name": "voip", "connector_type": "voip"},
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_provision_reflects_a_type_mismatch_instead_of_retyping(
        self, client, db_session, auth_headers_admin
    ):
        await _provision(db_session, "connector-hibp", "breaches")
        resp = await client.post(
            "/api/v1/connectors/provision",
            headers=auth_headers_admin,
            json={"name": "connector-hibp", "connector_type": "phishing"},
        )
        assert resp.status_code == 400
        unchanged = await ConnectorService(db_session).get_by_name("connector-hibp")
        assert unchanged.connector_type == "breaches"

    @pytest.mark.asyncio
    async def test_rotate_endpoint_replaces_the_live_token(
        self, client, db_session, auth_headers_admin
    ):
        conn, old_token = await _provision(db_session, "connector-hibp", "breaches")
        resp = await client.post(
            f"/api/v1/connectors/{conn.id}/token", headers=auth_headers_admin
        )
        assert resp.status_code == 200
        assert resp.json()["rotated"] is True
        new_token = resp.json()["token"]

        stale = await client.get(
            "/api/v1/connectors/me/work", headers=_headers(old_token, "connector-hibp")
        )
        assert stale.status_code == 401
        fresh = await client.get(
            "/api/v1/connectors/me/work", headers=_headers(new_token, "connector-hibp")
        )
        assert fresh.status_code == 204

    @pytest.mark.asyncio
    async def test_revoke_endpoint_cuts_the_connector_off(
        self, client, db_session, auth_headers_admin
    ):
        conn, token = await _provision(db_session, "connector-hibp", "breaches")
        resp = await client.delete(
            f"/api/v1/connectors/{conn.id}/token", headers=auth_headers_admin
        )
        assert resp.status_code == 200
        assert resp.json()["has_token"] is False
        assert resp.json()["token_prefix"] is None

        denied = await client.get(
            "/api/v1/connectors/me/work", headers=_headers(token, "connector-hibp")
        )
        assert denied.status_code == 401
        # Same connector, new credential: registry and history were never touched.
        assert (await ConnectorService(db_session).get_by_name("connector-hibp")) is not None

    @pytest.mark.asyncio
    async def test_token_of_one_connector_cannot_act_as_another(
        self, client, db_session
    ):
        _conn_a, token_a = await _provision(db_session, "dnstwist", "phishing")
        await _provision(db_session, "hibp", "breaches")

        # A is A, and only A: the sibling's name does not make A the sibling.
        assert (
            await client.get("/api/v1/connectors/me/work", headers=_headers(token_a, "dnstwist"))
        ).status_code == 204
        assert (
            await client.get("/api/v1/connectors/me/work", headers=_headers(token_a, "hibp"))
        ).status_code == 403
        assert (
            await client.post(
                "/api/v1/connectors/me/heartbeat",
                headers=_headers(token_a, "hibp"),
                json={},
            )
        ).status_code == 403

    @pytest.mark.asyncio
    async def test_connector_listing_never_exposes_the_digest(
        self, client, db_session, auth_headers_admin
    ):
        conn, token = await _provision(db_session, "connector-hibp", "breaches")
        resp = await client.get("/api/v1/connectors", headers=auth_headers_admin)
        assert resp.status_code == 200
        serialized = resp.json()
        blob = str(serialized)
        for entry in serialized:
            assert "token_hash" not in entry
            assert entry.get("token_prefix") != token  # prefix only, never the secret
        assert hash_token(token) not in blob
        assert token not in blob

    @pytest.mark.asyncio
    async def test_credential_management_requires_admin(
        self, client, db_session, auth_headers_analyst, auth_headers_viewer
    ):
        conn, _token = await _provision(db_session, "connector-hibp", "breaches")
        for headers in (auth_headers_analyst, auth_headers_viewer):
            assert (
                await client.post(
                    "/api/v1/connectors/provision",
                    headers=headers,
                    json={"name": "sneaky", "connector_type": "phishing"},
                )
            ).status_code == 403
            assert (
                await client.post(f"/api/v1/connectors/{conn.id}/token", headers=headers)
            ).status_code == 403
            assert (
                await client.delete(f"/api/v1/connectors/{conn.id}/token", headers=headers)
            ).status_code == 403
        assert (await ConnectorService(db_session).get_by_name("sneaky")) is None

    @pytest.mark.asyncio
    async def test_revoked_credential_is_rejected_on_every_endpoint(
        self, client, db_session
    ):
        _conn, token = await _provision(db_session, "dnstwist", "phishing")
        headers = _headers(token, "dnstwist")
        assert (await client.get("/api/v1/connectors/me/work", headers=headers)).status_code == 204

        revoked = await ConnectorCredentials(db_session).get(
            (await ConnectorService(db_session).get_by_name("dnstwist")).id
        )
        await ConnectorCredentials(db_session).revoke(revoked)

        calls = (
            ("get", "/api/v1/connectors/me/work", None),
            ("post", "/api/v1/connectors/me/heartbeat", {}),
            ("post", "/api/v1/connectors/me/complete/<id>", {"ok": True}),
            (
                "post",
                "/api/v1/connectors/register",
                {"name": "dnstwist", "connector_type": "phishing"},
            ),
            ("post", "/api/v1/connectors/me/findings/<id>", []),
        )
        for method, path, body in calls:
            url = path.replace("<id>", str(uuid.uuid4()))
            request = getattr(client, method)
            resp = await (
                request(url, headers=headers, json=body)
                if body is not None
                else request(url, headers=headers)
            )
            assert resp.status_code == 401, f"{method.upper()} {url}"
