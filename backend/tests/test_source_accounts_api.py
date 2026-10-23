from datetime import datetime, timezone
import uuid

import pytest

from app.models import Asset, AssetType, Connector, Job
from app.models.audit import AuditLog
from app.models.source_account import SourceAccount
from app.core.exceptions import BadRequestException, NotFoundException
from app.services.source_accounts import (
    api_key_for_connector,
    approve_policy,
    clear_api_key,
    provision_account,
    set_api_key,
)


class TestAccountRefusals:
    """What the account service declines, and the field it names.

    The route schemas check the shapes an operator types; these are the checks
    that belong to the service because they run against what is stored — a
    credential reference that is not an environment variable name, an account that
    no longer exists, a policy whose field the quota code would not understand.
    Each refusal names its field so an operator can fix it instead of guessing.
    """

    @pytest.mark.asyncio
    async def test_a_source_id_or_name_outside_the_grammar_is_refused(self, db_session):
        for source_id, name in (
            ("Netlas", "default"),  # capitals are not part of the grammar
            ("netlas", "Account Two"),  # nor are spaces
            ("", "default"),
            ("netlas", ""),
        ):
            with pytest.raises(BadRequestException, match="Invalid account identity"):
                await provision_account(db_session, source_id=source_id, name=name)

    @pytest.mark.asyncio
    async def test_a_credential_reference_must_be_an_environment_variable(self, db_session):
        """The reference is a name read at runtime, not a path to a secret file.

        `NETLAS_KEY` is how the deployment names it; `secrets/netlas.txt` would be
        a filesystem path stored in a column and read by something less careful.
        """
        with pytest.raises(
            BadRequestException, match="Credential reference must be an environment variable"
        ):
            await provision_account(
                db_session, source_id="netlas", name="default", credential_ref="/etc/passwd"
            )

    @pytest.mark.asyncio
    async def test_a_policy_for_an_unknown_account_is_a_404(self, db_session):
        with pytest.raises(NotFoundException, match="Source account not found"):
            await approve_policy(
                db_session,
                uuid.uuid4(),
                {"approved": True, "requests_per_minute": 10, "daily_budget": 100},
            )

    @pytest.mark.asyncio
    async def test_a_policy_field_the_quota_code_does_not_read_is_refused(self, db_session):
        """An unknown key would be stored and then silently ignored by reserve()."""
        account, _created, _updated = await provision_account(
            db_session, source_id="netlas", name="default"
        )
        with pytest.raises(BadRequestException, match="Unsupported account policy field"):
            await approve_policy(
                db_session,
                account.id,
                {"approved": True, "requests_per_minute": 10, "daily_budget": 100, "burst": 5},
            )

    @pytest.mark.asyncio
    async def test_approval_must_be_an_explicit_boolean(self, db_session):
        """`1` is truthy and would approve a provider account nobody approved."""
        account, _created, _updated = await provision_account(
            db_session, source_id="netlas", name="default"
        )
        with pytest.raises(BadRequestException, match="Explicit approved boolean required"):
            await approve_policy(
                db_session,
                account.id,
                {"approved": 1, "requests_per_minute": 10, "daily_budget": 100},
            )

    @pytest.mark.asyncio
    async def test_the_budgets_are_both_required(self, db_session):
        account, _created, _updated = await provision_account(
            db_session, source_id="netlas", name="default"
        )
        with pytest.raises(
            BadRequestException, match="Explicit minute and daily request budgets required"
        ):
            await approve_policy(db_session, account.id, {"approved": True, "daily_budget": 100})

    @pytest.mark.asyncio
    async def test_a_budget_outside_the_supported_range_is_refused(self, db_session):
        account, _created, _updated = await provision_account(
            db_session, source_id="netlas", name="default"
        )
        with pytest.raises(BadRequestException, match="requests_per_minute must be an integer 1..600"):
            await approve_policy(
                db_session,
                account.id,
                {"approved": True, "requests_per_minute": 0, "daily_budget": 100},
            )

    @pytest.mark.asyncio
    async def test_an_api_key_is_refused_when_it_could_not_be_sent(self, db_session):
        """A key with a space or a newline cannot travel in a header.

        Accepting it would store a value that fails at scan time as an authentication
        error, and the operator would debug the provider instead of the key.
        """
        account, _created, _updated = await provision_account(
            db_session, source_id="netlas", name="default"
        )
        for value in ("key with space", "key\nheader", "ключ", "", 123):
            with pytest.raises(BadRequestException, match="Invalid API key format"):
                await set_api_key(db_session, account.id, value)

        # A key that is merely odd is still a key: refusing it would reject a value
        # issued before any format rule.
        stored = await set_api_key(db_session, account.id, "a-b_c:1234")
        assert stored.api_key_hint and stored.api_key_hint.endswith("1234")
        assert stored.api_key_encrypted

        cleared = await clear_api_key(db_session, account.id)
        assert cleared.api_key_encrypted is None and cleared.api_key_hint is None

    @pytest.mark.asyncio
    async def test_an_api_key_for_an_unknown_account_is_a_404(self, db_session):
        with pytest.raises(NotFoundException, match="Source account not found"):
            await set_api_key(db_session, uuid.uuid4(), "valid-looking-key")

    @pytest.mark.asyncio
    async def test_a_connector_only_receives_the_key_of_its_own_provider(self, db_session):
        """The binding is not enough: the account's provider has to match too.

        Otherwise an operator binding a Shodan connector to a Netlas account would
        hand the Shodan worker the Netlas credential, and the provider would see a
        key that belongs to a different service.
        """
        account, _created, _updated = await provision_account(
            db_session, source_id="netlas", name="default"
        )
        await set_api_key(db_session, account.id, "netlas-key-0001")

        def _connector(**overrides):
            values = {
                "name": "netlas-exposure",
                "connector_type": "exposure",
                "default_job_type": "exposure.netlas",
                "provider": "netlas",
                "source_account_id": account.id,
            }
            values.update(overrides)
            return Connector(**values)

        assert await api_key_for_connector(db_session, _connector()) == "netlas-key-0001"
        # Unbound, wrong provider, and an account whose key was cleared: three
        # different reasons for the same answer, which is "no credential here".
        assert await api_key_for_connector(db_session, _connector(source_account_id=None)) is None
        assert await api_key_for_connector(db_session, _connector(provider="shodan")) is None
        await clear_api_key(db_session, account.id)
        assert await api_key_for_connector(db_session, _connector()) is None

        # A binding to a row that no longer exists is not an error the caller has
        # to handle mid-scan; it is simply no key.
        missing = uuid.uuid4()
        assert await api_key_for_connector(db_session, _connector(source_account_id=missing)) is None


@pytest.mark.asyncio
async def test_source_account_lifecycle_is_admin_only_and_audited(
    client, db_session, auth_headers_admin, auth_headers_analyst
):
    assert (
        await client.get("/api/v1/connectors/accounts", headers=auth_headers_analyst)
    ).status_code == 403

    created = await client.post(
        "/api/v1/connectors/accounts",
        headers=auth_headers_admin,
        json={
            "source_id": "netlas",
            "name": "account-2",
            "credential_ref": "NETLAS_API_KEY_ACCOUNT2",
        },
    )
    assert created.status_code == 200
    account_id = created.json()["id"]
    assert "credential" not in str(created.json()).lower()

    accounts = await client.get(
        "/api/v1/connectors/accounts", headers=auth_headers_admin
    )
    account = next(row for row in accounts.json() if row["id"] == account_id)
    assert account["policy"] == {"approved": False}
    assert account["credential_ref"] == "NETLAS_API_KEY_ACCOUNT2"

    updated = await client.post(
        "/api/v1/connectors/accounts",
        headers=auth_headers_admin,
        json={
            "source_id": "netlas",
            "name": "account-2",
            "credential_ref": "NETLAS_API_KEY_V3",
        },
    )
    assert updated.status_code == 200 and updated.json()["id"] == account_id
    account = next(
        row
        for row in (
            await client.get("/api/v1/connectors/accounts", headers=auth_headers_admin)
        ).json()
        if row["id"] == account_id
    )
    assert account["credential_ref"] == "NETLAS_API_KEY_V3"

    invalid = await client.patch(
        f"/api/v1/connectors/accounts/{account_id}/policy",
        headers=auth_headers_admin,
        json={"approved": 1, "requests_per_minute": 10, "daily_budget": 100},
    )
    assert invalid.status_code == 422
    approved = await client.patch(
        f"/api/v1/connectors/accounts/{account_id}/policy",
        headers=auth_headers_admin,
        json={"approved": True, "requests_per_minute": 10, "daily_budget": 100},
    )
    assert approved.status_code == 200
    assert approved.json()["policy"] == {
        "approved": True,
        "requests_per_minute": 10,
        "daily_budget": 100,
    }
    wrong_provider_history_cap = await client.patch(
        f"/api/v1/connectors/accounts/{account_id}/policy",
        headers=auth_headers_admin,
        json={
            "approved": True,
            "requests_per_minute": 10,
            "daily_budget": 100,
            "max_certificate_history_credits": 3,
        },
    )
    # The history-credit field is no longer part of the account policy schema.
    assert wrong_provider_history_cap.status_code == 422
    assert (
        await client.patch(
            f"/api/v1/connectors/accounts/{account_id}/policy",
            headers=auth_headers_analyst,
            json={"approved": False, "requests_per_minute": 10, "daily_budget": 100},
        )
    ).status_code == 403

    connector = Connector(
        name="netlas-exposure-default",
        connector_type="exposure",
        default_job_type="exposure.netlas",
        status="enabled",
        provider="netlas",
        readiness={
            "credentials_configured": True,
            "credential_state": "unknown",
            "capabilities": ["hostname"],
        },
        last_seen_at=datetime.now(timezone.utc),
    )
    db_session.add(
        Asset(
            asset_type=AssetType.domain,
            asset_value="example.com",
            criticality="medium",
            is_active=True,
        )
    )
    db_session.add(connector)
    await db_session.commit()

    mismatch = SourceAccount(
        source_id="unknown-provider",
        name="wrong-provider",
        policy={"approved": False},
    )
    db_session.add(mismatch)
    await db_session.commit()
    assert (
        await client.patch(
            f"/api/v1/connectors/{connector.id}/account?account_id={mismatch.id}",
            headers=auth_headers_admin,
        )
    ).status_code == 400

    bound = await client.patch(
        f"/api/v1/connectors/{connector.id}/account?account_id={account_id}",
        headers=auth_headers_admin,
    )
    assert bound.status_code == 200
    assert bound.json()["source_account_id"] == account_id
    assert bound.json()["provider"] == "netlas"
    # The binding answers the connector, so it is the same resource the list row
    # describes and is built by the same `_connector_out`. Comparing the two
    # responses field for field is what keeps the two routes from drifting apart
    # while each still passes its own assertions.
    listed = (
        await client.get("/api/v1/connectors", headers=auth_headers_admin)
    ).json()
    assert bound.json() == next(row for row in listed if row["id"] == str(connector.id))
    created_response = await client.post(
        "/api/v1/modules/exposure/scan", headers=auth_headers_analyst
    )
    assert created_response.status_code == 202, created_response.text
    created_job = created_response.json()
    assert len(created_job["job_ids"]) == 1
    job = await db_session.get(Job, uuid.UUID(created_job["job_ids"][0]))
    assert job.params["source_account_id"] == account_id
    assert job.params["config_snapshot"]["requests_per_minute"] == 10

    wrong_provider = await client.post(
        "/api/v1/connectors/accounts",
        headers=auth_headers_admin,
        json={"source_id": "invalid provider", "name": "oops"},
    )
    assert wrong_provider.status_code == 422

    # Query through the ORM so this also asserts audit rows committed with the
    # corresponding operator actions.
    from sqlalchemy import select

    audit_rows = list((await db_session.execute(select(AuditLog))).scalars())
    assert {row.action for row in audit_rows} >= {
        "source_account.provisioned",
        "source_account.policy.updated",
        "connector.account.bound",
    }
    # `connectors.list` is the one row written without an actor: the list route
    # records the read with `user_id=None` on purpose, so it is the single
    # exception to the blanket check that every trail entry names a user.
    assert all(
        row.user_id is not None and row.ip_address
        for row in audit_rows
        if row.action != "connectors.list"
    )


@pytest.mark.asyncio
async def test_the_account_list_is_the_shape_the_client_declares(
    client, db_session, auth_headers_admin
):
    """The settings page's payload is a declaration, not whatever the route built.

    Two properties are pinned because either is easy to undo by "tidying" the
    decorator: a policy that has not been approved stays the single key
    `{"approved": false}` (the page reads a missing budget as "use the default"),
    and a policy key the model does not name is forwarded rather than cut — the
    column is a stored document, so a restore may hold a field this writer retired.
    """
    created = await client.post(
        "/api/v1/connectors/accounts",
        headers=auth_headers_admin,
        json={"source_id": "netlas", "name": "shape-account"},
    )
    assert created.status_code == 200, created.text
    account_id = created.json()["id"]

    def _row(rows: list[dict]) -> dict:
        return next(row for row in rows if row["id"] == account_id)

    rows = (
        await client.get("/api/v1/connectors/accounts", headers=auth_headers_admin)
    ).json()
    row = _row(rows)
    # Six keys: no secret reference and no stored key means those two keys are
    # absent, which is how the client types them (`credential_ref?`).
    assert set(row) == {
        "id",
        "source_id",
        "name",
        "policy",
        "access_state",
        "has_api_key",
    }
    assert row["policy"] == {"approved": False}
    assert row["has_api_key"] is False

    approved = await client.patch(
        f"/api/v1/connectors/accounts/{account_id}/policy",
        headers=auth_headers_admin,
        json={"approved": True, "requests_per_minute": 12, "daily_budget": 240},
    )
    assert approved.status_code == 200, approved.text
    row = _row(
        (await client.get("/api/v1/connectors/accounts", headers=auth_headers_admin)).json()
    )
    assert row["policy"] == {
        "approved": True,
        "requests_per_minute": 12,
        "daily_budget": 240,
    }

    stored = await db_session.get(SourceAccount, uuid.UUID(account_id))
    stored.policy = {"approved": False, "max_certificate_history_credits": 3}
    await db_session.commit()
    row = _row(
        (await client.get("/api/v1/connectors/accounts", headers=auth_headers_admin)).json()
    )
    assert row["policy"]["max_certificate_history_credits"] == 3
