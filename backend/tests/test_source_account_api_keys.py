import uuid

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select

from app.core import crypto
from app.core.config import settings
from app.core.crypto import decrypt_value
from app.models.audit import AuditLog
from app.models.source_account import SourceAccount
from app.services.connector_credentials import ConnectorCredentials
from app.services.connector_service import ConnectorService

SECRET = "nl-live-SECRET-KEY-1234"


async def _account(client, headers, name="key-account"):
    created = await client.post(
        "/api/v1/connectors/accounts",
        headers=headers,
        json={"source_id": "netlas", "name": name},
    )
    assert created.status_code == 200
    return uuid.UUID(created.json()["id"])


async def _connector_headers(db, *, provider, account_id=None, name="netlas-phishing"):
    svc = ConnectorService(db)
    conn = await svc.get_by_name(name)
    if conn is None:
        conn = await svc.register(
            name=name,
            connector_type="phishing",
            api_version="1.0",
            default_job_type=f"phishing.{name}",
        )
    conn.provider = provider
    conn.source_account_id = account_id
    token, _ = await ConnectorCredentials(db).issue(conn)
    await db.commit()
    return {"X-Connector-Token": token, "X-Connector-Name": name}


@pytest.mark.asyncio
async def test_api_key_is_stored_encrypted_and_never_returned(
    client, db_session, auth_headers_admin
):
    account_id = await _account(client, auth_headers_admin)

    put = await client.put(
        f"/api/v1/connectors/accounts/{account_id}/api-key",
        headers=auth_headers_admin,
        json={"api_key": SECRET},
    )
    assert put.status_code == 200
    body = put.json()
    assert body["has_api_key"] is True
    assert body["api_key_hint"].endswith("1234")
    assert SECRET not in put.text

    listed = await client.get("/api/v1/connectors/accounts", headers=auth_headers_admin)
    assert SECRET not in listed.text
    row = next(item for item in listed.json() if item["id"] == str(account_id))
    assert row["has_api_key"] is True

    stored = await db_session.get(SourceAccount, account_id)
    await db_session.refresh(stored)
    assert stored.api_key_encrypted and SECRET not in stored.api_key_encrypted
    assert decrypt_value(stored.api_key_encrypted) == SECRET

    audit = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "source_account.api_key.updated")
        )
    ).scalars().all()
    assert audit, "key update must be audited"
    assert all(SECRET not in str(entry.details) for entry in audit)


@pytest.mark.asyncio
async def test_api_key_rejects_malformed_values(client, auth_headers_admin):
    account_id = await _account(client, auth_headers_admin, name="bad-keys")
    url = f"/api/v1/connectors/accounts/{account_id}/api-key"
    for value in ["", "has space", "tab\tkey", "x" * 513, "ключ"]:
        response = await client.put(url, headers=auth_headers_admin, json={"api_key": value})
        assert response.status_code == 422, value


@pytest.mark.asyncio
async def test_api_key_management_is_admin_only(
    client, auth_headers_admin, auth_headers_analyst
):
    account_id = await _account(client, auth_headers_admin, name="admin-only")
    url = f"/api/v1/connectors/accounts/{account_id}/api-key"
    assert (
        await client.put(url, headers=auth_headers_analyst, json={"api_key": SECRET})
    ).status_code == 403
    assert (await client.delete(url, headers=auth_headers_analyst)).status_code == 403


@pytest.mark.asyncio
async def test_connector_receives_only_its_bound_account_key(
    client, db_session, auth_headers_admin
):
    account_id = await _account(client, auth_headers_admin, name="bound")
    await client.put(
        f"/api/v1/connectors/accounts/{account_id}/api-key",
        headers=auth_headers_admin,
        json={"api_key": SECRET},
    )

    unbound = await _connector_headers(db_session, provider="netlas", name="netlas-unbound")
    response = await client.get("/api/v1/connectors/me/credential", headers=unbound)
    assert response.status_code == 200
    assert response.json() == {"configured": False}

    bound = await _connector_headers(
        db_session, provider="netlas", account_id=account_id, name="netlas-bound"
    )
    response = await client.get("/api/v1/connectors/me/credential", headers=bound)
    assert response.status_code == 200
    assert response.json() == {"configured": True, "api_key": SECRET}
    assert response.headers["cache-control"] == "no-store"

    mismatched = await _connector_headers(
        db_session, provider="shodan", account_id=account_id, name="shodan-mismatch"
    )
    response = await client.get("/api/v1/connectors/me/credential", headers=mismatched)
    assert response.json() == {"configured": False}


@pytest.mark.asyncio
async def test_credential_endpoint_requires_connector_token(client):
    response = await client.get("/api/v1/connectors/me/credential")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_removing_key_clears_storage_and_connector_view(
    client, db_session, auth_headers_admin
):
    account_id = await _account(client, auth_headers_admin, name="removable")
    url = f"/api/v1/connectors/accounts/{account_id}/api-key"
    await client.put(url, headers=auth_headers_admin, json={"api_key": SECRET})
    bound = await _connector_headers(
        db_session, provider="netlas", account_id=account_id, name="netlas-removable"
    )

    removed = await client.delete(url, headers=auth_headers_admin)
    assert removed.status_code == 200
    assert removed.json()["has_api_key"] is False

    stored = await db_session.get(SourceAccount, account_id)
    await db_session.refresh(stored)
    assert stored.api_key_encrypted is None and stored.api_key_hint is None

    response = await client.get("/api/v1/connectors/me/credential", headers=bound)
    assert response.json() == {"configured": False}


@pytest.mark.asyncio
async def test_key_rotation_rewraps_stored_provider_keys(db_session, monkeypatch):
    from scripts.rotate_keys import rewrap_stored

    old_key = Fernet.generate_key().decode("ascii")
    new_key = Fernet.generate_key().decode("ascii")
    crypto.reset_cache()
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", old_key)
    monkeypatch.setattr(settings, "ENCRYPTION_PREVIOUS_KEYS", "")
    account = SourceAccount(
        source_id="netlas",
        name="rotation-probe",
        policy={"approved": False},
        api_key_encrypted=crypto.encrypt_value("rot-secret-0001"),
        api_key_hint="0001",
    )
    db_session.add(account)
    await db_session.flush()

    monkeypatch.setattr(settings, "ENCRYPTION_KEY", new_key)
    monkeypatch.setattr(settings, "ENCRYPTION_PREVIOUS_KEYS", old_key)
    crypto.reset_cache()
    assert crypto.key_index_for(account.api_key_encrypted) == 1

    changed, failures = await rewrap_stored(db_session)

    assert failures == []
    assert changed >= 1
    assert crypto.key_index_for(account.api_key_encrypted) == 0
    assert crypto.decrypt_value(account.api_key_encrypted) == "rot-secret-0001"
    crypto.reset_cache()
