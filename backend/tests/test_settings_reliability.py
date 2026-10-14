import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.models.settings import SystemSettings
from app.services.settings_service import SettingsService


@pytest.mark.anyio
async def test_settings_update_rolls_back_when_audit_fails(client, db_session, auth_headers_admin, monkeypatch):
    from app.core import audit

    row = await SettingsService(db_session).get_singleton()
    original = row.smtp_host
    async def unavailable(*args, **kwargs):
        raise RuntimeError("audit unavailable")
    monkeypatch.setattr(audit, "prepare_entry", unavailable)
    response = await client.put("/api/v1/settings", headers=auth_headers_admin, json={"smtp_host": "smtp.example.com"})
    assert response.status_code == 503
    await db_session.refresh(row)
    assert row.smtp_host == original


@pytest.mark.anyio
async def test_stale_settings_version_returns_conflict(client, auth_headers_admin):
    first = await client.get("/api/v1/settings", headers=auth_headers_admin)
    version = first.json()["version"]
    applied = await client.put("/api/v1/settings", headers=auth_headers_admin, json={"smtp_host": "mail.example.com", "expected_version": version})
    assert applied.status_code == 200
    stale = await client.put("/api/v1/settings", headers=auth_headers_admin, json={"smtp_host": "stale.example.com", "expected_version": version})
    assert stale.status_code == 409
    current = await client.get("/api/v1/settings", headers=auth_headers_admin)
    assert current.json()["smtp_host"] == "mail.example.com"


@pytest.mark.anyio
async def test_singleton_is_database_invariant(db_session):
    await SettingsService(db_session).get_singleton()
    db_session.add(SystemSettings())
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()
    assert len(list((await db_session.execute(select(SystemSettings))).scalars())) == 1


@pytest.mark.parametrize("payload", [
    {"telegram_chat_ids": [str(10000 + i) for i in range(101)]},
    {"schedule_phishing": {"days": [True], "hour": 1, "minute": 0}},
    {"schedules": {"phishing": {"days": [1], "hour": 1, "minute": 0}}},
])
def test_invalid_settings_are_rejected(payload):
    from pydantic import ValidationError
    from app.schemas.settings import SystemSettingsUpdate
    with pytest.raises(ValidationError):
        SystemSettingsUpdate(**payload)
