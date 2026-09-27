"""Characterization tests: settings test-notification endpoints (Step 8).

Pins the CURRENT behavior of the two previously untested admin endpoints:

* ``POST /settings/test-email`` — delegates to ``SettingsService``; on
  success writes a ``settings.test_email_sent`` audit row, on failure writes
  ``settings.test_email_failed`` (truncated error) and re-raises (→ 400 for
  ``BadRequestException``).
* ``POST /settings/test-telegram`` — delegates to ``AlertService``; on
  success audits ``settings.test_telegram_sent`` with ``sent``/``total``
  counts and commits; on failure audits ``settings.test_telegram_failed``.
* RBAC: both endpoints are admin-only (viewer → 403).
"""

from __future__ import annotations

from typing import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


BASE = "http://test"

TG_TOKEN = "1234567890:ABCdefGHIjklMNOpqrSTUvwxYZ1234567890"


@pytest.fixture()
async def client(db_session) -> AsyncGenerator[AsyncClient, None]:
    from app.api.deps import get_db

    async def _override():
        yield db_session

    app.dependency_overrides[get_db] = _override
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url=BASE
        ) as c:
            yield c
    finally:
        app.dependency_overrides.pop(get_db, None)


async def _audit_actions(db, action: str) -> list[dict]:
    from sqlalchemy import text

    rows = (
        await db.execute(
            text(
                "SELECT action, details FROM drp_audit_logs "
                "WHERE action = :a ORDER BY timestamp"
            ),
            {"a": action},
        )
    ).mappings().all()
    return [dict(r) for r in rows]


async def _seed_email_settings(db) -> None:
    from app.services.settings_service import SettingsService

    s = await SettingsService(db).get_singleton()
    s.smtp_host = "smtp.example.com"
    s.smtp_port = 587
    s.smtp_user = "ops@example.com"
    s.smtp_password_decrypted = "Passw0rd!"
    s.alert_recipient_email_decrypted = "soc@example.com"
    await db.commit()


async def _seed_telegram_settings(db) -> None:
    from app.services.settings_service import SettingsService

    s = await SettingsService(db).get_singleton()
    s.telegram_bot_token_decrypted = TG_TOKEN
    s.telegram_alerts_enabled = True
    s.telegram_chat_ids = ["@channelone", "-100999888777"]
    await db.commit()


class TestTestEmailEndpoint:
    @pytest.mark.asyncio
    async def test_success_sends_and_audits(
        self, client, db_session, auth_headers_admin
    ):
        await _seed_email_settings(db_session)

        with patch("app.services.settings_service.smtplib.SMTP") as mock_cls:
            instance = MagicMock()
            mock_cls.return_value.__enter__.return_value = instance
            r = await client.post(
                "/api/v1/settings/test-email",
                json={"to": "custom-test@example.com"},
                headers=auth_headers_admin,
            )

        assert r.status_code == 200, r.text
        assert r.json() == {"status": "sent", "to": "custom-test@example.com"}
        instance.send_message.assert_called_once()

        rows = await _audit_actions(db_session, "settings.test_email_sent")
        assert len(rows) == 1

    @pytest.mark.asyncio
    async def test_failure_audits_and_reraises_400(
        self, client, db_session, auth_headers_admin
    ):
        # Singleton exists but nothing configured -> service raises.
        r = await client.post(
            "/api/v1/settings/test-email",
            json={"to": "nobody@example.com"},
            headers=auth_headers_admin,
        )
        assert r.status_code == 400, r.text

        rows = await _audit_actions(db_session, "settings.test_email_failed")
        assert len(rows) == 1
        assert "nobody@example.com" in rows[0]["details"]
        assert "SMTP settings not configured" in rows[0]["details"]

    @pytest.mark.asyncio
    async def test_viewer_forbidden_403(self, client, auth_headers_viewer):
        r = await client.post(
            "/api/v1/settings/test-email",
            json={"to": "x@example.com"},
            headers=auth_headers_viewer,
        )
        assert r.status_code == 403


class TestTestTelegramEndpoint:
    @pytest.mark.asyncio
    async def test_success_sends_to_all_chats_and_audits(
        self, client, db_session, auth_headers_admin
    ):
        await _seed_telegram_settings(db_session)

        with patch("app.services.alert_service.httpx.AsyncClient") as mock_cls:
            instance = MagicMock()
            resp = MagicMock()
            resp.status_code = 200
            instance.get = AsyncMock(return_value=MagicMock(status_code=200, text='{"ok": true, "result": {"type": "private"}}'))
            instance.post = AsyncMock(return_value=resp)
            mock_cls.return_value.__aenter__.return_value = instance

            r = await client.post(
                "/api/v1/settings/test-telegram",
                json={},
                headers=auth_headers_admin,
            )

        assert r.status_code == 200, r.text
        body = r.json()
        assert body["sent"] == 2  # both configured chats
        assert body["total"] == 2
        assert all(res["ok"] for res in body["results"])
        assert instance.post.await_count == 2

        rows = await _audit_actions(db_session, "settings.test_telegram_sent")
        assert len(rows) == 1
        assert '"sent":2' in rows[0]["details"].replace(" ", "")
        assert '"total":2' in rows[0]["details"].replace(" ", "")
        await db_session.commit()

    @pytest.mark.asyncio
    async def test_chat_id_override_sends_to_one_chat(
        self, client, db_session, auth_headers_admin
    ):
        await _seed_telegram_settings(db_session)

        with patch("app.services.alert_service.httpx.AsyncClient") as mock_cls:
            instance = MagicMock()
            resp = MagicMock()
            resp.status_code = 200
            instance.get = AsyncMock(return_value=MagicMock(status_code=200, text='{"ok": true, "result": {"type": "private"}}'))
            instance.get = AsyncMock(return_value=MagicMock(status_code=200, text='{"ok": true, "result": {"type": "private"}}'))
            instance.post = AsyncMock(return_value=resp)
            mock_cls.return_value.__aenter__.return_value = instance

            r = await client.post(
                "/api/v1/settings/test-telegram",
                json={"chat_id": "@overridechat"},
                headers=auth_headers_admin,
            )

        assert r.status_code == 200, r.text
        body = r.json()
        assert body["sent"] == 1
        assert body["results"][0]["chat_id"] == "@overridechat"

    @pytest.mark.asyncio
    async def test_validate_endpoint_returns_safe_per_chat_results(
        self, client, db_session, auth_headers_admin
    ):
        await _seed_telegram_settings(db_session)

        with patch("app.services.alert_service.httpx.AsyncClient") as mock_cls:
            instance = MagicMock()
            instance.get = AsyncMock(return_value=MagicMock(status_code=200, text='{"ok": true, "result": {"type": "private", "username": "owner"}}'))
            mock_cls.return_value.__aenter__.return_value = instance

            r = await client.post(
                "/api/v1/settings/validate-telegram",
                json={},
                headers=auth_headers_admin,
            )

        assert r.status_code == 200, r.text
        body = r.json()
        assert body["valid"] == 2
        assert body["total"] == 2
        assert body["results"][0]["chat_type"] == "private"
        assert body["results"][0]["username"] == "owner"
        assert "token" not in r.text.lower()
        instance.get.assert_awaited()

    @pytest.mark.asyncio
    async def test_chat_id_override_is_trimmed_before_delivery(
        self, client, db_session, auth_headers_admin
    ):
        await _seed_telegram_settings(db_session)

        with patch("app.services.alert_service.httpx.AsyncClient") as mock_cls:
            instance = MagicMock()
            response = MagicMock()
            response.status_code = 200
            instance.get = AsyncMock(return_value=MagicMock(status_code=200, text='{"ok": true, "result": {"type": "private"}}'))
            instance.post = AsyncMock(return_value=response)
            mock_cls.return_value.__aenter__.return_value = instance

            r = await client.post(
                "/api/v1/settings/test-telegram",
                json={"chat_id": "  @overridechat  "},
                headers=auth_headers_admin,
            )

        assert r.status_code == 200, r.text
        assert r.json()["results"][0]["chat_id"] == "@overridechat"

    @pytest.mark.asyncio
    async def test_invalid_chat_id_override_is_rejected_before_external_call(
        self, client, auth_headers_admin
    ):
        r = await client.post(
            "/api/v1/settings/test-telegram",
            json={"chat_id": "not a valid chat id"},
            headers=auth_headers_admin,
        )
        assert r.status_code == 422, r.text

    @pytest.mark.asyncio
    async def test_chat_id_control_character_is_rejected(
        self, client, auth_headers_admin
    ):
        response = await client.post(
            "/api/v1/settings/test-telegram",
            json={"chat_id": "@ops\r\nX-Injected: yes"},
            headers=auth_headers_admin,
        )
        assert response.status_code == 422, response.text

    @pytest.mark.asyncio
    async def test_partial_delivery_reports_failure_per_chat(
        self, client, db_session, auth_headers_admin
    ):
        """Per-chat delivery results are returned raw (no exception)."""
        await _seed_telegram_settings(db_session)

        with patch("app.services.alert_service.httpx.AsyncClient") as mock_cls:
            instance = MagicMock()
            ok = MagicMock()
            ok.status_code = 200
            bad = MagicMock()
            bad.status_code = 400
            bad.text = '{"description": "chat not found"}'
            instance.get = AsyncMock(side_effect=[MagicMock(status_code=200, text='{"ok": true, "result": {"type": "private"}}'), MagicMock(status_code=400, text='{"description": "chat not found"}')])
            instance.post = AsyncMock(side_effect=[ok, bad])
            mock_cls.return_value.__aenter__.return_value = instance

            r = await client.post(
                "/api/v1/settings/test-telegram",
                json={},
                headers=auth_headers_admin,
            )

        assert r.status_code == 200, r.text
        body = r.json()
        assert body["sent"] == 1
        assert body["total"] == 2
        assert body["results"][1]["ok"] is False
        assert body["results"][1]["error_code"] == "chat_not_found"
        assert "cannot find this chat" in body["results"][1]["error"]

    @pytest.mark.asyncio
    async def test_failure_no_token_audits_and_returns_400(
        self, client, db_session, auth_headers_admin
    ):
        r = await client.post(
            "/api/v1/settings/test-telegram",
            json={"chat_id": "@somechat"},
            headers=auth_headers_admin,
        )
        assert r.status_code == 400, r.text

        rows = await _audit_actions(db_session, "settings.test_telegram_failed")
        assert len(rows) == 1
        assert "@somechat" in rows[0]["details"]
        assert "not configured" in rows[0]["details"]

    @pytest.mark.asyncio
    async def test_viewer_forbidden_403(self, client, auth_headers_viewer):
        r = await client.post(
            "/api/v1/settings/test-telegram",
            json={},
            headers=auth_headers_viewer,
        )
        assert r.status_code == 403
