"""Alert-channel health probes and their endpoint.

Two distinctions the UI depends on and that are easy to get wrong:

* ``not_configured`` (nobody filled in the settings) is not the same as
  ``failed`` (settings are filled in and the channel is broken). Reporting the
  first as the second sends an operator hunting a network problem that does not
  exist;
* a channel an operator switched **off** reports ``disabled`` no matter what a
  probe would say, and is not probed at all for the message it reports.

Credentials being rejected (401/403) is also distinguished from a non-200 the
provider returns for another reason — the first is an operator error, the second
may be a provider outage.
"""

from __future__ import annotations

import smtplib
import ssl
from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import pytest

from app.api.v1.routers import alerts


def _settings(**overrides) -> SimpleNamespace:
    base = {
        "smtp_host": None,
        "smtp_port": None,
        "smtp_security_mode": "starttls",
        "smtp_from_email_decrypted": None,
        "smtp_user": None,
        "smtp_password_decrypted": None,
        "email_alerts_enabled": False,
        "telegram_bot_token_decrypted": None,
        "telegram_chat_ids": None,
        "telegram_alerts_enabled": False,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


class _FakeSmtpServer:
    """Stands in for ``smtplib.SMTP`` / ``SMTP_SSL``."""

    def __init__(self, host, port, timeout=None, context=None) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.context = context
        self.calls: list[tuple] = []
        self.logged_in: tuple | None = None

    def __enter__(self) -> "_FakeSmtpServer":
        return self

    def __exit__(self, *_exc) -> bool:
        return False

    def ehlo(self) -> None:
        self.calls.append(("ehlo",))

    def starttls(self, context=None) -> None:
        self.calls.append(("starttls", context is not None))

    def login(self, user, password) -> None:
        self.logged_in = (user, password)

    def close(self) -> None:  # pragma: no cover - SMTP() context manager handles it
        pass


class TestSmtpConfiguration:
    def test_a_sender_address_is_enough(self):
        assert alerts._configured_smtp(_settings(smtp_host="smtp.example", smtp_port=587, smtp_from_email_decrypted="a@b.example")) is True

    def test_a_login_is_enough_without_a_sender_address(self):
        assert alerts._configured_smtp(_settings(smtp_host="smtp.example", smtp_port=587, smtp_user="u")) is True

    @pytest.mark.parametrize(
        "overrides",
        [
            {},
            {"smtp_host": "smtp.example"},
            {"smtp_host": "smtp.example", "smtp_port": 587},
            {"smtp_port": 587, "smtp_from_email_decrypted": "a@b.example"},
        ],
    )
    def test_incomplete_settings_are_not_configured(self, overrides):
        assert alerts._configured_smtp(_settings(**overrides)) is False


class TestSmtpProbe:
    def test_unconfigured_settings_are_reported_as_such(self):
        result = alerts._smtp_probe(_settings())
        assert (result.health, result.latency_ms) == ("not_configured", None)
        assert "incomplete" in result.message
        assert result.blocked_reason is None

    @pytest.mark.asyncio
    async def test_implicit_tls_upgrades_the_connection(self, monkeypatch):
        servers: list[_FakeSmtpServer] = []

        def _factory(host, port, timeout=None, context=None):
            server = _FakeSmtpServer(host, port, timeout, context)
            servers.append(server)
            return server

        monkeypatch.setattr(smtplib, "SMTP", _factory)
        settings = _settings(
            smtp_host="smtp.example", smtp_port=587, smtp_user="u", smtp_password_decrypted="p"
        )

        result = alerts._smtp_probe(settings)

        assert result.health == "healthy"
        assert result.latency_ms is not None
        assert ("starttls", True) in servers[0].calls
        assert servers[0].logged_in == ("u", "p")

    @pytest.mark.asyncio
    async def test_port_465_uses_an_implicit_tls_connection(self, monkeypatch):
        servers: list[_FakeSmtpServer] = []

        def _factory(host, port, timeout=None, context=None):
            server = _FakeSmtpServer(host, port, timeout, context)
            servers.append(server)
            return server

        implicit: list[_FakeSmtpServer] = []

        def _ssl_factory(host, port, timeout=None, context=None):
            server = _FakeSmtpServer(host, port, timeout, context)
            implicit.append(server)
            return server

        monkeypatch.setattr(smtplib, "SMTP", _factory)
        monkeypatch.setattr(smtplib, "SMTP_SSL", _ssl_factory)

        result = alerts._smtp_probe(
            _settings(smtp_host="smtp.example", smtp_port=465, smtp_security_mode="ssl", smtp_from_email_decrypted="a@b.example")
        )

        assert result.health == "healthy"
        assert len(implicit) == 1
        assert servers == []
        # No STARTTLS on an already-encrypted connection, and no login attempted
        # without credentials.
        assert implicit[0].calls == []
        assert implicit[0].logged_in is None

    def test_a_broken_server_is_reported_with_its_failure_kind(self, monkeypatch):
        def _boom(*_args, **_kwargs):
            raise smtplib.SMTPAuthenticationError(535, b"nope")

        monkeypatch.setattr(smtplib, "SMTP", _boom)

        result = alerts._smtp_probe(
            _settings(smtp_host="smtp.example", smtp_port=587, smtp_from_email_decrypted="a@b.example")
        )

        assert result.health == "failed"
        assert "SMTPAuthenticationError" in result.message
        assert result.latency_ms is not None

    def test_a_network_failure_is_reported_as_failed(self, monkeypatch):
        monkeypatch.setattr(smtplib, "SMTP", MagicMock(side_effect=OSError("unreachable")))

        result = alerts._smtp_probe(
            _settings(smtp_host="smtp.example", smtp_port=587, smtp_from_email_decrypted="a@b.example")
        )

        assert result.health == "failed"
        assert "OSError" in result.message


class TestTelegramConfiguration:
    def test_a_token_and_at_least_one_chat(self):
        assert alerts._telegram_configured(
            _settings(telegram_bot_token_decrypted="t", telegram_chat_ids=["1"])
        ) is True

    def test_a_legacy_single_chat_id_does_not_configure_the_channel(self):
        """The v0.1.0 removal, pinned: ``telegram_chat_ids`` is the only source.

        An extra attribute is deliberately present rather than absent: it is how
        a settings row restored from a pre-0.1.0 dump would arrive, and the
        channel must read it as "nothing configured" instead of reporting a
        configured channel that then cannot resolve a destination.
        """
        legacy = _settings(telegram_bot_token_decrypted="t")
        legacy.telegram_chat_id = "1"
        assert alerts._telegram_configured(legacy) is False

    def test_a_chat_without_a_token_is_not_configured(self):
        assert alerts._telegram_configured(_settings(telegram_chat_ids=["1"])) is False

    def test_a_token_without_a_chat_is_not_configured(self):
        assert alerts._telegram_configured(
            _settings(telegram_bot_token_decrypted="t")
        ) is False


class _FakeAsyncClient:
    def __init__(self, *, response=None, error: Exception | None = None, **kwargs) -> None:
        self._response = response
        self._error = error
        self.requested: list[str] = []
        self.kwargs = kwargs

    async def __aenter__(self) -> "_FakeAsyncClient":
        return self

    async def __aexit__(self, *_exc) -> bool:
        return False

    async def get(self, url: str):
        self.requested.append(url)
        if self._error is not None:
            raise self._error
        return self._response


class TestTelegramProbe:
    @pytest.mark.asyncio
    async def test_unconfigured_settings_are_reported_as_such(self):
        result = await alerts._telegram_probe(_settings())
        assert (result.health, result.latency_ms) == ("not_configured", None)
        assert "incomplete" in result.message

    @pytest.mark.asyncio
    async def test_a_reachable_api_is_healthy(self, monkeypatch):
        client = _FakeAsyncClient(response=SimpleNamespace(status_code=200))
        monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: client)

        result = await alerts._telegram_probe(
            _settings(telegram_bot_token_decrypted="tok", telegram_chat_ids=["1"])
        )

        assert result.health == "healthy"
        assert result.latency_ms is not None
        assert client.requested == ["https://api.telegram.org/bottok/getMe"]

    @pytest.mark.asyncio
    async def test_rejected_credentials_are_a_failure_not_a_degradation(self, monkeypatch):
        client = _FakeAsyncClient(response=SimpleNamespace(status_code=401))
        monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: client)

        result = await alerts._telegram_probe(
            _settings(telegram_bot_token_decrypted="tok", telegram_chat_ids=["1"])
        )

        assert result.health == "failed"
        assert "rejected" in result.message

    @pytest.mark.asyncio
    async def test_another_http_error_is_degraded(self, monkeypatch):
        client = _FakeAsyncClient(response=SimpleNamespace(status_code=502))
        monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: client)

        result = await alerts._telegram_probe(
            _settings(telegram_bot_token_decrypted="tok", telegram_chat_ids=["1"])
        )

        assert result.health == "degraded"
        assert "502" in result.message

    @pytest.mark.asyncio
    async def test_a_transport_error_is_a_failure(self, monkeypatch):
        client = _FakeAsyncClient(error=httpx.ConnectError("no route"))
        monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: client)

        result = await alerts._telegram_probe(
            _settings(telegram_bot_token_decrypted="tok", telegram_chat_ids=["1"])
        )

        assert result.health == "failed"
        assert "ConnectError" in result.message


class TestAlertHealthEndpoint:
    """The endpoint reports per-channel state without ever probing a disabled one."""

    @pytest.fixture
    def fake_settings_service(self, monkeypatch):
        def _install(settings_obj):
            class _Service:
                def __init__(self, _db):
                    pass

                async def get_singleton(self):
                    return settings_obj

            monkeypatch.setattr(alerts, "SettingsService", _Service)

        return _install

    @pytest.mark.asyncio
    async def test_disabled_channels_report_disabled_and_are_not_probed(
        self, client, auth_headers_viewer, fake_settings_service, monkeypatch
    ):
        fake_settings_service(_settings())
        probed: list[str] = []

        def _smtp(_s):
            probed.append("smtp")
            return alerts.ProbeResult("healthy", "x", 1)

        async def _telegram(_s):
            probed.append("telegram")
            return alerts.ProbeResult("healthy", "x", 1)

        monkeypatch.setattr(alerts, "_smtp_probe", _smtp)
        monkeypatch.setattr(alerts, "_telegram_probe", _telegram)

        response = await client.get("/api/v1/alerts/health", headers=auth_headers_viewer)

        assert response.status_code == 200
        items = {item["channel"]: item for item in response.json()["items"]}
        assert items["email"]["health"] == "disabled"
        assert items["telegram"]["health"] == "disabled"
        assert items["email"]["message"] == "Email alerts are disabled"
        assert items["email"]["configured"] is False
        assert items["email"]["last_checked_at"]
        # A switched-off channel is never dialled: probing it could block the
        # endpoint for the full SMTP timeout and still report "disabled".
        assert probed == []

    @pytest.mark.asyncio
    async def test_enabled_channels_report_their_probe_result(
        self, client, auth_headers_viewer, fake_settings_service, monkeypatch
    ):
        fake_settings_service(
            _settings(
                email_alerts_enabled=True,
                smtp_host="smtp.example",
                smtp_port=587,
                smtp_from_email_decrypted="a@b.example",
                telegram_alerts_enabled=True,
                telegram_bot_token_decrypted="tok",
                telegram_chat_ids=["1"],
            )
        )

        async def _telegram(_s):
            return alerts.ProbeResult("degraded", "Telegram API returned HTTP 502", 12)

        monkeypatch.setattr(
            alerts,
            "_smtp_probe",
            lambda s: alerts.ProbeResult("healthy", "SMTP connection is available", 30),
        )
        monkeypatch.setattr(alerts, "_telegram_probe", _telegram)

        response = await client.get("/api/v1/alerts/health", headers=auth_headers_viewer)
        items = {item["channel"]: item for item in response.json()["items"]}

        assert items["email"]["health"] == "healthy"
        assert items["email"]["configured"] is True
        assert items["email"]["latency_ms"] == 30
        assert items["telegram"]["health"] == "degraded"
        assert items["telegram"]["configured"] is True

    @pytest.mark.asyncio
    async def test_a_refused_destination_is_audited_as_a_security_event(
        self, client, auth_headers_viewer, fake_settings_service, monkeypatch
    ):
        """A blocked destination is not a configuration typo, so it is not logged
        as one: the reason reaches the audit trail as `outbound.blocked`, and the
        operator-facing message stays a health message."""
        fake_settings_service(
            _settings(
                email_alerts_enabled=True,
                smtp_host="smtp.example",
                smtp_port=587,
                smtp_from_email_decrypted="a@b.example",
            )
        )
        recorded: list[dict] = []

        async def _emit(_db, **kwargs):
            recorded.append(kwargs)

        monkeypatch.setattr(alerts.AuditLogger, "emit_background", _emit)
        monkeypatch.setattr(
            alerts,
            "_smtp_probe",
            lambda s: alerts.ProbeResult(
                "failed", "SMTP destination refused (blocked_network)", 4, "blocked_network"
            ),
        )

        response = await client.get("/api/v1/alerts/health", headers=auth_headers_viewer)

        assert response.status_code == 200
        # The view itself is always recorded, and the refusal comes after it.
        assert [call["action"] for call in recorded] == [
            "alerts.health.view",
            "outbound.blocked",
        ]
        assert recorded[1]["details"] == {
            "operation": "alert_channel_probe",
            "channels": {"email": "blocked_network"},
        }

    @pytest.mark.asyncio
    async def test_channel_health_requires_authentication(self, client):
        response = await client.get("/api/v1/alerts/health")
        assert response.status_code == 401


def test_probe_uses_the_configured_timeout(monkeypatch):
    """An unbounded probe would hang the request behind a dead mail server."""
    captured: dict = {}

    def _factory(host, port, timeout=None, context=None):
        captured["timeout"] = timeout
        return _FakeSmtpServer(host, port, timeout, context)

    monkeypatch.setattr(smtplib, "SMTP", _factory)
    from app.api.v1.routers.alerts import core_settings

    alerts._smtp_probe(
        _settings(smtp_host="smtp.example", smtp_port=587, smtp_from_email_decrypted="a@b.example")
    )

    assert captured["timeout"] == core_settings.ALERT_HEALTH_CHECK_TIMEOUT_SECONDS
    assert isinstance(ssl.create_default_context(), ssl.SSLContext)
