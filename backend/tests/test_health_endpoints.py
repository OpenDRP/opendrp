import json

import pytest
from unittest.mock import AsyncMock, patch

from app.models import Connector


@pytest.mark.asyncio
async def test_connector_health_is_dynamic_and_secret_free(client, test_viewer, auth_headers_viewer, db_session):
    conn = Connector(
        name="custom-monitor",
        connector_type="phishing",
        status="enabled",
        default_job_type="phishing.custom-monitor",
        info={"api_version": "1.0", "secret": "must-not-be-exposed"},
        config={"api_key": "secret"},
    )
    db_session.add(conn)
    await db_session.commit()

    response = await client.get("/api/v1/connectors/health", headers=auth_headers_viewer)
    assert response.status_code == 200
    body = response.json()
    item = next(i for i in body["items"] if i["name"] == "custom-monitor")
    assert item["health"] == "unknown"
    assert "config" not in item
    assert item["info"] == {"api_version": "1.0"}


@pytest.mark.asyncio
async def test_connector_health_hides_provider_error_text_from_non_admins(
    client, test_admin, auth_headers_admin, auth_headers_viewer, db_session
):
    """Connector error text routinely echoes the provider URL as a credential.

    Shodan passes its API key as a query parameter, so an unfiltered
    ``last_error`` hands a working credential to any signed-in viewer.
    """
    leaked = "https://api.shodan.io/shodan/host/search?key=SUPER-SECRET-KEY&query=acme"
    conn = Connector(
        name="leaky-monitor",
        connector_type="phishing",
        status="enabled",
        default_job_type="phishing.leaky-monitor",
        last_error=leaked,
    )
    db_session.add(conn)
    await db_session.commit()

    viewer_response = await client.get(
        "/api/v1/connectors/health", headers=auth_headers_viewer
    )
    assert viewer_response.status_code == 200
    assert "SUPER-SECRET-KEY" not in json.dumps(viewer_response.json())
    viewer_item = next(
        i for i in viewer_response.json()["items"] if i["name"] == "leaky-monitor"
    )
    assert viewer_item["last_error"] is None
    assert viewer_item["health"] == "failed"

    admin_response = await client.get(
        "/api/v1/connectors/health", headers=auth_headers_admin
    )
    assert admin_response.status_code == 200
    admin_item = next(
        i for i in admin_response.json()["items"] if i["name"] == "leaky-monitor"
    )
    assert admin_item["last_error"] == leaked


@pytest.mark.asyncio
async def test_alert_health_reports_disabled_channels_without_network_calls(
    client, auth_headers_viewer, db_session
):
    from app.services.settings_service import SettingsService

    settings = await SettingsService(db_session).get_singleton()
    settings.email_alerts_enabled = False
    settings.telegram_alerts_enabled = False
    settings.smtp_host = None
    settings.telegram_bot_token_decrypted = None
    settings.telegram_chat_ids = []
    await db_session.commit()

    with patch("app.api.v1.routers.alerts._smtp_probe") as smtp_probe, patch(
        "app.api.v1.routers.alerts._telegram_probe", new_callable=AsyncMock
    ) as telegram_probe:
        response = await client.get("/api/v1/alerts/health", headers=auth_headers_viewer)

    assert response.status_code == 200
    assert {item["health"] for item in response.json()["items"]} == {"disabled"}
    smtp_probe.assert_not_called()
    telegram_probe.assert_not_awaited()


@pytest.mark.asyncio
async def test_alert_health_does_not_dial_a_disabled_but_configured_channel(
    client, auth_headers_viewer, db_session
):
    """A switched-off channel must not be probed even when it is configured.

    The endpoint reports ``disabled`` either way, so dialling it can only add
    latency: the SMTP probe blocks for up to ``ALERT_HEALTH_CHECK_TIMEOUT_SECONDS``
    against an unreachable server. The response must still say the channel is
    configured, otherwise an operator cannot tell "off" from "incomplete".
    """
    from app.services.settings_service import SettingsService

    settings = await SettingsService(db_session).get_singleton()
    settings.email_alerts_enabled = False
    settings.telegram_alerts_enabled = False
    settings.smtp_host = "203.0.113.1"
    settings.smtp_port = 25
    settings.smtp_from_email_decrypted = "alerts@example.com"
    settings.telegram_bot_token_decrypted = "123456:token"
    settings.telegram_chat_ids = ["1"]
    await db_session.commit()

    with patch("app.api.v1.routers.alerts._smtp_probe") as smtp_probe, patch(
        "app.api.v1.routers.alerts._telegram_probe", new_callable=AsyncMock
    ) as telegram_probe:
        response = await client.get("/api/v1/alerts/health", headers=auth_headers_viewer)

    assert response.status_code == 200
    items = {item["channel"]: item for item in response.json()["items"]}
    assert {item["health"] for item in items.values()} == {"disabled"}
    assert all(item["configured"] is True for item in items.values())
    smtp_probe.assert_not_called()
    telegram_probe.assert_not_awaited()
