import json
from datetime import datetime, timedelta, timezone

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
@pytest.mark.parametrize("naive", [True, False])
async def test_connector_health_handles_recent_aware_and_naive_heartbeat(
    client, auth_headers_viewer, db_session, naive
):
    last_seen = datetime.now(timezone.utc) - timedelta(seconds=5)
    if naive:
        last_seen = last_seen.replace(tzinfo=None)
    conn = Connector(
        name=f"recent-heartbeat-{naive}",
        connector_type="phishing",
        status="enabled",
        default_job_type=f"phishing.recent-heartbeat-{naive}",
        last_seen_at=last_seen,
    )
    db_session.add(conn)
    await db_session.commit()

    response = await client.get("/api/v1/connectors/health", headers=auth_headers_viewer)

    assert response.status_code == 200, response.text
    item = next(row for row in response.json()["items"] if row["name"] == conn.name)
    assert item["health"] == "healthy"
    assert item["online"] is True


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
@pytest.mark.parametrize("naive", [True, False])
async def test_connector_health_publishes_derived_readiness_and_last_success(
    client, auth_headers_viewer, auth_headers_admin, db_session, naive
):
    """Readiness explains a refusal that `health` cannot: the worker is online,
    but its provider key was rejected. The closed vocabulary reaches every role;
    the raw readiness document stays administrator-only, like `last_error`."""
    last_success = datetime.now(timezone.utc) - timedelta(hours=6)
    if naive:
        last_success = last_success.replace(tzinfo=None)
    conn = Connector(
        name=f"readiness-{naive}",
        connector_type="phishing",
        status="enabled",
        default_job_type=f"phishing.readiness-{naive}",
        readiness={
            "credentials_configured": True,
            "credential_state": "invalid",
            "provider_error": "invalid_credentials",
            "capabilities": ["certificate_search"],
            "checked_at": "2026-01-01T00:00:00Z",
        },
        last_success_at=last_success,
    )
    db_session.add(conn)
    await db_session.commit()

    viewer_response = await client.get("/api/v1/connectors/health", headers=auth_headers_viewer)
    viewer_item = next(
        row for row in viewer_response.json()["items"] if row["name"] == conn.name
    )
    assert viewer_item["credentials_configured"] is True
    assert viewer_item["credential_state"] == "invalid"
    assert viewer_item["provider_error"] == "invalid_credentials"
    assert viewer_item["checked_at"] == "2026-01-01T00:00:00Z"
    assert viewer_item["readiness"] is None
    assert 6 * 3600 - 5 <= viewer_item["last_success_age_seconds"] <= 6 * 3600 + 60

    admin_response = await client.get("/api/v1/connectors/health", headers=auth_headers_admin)
    admin_item = next(
        row for row in admin_response.json()["items"] if row["name"] == conn.name
    )
    assert admin_item["readiness"]["capabilities"] == ["certificate_search"]


@pytest.mark.asyncio
async def test_connector_health_reduces_untrusted_readiness_to_the_closed_vocabulary(
    client, auth_headers_viewer, db_session
):
    """A row written before the write-side constraint existed must not put
    provider prose in front of a viewer through the derived fields."""
    conn = Connector(
        name="stale-readiness",
        connector_type="phishing",
        status="enabled",
        default_job_type="phishing.stale-readiness",
        readiness={
            "credentials_configured": "yes",
            "credential_state": "definitely-fine",
            "provider_error": "<html>provider said no</html>",
            "checked_at": 12345,
        },
    )
    db_session.add(conn)
    await db_session.commit()

    response = await client.get("/api/v1/connectors/health", headers=auth_headers_viewer)
    item = next(row for row in response.json()["items"] if row["name"] == conn.name)

    assert item["credentials_configured"] is False
    assert item["credential_state"] == "unknown"
    assert item["provider_error"] is None
    assert item["checked_at"] is None
    # A connector that has never completed a scan has no collection age to report.
    assert item["last_success_at"] is None
    assert item["last_success_age_seconds"] is None


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
