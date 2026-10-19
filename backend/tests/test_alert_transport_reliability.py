import asyncio
import smtplib
import threading
from unittest.mock import MagicMock

import pytest

from app.core.config import settings
from app.core.outbound import pinned_smtp_class
from app.core.safe_errors import sanitize_external_error
from app.services.alert_service import AlertDeliveryAmbiguousError, bounded_smtp


def test_smtp_uses_only_checked_ip_and_keeps_tls_hostname(monkeypatch):
    connected = []
    sock = MagicMock()
    monkeypatch.setattr("app.core.outbound.socket.create_connection", lambda destination, timeout, source: connected.append(destination) or sock)
    transport = pinned_smtp_class(smtplib.SMTP_SSL, ("203.0.113.17",), implicit_tls=True)()
    context = MagicMock()
    transport.context = context
    transport._get_socket("smtp.example.com", 465, 3)
    assert connected == [("203.0.113.17", 465)]
    context.wrap_socket.assert_called_once_with(sock, server_hostname="smtp.example.com")


def test_smtp_never_re_resolves_unresolved_host(monkeypatch):
    connect = MagicMock()
    monkeypatch.setattr("app.core.outbound.socket.create_connection", connect)
    transport = pinned_smtp_class(smtplib.SMTP, ("unresolved.example",))()
    with pytest.raises(OSError, match="DNS resolution unavailable"):
        transport._get_socket("unresolved.example", 587, 3)
    connect.assert_not_called()


@pytest.mark.asyncio
async def test_smtp_timeout_keeps_work_bounded_until_thread_exits(monkeypatch):
    monkeypatch.setattr(settings, "ALERT_DELIVERY_TIMEOUT_SECONDS", 0.02)
    release = threading.Event()
    entered = threading.Event()
    def work():
        entered.set()
        release.wait(2)
    try:
        with pytest.raises(AlertDeliveryAmbiguousError):
            await bounded_smtp(work)
        assert entered.is_set()
        from app.services.alert_service import _SMTP_SLOTS
        acquired = sum(_SMTP_SLOTS.acquire(blocking=False) for _ in range(4))
        assert acquired == 3
        for _ in range(acquired):
            _SMTP_SLOTS.release()
    finally:
        release.set()
        await asyncio.sleep(0.03)


def test_url_credentials_and_telegram_path_are_redacted():
    text = sanitize_external_error("https://user:password@api.telegram.org/bot123456:SECRET/sendMessage?token=OTHER")
    assert "SECRET" not in text and "OTHER" not in text and "user:password" not in text
