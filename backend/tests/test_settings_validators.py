"""
Tests for SystemSettings secure input validators added in Secure by Design
Rule 2 upgrade. Covers Shodan / HIBP keys, the Telegram bot token and chat list
(including the removed single-chat field), and SMTP host/user/password.
"""

import pytest
from pydantic import ValidationError

from app.schemas.settings import SystemSettingsUpdate, _validate_hostname_or_ip


class TestHostnameOrIpHelper:
    def test_valid_domain_ok(self):
        assert _validate_hostname_or_ip("smtp.example.com", "smtp_host") == "smtp.example.com"

    def test_valid_ipv4_ok(self):
        assert _validate_hostname_or_ip("127.0.0.1", "smtp_host") == "127.0.0.1"

    def test_valid_ipv6_ok(self):
        assert _validate_hostname_or_ip("::1", "smtp_host") == "::1"

    def test_invalid_hostname_raises(self):
        with pytest.raises(ValueError, match="invalid hostname or IP address"):
            _validate_hostname_or_ip("not a valid name!!", "smtp_host")

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            _validate_hostname_or_ip("   ", "smtp_host")



class TestTelegramBotTokenValidator:
    def test_valid_format(self):
        tok = "123456789:ABCDEFGHijklmnopQRSTUVWxyz1234567890"
        s = SystemSettingsUpdate(telegram_bot_token=tok)
        assert s.telegram_bot_token == tok

    def test_masked_token_passes(self):
        tok = "12****************90"
        s = SystemSettingsUpdate(telegram_bot_token=tok)
        assert s.telegram_bot_token == tok

    def test_missing_colon_raises(self):
        with pytest.raises(ValidationError):
            SystemSettingsUpdate(telegram_bot_token="not-a-bot-token")


class TestRemovedLegacyChatIdField:
    """The v0.1.0 removal, pinned at the schema boundary.

    ``SystemSettingsUpdate`` forbids unknown keys, so a payload written against
    the older single-chat contract fails loudly rather than being accepted and
    ignored. An operator told "saved" while their chat ID goes nowhere is worse
    than an error naming the field to move.
    """

    def test_the_legacy_single_chat_field_is_rejected(self):
        with pytest.raises(ValidationError):
            SystemSettingsUpdate(telegram_chat_id="-1001234567890")

    def test_the_chat_list_is_the_accepted_shape(self):
        s = SystemSettingsUpdate(telegram_chat_ids=["-1001234567890", "@opendrp_alerts"])
        assert s.telegram_chat_ids == ["-1001234567890", "@opendrp_alerts"]


class TestSmtpValidators:
    def test_smtp_host_domain(self):
        s = SystemSettingsUpdate(smtp_host="mail.corp.example")
        assert s.smtp_host == "mail.corp.example"

    def test_smtp_host_ipv4(self):
        s = SystemSettingsUpdate(smtp_host="10.0.0.25")
        assert s.smtp_host == "10.0.0.25"

    def test_smtp_host_invalid_raise(self):
        with pytest.raises(ValidationError):
            SystemSettingsUpdate(smtp_host="bad host name")

    def test_smtp_port_valid(self):
        s = SystemSettingsUpdate(smtp_port=465)
        assert s.smtp_port == 465

    def test_smtp_port_out_of_range_raise(self):
        with pytest.raises(ValidationError):
            SystemSettingsUpdate(smtp_port=99999)

    def test_smtp_user_control_chars_rejected(self):
        with pytest.raises(ValidationError):
            SystemSettingsUpdate(smtp_user="inject\x00user\r\n")

    def test_smtp_password_nul_rejected(self):
        with pytest.raises(ValidationError):
            SystemSettingsUpdate(smtp_password="pass\x00word")
