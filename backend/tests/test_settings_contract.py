"""The settings payload's refusals, named by field.

Coverage batch 02. `test_settings_validators.py` checks the values an operator
is likely to type; this suite walks the branches that exist so a bad payload is
refused *before* storage, and asserts the message names the field rather than
saying "invalid input". The distinction is operational: a 422 that does not name
the field sends the reader back to the whole form, and a validator that silently
normalises a malformed value writes something nobody chose.

Every case here is a pure schema call — no database, no route — because that is
the boundary that owns the rule.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schemas.settings import (
    SystemSettingsResponse,
    SystemSettingsUpdate,
    TestTelegramRequest as TelegramProbeRequest,
)


def _rejects(payload: dict, field: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        SystemSettingsUpdate(**payload)
    assert field in str(exc_info.value), str(exc_info.value)


class TestAbsentFields:
    def test_an_explicit_none_is_accepted_by_every_optional_field(self):
        settings = SystemSettingsUpdate(
            telegram_bot_token=None,
            smtp_host=None,
            smtp_user=None,
            smtp_password=None,
            smtp_from_email=None,
            alert_email_user_ids=None,
            telegram_chat_ids=None,
        )
        assert settings.telegram_bot_token is None
        assert settings.smtp_host is None
        assert settings.smtp_user is None
        assert settings.smtp_password is None
        assert settings.smtp_from_email is None
        assert settings.alert_email_user_ids is None
        assert settings.telegram_chat_ids is None


class TestSmtpFields:
    def test_the_security_mode_is_normalised_and_unknown_modes_are_named(self):
        assert SystemSettingsUpdate(smtp_security_mode="  SSL ").smtp_security_mode == "ssl"
        _rejects({"smtp_security_mode": "tls"}, "smtp_security_mode")

    def test_empty_optional_strings_become_absent(self):
        assert SystemSettingsUpdate(smtp_host="   ").smtp_host is None
        assert SystemSettingsUpdate(smtp_user="").smtp_user is None
        assert SystemSettingsUpdate(smtp_password="").smtp_password is None

    def test_a_port_must_be_an_integer_in_range(self):
        _rejects({"smtp_port": True}, "smtp_port")
        _rejects({"smtp_port": 1.5}, "smtp_port")
        _rejects({"smtp_port": "not-a-port"}, "smtp_port")
        _rejects({"smtp_port": 0}, "smtp_port")

    def test_smtp_credentials_have_length_bounds(self):
        _rejects({"smtp_user": "u" * 256}, "smtp_user")
        _rejects({"smtp_password": "p" * 513}, "smtp_password")

    def test_an_address_must_be_a_string_that_parses(self):
        _rejects({"smtp_from_email": 123}, "email address must be a string")
        _rejects({"smtp_from_email": "not-an-address"}, "valid email address required")
        _rejects({"alert_recipient_email": "still-not-an-address"}, "valid email address required")


class TestRecipients:
    def test_the_email_recipient_list_is_validated_and_deduplicated(self):
        one = uuid.uuid4()
        parsed = SystemSettingsUpdate(
            alert_email_user_ids=[str(one), str(one)]
        ).alert_email_user_ids
        assert parsed == [str(one)]

        _rejects({"alert_email_user_ids": "not-a-list"}, "alert_email_user_ids")
        _rejects({"alert_email_user_ids": ["not-a-uuid"]}, "invalid user id")
        _rejects(
            {"alert_email_user_ids": [str(uuid.uuid4()) for _ in range(101)]},
            "at most 100",
        )

    def test_the_telegram_list_accepts_a_blob_and_drops_blank_entries(self):
        parsed = SystemSettingsUpdate(
            telegram_chat_ids=" @opendrp_alerts , -1001234567890 \n, "
        ).telegram_chat_ids
        assert parsed == ["@opendrp_alerts", "-1001234567890"]

        _rejects({"telegram_chat_ids": ["not a chat id!"]}, "telegram_chat_ids")

    def test_a_telegram_probe_address_is_optional_string(self):
        assert TelegramProbeRequest(chat_id=None).chat_id is None
        assert TelegramProbeRequest(chat_id="   ").chat_id is None
        with pytest.raises(ValidationError) as exc_info:
            TelegramProbeRequest(chat_id=123)
        assert "chat_id must be a string" in str(exc_info.value)


class TestSchedules:
    def test_a_dedicated_schedule_refuses_the_wrong_shape(self):
        assert SystemSettingsUpdate(schedule_phishing=None).schedule_phishing is None
        _rejects(
            {"schedule_phishing": {"days": [1], "hour": 1}},
            "schedule: expected days, hour and minute only",
        )
        _rejects(
            {"schedule_phishing": {"days": [], "hour": 1, "minute": 0}},
            "schedule.days",
        )
        _rejects(
            {"schedule_phishing": {"days": [1], "hour": 1, "minute": 60}},
            "schedule.minute",
        )

    def test_the_module_map_accepts_absent_specs_and_refuses_bad_ones(self):
        assert SystemSettingsUpdate(schedules=None).schedules is None
        assert SystemSettingsUpdate(schedules={"custom": None}).schedules == {
            "custom": None
        }
        _rejects(
            {"schedules": {"phishing": {"days": [1], "hour": 1, "minute": 0}}},
            "Built-in schedules",
        )
        _rejects({"schedules": {"Bad ID": None}}, "invalid module id")
        _rejects(
            {"schedules": {"custom": {"days": [1], "hour": 1}}},
            "expected days, hour, and minute",
        )
        _rejects(
            {"schedules": {"custom": {"days": [7], "hour": 1, "minute": 0}}},
            "weekday list",
        )
        _rejects(
            {"schedules": {"custom": {"days": [1], "hour": 1, "minute": -1}}},
            "minute",
        )
        _rejects(
            {"schedules": {"custom": {"days": [1], "hour": 24, "minute": 0}}},
            "hour",
        )

    def test_a_valid_module_schedule_is_normalised(self):
        parsed = SystemSettingsUpdate(
            schedules={"custom": {"days": [2, 1, 2], "hour": 3, "minute": 4}}
        ).schedules
        assert parsed == {"custom": {"days": [1, 2], "hour": 3, "minute": 4}}

    def test_a_dedicated_schedule_is_normalised(self):
        parsed = SystemSettingsUpdate(
            schedule_breaches={"days": [6, 0, 6], "hour": 23, "minute": 59}
        ).schedule_breaches
        assert parsed == {"days": [0, 6], "hour": 23, "minute": 59}

        _rejects(
            {"schedule_dns_security": {"days": [1], "hour": 24, "minute": 0}},
            "schedule.hour",
        )

    def test_the_module_map_is_bounded(self):
        _rejects(
            {"schedules": {f"custom{index}": None for index in range(101)}},
            "at most 100",
        )


class TestResponseShape:
    def test_a_persisted_dict_passes_through_untouched(self):
        """The response validator must not decrypt what is already a dict."""
        now = datetime.now(timezone.utc)
        response = SystemSettingsResponse.model_validate(
            {
                "id": uuid.uuid4(),
                "version": 1,
                "created_at": now,
                "updated_at": now,
                "smtp_host": "mail.example.com",
            }
        )
        assert response.smtp_host == "mail.example.com"
