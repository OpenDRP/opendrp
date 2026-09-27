"""Tests for alert channel routing (Part 2) and scan schedules (Part 3)."""

import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.alert_service import AlertService


def _settings(**kw):
    s = MagicMock()
    s.email_alerts_enabled = kw.get("email_alerts_enabled", False)
    s.telegram_alerts_enabled = kw.get("telegram_alerts_enabled", False)
    s.alert_email_user_ids = kw.get("alert_email_user_ids", None)
    s.telegram_chat_ids = kw.get("telegram_chat_ids", None)
    s.alert_recipient_email_decrypted = kw.get("alert_recipient_email_decrypted", None)
    s.telegram_bot_token_decrypted = kw.get("telegram_bot_token_decrypted", None)
    s.smtp_host = None
    s.smtp_port = 587
    s.smtp_user = None
    s.smtp_password_decrypted = None
    s.smtp_from_email_decrypted = None
    return s


class TestRecipientResolution:
    @pytest.mark.asyncio
    async def test_email_channel_disabled_yields_empty(self, db_session):
        s = _settings(email_alerts_enabled=False, alert_recipient_email_decrypted="a@b.c")
        assert await AlertService(db_session)._resolve_email_recipients(s) == []

    @pytest.mark.asyncio
    async def test_email_recipients_deduped_users_plus_custom(self, db_session):
        from app.models.user import User, UserRole

        u1 = User(email=f"dup-{uuid.uuid4().hex[:6]}@example.com", password_hash="x", role=UserRole.viewer)
        u2 = User(email=f"ana-{uuid.uuid4().hex[:6]}@example.com", password_hash="x", role=UserRole.analyst)
        db_session.add_all([u1, u2])
        await db_session.commit()
        await db_session.refresh(u1)
        await db_session.refresh(u2)

        s = _settings(
            email_alerts_enabled=True,
            alert_email_user_ids=[str(u1.id), str(u2.id), str(u1.id)],  # duplicate
            alert_recipient_email_decrypted=u1.email.upper(),  # same as u1 after normalize
        )
        out = await AlertService(db_session)._resolve_email_recipients(s)
        lowered = [r.lower() for r in out]
        assert len(out) == 2
        assert u1.email.lower() in lowered
        assert u2.email.lower() in lowered

    def test_telegram_chats_disabled_yields_empty(self, db_session):
        s = _settings(telegram_alerts_enabled=False, telegram_chat_ids=["-1001", "-1002"])
        assert AlertService(db_session)._resolve_telegram_chats(s) == []

    def test_telegram_chats_deduped(self, db_session):
        s = _settings(
            telegram_alerts_enabled=True,
            telegram_chat_ids=["-1001", "@ops", "-1001"],
        )
        assert AlertService(db_session)._resolve_telegram_chats(s) == ["-1001", "@ops"]


class TestAlertFanOut:
    """Fan-out is one queue row per destination, resolved when it is queued.

    Queueing per channel and per target is what makes a successful email and a
    failed Telegram message two lifecycles instead of one: the email is not
    retried because a chat ID was wrong.
    """

    @staticmethod
    def _row(**overrides):
        return _settings(**overrides)

    @staticmethod
    async def _configured(db_session, **overrides):
        """Store a settings row and return the destinations it resolves to."""
        from app.models.settings import SystemSettings
        from app.services.alert_delivery_service import AlertDeliveryService

        row = SystemSettings(
            email_alerts_enabled=bool(overrides.get("email_alerts_enabled")),
            telegram_alerts_enabled=bool(overrides.get("telegram_alerts_enabled")),
            smtp_host=overrides.get("smtp_host"),
            smtp_port=overrides.get("smtp_port"),
            alert_email_user_ids=[],
            telegram_chat_ids=overrides.get("telegram_chat_ids"),
        )
        if overrides.get("alert_recipient_email_decrypted"):
            row.alert_recipient_email_decrypted = overrides["alert_recipient_email_decrypted"]
        if overrides.get("telegram_bot_token_decrypted"):
            row.telegram_bot_token_decrypted = overrides["telegram_bot_token_decrypted"]
        db_session.add(row)
        await db_session.commit()
        return await AlertDeliveryService(db_session)._configured_destinations()

    @pytest.mark.asyncio
    async def test_each_chat_and_recipient_gets_its_own_row(self, db_session):
        destinations = await self._configured(
            db_session,
            email_alerts_enabled=True,
            alert_recipient_email_decrypted="soc@example.com",
            telegram_alerts_enabled=True,
            telegram_chat_ids=["-1001", "-1002"],
            telegram_bot_token_decrypted="TOKEN",
            smtp_host="smtp.example",
            smtp_port=587,
        )

        assert destinations == [
            ("email", "soc@example.com"),
            ("telegram", "-1001"),
            ("telegram", "-1002"),
        ]

    @pytest.mark.asyncio
    async def test_channels_off_queue_nothing(self, db_session):
        """A finding is already stored; a row no destination can satisfy would
        only be retried into a permanent failure."""
        from app.services.alert_delivery_service import AlertDeliveryService

        assert await self._configured(db_session) == []

        queued = await AlertDeliveryService(db_session).enqueue(
            threat_type="phishing", details={"phishing_domain": "evil.example"}
        )

        assert queued is None

    @pytest.mark.asyncio
    async def test_one_chat_failing_is_retried_without_touching_the_email(self, db_session, monkeypatch):
        service = AlertService(db_session)
        service._audit_alert = AsyncMock()
        monkeypatch.setattr(
            service,
            "_get_settings",
            AsyncMock(
                return_value=self._row(
                    telegram_alerts_enabled=True,
                    telegram_chat_ids=["-bad", "-good"],
                    telegram_bot_token_decrypted="TOKEN",
                )
            ),
        )
        email = AsyncMock(return_value=True)
        monkeypatch.setattr(service, "_send_email_smtp", email)
        calls: list[str | None] = []

        async def tg_side_effect(text, parse_mode="HTML", chat_id=None):
            calls.append(chat_id)
            if chat_id == "-bad":
                raise RuntimeError("TG 400: chat not found")
            return True

        monkeypatch.setattr(service, "_send_telegram", tg_side_effect)

        # Two rows, as the queue claims them: the bad chat is retried on its own,
        # and the good one is never resent.
        with pytest.raises(RuntimeError):
            await service.send_aggregated_alert_notification(
                threat_type="phishing",
                findings=[{"phishing_domain": "evil.example"}],
                channel="telegram",
                target="-bad",
            )
        assert await service.send_aggregated_alert_notification(
            threat_type="phishing",
            findings=[{"phishing_domain": "evil.example"}],
            channel="telegram",
            target="-good",
        ) == {"sent": 1, "failed": 0, "total": 1, "findings": 1}

        assert calls == ["-bad", "-good"]
        email.assert_not_awaited()


class TestScheduleMatcher:
    def test_matches_weekday_hour_minute(self):
        from app.tasks.scheduler_tasks import schedule_matches
        # 2026-09-07 is a Monday (cron dow=1)
        now = datetime(2026, 9, 7, 2, 30)
        spec = {"days": [1, 2, 3, 4, 5], "hour": 2, "minute": 30}
        assert schedule_matches(spec, now) is True

    def test_no_match_wrong_minute(self):
        from app.tasks.scheduler_tasks import schedule_matches
        now = datetime(2026, 9, 7, 2, 31)
        spec = {"days": [1, 2, 3, 4, 5], "hour": 2, "minute": 30}
        assert schedule_matches(spec, now) is False

    def test_no_match_weekend(self):
        from app.tasks.scheduler_tasks import schedule_matches
        # 2026-09-06 is a Sunday
        now = datetime(2026, 9, 6, 2, 30)
        spec = {"days": [1, 2, 3, 4, 5], "hour": 2, "minute": 30}
        assert schedule_matches(spec, now) is False

    def test_sunday_is_zero_and_saturday_is_six(self):
        from app.tasks.scheduler_tasks import schedule_matches
        sunday = datetime(2026, 9, 6, 22, 0)
        assert schedule_matches({"days": [0], "hour": 22, "minute": 0}, sunday) is True
        saturday = datetime(2026, 9, 12, 22, 0)
        assert schedule_matches({"days": [6], "hour": 22, "minute": 0}, saturday) is True

    def test_invalid_spec_is_never_matched(self):
        from app.tasks.scheduler_tasks import schedule_matches
        now = datetime(2026, 9, 7, 2, 30)
        assert schedule_matches({}, now) is False
        assert schedule_matches({"days": [], "hour": 1, "minute": 0}, now) is False
        assert schedule_matches({"days": [1], "hour": "x", "minute": 0}, now) is False


class TestSchedulerTask:
    @pytest.fixture
    async def seeded_connectors(self, db_session):
        """Register one enabled connector per module for scheduler tests."""
        from app.models import Connector

        rows = [
            Connector(name="dnstwist", connector_type="phishing", default_job_type="phishing.dnstwist"),
            Connector(name="hibp", connector_type="breaches", default_job_type="breaches.hibp"),
        ]
        db_session.add_all(rows)
        await db_session.commit()
        yield rows
        for r in rows:
            await db_session.delete(r)
        await db_session.commit()

    @pytest.mark.asyncio
    async def test_fires_module_tasks_when_matching(self, db_session, seeded_connectors):
        from app.tasks import scheduler_tasks as st

        with patch.object(st, "_load_schedules", new_callable=AsyncMock, return_value={
            "schedule_phishing": {"days": [1, 2, 3, 4, 5], "hour": 2, "minute": 30},
            "schedule_breaches": {"days": [1, 2, 3, 4, 5], "hour": 3, "minute": 30},
        }), patch.object(st, "_try_acquire_dedup", return_value=True) as dedup:
            res = await st.refresh_scan_schedules_task.run.__wrapped__(None, datetime(2026, 9, 7, 2, 30))
            # Phishing schedule matched: one job for the dnstwist connector.
            assert any(f.startswith("phishing:") for f in res["fired"])
            assert not any(f.startswith("breaches:") for f in res["fired"])  # breaches schedule doesn't match
            assert dedup.call_count == 1

    @pytest.mark.asyncio
    async def test_dedup_prevents_double_fire(self, db_session, seeded_connectors):
        from app.tasks import scheduler_tasks as st

        with patch.object(st, "_load_schedules", new_callable=AsyncMock, return_value={
            "schedule_phishing": {"days": [1, 2, 3, 4, 5], "hour": 2, "minute": 30},
            "schedule_breaches": None,
        }), patch.object(st, "_try_acquire_dedup", return_value=False):
            res = await st.refresh_scan_schedules_task.run.__wrapped__(None, datetime(2026, 9, 7, 2, 30))
            assert res["fired"] == []


class TestSettingsRoundTrip:
    @pytest.mark.asyncio
    async def test_update_schedules_and_channels(self, db_session):
        from app.schemas.settings import SystemSettingsUpdate
        from app.services.settings_service import SettingsService

        s = await SettingsService(db_session).get_singleton()
        upd = SystemSettingsUpdate(
            email_alerts_enabled=True,
            telegram_alerts_enabled=True,
            telegram_chat_ids=["-100999", "@soc_team"],
            schedule_phishing={"days": [1, 3, 5], "hour": 1, "minute": 15},
            schedule_breaches={"days": [0, 6], "hour": 22, "minute": 0},
        )
        saved = await SettingsService(db_session).update_settings(s, upd)
        assert saved.email_alerts_enabled is True
        assert saved.telegram_alerts_enabled is True
        assert saved.telegram_chat_ids == ["-100999", "@soc_team"]
        assert saved.schedule_phishing == {"days": [1, 3, 5], "hour": 1, "minute": 15}
        assert saved.schedule_breaches == {"days": [0, 6], "hour": 22, "minute": 0}

        # restore via ORM (portable across SQLite/Postgres test DBs)
        saved.email_alerts_enabled = False
        saved.telegram_alerts_enabled = False
        saved.telegram_chat_ids = []
        saved.schedule_phishing = {"days": [1, 2, 3, 4, 5], "hour": 2, "minute": 30}
        saved.schedule_breaches = {"days": [1, 2, 3, 4, 5], "hour": 3, "minute": 30}
        await db_session.commit()

    def test_invalid_schedule_rejected(self):
        from pydantic import ValidationError

        from app.schemas.settings import SystemSettingsUpdate

        with pytest.raises(ValidationError):
            SystemSettingsUpdate(schedule_phishing={"days": [7], "hour": 1, "minute": 0})
        with pytest.raises(ValidationError):
            SystemSettingsUpdate(schedule_breaches={"days": [1], "hour": 24, "minute": 0})
        with pytest.raises(ValidationError):
            SystemSettingsUpdate(telegram_chat_ids=["not a chat id!"])

    def test_chat_ids_accept_blob_string(self):
        from app.schemas.settings import SystemSettingsUpdate

        upd = SystemSettingsUpdate(telegram_chat_ids="-1001\n@ops_chat, -1002")
        assert upd.telegram_chat_ids == ["-1001", "@ops_chat", "-1002"]
