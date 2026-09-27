from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import structlog
from sqlalchemy import or_, select

from app.models.settings import SystemSettings
from app.models.user import User
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.safe_errors import sanitize_external_error
from app.models.alert_delivery import AlertDelivery, AlertDeliveryStatus
from app.models.job import Job, JobStatus

log = structlog.get_logger()


class AlertDeliveryService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def _configured_destinations(self) -> list[tuple[str, str | None]]:
        """Return channels that can currently receive a notification.

        Queueing per channel is deliberate: a successful email must not mark a
        Telegram delivery as sent. An installation with no channel configured
        gets an empty list, so nothing is queued and nothing has to be delivered
        later on the strength of settings that did not exist when the finding
        was stored.
        """
        settings_row = (
            await self.db.execute(select(SystemSettings).limit(1))
        ).scalar_one_or_none()
        if settings_row is None:
            return []
        destinations: list[tuple[str, str | None]] = []
        if (
            settings_row.email_alerts_enabled
            and settings_row.smtp_host
            and settings_row.smtp_port
        ):
            email_targets: list[str] = []
            if settings_row.alert_email_user_ids:
                from uuid import UUID

                user_ids = [UUID(str(value)) for value in settings_row.alert_email_user_ids]
                result = await self.db.execute(
                    select(User.email).where(
                        User.id.in_(user_ids), User.is_active.is_(True)
                    )
                )
                email_targets.extend(row[0] for row in result.all())
            if settings_row.alert_recipient_email_decrypted:
                email_targets.append(settings_row.alert_recipient_email_decrypted)
            seen: set[str] = set()
            for target in email_targets:
                key = target.strip().lower()
                if key and key not in seen:
                    seen.add(key)
                    destinations.append(("email", target.strip()))
        if (
            settings_row.telegram_alerts_enabled
            and settings_row.telegram_bot_token
        ):
            telegram_targets = list(settings_row.telegram_chat_ids or [])
            seen_chats: set[str] = set()
            for target in telegram_targets:
                value = str(target).strip()
                if value and value not in seen_chats:
                    seen_chats.add(value)
                    destinations.append(("telegram", value))
        return destinations

    async def enqueue(
        self,
        *,
        threat_type: str,
        details: dict[str, Any],
        job_id=None,
    ) -> AlertDelivery | None:
        """Queue one row per configured destination; ``None`` when there is none.

        Nothing is queued for an installation that has no channel configured:
        the finding is already durable, and a row that no destination can
        satisfy would only be retried into a permanent failure.
        """
        destinations = await self._configured_destinations()
        if not destinations:
            log.warning("alert_delivery_no_channel", threat_type=str(threat_type))
            return None
        next_attempt = datetime.now(timezone.utc) + timedelta(
            seconds=settings.ALERT_AGGREGATION_DELAY_SECONDS
        )
        rows = [
            AlertDelivery(
                job_id=job_id,
                threat_type=str(threat_type)[:100],
                channel=channel,
                target=target,
                payload=details,
                status=AlertDeliveryStatus.pending,
                next_attempt_at=next_attempt,
            )
            for channel, target in destinations
        ]
        self.db.add_all(rows)
        await self.db.flush()
        return rows[0]

    @staticmethod
    def _terminal_job_clause():
        """Only flush a job group after its scan is terminal.

        Keep the locking query rooted exclusively in ``alert_deliveries``. A
        ``FOR UPDATE`` over a nullable side of an outer join is rejected by
        PostgreSQL, so the terminal-job check uses an ``IN`` subquery instead.
        The column is nullable because a delivery may not belong to a job, which
        is why it is checked with ``IN`` rather than joined.
        """
        terminal_jobs = select(Job.id).where(
            Job.status.in_(
                [
                    JobStatus.success.value,
                    JobStatus.partial.value,
                    JobStatus.error.value,
                    JobStatus.cancelled.value,
                    JobStatus.skipped.value,
                ]
            )
        )
        return or_(
            AlertDelivery.job_id.is_(None),
            AlertDelivery.job_id.in_(terminal_jobs),
        )

    async def claim_group(self, *, limit: int = 100) -> list[AlertDelivery]:
        """Claim one due job/threat group atomically for one worker instance."""
        now = datetime.now(timezone.utc)
        stale_before = now - timedelta(minutes=15)
        available = or_(
            AlertDelivery.status == AlertDeliveryStatus.pending,
            (AlertDelivery.status == AlertDeliveryStatus.delivering)
            & (AlertDelivery.locked_at < stale_before),
        )
        due = or_(
            AlertDelivery.next_attempt_at.is_(None),
            AlertDelivery.next_attempt_at <= now,
        )
        first_stmt = (
            select(AlertDelivery)
            .where(available, due, self._terminal_job_clause())
            .order_by(AlertDelivery.created_at.asc(), AlertDelivery.id.asc())
            .limit(1)
        )
        # Do not lock only this representative row. Two workers could then skip
        # each other's representative and claim different rows from the same
        # group. The group query below takes the row locks for the whole group
        # atomically; keeping this lookup unlocked makes concurrent workers pick
        # the same deterministic group instead.
        first = (await self.db.execute(first_stmt)).scalar_one_or_none()
        if first is None:
            return []

        same_job = (
            AlertDelivery.job_id == first.job_id
            if first.job_id is not None
            else AlertDelivery.job_id.is_(None)
        )
        group_stmt = (
            select(AlertDelivery)
            .where(
                AlertDelivery.threat_type == first.threat_type,
                AlertDelivery.channel == first.channel,
                AlertDelivery.target == first.target,
                same_job,
                available,
                due,
                self._terminal_job_clause(),
            )
            .order_by(AlertDelivery.created_at.asc(), AlertDelivery.id.asc())
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        rows = list((await self.db.execute(group_stmt)).scalars().all())
        for row in rows:
            row.status = AlertDeliveryStatus.delivering
            row.locked_at = now
            row.attempts = (row.attempts or 0) + 1
        await self.db.commit()
        return rows

    async def mark_sent(self, rows: list[AlertDelivery]) -> None:
        now = datetime.now(timezone.utc)
        for row in rows:
            row.status = AlertDeliveryStatus.sent
            row.sent_at = now
            row.locked_at = None
            row.last_error = None
        await self.db.commit()

    async def mark_failed(
        self, rows: list[AlertDelivery], error: object, *, max_attempts: int
    ) -> None:
        now = datetime.now(timezone.utc)
        safe_error = sanitize_external_error(error, limit=600)
        for row in rows:
            row.locked_at = None
            row.last_error = safe_error
            if (row.attempts or 0) >= max_attempts:
                row.status = AlertDeliveryStatus.failed
                row.next_attempt_at = None
            else:
                row.status = AlertDeliveryStatus.pending
                delay = min(
                    900,
                    settings.ALERT_DELIVERY_RETRY_BASE_SECONDS
                    * (2 ** max(0, (row.attempts or 1) - 1)),
                )
                row.next_attempt_at = now + timedelta(seconds=delay)
        await self.db.commit()

    @staticmethod
    def _channel_of(row: AlertDelivery) -> Literal["email", "telegram"]:
        """The row's channel in the delivery path's own vocabulary.

        The column is a string, so the value is narrowed here rather than cast:
        a row naming a channel nothing can deliver is a defect, and the delivery
        attempt should say so instead of reaching a sender.
        """
        channel = str(row.channel)
        if channel == "email":
            return "email"
        if channel == "telegram":
            return "telegram"
        raise ValueError(f"unknown alert delivery channel: {channel[:32]!r}")

    async def process_one_group(self, *, max_attempts: int, limit: int = 100) -> dict:
        from app.services.alert_service import AlertService

        rows = await self.claim_group(limit=limit)
        if not rows:
            return {"status": "idle", "count": 0}
        try:
            await AlertService(self.db).send_aggregated_alert_notification(
                threat_type=rows[0].threat_type,
                findings=[row.payload for row in rows],
                job_id=rows[0].job_id,
                channel=self._channel_of(rows[0]),
                target=rows[0].target,
            )
        except Exception as exc:
            await self.mark_failed(rows, exc, max_attempts=max_attempts)
            return {
                "status": "retry" if rows[0].attempts < max_attempts else "failed",
                "count": len(rows),
            }
        await self.mark_sent(rows)
        return {"status": "sent", "count": len(rows)}
