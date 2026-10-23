from __future__ import annotations

import asyncio
import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import structlog
from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from app.models.settings import SystemSettings
from app.models.user import User
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.safe_errors import sanitize_external_error
from app.models.alert_delivery import AlertDelivery, AlertDeliveryStatus, AlertRecipientState
from app.models.job import Job, JobStatus

log = structlog.get_logger()


class AlertDeliveryService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.tokens: dict[uuid.UUID, str] = {}

    @staticmethod
    def recipient_key(channel, target):
        return hashlib.sha256(f"{channel}:{str(target).lower()}".encode()).hexdigest()

    async def _recipient(self, channel, target):
        key = self.recipient_key(channel, target)
        factory = sqlite_insert if self.db.get_bind().dialect.name == "sqlite" else pg_insert
        await self.db.execute(factory(AlertRecipientState).values(key=key).on_conflict_do_nothing())
        return (await self.db.execute(select(AlertRecipientState).where(AlertRecipientState.key == key).with_for_update(skip_locked=True).execution_options(populate_existing=True))).scalar_one_or_none()

    async def _configured_destinations(self) -> list[tuple[str, str | None]]:
        """Return channels that can currently receive a notification.

        Queueing per channel is deliberate: a successful email must not mark a
        Telegram delivery as sent. An installation with no channel configured
        gets an empty list, so nothing is queued and nothing has to be delivered
        later on the strength of settings that did not exist when the finding
        was stored.
        """
        settings_row = (
            await self.db.execute(select(SystemSettings).where(SystemSettings.singleton_key == 1).execution_options(populate_existing=True))
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
        from app.services.alert_content import safe_snapshot
        for row in rows:
            row.payload = safe_snapshot(row.payload)
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
        await self._end_expired_holds(now)
        # Lost workers may have reached the provider; never automatically replay
        # an unacknowledged acceptance. Expose ambiguity for reconciliation.
        stale = (await self.db.execute(select(AlertDelivery.channel, AlertDelivery.target, AlertDelivery.lease_token).where(AlertDelivery.status == AlertDeliveryStatus.delivering, AlertDelivery.locked_at < stale_before))).all()
        hold_until = now + timedelta(seconds=settings.ALERT_RECIPIENT_HOLD_SECONDS)
        for channel, target, owner in stale:
            if owner:
                # The worker that held this recipient is gone, and its message may
                # or may not have reached the provider. Release the lease but put
                # the recipient on the same bounded hold an ambiguous delivery
                # gets, so the queue resumes by itself once the window passes
                # instead of waiting for an operator who may never arrive.
                await self.db.execute(update(AlertRecipientState).where(AlertRecipientState.key == self.recipient_key(channel, target), AlertRecipientState.lease_token == owner).values(lease_token=None, lease_expires_at=None, next_send_at=hold_until))
        await self.db.execute(update(AlertDelivery).where(AlertDelivery.status == AlertDeliveryStatus.delivering, AlertDelivery.locked_at < stale_before).values(status=AlertDeliveryStatus.ambiguous, last_error="Worker lease expired; provider acceptance unknown"))
        available = AlertDelivery.status == AlertDeliveryStatus.pending
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
            await self.db.commit()
            return []
        recipient = await self._recipient(first.channel, first.target)
        if recipient is None:
            await self.db.rollback()
            return []
        expiry = recipient.lease_expires_at
        next_send = recipient.next_send_at
        if recipient.lease_token and (expiry is None or expiry.replace(tzinfo=timezone.utc) > now):
            # Defer only this recipient so the next tick can serve other targets;
            # an ambiguous recipient must not indefinitely starve the queue head.
            first.next_attempt_at = now + timedelta(seconds=30)
            await self.db.commit()
            return []
        if next_send and next_send.replace(tzinfo=timezone.utc) > now:
            first.next_attempt_at = next_send
            await self.db.commit()
            return []
        token = uuid.uuid4().hex
        recipient.lease_token = token
        recipient.lease_expires_at = now + timedelta(minutes=15)

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
                AlertDelivery.batch_id == first.batch_id if first.batch_id else AlertDelivery.batch_id.is_(None),
            )
            .order_by(AlertDelivery.created_at.asc(), AlertDelivery.id.asc())
            .limit(None if first.batch_id else limit)
            .with_for_update(skip_locked=True)
        )
        rows = list((await self.db.execute(group_stmt)).scalars().all())
        batch_id = first.batch_id or uuid.uuid4().hex
        for row in rows:
            row.lease_token = token
            row.batch_id = batch_id
            self.tokens[row.id] = token
            row.status = AlertDeliveryStatus.delivering
            row.locked_at = now
            row.attempts = (row.attempts or 0) + 1
        await self.db.commit()
        return rows

    async def _finish(self, rows, values, token=None):
        if not rows:
            return
        owner = token or self.tokens.get(rows[0].id)
        predicate = AlertDelivery.lease_token == owner if owner else AlertDelivery.lease_token.is_(None)
        await self.db.flush()
        await self.db.execute(update(AlertDelivery).where(AlertDelivery.id.in_([row.id for row in rows]), predicate, AlertDelivery.status == AlertDeliveryStatus.delivering).values(**values).execution_options(synchronize_session="fetch"))
        if owner:
            recipient_values = {"lease_token": None, "lease_expires_at": None}
            if values.get("status") == AlertDeliveryStatus.ambiguous:
                # The recipient's window is the hold, and `claim_group` ends it:
                # the alerts view offers an operator an early release too, once
                # they have reconciled the delivery with the recipient.
                recipient_values["next_send_at"] = datetime.now(timezone.utc) + timedelta(
                    seconds=settings.ALERT_RECIPIENT_HOLD_SECONDS
                )
            if values.get("next_attempt_at") is not None:
                recipient_values["next_send_at"] = values["next_attempt_at"]
            await self.db.execute(update(AlertRecipientState).where(AlertRecipientState.key == self.recipient_key(rows[0].channel, rows[0].target), AlertRecipientState.lease_token == owner).values(**recipient_values))
        await self.db.commit()
        for row in rows:
            await self.db.refresh(row)
        await self.db.commit()

    async def mark_sent(self, rows: list[AlertDelivery], *, token=None) -> None:
        await self._finish(rows, dict(status=AlertDeliveryStatus.sent, sent_at=datetime.now(timezone.utc), locked_at=None, lease_token=None, last_error=None), token)

    async def mark_failed(
        self, rows: list[AlertDelivery], error: object, *, max_attempts: int
    ) -> None:
        now = datetime.now(timezone.utc)
        safe_error = sanitize_external_error(error, limit=600)
        from app.services.alert_service import AlertDeliveryPermanentError, AlertDeliveryCancelledError, AlertDeliveryAmbiguousError
        if not rows:
            return
        attempts = max(row.attempts or 0 for row in rows)
        status = AlertDeliveryStatus.pending
        if isinstance(error, AlertDeliveryCancelledError):
            status = AlertDeliveryStatus.cancelled
        elif isinstance(error, AlertDeliveryAmbiguousError):
            status = AlertDeliveryStatus.ambiguous
        elif isinstance(error, AlertDeliveryPermanentError) or attempts >= max_attempts:
            status = AlertDeliveryStatus.failed
        delay = max(float(getattr(error, "retry_after", 0) or 0), min(900, settings.ALERT_DELIVERY_RETRY_BASE_SECONDS * 2 ** max(0, attempts - 1)))
        await self._finish(rows, dict(status=status, locked_at=None, lease_token=None, last_error=safe_error, next_attempt_at=now + timedelta(seconds=delay) if status == AlertDeliveryStatus.pending else None))

    async def _end_expired_holds(self, now: datetime) -> int:
        """Return the deliveries of a run-out hold to the queue.

        The hold lives on the recipient (`ALERT_RECIPIENT_HOLD_SECONDS`) and the
        delivery rows of an ambiguous send stay `ambiguous` while it lasts. A
        window that expired without requeueing anything would silence the
        recipient for good — the outcome the hold replaced — so the expiry is
        applied here, where the worker decides what is deliverable, and not left
        to an operator who may never arrive. `release_recipient` is the same
        edit, made early by hand.

        The keys are recomputed in Python because a recipient's key is a digest
        of its channel and target, which only this class can derive; the rows it
        works on are the ambiguous ones, a set bounded by the holds themselves.
        """
        expired = (
            await self.db.execute(
                select(AlertRecipientState)
                .where(
                    AlertRecipientState.next_send_at.is_not(None),
                    AlertRecipientState.next_send_at <= now,
                    # A live lease is a worker sending at this instant: its hold is
                    # not over, it is being served.
                    or_(
                        AlertRecipientState.lease_token.is_(None),
                        and_(
                            AlertRecipientState.lease_expires_at.is_not(None),
                            AlertRecipientState.lease_expires_at <= now,
                        ),
                    ),
                )
                .limit(100)
                .with_for_update(skip_locked=True)
                .execution_options(populate_existing=True)
            )
        ).scalars().all()
        if not expired:
            return 0

        keys = {recipient.key for recipient in expired}
        ambiguous = (
            await self.db.execute(
                select(AlertDelivery).where(
                    AlertDelivery.status == AlertDeliveryStatus.ambiguous
                ).with_for_update(skip_locked=True)
            )
        ).scalars().all()
        requeued = 0
        for row in ambiguous:
            if self.recipient_key(row.channel, row.target) not in keys:
                continue
            row.status = AlertDeliveryStatus.pending
            row.next_attempt_at = None
            row.last_error = None
            requeued += 1
        for recipient in expired:
            recipient.next_send_at = None
        # Committed here rather than left to the caller: the claim below reads
        # the queue through a fresh query, and a requeue nothing can see is a
        # hold that did not end.
        await self.db.commit()
        if requeued:
            log.info(
                "alert_hold_expired",
                recipients=len(keys),
                requeued_deliveries=requeued,
            )
        return requeued

    @staticmethod
    def _as_utc(value: datetime | None) -> datetime | None:
        """A stored timestamp as UTC. SQLite hands naive datetimes back."""
        if value is None or value.tzinfo is not None:
            return value
        return value.replace(tzinfo=timezone.utc)

    async def _ambiguous_deliveries(self, key: str, *, lock: bool = False) -> list[AlertDelivery]:
        """One recipient's deliveries whose outcome is unknown.

        Recovered from ``channel`` and ``target`` rather than stored on the
        recipient row: the row holds only the digest of the pair, and a second
        copy of the pair would be a second source of truth for it.
        """
        statement = select(AlertDelivery).where(
            AlertDelivery.status == AlertDeliveryStatus.ambiguous
        )
        if lock:
            statement = statement.with_for_update()
        rows = (await self.db.execute(statement)).scalars().all()
        return [row for row in rows if self.recipient_key(row.channel, row.target) == key]

    async def channel_delivery_summary(
        self, *, stuck_after_seconds: int
    ) -> tuple[dict[str, dict[str, Any]], int]:
        """Per-channel delivery counters, and the recipients currently waiting.

        A probe answers "can this installation reach the provider?", not "are the
        messages leaving?". The queue is a second, independent fact: a channel can
        pass its probe while every notification sits behind a hold. These numbers
        are what lets the health card say which one is true.

        Numbers only — no target, batch id or recipient digest leaves this
        method, so the same aggregate is safe for a viewer. A delivery counts as
        *stuck* when it is ``ambiguous`` or ``failed`` and older than the
        recipient-hold window; that is the age at which the queue has stopped
        being able to resolve it by itself (D10).

        Returns ``(by_channel, waiting_recipients)``. A recipient is waiting when
        its next send is in the future: either an ambiguous hold or an ordinary
        retry window. A live lease is a send in progress, not a wait.
        """
        now = datetime.now(timezone.utc)
        unresolved = (
            AlertDeliveryStatus.pending,
            AlertDeliveryStatus.delivering,
            AlertDeliveryStatus.ambiguous,
            AlertDeliveryStatus.failed,
        )
        statuses = (
            AlertDeliveryStatus.pending,
            AlertDeliveryStatus.delivering,
            AlertDeliveryStatus.sent,
            AlertDeliveryStatus.failed,
            AlertDeliveryStatus.cancelled,
            AlertDeliveryStatus.ambiguous,
        )
        rows = (
            await self.db.execute(
                select(
                    AlertDelivery.channel,
                    AlertDelivery.status,
                    func.count(AlertDelivery.id),
                    func.min(AlertDelivery.created_at),
                ).group_by(AlertDelivery.channel, AlertDelivery.status)
            )
        ).all()

        by_channel: dict[str, dict[str, Any]] = {}
        for channel, status, count, oldest in rows:
            summary = by_channel.setdefault(
                str(channel),
                {
                    "counts": {name: 0 for name in statuses},
                    "oldest_unresolved_at": None,
                },
            )
            if status in summary["counts"]:
                summary["counts"][status] = int(count)
            if status in unresolved and oldest is not None:
                if oldest.tzinfo is None:
                    # SQLite hands back naive values for a timezone-aware column.
                    oldest = oldest.replace(tzinfo=timezone.utc)
                current = summary["oldest_unresolved_at"]
                if current is None or oldest < current:
                    summary["oldest_unresolved_at"] = oldest

        cutoff = now - timedelta(seconds=stuck_after_seconds)
        stuck_rows = (
            await self.db.execute(
                select(AlertDelivery.channel, func.count(AlertDelivery.id))
                .where(
                    AlertDelivery.status.in_(
                        [AlertDeliveryStatus.ambiguous, AlertDeliveryStatus.failed]
                    ),
                    AlertDelivery.created_at < cutoff,
                )
                .group_by(AlertDelivery.channel)
            )
        ).all()
        stuck_by_channel = {str(channel): int(count) for channel, count in stuck_rows}

        # A retry window is a delivery the queue will attempt again by itself;
        # counting it separately is what lets the card say "waiting to retry"
        # instead of lumping it in with rows that are due now.
        retry_rows = (
            await self.db.execute(
                select(AlertDelivery.channel, func.count(AlertDelivery.id))
                .where(
                    AlertDelivery.status.in_(
                        [AlertDeliveryStatus.pending, AlertDeliveryStatus.failed]
                    ),
                    AlertDelivery.next_attempt_at > now,
                )
                .group_by(AlertDelivery.channel)
            )
        ).all()
        retrying_by_channel = {str(channel): int(count) for channel, count in retry_rows}

        waiting = (
            await self.db.execute(
                select(func.count())
                .select_from(AlertRecipientState)
                .where(AlertRecipientState.next_send_at > now)
            )
        ).scalar_one()

        for channel, summary in by_channel.items():
            oldest = summary["oldest_unresolved_at"]
            summary["oldest_unresolved_at"] = oldest.isoformat() if oldest else None
            summary["oldest_unresolved_age_seconds"] = (
                int((now - oldest).total_seconds()) if oldest else None
            )
            summary["stuck"] = stuck_by_channel.get(channel, 0)
            summary["retrying"] = retrying_by_channel.get(channel, 0)
            summary["degraded_reason"] = (
                "delivery_stuck" if summary["stuck"] else None
            )
        return by_channel, int(waiting or 0)

    async def held_recipients(self, *, limit: int = 100) -> list[dict[str, Any]]:
        """Recipients the queue is not delivering to, and the reason for each.

        Two states look alike from the queue's side and mean different things to
        an operator: an *ambiguous hold* is a delivery whose outcome nobody
        knows (see `ALERT_RECIPIENT_HOLD_SECONDS`), while a live *lease* means a
        worker is sending at this instant. The second is not an error and must
        not be cleared, so the two are reported separately and only the first is
        releasable.

        A key is a digest of the channel and target — the queue stores no
        address, which is deliberate — so the affected rows are reported by
        channel, the part an operator can actually act on.
        """
        now = datetime.now(timezone.utc)
        held = (
            await self.db.execute(
                select(AlertRecipientState)
                .where(
                    or_(
                        AlertRecipientState.lease_token.is_not(None),
                        AlertRecipientState.next_send_at > now,
                    )
                )
                .order_by(AlertRecipientState.key.asc())
                .limit(limit)
                .execution_options(populate_existing=True)
            )
        ).scalars().all()
        if not held:
            return []

        by_key: dict[str, list[AlertDelivery]] = {}
        for row in (
            await self.db.execute(
                select(AlertDelivery).where(
                    AlertDelivery.status == AlertDeliveryStatus.ambiguous
                )
            )
        ).scalars().all():
            by_key.setdefault(self.recipient_key(row.channel, row.target), []).append(row)

        items: list[dict[str, Any]] = []
        for recipient in held:
            ambiguous = by_key.get(recipient.key, [])
            expires = self._as_utc(recipient.lease_expires_at)
            lease_live = bool(recipient.lease_token) and (expires is None or expires > now)
            items.append(
                {
                    "key": recipient.key,
                    "state": "delivering" if lease_live else ("ambiguous" if ambiguous else "held"),
                    "channels": sorted({str(row.channel) for row in ambiguous}),
                    "hold_ends_at": self._as_utc(recipient.next_send_at),
                    "lease_expires_at": expires,
                    "ambiguous_deliveries": len(ambiguous),
                    "last_error": next((row.last_error for row in ambiguous if row.last_error), None),
                    "releasable": not lease_live,
                }
            )
        return items

    async def release_recipient(self, *, key: str) -> dict[str, Any]:
        """End one recipient's hold so the queue may deliver to it again.

        The operator is asserting that they have reconciled the ambiguous
        delivery, usually by asking the recipient whether the message arrived.
        The deliveries go back into the queue keeping their rendered parts and
        their acknowledgement count, so a multi-part notification resumes at the
        part whose outcome was unknown rather than repeating the parts the
        provider already accepted.

        A live lease is refused instead of broken: a worker is sending at this
        instant, and clearing the lease would start a second send of the same
        message. It ends by itself within the delivery timeout, and the stale
        sweep in `claim_group` covers a worker that died holding it.
        """
        now = datetime.now(timezone.utc)
        recipient = (
            await self.db.execute(
                select(AlertRecipientState)
                .where(AlertRecipientState.key == key)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        if recipient is None:
            return {"key": key, "found": False, "released": False}
        expires = self._as_utc(recipient.lease_expires_at)
        if recipient.lease_token and (expires is None or expires > now):
            return {
                "key": key,
                "found": True,
                "released": False,
                "reason": "lease_live",
            }

        ambiguous = await self._ambiguous_deliveries(key, lock=True)
        if recipient.next_send_at is None and not ambiguous:
            # Nothing is holding this recipient: the caller is either looking at
            # a stale view or has already released the hold. Saying so is more
            # useful than a success that changed nothing.
            return {"key": key, "found": True, "released": False, "reason": "not_held"}
        for row in ambiguous:
            row.status = AlertDeliveryStatus.pending
            row.next_attempt_at = None
            row.locked_at = None
            row.lease_token = None
        recipient.next_send_at = None
        recipient.lease_token = None
        recipient.lease_expires_at = None
        await self.db.commit()
        return {
            "key": key,
            "found": True,
            "released": True,
            "reason": "ambiguous_hold" if ambiguous else "hold",
            "requeued_deliveries": len(ambiguous),
        }

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
        service = AlertService(self.db)
        token = self.tokens[rows[0].id]
        ids = [row.id for row in rows]
        channel, target = self._channel_of(rows[0]), rows[0].target
        try:
            s = await service._get_settings()
            destinations = await self._configured_destinations()
            from app.services.alert_service import (
                AlertDeliveryCancelledError,
                AlertDeliveryPermanentError,
                _breach_subject_class,
                _plain_text,
                digest_heading,
            )
            if target is None or (channel, target.lower()) not in {(kind, str(value).lower()) for kind, value in destinations}:
                raise AlertDeliveryCancelledError("Destination disabled or removed")
            parts = rows[0].parts
            acknowledged = rows[0].acknowledged_parts
            if parts is None:
                from app.services.alert_content import telegram_parts
                group_job = AlertDelivery.job_id == rows[0].job_id if rows[0].job_id else AlertDelivery.job_id.is_(None)
                group_total = int((await self.db.scalar(select(func.count(AlertDelivery.id)).where(group_job, AlertDelivery.threat_type == rows[0].threat_type, AlertDelivery.channel == channel, AlertDelivery.target == target))) or len(rows))
                # The facts are read from the module's own rows as they stand now,
                # not from the payload captured when the finding arrived: a delivery
                # that was retried sends the state of the world it is sent in.
                # A digest batch says what it is — and counts only itself: the
                # group total counts every delivery queued for this channel and
                # target, including the alerts already sent, so a summary of four
                # candidates would otherwise report seven in a chat while its own
                # subject said four. An ordinary alert keeps the group total: its
                # count is the batch the reader is being told about.
                # `digest` is set by the pass that
                # built the band (WI-10), and the group it lands in is the ordinary
                # one — same queue, same retry policy, same recipient rotation — so
                # only the words change: a summary of eighty look-alikes is not "80
                # new findings" and must not read as though eighty things happened.
                # `all`, not `rows[0]`: the digest shares the queue's aggregation
                # key, so a job-less batch can hold a digest and an arrival at once.
                # A batch that is not entirely a digest is an alert — calling it a
                # summary of candidates below the threshold would be a lie about its
                # own contents.
                counted_noun, counted_tail = "new finding", ""
                is_digest = all(row.payload.get("digest") for row in rows)
                if is_digest:
                    label, subject, counted_noun, counted_tail = digest_heading(
                        len(rows), rows[0].threat_type
                    )
                else:
                    label, subject = (
                        rows[0].threat_type.removeprefix("module:"),
                        f"[OpenDRP Alert] {len(rows)} new findings",
                    )
                    if rows[0].threat_type == "breach":
                        # The class, when the batch agrees on one: a breach alert is
                        # read in a mail list first, and "it grew" is a different
                        # triage decision from "it appeared" (WI-08).
                        change = _breach_subject_class([row.payload for row in rows])
                        if change is not None:
                            subject = f"{subject} ({change})"
                notification = service._build_notification(threat_type=rows[0].threat_type, label=label, subject=subject, findings=[row.payload for row in rows], bounded=[row.payload for row in rows], job_id=rows[0].job_id, link=service._platform_link(rows[0].threat_type), stored_facts=await service._stored_message_facts(rows[0].threat_type, [row.payload for row in rows]), counted_noun=counted_noun, counted_tail=counted_tail, total_count=len(rows) if is_digest else group_total)
                if channel == "telegram":
                    parts = [{"text": text} for text in telegram_parts(notification, settings.ALERT_MAX_TELEGRAM_MESSAGE_LENGTH, rows[0].batch_id)]
                else:
                    markup = service._render_template("emails/finding_summary.html", module_label=notification.label, title=notification.subject, badge_class="", dashboard_url=notification.link, job_id=notification.job_id, total=notification.total, included=notification.included, groups=notification.groups, columns=notification.columns, rows=notification.table())
                    parts = [{"subject": notification.subject, "html": markup, "plain": _plain_text(notification)}]
                await self.db.execute(update(AlertDelivery).where(AlertDelivery.id.in_(ids), AlertDelivery.lease_token == token).values(parts=parts))
            await service.detach_settings(s)
            for index in range(acknowledged, len(parts)):
                current_destinations = await self._configured_destinations()
                if (channel, target.lower()) not in {(kind, str(value).lower()) for kind, value in current_destinations}:
                    await self.db.commit()
                    raise AlertDeliveryCancelledError("Destination disabled or removed")
                recipient = await self._recipient(channel, target)
                if recipient is None or recipient.lease_token != token:
                    await self.db.rollback()
                    raise AlertDeliveryCancelledError("Delivery lease lost")
                now = datetime.now(timezone.utc)
                wait = max(0, (recipient.next_send_at.replace(tzinfo=timezone.utc) - now).total_seconds()) if recipient.next_send_at else 0
                recipient.next_send_at = now + timedelta(seconds=wait + settings.ALERT_RECIPIENT_INTERVAL_SECONDS)
                recipient.lease_expires_at = now + timedelta(seconds=wait + settings.ALERT_DELIVERY_TIMEOUT_SECONDS + 60)
                await self.db.execute(update(AlertDelivery).where(AlertDelivery.id.in_(ids), AlertDelivery.lease_token == token).values(locked_at=now + timedelta(seconds=wait)))
                await self.db.commit()
                if wait:
                    await asyncio.sleep(wait)
                part = parts[index]
                accepted = await service._send_telegram(part["text"], chat_id=target) if channel == "telegram" else await service._send_email_smtp(to=target, subject=part["subject"], html_body=part["html"], plain_body=part["plain"])
                if not accepted:
                    raise AlertDeliveryPermanentError("Provider refused message")
                acknowledged_result = await self.db.execute(update(AlertDelivery).where(AlertDelivery.id.in_(ids), AlertDelivery.lease_token == token, AlertDelivery.status == AlertDeliveryStatus.delivering).values(acknowledged_parts=index + 1))
                await self.db.commit()
                if acknowledged_result.rowcount != len(ids):
                    raise AlertDeliveryCancelledError("Stale acknowledgement rejected")
        except Exception as exc:
            await self.mark_failed(rows, exc, max_attempts=max_attempts)
            return {
                "status": rows[0].status if rows[0].status != AlertDeliveryStatus.pending else "retry",
                "count": len(rows),
            }
        await self.mark_sent(rows)
        return {"status": "sent", "count": len(rows)}
