import uuid
from datetime import datetime, timedelta, timezone
from sqlalchemy import func, or_, select, update
from app.core.config import settings
from app.models.ingestion_event import IngestionEvent
from app.models.phishing import PhishingDomain
from app.services.alert_delivery_service import AlertDeliveryService
from app.services.alert_policy import AlertPolicy, resolve_alert_policy
from app.services.alert_service import phishing_alert_route
from app.services.phishing_score_service import record_stored_signals


async def record_event(db, *, kind, module, entity_id, payload, job_id=None, dedup=None):
    """Queue one outbox row, optionally distinguishing several facts about one entity.

    `dedup` is what lets a *current fact* fire more than once. Phishing and breaches
    report an arrival and are done with it, so their key - kind, module, entity id -
    is naturally unique. A DNS observation is a row that is updated in place: a record
    that changes twice is two arrivals of the same row, and keying them by entity id
    alone would report the first and swallow every later one. The caller passes a
    short digest of what arrived (rule plus the new value or fingerprint), so an
    identical rediscovery stays suppressed while a real change is delivered.

    Answers whether a row was written, because a rule that re-runs over unchanged
    evidence has to be able to report "nothing new" rather than "queued" (the
    certificate rules sweep the same identities every day).
    """
    key = f"{kind}:{module}:{entity_id}" + (f":{dedup}" if dedup else "")
    existing = (await db.execute(select(IngestionEvent.id).where(IngestionEvent.event_key == key))).scalar_one_or_none()
    if existing is not None:
        return False
    db.add(IngestionEvent(event_key=key, kind=kind, module=module, entity_id=entity_id, job_id=job_id, payload=payload))
    await db.flush()
    return True


#: The reason a breach notification carries while it waits for the digest, and the
#: reason a noise-suppressed one is consumed with. Both are stored on the outbox row
#: so the alert history can answer "why did this incident not become a message?"
#: without a log line (WI-05, WI-06).
BREACH_DIGEST_REASON = "breach_digest_pending"
BREACH_NOISE_REASON = "breach_noise_stored_only"


async def _breach_scans_over_threshold(db, threshold: int) -> set[str]:
    """The scans whose pending breach incidents are past the digest threshold.

    One grouped read for the pass, and it counts the rows *already* held for the
    digest as well as the ones due now: a scan's size is decided by what it found,
    and a count that shrank as rows were held would deliver the second half of a
    backlog individually — which is the behaviour the threshold exists to stop.
    """
    rows = await db.execute(
        select(IngestionEvent.job_id, func.count(IngestionEvent.id))
        .where(
            IngestionEvent.kind == "notification",
            IngestionEvent.module == "breach",
            IngestionEvent.processed_at.is_(None),
            IngestionEvent.job_id.isnot(None),
        )
        .group_by(IngestionEvent.job_id)
    )
    return {str(job_id) for job_id, count in rows.all() if count > threshold}


async def dispatch_notification_events(db, limit=100):
    now = datetime.now(timezone.utc)
    # One read for the whole pass: the budget and the deferral window are decisions
    # about this installation, not about a row, and reading them per event would
    # ask the same question once per finding.
    policy = await resolve_alert_policy(db)
    due = (IngestionEvent.next_attempt_at.is_(None)) | (IngestionEvent.next_attempt_at <= now)
    conditions = [
        IngestionEvent.kind == "notification",
        IngestionEvent.processed_at.is_(None),
        due,
    ]
    if policy.digest_enabled:
        # Rows waiting for the digest belong to that pass and to nobody else: leaving
        # them in this selection would deliver them one by one at the very hour the
        # digest is being assembled, which is the defect the threshold closes. When
        # the digest is switched off they are *not* excluded — the breach pass reads
        # the policy and releases them back into this drain (WI-06).
        conditions.append(
            or_(
                IngestionEvent.last_error.is_(None),
                IngestionEvent.last_error != BREACH_DIGEST_REASON,
            )
        )
    rows = list((await db.execute(select(IngestionEvent).where(*conditions).order_by(IngestionEvent.created_at, IngestionEvent.id).limit(limit).with_for_update(skip_locked=True))).scalars())
    #: The scans whose size makes them a backlog rather than a report. Computed once
    #: per pass, and only when the deferral is on: 0 means one message per scan.
    backlogged = (
        await _breach_scans_over_threshold(db, policy.breach_digest_threshold)
        if policy.breach_digest_threshold > 0 and policy.digest_enabled
        else set()
    )
    processed = 0
    for row in rows:
        if row.module == "phishing":
            route = phishing_alert_route(
                await db.get(PhishingDomain, row.entity_id), policy=policy
            )
            if route in {"digest", "list", "suppressed", "closed"}:
                # The budget, not the channel, is what stops this message: the
                # candidate is not worth interrupting someone for. The event is
                # consumed rather than held, because the daily digest reads the
                # candidate's own scored row — the event has nothing the digest
                # needs — and the reason is recorded so the alert history can tell
                # "not worth a message" from "nobody to send it to".
                #
                # `suppressed` is the analyst's own rejection (WI-12) and consumes the
                # event for the same reason with a reason of its own: a candidate that
                # keeps arriving in every later scan must not keep producing messages,
                # which is the whole point of the verdict outranking the score. The
                # row stays readable in the list; only the channel goes quiet.
                row.processed_at = now
                row.last_error = {
                    "digest": "phishing_digest_pending",
                    "list": "phishing_below_threshold",
                    "suppressed": "phishing_verdict_rejected",
                    # An investigation status, not a verdict: the reason names the
                    # resolution so the alert history cannot report one decision as
                    # the other (the digest skips these rows for the same reason).
                    "closed": "phishing_status_resolved",
                }[route]
                continue
        if row.module == "breach":
            # An incident the source itself labels spam or fabricated is stored and
            # visible, and is not a message: the row's flag is the answer to "why did
            # this not alert?", and the operator can ask for the loud behaviour back
            # by setting the policy to `all` (WI-05).
            reason = policy.breach_noise_reason((row.payload or {}).get("attributes"))
            if reason is not None:
                # Consumed where it stands, with the reason on the row: the incident
                # itself stays readable in the list, and the alert history can tell
                # "not worth a message" from "nobody to send it to".
                row.processed_at = now
                row.last_error = BREACH_NOISE_REASON
                continue
            if row.job_id is not None and str(row.job_id) in backlogged:
                # Left pending on purpose: the daily breach digest reads these rows
                # and reports the scan as one summary instead of one message per
                # incident. The selection above excludes them while the digest is on,
                # so no other pass can deliver them first.
                row.last_error = BREACH_DIGEST_REASON
                continue
        result = await AlertDeliveryService(db).enqueue(threat_type=row.module, details=row.payload, job_id=row.job_id)
        if result is not None:
            row.processed_at = now
            processed += 1
        elif policy.no_channel_retry_hours <= 0:
            # The window is off, which is how this drain behaved before the window
            # existed: a finding no channel can receive is consumed where it
            # stands, while a scheduled operations row keeps a short retry.
            if row.module == "module:operations":
                row.next_attempt_at = now + timedelta(minutes=5)
            else:
                row.processed_at = now
            row.last_error = "no_delivery_channel"
        else:
            # No channel is a temporary state, not a terminal one: an installation
            # is configured at some point, and the finding recorded while it could
            # not deliver is still worth reporting then. The row is held for the
            # configured window, which is also what keeps a deployment with no
            # channel from re-walking its whole backlog on every pass, and the save
            # that configures a channel reports what was held as one digest
            # (``queue_backlog_digest``) instead of waiting this window out.
            row.next_attempt_at = now + timedelta(
                hours=policy.no_channel_retry_hours
            )
            row.last_error = "no_delivery_channel"
    await db.commit()
    return processed


async def queue_backlog_digest(db) -> dict:
    """Report, once, what was held while no channel could receive it.

    Called when a save makes an installation able to deliver for the first time.
    Waking the drain is not enough for the rows it held: they were left unprocessed
    *because* nobody could receive them, and replaying them job by job is the
    stream the deferral window exists to prevent. So the held rows are claimed here
    in one statement — which is also what makes the report happen once, even when
    two administrators save at the same moment, because a row can only be claimed
    by one of them — and described in a single operations notification.

    The claimed rows keep ``no_delivery_channel`` as the reason they were late and
    gain a ``processed_at`` saying the digest covered them. The caller owns the
    transaction: a settings save that fails takes its digest with it, and no
    notification is queued for a save that did not happen.
    """
    now = datetime.now(timezone.utc)
    claimed = (
        await db.execute(
            update(IngestionEvent)
            .where(
                IngestionEvent.kind == "notification",
                IngestionEvent.processed_at.is_(None),
                IngestionEvent.last_error == "no_delivery_channel",
            )
            .values(processed_at=now)
            .returning(IngestionEvent.module, IngestionEvent.created_at)
        )
    ).all()
    if not claimed:
        return {"held": 0}
    by_module: dict[str, int] = {}
    for module, _ in claimed:
        by_module[module] = by_module.get(module, 0) + 1
    # `created_at` is NOT NULL, so the backlog always has a first instant.
    oldest = min(created_at for _, created_at in claimed)
    total = len(claimed)
    await record_event(
        db,
        kind="notification",
        module="module:operations",
        # A fresh id, because the claim above is what makes this once: the key has
        # to differ per digest, and one digest never covers two backlogs.
        entity_id=uuid.uuid4(),
        payload={
            "title": (
                f"Alert backlog: {total} finding{'s' if total != 1 else ''} "
                "arrived while no channel was configured"
            ),
            "fields": {
                "Held findings": total,
                "By module": ", ".join(
                    f"{module.removeprefix('module:')} × {count}"
                    for module, count in sorted(by_module.items())
                ),
                # A date rather than an instant: what the reader needs is how stale
                # the backlog is, and SQLite hands the column back naive.
                "Held since": oldest.date().isoformat(),
            },
        },
    )
    return {"held": total, "by_module": by_module}


async def queue_phishing_digest(
    db, *, limit: int | None = None, policy: AlertPolicy | None = None
) -> dict:
    """Queue the day's digest: the candidates the budget chose not to interrupt for.

    The middle band exists so that the channel is neither silent nor noisy: a
    look-alike with a young registration and one corroborating source is worth
    knowing about, and not worth a message at 02:30. This pass turns that band into
    one message per recipient per day, and it is the reason a candidate below the
    direct threshold is not simply dropped — the delivery path consumes its event
    (``dispatch_notification_events``) precisely because this runs later.

    Two rules make "once a day" hold rather than "once a day, unless":

    * ``digest_queued_at`` marks the candidates this message carried, so tomorrow'
      run reports what is new instead of repeating the same lookalikes. The mark is
      written only when a delivery row was actually queued — an installation with no
      channel yet gets its first digest when it has one, not an empty mark it cannot
      clear;
    * a candidate something *arrived* about after it was digested is included again,
      which is read from the outbox: the revision the scan wrote is still a row in
      ``ingestion_events`` even though the budget consumed it, so "anything new
      about this candidate since the last digest" is a question the platform can
      already answer. Its own ``updated_at`` cannot serve here — writing the mark is
      itself an update of that row, so every digested candidate looks changed the
      moment it is marked.

    The message is capped at ``ALERT_MAX_FINDINGS_PER_MESSAGE`` candidates, which is
    what keeps it one message: the rest are simply tomorrow's, since they were not
    marked. A resolved candidate is not digested at all — an operator who closed a
    finding is not asking to be told about it daily.

    Returns how many candidates the message carried and how many were considered.

    The budget and the digest switch come from the resolved alert policy: an
    installation that turned the digest off in Settings has asked for a binary
    channel, and this pass is where that request is answered. ``policy`` lets a
    caller that already resolved it (the digest's own entry point does) avoid
    asking the same question twice.
    """
    if policy is None:
        policy = await resolve_alert_policy(db)
    if not policy.digest_enabled:
        return {"queued": 0, "candidates": 0, "reason": "digest_disabled"}

    now = datetime.now(timezone.utc)
    bound = limit or settings.ALERT_MAX_FINDINGS_PER_MESSAGE
    rows = list(
        (
            await db.execute(
                select(PhishingDomain)
                .where(
                    PhishingDomain.confidence >= policy.confidence_digest,
                    PhishingDomain.confidence < policy.confidence_direct,
                    PhishingDomain.status != "resolved",
                    # A rejection is silence, and the digest is part of the channel: an
                    # analyst who decided a candidate was noise must not find it in
                    # tomorrow's summary either (WI-12). `!=` alone would also drop
                    # every undecided candidate — NULL is not "not rejected" in SQL —
                    # so the ordinary state is stated first.
                    or_(
                        PhishingDomain.verdict.is_(None),
                        PhishingDomain.verdict != "rejected",
                    ),
                    or_(
                        PhishingDomain.digest_queued_at.is_(None),
                        select(IngestionEvent.id)
                        .where(
                            IngestionEvent.module == "phishing",
                            IngestionEvent.entity_id == PhishingDomain.id,
                            IngestionEvent.created_at
                            > PhishingDomain.digest_queued_at,
                        )
                        .exists(),
                    ),
                )
                # The most convincing candidates lead, so a digest truncated by its
                # own bound still reports the ones nearest the alert threshold.
                .order_by(
                    PhishingDomain.confidence.desc(), PhishingDomain.created_at
                )
                .limit(bound)
            )
        ).scalars()
    )

    service = AlertDeliveryService(db)
    queued = 0
    for row in rows:
        # One candidate, one payload: the aggregation key (no job, module
        # ``phishing``, channel, recipient) collapses the whole band into a single
        # message, and the ``digest`` flag is what tells the delivery path to build
        # it as one.
        delivered = await service.enqueue(
            threat_type="phishing",
            details={
                "rule": "phishing.digest",
                "digest": True,
                "severity": "info",
                "title": f"{row.phishing_domain} is below the alert threshold",
                "phishing_domain": row.phishing_domain,
                "matched_asset": row.matched_asset,
                "detection_source": row.detection_source,
                "confidence": int(row.confidence or 0),
                "finding_id": str(row.id),
            },
            job_id=None,
        )
        if delivered is not None:
            row.digest_queued_at = now
            queued += 1

    await db.commit()
    return {"queued": queued, "candidates": len(rows)}


async def queue_breach_digest(
    db, *, limit: int | None = None, policy: AlertPolicy | None = None
) -> dict:
    """Report the incidents a scan found past the threshold, as one summary (WI-06).

    The complement of :func:`queue_phishing_digest`, and the same shape: a breach
    scan that returns a hundred new incidents is a backlog, and a hundred separate
    messages is not a report of it. Past ``breach_digest_threshold`` the drain holds
    the scan's notifications (``BREACH_DIGEST_REASON``) instead of delivering them,
    and this pass turns what was held into one message — the same queue, the same
    retry policy, the same recipient rotation, only the words change.

    ``limit`` bounds how many rows one message carries; the rest keep their reason
    and are reported by the next pass, so a backlog larger than one message is
    summarised in several rather than dropped. Nothing is claimed destructively: a
    row is marked processed only when a delivery row was actually queued, so an
    installation with no channel yet gets its summary when it has one.
    """
    if policy is None:
        policy = await resolve_alert_policy(db)
    if not policy.digest_enabled:
        # The digest is the switch for this deferral: with it off, the drain releases
        # held rows back into ordinary delivery on its next pass, and this pass must
        # not queue anything behind its back.
        return {"queued": 0, "incidents": 0, "reason": "digest_disabled"}

    now = datetime.now(timezone.utc)
    bound = limit or settings.ALERT_MAX_FINDINGS_PER_MESSAGE
    rows = list(
        (
            await db.execute(
                select(IngestionEvent)
                .where(
                    IngestionEvent.kind == "notification",
                    IngestionEvent.module == "breach",
                    IngestionEvent.processed_at.is_(None),
                    IngestionEvent.last_error == BREACH_DIGEST_REASON,
                )
                .order_by(IngestionEvent.created_at, IngestionEvent.id)
                .limit(bound)
            )
        ).scalars()
    )

    service = AlertDeliveryService(db)
    queued = 0
    for row in rows:
        # One incident, one payload, and the aggregation key (no job, module
        # ``breach``, channel, recipient) collapses the whole backlog into a single
        # message. ``digest`` is what tells the delivery path to word it as a
        # summary: eighty incidents are not "80 new findings" in the sense the
        # ordinary subject means.
        delivered = await service.enqueue(
            threat_type="breach",
            details={**(row.payload or {}), "digest": True},
            job_id=None,
        )
        if delivered is None:
            # No channel can receive it, so the row stays held: marking it processed
            # would consume a backlog for a delivery that never happened. It keeps
            # its reason and is reported by a later pass, once there is somewhere to
            # send it.
            break
        row.processed_at = now
        row.last_error = BREACH_DIGEST_REASON
        queued += 1

    await db.commit()
    # Counted after the commit, so the rows this pass queued are no longer in the
    # figure: `remaining` is the backlog a later pass will carry, not the rest of
    # the window this one fetched. Subtracting from the window reported zero for a
    # pass that used its whole limit while a backlog waited behind it (AUD-088).
    outstanding = (
        await db.execute(
            select(func.count())
            .select_from(IngestionEvent)
            .where(
                IngestionEvent.kind == "notification",
                IngestionEvent.module == "breach",
                IngestionEvent.processed_at.is_(None),
                IngestionEvent.last_error == BREACH_DIGEST_REASON,
            )
        )
    ).scalar_one()
    return {
        "queued": queued,
        "incidents": len(rows),
        "remaining": int(outstanding or 0),
    }


async def run_breach_digest(db, *, now: datetime | None = None) -> dict:
    """The breach digest's entry point: the shared hour gate, then the pass.

    The hour is the phishing digest's (``ALERT_PHISHING_DIGEST_HOUR_UTC``, or the
    value saved in Settings) so the installation has one "summary hour" rather than
    two, and the gate is asked the same way for the same reason: a beat schedule is
    built when the worker starts, and an operator's hour must take effect without
    recreating a container.
    """
    moment = now or datetime.now(timezone.utc)
    policy = await resolve_alert_policy(db)
    if not policy.digest_enabled:
        return {"queued": 0, "incidents": 0, "reason": "digest_disabled"}
    if not policy.digest_is_due(moment):
        return {
            "queued": 0,
            "incidents": 0,
            "reason": "outside_digest_hour",
            "digest_hour_utc": policy.digest_hour_utc,
        }
    return await queue_breach_digest(db, policy=policy)


async def run_phishing_digest(db, *, now: datetime | None = None) -> dict:
    """The digest's own entry point: the hour gate, then the pass (WI-10).

    The hour an installation wants its summary at is an operator's value now, so it
    cannot live in the beat schedule: a schedule is built when the worker starts, and
    a saved hour would only take effect after a container was recreated — which is
    the whole thing the Settings page exists to avoid. The schedule is therefore a
    plain hourly tick and the decision is made here, from the resolved policy, where
    one hourly tick falls inside the configured hour and is exactly the one that
    sends. A tick outside the hour answers without touching the candidates, and the
    answer names the reason so an operator reading task results can tell "not your
    hour" from "nothing to report".

    ``now`` is injectable because the gate is about a wall clock: a test states the
    moment instead of waiting for it.
    """
    moment = now or datetime.now(timezone.utc)
    policy = await resolve_alert_policy(db)
    if not policy.digest_is_due(moment):
        return {
            "queued": 0,
            "candidates": 0,
            "reason": "outside_digest_hour",
            "digest_hour_utc": policy.digest_hour_utc,
        }
    return await queue_phishing_digest(db, policy=policy)


#: How many registration events one pass claims. The batch has to fit inside the
#: beat's own tick — fifteen seconds, see ``app/core/celery_app.py`` — because a
#: pass that outlives its tick queues the next one behind itself: three lookups at
#: the default three-second outbound budget leave the pass room to write what it
#: found (WI-25).
ENRICHMENT_BATCH_LIMIT = 3

#: How long an event waits when the pass could not reach it: one tick. The rule is
#: one lookup per answering server per pass, so the second candidate under ``.com``
#: is asked in the next pass rather than in this one, and the registry sees a
#: trickle where a scan's forty look-alikes would otherwise be a burst.
ENRICHMENT_PASS_SECONDS = 15

#: A registry that refused us holds every event that would ask it again for this
#: long, and the pass does not look that server up while the pause stands. Fifteen
#: minutes is one refusal answered politely; a per-event backoff against a server
#: that is already saying stop is the retry stream this constant removes (WI-25).
WHOIS_RATE_LIMIT_PAUSE_SECONDS = 15 * 60

#: Backoff for a lookup that did not answer: thirty seconds doubling, capped at an
#: hour. After ``WHOIS_MAX_ATTEMPTS`` the event is completed rather than retried
#: forever. Enrichment is best effort — a registry unreachable for a day, or a
#: deployment whose egress blocks port 43, must not leave a permanently pending
#: queue that every later pass spends its whole batch on.
WHOIS_RETRY_BASE_SECONDS = 30
WHOIS_RETRY_MAX_SECONDS = 3600
WHOIS_MAX_ATTEMPTS = 8

#: A name the registry says is not registered is asked about again twice a day
#: rather than never: a look-alike nobody has registered is a name that can be
#: registered at any time, and the fact is worth having when it happens. It is also
#: a different thing from the thirty-second backoff an outage earns.
WHOIS_NO_RECORD_RETRY_SECONDS = 12 * 3600


def _whois_is_pending(kind: str = "whois"):
    """The events a registration pass may claim."""
    return (IngestionEvent.kind == kind, IngestionEvent.processed_at.is_(None))


def _retry_delay(attempt: int) -> int:
    """Thirty seconds doubling to an hour, the bound the drain always applied."""
    return min(WHOIS_RETRY_MAX_SECONDS, WHOIS_RETRY_BASE_SECONDS * 2 ** min(attempt, 7))


def _instant(value: datetime | None) -> datetime | None:
    """Read a stored instant as UTC: SQLite hands the column back naive."""
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


async def _claimed_event(db, *, event_id, attempt):
    """Re-read a claimed event under its lock, or answer that the claim is stale.

    The pass releases its locks before it talks to the network, so a second worker
    may have claimed the same event meanwhile. Its claim wins: the row is left to
    that worker (a rollback discards whatever this pass had staged) and the caller
    moves on. This is what keeps a slow registry from letting two workers race to
    write two different results for one candidate.
    """
    row = (await db.execute(select(IngestionEvent).where(IngestionEvent.id == event_id).with_for_update().execution_options(populate_existing=True))).scalar_one_or_none()
    if row is None or row.processed_at is not None or row.attempts != attempt:
        await db.rollback()
        return None
    return row


async def _hold_whois_event(db, *, event_id, attempt, seconds, reason, now, give_up_at_limit=False) -> str:
    """Defer one claimed event, or complete it once a best-effort try is spent.

    Answers ``held``, ``exhausted`` or ``fenced``. A hold is a retry time and a
    reason on the row — the same two fields the alert side uses to say why a
    finding is still pending — so an operator reading the outbox can tell "the
    registry stopped answering us" from "the socket timed out" without a log line.
    """
    row = await _claimed_event(db, event_id=event_id, attempt=attempt)
    if row is None:
        return "fenced"
    if give_up_at_limit and attempt >= WHOIS_MAX_ATTEMPTS:
        row.processed_at = now
        row.last_error = f"{reason}_exhausted"
        await db.commit()
        return "exhausted"
    moment = now + timedelta(seconds=seconds)
    standing = _instant(row.next_attempt_at)
    if standing is not None and standing > moment:
        # A longer hold already stands for this row — the server-wide pause a
        # refusal wrote, this pass or another worker's — and pacing one candidate
        # must not shorten it. The reason stays the pause's, so the row still says
        # why it is waiting.
        await db.commit()
        return "held"
    row.next_attempt_at = moment
    row.last_error = reason
    await db.commit()
    return "held"


async def _pause_whois_server(db, *, server: str, now: datetime) -> int:
    """Hold every pending event that would ask a refusing server again (WI-25).

    Scoped to the answering server rather than to the installation: another
    top-level domain is another registry with its own budget, and silencing the
    whole queue because one of them said "enough" would trade a burst for
    starvation. The label is checked before it reaches the statement, because it
    becomes a ``LIKE`` pattern and a key that is not a plain label has no business
    widening it.

    The candidate subquery is a scan of the candidate table, which is the price of
    a leading-wildcard match; what keeps it affordable is that it runs on a refusal
    (once per pause, per server) rather than on every pass.
    """
    from app.services.phishing import whois_service

    if not whois_service.is_server_label(server):
        return 0
    result = await db.execute(
        update(IngestionEvent)
        .where(
            *_whois_is_pending(),
            IngestionEvent.entity_id.in_(
                select(PhishingDomain.id).where(
                    # Lowered on both sides: ``LIKE`` is case-insensitive in SQLite
                    # and case-sensitive in PostgreSQL, and the pause has to mean
                    # the same thing in the deployment as it does in the tests.
                    func.lower(PhishingDomain.phishing_domain).like(f"%.{server}")
                )
            ),
        )
        .values(
            next_attempt_at=now + timedelta(seconds=WHOIS_RATE_LIMIT_PAUSE_SECONDS),
            last_error="whois_rate_limited",
        )
        .returning(IngestionEvent.id)
    )
    held = len(result.all())
    await db.commit()
    return held


async def _complete_enrichment(
    db, *, event_id, entity_id, attempt, snapshot, now, reason=None
) -> str:
    """Store what a lookup resolved, re-score, report the arrival, complete the row."""
    from app.services.phishing import whois_service

    row = await _claimed_event(db, event_id=event_id, attempt=attempt)
    if row is None:
        return "fenced"
    threat = await db.get(PhishingDomain, entity_id)
    resolved = False
    if threat is not None and snapshot is not None:
        for field in whois_service.FACTS:
            if not getattr(threat, field):
                value = getattr(snapshot, field)
                setattr(threat, field, value)
                resolved = resolved or value is not None
    row.processed_at = now
    row.last_error = reason
    # `resolved` is only set while a candidate row was found, and the narrow is
    # spelled out so the scorer below is handed a row rather than an optional.
    if resolved and threat is not None:
        # The registration date this pass just resolved is the fact the age
        # signal is derived from, so the score is re-derived before the arrival
        # is queued: an operator opening the alert sees a candidate that has been
        # judged by everything the platform knows, not by what it knew at
        # creation time (WI-07).
        await record_stored_signals(db, candidate=threat)
        # A candidate is reported the moment it is seen, which is usually
        # before its registration is known, so the alert an operator reads
        # first can say nothing about the registrar, the abuse contact or the
        # age of the domain (WI-01). Resolving them is therefore an arrival in
        # its own right: it is queued once per candidate — the digest keeps a
        # second enrichment pass from repeating it — and by the time it is
        # delivered the message is assembled from the row, so it carries the
        # facts the first one could not. When the first alert has not gone out
        # yet, the two collapse into one aggregated message.
        await record_event(
            db,
            kind="notification",
            module="phishing",
            entity_id=entity_id,
            job_id=row.job_id,
            dedup="enriched",
            payload={
                "severity": "info",
                "rule": "phishing.enrichment.completed",
                "title": f"Registration resolved for {snapshot.phishing_domain}",
            },
        )
    await db.commit()
    return "completed"


async def enrich_pending_events(db, *, limit: int = ENRICHMENT_BATCH_LIMIT) -> dict:
    """Resolve registration facts for the events that are due (WI-01, WI-25).

    Every part of this pass exists because of how a WHOIS lookup behaves when
    there are many of them:

    * it claims up to ``limit`` due events in one statement rather than one event
      per tick, so a scan's worth of candidates is served by one worker's pass;
    * it takes the locks, releases them, and re-checks each claim before writing
      anything — the network call is where a second worker can claim a row, and the
      newer claim wins;
    * it asks each *answering server* at most once per pass: the rest of that
      server's events wait for the next pass. Forty look-alikes under one TLD are
      forty queries at one registry's budget, and the batch limit is the other
      half of that rule;
    * a candidate whose row already carries the facts is completed without a
      lookup at all — the row is the cache, and a re-queued event costs nothing;
    * a refusal (``rate_limited``) holds the event *and* every other pending event
      that would ask the same server, for a pause measured in minutes. A refusal is
      the one answer that is about the server rather than the name, so it is the
      one answer that must not be retried event by event;
    * a lookup that did not answer, or raised, is held with the bounded backoff and
      completed once its tries are spent, so a registry nobody can reach does not
      leave a pending queue that every later pass re-walks.

    Returns what the pass did, by outcome, so a quiet pass can be told from a
    blocked one. ``claimed`` counts the events it took, the outcome names (``answer-
    ed``, ``nothing_to_ask``, ``refused``, ``no_record``, ``rate_limited``,
    ``unavailable``, ``failed``) count how many lookups ended each way, and the
    dispositions — ``completed``, ``held``, ``exhausted``, ``fenced`` — count what
    became of the rows.
    """
    from app.services.phishing import whois_service

    summary = {
        "claimed": 0,
        "completed": 0,
        "held": 0,
        "exhausted": 0,
        "fenced": 0,
        "answered": 0,
        "nothing_to_ask": 0,
        "refused": 0,
        "no_record": 0,
        "rate_limited": 0,
        "unavailable": 0,
        "failed": 0,
    }

    def _tally(outcome: str) -> None:
        """Count what became of a claimed row. A fenced row is the winner's."""
        summary[outcome if outcome in summary else "fenced"] += 1

    now = datetime.now(timezone.utc)
    rows = list(
        (
            await db.execute(
                select(IngestionEvent)
                .where(
                    *_whois_is_pending(),
                    or_(
                        IngestionEvent.next_attempt_at.is_(None),
                        IngestionEvent.next_attempt_at <= now,
                    ),
                )
                .order_by(IngestionEvent.created_at, IngestionEvent.id)
                .limit(limit)
                .with_for_update(skip_locked=True)
            )
        ).scalars()
    )
    if not rows:
        await db.commit()
        return summary

    claimed = []
    for row in rows:
        row.attempts += 1
        # The claim's own guard: an event that is claimed and then never written —
        # a worker killed mid-pass — is due again on the next tick instead of being
        # stranded for the length of a backoff it never earned.
        row.next_attempt_at = now + timedelta(seconds=ENRICHMENT_PASS_SECONDS)
        claimed.append((row.id, row.entity_id, row.attempts))
    summary["claimed"] = len(claimed)
    await db.commit()  # No locks held during external enrichment.

    class DetachedEnrichmentSession:
        """The stand-in a lookup is handed once the pass has released its locks.

        The pass writes the outcome itself, so this session's two calls are no-ops
        by design rather than by oversight: a lookup must not be able to commit a
        half-resolved row while another worker's claim is the one that counts.
        """

        async def commit(self) -> None:
            return None

        async def refresh(self, entity: object) -> None:
            return None

    from types import SimpleNamespace

    asked: set[str] = set()
    for event_id, entity_id, attempt in claimed:
        threat = await db.get(PhishingDomain, entity_id)
        fields = whois_service.FACTS + ("phishing_domain",)
        snapshot = SimpleNamespace(**{field: getattr(threat, field) for field in fields}) if threat else None
        await db.commit()  # End the read transaction before DNS/WHOIS network calls.
        server = whois_service.lookup_group_key(getattr(snapshot, "phishing_domain", None))

        # The row is the cache: a candidate that already carries the registrar and
        # the registration date is completed here, without a query and without
        # spending this server's one slot in the pass.
        if snapshot is not None and whois_service.registration_known(snapshot):
            summary["nothing_to_ask"] += 1
            _tally(
                await _complete_enrichment(
                    db,
                    event_id=event_id,
                    entity_id=entity_id,
                    attempt=attempt,
                    snapshot=snapshot,
                    now=now,
                    reason="whois_facts_known",
                )
            )
            continue

        if server and server in asked:
            # One lookup per answering server per pass; this candidate is next
            # pass's, which is what paces a scan's worth of look-alikes.
            _tally(
                await _hold_whois_event(
                    db,
                    event_id=event_id,
                    attempt=attempt,
                    seconds=ENRICHMENT_PASS_SECONDS,
                    reason="whois_pacing",
                    now=now,
                )
            )
            continue
        if server:
            asked.add(server)

        status = whois_service.ANSWERED
        if snapshot is not None:
            try:
                from app.services.phishing.whois_service import WhoisService

                status = await WhoisService(DetachedEnrichmentSession()).enrich(snapshot)
            except Exception as exc:
                # A failure here is the enrichment's own, not the registry's: the
                # pass counts it, holds the event, and keeps going, because one
                # candidate must not stop the rest of a batch.
                summary["failed"] += 1
                _tally(
                    await _hold_whois_event(
                        db,
                        event_id=event_id,
                        attempt=attempt,
                        seconds=_retry_delay(attempt),
                        reason=type(exc).__name__[:128],
                        now=now,
                        give_up_at_limit=True,
                    )
                )
                continue

        if status == whois_service.NOTHING_TO_ASK:
            summary["nothing_to_ask"] += 1
            _tally(
                await _complete_enrichment(
                    db,
                    event_id=event_id,
                    entity_id=entity_id,
                    attempt=attempt,
                    snapshot=snapshot,
                    now=now,
                    reason="whois_facts_known",
                )
            )
        elif status == whois_service.REFUSED:
            # Terminal on purpose: the target was refused by our own destination
            # policy or by its shape, and asking a deliberately blocked
            # destination again on a timer is the retry stream the guard exists to
            # prevent. The reason stays on the row, so the refusal is inspectable.
            summary["refused"] += 1
            _tally(
                await _complete_enrichment(
                    db,
                    event_id=event_id,
                    entity_id=entity_id,
                    attempt=attempt,
                    snapshot=snapshot,
                    now=now,
                    reason="whois_target_refused",
                )
            )
        elif status == whois_service.NO_RECORD:
            # The name is not registered: an answer, and one worth re-asking for
            # twice a day, because a name nobody owns yet can be registered. It is
            # a hold rather than the thirty-second backoff an outage earns.
            summary["no_record"] += 1
            _tally(
                await _hold_whois_event(
                    db,
                    event_id=event_id,
                    attempt=attempt,
                    seconds=WHOIS_NO_RECORD_RETRY_SECONDS,
                    reason="whois_no_record",
                    now=now,
                )
            )
        elif status == whois_service.RATE_LIMITED:
            # The whole server pauses, not just this event, and the pass stops
            # asking it: the answer was about us, not about the name.
            summary["rate_limited"] += 1
            paused = await _pause_whois_server(db, server=server, now=now)
            if paused == 0:
                # No key to scope a server-wide hold with (a name whose suffix is
                # not a plain label): hold this event for the same pause rather
                # than let it come back in fifteen seconds.
                paused = int(
                    await _hold_whois_event(
                        db,
                        event_id=event_id,
                        attempt=attempt,
                        seconds=WHOIS_RATE_LIMIT_PAUSE_SECONDS,
                        reason="whois_rate_limited",
                        now=now,
                    )
                    == "held"
                )
            summary["held"] += paused
        elif status == whois_service.UNAVAILABLE:
            summary["unavailable"] += 1
            _tally(
                await _hold_whois_event(
                    db,
                    event_id=event_id,
                    attempt=attempt,
                    seconds=_retry_delay(attempt),
                    reason="whois_unavailable",
                    now=now,
                    give_up_at_limit=True,
                )
            )
        else:
            # ``answered`` — or anything a stand-in returned: an enrichment that
            # says nothing about the registry is treated as a resolved one, which
            # is what this drain did before it could tell the outcomes apart.
            summary["answered"] += 1
            _tally(
                await _complete_enrichment(
                    db,
                    event_id=event_id,
                    entity_id=entity_id,
                    attempt=attempt,
                    snapshot=snapshot,
                    now=now,
                )
            )

    return summary


async def enrich_one_event(db) -> bool:
    """One event per call: the single-event form of the pass above.

    The scheduled worker runs the batch (:func:`enrich_pending_events`); this is
    the same pass with a batch of one, kept for the drain's own single-row tests
    and for any caller that wants exactly one event resolved. It answers whether
    an event was claimed at all, which is not the same as whether facts were
    resolved: a claimed event that a newer claim fenced still counts, because the
    work was taken and accounted for.
    """
    summary = await enrich_pending_events(db, limit=1)
    return summary["claimed"] > 0
