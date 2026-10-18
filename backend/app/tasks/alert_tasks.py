"""Durable alert delivery worker.

Finding ingestion only writes queue rows. This task is allowed to perform
network I/O and is safe to stop: locked rows are reclaimed after a lease and
failed rows are retried with bounded exponential backoff.
"""

from app.core.celery_app import async_task, celery_app
from app.core.config import settings


@celery_app.task(name="deliver_pending_alerts", ignore_result=False)
@async_task
async def deliver_pending_alerts_task(self=None, *, max_groups: int = 20) -> dict:
    from app.core.database import AsyncSessionLocal
    from app.services.alert_delivery_service import AlertDeliveryService

    summary = {"groups": 0, "sent": 0, "retry": 0, "failed": 0, "cancelled": 0, "ambiguous": 0, "findings": 0}
    async with AsyncSessionLocal() as db:
        from app.services.ingestion_events import dispatch_notification_events
        await dispatch_notification_events(db)
        service = AlertDeliveryService(db)
        for _ in range(max_groups):
            result = await service.process_one_group(
                max_attempts=settings.ALERT_DELIVERY_MAX_ATTEMPTS,
                limit=settings.ALERT_MAX_FINDINGS_PER_MESSAGE,
            )
            if result["status"] == "idle":
                break
            summary["groups"] += 1
            summary["findings"] += result["count"]
            key = result["status"]
            if key in summary:
                summary[key] += 1
    return summary


@celery_app.task(name="send_phishing_digest", ignore_result=True)
@async_task
async def send_phishing_digest_task(self=None) -> dict:
    """The daily phishing digest, the middle band's own channel (WI-10, W1.4).

    The budget routes a candidate that is not worth interrupting someone for into
    this pass instead of dropping it, and the pass runs once a day so the channel
    answers "what did the platform see?" without answering it eighty times. It
    queues into the ordinary delivery queue — no separate sender, no second retry
    policy — which is why a digest inherits the reliability the alert path already
    has, including an attempt record an operator can inspect.

    The task is the schedule's adapter and nothing else: the beat entry ticks hourly
    and ``run_phishing_digest`` decides from the resolved policy whether this is the
    hour the operator asked for, so the hour can be changed in Settings instead of
    in a container's environment (see ``app/services/alert_policy.py``).
    """
    from app.core.database import AsyncSessionLocal
    from app.services.ingestion_events import run_phishing_digest

    async with AsyncSessionLocal() as db:
        return await run_phishing_digest(db)


@celery_app.task(name="send_breach_digest", ignore_result=True)
@async_task
async def send_breach_digest_task(self=None) -> dict:
    """The breach backlog's own pass: the scans past the digest threshold (WI-06).

    A server-side scan of a shared hosting provider can return hundreds of new
    incidents at once, and one message per incident is not a report of that - it is
    the channel being flooded by the source's own discovery. Past
    ``ALERT_BREACH_DIGEST_THRESHOLD`` the drain holds a scan's notifications and
    this pass turns them into a summary. Same queue, same retry policy, same
    recipient rotation as every other alert; only the wording changes.

    The tick is hourly and the pass decides whether this is the configured hour, so
    the hour can be changed in Settings without recreating a container, exactly as
    the phishing digest does.
    """
    from app.core.database import AsyncSessionLocal
    from app.services.ingestion_events import run_breach_digest

    async with AsyncSessionLocal() as db:
        return await run_breach_digest(db)


@celery_app.task(name="process_enrichment_events", ignore_result=True)
@async_task
async def process_enrichment_events_task(self=None) -> dict:
    """The registration enrichment pass: one batch per tick (WI-01, WI-25).

    The schedule is unchanged — every fifteen seconds — but a tick now serves a
    batch instead of the single oldest event, and it answers with what it did by
    outcome rather than a bare boolean. Both matter to whoever is reading a quiet
    day: an installation whose registry refuses it, and one whose scan found
    nothing, used to report the same thing, and now do not. The pass itself owns
    the pacing, the cache and the pauses (see ``app/services/ingestion_events``).
    """
    from app.core.database import AsyncSessionLocal
    from app.services.ingestion_events import enrich_pending_events

    async with AsyncSessionLocal() as db:
        return await enrich_pending_events(db)


@celery_app.task(name="check_dns_expiry_alerts", ignore_result=True)
@async_task
async def check_dns_expiry_alerts_task(self=None) -> dict:
    """The daily DNS sweep: expiry reminders, controls gone quiet, and certificates.

    All three share one schedule because they answer the same question from different
    sides - an expiry date the platform knows about, a control it has stopped hearing
    from, and a certificate of ours seen somewhere that is not ours - and every one of
    them ends in the same aggregated delivery. The certificate step projects the new
    evidence into identities and sightings first, then scores it.
    """
    from app.core.database import AsyncSessionLocal
    from app.services.dns_expiry_service import queue_expiry_alerts, queue_stale_monitor_alerts
    from app.services.tls_identity_service import run_certificate_sweep

    async with AsyncSessionLocal() as db:
        count = await queue_expiry_alerts(db)
        stale = await queue_stale_monitor_alerts(db)
        certificates = await run_certificate_sweep(db)
    return {"queued": count, "stale": stale, "certificates": certificates}
