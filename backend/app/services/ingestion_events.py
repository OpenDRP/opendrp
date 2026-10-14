from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from app.models.ingestion_event import IngestionEvent
from app.models.phishing import PhishingDomain
from app.services.alert_delivery_service import AlertDeliveryService


async def record_event(db, *, kind, module, entity_id, payload, job_id=None):
    key = f"{kind}:{module}:{entity_id}"
    existing = (await db.execute(select(IngestionEvent.id).where(IngestionEvent.event_key == key))).scalar_one_or_none()
    if existing is None:
        db.add(IngestionEvent(event_key=key, kind=kind, module=module, entity_id=entity_id, job_id=job_id, payload=payload))
        await db.flush()


async def dispatch_notification_events(db, limit=100):
    now = datetime.now(timezone.utc)
    rows = list((await db.execute(select(IngestionEvent).where(IngestionEvent.kind == "notification", IngestionEvent.processed_at.is_(None), (IngestionEvent.next_attempt_at.is_(None)) | (IngestionEvent.next_attempt_at <= now)).order_by(IngestionEvent.created_at, IngestionEvent.id).limit(limit).with_for_update(skip_locked=True))).scalars())
    processed = 0
    for row in rows:
        result = await AlertDeliveryService(db).enqueue(threat_type=row.module, details=row.payload, job_id=row.job_id)
        if result is not None:
            row.processed_at = now
            processed += 1
        elif row.module == "module:operations":
            row.next_attempt_at = now + timedelta(minutes=5)
            row.last_error = "no_delivery_channel"
        else:
            # No delivery configured is terminal for the current deployment:
            # avoid retrying the same outbox row every five minutes forever.
            row.processed_at = now
            row.last_error = "no_delivery_channel"
    await db.commit()
    return processed


async def enrich_one_event(db):
    now = datetime.now(timezone.utc)
    row = (await db.execute(select(IngestionEvent).where(IngestionEvent.kind == "whois", IngestionEvent.processed_at.is_(None), (IngestionEvent.next_attempt_at.is_(None)) | (IngestionEvent.next_attempt_at <= now)).order_by(IngestionEvent.created_at).limit(1).with_for_update(skip_locked=True))).scalar_one_or_none()
    if row is None:
        return False
    row.attempts += 1
    row.next_attempt_at = now + timedelta(minutes=5)
    event_id, entity_id, attempt = row.id, row.entity_id, row.attempts
    await db.commit()  # No locks held during external enrichment.
    from types import SimpleNamespace
    threat = await db.get(PhishingDomain, entity_id)
    fields = ("phishing_domain", "whois_registrar", "whois_abuse_email", "domain_created_at")
    snapshot = SimpleNamespace(**{field: getattr(threat, field) for field in fields}) if threat else None
    await db.commit()  # End the read transaction before DNS/WHOIS network calls.

    class DetachedEnrichmentSession:
        async def commit(self):
            return None

        async def refresh(self, entity):
            return None

    error = None
    try:
        if snapshot is not None:
            from app.services.phishing.whois_service import WhoisService
            await WhoisService(DetachedEnrichmentSession()).enrich(snapshot)
    except Exception as exc:
        error = type(exc).__name__[:128]
    row = (await db.execute(select(IngestionEvent).where(IngestionEvent.id == event_id).with_for_update().execution_options(populate_existing=True))).scalar_one_or_none()
    if row is None or row.processed_at is not None or row.attempts != attempt:
        await db.rollback()
        return True  # A newer claim fences this result.
    if error:
        row.last_error = error
        row.next_attempt_at = datetime.now(timezone.utc) + timedelta(seconds=min(3600, 30 * 2 ** min(attempt, 7)))
    else:
        threat = await db.get(PhishingDomain, entity_id)
        if threat is not None and snapshot is not None:
            for field in fields[1:]:
                if not getattr(threat, field):
                    setattr(threat, field, getattr(snapshot, field))
        row.processed_at = datetime.now(timezone.utc)
        row.last_error = None
    await db.commit()
    return True
