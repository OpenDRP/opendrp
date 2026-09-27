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

    summary = {"groups": 0, "sent": 0, "retry": 0, "failed": 0, "findings": 0}
    async with AsyncSessionLocal() as db:
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
