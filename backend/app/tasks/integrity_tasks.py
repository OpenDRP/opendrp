"""Nightly verification of the audit hash chain.

Verification is only worth having if it runs without being asked for. A chain
that is checked when someone remembers to check it records the day a
maintainer was curious, not the day something was deleted — and the entries a
break was hiding are exactly the ones a later retention sweep will remove.

So the check is a scheduled task, it is incremental (it starts where the
previous pass finished), and a failure is loud in three places at once: the log
stream, the audit trail itself, and the operator's configured alert channel. The
one thing it never does is repair anything — a chain that does not verify is the
finding, and rewriting it would destroy the evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.core.audit_chain import verify
from app.core.celery_app import async_task, celery_app
from app.core.logging_config import get_logger

log = get_logger("opendrp.integrity")

#: Audit actions. Both exist so that a SIEM rule can distinguish "the chain was
#: checked and held" from "the chain was checked and did not hold" without
#: parsing prose out of a details blob.
ACTION_CHAIN_VERIFIED = "audit.chain.verified"
ACTION_CHAIN_BROKEN = "audit.chain.broken"


async def _notify_break(details: dict) -> None:
    """Send the alert through the operator's own channel.

    A break found at 04:45 and read at 09:00 is a break with a five-hour head
    start, so it goes out the same way a finding does. Failure to send is logged
    and swallowed: the audit row and the log line are already written, and an
    unreachable SMTP server must not make the verification look like it did not
    run.
    """
    try:
        from app.core.database import AsyncSessionLocal
        from app.services.alert_service import AlertService

        subject = "[OpenDRP] Audit chain verification failed"
        body = (
            "<h2>Audit chain verification failed</h2>"
            "<p>The stored audit trail does not hash-chain. This is either "
            "database tampering or a corruption that must be explained.</p>"
            f"<pre>{details}</pre>"
            "<p>Run <code>python -m scripts.verify_audit_chain --full</code> and "
            "compare the reported position against the SIEM's copy of the audit "
            "stream.</p>"
        )
        async with AsyncSessionLocal() as session:
            await AlertService(session).send_operator_message(
                subject=subject, html_body=body, plain_body=str(details)
            )
    except Exception as exc:  # pragma: no cover - depends on operator channels
        log.warning("audit_chain_alert_failed", err=str(exc)[:200])


@celery_app.task(name="verify_audit_chain", ignore_result=False)
@async_task
async def verify_audit_chain_task(self=None, *, full: bool = False) -> dict:
    """Celery entry point. ``full=True`` re-derives the whole retained chain."""
    from app.core.audit import AuditLogger
    from app.core.database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        result = await verify(db, full=full)

    details = {
        **result.as_details(),
        "full": full,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    log.info(
        "audit_chain_verified" if result.ok else "audit_chain_broken",
        **{key: value for key, value in details.items() if key != "checked_at"},
    )
    if not result.ok:
        await _notify_break(details)

    try:
        async with AsyncSessionLocal() as session:
            await AuditLogger.emit(
                session,
                action=ACTION_CHAIN_VERIFIED if result.ok else ACTION_CHAIN_BROKEN,
                ip_address="internal:celery-beat",
                user_id=None,
                details=details,
            )
    except Exception as exc:
        log.error("audit_chain_emit_failed", err=str(exc)[:200])

    return details
