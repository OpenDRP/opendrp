"""How an alert leaves the platform when the reason is the transport itself.

Two things live here because they are decided by the transport and by nothing
else: the error taxonomy a delivery attempt is classified into, and the bounded
SMTP thread pool that keeps a slow provider from consuming the worker.

The classification is what the queue acts on, so the distinctions are load
bearing. `Transient` means "the provider did not take it and can be asked
again"; `Permanent` means asking again would only repeat a rejection;
`Ambiguous` means the provider may or may not have accepted the message, which
is the one state a retry would turn into a duplicate — it needs a person, not a
second attempt. `Cancelled` is not a provider's answer at all: the destination
the delivery was queued for is gone.
"""

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor

from tenacity import RetryCallState

from app.core.config import settings


class AlertDeliveryTransientError(RuntimeError):
    """A provider/network failure that is safe to retry."""

    def __init__(self, message: str, *, retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class AlertDeliveryAmbiguousError(RuntimeError):
    """Provider acceptance is unknown; operator reconciliation is required."""


class AlertDeliveryCancelledError(RuntimeError):
    """The configured destination no longer permits this queued delivery."""


class AlertDeliveryPermanentError(RuntimeError):
    """A configuration or provider rejection that must not be retried."""


def alert_retry_wait(state: RetryCallState) -> float:
    """Honor provider Retry-After without losing the local exponential backoff."""
    exception = state.outcome.exception() if state.outcome else None
    retry_after = getattr(exception, "retry_after", None)
    if retry_after is not None:
        return min(max(float(retry_after), 0.0), 300.0)
    # Keep a bounded fallback for network failures that carry no provider hint.
    attempt = max(state.attempt_number - 1, 0)
    return min(max(settings.ALERT_DELIVERY_RETRY_BASE_SECONDS * (2**attempt), 1.0), 30.0)


_SMTP_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="alert-smtp")
_SMTP_SLOTS = threading.BoundedSemaphore(4)


async def bounded_smtp(operation):
    if not _SMTP_SLOTS.acquire(blocking=False):
        raise AlertDeliveryTransientError("SMTP workers are busy")
    future = _SMTP_EXECUTOR.submit(operation)
    future.add_done_callback(lambda done: _SMTP_SLOTS.release())
    try:
        await asyncio.wait_for(asyncio.shield(asyncio.wrap_future(future)), settings.ALERT_DELIVERY_TIMEOUT_SECONDS)
    except asyncio.TimeoutError as exc:
        # The slot remains occupied until the thread actually exits. Do not start
        # another attempt: cancellation cannot establish provider non-acceptance.
        raise AlertDeliveryAmbiguousError("SMTP deadline exceeded; acceptance unknown") from exc
