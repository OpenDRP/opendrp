"""The retry wait is a policy, so it is asserted without a provider or a clock.

`alert_retry_wait` is handed a tenacity state object; everything it reads is a
provider hint (`retry_after`) or the attempt number. These tests pin both
branches of that decision, including the bounds that keep a provider's
`Retry-After: 86400` from parking a delivery for a day.
"""

from types import SimpleNamespace

from app.core.config import settings
from app.services.alert_transport import alert_retry_wait


def _state(*, retry_after=None, attempt: int = 1):
    exception = None
    if retry_after is not None:
        exception = SimpleNamespace(retry_after=retry_after)
    outcome = SimpleNamespace(exception=lambda: exception) if exception is not None else None
    return SimpleNamespace(outcome=outcome, attempt_number=attempt)


def test_a_provider_hint_is_honoured():
    assert alert_retry_wait(_state(retry_after=7.5)) == 7.5


def test_a_provider_hint_is_bounded_in_both_directions():
    assert alert_retry_wait(_state(retry_after=-5)) == 0.0
    assert alert_retry_wait(_state(retry_after=86_400)) == 300.0


def test_without_a_hint_the_local_backoff_grows_and_stops_at_the_ceiling():
    base = settings.ALERT_DELIVERY_RETRY_BASE_SECONDS
    assert alert_retry_wait(_state(attempt=1)) == min(max(base, 1.0), 30.0)
    assert alert_retry_wait(_state(attempt=3)) == min(max(base * 4, 1.0), 30.0)
    assert alert_retry_wait(_state(attempt=20)) == 30.0
