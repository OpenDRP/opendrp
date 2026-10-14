from __future__ import annotations

from unittest.mock import AsyncMock

import pytest


def _drain_outbox(monkeypatch) -> None:
    """Take the notification outbox out of the isolated group-loop tests.

    The worker first drains the durable ingestion outbox and then processes
    delivery groups. These tests pin the group loop against a fake session that
    cannot serve the outbox query, so the drain — a separate collaborator with
    its own coverage — is replaced.
    """
    monkeypatch.setattr(
        "app.services.ingestion_events.dispatch_notification_events",
        AsyncMock(return_value=0),
    )


class _SessionContext:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, exc_type, exc, tb):
        return False


def test_alert_task_processes_groups_until_idle(monkeypatch):
    from app.tasks.alert_tasks import deliver_pending_alerts_task

    session = object()
    results = [
        {"status": "sent", "count": 3},
        {"status": "retry", "count": 2},
        {"status": "failed", "count": 1},
        {"status": "idle", "count": 0},
    ]

    class FakeService:
        def __init__(self, db):
            assert db is session
            self.calls = []

        async def process_one_group(self, **kwargs):
            self.calls.append(kwargs)
            return results.pop(0)

    monkeypatch.setattr(
        "app.core.database.AsyncSessionLocal",
        lambda: _SessionContext(session),
    )
    monkeypatch.setattr("app.services.alert_delivery_service.AlertDeliveryService", FakeService)
    _drain_outbox(monkeypatch)

    summary = deliver_pending_alerts_task.run(max_groups=20)

    assert summary == {
        "groups": 3,
        "sent": 1,
        "retry": 1,
        "failed": 1,
        "cancelled": 0,
        "ambiguous": 0,
        "findings": 6,
    }


def test_alert_task_respects_max_groups(monkeypatch):
    from app.tasks.alert_tasks import deliver_pending_alerts_task

    session = object()
    calls = 0

    class FakeService:
        def __init__(self, db):
            assert db is session

        async def process_one_group(self, **kwargs):
            nonlocal calls
            calls += 1
            return {"status": "sent", "count": 1}

    monkeypatch.setattr(
        "app.core.database.AsyncSessionLocal",
        lambda: _SessionContext(session),
    )
    monkeypatch.setattr("app.services.alert_delivery_service.AlertDeliveryService", FakeService)
    _drain_outbox(monkeypatch)

    summary = deliver_pending_alerts_task.run(max_groups=2)

    assert calls == 2
    assert summary == {
        "groups": 2,
        "sent": 2,
        "retry": 0,
        "failed": 0,
        "cancelled": 0,
        "ambiguous": 0,
        "findings": 2,
    }


def test_alert_task_does_not_hide_worker_errors(monkeypatch):
    from app.tasks.alert_tasks import deliver_pending_alerts_task

    session = object()

    class FakeService:
        def __init__(self, db):
            assert db is session

        async def process_one_group(self, **kwargs):
            raise RuntimeError("database unavailable")

    monkeypatch.setattr(
        "app.core.database.AsyncSessionLocal",
        lambda: _SessionContext(session),
    )
    monkeypatch.setattr("app.services.alert_delivery_service.AlertDeliveryService", FakeService)
    _drain_outbox(monkeypatch)

    with pytest.raises(RuntimeError, match="database unavailable"):
        deliver_pending_alerts_task.run(max_groups=1)


# ==============================================================================
# The other two scheduled tasks
# ==============================================================================
# Each is a thin wrapper around one service call, and that is exactly why they
# need a test: the wrapper owns the session and the return shape, so a rename of
# the scheduled name, a missing `await` or a session that is opened but never used
# leaves the schedule live and the work undone. The critical-coverage gate caught
# the gap — neither body was executed by any test, so `app/tasks/alert_tasks.py`
# sat at 75.68% against a floor of 80.


def test_enrichment_task_reports_what_it_processed(monkeypatch):
    """`process_enrichment_events`, the beat-scheduled WHOIS drain."""
    from app.tasks.alert_tasks import process_enrichment_events_task

    session = object()
    monkeypatch.setattr(
        "app.core.database.AsyncSessionLocal",
        lambda: _SessionContext(session),
    )
    enrich = AsyncMock(return_value=True)
    monkeypatch.setattr("app.services.ingestion_events.enrich_one_event", enrich)

    assert process_enrichment_events_task.run() == {"processed": True}
    # The session the task opens is the one the service is handed: a wrapper that
    # opened its own and passed nothing would otherwise still look right.
    assert enrich.await_args.args[0] is session


def test_enrichment_task_reports_nothing_to_do(monkeypatch):
    from app.tasks.alert_tasks import process_enrichment_events_task

    monkeypatch.setattr(
        "app.core.database.AsyncSessionLocal",
        lambda: _SessionContext(object()),
    )
    monkeypatch.setattr(
        "app.services.ingestion_events.enrich_one_event", AsyncMock(return_value=False)
    )

    assert process_enrichment_events_task.run() == {"processed": False}


def test_dns_expiry_task_reports_the_queued_count(monkeypatch):
    """`check_dns_expiry_alerts`, the scheduled registration/certificate check."""
    from app.tasks.alert_tasks import check_dns_expiry_alerts_task

    session = object()
    monkeypatch.setattr(
        "app.core.database.AsyncSessionLocal",
        lambda: _SessionContext(session),
    )
    queue = AsyncMock(return_value=3)
    monkeypatch.setattr("app.services.dns_expiry_service.queue_expiry_alerts", queue)

    assert check_dns_expiry_alerts_task.run() == {"queued": 3}
    assert queue.await_args.args[0] is session


def test_dns_expiry_task_reports_an_idle_sweep(monkeypatch):
    from app.tasks.alert_tasks import check_dns_expiry_alerts_task

    monkeypatch.setattr(
        "app.core.database.AsyncSessionLocal",
        lambda: _SessionContext(object()),
    )
    monkeypatch.setattr(
        "app.services.dns_expiry_service.queue_expiry_alerts", AsyncMock(return_value=0)
    )

    assert check_dns_expiry_alerts_task.run() == {"queued": 0}
