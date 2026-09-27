from __future__ import annotations

import pytest


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

    summary = deliver_pending_alerts_task.run(max_groups=20)

    assert summary == {
        "groups": 3,
        "sent": 1,
        "retry": 1,
        "failed": 1,
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

    summary = deliver_pending_alerts_task.run(max_groups=2)

    assert calls == 2
    assert summary == {
        "groups": 2,
        "sent": 2,
        "retry": 0,
        "failed": 0,
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

    with pytest.raises(RuntimeError, match="database unavailable"):
        deliver_pending_alerts_task.run(max_groups=1)
