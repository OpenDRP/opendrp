"""AUD-033: a stored confidence is repaired by a scheduled pass, not left stale.

`score_pending` had no caller outside its own tests, so a release that changed a
weight left every stored `confidence` computed under the old table while the API
recomputed the breakdown with today's. These tests pin the two halves of the fix:
the task calls the pass, and the beat schedule actually runs the task — a task
nothing schedules would be the same defect wearing a different name.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.tasks import phishing_tasks


class _FakeSession:
    async def __aenter__(self):
        return SimpleNamespace()

    async def __aexit__(self, *exc_info) -> bool:
        return False


class TestThePassHasACaller:
    @pytest.mark.asyncio
    async def test_the_task_rescores_and_reports_what_moved(self, monkeypatch):
        import app.core.database as database
        from app.services import phishing_score_service

        monkeypatch.setattr(database, "AsyncSessionLocal", lambda: _FakeSession())
        pass_mock = AsyncMock(return_value=4)
        monkeypatch.setattr(phishing_score_service, "score_pending", pass_mock)

        result = await phishing_tasks.rescore_phishing_candidates_task.run.__wrapped__()

        assert result == {"candidates_moved": 4}
        assert pass_mock.await_count == 1

    def test_the_beat_schedule_runs_it(self):
        """A maintenance pass nothing schedules is the defect, not the fix."""
        from app.core.celery_app import celery_app

        entry = celery_app.conf.beat_schedule["rescore-phishing-candidates-daily"]

        assert entry["task"] == "rescore_phishing_candidates"
        assert entry["options"]["queue"] == "default"
        assert "app.tasks.phishing_tasks" in celery_app.conf.include

    def test_a_redelivered_run_is_safe_to_acknowledge_late(self):
        """Rescoring twice writes the same numbers, so a killed run is retried."""
        from app.core.celery_app import celery_app

        annotations = celery_app.conf.task_annotations["rescore_phishing_candidates"]

        assert annotations["acks_late"] is True
        assert annotations["reject_on_worker_lost"] is True
