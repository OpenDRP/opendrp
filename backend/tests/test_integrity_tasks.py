"""The nightly audit-chain check: loud, incremental, and never repairing.

Verification that nobody runs records the day a maintainer was curious. This task
is what makes the chain worth having, so the properties under test are the ones
that decide whether it works unattended: both outcomes are written to the audit
trail under their own action, a break pages the operator through the channel the
operator configured, a failure to *send* that page does not stop the record, and
nothing in the path ever rewrites the chain it just judged.
"""

from __future__ import annotations

import asyncio
import functools
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.core.audit import AUDIT_ALLOWED_ACTIONS, AuditLogger
from app.core.audit_chain import ChainVerification
from app.tasks import integrity_tasks as it


class _Session:
    """Enough of ``AsyncSessionLocal()`` for the task's two ``async with`` blocks."""

    def __init__(self) -> None:
        self.entered = 0

    async def __aenter__(self):
        self.entered += 1
        return AsyncMock()

    async def __aexit__(self, *_exc_info) -> bool:
        return False


@pytest.fixture
def env(monkeypatch):
    """The task with its chain walk, database, audit sink and pager replaced."""

    def _environment(result: ChainVerification, emit_error: Exception | None = None):
        verify = AsyncMock(return_value=result)
        notify = AsyncMock()

        async def _emit(*_args, **_kwargs):
            if emit_error is not None:
                raise emit_error

        emit = AsyncMock(side_effect=_emit)
        sessions: list[_Session] = []

        def _factory() -> _Session:
            session = _Session()
            sessions.append(session)
            return session

        monkeypatch.setattr(it, "verify", verify)
        async def full_chunk(db):
            return await verify(db, full=True)
        monkeypatch.setattr("app.services.audit_verification.verify_full_chunk", full_chunk)
        monkeypatch.setattr(it, "_notify_break", notify)
        monkeypatch.setattr(AuditLogger, "emit", emit)
        monkeypatch.setattr("app.core.database.AsyncSessionLocal", _factory)
        return SimpleNamespace(verify=verify, notify=notify, emit=emit, sessions=sessions)

    return _environment


async def _run_task(full: bool = False) -> dict:
    """``.run`` drives its own event loop, so it must be called off the test loop."""
    return await asyncio.get_running_loop().run_in_executor(
        None, functools.partial(it.verify_audit_chain_task.run, full=full)
    )


def test_both_outcomes_have_an_allowlisted_action() -> None:
    """An unlisted action is stored under a name the UI cannot label."""
    assert it.ACTION_CHAIN_VERIFIED in AUDIT_ALLOWED_ACTIONS
    assert it.ACTION_CHAIN_BROKEN in AUDIT_ALLOWED_ACTIONS


class TestVerifiedChain:
    @pytest.mark.asyncio
    async def test_a_chain_that_holds_is_recorded_and_nobody_is_paged(self, env):
        environment = env(ChainVerification(checked=5, through_seq=5))

        summary = await _run_task()

        environment.notify.assert_not_awaited()
        assert not environment.verify.await_args.kwargs.get("full", False)
        assert environment.emit.await_args.kwargs["action"] == it.ACTION_CHAIN_VERIFIED
        assert environment.emit.await_args.kwargs["ip_address"] == "internal:celery-beat"
        # No user: this is the platform checking itself, and a user_id here would
        # put the sweep in somebody's name.
        assert environment.emit.await_args.kwargs["user_id"] is None
        assert summary["checked"] == 5
        assert summary["full"] is False
        assert summary["checked_at"]

    @pytest.mark.asyncio
    async def test_a_full_pass_is_declared_in_the_record(self, env):
        environment = env(ChainVerification(checked=40, through_seq=40))

        await _run_task(full=True)

        assert environment.verify.await_args.kwargs["full"] is True
        assert environment.emit.await_args.kwargs["details"]["full"] is True


class TestBreakNotification:
    """The page a break sends: one outbox row, and it never becomes a second failure.

    The task's other tests replace ``_notify_break`` because they are about the
    verdict. These pin the page itself, which is the only part of the nightly
    check an operator actually sees at 04:45.
    """

    @staticmethod
    def _session(db):
        class _Context:
            async def __aenter__(self):
                return db

            async def __aexit__(self, *_exc_info):
                return False

        return _Context()

    @pytest.mark.asyncio
    async def test_a_break_is_queued_as_one_notification_event(self, db_session, monkeypatch):
        import uuid
        from sqlalchemy import select

        from app.core import database
        from app.models.ingestion_event import IngestionEvent

        monkeypatch.setattr(database, "AsyncSessionLocal", lambda: self._session(db_session))
        details = {
            "checked": 12,
            "through_seq": 12,
            "first_broken_seq": 7,
            "reason": "hash_mismatch",
            "full": True,
            "checked_at": "2026-10-20T04:45:00+00:00",
        }

        await it._notify_break(details)

        rows = (
            await db_session.execute(select(IngestionEvent))
        ).scalars().all()
        assert len(rows) == 1
        event = rows[0]
        assert event.kind == "notification"
        assert event.module == "module:operations"
        assert event.payload["title"] == "[OpenDRP] Audit chain verification failed"
        assert event.payload["fields"]["first_broken_seq"] == 7
        # The id is derived from the finding, so a repeat pass over the same
        # break cannot page the operator twice.
        expected = uuid.uuid5(
            uuid.NAMESPACE_URL,
            "audit-chain-break:"
            + json.dumps(
                {key: value for key, value in details.items() if key != "checked_at"},
                sort_keys=True,
            ),
        )
        assert event.entity_id == expected

        await it._notify_break({**details, "checked_at": "2026-10-20T05:45:00+00:00"})
        again = (await db_session.execute(select(IngestionEvent))).scalars().all()
        assert len(again) == 1

    @pytest.mark.asyncio
    async def test_a_channel_that_cannot_be_reached_does_not_fail_the_check(
        self, db_session, monkeypatch
    ):
        """The audit row and the log line are already written; the page is best effort."""
        from app.core import database

        monkeypatch.setattr(database, "AsyncSessionLocal", lambda: self._session(db_session))

        async def _unavailable(*_args, **_kwargs):
            raise RuntimeError("operator channels are down")

        monkeypatch.setattr(
            "app.services.ingestion_events.record_event", _unavailable
        )

        await it._notify_break({"first_broken_seq": 1, "reason": "gap"})


class TestBrokenChain:
    @pytest.mark.asyncio
    async def test_a_break_names_where_it_happened_and_pages_the_operator(self, env):
        environment = env(
            ChainVerification(
                checked=10,
                from_seq=1,
                through_seq=11,
                retired_through_seq=1,
                first_broken_seq=5,
                reason="hash_mismatch",
            )
        )

        summary = await _run_task()

        environment.notify.assert_awaited_once()
        paged = environment.notify.await_args.args[0]
        assert paged["first_broken_seq"] == 5
        assert paged["reason"] == "hash_mismatch"
        assert environment.emit.await_args.kwargs["action"] == it.ACTION_CHAIN_BROKEN
        assert summary["reason"] == "hash_mismatch"
        # The chain is reported on, never touched: the only query the task makes
        # is the verification pass itself.
        assert environment.verify.await_count == 1

    @pytest.mark.asyncio
    async def test_a_failed_audit_write_does_not_discard_the_result(self, env):
        """The alert already went out; losing the summary would hide the pass."""
        environment = env(
            ChainVerification(checked=3, through_seq=3, first_broken_seq=2, reason="gap"),
            emit_error=RuntimeError("database is gone"),
        )

        summary = await _run_task()

        environment.notify.assert_awaited_once()
        assert summary["first_broken_seq"] == 2
