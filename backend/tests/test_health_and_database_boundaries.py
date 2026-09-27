"""Readiness probes and the database boundary.

These probes decide whether an orchestrator keeps a replica in rotation, so the
two things worth pinning are that a *failure* actually propagates (a probe that
swallows errors keeps a broken replica serving) and that the Redis client is
closed even when PING fails (otherwise every failed probe leaks a connection).

The engine is read at call time rather than imported as an object precisely so
these tests can substitute one; the substitution is part of the contract, not a
workaround.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from sqlalchemy import String
from sqlalchemy.orm import DeclarativeBase, mapped_column

from app.core import database
from app.core import health


class _FakeConnection:
    def __init__(self, error: Exception | None = None) -> None:
        self.statements: list[str] = []
        self._error = error

    async def execute(self, statement) -> None:
        self.statements.append(str(statement))
        if self._error is not None:
            raise self._error

    async def __aenter__(self) -> "_FakeConnection":
        return self

    async def __aexit__(self, *_exc) -> bool:
        return False


class _FakeEngine:
    def __init__(self, connection: _FakeConnection) -> None:
        self._connection = connection

    def connect(self) -> _FakeConnection:
        return self._connection


class TestDatabaseProbe:
    @pytest.mark.asyncio
    async def test_issues_a_trivial_statement(self, monkeypatch):
        connection = _FakeConnection()
        monkeypatch.setattr(database, "engine", _FakeEngine(connection))

        await health.check_database()

        assert connection.statements == ["SELECT 1"]

    @pytest.mark.asyncio
    async def test_an_unreachable_database_fails_the_probe(self, monkeypatch):
        connection = _FakeConnection(OSError("connection refused"))
        monkeypatch.setattr(database, "engine", _FakeEngine(connection))

        with pytest.raises(OSError):
            await health.check_database()

    @pytest.mark.asyncio
    async def test_uses_the_engine_bound_at_call_time(self, monkeypatch):
        """A replica swapped at runtime must be probed as it is now."""
        first = _FakeConnection()
        monkeypatch.setattr(database, "engine", _FakeEngine(first))
        assert (await health.check_database()) is None

        second = _FakeConnection()
        monkeypatch.setattr(database, "engine", _FakeEngine(second))
        await health.check_database()

        assert second.statements == ["SELECT 1"]


class _FakeRedisClient:
    def __init__(self, *, ping_error: Exception | None = None) -> None:
        self.ping_error = ping_error
        self.pinged = 0
        self.closed = False

    async def ping(self) -> bool:
        self.pinged += 1
        if self.ping_error is not None:
            raise self.ping_error
        return True

    async def aclose(self) -> None:
        self.closed = True


class TestRedisProbe:
    @pytest.mark.asyncio
    async def test_pings_and_releases_the_client(self, monkeypatch):
        client = _FakeRedisClient()
        captured: dict = {}

        def _from_url(url, **kwargs):
            captured["url"] = url
            captured["kwargs"] = kwargs
            return client

        monkeypatch.setattr("redis.asyncio.Redis", MagicMock(from_url=_from_url))

        await health.check_redis()

        assert client.pinged == 1
        assert client.closed is True
        # A probe must time out on its own, before the orchestrator loses patience.
        assert captured["kwargs"]["socket_timeout"] == health._PROBE_TIMEOUT_SECONDS
        assert captured["kwargs"]["socket_connect_timeout"] == health._PROBE_TIMEOUT_SECONDS

    @pytest.mark.asyncio
    async def test_a_failed_ping_propagates_but_still_closes_the_client(self, monkeypatch):
        client = _FakeRedisClient(ping_error=ConnectionError("redis down"))
        monkeypatch.setattr("redis.asyncio.Redis", MagicMock(from_url=lambda *a, **k: client))

        with pytest.raises(ConnectionError):
            await health.check_redis()

        assert client.closed is True


class _FakeSession:
    """Behaves like ``AsyncSessionLocal()``: an async context manager."""

    def __init__(self) -> None:
        self.closed = False

    async def __aenter__(self) -> "_FakeSession":
        return self

    async def __aexit__(self, *_exc) -> bool:
        return False

    async def close(self) -> None:
        self.closed = True


class TestSessionDependency:
    @pytest.mark.asyncio
    async def test_yields_a_session_and_closes_it(self, monkeypatch):
        session = _FakeSession()
        monkeypatch.setattr(database, "AsyncSessionLocal", lambda: session)

        yielded = [item async for item in database.get_db()]

        assert yielded == [session]
        assert session.closed is True

    @pytest.mark.asyncio
    async def test_closes_the_session_when_the_consumer_stops_early(self, monkeypatch):
        """A handler that raises must not leak the connection back into the pool."""
        session = _FakeSession()
        monkeypatch.setattr(database, "AsyncSessionLocal", lambda: session)

        generator = database.get_db()
        assert await generator.__anext__() is session
        await generator.aclose()

        assert session.closed is True


#: Mixin coverage asserts the *declared* column contract, not the instance
#: values: SQLAlchemy applies python-side defaults at flush, so an un-flushed
#: object legitimately has None in every defaulted attribute.


class _ProbeBase(DeclarativeBase):
    """A declarative base of this module's own, not the application's.

    These classes exist to assert the *mixin* contract. Declaring them on the
    application's ``Base`` would leave them in ``Base.metadata`` for the rest of
    the session — ``tests/conftest.py`` calls ``create_all``/``drop_all`` per test
    function, so every later test would create and drop two tables no revision
    knows about, and ``scripts/check_schema_drift.py`` would report them as
    drift the moment that module was imported first.
    """


def _uuid_row():
    from app.core.database import UUIDMixin

    class _UuidRow(_ProbeBase, UUIDMixin):
        __tablename__ = "test_uuid_defaults"

    return _UuidRow


def _stamped_row():
    from app.core.database import TimestampMixin, UUIDMixin

    class _StampedRow(_ProbeBase, UUIDMixin, TimestampMixin):
        __tablename__ = "test_timestamp_defaults"

        name = mapped_column(String(10))

    return _StampedRow


class TestMixinDefaults:
    def test_the_primary_key_is_generated_by_the_orm(self):
        column = _uuid_row().__table__.c.id

        assert column.primary_key is True
        # Generated on the Python side, so a row is addressable by id before it
        # is flushed — the relationship wiring and audit logging rely on that.
        assert column.default is not None
        assert column.default.is_callable

    def test_timestamps_are_timezone_aware_and_refresh_on_update(self):
        table = _stamped_row().__table__

        # Naive timestamps in an audit-facing product are a bug, not a style
        # preference: the audit trail is compared across deployments.
        assert table.c.created_at.type.timezone is True
        assert table.c.updated_at.type.timezone is True
        assert table.c.created_at.default is not None
        assert table.c.updated_at.default is not None
        # Without onupdate, updated_at would silently equal created_at forever.
        assert table.c.updated_at.onupdate is not None
