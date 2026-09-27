"""The per-connection statement limits, and how a timeout is reported.

Two failures are being prevented here, and neither is visible in a passing
functional test:

1. **The limits silently disappearing.** They are passed to asyncpg rather than
   to the ORM, so a refactor of the engine options — or a driver change — can
   drop them without a single test going red. The pool is bounded, which is what
   turns "one slow query" into "the platform stops answering", so the presence of
   the limits is asserted rather than assumed.
2. **A deliberate limit being reported as a defect.** A statement the database
   cancelled on purpose (SQLSTATE 57014) must not look like an unhandled bug, or
   the operator learns to ignore the one signal that says the platform is being
   asked to do too much in one statement.
"""

from __future__ import annotations

import sqlite3

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.exc import DBAPIError
from sqlalchemy.exc import TimeoutError as SQLAlchemyPoolTimeout
from sqlalchemy.pool import QueuePool

from app.core.config import Settings
from app.core.database import engine_kwargs, postgres_connect_args
from app.core.exceptions import (
    _is_database_timeout,
    register_exception_handlers,
    statement_timeout_sqlstate,
)


class _StatementTimeout(Exception):
    """Stands in for ``asyncpg.exceptions.QueryCanceledError``."""

    sqlstate = "57014"


class _UndefinedTable(Exception):
    """A real bug: the statement was never valid."""

    sqlstate = "42P01"


def _dbapi_error(orig: BaseException) -> DBAPIError:
    return DBAPIError(None, None, orig)


class TestPoolTimeout:
    def test_connection_pool_timeout_is_bounded_and_surfaces_as_pool_timeout(self):
        """A saturated pool must fail promptly instead of hanging a request.

        The application uses the same QueuePool options for asyncpg. A small
        synchronous SQLite pool makes the boundary deterministic without
        requiring PostgreSQL: one checked-out connection, no overflow, and a
        short configured wait must produce SQLAlchemy's pool timeout.
        """
        pool = QueuePool(
            lambda: sqlite3.connect(":memory:"),
            pool_size=1,
            max_overflow=0,
            timeout=0.05,
        )
        engine = create_engine("sqlite://", pool=pool)
        first = engine.connect()
        try:
            with pytest.raises(SQLAlchemyPoolTimeout, match="QueuePool limit"):
                engine.connect()
        finally:
            first.close()
            engine.dispose()


class TestEngineOptions:
    def test_postgres_engine_carries_the_statement_limits(self):
        options = engine_kwargs("postgresql+asyncpg://u:p@postgres:5432/opendrp")
        server_settings = options["connect_args"]["server_settings"]

        assert int(server_settings["statement_timeout"]) > 0
        assert int(server_settings["lock_timeout"]) > 0
        assert int(server_settings["idle_in_transaction_session_timeout"]) > 0
        assert server_settings["application_name"]
        assert options["connect_args"]["command_timeout"] > 0

    def test_limits_follow_the_settings(self):
        custom = Settings(
            DB_STATEMENT_TIMEOUT_MS=1234,
            DB_LOCK_TIMEOUT_MS=99,
            DB_IDLE_IN_TRANSACTION_TIMEOUT_MS=4321,
            DB_COMMAND_TIMEOUT_SECONDS=7,
            DB_APPLICATION_NAME="opendrp-test",
        )
        server_settings = postgres_connect_args(custom)["server_settings"]

        assert server_settings["statement_timeout"] == "1234"
        assert server_settings["lock_timeout"] == "99"
        assert server_settings["idle_in_transaction_session_timeout"] == "4321"
        assert server_settings["application_name"] == "opendrp-test"
        assert postgres_connect_args(custom)["command_timeout"] == pytest.approx(7.0)

    def test_zero_disables_the_bound_instead_of_removing_the_argument(self):
        """`0` is PostgreSQL's own spelling for "no limit".

        Dropping the setting when it is zero would look equivalent and is not:
        the operator who raised it to 0 to let a large report finish would get
        whatever the server's default is, which is also no limit — but on a
        deployment where the default is set to something small, the difference
        decides whether the report runs at all.
        """
        disabled = Settings(DB_STATEMENT_TIMEOUT_MS=0)
        assert postgres_connect_args(disabled)["server_settings"]["statement_timeout"] == "0"

    def test_client_timeout_stays_above_the_server_statement_timeout(self):
        """Postgres should be the one to cancel a slow statement.

        A shorter client timeout would abort the connection first, and the caller
        would see a disconnect instead of a database that said "this was too
        expensive" — a distinction the 503 mapping depends on.
        """
        defaults = Settings()
        assert defaults.DB_STATEMENT_TIMEOUT_MS > 0
        assert defaults.DB_COMMAND_TIMEOUT_SECONDS * 1000 > defaults.DB_STATEMENT_TIMEOUT_MS

    def test_sqlite_engine_is_untouched(self):
        options = engine_kwargs("sqlite+aiosqlite:///./test.sqlite3")
        assert "server_settings" not in options.get("connect_args", {})
        assert "pool_size" not in options


class TestTimeoutClassification:
    def test_statement_timeout_sqlstate_is_recognized(self):
        assert statement_timeout_sqlstate(_dbapi_error(_StatementTimeout())) == "57014"
        assert _is_database_timeout(_dbapi_error(_StatementTimeout())) is True

    def test_another_sqlstate_is_not_a_timeout(self):
        error = _dbapi_error(_UndefinedTable())
        assert statement_timeout_sqlstate(error) == "42P01"
        assert _is_database_timeout(error) is False

    def test_client_side_command_timeout_is_recognized(self):
        """asyncpg's `command_timeout` arrives as a driver TimeoutError."""
        assert _is_database_timeout(_dbapi_error(TimeoutError())) is True


@pytest.mark.asyncio
class TestTimeoutResponse:
    """The handlers, exercised through a real application."""

    @staticmethod
    def _app(exc: BaseException | None, *, raise_exc: bool = False) -> FastAPI:
        application = FastAPI()
        register_exception_handlers(application)

        @application.get("/boom")
        async def boom():  # pragma: no cover - the handler is the subject
            raise exc  # type: ignore[misc]

        return application

    async def _get(self, exc: BaseException | None) -> tuple[int, dict | str, dict]:
        app = self._app(exc)
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get("/boom")
        try:
            body: dict | str = response.json()
        except ValueError:
            body = response.text
        return response.status_code, body, dict(response.headers)

    async def test_statement_timeout_becomes_a_retryable_503(self):
        status, body, headers = await self._get(_dbapi_error(_StatementTimeout()))
        assert status == 503
        assert body["code"] == "database_busy"
        assert headers["retry-after"] == "5"

    async def test_pool_timeout_is_reported_as_a_retryable_503(self):
        status, body, headers = await self._get(SQLAlchemyPoolTimeout("pool exhausted"))
        assert status == 503
        assert body["code"] == "database_busy"
        assert headers["retry-after"] == "5"
        assert "pool" in body["detail"].lower()

    async def test_client_side_timeout_is_reported_the_same_way(self):
        status, body, _headers = await self._get(_dbapi_error(TimeoutError()))
        assert status == 503
        assert body["code"] == "database_busy"

    async def test_an_ordinary_database_error_stays_a_500(self):
        """The mapping must not swallow real defects."""
        status, body, _headers = await self._get(_dbapi_error(_UndefinedTable()))
        assert status == 500
        assert body == "Internal Server Error"
