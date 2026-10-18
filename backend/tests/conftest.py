from __future__ import annotations

import os
import atexit
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

_TMP_DB = Path(tempfile.gettempdir()) / f"opendrp_test_{os.getpid()}_{__import__('time').time_ns()}.sqlite3"
# The ordinary test suite is isolated on a temporary SQLite file. A small set
# of concurrency tests can opt into a dedicated PostgreSQL database because
# SQLite does not implement SELECT FOR UPDATE; callers must provision that DB.
_test_database_url = os.environ.get("OPENDRP_TEST_DATABASE_URL")
if _test_database_url and "_test" not in _test_database_url.rsplit("/", 1)[-1].lower():
    raise RuntimeError("OPENDRP_TEST_DATABASE_URL must target a dedicated database with '_test' in its name")
os.environ["DATABASE_URL"] = _test_database_url or f"sqlite+aiosqlite:///{_TMP_DB}"
os.environ["APP_ENV"] = "test"
os.environ["TESTING"] = "1"
# Tests must not inherit a developer's production-like MFA setting from the
# repository .env. MFA-specific tests enable it explicitly with monkeypatch;
# keeping the default off preserves isolation and avoids unrelated RBAC tests
# being blocked by onboarding policy.
os.environ["REQUIRE_MFA_FOR_ADMINS"] = "false"
if not _test_database_url and _TMP_DB.exists():
    try:
        _TMP_DB.unlink()
    except OSError:
        pass


@atexit.register
def _rm_tmp_db():
    try:
        if not _test_database_url and _TMP_DB.exists():
            _TMP_DB.unlink()
    except Exception:
        pass


import uuid  # noqa: E402
from typing import AsyncGenerator  # noqa: E402

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402


@pytest.fixture
def without_testing_switch(monkeypatch):
    """Remove the suite's `TESTING=1` for a test that builds production settings.

    `TESTING` makes scan admission fail-open and the rate limiter behave as if
    Redis were unreachable, so the suite sets it once for everyone. Production
    settings are supposed to refuse that flag outright, which means a module that
    constructs `Settings(APP_ENV="production")` has to look like a deployment
    rather than like the suite: opt in with
    `pytestmark = pytest.mark.usefixtures("without_testing_switch")`.

    `APP_ENV=test` still carries the suite's other bypasses, so this removes only
    the flag production refuses and leaves the test environment intact.
    """
    monkeypatch.delenv("TESTING", raising=False)


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(config, items):
    """Auto-tag tests that use the HTTP ``client`` fixture as ``integration``.

    Lets CI / developers run the fast unit set with ``-m 'not integration'``
    while the full suite keeps its current behavior.
    """
    for item in items:
        if "client" in getattr(item, "fixturenames", ()):
            item.add_marker(pytest.mark.integration)
from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy import event  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool  # noqa: E402

from app.core.database import Base  # noqa: E402
from app.core.security import create_access_token  # noqa: E402
# The dependency the routers actually declare. ``app.core.database.get_db`` is a
# second, unconnected function: overriding it left every request opening its own
# session from ``app.api.deps.AsyncSessionLocal``, so the override did nothing and
# the suite only appeared to share state because both engines point at the same
# database (RWI-09).
from app.api.deps import get_db  # noqa: E402
from app.models.asset import Asset  # noqa: E402,F401
from app.models.user import User, UserRole  # noqa: E402,F401
from app.models.phishing import PhishingDomain  # noqa: E402,F401
from app.models.dns_observation import DNSObservation  # noqa: E402,F401
from app.models.breach import Breach  # noqa: E402,F401
from app.models.report import Report  # noqa: E402,F401
from app.models.settings import SystemSettings  # noqa: E402,F401
from app.models.audit import AuditLog  # noqa: E402,F401
from app.models.token import RefreshTokenFamily  # noqa: E402,F401
from app.main import app  # noqa: E402


app_db_engine: AsyncEngine | None = None

_test_engine = create_async_engine(
    os.environ["DATABASE_URL"],
    future=True,
    poolclass=NullPool,
    connect_args=(
        {"check_same_thread": False, "timeout": 30}
        if os.environ["DATABASE_URL"].startswith("sqlite")
        else {}
    ),
)


def _enable_sqlite_foreign_keys(engine) -> None:
    """Enforce ``ON DELETE SET NULL``/``CASCADE`` on this engine's connections.

    SQLite ignores foreign keys unless every connection asks for them, so a suite
    that asserts what a delete leaves behind is only meaningful on a connection
    where the constraint runs. Registering this on one engine was not enough:
    an HTTP request is served by ``app.api.deps.AsyncSessionLocal``, whose engine
    is the application's own (``app.core.database.engine``), not the suite's. The
    result was a test that read ``created_by`` as ``NULL`` because its query
    matched no row at all — the report had survived but never lost its creator
    (RWI-09). PostgreSQL enforces its constraints without being asked, which is
    why the difference only showed up in the SQLite run.
    """

    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):
        try:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
        except Exception:
            pass


_enable_sqlite_foreign_keys(_test_engine)
# The HTTP path opens its session from this engine, so the constraint has to be
# requested there too (the fixture below only re-points the module attribute).
from app.core import database as _database_module  # noqa: E402

_enable_sqlite_foreign_keys(_database_module.engine)


_TestSessionLocal = async_sessionmaker(
    _test_engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
)


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture(scope="function", autouse=True)
async def _create_tables_per_function(_patch_app_db_engine_and_session):
    """Create/drop all tables per function inside a single function-scoped
    event loop, avoiding:
    * hangs on ``await db.commit()`` when a module-scoped loop's connection
      is reused from a function-scoped loop (aiosqlite connections are
      loop-bound);
    * SQLite ``OperationalError: database is locked`` during teardown races.
    """
    setup_engine = app_db_engine or _test_engine
    async with setup_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    if _test_database_url:
        # This branch is allowed only for an explicitly supplied, dedicated
        # test database URL; normal runs never drop application tables.
        async with (app_db_engine or _test_engine).begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        return
    from sqlalchemy import text as sql_text
    try:
        async with _test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
    except Exception:
        async with _test_engine.connect() as conn:
            for table in reversed(Base.metadata.sorted_tables):
                try:
                    await conn.execute(sql_text(f"DROP TABLE IF EXISTS {table.name}"))
                except Exception:
                    pass
            await conn.commit()


_ALLOWED_TEST_TABLES: frozenset[str] = frozenset(
    {
        "source_observations",
        "breach_catalogue",
        "drp_breaches",
        "drp_phishing_domains",
        "dns_security_observations",
        "reports",
        "drp_audit_logs",
        "drp_refresh_families",
        "assets",
        "system_settings",
        "users",
    }
)


def safe_sql_identifier(name: str, *, allowed: frozenset[str] | set[str] | None = None) -> str:
    """
    Strict whitelist validation for SQL identifiers used in text() queries.
    Raises ValueError if the name is not present in the whitelist.

    Default allowed set covers the production DRP schema table names. Callers
    may pass a custom allowed set for narrow / specialised cleanup contexts.
    """
    use_allowed = allowed if allowed is not None else _ALLOWED_TEST_TABLES
    if not isinstance(name, str):
        raise ValueError("SQL identifier must be str")
    if name not in use_allowed:
        raise ValueError(f"Disallowed SQL identifier: {name!r}")
    return name


_safe_identifier = safe_sql_identifier


async def _cleanup_all_tables(session: AsyncSession):
    from sqlalchemy import text

    ordered = [
        "source_observations",
        "breach_catalogue",
        "drp_breaches",
        "drp_phishing_domains",
        "dns_security_observations",
        "report_audit_outbox",
        "report_artifact_cleanup",
        "report_queue_control",
        "reports",
        "drp_audit_logs",
        "drp_refresh_families",
        "assets",
        "system_settings",
        "users",
    ]
    for name in ordered:
        safe = _safe_identifier(name)
        try:
            await session.execute(text(f"DELETE FROM {safe}"))
        except Exception:
            pass
    await session.commit()


@pytest_asyncio.fixture(scope="function", autouse=True)
async def _seed_builtin_modules(_create_tables_per_function) -> AsyncGenerator[None, None]:
    """Seed the platform's own modules into the freshly created schema.

    Tables are created from the models rather than by migrations, so the rows the
    baseline revision ``0001_initial_schema`` inserts have to come from the
    application's own built-in definition — without them no connector could
    register and no finding could be persisted, because modules are data now.
    """
    if _test_database_url:
        yield
        return

    from app.services.module_registry import ensure_builtin_modules

    session = _TestSessionLocal()
    try:
        await ensure_builtin_modules(session)
    finally:
        await session.close()
    yield


@pytest_asyncio.fixture(scope="function", autouse=True)
async def _reset_rate_limiter_and_tasks() -> AsyncGenerator[None, None]:
    from app.core.rate_limit import RateLimiter
    RateLimiter.reset_client_cache()
    yield
    RateLimiter.reset_client_cache()


@pytest_asyncio.fixture(scope="function", autouse=True)
async def _patch_app_db_engine_and_session(request) -> AsyncGenerator[None, None]:
    """Patch ``app.core.database`` so both the FastAPI overrides and the raw
    ``AsyncSessionLocal()`` calls (e.g. ``AuditLogger.emit_background``) share
    the exact same in-memory SQLite connection.

    Eliminates SQLite ``database is locked`` errors that occur when two
    engines each open their own ``StaticPool`` connection to the shared-memory
    URI during per-function cleanup.
    """
    from app.core import database as _database_mod

    global app_db_engine
    original_engine = _database_mod.engine
    original_session_factory = _database_mod.AsyncSessionLocal

    if _test_database_url:
        engine_options = {}
        if request.node.get_closest_marker("asyncio") is not None:
            engine_options["poolclass"] = NullPool
        test_engine = create_async_engine(
            _test_database_url,
            future=True,
            **engine_options,
        )
        test_session_factory = async_sessionmaker(
            test_engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
        )
        _database_mod.engine = test_engine
        _database_mod.AsyncSessionLocal = test_session_factory
        app_db_engine = test_engine
    else:
        test_engine = _test_engine
        test_session_factory = _TestSessionLocal
        _database_mod.engine = test_engine
        _database_mod.AsyncSessionLocal = test_session_factory
        app_db_engine = test_engine
    try:
        yield
    finally:
        _database_mod.engine = original_engine
        _database_mod.AsyncSessionLocal = original_session_factory
        app_db_engine = original_engine
        if _test_database_url:
            await test_engine.dispose()


def redis_url_for_display(url: str) -> str:
    """A broker URL with its credentials removed.

    The tests that need a broker skip with a reason, and that reason is written into
    a CI log and into a JUnit report anybody can read. ``REDIS_URL`` carries the
    deployment's password (``docs/security.md``), so the message names the host and
    database instead of the URL.
    """
    parts = urlsplit(url)
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{parts.hostname or ''}{port}{parts.path or ''}"


@pytest.fixture(scope="session")
def live_redis() -> str:
    """The platform's broker, when something actually answers on it.

    A few tests exercise behaviour only a real broker has — ``SET NX`` once per
    minute, the dispatch guard that blocks a second tick, the Lua script that
    charges a provider account atomically. They used to reach for
    ``settings.REDIS_URL`` (one of them for a hard-coded ``localhost:6379``) and
    *fail* when nothing listened there, so a run outside the tooling stack reported
    red tests whose cause was the environment rather than the change under test,
    while the PostgreSQL suites beside them had always skipped instead. This
    fixture gives them that same shape:

    * the URL is the one the code under test connects to (``settings.REDIS_URL``),
      probed once per session with short timeouts, so a test never claims a skip
      for a broker and then talks to a different one;
    * an unreachable broker is a skip naming the host — the run simply does not have
      the property to check;
    * ``REQUIRE_INTEGRATION=1``, which CI's integration job sets, turns the same
      condition into an error: a job that was *given* a broker and lost it must not
      report success on tests that never ran.

    Reachability rather than an explicit opt-in variable is deliberate. The tooling
    stack (``make up-tools``) supplies the broker through ``REDIS_URL``, so a gate
    on a separate ``INTEGRATION_REDIS_URL`` would quietly drop these tests exactly
    where they are supposed to run — the failure mode
    ``tests/test_postgres_only_suites_gate.py`` was written about.
    """
    import redis as redis_lib

    from app.core.config import settings

    url = settings.REDIS_URL
    try:
        client = redis_lib.Redis.from_url(
            url, socket_connect_timeout=1, socket_timeout=1, decode_responses=True
        )
        try:
            client.ping()
        finally:
            client.close()
    except (redis_lib.exceptions.RedisError, OSError) as exc:
        message = (
            f"no Redis broker at {redis_url_for_display(url)}: {exc} — start the "
            "tooling stack (`make up-tools`) or point REDIS_URL at a broker"
        )
        if os.environ.get("REQUIRE_INTEGRATION") == "1":
            raise RuntimeError(f"{message} — REQUIRE_INTEGRATION=1 forbids skipping")
        pytest.skip(message)
    return url


@pytest_asyncio.fixture(scope="function")
async def db_session(
    _patch_app_db_engine_and_session,
) -> AsyncGenerator[AsyncSession, None]:
    from app.core import database

    session = database.AsyncSessionLocal()
    try:
        yield session
    finally:
        try:
            await session.rollback()
        except Exception:
            pass
        if not _test_database_url:
            try:
                await _cleanup_all_tables(session)
            except Exception:
                pass
        try:
            await session.close()
        except Exception:
            pass


@pytest_asyncio.fixture(scope="function")
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    async def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://testserver"
        ) as c:
            yield c
    finally:
        app.dependency_overrides.pop(get_db, None)


async def _make_user(
    db: AsyncSession, email: str, password: str, role: UserRole | str, active: bool = True
) -> User:
    from app.core.security import hash_password

    role_val = role.value if isinstance(role, UserRole) else str(role)
    u = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password(password),
        role=role_val,
        is_active=active,
    )
    db.add(u)
    await db.commit()
    await db.refresh(u)
    return u


def _bearer(user: User) -> dict:
    token, _ = create_access_token({"sub": str(user.id), "role": str(user.role)})
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture(scope="function")
async def test_admin(db_session: AsyncSession) -> User:
    return await _make_user(db_session, "test_admin@example.com", "TestPass123!", UserRole.admin)


@pytest_asyncio.fixture(scope="function")
async def test_analyst(db_session: AsyncSession) -> User:
    return await _make_user(db_session, "test_analyst@example.com", "TestPass123!", UserRole.analyst)


@pytest_asyncio.fixture(scope="function")
async def test_viewer(db_session: AsyncSession) -> User:
    return await _make_user(db_session, "test_viewer@example.com", "TestPass123!", UserRole.viewer)


@pytest_asyncio.fixture(scope="function")
async def test_inactive_admin(db_session: AsyncSession) -> User:
    return await _make_user(db_session, "test_inactive@example.com", "TestPass123!", UserRole.admin, active=False)


@pytest.fixture
def auth_headers_admin(test_admin) -> dict:
    return _bearer(test_admin)


@pytest.fixture
def auth_headers_analyst(test_analyst) -> dict:
    return _bearer(test_analyst)


@pytest.fixture
def auth_headers_viewer(test_viewer) -> dict:
    return _bearer(test_viewer)


@pytest_asyncio.fixture(scope="function")
async def admin_user(test_admin: User) -> User:
    return test_admin


@pytest_asyncio.fixture(scope="function")
async def analyst_user(test_analyst: User) -> User:
    return test_analyst


@pytest_asyncio.fixture(scope="function")
async def viewer_user(test_viewer: User) -> User:
    return test_viewer


@pytest_asyncio.fixture(scope="function")
async def seeded_asset(db_session: AsyncSession, test_analyst: User) -> Asset:
    a = Asset(
        asset_type="domain",
        asset_value="seeded-audit.example.com",
        criticality="medium",
        is_active=True,
    )
    db_session.add(a)
    await db_session.commit()
    await db_session.refresh(a)
    return a
