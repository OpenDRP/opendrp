from __future__ import annotations

import os
import atexit
import tempfile
from pathlib import Path

_TMP_DB = Path(tempfile.gettempdir()) / f"opendrp_test_{os.getpid()}_{__import__('time').time_ns()}.sqlite3"
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_TMP_DB}"
os.environ["APP_ENV"] = "test"
os.environ["TESTING"] = "1"
# Tests must not inherit a developer's production-like MFA setting from the
# repository .env. MFA-specific tests enable it explicitly with monkeypatch;
# keeping the default off preserves isolation and avoids unrelated RBAC tests
# being blocked by onboarding policy.
os.environ["REQUIRE_MFA_FOR_ADMINS"] = "false"
if _TMP_DB.exists():
    try:
        _TMP_DB.unlink()
    except OSError:
        pass


@atexit.register
def _rm_tmp_db():
    try:
        if _TMP_DB.exists():
            _TMP_DB.unlink()
    except Exception:
        pass


import uuid  # noqa: E402
from typing import AsyncGenerator  # noqa: E402

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402


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
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool  # noqa: E402

from app.core.database import Base  # noqa: E402
from app.core.security import create_access_token  # noqa: E402
from app.core.database import get_db  # noqa: E402
from app.models.asset import Asset  # noqa: E402,F401
from app.models.user import User, UserRole  # noqa: E402,F401
from app.models.phishing import PhishingDomain  # noqa: E402,F401
from app.models.breach import Breach  # noqa: E402,F401
from app.models.report import Report  # noqa: E402,F401
from app.models.settings import SystemSettings  # noqa: E402,F401
from app.models.audit import AuditLog  # noqa: E402,F401
from app.models.token import RefreshTokenFamily  # noqa: E402,F401
from app.main import app  # noqa: E402


_test_engine = create_async_engine(
    os.environ["DATABASE_URL"],
    future=True,
    poolclass=NullPool,
    connect_args={"check_same_thread": False, "timeout": 30},
)


@event.listens_for(_test_engine.sync_engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    try:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
    except Exception:
        pass


_TestSessionLocal = async_sessionmaker(
    _test_engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
)


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture(scope="function", autouse=True)
async def _create_tables_per_function():
    """Create/drop all tables per function inside a single function-scoped
    event loop, avoiding:
    * hangs on ``await db.commit()`` when a module-scoped loop's connection
      is reused from a function-scoped loop (aiosqlite connections are
      loop-bound);
    * SQLite ``OperationalError: database is locked`` during teardown races.
    """
    async with _test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
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
        "drp_breaches",
        "drp_phishing_domains",
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
        "drp_breaches",
        "drp_phishing_domains",
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

    Tables are created from the models rather than by migrations, so the rows
    migration ``0018`` inserts have to come from the application's own built-in
    definition — without them no connector could register and no finding could be
    persisted, because modules are data now.
    """
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
async def _patch_app_db_engine_and_session() -> AsyncGenerator[None, None]:
    """Patch ``app.core.database`` so both the FastAPI overrides and the raw
    ``AsyncSessionLocal()`` calls (e.g. ``AuditLogger.emit_background``) share
    the exact same in-memory SQLite connection.

    Eliminates SQLite ``database is locked`` errors that occur when two
    engines each open their own ``StaticPool`` connection to the shared-memory
    URI during per-function cleanup.
    """
    from app.core import database as _database_mod

    original_engine = _database_mod.engine
    original_session_factory = _database_mod.AsyncSessionLocal

    _database_mod.engine = _test_engine
    _database_mod.AsyncSessionLocal = _TestSessionLocal
    try:
        yield
    finally:
        _database_mod.engine = original_engine
        _database_mod.AsyncSessionLocal = original_session_factory


@pytest_asyncio.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    session = _TestSessionLocal()
    try:
        yield session
    finally:
        try:
            await session.rollback()
        except Exception:
            pass
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
