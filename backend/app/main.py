import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, text
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app import __version__
from app.api.v1 import api_router
from app.core import health
from app.core.audit import audit_is_degraded
from app.core.config import settings
from app.core.database import AsyncSessionLocal, engine
from app.core.exceptions import register_exception_handlers
from app.core.logging_config import configure_logging, get_logger
from app.core.request_context import RequestContextMiddleware
from app.models import SystemSettings

# Before anything else in this process: a logger created before the handler is
# installed writes to a logger that discards its records. Idempotent, so the
# call from app/core/audit.py costs nothing.
configure_logging()


_SECURITY_HEADERS = {
    # Strict-Transport-Security is not here: it is a deployment setting rather than
    # a property of the application (see `hsts_header_value` in app/core/config.py
    # for why it is off by default), and it is added by the middleware below.
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'"
    ),

    "Server": "OpenDRP",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        for k, v in _SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        # Read from the same three variables the frontend's nginx reads, so the
        # header cannot say one thing on an API response and another on the page
        # that called it. `setdefault` still applies: a terminator that sets its
        # own value keeps it.
        hsts = settings.hsts_header_value
        if hsts:
            response.headers.setdefault("Strict-Transport-Security", hsts)
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.execute(text('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"'))
        await conn.commit()

    async with AsyncSessionLocal() as db:
        settings_result = await db.execute(select(SystemSettings).limit(1))
        existing_settings = settings_result.scalar_one_or_none()
        if not existing_settings:
            sys_settings = SystemSettings()
            db.add(sys_settings)
            await db.commit()
            print("[startup] Created system_settings singleton")
        else:
            print("[startup] system_settings singleton already exists")

    os.makedirs(settings.REPORTS_STORE_DIR, exist_ok=True)

    yield

    await engine.dispose()


_IS_PROD = settings.APP_ENV.lower() == "production"

app = FastAPI(
    title="OpenDRP API",
    version=__version__,
    description="Digital Risk Protection & Brand Protection Platform",
    docs_url=None if _IS_PROD else "/api/docs",
    redoc_url=None if _IS_PROD else "/api/redoc",
    openapi_url=None if _IS_PROD else "/api/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(SecurityHeadersMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-Connector-Token",
        "X-Connector-Name",
        "X-CSRF-Token",
        # The SPA sets its own id on every request (frontend/src/lib/api.ts), and
        # a custom header on a cross-origin request is refused unless it is
        # listed here.
        "X-Request-ID",
    ],
    # So a browser client can read the id back off the response.
    expose_headers=["X-Request-ID"],
)

# Added last, so it is the outermost middleware: a preflight or a request that
# CORS rejects still carries an identifier in its response headers.
app.add_middleware(RequestContextMiddleware)

register_exception_handlers(app)

app.include_router(api_router)


log = get_logger()


@app.get("/api/v1/health", tags=["Health"])
async def health_check():
    """Liveness probe: the API process itself is running.

    Deliberately free of dependency calls. A degraded PostgreSQL or Redis must
    not make an orchestrator restart an otherwise healthy container, so
    dependency state is reported by ``/api/v1/ready`` instead.
    """
    return {
        "status": "ok",
        # Same string the OpenAPI document reports: an operator comparing a
        # running instance with a release tag must not find two answers.
        "version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/v1/ready", tags=["Health"])
async def readiness_check(response: Response):
    """Readiness probe: PostgreSQL and Redis are reachable and answering.

    Returns 503 while any dependency is unusable, so a load balancer stops
    routing traffic to this replica instead of the orchestrator killing it.
    """
    checks: dict[str, str] = {}
    for dependency, probe in (
        ("database", health.check_database),
        ("redis", health.check_redis),
    ):
        try:
            await probe()
        except Exception as exc:
            checks[dependency] = "error"
            log.warning(
                "readiness_check_failed",
                dependency=dependency,
                error=str(exc)[:200],
            )
        else:
            checks[dependency] = "ok"

    # Audit persistence is a security dependency, not an informational metric:
    # serving mutating requests while audit writes are failing would create an
    # unreviewable window. Report it explicitly and drain this replica until a
    # later audit write clears the marker.
    checks["audit"] = "degraded" if audit_is_degraded() else "ok"
    ready = all(result == "ok" for result in checks.values())
    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ready" if ready else "degraded",
        "checks": checks,
        "audit_degraded": audit_is_degraded(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
