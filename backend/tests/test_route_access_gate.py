"""Every published route declares a capability, or is a named exception.

USR-05 in ``docs/internal/audit-2026-10-15_users-rbac_03``: nothing checked that
a route had any access control at all. The documentation contract compared the
*list* of routes, and ``test_rbac_integration`` hand-listed eight user routes, so
a route that forgot ``Depends(...)`` was simply open to every authenticated
account and the whole suite stayed green. The audit answered the question by
reading the table by hand once; this file answers it every run, over the real
table read through ``tests/route_table.py`` (lazy routers followed, and
``include_in_schema=False`` routes included — the alias is where a missing gate
would hide).

Exceptions are named one by one with the reason they are not a gap, and the list
is checked in both directions: an entry that no longer matches a route fails a
test (a stale exception is how such a list becomes the place forgotten routes are
buried), and a route with neither a capability nor an entry fails with its method
and path.
"""

from __future__ import annotations

from fastapi import APIRouter, FastAPI

from app.core.permissions import declared_roles_missing_from_table
from app.main import app
from tests.route_table import (
    CONNECTOR_DEPENDENCY,
    CONNECTOR_PREFIX,
    dependency_names,
    iter_api_routes,
    operations,
    unprotected_operations,
)

#: Routes that belong to no user session, each with the reason. Everything else
#: under ``/api/v1`` must carry a capability.
_PUBLIC_REASONS: dict[str, str] = {
    "GET /api/v1/health": "public liveness probe: it must answer before any session exists",
    "GET /api/v1/ready": "public readiness probe, same reason as liveness",
    "POST /api/v1/auth/login": "sign-in: no authenticated user exists yet by definition",
    "POST /api/v1/auth/refresh": "authenticates with the refresh token, not an access token",
    "POST /api/v1/auth/logout": "best-effort: a signed-out or expired session must be able to end itself",
    "POST /api/v1/auth/accept-invitation": "the invitation token is the credential; the account cannot sign in yet",
    "GET /api/v1/metrics": "scraper credential (METRICS_TOKEN), not a user account",
}


def test_every_route_declares_a_capability_or_is_a_documented_exception():
    problems = unprotected_operations(app.routes, _PUBLIC_REASONS)
    assert problems == [], (
        "routes with no capability and no documented reason (add a "
        "`Depends(require_...)` from app/api/deps.py, or an entry to "
        "_PUBLIC_REASONS):\n  " + "\n  ".join(problems)
    )


def test_the_exception_list_has_no_stale_entries():
    """An entry that matches nothing is a place a future route can hide."""
    unknown = sorted(set(_PUBLIC_REASONS) - operations(app.routes))
    assert unknown == [], f"documented exceptions that name no route: {unknown}"


def test_connector_protocol_is_identified_by_its_dependency_only():
    """The connector exemption cannot spread: every match is under its prefix."""
    connector_routes = [
        f"{methods[0]} {path}"
        for path, methods, route in iter_api_routes(app.routes)
        if CONNECTOR_DEPENDENCY in dependency_names(route)
    ]
    assert connector_routes, "the connector protocol has no routes? the exemption is stale"
    outside = [
        operation
        for operation in connector_routes
        if not operation.split(" ", 1)[1].startswith(CONNECTOR_PREFIX)
    ]
    assert outside == [], f"connector-authenticated routes outside {CONNECTOR_PREFIX}: {outside}"


def test_every_role_is_named_in_the_capability_table():
    """A fourth `UserRole` must not inherit access by being unmentioned."""
    assert declared_roles_missing_from_table() == frozenset()


def test_the_walk_reports_a_route_that_lost_its_gate():
    """The gate's own proof: an unprotected route is what it catches.

    Built on a scratch app so the assertion is about the check, not about the
    production table staying lucky.
    """
    scratch = FastAPI()
    router = APIRouter(prefix="/api/v1/scratch")

    @router.get("/open")
    async def _open() -> dict:  # pragma: no cover - never called
        return {}

    scratch.include_router(router)
    assert unprotected_operations(scratch.routes, _PUBLIC_REASONS) == [
        "GET /api/v1/scratch/open"
    ]


def test_the_production_table_is_read_through_the_lazy_routers():
    """Guards the walk itself: the top-level route list is not the route table."""
    walked = {path for path, _methods, _route in iter_api_routes(app.routes)}
    direct = {
        getattr(route, "path", "")
        for route in app.routes
        if getattr(route, "path", "").startswith("/api/v1/")
    }
    assert any(path.startswith("/api/v1/assets") for path in walked)
    assert len(walked) > len(direct) + 100
    assert "/api/v1/dns-security/observations" in walked, (
        "the include_in_schema=False alias must be walked too: OpenAPI-based "
        "checks cannot see it"
    )
