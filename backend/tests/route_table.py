"""Reading the application's real route table, for the gates that check access.

Three things make this more than a loop over ``app.routes``:

* **Included routers are lazy.** FastAPI keeps them as ``_IncludedRouter``
  objects, so the top level holds the *inclusions* rather than the routes inside
  them; the walk follows ``original_router`` and rebuilds each prefix from
  ``include_context``. A gate written against ``app.routes`` would silently check
  a handful of routes and pass on the rest.
* **``include_in_schema=False`` routes exist.** The ``/api/v1/dns-security``
  alias is served by the same handlers as ``/api/v1/dns`` and appears in no
  OpenAPI document — which is exactly where a missing gate would hide, so the
  walk includes it.
* **A capability can be declared anywhere in a dependency tree** (a router-level
  ``dependencies=[...]``, a nested ``Depends``), so resolution is recursive.

Used by ``test_route_access_gate.py`` (does every route declare one?) and by
``test_api_docs_contract.py`` (does the Access column say the same thing?).
"""

from __future__ import annotations

from typing import Iterator

from fastapi import FastAPI
from fastapi.routing import APIRoute, _IncludedRouter

from app.core.permissions import Capability

#: The verbs the reference page and the gates talk about. ``HEAD`` is added by
#: Starlette to some framework routes and is not an operator-facing operation.
HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})

#: The dependency that authenticates a connector rather than a person. Routes
#: resolving it belong to the connector protocol (``X-Connector-Token``), which
#: ``connectors/README.md`` documents instead of ``docs/api.md``.
CONNECTOR_DEPENDENCY = "require_connector"

#: Prefix every connector-protocol route lives under. The exemption is asserted
#: against this so it cannot quietly cover a user route.
CONNECTOR_PREFIX = "/api/v1/connectors"


def iter_api_routes(
    routes, prefix: str = ""
) -> Iterator[tuple[str, tuple[str, ...], APIRoute]]:
    """Every ``APIRoute`` as ``(path, methods, route)``, lazy inclusions included."""
    for route in routes:
        if isinstance(route, _IncludedRouter):
            nested = prefix + (route.include_context.prefix or "")
            yield from iter_api_routes(route.original_router.routes, nested)
        elif isinstance(route, APIRoute):
            methods = tuple(sorted(m for m in route.methods if m in HTTP_METHODS))
            if methods:
                yield prefix + route.path, methods, route


def dependency_names(route: APIRoute) -> set[str]:
    """Names of every callable in the route's dependency tree, however nested."""
    names: set[str] = set()

    def walk(dependant) -> None:
        call = getattr(dependant, "call", None)
        if call is not None:
            names.add(getattr(call, "__name__", str(call)))
        for child in getattr(dependant, "dependencies", []) or []:
            walk(child)

    walk(route.dependant)
    return names


def capabilities_of(route: APIRoute) -> set[Capability]:
    """Capabilities declared anywhere in the route's dependency tree."""
    found: set[Capability] = set()

    def walk(dependant) -> None:
        call = getattr(dependant, "call", None)
        capability = getattr(call, "__capability__", None)
        if isinstance(capability, Capability):
            found.add(capability)
        for child in getattr(dependant, "dependencies", []) or []:
            walk(child)

    walk(route.dependant)
    return found


def route_capabilities(app: FastAPI) -> dict[str, set[Capability]]:
    """``"METHOD /path"`` → the capabilities that route requires.

    A route with several capabilities must satisfy all of them, which is how the
    marker works in practice (the guards are additive).
    """
    table: dict[str, set[Capability]] = {}
    for path, methods, route in iter_api_routes(app.routes):
        capability = capabilities_of(route)
        for method in methods:
            table[f"{method} {path}"] = set(capability)
    return table


def operations(routes) -> set[str]:
    """Every ``"METHOD /path"`` in the given route list."""
    return {
        f"{method} {path}"
        for path, methods, _route in iter_api_routes(routes)
        for method in methods
    }


def unprotected_operations(routes, public_reasons: dict[str, str]) -> list[str]:
    """``"METHOD /path"`` for routes with neither a capability nor a reason.

    Connector-protocol routes are accepted by dependency and asserted to live
    under :data:`CONNECTOR_PREFIX`, so the exemption cannot spread.
    """
    problems: list[str] = []
    for path, methods, route in iter_api_routes(routes):
        if capabilities_of(route):
            continue
        names = dependency_names(route)
        if CONNECTOR_DEPENDENCY in names:
            if not path.startswith(CONNECTOR_PREFIX):
                problems.append(
                    f"{methods[0]} {path} — resolved {CONNECTOR_DEPENDENCY} outside "
                    f"the connector protocol prefix"
                )
            continue
        for method in methods:
            operation = f"{method} {path}"
            if operation not in public_reasons:
                problems.append(operation)
    return problems


__all__ = [
    "CONNECTOR_DEPENDENCY",
    "CONNECTOR_PREFIX",
    "HTTP_METHODS",
    "capabilities_of",
    "dependency_names",
    "iter_api_routes",
    "operations",
    "route_capabilities",
    "unprotected_operations",
]
