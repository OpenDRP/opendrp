"""The route inventory in ``docs/api.md`` against the schema the app publishes.

F-10 in the deployment audit was a documentation defect with no gate behind it:
the README carried a hand-written route table that listed 96 of the API's 104
routes, and nothing noticed the eight that were missing — including operator
routes an administrator needs (`GET /api/v1/alerts/queue`,
`GET /api/v1/settings/runtime`, `POST /api/v1/settings/validate-telegram`,
`GET /api/v1/auth/mfa/qr`). A reference that is 92% complete is worse than one
that says it is partial: a reader who finds seven routes in a section concludes
the eighth does not exist.

The tables now live in one place (``docs/api.md``) and this test keeps them
true, in both directions:

* a route the application publishes but the page does not list is a route an
  operator cannot find, and it is the failure that shipped;
* a route the page lists and the application does not publish is a stale
  sentence that sends a script to a 404.

The comparison happens here rather than in the ``repo-hygiene`` CI job, which
deliberately installs nothing: building the schema means importing FastAPI and
the application. The same split the page-size contract uses applies — the
mechanical half runs where the dependencies are, and the repository gate
compares the file-level artefacts.

Connector-facing routes are excluded by name, below: they authenticate with a
connector's own credential and are documented where a connector author looks
(``connectors/README.md``), not in the operator reference. The exclusion is
asserted to still be real, so it cannot quietly become a hole that hides a
missing route.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, FrozenSet, Set

from app.core.permissions import Capability
from tests.route_table import operations, route_capabilities

_ROOT = Path(__file__).resolve().parents[2]
_API_DOC = _ROOT / "docs" / "api.md"
_CONNECTOR_DOC = _ROOT / "connectors" / "README.md"

_HTTP_METHODS: FrozenSet[str] = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})

#: Routes served to connectors under the connector protocol, authenticated with
#: ``X-Connector-Token`` rather than a user session. They belong to the connector
#: interface, which ``connectors/README.md`` documents; ``docs/api.md`` says so in
#: its own "Connector-facing routes" section and links there.
_CONNECTOR_FACING: FrozenSet[str] = frozenset(
    {
        "GET /api/v1/connectors/me/control",
        "GET /api/v1/connectors/me/credential",
        "GET /api/v1/connectors/me/work",
        "POST /api/v1/connectors/me/catalogue/{job_id}",
        "POST /api/v1/connectors/me/complete/{job_id}",
        "POST /api/v1/connectors/me/findings/{job_id}",
        "POST /api/v1/connectors/me/heartbeat",
        "POST /api/v1/connectors/me/quota/provider",
        "POST /api/v1/connectors/me/quota/virustotal",
        "POST /api/v1/connectors/me/readiness",
        "POST /api/v1/connectors/register",
    }
)

_METHOD_CELL = re.compile(r"`([A-Z]+)`")
_ROUTE_CELL = re.compile(r"`(/[^`]+)`")
#: A path parameter, whatever the router happens to call it: `{asset_id}` and
#: `{id}` describe the same slot, so a page and the reference agree on the shape.
_PARAMETER = re.compile(r"\{[^}]*\}")


def _route_path(operation: str) -> str:
    """The path half of ``METHOD /path``, with parameter names normalised."""
    return _PARAMETER.sub("{}", operation.split(" ", 1)[1]).rstrip("/")


#: Paths a page may name that the operator reference does not list, each with the
#: reason it is not a gap. Built from ``_CONNECTOR_FACING`` rather than repeated:
#: the page-level contract and the schema-level test have to filter the same set,
#: and a second list would drift from the first the day a route is renamed.
_CONNECTOR_FACING_REASON = (
    "part of the connector protocol: documented in connectors/README.md and "
    "authenticated with the connector's own X-Connector-Token"
)
_PAGE_ROUTE_EXCEPTIONS: Dict[str, str] = {
    **{
        _route_path(operation): _CONNECTOR_FACING_REASON
        for operation in _CONNECTOR_FACING
    },
    "/api/v1/openapi.json": (
        "the machine-readable schema the page describes: it is the reference "
        "itself rather than an endpoint in it, and it is served only outside "
        "production"
    ),
    **{
        path: (
            "the deprecated DNS Security prefix: the same handlers as "
            "`/api/v1/dns`, kept out of the OpenAPI document on purpose. The "
            "reference names the old spelling in its own paragraph and lists the "
            "published one; a test checks every path here still has a "
            "schema-visible counterpart"
        )
        for path in (
            "/api/v1/dns-security/scan",
            "/api/v1/dns-security/observations",
            "/api/v1/dns-security/observations/{}",
            "/api/v1/dns-security/observations/{}/asset",
            "/api/v1/dns-security/observations/cleanup-orphans",
            "/api/v1/dns-security/certificates",
            "/api/v1/dns-security/certificates/sightings/{}",
            "/api/v1/dns-security/certificate-exceptions",
            "/api/v1/dns-security/certificate-exceptions/{}",
        )
    },
}

#: Prefixes a page may name as a namespace rather than as an endpoint. Keyed by
#: the path a page writes, so the reason sits next to the exception it explains.
_PAGE_ROUTE_PREFIXES: Dict[str, str] = {
    "/api/v1/auth": (
        "the per-prefix rate-limit table in configuration.md names the auth "
        "section, not one route inside it"
    ),
}


def _published_operations() -> Set[str]:
    """Every ``METHOD /path`` the application's OpenAPI schema declares.

    The schema rather than ``app.routes``: this application keeps included routers
    as their own route objects, so walking the top-level route list finds none of
    the API paths.
    """
    from app.main import app

    operations: Set[str] = set()
    for path, item in app.openapi().get("paths", {}).items():
        for method in item:
            upper = method.upper()
            if upper in _HTTP_METHODS:
                operations.add(f"{upper} {path}")
    return operations


def _heading_slugs(path: Path) -> Set[str]:
    """The anchors GitHub generates for a file's headings.

    Lowercased, spaces to hyphens, punctuation dropped. Checked rather than
    eyeballed because a fragment that points nowhere renders as a normal link:
    ``docs/api.md`` sent a reader to ``connectors/README.md`` for the
    connector-facing routes, and only the anchor was wrong.
    """
    slugs: Set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("#"):
            continue
        text = re.sub(r"[^\w\s-]", "", line.lstrip("#").strip().lower())
        slugs.add(re.sub(r"\s+", "-", text))
    return slugs


def _documented_rows() -> list[tuple[tuple[str, ...], tuple[str, ...], str]]:
    """Every route-table row as ``(methods, routes, access_cell)``.

    A row may name several methods (``GET``, ``PATCH``, ``DELETE``) and several
    routes (``/api/v1/assets/import``, ``/api/v1/assets/import/csv``); the access
    column is returned whole so the checks below can read it instead of trusting
    it. Header and separator rows carry neither a method nor a route and drop out.
    """
    rows: list[tuple[tuple[str, ...], tuple[str, ...], str]] = []
    for line in _API_DOC.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 3:
            continue
        methods = tuple(m for m in _METHOD_CELL.findall(cells[0]) if m in _HTTP_METHODS)
        routes = tuple(_ROUTE_CELL.findall(cells[1]))
        if not methods or not routes:
            continue  # header and separator rows
        rows.append((methods, routes, cells[2]))
    return rows


def _documented_operations() -> Set[str]:
    """Every ``METHOD /path`` the route tables in ``docs/api.md`` list."""
    documented: Set[str] = set()
    for methods, routes, _access in _documented_rows():
        for method in methods:
            for route in routes:
                documented.add(f"{method} {route}")
    return documented


#: The words the Access column uses for a user session, mapped to the capability
#: the route must declare. `Authenticated` is the self-service group (an account's
#: own password, factor, sessions); the other three name the role sets.
_ACCESS_TO_CAPABILITY: Dict[str, Capability] = {
    "Authenticated": Capability.SELF_SERVICE,
    "viewer+": Capability.VIEW_PLATFORM,
    "analyst+": Capability.ANALYSE,
    "admin": Capability.ADMINISTER,
}

#: Access cells that describe a credential other than a user session. The matching
#: routes are the exceptions `tests/test_route_access_gate.py` names one by one;
#: these are the words the page may use for them.
_NO_SESSION_ACCESS = frozenset(
    {"Public", "Refresh token", "Best-effort authenticated", "scrape token"}
)

#: The deprecated DNS Security prefix the application still serves with
#: ``include_in_schema=False``.
_DEPRECATED_PREFIX = "/api/v1/dns-security"


def _access_label(cell: str) -> str:
    """The access word of a cell, without its note or parenthetical qualifier.

    ``analyst+ (``delete`` is admin) — one audit row`` reads as ``analyst+``: the
    qualifier narrows the *operation*, not the route, and the route's capability
    is what the check is about.
    """
    head = cell.split("—")[0].strip()
    return head.split("(")[0].strip()


def _operation_key(method: str, route: str) -> str:
    """``"METHOD /path"`` with parameter names normalised and no trailing slash.

    The method stays in the key: ``GET`` and ``POST /api/v1/assets`` require
    different capabilities, and a key without the method would let one overwrite
    the other — which is the shape of the defect this file exists for.
    """
    return f"{method} {_PARAMETER.sub('{}', route).rstrip('/')}"


def _normalized_route_capabilities() -> Dict[str, Set[Capability]]:
    """``"METHOD /path"`` (parameter names normalised) → required capabilities."""
    from app.main import app

    normalized: Dict[str, Set[Capability]] = {}
    for operation, capabilities in route_capabilities(app).items():
        method, path = operation.split(" ", 1)
        normalized[_operation_key(method, path)] = capabilities
    return normalized


def _access_problems(
    rows, required: Dict[str, Set[Capability]]
) -> list[str]:
    """Rows whose Access cell disagrees with the code.

    Separate from the test so the check itself can be shown to have teeth: a page
    that promises a viewer may create an asset is the defect this exists for, and
    a fabricated row proves it is caught.
    """
    problems: list[str] = []
    for methods, routes, cell in rows:
        head = cell.split("—")[0]
        if len(methods) > 1 and "/" in head:
            problems.append(
                f"{', '.join(methods)} {'/'.join(routes)}: the Access cell lists "
                f"{head.strip()!r} for several methods — split the row by method, "
                "because a reader cannot tell which method each word applies to"
            )
            continue
        label = _access_label(cell)
        if label in _NO_SESSION_ACCESS:
            continue
        capability = _ACCESS_TO_CAPABILITY.get(label)
        if capability is None:
            problems.append(
                f"{'/'.join(routes)}: unknown access word {label!r} — use one of "
                f"{sorted(_ACCESS_TO_CAPABILITY)} or a documented no-session word"
            )
            continue
        for method in methods:
            for route in routes:
                declared = required.get(_operation_key(method, route))
                if declared is None:
                    continue  # not published: `test_the_reference_invents_no_route`
                if capability not in declared:
                    problems.append(
                        f"{method} {route}: page says {label!r} "
                        f"({capability.value}), code requires "
                        f"{sorted(c.value for c in declared) or ['none']}"
                    )
    return problems


def test_the_route_tables_are_not_empty():
    """A vacuous pass would be worse than no test, so the parse must find routes."""
    documented = _documented_operations()
    assert len(documented) > 50, (
        f"only {len(documented)} routes parsed out of docs/api.md: the table "
        "format changed and this test stopped reading it"
    )


def test_every_published_route_is_documented():
    """The defect that shipped: routes an operator cannot find in the reference."""
    missing = _published_operations() - _CONNECTOR_FACING - _documented_operations()
    assert missing == set(), (
        "these routes are served but not listed in docs/api.md, so a reader "
        f"concludes they do not exist: {sorted(missing)}"
    )


def test_the_reference_invents_no_route():
    """The other direction: a listed route the application no longer serves."""
    invented = _documented_operations() - _published_operations()
    assert invented == set(), (
        "docs/api.md lists routes the application does not publish, so a script "
        f"written from this page reaches a 404: {sorted(invented)}"
    )


def test_the_connector_facing_exclusion_is_still_real():
    """The exclusion is a claim about the schema, so it has to keep holding.

    If one of these is renamed or removed, the route stops being filtered — and
    a filter that no longer matches anything is how an exclusion turns into a
    place a missing route can hide.
    """
    published = _published_operations()
    unknown = _CONNECTOR_FACING - published
    assert unknown == set(), (
        "these routes are excluded from the operator reference as connector-facing "
        f"but the application no longer publishes them: {sorted(unknown)}"
    )
    assert _CONNECTOR_FACING, "the connector-facing exclusion list is empty"

    # The page has to keep pointing a reader at where those routes are documented,
    # and the fragment it names has to be an anchor that exists.
    assert "connectors/README.md#the-connector-facing-api" in _API_DOC.read_text(
        encoding="utf-8"
    )
    assert "the-connector-facing-api" in _heading_slugs(_CONNECTOR_DOC), (
        "docs/api.md links to a connectors/README.md heading that does not exist: "
        f"{sorted(_heading_slugs(_CONNECTOR_DOC))}"
    )


def test_the_access_column_matches_the_capability_that_enforces_it():
    """USR-06: the page described a row of methods, not a method.

    ``GET``, ``POST /api/v1/assets`` read as one access cell — "viewer+ /
    analyst+" — which a reader takes as "a viewer may create an asset". The access
    a reader infers now has to be the access `app/core/permissions.py` enforces.
    """
    problems = _access_problems(_documented_rows(), _normalized_route_capabilities())
    assert problems == [], "the Access column and the code disagree:\n  " + "\n  ".join(problems)


def test_the_access_check_catches_a_row_that_promises_too_much():
    """The check's own proof: the exact defect USR-06 shipped."""
    problems = _access_problems(
        [(('GET',), ('/api/v1/users',), "viewer+ — list users")],
        _normalized_route_capabilities(),
    )
    assert problems, "a viewer heading an admin route was accepted"
    assert "viewer+" in problems[0]


def test_a_multi_method_row_does_not_split_access_across_methods():
    """One cell, several methods, one access word each — or one row per method."""
    rows = _documented_rows()
    ambiguous = [
        f"{', '.join(methods)} {'/'.join(routes)}"
        for methods, routes, cell in rows
        if len(methods) > 1 and "/" in cell.split("—")[0]
    ]
    assert ambiguous == [], (
        "these rows list several methods and one slash-separated access cell: "
        f"{ambiguous}"
    )


def test_the_deprecated_dns_prefix_is_documented_and_has_published_counterparts():
    """The alias answers ten paths that no OpenAPI document shows.

    It is a live surface — a script written against the old prefix keeps working
    — so a reader has to be told it exists, and every path it serves has to have a
    spelling in the published reference; otherwise a rename leaves a route that
    nothing documents and nothing checks.
    """
    from app.main import app

    alias_operations = sorted(
        operation
        for operation in operations(app.routes)
        if operation.split(" ", 1)[1].startswith(_DEPRECATED_PREFIX + "/")
    )
    assert alias_operations, "the deprecated prefix no longer answers: remove the page's paragraph"
    assert _DEPRECATED_PREFIX in _API_DOC.read_text(encoding="utf-8")

    published = _published_operations()
    for operation in alias_operations:
        method, path = operation.split(" ", 1)
        counterpart = f"{method} {path.replace(_DEPRECATED_PREFIX, '/api/v1/dns', 1)}"
        assert counterpart in published, (
            f"{operation} has no schema-visible counterpart, so the deprecated "
            "spelling is the only one that answers it"
        )

    # The page-route exception list has to cover exactly the alias routes: a new
    # alias path that nobody listed would be reported by the page contract, and an
    # exception that outlives its route is the shape that hides a gap.
    documented = {
        _route_path(operation)
        for operation in alias_operations
    }
    excepted = {
        path for path in _PAGE_ROUTE_EXCEPTIONS if path.startswith(_DEPRECATED_PREFIX)
    }
    assert documented == excepted, (
        f"alias paths without an exception: {sorted(documented - excepted)}; "
        f"exceptions naming no alias path: {sorted(excepted - documented)}"
    )
