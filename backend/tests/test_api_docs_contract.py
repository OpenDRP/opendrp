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
from typing import FrozenSet, Set

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


def _documented_operations() -> Set[str]:
    """Every ``METHOD /path`` the route tables in ``docs/api.md`` list.

    A cell may name several methods (``GET``, ``PATCH``, ``DELETE``) and several
    routes (``/api/v1/assets/import``, ``/api/v1/assets/import/csv``); each
    combination is one documented operation.
    """
    documented: Set[str] = set()
    for line in _API_DOC.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 2:
            continue
        methods = [m for m in _METHOD_CELL.findall(cells[0]) if m in _HTTP_METHODS]
        routes = _ROUTE_CELL.findall(cells[1])
        if not methods or not routes:
            continue  # header and separator rows
        for method in methods:
            for route in routes:
                documented.add(f"{method} {route}")
    return documented


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
