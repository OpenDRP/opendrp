"""The page-size contract between the list endpoints and the shared table.

The defect these tests were written for: the UI offered "All" as ``size=10000``
while every list endpoint declared ``le=200``, so picking that option answered
HTTP 422 and the table fell back to its error state — the whole list looked broken
because of one entry in a dropdown.

The bound now lives in one place (`app.schemas.common.MAX_PAGE_SIZE`) and the
dropdown ends at it. Both halves are asserted here rather than only the half that
happens to be in Python: a value repeated in two languages drifts, and the point of
the test is that it cannot drift silently.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.schemas.common import MAX_PAGE_SIZE

_ROOT = Path(__file__).resolve().parents[2]
_TABLE_SOURCE = _ROOT / "frontend" / "src" / "components" / "DataTable" / "index.tsx"

_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete"})


def _published_size_bounds() -> dict[str, int | None]:
    """Every ``size`` query parameter the API publishes, with its declared bound.

    Read from the OpenAPI schema rather than from the route objects or a
    hand-written list: the schema is the contract a client generates from, and it is
    the only view that sees every router — this application keeps included routers as
    their own route objects, so walking ``app.routes`` finds none of the API paths.
    """
    from app.main import app

    bounds: dict[str, int | None] = {}
    for path, operations in app.openapi().get("paths", {}).items():
        for method, operation in operations.items():
            if method not in _HTTP_METHODS:
                continue
            for param in operation.get("parameters") or []:
                if param.get("name") == "size" and param.get("in") == "query":
                    bounds[f"{method.upper()} {path}"] = (param.get("schema") or {}).get(
                        "maximum"
                    )
    return bounds


def test_every_list_endpoint_publishes_the_shared_bound():
    bounds = _published_size_bounds()
    # A vacuous pass is worse than no test: if the schema stops describing these
    # parameters, this fails instead of reporting that everything is fine.
    assert len(bounds) > 5, f"only {len(bounds)} list endpoints found: {sorted(bounds)}"

    offenders = {route: bound for route, bound in bounds.items() if bound != MAX_PAGE_SIZE}
    assert offenders == {}, (
        "these endpoints bound `size` differently from MAX_PAGE_SIZE, so a client "
        f"cannot know what this API accepts: {offenders}"
    )


def test_the_table_offers_no_page_size_the_api_refuses():
    source = _TABLE_SOURCE.read_text(encoding="utf-8")
    assert (
        "const PAGE_SIZE_OPTIONS = [10, 20, 50, MAX_PAGE_SIZE] as const;" in source
    ), "the table's offered page sizes changed; the API bound did not move with them"
    assert (
        f"const MAX_PAGE_SIZE = {MAX_PAGE_SIZE};" in source
    ), "the table and the API disagree about the largest page"


def test_there_is_no_second_pagination_spelling_in_the_schemas():
    """One spelling of pagination, asserted against the module that had two (WI-24).

    ``PaginationParams(skip, limit <= 500)`` was a request-side model no route
    used, carrying a third limit and a second vocabulary beside ``page``/``size``.
    A dead model is not harmless here: the next reader to wire it up would have
    reintroduced exactly the divergence the page-size contract removed.
    """
    import app.schemas
    import app.schemas.common as common

    assert not hasattr(common, "PaginationParams")
    assert "PaginationParams" not in app.schemas.__all__

    schemas_dir = Path(common.__file__).resolve().parent
    offenders = [
        f"{path.name}: {field}"
        for path in sorted(schemas_dir.glob("*.py"))
        for field in ("skip:", "limit:")
        if field in path.read_text(encoding="utf-8")
    ]
    assert offenders == [], (
        "these schema modules declare a `skip`/`limit` field, a second pagination "
        f"spelling beside `page`/`size`: {offenders}"
    )


@pytest.mark.anyio
async def test_the_bound_is_enforced_on_the_assets_list(client, auth_headers_admin):
    """The bound is a refusal, not a comment: the table used to hit this 422."""
    allowed = await client.get(
        f"/api/v1/assets?page=1&size={MAX_PAGE_SIZE}", headers=auth_headers_admin
    )
    assert allowed.status_code == 200
    assert allowed.json()["size"] == MAX_PAGE_SIZE

    refused = await client.get(
        f"/api/v1/assets?page=1&size={MAX_PAGE_SIZE + 1}", headers=auth_headers_admin
    )
    assert refused.status_code == 422


@pytest.mark.anyio
async def test_the_generic_findings_list_refuses_a_page_instead_of_clamping_it(
    client, auth_headers_viewer
):
    """This route clamped silently, so a caller never learned it had been cut."""
    allowed = await client.get(
        f"/api/v1/findings?size={MAX_PAGE_SIZE}", headers=auth_headers_viewer
    )
    assert allowed.status_code == 200

    refused = await client.get("/api/v1/findings?size=100000", headers=auth_headers_viewer)
    assert refused.status_code == 422
