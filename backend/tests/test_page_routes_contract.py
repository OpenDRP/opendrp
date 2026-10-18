"""The route references on the documentation pages against ``docs/api.md``.

``docs/api.md`` is the operator reference, and ``test_api_docs_contract.py``
keeps it true to the application in both directions. Nothing kept the *other*
pages true to it. A runbook that tells an operator to call a route by name is as
much an instruction as a table row, so a route renamed in the reference left the
prose saying the old thing — the F-10 defect one page over, and just as invisible,
because a route in backticks is not a link any link rule reaches.

Every ``/api/v1/...`` token a reader can see on a page is collected, its path
parameters normalised (``{asset_id}`` and ``{job_id}`` describe the same slot),
and compared with the paths ``docs/api.md`` lists. Three things are deliberately
not findings:

* a token that names only a **namespace** — ``/api/v1/dns``, the prefix of routes
  the reference does document — names no single endpoint. The trade-off is
  stated: a route is still caught when no route below it survives, and the
  schema-level test catches a route the application stopped serving;
* the connector-facing protocol, excluded by the same object the schema-level
  test filters with, because those routes are documented where a connector
  author looks;
* ``/api/v1/openapi.json``, which is the schema itself rather than a route in it.

The exceptions live in ``test_api_docs_contract.py`` in one declared list with a
reason each, and a test here asserts every one of them still occurs in the pages:
an exception for text that is gone is how a list stops describing the corpus and
starts hiding gaps.

``docs/internal/**`` is left out. Those pages are dated records of the tree as it
stood when they were written; rewriting them to match today would falsify the
record the directory exists to keep.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from typing import Iterable, List, Set, Tuple

_ROOT = Path(__file__).resolve().parents[2]
_CONTRACT = Path(__file__).with_name("test_api_docs_contract.py")


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


contract = _load(_CONTRACT, "opendrp_test_api_docs_contract_for_pages")

#: Pages an operator reads as instructions, and therefore pages whose routes have
#: to exist. `CHANGELOG.md` is not one: it records what a release removed.
_PAGE_FILES: Tuple[str, ...] = ("README.md", "connectors/README.md")

#: A route as written on a page. The lookbehind keeps the match off a filesystem
#: path (`app/api/v1/routers/...`) and off the tail of a full URL
#: (`http://host:8000/api/v1/metrics`), neither of which is a route reference.
_ROUTE_TOKEN = re.compile(r"(?<![\w/.:-])/api/v1/[A-Za-z0-9_\-./{}]*")

#: A path parameter, by any name the router gives it.
_PARAMETER = re.compile(r"\{[^}]*\}")


def _pages() -> List[Path]:
    """Every page the route contract covers, in a stable order."""
    pages = [(_ROOT / name) for name in _PAGE_FILES]
    pages.extend(sorted((_ROOT / "docs").rglob("*.md")))
    covered: List[Path] = []
    for page in pages:
        if not page.is_file():
            continue
        relative = page.relative_to(_ROOT)
        if relative.parts[:2] == ("docs", "internal"):
            continue
        covered.append(page)
    return covered


def _normalised(token: str) -> str:
    """A route token reduced to what two spellings of it have to agree on.

    The query string is a view of the route, not a different route; parameter
    names are local to the router; a trailing slash is taste.
    """
    path = token.split("?", 1)[0].split("#", 1)[0]
    return _PARAMETER.sub("{}", path).rstrip("/")


def _route_references() -> List[Tuple[str, int, str]]:
    """``(page, line, path)`` for every route token a reader can see."""
    found: List[Tuple[str, int, str]] = []
    for page in _pages():
        display = page.relative_to(_ROOT).as_posix()
        text = page.read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), start=1):
            for match in _ROUTE_TOKEN.finditer(line):
                found.append((display, number, _normalised(match.group(0))))
    return found


def _documented_paths() -> Set[str]:
    """The paths ``docs/api.md`` documents, with parameter names normalised."""
    return {
        _normalised(operation.split(" ", 1)[1])
        for operation in contract._documented_operations()
    }


def _covered_by_exception(path: str) -> bool:
    if path in contract._PAGE_ROUTE_EXCEPTIONS:
        return True
    return any(
        path == prefix or path.startswith(prefix + "/")
        for prefix in contract._PAGE_ROUTE_PREFIXES
    )


def _unknown(
    references: Iterable[Tuple[str, int, str]], documented: Set[str]
) -> List[str]:
    """Findings for references that name no documented route.

    The arguments are passed rather than read from the checkout so the rule can be
    pinned on the smallest example: a test that only ever sees the shipped pages
    cannot show which of them a broken reference would have come from.
    """
    failures: List[str] = []
    for page, number, path in references:
        if path in documented or _covered_by_exception(path):
            continue
        if any(known.startswith(path + "/") for known in documented):
            # A namespace: it names the group, not one route in it.
            continue
        failures.append(
            f"{page}:{number}: `{path}` is named as a route but docs/api.md does "
            f"not list it: a reader who follows the sentence reaches a 404, and "
            f"nothing else in the repository notices"
        )
    return failures


def _unknown_references(documented: Set[str]) -> List[str]:
    """Findings for the checkout's own pages, against `documented`."""
    return _unknown(_route_references(), documented)


def _vanished_exceptions(declared: Iterable[str]) -> Set[str]:
    """Declared paths that no page writes any more.

    An exception is a claim about the corpus. Once the text it was written for is
    gone, the claim is stale — and a stale claim is how an exception list starts
    hiding a route that moved.
    """
    seen = {path for _page, _number, path in _route_references()}
    missing: Set[str] = set()
    for path in declared:
        normalised = _normalised(path)
        if normalised in seen:
            continue
        if any(candidate.startswith(normalised + "/") for candidate in seen):
            continue
        missing.add(normalised)
    return missing


def test_the_shipped_pages_name_only_documented_routes() -> None:
    """The rule itself: the tree as it stands has to be clean."""
    failures = _unknown_references(_documented_paths())
    assert failures == [], "\n".join(failures)


def test_the_scan_actually_reads_the_pages() -> None:
    """A vacuous pass would be worse than no test: the parse must find routes."""
    references = _route_references()
    assert len(references) > 50, (
        f"only {len(references)} route references parsed out of the pages: the "
        "format changed and this test stopped reading it"
    )
    pages = {page for page, _number, _path in references}
    expected = {"README.md", "connectors/README.md", "docs/api.md", "docs/deployment.md"}
    assert expected <= pages, f"the scan missed pages a route is documented on: {sorted(expected - pages)}"


def test_a_route_the_reference_dropped_is_reported() -> None:
    """The defect this rule is for: the page keeps an instruction the API lost."""
    documented = _documented_paths() - {"/api/v1/alerts/queue"}

    failures = _unknown_references(documented)

    assert failures, "removing a route from the reference left the pages green"
    assert any("/api/v1/alerts/queue" in failure for failure in failures)
    assert all("/api/v1/alerts/queue" in failure for failure in failures), failures


def test_a_namespace_is_not_a_route() -> None:
    """`/api/v1/dns` names the group; a token beside it that names nothing fails."""
    documented = {"/api/v1/dns/scan"}

    failures = _unknown(
        [("page.md", 1, "/api/v1/dns"), ("page.md", 2, "/api/v1/asset")],
        documented,
    )

    assert len(failures) == 1, failures
    assert "/api/v1/asset" in failures[0]


def test_every_declared_exception_still_occurs_in_the_pages() -> None:
    """The list has to describe the corpus, not a tree it used to describe."""
    declared = set(contract._PAGE_ROUTE_EXCEPTIONS) | set(contract._PAGE_ROUTE_PREFIXES)
    assert declared, "the page-route exception list is empty"

    missing = _vanished_exceptions(declared)

    assert missing == set(), (
        "these paths are excluded from the page-route contract but no page "
        f"writes them any more, so the exception has outlived its reason: {sorted(missing)}"
    )


def test_an_exception_for_text_that_is_gone_is_reported() -> None:
    """Pinning the behaviour above rather than trusting an empty result."""
    missing = _vanished_exceptions({"/api/v1/this-route-is-not-on-any-page"})

    assert missing == {"/api/v1/this-route-is-not-on-any-page"}
