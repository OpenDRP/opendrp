"""Every place the backend can skip a test is named on the readiness page.

Sixteen is a number, not an inventory. The page explained the sixteen skips a host
without a broker and without PostgreSQL reports, and nothing compared that
explanation to the tree — so a new module-level gate that skips when the file it
reads is not mounted arrived un-described, and a `file:line` reference on the page
broke silently the next time anyone inserted a line above it.

What this file pins:

* every skip site in ``backend/tests`` — a ``pytest.skip``, a
  ``pytest.importorskip``, ``@pytest.mark.skipif`` or ``@pytest.mark.skip`` — is
  listed on the page with the cause it belongs to, and every row on the page names
  a site that still exists. A site is named by its file and its enclosing
  function, or by the file alone for a module-level skip, because those survive an
  edit above them and line numbers do not;
* each cause row's site count is the number of inventory rows that name that
  cause, so the summary cannot drift from the list under it;
* every ``tests/...`` reference on the page resolves, so a renamed test is a
  finding rather than a dead link a reader has to notice;
* ``backend/app`` contains no skip call: the platform's tests skip for the
  reasons the page describes, and for no others.

The page is the inventory, deliberately. Keeping the list in this file instead
would make the test the only place a reader could find it, and the point of the
exercise is that an operator can read why a run reported skips.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_TESTS = Path(__file__).resolve().parent
_PAGE_NAME = "docs/production-readiness.md"
_PAGE = _ROOT / _PAGE_NAME
_SECTION = "### What a host run skips, and why"

#: The mechanisms that turn a test into a skip. `xfail` is not one of them: it
#: reports the test as expected-to-fail rather than as not-run, and the page is
#: about the second kind.
_SKIP_CALLS = frozenset({"skip", "importorskip"})
_SKIP_MARKS = frozenset({"skip", "skipif"})

#: The summary row that carries the total, which no inventory row may claim as
#: its cause.
_TOTAL = "Total"

#: A reference the page makes to a test file or a test in one.
_REFERENCE = re.compile(r"`(tests/[A-Za-z0-9_/]+\.py(?:::[A-Za-z0-9_]+)?)`")
_SITE = re.compile(r"`(tests/[A-Za-z0-9_/]+\.py(?:::[A-Za-z0-9_]+)?)`")
_BOLD = re.compile(r"\*\*(.+?)\*\*")

if not _PAGE.is_file():
    # The test container mounts the backend subtree; a gate that requires the
    # repository's documentation to be present there would fail on a fact about
    # the mount rather than about the tree. This site is itself listed on the
    # page, under the partial-checkout cause.
    pytest.skip(f"not a repository checkout: {_PAGE.name} missing", allow_module_level=True)


def _literal(node: ast.AST, strings: dict[str, str]) -> str | None:
    """The text of a message argument, as far as it can be resolved statically."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return strings.get(node.id)
    if isinstance(node, ast.BinOp | ast.JoinedStr | ast.Call):
        return ast.unparse(node)
    return None


def _module_strings(tree: ast.Module) -> dict[str, str]:
    """Module-level string constants, so `_message = "…"` reads as its text."""
    strings: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = [target for target in node.targets if isinstance(target, ast.Name)]
            value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            targets = [node.target]
            value = node.value
        else:
            continue
        if value is None or not targets:
            continue
        text = _literal(value, strings)
        if text is None:
            continue
        for target in targets:
            strings[target.id] = text
    return strings


def _call_text(node: ast.Call, strings: dict[str, str], keyword: str = "reason") -> str:
    """The message a skip carries: its first argument, or a named keyword."""
    for entry in node.keywords:
        if entry.arg == keyword:
            return _literal(entry.value, strings) or ast.unparse(entry.value)
    if node.args:
        return _literal(node.args[0], strings) or ast.unparse(node.args[0])
    return ""


def _mechanism(
    node: ast.AST,
    parents: dict[ast.AST, ast.AST],
    strings: dict[str, str],
) -> str | None:
    """How this node skips, with the reason it states — or `None`."""
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "pytest"
        and node.func.attr in _SKIP_CALLS
    ):
        text = _call_text(node, strings)
        return f"{node.func.attr}(): {text}" if text else f"{node.func.attr}()"

    if (
        isinstance(node, ast.Attribute)
        and node.attr in _SKIP_MARKS
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "mark"
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == "pytest"
    ):
        parent = parents.get(node)
        text = _call_text(parent, strings) if isinstance(parent, ast.Call) else ""
        if not text and node.attr == "skipif":
            text = ast.unparse(parent) if isinstance(parent, ast.Call) else ""
        return f"@mark.{node.attr}: {text}" if text else f"@mark.{node.attr}"

    return None


def _owner(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str | None:
    """The nearest enclosing function, or `None` for a module-level skip."""
    current = parents.get(node)
    while current is not None:
        if isinstance(current, ast.FunctionDef | ast.AsyncFunctionDef):
            return current.name
        current = parents.get(current)
    return None


def _skip_sites() -> dict[str, str]:
    """Every skip site in the backend suite, as `site -> what it says`."""
    sites: dict[str, str] = {}
    # Every module in the directory, not just `test_*`: a helper that skips on
    # behalf of a test is a skip site too, and `conftest.py` is where the fixture
    # that four broker tests depend on lives.
    for path in sorted(_TESTS.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        parents = {
            child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)
        }
        strings = _module_strings(tree)
        for node in ast.walk(tree):
            mechanism = _mechanism(node, parents, strings)
            if mechanism is None:
                continue
            owner = _owner(node, parents)
            site = f"tests/{path.name}" + (f"::{owner}" if owner else "")
            # Two skips in one function are one site: the page explains why the
            # function can skip, not how many statements say so.
            sites.setdefault(site, f"line {node.lineno} — {mechanism}")
    return sites


def _cells(line: str) -> list[str]:
    """A table row's cells, with the leading and trailing pipes removed."""
    text = line.strip()
    if text.startswith("|"):
        text = text[1:]
    if text.endswith("|"):
        text = text[:-1]
    return [cell.strip() for cell in text.split("|")]


def _is_delimiter(line: str) -> bool:
    return bool(line.strip()) and all(
        re.fullmatch(r":?-{2,}:?", cell) for cell in _cells(line) if cell
    )


def _section() -> list[str]:
    lines = _PAGE.read_text(encoding="utf-8").splitlines()
    start = next(
        (index for index, line in enumerate(lines) if line.strip() == _SECTION),
        None,
    )
    assert start is not None, (
        f"the readiness page no longer has the section {_SECTION!r}; the skip "
        "inventory lives there, so a renamed heading hides the whole list"
    )
    end = next(
        (index for index in range(start + 1, len(lines)) if lines[index].startswith("### ")),
        len(lines),
    )
    return lines[start:end]


def _tables(lines: list[str]) -> list[list[list[str]]]:
    """Every table in these lines, as a header row plus its body rows."""
    tables: list[list[list[str]]] = []
    index = 0
    while index + 1 < len(lines):
        if lines[index].startswith("|") and _is_delimiter(lines[index + 1]):
            rows = [_cells(lines[index])]
            index += 2
            while index < len(lines) and lines[index].startswith("|"):
                rows.append(_cells(lines[index]))
                index += 1
            tables.append(rows)
        else:
            index += 1
    return tables


def _documented() -> tuple[list[list[str]], list[list[str]]]:
    """The section's cause summary and its per-site inventory."""
    tables = _tables(_section())
    assert len(tables) == 2, (
        "the section must hold exactly two tables — the cause summary and the "
        f"per-site inventory — and holds {len(tables)}"
    )
    summary, inventory = tables
    assert summary[0][:2] == ["Cause", "Skip sites"], (
        "the cause summary's first two columns are the cause and the number of "
        f"skip sites, and read {summary[0][:2]}"
    )
    assert inventory[0][:2] == ["Site", "Cause"], (
        "the inventory's first two columns are the site and its cause, and read "
        f"{inventory[0][:2]}"
    )
    return summary[1:], inventory[1:]


def _label(cell: str) -> str | None:
    match = _BOLD.search(cell)
    return match.group(1) if match else None


def _documented_sites() -> dict[str, str]:
    _, inventory = _documented()
    sites: dict[str, str] = {}
    for row in inventory:
        match = _SITE.fullmatch(row[0])
        assert match is not None, (
            f"the inventory row {row[0]!r} must start with a backticked site such "
            "as `tests/test_alert_service.py::test_x`, or `tests/test_x.py` for a "
            "module-level skip"
        )
        assert row[1], f"the inventory row for {match.group(1)} names no cause"
        sites[match.group(1)] = row[1]
    return sites


def test_every_skip_site_in_the_backend_is_on_the_page() -> None:
    found = _skip_sites()
    documented = _documented_sites()

    missing = sorted(set(found) - set(documented))
    assert missing == [], (
        "these skip sites are not described on the readiness page, so a run that "
        "reports fewer tests than expected has no readable explanation:\n  "
        + "\n  ".join(f"{site} — {found[site]}" for site in missing)
        + f"\nAdd a row for each to the inventory under {_SECTION!r} in "
        f"{_PAGE_NAME}, with the cause it belongs to."
    )


def test_every_row_on_the_page_names_a_skip_site_that_still_exists() -> None:
    found = _skip_sites()
    documented = _documented_sites()

    stale = sorted(set(documented) - set(found))
    assert stale == [], (
        "the readiness page lists skip sites the tree no longer has, so the "
        "inventory describes a suite that is not this one:\n  "
        + "\n  ".join(stale)
    )


def test_each_cause_row_counts_the_sites_the_inventory_lists() -> None:
    summary, _ = _documented()
    documented = _documented_sites()

    labels: dict[str, int] = {}
    for row in summary:
        label = _label(row[0])
        assert label is not None, f"the cause row {row[0]!r} states no bold cause"
        assert re.fullmatch(r"\d+", row[1]), (
            f"the cause row for {label!r} states {row[1]!r} sites; the column is "
            "the number of inventory rows that name this cause"
        )
        labels[label] = int(row[1])

    counted: dict[str, int] = {}
    for site, cause in documented.items():
        assert cause in labels, (
            f"the inventory puts {site} under {cause!r}, which is not a cause in "
            f"the summary ({', '.join(sorted(labels))})"
        )
        assert cause != _TOTAL, (
            f"{site} names {_TOTAL!r} as its cause; the total row counts the "
            "inventory, it does not describe a site"
        )
        counted[cause] = counted.get(cause, 0) + 1

    wrong = {
        label: (count, len(documented) if label == _TOTAL else counted.get(label, 0))
        for label, count in labels.items()
        if count != (len(documented) if label == _TOTAL else counted.get(label, 0))
    }
    assert wrong == {}, (
        "the summary's site counts disagree with the inventory under it "
        f"(stated, listed): {wrong}"
    )


def test_every_test_the_page_names_still_exists() -> None:
    summary, inventory = _documented()
    references = {
        match.group(1)
        for row in [*summary, *inventory]
        for cell in row
        for match in _REFERENCE.finditer(cell)
    }
    assert references, "the page names no test files at all; the inventory is empty"

    names: dict[str, set[str]] = {}
    unresolved: list[str] = []
    for reference in sorted(references):
        path_text, _, name = reference.partition("::")
        # The page writes its references the way the suite is run, from
        # `backend/`; this file resolves them the same way.
        path = _ROOT / "backend" / path_text
        if not path.is_file():
            unresolved.append(f"{reference} — no such file")
            continue
        if not name:
            continue
        if path_text not in names:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            names[path_text] = {
                node.name
                for node in ast.walk(tree)
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
            } | {
                target.id
                for node in ast.walk(tree)
                if isinstance(node, ast.Assign)
                for target in node.targets
                if isinstance(target, ast.Name)
            }
        if name not in names[path_text]:
            unresolved.append(f"{reference} — {path_text} defines no {name}")

    assert unresolved == [], (
        "the readiness page points at tests that no longer exist:\n  "
        + "\n  ".join(unresolved)
    )


def test_the_application_does_not_skip_tests() -> None:
    offenders: list[str] = []
    for path in sorted((_TESTS.parent / "app").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        parents = {
            child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)
        }
        strings = _module_strings(tree)
        for node in ast.walk(tree):
            mechanism = _mechanism(node, parents, strings)
            if mechanism is not None:
                name = path.relative_to(_ROOT).as_posix()
                offenders.append(f"{name}:{getattr(node, 'lineno', 0)} — {mechanism}")

    assert offenders == [], (
        "the application skips no tests; a skip in `app/` would hide a code path "
        "from every run, and the readiness page describes skips in the suite "
        "only:\n  " + "\n  ".join(offenders)
    )
