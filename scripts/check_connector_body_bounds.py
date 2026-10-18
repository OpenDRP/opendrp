#!/usr/bin/env python3
"""Fail when a connector reads a body without a bound.

Five places in this repository read a third party's response in full and applied a
size limit afterwards, or had none at all: HIBP's and Shodan's provider bodies
(whatever a provider sent), DNS Security's (had the bound), and the endpoint
worker's `len(response.content) > MAX_BODY_BYTES`, which compared a length to a
number only after the body was in memory. A sixth was the Shodan favicon fetch —
the one request a connector makes to a *target* rather than to a provider.

Each was found by reading code, one at a time, and each was fixed the same way: a
streamed read that stops at the bound. Nothing in the repository noticed when they
appeared, and nothing would notice the seventh. This gate is that missing
observation, stated as one rule:

    A body from anywhere but this platform's own API is read through a bounded
    reader — never through `.content`, `.text`, `.json()` or `.aread()`.

The one exception is syntactically visible, which is why it can be enforced by
reading source rather than by asking the reader to be careful: the platform's own
answers are what `self._request(...)` and `self._request_with_retry(...)` return,
either inline or assigned to a name first. A name bound that way is tracked for
the length of its module; everything else that reads a body is a violation.

`connectors/base/` is out of scope because it *is* the reader: the SDK owns the
one bounded implementation, and a rule that forbade the SDK from touching a body
would forbid the bound from existing. Test files are out of scope for the same
reason a test may assert what production code must not do.

Deliberately stdlib-only, like its neighbours in this directory: it runs in CI
before dependencies are installed, and a gate that needs an environment is a gate
that gets skipped.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

#: Where the connector tree starts, relative to the checkout root.
CONNECTOR_TREE = "connectors"
#: Directories left alone: the SDK owns the one bounded reader, and a build
#: artefact is not source.
SKIP_DIRECTORIES = {"base", "__pycache__"}
#: Attributes that hand back a whole body that has already been read.
BODY_ATTRIBUTES = {"content", "text"}
#: Methods that read a whole body. `aread()` is the same read as `.content` with
#: an `await` in front of it, and it is the shape a fix that only banned the
#: attribute would leave behind.
BODY_METHODS = {"json", "aread"}
#: The core's own request helpers. Their answers are this platform's, and the
#: names bound from them are the only body reads this gate allows.
CORE_CALLS = {"_request", "_request_with_retry"}


class Unreadable(RuntimeError):
    """The check could not read its input, which is not the same as passing."""


def _is_core_call(node: ast.AST | None) -> bool:
    """Whether an expression is a call to one of the core's request helpers."""
    if isinstance(node, ast.Await):
        node = node.value
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in CORE_CALLS
    )


def _names_bound_to_core_answers(tree: ast.AST) -> set[str]:
    """Local names bound to a core answer, in every statement that binds one.

    Only names are tracked, and only within the module's own assignments and
    ``with ... as`` headers: a rule that needed real dataflow would be a rule
    nobody could read, and the shapes it would miss are not the shapes this
    repository's five defects had.
    """
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and _is_core_call(node.value):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and _is_core_call(node.value):
            if isinstance(node.target, ast.Name):
                names.add(node.target.id)
        elif isinstance(node, ast.withitem) and _is_core_call(node.context_expr):
            if isinstance(node.optional_vars, ast.Name):
                names.add(node.optional_vars.id)
    return names


def _reads_a_body(node: ast.AST, core_names: set[str]) -> str | None:
    """The attribute a node reads a body through, or ``None`` if it is allowed."""
    if isinstance(node, ast.Attribute) and node.attr in BODY_ATTRIBUTES:
        receiver = node.value
        attribute = node.attr
    elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in BODY_METHODS:
        receiver = node.func.value
        attribute = node.func.attr
    else:
        return None
    if _is_core_call(receiver):
        return None
    if isinstance(receiver, ast.Name) and receiver.id in core_names:
        return None
    return attribute


def check(root: Path | str) -> list[str]:
    """Every body read in the connector tree that the rule does not allow."""
    tree_root = Path(root) / CONNECTOR_TREE
    if not tree_root.is_dir():
        raise Unreadable(f"no {CONNECTOR_TREE}/ directory under {root}")

    failures: list[str] = []
    for path in sorted(tree_root.rglob("*.py")):
        if SKIP_DIRECTORIES.intersection(path.relative_to(tree_root).parts):
            continue
        if path.name.startswith("test_") or path.name == "conftest.py":
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise Unreadable(f"cannot read {path}: {exc}") from exc
        try:
            module = ast.parse(source, filename=str(path))
        except SyntaxError as exc:
            raise Unreadable(f"cannot parse {path}: {exc}") from exc

        core_names = _names_bound_to_core_answers(module)
        for node in ast.walk(module):
            attribute = _reads_a_body(node, core_names)
            if attribute is None:
                continue
            line = getattr(node, "lineno", 0)
            failures.append(
                f"{path}:{line}: reads a body through `{attribute}` — a body from "
                f"anywhere but this platform's own API is read through a bounded "
                f"reader (the shared provider client for a provider, and the "
                f"connector's own streamed read for anything else)"
            )
    return failures


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    root = Path(args[0]) if args else Path(__file__).resolve().parents[1]

    try:
        failures = check(root)
    except Unreadable as exc:
        print(f"body-bound gate: FAILED — cannot read input: {exc}", file=sys.stderr)
        return 2

    if failures:
        print("body-bound gate: FAILED")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(
        "body-bound gate: OK — no module under connectors/ (outside the SDK) "
        "reads a response body through `.content`, `.text`, `.json()` or "
        "`.aread()` except on an answer from this platform's own API"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
