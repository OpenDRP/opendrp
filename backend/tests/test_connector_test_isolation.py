"""A test module must collect in a fresh interpreter, not thanks to its neighbours.

The suite runs in one process on a developer machine and in shards in CI. Those are
different worlds: a module that only collects because an earlier module left
`connectors/base` on `sys.path` passes in the first and errors in the second with
`ModuleNotFoundError: No module named 'opendrp_connector'`. That is exactly what
happened to `tests/test_intelligence_credential.py`, found while running the suite
in shards after plan 011's pass C: the file executed
`connectors/intelligence/providers.py` by path, and every sibling that does the same
had inserted the SDK directory while this one had never needed to.

The modules this file checks are the ones that execute connector code by path, so
the SDK's name appears in the *loaded file* rather than in the test module — which
is why the marker is the `spec_from_file_location` call, resolved to a path under
`connectors/`, and not the string `opendrp_connector`.

A collection error is reported with the child's own message, because the failure is
about that module's imports, not about its assertions.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[1]
_SPEC_LOADER = "spec_from_file_location"


def _mentions_connectors(node: ast.AST, source: str) -> bool:
    segment = ast.get_source_segment(source, node) or ""
    return any(
        marker in segment
        for marker in ("connectors/", "connectors\\\\", "/connectors", '"connectors"')
    )


def _loads_a_connector_file(tree: ast.Module, source: str) -> bool:
    """Whether the module executes a file under `connectors/` by path.

    The path is either the spec call's own literal or a module-level name assigned
    from one — `_PATH = Path("/connectors/…/providers.py")`, its
    `__file__`-relative fallback, and a name built from another name
    (`_PATH = _ROOT / "intelligence" / "providers.py"`) are all followed, because
    a test that runs inside the API container resolves the same file differently.
    """
    assignments: list[tuple[list[ast.expr], ast.expr]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            assignments.append((node.targets, node.value))
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            assignments.append(([node.target], node.value))

    connector_paths: set[str] = set()
    changed = True
    while changed:
        changed = False
        for targets, value in assignments:
            names = {target.id for target in targets if isinstance(target, ast.Name)}
            if names <= connector_paths:
                continue
            if _mentions_connectors(value, source) or any(
                isinstance(item, ast.Name) and item.id in connector_paths
                for item in ast.walk(value)
            ):
                connector_paths.update(names)
                changed = True

    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and len(node.args) >= 2):
            continue
        function = node.func
        name = function.attr if isinstance(function, ast.Attribute) else getattr(function, "id", "")
        if name != _SPEC_LOADER:
            continue
        target = node.args[1]
        if isinstance(target, ast.Constant) and "connectors/" in str(target.value):
            return True
        if isinstance(target, ast.Name) and target.id in connector_paths:
            return True
    return False


def _modules_that_load_a_connector_file() -> list[str]:
    found: list[str] = []
    for path in sorted((_BACKEND / "tests").glob("test_*.py")):
        source = path.read_text(encoding="utf-8")
        if _SPEC_LOADER not in source:
            continue
        if _loads_a_connector_file(ast.parse(source), source):
            found.append(path.name)
    return found


MODULES = _modules_that_load_a_connector_file()


def _collect_alone(name: str) -> tuple[str, int, str]:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
            f"tests/{name}",
        ],
        cwd=_BACKEND,
        capture_output=True,
        text=True,
        timeout=300,
    )
    return name, completed.returncode, (completed.stdout + completed.stderr)[-2000:]


def test_the_gate_finds_the_modules_it_is_meant_to_check() -> None:
    """A gate that checks nothing passes forever; this is the count it checks."""
    assert MODULES, (
        "no test module executes a connector file by path, so this gate would never "
        "run — the detection or the tests directory has moved"
    )


def test_every_module_that_executes_connector_code_collects_alone() -> None:
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(_collect_alone, MODULES))

    broken = {name: tail for name, code, tail in results if code != 0}

    assert broken == {}, (
        "these test modules need another module to run first, so a sharded run "
        "fails where the single-process run passed:\n\n"
        + "\n\n".join(f"{name}:\n{tail}" for name, tail in sorted(broken.items()))
    )
