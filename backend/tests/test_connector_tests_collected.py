"""Every connector test file is a file CI actually runs.

The DNS Security connector suite sat in this repository for months and ran in no
configuration at all: `backend/pytest.ini` sets `testpaths = tests`, so a test file
under `connectors/` is collected by nothing the backend job starts, and the only
step that touched connector code named two files by hand. The 23 cases in it pin
exactly the behaviour a later change is most likely to break — that a truncated CT
lookup is never promoted to `verified`, that the newest *issued* certificate is
selected, that deduplication keeps one row per certificate — and none of them ran
on a pull request (F-12 in the DNS & TLS audit).

The rule this file enforces is deliberately about *collection*, not about a list of
names: for every `connectors/<connector>/test_*.py` in the tree, some CI step has to
name a path that contains it. A new connector therefore arrives with its tests
already running, and a step that is deleted or narrowed fails here rather than
quietly turning a suite into decoration.

Like `tests/test_github_docs_claims.py`, this file skips itself outside a full
checkout: the tooling container mounts the backend tree as `/app` and has no
workflows, which is not a defect in the tree it is looking at.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

_BACKEND = Path(__file__).resolve().parents[1]
_ROOT = _BACKEND.parent
_CONNECTORS = _ROOT / "connectors"
_CI = _ROOT / ".github" / "workflows" / "ci.yml"

_REQUIRED = (_CONNECTORS, _CI)
_MISSING = [path.name for path in _REQUIRED if not path.exists()]
if _MISSING:
    pytest.skip(
        f"not a repository checkout: {', '.join(_MISSING)} missing",
        allow_module_level=True,
    )

#: A path a pytest invocation collects, wherever it appears in a `run` command.
_PYTEST_PATH = re.compile(r"(?<![\w./-])((?:\.\./)*(?:connectors|tests)[\w./-]*)")


def _connector_test_files() -> list[Path]:
    """Every test file under `connectors/`, as a path relative to the root."""
    return sorted(
        path.relative_to(_ROOT) for path in _CONNECTORS.rglob("test_*.py") if path.is_file()
    )


def _pytest_commands() -> list[str]:
    """Every `run:` command in the workflow that invokes pytest."""
    workflow = yaml.safe_load(_CI.read_text(encoding="utf-8"))
    commands: list[str] = []
    for job in workflow.get("jobs", {}).values():
        for step in job.get("steps", []) or []:
            raw = step.get("run")
            if isinstance(raw, str) and "pytest" in raw:
                commands.append(raw)
    return commands


def test_the_tree_has_connector_tests_to_collect():
    """A vacuous pass would hide exactly the regression this file exists for."""
    assert _connector_test_files(), "no connectors/**/test_*.py exists in this tree"


def test_every_connector_test_file_is_collected_by_a_ci_step():
    commands = _pytest_commands()
    assert commands, "ci.yml starts no pytest step at all"
    collected = set()
    for command in commands:
        for match in _PYTEST_PATH.finditer(command):
            collected.add(match.group(1).replace("../", "").removeprefix("./"))
    missing = []
    for test_file in _connector_test_files():
        target = test_file.as_posix()
        if any(
            path == target
            or target.startswith(path.rstrip("/") + "/")
            or path == target.rsplit("/", 1)[0]
            for path in collected
        ):
            continue
        missing.append(target)
    assert missing == [], (
        "these connector test files are collected by no CI step, so a regression "
        f"in them ships unnoticed: {missing}"
    )


def _steps_collecting_connector_suites() -> list[dict]:
    """The steps whose pytest invocation reaches into the `connectors/` tree.

    A backend step that names `tests/test_connector_runtime.py` is not one of them:
    it runs inside the backend package and needs no SDK import path.
    """
    workflow = yaml.safe_load(_CI.read_text(encoding="utf-8"))
    steps: list[dict] = []
    for job in workflow.get("jobs", {}).values():
        for step in job.get("steps", []) or []:
            command = step.get("run")
            if not isinstance(command, str) or "pytest" not in command:
                continue
            if any(
                (path := match.group(1).replace("../", "")) == "connectors"
                or path.startswith("connectors/")
                for match in _PYTEST_PATH.finditer(command)
            ):
                steps.append(step)
    return steps


def test_the_connector_step_can_import_the_sdk_from_the_checkout():
    """The suite imports `main`, which imports the SDK the image installs separately.

    Running it without `connectors/base` on `PYTHONPATH` (or an installed SDK) ends
    in a collection error, which is a red job for the wrong reason and gets disabled
    by whoever hits it first.
    """
    connector_steps = _steps_collecting_connector_suites()
    assert connector_steps, "no CI step runs the connector worker tests"
    assert all(
        "connectors/base" in str((step.get("env") or {}).get("PYTHONPATH", ""))
        for step in connector_steps
    ), "a connector test step does not put connectors/base on PYTHONPATH"
