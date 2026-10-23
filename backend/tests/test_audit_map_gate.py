"""The staged audit covers every production file, exactly once.

An audit that loses attention loses coverage first: a module read by nobody looks
the same, in a progress table, as a module with no defects. The partition in
[plan 009](../../docs/exec-plans/009-staged-audit.md) is what makes the difference
visible, and this gate holds it in three ways:

* every production file below is named by exactly one step's surface, so a new
  module cannot arrive un-audited and a file cannot be claimed twice;
* no step names a file or directory that has since moved, so the plan does not
  describe a tree that no longer exists;
* each step states its surface, the questions it asks and its exit, and the plan
  keeps one handoff slot for the context the next step inherits.

"Production" is defined here, not discovered: the application, the scripts that
ship beside it, the connector workers (their tests are evidence, not surface), the
SPA's non-test files, and the files that deploy them. Tests are excluded on
purpose — an audit reads them to learn what a module promises, and counting them
as surface would make a step's budget depend on how well the area is tested.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_PLAN_NAME = "docs/exec-plans/009-staged-audit.md"
_PLAN = _ROOT / _PLAN_NAME

if not _PLAN.is_file():
    # The test container mounts the backend subtree; the partition lives in the
    # repository's documentation, which is not mounted there. This site is listed
    # on the readiness page under the partial-checkout cause.
    pytest.skip(f"not a repository checkout: {_PLAN.name} missing", allow_module_level=True)

_STEP = re.compile(r"^#### (S\d+) — ")


def _relative(path: Path) -> str:
    return path.relative_to(_ROOT).as_posix()


def _production_files() -> set[str]:
    """Every file the audit must account for."""
    found: set[str] = set()

    def collect(root: Path, predicate) -> None:
        for path in root.rglob("*"):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            if not predicate(path) or path.stat().st_size == 0:
                continue
            found.add(_relative(path))

    collect(_ROOT / "backend/app", lambda path: path.suffix == ".py")
    collect(_ROOT / "backend/scripts", lambda path: path.suffix == ".py")
    collect(_ROOT / "backend/alembic", lambda path: path.suffix in {".py", ".mako"})
    collect(
        _ROOT / "connectors",
        lambda path: path.suffix == ".py" and not path.name.startswith("test_"),
    )
    collect(_ROOT / "scripts", lambda path: path.suffix in {".py", ".sh"})
    collect(
        _ROOT / "frontend/src",
        lambda path: path.suffix in {".ts", ".tsx"}
        and ".test." not in path.name
        and path.name != "test-setup.ts",
    )

    explicit = [
        *_ROOT.glob("docker-compose*.yml"),
        *(_ROOT / "docker").rglob("*"),
        _ROOT / "backend/Dockerfile",
        _ROOT / "frontend/Dockerfile",
        *_ROOT.glob("connectors/*/Dockerfile"),
        *(_ROOT / ".github/workflows").glob("*.yml"),
        _ROOT / "Makefile",
        # The template every operator copies: it carries half of the settings
        # contract, so a file that no step claims is half the configuration
        # surface nobody reads (S19 owns it).
        _ROOT / ".env.example",
        _ROOT / "setup.py",
        _ROOT / "backend/pyproject.toml",
        _ROOT / "connectors/base/pyproject.toml",
        _ROOT / "frontend/index.html",
        _ROOT / "frontend/package.json",
        _ROOT / "frontend/vite.config.ts",
        *(_ROOT / "frontend").glob("tsconfig*.json"),
        *(_ROOT / "backend").glob("requirements*.txt"),
    ]
    for path in explicit:
        if path.is_file() and path.stat().st_size > 0:
            found.add(_relative(path))
    return found


def _blocks() -> dict[str, str]:
    """Each step's text, keyed by its id."""
    blocks: dict[str, list[str]] = {}
    current: str | None = None
    for line in _PLAN.read_text(encoding="utf-8").splitlines():
        match = _STEP.match(line)
        if match:
            current = match.group(1)
            blocks[current] = []
            continue
        if line.startswith("### ") or line.startswith("#### "):
            current = None
            continue
        if current is not None:
            blocks[current].append(line)
    return {step: "\n".join(lines) for step, lines in blocks.items()}


def _surface(block: str) -> list[str]:
    """The backticked paths in a step's surface, however the paragraph wraps."""
    lines = block.splitlines()
    collected: list[str] = []
    inside = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("**Surface:**"):
            inside = True
            collected.append(stripped)
            continue
        if inside and stripped.startswith("**"):
            break
        if inside:
            collected.append(stripped)
    return re.findall(r"`([^`]+)`", "\n".join(collected))


def _assignments() -> tuple[dict[str, set[str]], list[str]]:
    """`file -> steps that claim it`, plus every surface entry that resolves to nothing."""
    universe = _production_files()
    claimed: dict[str, set[str]] = {}
    unresolved: list[str] = []
    for step, block in _blocks().items():
        for token in _surface(block):
            if token.endswith("/"):
                matched = {path for path in universe if path.startswith(token)}
                if not (_ROOT / token).is_dir():
                    unresolved.append(f"{step}: {token} (no such directory)")
                    continue
            elif "*" in token:
                matched = {
                    _relative(path)
                    for path in _ROOT.glob(token)
                    if path.is_file() and path.stat().st_size > 0
                }
                if not matched:
                    unresolved.append(f"{step}: {token} (matches nothing)")
                    continue
            else:
                path = _ROOT / token
                if not path.is_file():
                    unresolved.append(f"{step}: {token} (no such file)")
                    continue
                matched = {token}
            for name in matched:
                claimed.setdefault(name, set()).add(step)
    return claimed, unresolved


def test_every_production_file_belongs_to_exactly_one_step() -> None:
    claimed, _ = _assignments()
    universe = _production_files()

    unclaimed = sorted(universe - set(claimed))
    assert unclaimed == [], (
        "these production files are not assigned to any audit step, so nothing will "
        "read them:\n  " + "\n  ".join(unclaimed)
        + f"\nAdd each to one step's **Surface:** in {_PLAN_NAME}."
    )

    shared = {name: sorted(steps) for name, steps in claimed.items() if len(steps) > 1}
    assert shared == {}, (
        "these files are claimed by more than one step, so the budget is counted "
        f"twice: {shared}. A step that re-reads a file says so in its Ask; the file "
        "is owned by one step."
    )


def test_no_step_names_a_file_that_does_not_exist() -> None:
    _, unresolved = _assignments()
    assert unresolved == [], (
        "the audit plan names paths the tree does not have, so a step's surface is "
        "smaller than it looks:\n  " + "\n  ".join(unresolved)
    )


def test_every_step_states_its_surface_questions_and_exit() -> None:
    blocks = _blocks()
    assert blocks, f"{_PLAN_NAME} declares no steps"

    numbers = sorted(int(step[1:]) for step in blocks)
    assert numbers == list(range(len(numbers))), (
        "steps must be numbered S0, S1, … without gaps; the plan has " f"{sorted(blocks)}"
    )

    missing: list[str] = []
    for step, block in sorted(blocks.items(), key=lambda item: int(item[0][1:])):
        for marker in ("**Surface:**", "**Ask:**", "**Exit:**"):
            if marker not in block:
                missing.append(f"{step}: {marker}")
    assert missing == [], (
        "a step without these cannot be run or closed:\n  " + "\n  ".join(missing)
    )


def test_the_plan_keeps_one_handoff_slot() -> None:
    text = _PLAN.read_text(encoding="utf-8")
    assert "## Handoff protocol" in text, (
        "the handoff format is what carries context between steps; without it each "
        "step re-derives the previous one's facts"
    )
    assert "### Carried context for the next step" in text, (
        "the plan needs exactly one live handoff block; appending one per step turns "
        "the section into a history nobody reads"
    )
    assert text.count("### Carried context for the next step") == 1, (
        "more than one handoff block: each step replaces the previous one"
    )
