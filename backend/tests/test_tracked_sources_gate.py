"""Tests for ``scripts/check_tracked_sources.py``.

The gate exists because an over-broad ignore rule once took real source out of
the published repository: a bare `lib/` (a Python packaging pattern) also matched
`frontend/src/lib`, so fourteen frontend sources were present locally, every
local command passed, and only a fresh clone showed the loss.

It then failed on its own author for the opposite reason. A developer's local
environment named `.venv-alerts` is not source, but the shape test that recognised
`.venv` and `.venv313` did not allow letters in the suffix, so the path was
reported as hidden source and the `repo-hygiene` job went red for something that
had nothing to do with the change under test.

Both questions are decisions over a path — is this an artifact we expect to be
ignored, is this source we would miss — which is what the tests below pin, plus
an end-to-end run against a real temporary checkout. The git-backed cases skip
where `git` is unavailable, because the tooling image mounts `scripts/` for this
suite but not the repository's `.git`.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_GATE = _ROOT / "scripts" / "check_tracked_sources.py"

if not _GATE.is_file():
    # The dev overlay mounts the repository's scripts/ read-only for this suite;
    # a trimmed checkout cannot answer the question.
    pytest.skip(
        f"not a repository checkout: {_GATE.name} missing", allow_module_level=True
    )


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


gate = _load(_GATE, "opendrp_test_check_tracked_sources")

_HAVE_GIT = shutil.which("git") is not None


# ==============================================================================
# Artifacts: paths whose absence from the repository is expected
# ==============================================================================
@pytest.mark.parametrize(
    "path",
    [
        ".venv/lib/python3.12/site-packages/jinja2/__init__.py",
        "venv3/Lib/site-packages/requests/api.py",
        ".venv313/pyvenv.cfg",
        # The name that was reported instead of skipped: letters are part of the
        # suffix a developer actually used.
        ".venv-alerts/pyvenv.cfg",
        ".venv-alerts/Lib/site-packages/jinja2/__init__.py",
        ".venv-audit/Lib/site-packages/pip/_internal/cli/main.py",
        "backend/.venv-verify/Lib/site-packages/mypy/main.py",
    ],
)
def test_a_virtual_environment_is_an_artifact(path: str) -> None:
    assert gate._is_artifact(path) is True


@pytest.mark.parametrize(
    "path",
    [
        "node_modules/react/index.js",
        "backend/app/__pycache__/main.cpython-312.pyc",
        "frontend/dist/assets/index.js",
        ".pytest_cache/v/cache/lastfailed",
        "reports_store/report.pdf",
    ],
)
def test_dependency_and_build_directories_are_artifacts(path: str) -> None:
    assert gate._is_artifact(path) is True


def test_frontend_source_is_not_an_artifact() -> None:
    """The defect the gate was written for: `lib/` must not cover `src/lib`."""
    assert gate._is_artifact("frontend/src/lib/utils.ts") is False
    assert gate._is_artifact("backend/app/services/connector_service.py") is False


# ==============================================================================
# Source: what a clone would actually miss
# ==============================================================================
@pytest.mark.parametrize(
    "path",
    [
        "frontend/src/lib/utils.ts",
        "backend/app/main.py",
        "docs/deployment.md",
        "backend/main.pyi",
    ],
)
def test_source_files_are_recognised(path: str) -> None:
    assert gate._looks_like_source(path) is True


@pytest.mark.parametrize(
    "path", ["Dockerfile", "Makefile", "backend/Dockerfile", ".gitattributes"]
)
def test_suffixed_less_source_names_are_recognised(path: str) -> None:
    assert gate._looks_like_source(path) is True


@pytest.mark.parametrize("path", ["backend/requirements.txt", "logo.png", "data.csv"])
def test_a_non_source_suffix_is_not_reported(path: str) -> None:
    assert gate._looks_like_source(path) is False


# ==============================================================================
# Deliberate ignores: source-looking files whose absence from a clone is the rule
# ==============================================================================
@pytest.mark.parametrize(
    "path",
    [
        "docs/internal/README.md",
        "docs/internal/repo-hygiene-cleanup-2026-10-11.md",
        "docs/internal",
    ],
)
def test_the_internal_record_directory_is_a_deliberate_ignore(path: str) -> None:
    """`.gitignore` keeps `docs/internal/` out of the repository on purpose."""
    assert gate._is_in_allowed_ignored_dir(path) is True


@pytest.mark.parametrize(
    "path",
    [
        "docs/deployment.md",
        "docs/internal-audit/README.md",
        "frontend/src/lib/utils.ts",
    ],
)
def test_neighbours_of_a_deliberate_ignore_are_still_reported(path: str) -> None:
    """The exemption is the directory, not a prefix that could swallow a sibling."""
    assert gate._is_in_allowed_ignored_dir(path) is False


# ==============================================================================
# A directory that is not a checkout
# ==============================================================================
def test_a_non_checkout_is_skipped_rather_than_failed(tmp_path: Path, capsys) -> None:
    """The backend container mounts its own subtree, with no `.git` above it."""
    assert gate.main(["check_tracked_sources.py", str(tmp_path)]) == 0
    assert "not a git checkout" in capsys.readouterr().out


# ==============================================================================
# End-to-end over a real checkout
# ==============================================================================
def _git_checkout(root: Path, ignore_rules: str, files: list[str]) -> Path:
    (root / ".gitignore").write_text(ignore_rules, encoding="utf-8")
    for relative in files:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x = 1\n", encoding="utf-8")

    def git(*args: str) -> None:
        subprocess.run(
            ["git", *args], cwd=root, check=True, capture_output=True, text=True
        )

    git("init", "--quiet")
    return root


@pytest.mark.skipif(not _HAVE_GIT, reason="git is not installed")
def test_the_gate_reports_source_hidden_by_an_over_broad_rule(
    tmp_path: Path, capsys
) -> None:
    root = _git_checkout(
        tmp_path,
        "lib/\n",
        ["frontend/src/lib/utils.ts", "backend/app/main.py"],
    )

    assert gate.main(["check_tracked_sources.py", str(root)]) == 1
    out = capsys.readouterr().out
    assert "frontend/src/lib/utils.ts" in out
    assert "backend/app/main.py" not in out  # not ignored, so not this gate's finding


@pytest.mark.skipif(not _HAVE_GIT, reason="git is not installed")
def test_the_gate_accepts_an_ignored_virtual_environment(
    tmp_path: Path, capsys
) -> None:
    """`.venv-alerts` is exactly the shape that produced a false failure."""
    root = _git_checkout(
        tmp_path,
        "**/.venv*/\n",
        [".venv-alerts/Lib/site-packages/jinja2/__init__.py"],
    )

    assert gate.main(["check_tracked_sources.py", str(root)]) == 0
    assert "OK" in capsys.readouterr().out


@pytest.mark.skipif(not _HAVE_GIT, reason="git is not installed")
def test_the_gate_accepts_the_deliberately_ignored_internal_records(
    tmp_path: Path, capsys
) -> None:
    """A checkout holding `docs/internal/` is not a checkout missing source."""
    root = _git_checkout(
        tmp_path,
        "docs/internal/\n",
        [
            "docs/internal/README.md",
            "docs/internal/refactoring.md",
            "docs/internal/repo-hygiene-cleanup-2026-10-11.md",
        ],
    )

    assert gate.main(["check_tracked_sources.py", str(root)]) == 0
    assert "OK" in capsys.readouterr().out
