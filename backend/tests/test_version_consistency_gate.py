"""The version gate has to see a tree whose release version disagrees with itself.

The gate used to compare three statements inside the core. Two more trees state
the same release — the connector SDK every bundled connector imports and
registers with, and the SPA package — and both had drifted: the connector
runtime announced `1.2.0` as its `api_version`, the SDK package metadata and
`__version__` said `1.0.0`, and `frontend/package.json` said `1.0.0`, while the
platform was `0.2.0`. Nothing was red, because nothing compared them.

Each test below builds the smallest checkout that demonstrates one failure mode,
and the shipped tree is asserted to be consistent as well — a gate that only
fails on a synthetic tree is a rule nobody satisfies.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Dict

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_GATE = _ROOT / "scripts" / "check_version_consistency.py"

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


gate = _load(_GATE, "opendrp_test_check_version_consistency")

#: Every statement the gate reads, at one agreed version: the tree that must pass.
_CONSISTENT = {
    "backend/app/__init__.py": '__version__ = "0.2.0"\n',
    "backend/pyproject.toml": '[tool.poetry]\nname = "opendrp-backend"\nversion = "0.2.0"\n',
    "CHANGELOG.md": "# Changelog\n\n## [Unreleased]\n\n## [0.2.0] - 2026-10-15\n",
    "connectors/base/opendrp_connector/__init__.py": '__version__ = "0.2.0"\n',
    "connectors/base/opendrp_connector/base.py": 'SDK_VERSION = "0.2.0"\n',
    "connectors/base/pyproject.toml": (
        '[project]\nname = "opendrp-connector-sdk"\nversion = "0.2.0"\n'
    ),
    "frontend/package.json": '{\n  "name": "opendrp-frontend",\n  "version": "0.2.0"\n}\n',
    # The three statements a release bump leaves behind: the template a new
    # installation copies, and the two build defaults that become the version
    # the SPA prints.
    ".env.example": "# Application\nOPENDRP_VERSION=0.2.0\nLOG_LEVEL=INFO\n",
    "docker-compose.yml": (
        "services:\n  frontend:\n    build:\n      args:\n"
        "        VITE_APP_VERSION: ${OPENDRP_VERSION:-0.2.0}\n"
    ),
    "frontend/Dockerfile": "FROM nginx:1.29.8-alpine3.23\nARG VITE_APP_VERSION=0.2.0\n",
}


def _checkout(tmp_path: Path, overrides: Dict[str, str]) -> Path:
    """Write the smallest tree the gate accepts, then apply the overrides."""
    for relative, text in {**_CONSISTENT, **overrides}.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return tmp_path


# ==============================================================================
# The shipped tree
# ==============================================================================
@pytest.mark.skipif(
    # `_ROOT` is the checkout root on a real clone and `/` inside the test
    # container, where the mounts are partial: an absent tree there is a fact
    # about the container, not a finding about the repository.
    _ROOT.parent == _ROOT
    or not (_ROOT / "docker-compose.yml").is_file()
    or not (_ROOT / "connectors" / "base" / "opendrp_connector" / "base.py").is_file()
    or not (_ROOT / "frontend" / "package.json").is_file(),
    reason="not a repository checkout (the test container mounts the backend subtree)",
)
def test_the_shipped_tree_declares_one_release_version() -> None:
    assert gate.check(_ROOT) == []


# ==============================================================================
# Disagreement
# ==============================================================================
def test_a_connector_announcing_another_release_is_reported(tmp_path: Path) -> None:
    """The connector's `api_version` is the release it was built from, not its own."""
    root = _checkout(
        tmp_path,
        {"connectors/base/opendrp_connector/base.py": 'SDK_VERSION = "1.2.0"\n'},
    )

    failures = gate.check(root)

    assert len(failures) == 1, failures
    assert "connector api_version=1.2.0" in failures[0]
    assert "disagrees with itself" in failures[0]


def test_a_stale_spa_package_is_reported(tmp_path: Path) -> None:
    root = _checkout(
        tmp_path,
        {
            "frontend/package.json": (
                '{\n  "name": "opendrp-frontend",\n  "version": "1.0.0"\n}\n'
            )
        },
    )

    failures = gate.check(root)

    assert len(failures) == 1, failures
    assert "frontend package.json=1.0.0" in failures[0]


def test_a_stale_env_template_is_reported(tmp_path: Path) -> None:
    """The value a new installation copies is the release it will run.

    `make up` builds the images from this checkout and Settings reports
    `OPENDRP_VERSION` while the health endpoint reports the code's own version, so
    a template naming the previous release is an installation displaying two
    versions — and an image tag nobody released.
    """
    root = _checkout(tmp_path, {".env.example": "OPENDRP_VERSION=0.1.9\n"})

    failures = gate.check(root)

    assert len(failures) == 1, failures
    assert "env template OPENDRP_VERSION=0.1.9" in failures[0]


def test_a_stale_compose_display_version_is_reported(tmp_path: Path) -> None:
    """The SPA's build argument fallback is the version the UI prints."""
    root = _checkout(
        tmp_path,
        {
            "docker-compose.yml": (
                "services:\n  frontend:\n    build:\n      args:\n"
                "        VITE_APP_VERSION: ${OPENDRP_VERSION:-0.1.9}\n"
            )
        },
    )

    failures = gate.check(root)

    assert len(failures) == 1, failures
    assert "compose VITE_APP_VERSION=0.1.9" in failures[0]


def test_a_stale_dockerfile_display_version_is_reported(tmp_path: Path) -> None:
    """A direct `docker build frontend/` bakes this default into the bundle."""
    root = _checkout(
        tmp_path,
        {"frontend/Dockerfile": "FROM nginx:1.29.8-alpine3.23\nARG VITE_APP_VERSION=0.1.9\n"},
    )

    failures = gate.check(root)

    assert len(failures) == 1, failures
    assert "frontend Dockerfile VITE_APP_VERSION=0.1.9" in failures[0]


def test_a_missing_env_template_is_a_finding(tmp_path: Path) -> None:
    """Absent is not consistent: a template nobody can read cannot be checked."""
    root = _checkout(tmp_path, {})
    (root / ".env.example").unlink()

    failures = gate.check(root)

    assert len(failures) == 1, failures
    assert ".env.example: cannot read" in failures[0]


def test_a_connector_package_that_stopped_being_read_is_reported(
    tmp_path: Path,
) -> None:
    """A file the gate reads and the checkout does not hold is a finding, not a pass."""
    root = _checkout(tmp_path, {})
    (root / "connectors" / "base" / "pyproject.toml").unlink()

    failures = gate.check(root)

    assert len(failures) == 1, failures
    assert "connectors/base/pyproject.toml: cannot read" in failures[0]


def test_a_missing_version_reading_is_not_guessed(tmp_path: Path) -> None:
    root = _checkout(tmp_path, {"connectors/base/opendrp_connector/base.py": "X = 1\n"})

    failures = gate.check(root)

    assert len(failures) == 1, failures
    assert "SDK_VERSION" in failures[0]


# ==============================================================================
# What the changelog may say
# ==============================================================================
def test_an_unreleased_section_is_not_the_release_version(tmp_path: Path) -> None:
    """Changes accumulate under `Unreleased`; the code's version is the newest release."""
    root = _checkout(
        tmp_path,
        {
            "CHANGELOG.md": (
                "# Changelog\n\n## [Unreleased]\n\n## [0.2.0] - 2026-10-15\n"
            )
        },
    )

    assert gate.check(root) == []


def test_the_wire_protocol_revision_is_not_a_release(tmp_path: Path) -> None:
    """`protocol_version` is an integer about the protocol shape, not this release."""
    root = _checkout(
        tmp_path,
        {
            "connectors/base/opendrp_connector/base.py": (
                'PROTOCOL_VERSION = 2\nSDK_VERSION = "0.2.0"\n'
            )
        },
    )

    assert gate.check(root) == []
