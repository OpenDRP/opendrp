"""Tests for ``scripts/check_dependency_sources.py``.

The gate keeps ``requirements*.txt`` the single source of truth for Python
dependencies. These tests pin each rule: no dependency tables in pyproject,
exact pins only, and the two documented exemptions (the ``-r`` include and the
connector SDK's local direct reference).
"""

import importlib.util
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "scripts" / "check_dependency_sources.py"

_spec = importlib.util.spec_from_file_location("check_dependency_sources", _SCRIPT)
_gate = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("check_dependency_sources", _gate)
_spec.loader.exec_module(_gate)


# --- pyproject: no dependency tables ------------------------------------------


def test_clean_pyproject_passes():
    source = (
        "[tool.poetry]\n"
        'name = "opendrp-backend"\n'
        'version = "0.2.0"\n'
        "\n"
        "[tool.mypy]\n"
        'python_version = "3.12"\n'
    )
    assert _gate.check_pyproject(source) == []


def test_poetry_dependency_table_is_rejected():
    source = "[tool.poetry.dependencies]\nfastapi = '^0.115.0'\n"
    failures = _gate.check_pyproject(source)
    assert len(failures) == 1
    assert "dependencies" in failures[0]


def test_poetry_dev_group_dependency_table_is_rejected():
    source = "[tool.poetry.group.dev.dependencies]\npytest = '^8.3.2'\n"
    failures = _gate.check_pyproject(source)
    assert len(failures) == 1


def test_pep621_project_table_is_rejected():
    source = '[project]\nname = "opendrp-backend"\ndependencies = ["fastapi"]\n'
    failures = _gate.check_pyproject(source)
    assert len(failures) == 1
    assert "[project]" in failures[0]


def test_poetry_version_table_is_allowed():
    # The version gate reads [tool.poetry].version; keeping the table must not
    # trip the dependency gate.
    source = '[tool.poetry]\nname = "x"\nversion = "0.2.0"\n'
    assert _gate.check_pyproject(source) == []


# --- requirements: exact pins only --------------------------------------------


def test_exact_pins_pass():
    source = (
        "fastapi==0.141.1\n"
        "PyJWT[crypto]==2.14.0\n"
        "pytest==9.0.3\n"
        "anyio==4.14.2\n"
    )
    assert _gate.check_requirements(Path("requirements.txt"), source) == []


def test_caret_range_is_rejected():
    failures = _gate.check_requirements(Path("r.txt"), "fastapi = ^0.115.0\n")
    assert len(failures) == 1


def test_comparison_range_is_rejected():
    failures = _gate.check_requirements(Path("r.txt"), "starlette>=1.3.1\n")
    assert len(failures) == 1


def test_bare_name_is_rejected():
    failures = _gate.check_requirements(Path("r.txt"), "requests\n")
    assert len(failures) == 1


def test_include_line_is_allowed():
    assert _gate.check_requirements(Path("r.txt"), "-r requirements.txt\n") == []


def test_sdk_direct_reference_is_allowed():
    source = "opendrp-connector-sdk @ file:///opt/sdk\nhttpx==0.27.2\n"
    assert _gate.check_requirements(Path("r.txt"), source) == []


def test_comment_and_blank_lines_are_ignored():
    source = "# a comment\n\nfastapi==0.141.1\n"
    assert _gate.check_requirements(Path("r.txt"), source) == []


def test_environment_marker_on_exact_pin_is_allowed():
    source = "uvloop==0.21.0 ; sys_platform != 'win32'\n"
    assert _gate.check_requirements(Path("r.txt"), source) == []


# --- every manifest the tree ships is scanned --------------------------------
#: A pin with the hash line a generated lock carries.
_HASHED_PIN = "fastapi==0.141.1\n    --hash=sha256:" + "a" * 64 + "\n"


def _shipped_tree(tmp_path: Path, overrides: dict) -> Path:
    """The smallest checkout the gate accepts, with `overrides` applied."""
    files = {
        "backend/pyproject.toml": (
            '[tool.poetry]\nname = "opendrp-backend"\nversion = "0.2.1"\n'
        ),
        "backend/requirements-dev.txt": "pytest==9.0.3\n",
        "backend/requirements.txt": _HASHED_PIN,
    }
    for connector in (
        "dnstwist",
        "shodan",
        "hibp",
        "dns_security",
        "intelligence",
        "exposure_endpoints",
    ):
        files[f"connectors/{connector}/requirements.txt"] = _HASHED_PIN
    files.update(overrides)
    for relative, text in files.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return tmp_path


def test_every_connector_manifest_the_tree_ships_is_scanned(tmp_path: Path) -> None:
    """The list of manifests is the tree's, not a copy that can fall behind.

    The shipped set was hand-kept, and three of the six manifests every connector
    image installs with `--require-hashes` went unchecked: `dns_security` and
    `intelligence` were named for a hash rule the scan loop never reached, and
    `exposure_endpoints` was in neither list. A new connector's manifest is the
    same omission one release later.
    """
    root = _shipped_tree(tmp_path, {})

    shipped, dev = _gate.requirements_manifests(root)

    assert set(shipped) == {
        Path("backend/requirements.txt"),
        Path("connectors/dnstwist/requirements.txt"),
        Path("connectors/shodan/requirements.txt"),
        Path("connectors/hibp/requirements.txt"),
        Path("connectors/dns_security/requirements.txt"),
        Path("connectors/intelligence/requirements.txt"),
        Path("connectors/exposure_endpoints/requirements.txt"),
    }
    assert dev == [Path("backend/requirements-dev.txt")]


def test_a_range_in_a_connector_manifest_is_reported(tmp_path: Path) -> None:
    root = _shipped_tree(
        tmp_path,
        {"connectors/exposure_endpoints/requirements.txt": "requests>=2.0\n"},
    )

    failures = _gate.check(root)

    assert failures, "a range in a shipped manifest has to be a failure"
    assert any("exposure_endpoints" in failure for failure in failures), failures


def test_a_connector_pin_without_a_hash_is_reported(tmp_path: Path) -> None:
    """Every connector image installs its manifest with `--require-hashes`."""
    root = _shipped_tree(
        tmp_path,
        {"connectors/intelligence/requirements.txt": "fastapi==0.141.1\n"},
    )

    failures = _gate.check(root)

    assert failures, "a shipped pin without a hash has to be a failure"
    assert any("intelligence" in failure for failure in failures), failures


# --- end-to-end over the repository -------------------------------------------


def test_repository_is_clean():
    assert _gate.check(_ROOT) == []
