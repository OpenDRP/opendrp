"""The front pages describe the installation, and the installation is checked.

README.md is the platform's description and CONTRIBUTING.md is how a contributor
runs things; both name concrete things — the services `make up` starts, the make
targets, the CI jobs — and a name that no longer exists is a step that fails for
whoever follows it. One release shipped a README whose services table was missing
a worker the stack had been starting for weeks, and nothing in the suite could
see it: the pages that describe an installation are read by people, not by the
code that builds it.

So the names are read from the files that define them — `docker-compose.yml`, the
`Makefile`, `.github/workflows/ci.yml` — and a page that names something absent
fails here. The reverse direction is deliberately not gated for CI jobs: a job no
page mentions is a gap to write up, not a broken instruction.

The setup wizard's two promises live here as well, because an operator meets them
before anything is installed: it runs on Python 3.8 or newer, and it imports
nothing but the standard library, so it works on a host that has never run `pip`.
`ast.parse(..., feature_version=(3, 8))` pins the first, and the import list
against `sys.stdlib_module_names` the second.

In the tooling container the repository root is not mounted as a directory (the
backend tree is `/app` there, and the `Makefile` and the Compose files are absent
from it), so this file skips itself rather than reporting files a container cannot
see — the choice `tests/test_no_legacy_surface.py` makes for the same reason. CI's
`backend` job runs it against the full checkout.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest
import yaml

_BACKEND = Path(__file__).resolve().parents[1]
_ROOT = _BACKEND.parent

_README = _ROOT / "README.md"
_CONTRIBUTING = _ROOT / "CONTRIBUTING.md"
_COMPOSE = _ROOT / "docker-compose.yml"
_MAKEFILE = _ROOT / "Makefile"
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_WIZARD = _ROOT / "setup.py"

_REQUIRED = (_README, _CONTRIBUTING, _COMPOSE, _MAKEFILE, _CI, _WIZARD)
_MISSING = [path.name for path in _REQUIRED if not path.is_file()]
if _MISSING:
    pytest.skip(
        f"not a repository checkout: {', '.join(_MISSING)} missing",
        allow_module_level=True,
    )

#: What the pages write when they mean a make target. Every occurrence in the two
#: pages is a target today, so a prose "make sure" fails loudly rather than
#: silently skipping the check.
_MAKE_TARGET = re.compile(r"\bmake ([a-z][a-z0-9-]*)")
#: A target the specialist pages name, in backticks. Prose in those pages says
#: "make it" and "make the" often enough that only the quoted form is read.
_MAKE_TARGET_QUOTED = re.compile(r"`make ([a-z][a-z0-9-]*)`")
#: A CI job named the way these pages name them — in backticks, so prose like "the
#: same job" cannot be read as a job name.
_CI_JOB = re.compile(r"`([a-z][a-z0-9-]*)` job")
#: A target definition in the Makefile.
_MAKE_DEFINITION = re.compile(r"^([a-zA-Z][a-zA-Z0-9_.-]*):", re.MULTILINE)


def _page_text() -> str:
    return _README.read_text(encoding="utf-8") + _CONTRIBUTING.read_text(encoding="utf-8")


def _specialist_pages() -> list[Path]:
    """The documentation beside the two front pages, where targets are also named."""
    return [
        *sorted((_ROOT / "docs").glob("*.md")),
        _ROOT / "connectors" / "README.md",
        *sorted((_ROOT / "connectors").glob("*/README.md")),
    ]


def test_every_make_target_the_pages_name_exists():
    known = set(_MAKE_DEFINITION.findall(_MAKEFILE.read_text(encoding="utf-8")))
    assert known, "the Makefile defines no targets"
    named = set(_MAKE_TARGET.findall(_page_text()))
    for page in _specialist_pages():
        named |= set(
            _MAKE_TARGET_QUOTED.findall(page.read_text(encoding="utf-8", errors="replace"))
        )
    assert named - known == set()


def test_every_service_the_stack_starts_is_named_in_the_readme():
    compose = yaml.safe_load(_COMPOSE.read_text(encoding="utf-8"))
    services = set(compose.get("services", {}))
    assert services, "docker-compose.yml declares no services"
    readme = _README.read_text(encoding="utf-8")
    assert {service for service in services if service not in readme} == set()


def test_every_ci_job_the_pages_name_exists():
    workflow = yaml.safe_load(_CI.read_text(encoding="utf-8"))
    jobs = set(workflow.get("jobs", {}))
    assert jobs, "ci.yml declares no jobs"
    named = set(_CI_JOB.findall(_page_text()))
    assert named, "neither page names a CI job"
    assert named - jobs == set()


def test_the_wizard_runs_on_the_python_the_readme_promises():
    # README.md, "Prerequisites": Python 3.8 or newer on the host, with nothing
    # installed for it — so its syntax has to parse under that grammar.
    ast.parse(_WIZARD.read_text(encoding="utf-8"), feature_version=(3, 8))


def test_the_wizard_imports_only_the_standard_library():
    imported: set[str] = set()
    for node in ast.walk(ast.parse(_WIZARD.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module.split(".")[0])
    assert imported, "the wizard imports nothing"
    assert imported <= set(sys.stdlib_module_names), sorted(
        imported - set(sys.stdlib_module_names)
    )
