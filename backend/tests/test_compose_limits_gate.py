"""The Compose gate has to see a limit that disagrees with its documentation.

Two defects are asserted here, and both of them were real:

* the tables in `docs/configuration.md` listed eight services out of twenty-six
  and stated a PostgreSQL memory limit the Compose file did not set. Capacity
  planning from a page that disagrees with the deployment is worse than no page:
  the operator sizes a host for a stack that is not the one that starts;
* three services — `postgres`, `redis` and `frontend` — carried no container
  hardening at all while the other eleven did. Nothing failed, because hardening
  is invisible until the day it is needed, which is exactly why the asymmetry has
  to be a failing check rather than a convention.

The rule is deliberately two-sided: a service that cannot be hardened belongs in
the exception list *with its reason written out*, so a deliberate exception and a
forgotten line cannot look the same.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_GATE = _ROOT / "scripts" / "check_compose_healthchecks.py"
_COMPOSE = _ROOT / "docker-compose.yml"
_LIMITS_DOC = _ROOT / "docs" / "configuration.md"

if not _GATE.is_file() or not _COMPOSE.is_file() or not _LIMITS_DOC.is_file():
    pytest.skip(
        "not a repository checkout: the Compose gate, the compose file or the "
        "limits table is missing",
        allow_module_level=True,
    )


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


gate = _load(_GATE, "opendrp_test_check_compose_limits")

_COMPOSE_TEXT = _COMPOSE.read_text(encoding="utf-8")
_DOC_TEXT = _LIMITS_DOC.read_text(encoding="utf-8")


def _rows() -> list[str]:
    return [line for line in _DOC_TEXT.splitlines() if gate._LIMITS_TABLE_ROW.match(line.strip())]


def _doc_without(service: str, tmp_path: Path) -> Path:
    body = "\n".join(
        line for line in _DOC_TEXT.splitlines() if f"`{service}`" not in line or not gate._LIMITS_TABLE_ROW.match(line.strip())
    )
    path = tmp_path / "configuration.md"
    path.write_text(body, encoding="utf-8")
    return path


# ==============================================================================
# The shipped pair
# ==============================================================================
def test_the_documented_limits_are_the_ones_compose_applies() -> None:
    assert gate._check_documented_limits(_COMPOSE_TEXT, _LIMITS_DOC) == []


def test_the_shipped_stack_needs_no_hardening_exception() -> None:
    """Every service carries `security_opt` and `cap_drop` today.

    Stated as an assertion rather than left implicit: adding an exception is then
    a deliberate edit here as well as in the gate, and a service slipping back to
    no hardening cannot be explained away as a tuning choice.
    """
    services, _line = gate.parse_services(_COMPOSE_TEXT)

    assert gate._check_hardening(services) == []
    assert gate._HARDENING_EXCEPTIONS == {}


def test_the_whole_gate_passes_over_the_shipped_file() -> None:
    assert gate.check(_COMPOSE_TEXT, _ROOT) == []


def test_every_service_has_a_documented_row() -> None:
    services, _line = gate.parse_services(_COMPOSE_TEXT)
    documented = {
        match.group("service")
        for line in _DOC_TEXT.splitlines()
        if (match := gate._LIMITS_TABLE_ROW.match(line.strip())) is not None
    }

    assert {service.name for service in services} <= documented


# ==============================================================================
# The defects the rule exists for
# ==============================================================================
def test_a_service_missing_from_the_table_is_reported(tmp_path: Path) -> None:
    failures = gate._check_documented_limits(
        _COMPOSE_TEXT, _doc_without("celery-worker", tmp_path)
    )

    assert len(failures) == 1, failures
    assert "celery-worker" in failures[0]
    assert "not in the resource table" in failures[0]


def test_a_limit_that_disagrees_with_the_documentation_is_reported(
    tmp_path: Path,
) -> None:
    """The original defect: a page saying 1 GB while Compose set something else."""
    body = _DOC_TEXT.replace(
        "| `postgres` | `1.5g` | `1.0` | `256` |",
        "| `postgres` | `1g` | `1.0` | `256` |",
    )
    assert body != _DOC_TEXT, "the row the test edits is not in the table"
    path = tmp_path / "configuration.md"
    path.write_text(body, encoding="utf-8")

    failures = gate._check_documented_limits(_COMPOSE_TEXT, path)

    assert len(failures) == 1, failures
    assert "1g" in failures[0]
    assert "1.5g" in failures[0]


def test_a_row_that_outlived_its_service_is_reported(tmp_path: Path) -> None:
    body = _DOC_TEXT + "\n| `connector-retired` | `512m` | `0.5` | `128` |\n"
    path = tmp_path / "configuration.md"
    path.write_text(body, encoding="utf-8")

    failures = gate._check_documented_limits(_COMPOSE_TEXT, path)

    assert len(failures) == 1, failures
    assert "connector-retired" in failures[0]


def test_a_duplicated_row_is_reported(tmp_path: Path) -> None:
    body = _DOC_TEXT + "\n| `redis` | `512m` | `0.5` | `128` |\n"
    path = tmp_path / "configuration.md"
    path.write_text(body, encoding="utf-8")

    failures = gate._check_documented_limits(_COMPOSE_TEXT, path)

    assert len(failures) == 1, failures
    assert "twice" in failures[0]


def test_a_missing_table_is_reported_rather_than_passing() -> None:
    failures = gate._check_documented_limits(
        _COMPOSE_TEXT, _ROOT / "docs" / "does-not-exist.md"
    )

    assert len(failures) == 1
    assert "cannot read the resource table" in failures[0]


def test_a_service_without_hardening_is_reported() -> None:
    text = "services:\n  redis:\n    image: redis:7-alpine\n    mem_limit: 512m\n"
    services, _line = gate.parse_services(text)

    failures = gate._check_hardening(services)

    assert len(failures) == 1, failures
    assert "redis" in failures[0]
    assert "security_opt" in failures[0]
    assert "cap_drop" in failures[0]


def test_an_exception_without_a_reason_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`_HARDENING_EXCEPTIONS = {"redis": ""}` is the shape this forbids."""
    monkeypatch.setitem(gate._HARDENING_EXCEPTIONS, "redis", "")
    services, _line = gate.parse_services(_COMPOSE_TEXT)

    failures = gate._check_hardening(services)

    assert len(failures) == 1, failures
    assert "without a reason" in failures[0]


def test_a_named_exception_is_accepted_with_its_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other direction: a stated exception is not a finding."""
    monkeypatch.setitem(
        gate._HARDENING_EXCEPTIONS,
        "redis",
        "requires the default capability set for reasons recorded in the audit",
    )
    services, _line = gate.parse_services(_COMPOSE_TEXT)

    assert gate._check_hardening(services) == []
