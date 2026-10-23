"""The page an operator reads and the gate that enforces it say the same thing.

`docs/production-readiness.md` promises which security boundaries fail the build
below their threshold. That promise was a second copy of the gate's map, and the
release before this one shipped with the copies out of step — the page named a
table the gate did not hold, and nothing could tell. The gate now prints the
coverage flag the runs use (`--cov-args`), so the run and the gate cannot
disagree; these tests keep the page on the gate's own list, keep that output a
single flag over the package the gated modules live in, and keep a report that
drops one of them a failure rather than a pass.

Dated snapshots in the appendix are deliberately out of scope: they describe a
tree, not the gate, and are meant to differ from today's rule.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

#: The backend tree this test lives in (``/app`` in the Compose dev container,
#: where the repository root is not mounted as a directory of its own).
_BACKEND = Path(__file__).resolve().parents[1]
#: ``parents[2]`` of ``tests/`` is the repository root — ``/`` in that container,
#: with ``docs/`` mounted read-only at the path the page is expected at.
_ROOT = _BACKEND.parent
_GATE = _BACKEND / "scripts" / "check_critical_coverage.py"
_PAGE = _ROOT / "docs" / "production-readiness.md"

_spec = importlib.util.spec_from_file_location("check_critical_coverage", _GATE)
assert _spec is not None and _spec.loader is not None
_gate = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("check_critical_coverage", _gate)
_spec.loader.exec_module(_gate)

_SECTION = "## Gated security boundaries"
_ROW = re.compile(r"^\|\s*`([^`]+)`\s*\|\s*(\d+)%\s*\|\s*$", re.MULTILINE)
_MODULE_PATH = re.compile(r"^app/(?:[a-z0-9_]+/)*[a-z0-9_]+\.py$")


def _table() -> dict[str, int]:
    text = _PAGE.read_text(encoding="utf-8")
    start = text.index(_SECTION)
    section = text[start:]
    end = section.find("\n## ", len(_SECTION))
    if end != -1:
        section = section[:end]
    return {
        module: int(threshold)
        for module, threshold in _ROW.findall(section)
    }


def test_the_page_lists_exactly_the_modules_the_gate_holds():
    table = _table()
    assert table, "the gated-boundaries section lists no modules"
    assert set(table) == set(_gate.THRESHOLDS), (
        "docs/production-readiness.md and check_critical_coverage.py disagree: "
        f"only in the page {sorted(set(table) - set(_gate.THRESHOLDS))}, "
        f"only in the gate {sorted(set(_gate.THRESHOLDS) - set(table))}"
    )
    assert all(_MODULE_PATH.match(module) for module in table)


def test_the_page_states_the_threshold_the_gate_enforces():
    table = _table()
    for module, threshold in table.items():
        assert float(threshold) == _gate.THRESHOLDS[module], (
            f"{module}: the page says {threshold}%, the gate enforces "
            f"{_gate.THRESHOLDS[module]}%"
        )


def test_the_gate_prints_the_package_flag_the_runs_use(capsys):
    assert _gate.main(["--cov-args"]) == 0
    assert capsys.readouterr().out.split() == ["--cov=app"]


def test_a_report_missing_a_gated_module_fails_the_gate(tmp_path, capsys):
    """A package measurement cannot silently drop a module: absence is failure.

    This is the failure the dotted per-module flags were introduced to prevent —
    a report without the file reported as a missing measurement while the coverage
    asked about was fine. The package flag makes that impossible by measuring
    everything, and this test keeps the gate's own check honest for a report that
    was produced some other way.
    """
    report = tmp_path / "coverage.json"
    report.write_text(json.dumps({"files": {}}), encoding="utf-8")
    assert _gate.main([str(report)]) == 1
    output = capsys.readouterr().out
    assert "critical coverage gate: FAILED" in output
    assert "missing from coverage report" in output
