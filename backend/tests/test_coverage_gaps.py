"""The ranking a coverage session chooses from has to be the one the report says.

A coverage program built on a hand-read report drifts in a specific way: the
session picks the module it remembers as worst, and the numbers in the plan stop
describing the tree a run actually produced. These tests pin the two decisions the
helper makes — *which* files it lists (statements missed, not percentage) and what
it leaves out (a file with nothing to cover, a filter that excludes it) — plus the
markdown it writes into a batch document, because that text is copied rather than
retyped.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "coverage_gaps.py"
_spec = importlib.util.spec_from_file_location("coverage_gaps", _SCRIPT)
assert _spec is not None and _spec.loader is not None
coverage_gaps = importlib.util.module_from_spec(_spec)
# ``dataclass`` resolves the defining module through ``sys.modules``; a module
# loaded by path is absent from it until it is registered.
sys.modules[_spec.name] = coverage_gaps
_spec.loader.exec_module(coverage_gaps)


def _entry(statements: int, missed: int) -> dict:
    return {
        "summary": {
            "num_statements": statements,
            "missing_lines": missed,
            "percent_covered": 0.0
            if statements == 0
            else 100.0 * (statements - missed) / statements,
        }
    }


def _report(**files: dict) -> dict:
    return {
        "files": files,
        # pytest-cov's totals are flat, unlike a file entry's nested ``summary``.
        "totals": {"num_statements": 100, "missing_lines": 25, "percent_covered": 75.0},
    }


class TestWhichModulesAreRanked:
    def test_most_missed_statements_come_first(self):
        rows = coverage_gaps.modules(
            _report(
                **{
                    "app/small.py": _entry(10, 4),  # 60%, 4 missed
                    "app/large.py": _entry(400, 40),  # 90%, 40 missed
                    "app/mid.py": _entry(40, 10),  # 75%, 10 missed
                }
            )
        )
        ranked = coverage_gaps.rank(rows)
        assert [row.module for row in ranked] == [
            "app/large.py",
            "app/mid.py",
            "app/small.py",
        ]

    def test_percentage_breaks_a_missed_tie(self):
        rows = coverage_gaps.modules(
            _report(**{"app/b.py": _entry(100, 20), "app/a.py": _entry(50, 20)})
        )
        ranked = coverage_gaps.rank(rows)
        assert [row.module for row in ranked] == ["app/a.py", "app/b.py"]

    def test_a_file_with_nothing_to_cover_is_not_a_row(self):
        rows = coverage_gaps.modules(_report(**{"app/__init__.py": _entry(0, 0)}))
        assert rows == []

    def test_windows_separators_are_normalised(self):
        rows = coverage_gaps.modules(_report(**{".\\app\\core\\x.py": _entry(10, 1)}))
        assert [row.module for row in rows] == ["app/core/x.py"]


class TestFilters:
    def test_prefix_selects_one_subtree(self):
        rows = coverage_gaps.modules(
            _report(
                **{"app/services/a.py": _entry(10, 5), "app/core/b.py": _entry(10, 5)}
            )
        )
        ranked = coverage_gaps.rank(rows, prefix="app/services")
        assert [row.module for row in ranked] == ["app/services/a.py"]

    def test_below_keeps_only_modules_under_the_line(self):
        rows = coverage_gaps.modules(
            _report(**{"app/low.py": _entry(10, 5), "app/high.py": _entry(10, 1)})
        )
        ranked = coverage_gaps.rank(rows, below=85.0)
        assert [row.module for row in ranked] == ["app/low.py"]

    def test_min_missed_and_limit_bound_the_list(self):
        rows = coverage_gaps.modules(
            _report(
                **{
                    "app/a.py": _entry(100, 30),
                    "app/b.py": _entry(100, 3),
                    "app/c.py": _entry(100, 20),
                }
            )
        )
        assert [row.module for row in coverage_gaps.rank(rows, min_missed=5)] == [
            "app/a.py",
            "app/c.py",
        ]
        assert [row.module for row in coverage_gaps.rank(rows, limit=1)] == ["app/a.py"]


class TestRendering:
    def test_table_has_one_row_per_module_and_no_extra_cells(self):
        rows = coverage_gaps.modules(
            _report(**{"app/a.py": _entry(100, 25), "app/b.py": _entry(8, 2)})
        )
        table = coverage_gaps.render_markdown(coverage_gaps.rank(rows))
        lines = table.splitlines()
        assert lines[0] == "| Module | Statements | Missed | Covered |"
        assert lines[1] == "|---|---|---|---|"
        assert lines[2] == "| `app/a.py` | 100 | 25 | 75.0% |"
        assert len(lines) == 4

    def test_text_is_one_line_per_module(self):
        rows = coverage_gaps.modules(_report(**{"app/a.py": _entry(100, 25)}))
        text = coverage_gaps.render_text(rows)
        assert text == "app/a.py  statements=100  missed=25  75.0%"


class TestTotalsAndErrors:
    def test_totals_come_from_the_report_not_from_the_file_list(self):
        overall = coverage_gaps.totals(_report(**{"app/a.py": _entry(10, 1)}))
        assert (overall.statements, overall.missed) == (100, 25)
        assert overall.percent == pytest.approx(75.0)

    def test_a_report_without_files_is_an_error(self):
        with pytest.raises(ValueError, match="files"):
            coverage_gaps.modules({"totals": _entry(1, 0)})

    def test_cli_reports_an_unreadable_report_as_exit_two(self, tmp_path, capsys):
        missing = tmp_path / "nope.json"
        assert coverage_gaps.main([str(missing)]) == 2
        assert "cannot read" in capsys.readouterr().err

    def test_cli_prints_the_aggregate_when_asked(self, tmp_path, capsys):
        report = tmp_path / "coverage.json"
        report.write_text(
            json.dumps(_report(**{"app/a.py": _entry(100, 25)})), encoding="utf-8"
        )
        assert coverage_gaps.main([str(report), "--total", "--min-missed", "1"]) == 0
        out = capsys.readouterr().out
        assert "app: 100 statements, 25 missed, 75.00% covered" in out
        assert "app/a.py" in out
