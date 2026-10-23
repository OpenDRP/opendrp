"""The mypy ratchet gate's own proof (AUD-089).

`scripts/check_mypy_baseline.py` is the only thing keeping `mypy app` at zero
errors: `MYPY_ERROR_BASELINE` is 0, so a summary regex that stops matching, a
comparison that stops comparing, or an exit code that flips passes a build with
type errors in it and no test reports the difference.

These tests drive `main` with `_run_mypy` stubbed through all four outcomes the
gate can reach, so each decision is pinned by the number it must produce. They
also pin the fifth case the gate met on a host without the tool installed: the
gate must answer its own "no summary" failure instead of raising out of the
process with a traceback no CI log explains.
"""

from __future__ import annotations

from scripts import check_mypy_baseline as gate


def _with_output(monkeypatch, count: int | None, output: str) -> None:
    monkeypatch.setattr(gate, "_run_mypy", lambda argv: (count, output))


def test_an_over_baseline_count_fails_the_build(monkeypatch, capsys):
    _with_output(
        monkeypatch,
        3,
        "app/services/x.py:1: error: Incompatible return value\n"
        "Found 3 errors in 1 file (checked 120 source files)\n",
    )

    assert gate.main([]) == 1
    printed = capsys.readouterr().out
    assert "3 errors exceed baseline 0" in printed
    assert "Incompatible return value" in printed


def test_the_success_line_passes(monkeypatch):
    _with_output(monkeypatch, 0, "Success: no issues found in 120 source files\n")

    assert gate.main([]) == 0


def test_a_count_equal_to_the_baseline_passes(monkeypatch):
    """The baseline is a ceiling, not a target: equal is not a regression."""
    _with_output(monkeypatch, 0, "Found 0 errors in 0 files (checked 120 source files)\n")

    assert gate.main([]) == 0


def test_output_without_a_summary_is_its_own_failure(monkeypatch, capsys):
    _with_output(monkeypatch, None, "Traceback (most recent call last): ...\n")

    assert gate.main([]) == 2
    assert "no error summary found" in capsys.readouterr().out


def test_a_missing_mypy_answers_the_gate_failure_instead_of_raising(monkeypatch, capsys):
    """A host without the tool must still get the gate's verdict, not a traceback.

    This is the path a fresh checkout takes when the dev requirements are not
    installed: `subprocess.run` raises `FileNotFoundError` before mypy prints
    anything, and the gate used to exit through an unhandled exception. Exit 2 is
    the documented answer for "mypy printed no summary", and that covers this.
    """

    def missing(*args, **kwargs):
        raise FileNotFoundError(2, "The system cannot find the file specified", "mypy")

    monkeypatch.setattr(gate.subprocess, "run", missing)

    assert gate.main([]) == 2
    printed = capsys.readouterr().out
    assert "mypy" in printed
    assert "no error summary found" in printed


def test_the_gate_runs_mypy_over_the_application_package(monkeypatch):
    """The arguments matter too: a gate that stopped passing `app` would type-check nothing."""
    seen: list[list[str]] = []

    def record(args):
        seen.append(args)
        return 0, "Success: no issues found in 120 source files\n"

    monkeypatch.setattr(gate, "_run_mypy", record)

    assert gate.main(["--strict"]) == 0
    assert seen == [["--strict"]]
