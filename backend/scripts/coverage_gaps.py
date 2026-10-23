"""Rank the modules a coverage run left behind, so a session picks by evidence.

The coverage gate answers one question — does every gated module clear its
floor — and says nothing about where the next hour is best spent. Answering that
by eye means reading a 10 000-statement report and comparing percentages whose
denominators differ: a module at 60% of twelve statements is not the same debt as
one at 88% of nine hundred, and only the second can move the aggregate.

This is the tool the coverage program uses between sessions. It reads the JSON
report ``pytest-cov`` already writes, ranks modules by statements *missed* rather
than by percentage, and prints either a table for a plan document or one line per
module for a shell. It measures nothing itself: the run is the expensive part, and
a batch records the numbers from one run instead of repeating it.

Usage::

    python scripts/coverage_gaps.py ../.coverage-baseline.json --limit 20
    python scripts/coverage_gaps.py ../.coverage-baseline.json --prefix app/services --below 85 --format table

Deliberately stdlib-only, like the other gates in this directory: it runs where
the backend tests run and installs nothing.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class ModuleCoverage:
    """One file's line coverage, in the terms the ranking needs."""

    module: str
    statements: int
    missed: int

    @property
    def percent(self) -> float:
        if self.statements <= 0:
            return 100.0
        return 100.0 * (self.statements - self.missed) / self.statements


def _normalized(name: str) -> str:
    # A report may spell a path with the separator of the host that wrote it, and
    # the ranking is compared across hosts. `Path.as_posix()` only rewrites the
    # separator of the running platform, so a Windows-style key read on Linux kept
    # its backslashes and ranked as a module of its own.
    return name.replace("\\", "/").lstrip("./")


def modules(report: dict[str, Any]) -> list[ModuleCoverage]:
    """Every file in a pytest-cov JSON report, with empty files dropped."""
    files = report.get("files")
    if not isinstance(files, dict):
        raise ValueError("coverage report does not contain a 'files' object")

    rows: list[ModuleCoverage] = []
    for name, data in files.items():
        if not isinstance(data, dict):
            continue
        summary = data.get("summary")
        if not isinstance(summary, dict):
            continue
        statements = summary.get("num_statements")
        missed = summary.get("missing_lines")
        if not isinstance(statements, int) or not isinstance(missed, int):
            continue
        if statements == 0:
            # A package marker or a stub has nothing to cover; listing it as
            # 100% adds a row to every table and teaches a reader to skip rows.
            continue
        rows.append(
            ModuleCoverage(
                module=_normalized(str(name)),
                statements=statements,
                missed=missed,
            )
        )
    return rows


def rank(
    rows: Iterable[ModuleCoverage],
    *,
    prefix: str | None = None,
    below: float | None = None,
    min_missed: int = 1,
    limit: int | None = None,
) -> list[ModuleCoverage]:
    """The worst files first: most missed statements, then lowest percentage."""
    selected = [
        row
        for row in rows
        if (prefix is None or row.module.startswith(prefix))
        and row.missed >= min_missed
        and (below is None or row.percent < below)
    ]
    selected.sort(key=lambda row: (-row.missed, row.percent, row.module))
    return selected[:limit] if limit is not None else selected


def totals(report: dict[str, Any]) -> ModuleCoverage:
    """The aggregate line, from the report's own totals."""
    summary = report.get("totals")
    if not isinstance(summary, dict):
        raise ValueError("coverage report does not contain a 'totals' object")
    statements = summary.get("num_statements")
    missed = summary.get("missing_lines")
    if not isinstance(statements, int) or not isinstance(missed, int):
        raise ValueError("coverage totals do not carry statement counts")
    return ModuleCoverage(module="app", statements=statements, missed=missed)


def render_markdown(rows: Iterable[ModuleCoverage]) -> str:
    """A table that can be pasted into a plan document unchanged."""
    lines = [
        "| Module | Statements | Missed | Covered |",
        "|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| `{row.module}` | {row.statements} | {row.missed} | {row.percent:.1f}% |"
        )
    return "\n".join(lines)


def render_text(rows: Iterable[ModuleCoverage]) -> str:
    return "\n".join(
        f"{row.module}  statements={row.statements}  missed={row.missed}  "
        f"{row.percent:.1f}%"
        for row in rows
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Rank modules by uncovered statements in a coverage JSON report."
    )
    parser.add_argument("report", type=Path, help="pytest-cov JSON report")
    parser.add_argument("--prefix", help="only modules whose path starts with this")
    parser.add_argument(
        "--below", type=float, help="only modules under this coverage percentage"
    )
    parser.add_argument(
        "--min-missed", type=int, default=1, help="ignore modules with fewer misses"
    )
    parser.add_argument("--limit", type=int, help="print at most this many modules")
    parser.add_argument(
        "--format", choices=("text", "table"), default="text", help="output shape"
    )
    parser.add_argument(
        "--total", action="store_true", help="print the aggregate line first"
    )
    args = parser.parse_args(argv)

    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"coverage gaps: cannot read {args.report}: {exc}", file=sys.stderr)
        return 2

    try:
        rows = rank(
            modules(report),
            prefix=args.prefix,
            below=args.below,
            min_missed=args.min_missed,
            limit=args.limit,
        )
        overall = totals(report)
    except ValueError as exc:
        print(f"coverage gaps: {exc}", file=sys.stderr)
        return 2

    if args.total:
        print(
            f"app: {overall.statements} statements, {overall.missed} missed, "
            f"{overall.percent:.2f}% covered"
        )
    if rows:
        print(render_markdown(rows) if args.format == "table" else render_text(rows))
    else:
        print("no module matched the filters")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
