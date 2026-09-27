"""Fail when the integration suite silently skipped instead of running.

The integration modules skip themselves when their connection env vars are
missing. That keeps local runs convenient, but it also means a CI wiring
mistake turns the strongest gate in the pipeline into a green no-op: the job
reports success while the PostgreSQL and Redis contracts are never exercised.

This reads pytest's JUnit XML and fails when anything was skipped, or when
fewer tests passed than the caller expects.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ElementTree
from pathlib import Path


class Counts:
    def __init__(self) -> None:
        self.passed = 0
        self.skipped: list[str] = []
        self.failed: list[str] = []


def _case_label(case: ElementTree.Element) -> str:
    classname = case.get("classname") or ""
    return f"{classname}::{case.get('name')}" if classname else str(case.get("name"))


def collect_counts(report_path: Path) -> Counts:
    root = ElementTree.parse(report_path).getroot()
    counts = Counts()
    for case in root.iter("testcase"):
        if case.find("skipped") is not None:
            counts.skipped.append(_case_label(case))
        elif case.find("failure") is not None or case.find("error") is not None:
            counts.failed.append(_case_label(case))
        else:
            counts.passed += 1
    return counts


def main(argv: list[str]) -> int:
    min_passed = 0
    positional: list[str] = []
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument == "--min-passed":
            index += 1
            if index >= len(argv):
                print("usage: python scripts/check_integration_ran.py REPORT.xml [--min-passed N]")
                return 2
            try:
                min_passed = int(argv[index])
            except ValueError:
                print(f"integration gate: FAILED — --min-passed must be an integer, got {argv[index]!r}")
                return 2
        else:
            positional.append(argument)
        index += 1

    if len(positional) != 1:
        print("usage: python scripts/check_integration_ran.py REPORT.xml [--min-passed N]")
        return 2

    report_path = Path(positional[0])
    if not report_path.is_file():
        print(f"integration gate: FAILED — report not found: {report_path}")
        return 2

    try:
        counts = collect_counts(report_path)
    except (OSError, ElementTree.ParseError) as exc:
        print(f"integration gate: FAILED — cannot read report: {exc}")
        return 2

    failures: list[str] = []
    if counts.skipped:
        failures.append(
            f"{len(counts.skipped)} integration test(s) were skipped instead of run:"
        )
        failures.extend(f"  - {label}" for label in counts.skipped)
    if counts.failed:
        failures.append(f"{len(counts.failed)} integration test(s) failed:")
        failures.extend(f"  - {label}" for label in counts.failed)
    if counts.passed < min_passed:
        failures.append(
            f"only {counts.passed} integration test(s) passed, expected at least {min_passed}"
        )

    if failures:
        print("integration gate: FAILED")
        for failure in failures:
            print(f"  {failure}" if not failure.startswith("  ") else failure)
        return 1

    print(f"integration gate: OK — {counts.passed} integration test(s) ran, none skipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
