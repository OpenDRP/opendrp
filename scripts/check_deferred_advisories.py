#!/usr/bin/env python3
"""Fail when the README's deferred-advisory list disagrees with the audits.

`README.md` used to say, under "Known deferred findings":

    The Vite/esbuild/vitest toolchain advisories are devDependencies; every fix
    is a major bump.

Both halves were false the day they were read. The advisories were lifted by a
patch and a minor (`source-map-js` 1.2.2, `vitest` 4.1.12), so the list named
four packages that no longer had an advisory and claimed a migration that was
never needed — and nothing recomputed the sentence, because the exemption it
described was exactly the part CI did not gate: `npm audit` ran with
`continue-on-error`, so a *new* dev advisory would appear in the log and the
paragraph would go on saying "these are the known ones".

This gate is the recomputation. The audits in the `security` job write their JSON
(`npm audit --json` over the whole frontend tree, `pip-audit -f json` over the
backend runtime lock and every connector lock), and this compares that set with
what the README declares — in both directions, because the two failures are
different:

* an audit reports an advisory the README does not name — the paragraph is
  silently incomplete, which is how the old one aged;
* the README names an advisory no audit reports — the paragraph is stale, which
  is what the old one was.

The README declares the list in one of two ways, and the gate accepts exactly
one of them:

* the sentence `none at the time of writing`, for an empty set; or
* a table under the section's opening line, one row per deferred advisory:

      | Package | Ecosystem | Why it is deferred |
      |---|---|---|
      | `vite` | npm | build-time only, not in the served bundle |

`Package` is read from the backticks, `Ecosystem` is `npm` or `pip`. Severity is
deliberately not a column: `pip-audit`'s JSON carries no severity, so a column
the gate could only check on one side would be a claim it cannot recompute. The
"why" cell is prose for the reader; the gate never parses it.

Usage
-----
    python scripts/check_deferred_advisories.py README.md /tmp/audit-*.json

Each audit file is classified by its shape — a JSON object with a
`vulnerabilities` map is `npm audit --json`, and a JSON object with a
`dependencies` list (pip-audit 2.x) or a bare list of `{name, version, vulns}`
entries (pip-audit 0.x) is `pip-audit -f json` — so the workflow can hand over
every file it wrote without labelling them twice. Both pip-audit shapes are read
because the audit step pins a date rather than a version: the shape changed
under a `pip install --upgrade pip-audit` once already.

What this does not cover: the Python *development* requirements
(`backend/requirements-dev.txt`) have no audit step in CI, so an advisory there is
not in any file this reads. The frontend is audited whole, devDependencies
included, which is the surface that produced the paragraph.

Exit codes: 0 the list and the audits agree, 1 they disagree (every difference is
printed), 2 an input cannot be read or is not in the form above.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable, NamedTuple, Sequence

#: The sentence that opens the section, matched on its first words.
SECTION_TITLE = "Known deferred findings"

#: The sentence that declares the empty set. Its absence, with no table, is an
#: unreadable section rather than an empty one — silence must not pass here.
NOTHING_DEFERRED = "none at the time of writing"

#: The table's header, cell by cell, in order.
TABLE_COLUMNS = ("Package", "Ecosystem", "Why it is deferred")

#: The ecosystems the audits in this repository cover, and the spelling the
#: README has to use for each.
ECOSYSTEMS = ("npm", "pip")

#: A backticked token in the `Package` cell: the name, as written in the manifest.
_BACKTICKED = re.compile(r"`([^`]+)`")

#: PEP 503: a Python name is case-insensitive and `-`, `_` and `.` are one character.
_PYTHON_SEPARATOR = re.compile(r"[-_.]+")


class GateError(RuntimeError):
    """An input exists but cannot be read as the form this gate compares."""


class Advisory(NamedTuple):
    """One package an audit reports, named the way its ecosystem names it."""

    ecosystem: str
    package: str

    def __str__(self) -> str:
        return f"{self.package} ({self.ecosystem})"


def normalise(ecosystem: str, package: str) -> str:
    """The name a manifest and an audit both spell, reduced to one key."""
    name = package.strip().strip("`").strip()
    if ecosystem == "npm":
        # npm names are lowercase; a scope is part of the name.
        return name.lower()
    return _PYTHON_SEPARATOR.sub("-", name).lower()


def section(text: str) -> list[str]:
    """The deferred-findings section, up to the next heading.

    The opener line's own tail is part of it: the empty set is declared on that
    line (`Known deferred findings, tracked rather than ignored: none at the time
    of writing.`), and reading only the lines below it would miss the sentence.
    """
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip().startswith(SECTION_TITLE):
            body: list[str] = [line.strip()[len(SECTION_TITLE) :].lstrip(",:").strip()]
            for following in lines[index + 1 :]:
                if following.startswith("#"):
                    break
                body.append(following)
            return body
    raise GateError(f"no {SECTION_TITLE!r} section: the paragraph this gate checks is gone")


def _cells(line: str) -> list[str]:
    """A markdown table row's cells, without the outer pipes."""
    stripped = line.strip()
    if not stripped.startswith("|"):
        return []
    return [cell.strip() for cell in stripped.strip("|").split("|")]


def _is_separator(line: str) -> bool:
    cells = _cells(line)
    return bool(cells) and all(set(cell) <= set("-: ") and cell for cell in cells)


def deferred(text: str) -> tuple[set[Advisory], list[str]]:
    """What the README declares deferred, and any reason it could not be read.

    A problem here is a malformed declaration, not a wrong one: it means the
    section neither says "none" nor holds a table the gate can read, which is the
    state in which the old paragraph lived.
    """
    body = section(text)
    joined = "\n".join(body)
    declares_nothing = NOTHING_DEFERRED in joined.lower()

    table_start = None
    for offset, line in enumerate(body):
        if tuple(_cells(line)) == TABLE_COLUMNS:
            table_start = offset
            break

    if declares_nothing and table_start is not None:
        return set(), [
            f"the section says {NOTHING_DEFERRED!r} and also holds a table: "
            "one of the two is the list"
        ]
    if declares_nothing:
        return set(), []
    if table_start is None:
        return set(), [
            f"the section says neither {NOTHING_DEFERRED!r} nor a table headed "
            f"{' | '.join(TABLE_COLUMNS)}"
        ]

    entries: set[Advisory] = set()
    problems: list[str] = []
    for line in body[table_start + 1 :]:
        if not line.strip().startswith("|"):
            break
        if _is_separator(line):
            continue
        cells = _cells(line)
        if len(cells) < len(TABLE_COLUMNS):
            problems.append(f"a row has {len(cells)} cells, the table has {len(TABLE_COLUMNS)}: {line}")
            continue
        package_cell, ecosystem_cell = cells[0], cells[1]
        names = _BACKTICKED.findall(package_cell)
        if not names:
            problems.append(f"the Package cell names no package in backticks: {line}")
            continue
        ecosystem = ecosystem_cell.strip("`").strip().lower()
        if ecosystem not in ECOSYSTEMS:
            problems.append(
                f"{names[0]!r} is filed under {ecosystem_cell!r}; "
                f"the ecosystems here are {', '.join(ECOSYSTEMS)}: {line}"
            )
            continue
        entries.add(Advisory(ecosystem, normalise(ecosystem, names[0])))
    return entries, problems


def npm_advisories(payload: Any) -> set[Advisory]:
    """The packages `npm audit --json` reports, from its `vulnerabilities` map."""
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), dict):
        raise GateError(
            "not an `npm audit --json` report: expected an object with a "
            "`vulnerabilities` map"
        )
    return {Advisory("npm", normalise("npm", name)) for name in payload["vulnerabilities"]}


def pip_advisories(payload: Any) -> set[Advisory]:
    """The packages `pip-audit -f json` reports: only the entries with `vulns`.

    pip-audit 2.x writes an envelope — `{"dependencies": [...], "fixes": []}` —
    and 0.x wrote the bare list. Both have to parse: the workflow installs
    whatever `pip install --upgrade pip-audit` gives it that morning, and the
    first version of this gate read only the list, which is how the step failed
    on its first run with an envelope on disk.
    """
    entries = payload.get("dependencies") if isinstance(payload, dict) else payload
    if not isinstance(entries, list):
        raise GateError(
            "not a `pip-audit -f json` report: expected a `dependencies` list or "
            "a list of `{name, version, vulns}` entries"
        )
    reported: set[Advisory] = set()
    for entry in entries:
        if not isinstance(entry, dict) or "name" not in entry:
            raise GateError(f"a pip-audit entry has no `name`: {entry!r}")
        if entry.get("vulns"):
            reported.add(Advisory("pip", normalise("pip", str(entry["name"]))))
    return reported


def read_audit(path: Path) -> set[Advisory]:
    """The advisories one audit file reports, classified by its shape."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise GateError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise GateError(f"{path} is not JSON: {exc}") from exc

    if isinstance(payload, list):
        return pip_advisories(payload)
    if isinstance(payload, dict) and "vulnerabilities" in payload:
        return npm_advisories(payload)
    if isinstance(payload, dict) and "dependencies" in payload:
        return pip_advisories(payload)
    raise GateError(f"{path} is neither an npm audit nor a pip-audit report")


def audited(paths: Sequence[Path]) -> dict[Advisory, list[str]]:
    """Every advisory the audits report, with the files that reported it."""
    found: dict[Advisory, list[str]] = {}
    for path in paths:
        for advisory in read_audit(path):
            found.setdefault(advisory, []).append(path.name)
    return found


def compare(declared: Iterable[Advisory], reported: dict[Advisory, list[str]]) -> list[str]:
    """Both directions of the disagreement, as failures an operator can act on."""
    declared_set = set(declared)
    failures = [
        f"the audit reports {advisory}, the README's deferred list does not name it — "
        f"fix it, or add the row (reported by {', '.join(sorted(sources))}):\n"
        f"    | `{advisory.package}` | {advisory.ecosystem} | <why it cannot be fixed here> |"
        for advisory, sources in sorted(reported.items())
        if advisory not in declared_set
    ]
    failures.extend(
        f"the README defers {advisory}, no audit reports it any more — "
        f"drop the row"
        for advisory in sorted(declared_set - set(reported))
    )
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare the README's deferred advisories with the audits' JSON."
    )
    parser.add_argument("readme", help="the page that declares the list")
    parser.add_argument(
        "audits",
        nargs="+",
        help="`npm audit --json` and `pip-audit -f json` reports to compare it with",
    )
    args = parser.parse_args(argv)

    readme = Path(args.readme)
    try:
        text = readme.read_text(encoding="utf-8")
        declared, problems = deferred(text)
        reported = audited([Path(path) for path in args.audits])
    except GateError as exc:
        print(f"cannot compare: {exc}", file=sys.stderr)
        return 2

    if problems:
        for problem in problems:
            print(f"{readme}: {problem}", file=sys.stderr)
        return 2

    failures = compare(declared, reported)
    if failures:
        print(
            f"{readme} and the {len(args.audits)} audit report(s) disagree:",
            file=sys.stderr,
        )
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print(
        f"{readme}: {len(declared)} deferred advisories, "
        f"{len(reported)} reported by {len(args.audits)} audit report(s) — they agree"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
