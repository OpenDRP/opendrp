"""The register is the audit's memory, so it has to be readable by a machine.

`docs/audit-findings.md` states its own schema: ten columns, a severity from a
four-level rubric, a step the plan owns, a fix size of `S`, `M` or `L`, and a
disposition from a closed vocabulary in which `planned` names the plan that will
carry the finding. The synthesis step has to group the findings by size and by
disposition and to check that every planned row still has a plan to go to — work
that is only possible if the table means what its header says.

It did not. Thirty-nine of the eighty-seven rows had the *change* in the `Fix`
cell instead of the size, so no row's size could be read without reading the prose
beside it; and the seventeen `planned` rows named `009 S28`, a step of the plan
that was closing as they were written, so every one of them pointed at a session
that would never run. Both defects were invisible: the documentation gate checks
that a row carries its header's cells, not that a cell holds a value of the stated
kind.

What this file pins, in the order a reader would check it:

* the table has one header, no torn rows (a blank line between two rows is the
  audit's own AUD-078) and every row carries ten cells;
* IDs are contiguous from `AUD-001`, because the register is append-only and a gap
  is either a deleted finding or a mistyped one;
* each row's step is a step the plan actually defines;
* each row's `Fix` cell begins with its size, and its disposition begins with one
  of the four words the rubric allows;
* a `planned` row names a plan file that exists — and not the plan whose step is
  recorded in the same row, because that plan has finished and a finding cannot be
  carried by a closed step;
* a `fixed` row cites at least one test file, and every test file it cites exists;
* an `accepted` row names a page that states the risk, because the rubric requires
  "a sentence an operator can read" rather than a code comment.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_REGISTER = _ROOT / "docs" / "audit-findings.md"
_PLANS = _ROOT / "docs" / "exec-plans"

if not _REGISTER.is_file() or not _PLANS.is_dir():
    pytest.skip(
        "not a repository checkout: the register or the plans directory is missing",
        allow_module_level=True,
    )

_HEADER = "| ID | Sev | Step | Area |"
_SEVERITIES = {"S1", "S2", "S3", "S4"}
_DISPOSITIONS = ("fixed", "planned", "accepted", "duplicate")
_SIZES = ("S", "M", "L")
#: A test file a row's evidence names. Rows write these three ways — `tests/x.py`
#: from `backend/`, `backend/tests/x.py` from the repository root, and
#: `connectors/<worker>/test_x.py` — so the path is resolved against both roots
#: rather than normalised in the document. `tsx` comes before `ts`: the shorter
#: alternative would stop at the `ts` of a `.tsx` path and look for a file that
#: does not exist.
_EVIDENCE_TEST = re.compile(r"`([A-Za-z0-9_./-]+\.(?:py|tsx|ts))(?:[^`]*)`")
#: Inside a register row a test is also named by its file alone ("… and
#: `test_alert_policy.py` are 44 passed"), so a bare name is resolved by search.
_TEST_TREES = ("backend/tests", "frontend/src", "connectors")
_PLAN_REFERENCE = re.compile(r"\b(\d{3}-[a-z0-9][a-z0-9-]*)")


def _cells(line: str) -> list[str]:
    """The cells of one row, with an escaped `\\|` kept as text.

    GFM ends a cell at an unescaped pipe, and several rows quote a `||` guard or a
    TypeScript `string[] | undefined`; splitting naively would slice those rows
    into more cells than they have.
    """
    body = line.strip()
    assert body.startswith("|"), line
    body = body[1:]
    cells: list[str] = []
    current: list[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        if char == "\\" and index + 1 < len(body) and body[index + 1] == "|":
            current.append("|")
            index += 2
            continue
        if char == "|":
            cells.append("".join(current).strip())
            current = []
            index += 1
            continue
        current.append(char)
        index += 1
    if current:
        cells.append("".join(current).strip())
    return cells


def _register_lines() -> list[str]:
    return _REGISTER.read_text(encoding="utf-8").splitlines()


def _rows() -> list[list[str]]:
    return [_cells(line) for line in _register_lines() if line.startswith("| AUD-")]


def _plan_steps() -> set[str]:
    """Every step the staged-audit plan defines, as `#### S12` or `**S27b — …`."""
    text = (_PLANS / "009-staged-audit.md").read_text(encoding="utf-8")
    headings = set(re.findall(r"^#### (S\d{1,2}[a-f]?)\b", text, flags=re.MULTILINE))
    slices = set(re.findall(r"\*\*(S\d{1,2}[a-f]?) —", text))
    assert headings, "the staged-audit plan defines no steps"
    return headings | slices


def _plans_by_number() -> dict[str, Path]:
    return {path.name[:3]: path for path in _PLANS.glob("*.md")}


# ==============================================================================
# Shape
# ==============================================================================
def test_the_register_is_one_table_whose_rows_carry_ten_cells() -> None:
    lines = _register_lines()
    header_index = next(
        (index for index, line in enumerate(lines) if line.startswith(_HEADER)),
        None,
    )
    assert header_index is not None, f"the register has no header row starting {_HEADER!r}"

    within = False
    for number, line in enumerate(lines[header_index:], start=header_index + 1):
        if line.startswith("| AUD-"):
            within = True
            cells = _cells(line)
            assert len(cells) == 10, (
                f"line {number}: {cells[0]} carries {len(cells)} cell(s) where the "
                "header promises ten — a cell holding a pipe must escape it as `\\|`"
            )
        elif within and not line.strip():
            # A blank line ends the table in GFM; rows after it render as text.
            following = lines[number:]
            assert not any(entry.startswith("| AUD-") for entry in following[:1]), (
                f"line {number}: a blank line ends the register's table, so a finding "
                "renders as a paragraph of pipes (AUD-078)"
            )


def test_every_finding_id_is_contiguous() -> None:
    numbers = [int(row[0][len("AUD-") :]) for row in _rows()]

    assert numbers == list(range(1, len(numbers) + 1)), (
        "the register is append-only and its IDs run without a gap: "
        f"{len(numbers)} rows numbered {numbers[:3]}…{numbers[-3:]}"
    )


# ==============================================================================
# The columns the synthesis reads
# ==============================================================================
def test_every_step_is_one_the_plan_defines() -> None:
    steps = _plan_steps()
    unknown = {
        row[0]: row[2] for row in _rows() if row[2] not in steps
    }

    assert unknown == {}, (
        "these findings name a step no plan defines: "
        f"{unknown}; the plan's steps are {sorted(steps)}"
    )


def test_every_severity_is_from_the_rubric() -> None:
    wrong = {row[0]: row[1] for row in _rows() if row[1] not in _SEVERITIES}

    assert wrong == {}, f"severity must be one of {sorted(_SEVERITIES)}: {wrong}"


def test_every_fix_cell_starts_with_its_size() -> None:
    """The rubric's `S`/`M`/`L`, which is what "order by risk divided by cost" reads."""
    wrong = {
        row[0]: row[8][:60]
        for row in _rows()
        if not (row[8].startswith(tuple(_SIZES)) and row[8][1:2] in {" ", "—", ""})
    }

    assert wrong == {}, (
        "these rows put something other than a size in the Fix column, so the "
        "remediation order cannot be computed from the register:\n  "
        + "\n  ".join(f"{ident}: {text!r}" for ident, text in wrong.items())
    )


def test_every_disposition_is_one_of_the_four_words() -> None:
    wrong = {
        row[0]: row[9][:60]
        for row in _rows()
        if not row[9].startswith(_DISPOSITIONS)
    }

    assert wrong == {}, f"disposition must begin with one of {_DISPOSITIONS}: {wrong}"


def test_no_finding_is_left_open() -> None:
    open_rows = [row[0] for row in _rows() if row[9].startswith("open")]

    assert open_rows == [], (
        "`open` is a transient value inside a step; at the end of the audit every "
        f"finding has a disposition: {open_rows}"
    )


# ==============================================================================
# The dispositions' promises
# ==============================================================================
def test_a_planned_finding_names_a_plan_that_exists_and_is_not_its_own() -> None:
    plans = _plans_by_number()
    problems: list[str] = []
    for row in _rows():
        if not row[9].startswith("planned"):
            continue
        referenced = _PLAN_REFERENCE.findall(row[9])
        if not referenced:
            problems.append(f"{row[0]}: names no plan file")
            continue
        for number in referenced:
            # `011-remediation-pass.md` names the file; the plan's number is what
            # the lookup needs, and the file check below proves the rest.
            number = number.split("-")[0]
            plan = plans.get(number)
            if plan is None:
                problems.append(f"{row[0]}: {number} is not a file in docs/exec-plans")
                continue
            if number == "009":
                problems.append(
                    f"{row[0]}: points at 009, the plan whose step {row[2]} records "
                    "this finding — a closed plan cannot carry it"
                )

    assert problems == [], "planned findings must name a live plan:\n  " + "\n  ".join(problems)


def _resolves(path: str) -> bool:
    """Whether a cited file exists, from the root, `backend/` or `frontend/`.

    A citation with no directory is resolved by its name inside the three trees
    that hold tests, which is how the evidence cells write a second test file in
    the same sentence as a fully pathed one.
    """
    candidates = [_ROOT / path, _ROOT / "backend" / path, _ROOT / "frontend" / path]
    if any(candidate.is_file() for candidate in candidates):
        return True
    name = Path(path).name
    return any(
        found.is_file()
        for tree in _TEST_TREES
        for found in (_ROOT / tree).rglob(name)
    )


def test_a_fixed_finding_cites_a_test_that_exists() -> None:
    missing: list[str] = []
    uncited: list[str] = []
    for row in _rows():
        if not row[9].startswith("fixed"):
            continue
        # The evidence cell is where a step recorded what it reproduced; the fix
        # cell is where it says what pins the repair. Either one names the test.
        cited = {
            path
            for path in _EVIDENCE_TEST.findall(f"{row[6]} {row[8]}")
            if "test" in Path(path).name
        }
        if not cited:
            uncited.append(row[0])
            continue
        for path in sorted(cited):
            if not _resolves(path):
                missing.append(f"{row[0]} → {path}")

    assert uncited == [], (
        "a fixed finding is closed by a regression test, and these rows name none: "
        f"{uncited}"
    )
    assert missing == [], "these rows cite a test file that no longer exists:\n  " + "\n  ".join(missing)


def test_an_accepted_finding_names_the_page_that_states_the_risk() -> None:
    problems: list[str] = []
    for row in _rows():
        if not row[9].startswith("accepted"):
            continue
        pages = re.findall(r"([a-z-]+\.md)", row[9])
        if not pages:
            problems.append(f"{row[0]}: names no page")
            continue
        for page in pages:
            if not (_ROOT / "docs" / page).is_file():
                problems.append(f"{row[0]}: docs/{page} does not exist")

    assert problems == [], (
        "an accepted risk needs a sentence an operator can read: "
        + "; ".join(problems)
    )
