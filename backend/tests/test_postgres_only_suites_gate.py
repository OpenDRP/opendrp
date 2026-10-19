"""The PostgreSQL-only suites must be *run* by a job, not merely exist.

Both files below check properties only PostgreSQL can host: a row lock that makes
two concurrent DNS expiry sweeps queue one alert, and the correlated ``EXISTS``
behind the ``has_findings`` filter. Each skipped itself when
``INTEGRATION_MIGRATION_DATABASE_URL`` was absent — which is exactly what no job
ever provided — so both were green-looking tests that had never run anywhere,
and the properties they assert had no gate at all. The audit that opened the
remediation plan named them one by one
(`docs/production-readiness-audit-2026-10-13-independent-review.md`).

This is the gate on the wiring itself, because a file that exists and is never
selected is the failure this test exists to prevent:

* the job that already leaves a migrated database behind runs both files;
* the same job turns a missing database into a failure (``REQUIRE_INTEGRATION=1``)
  and then asserts, on the report, that nothing was skipped;
* each suite declares the ``integration`` marker, so the SQLite job keeps
  deselecting it and the integration job keeps selecting it.

The workflow, the two suites and ``scripts/check_integration_ran.py`` are all
inputs, and the dev overlay mounts each one where this test resolves it.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ElementTree
from pathlib import Path

import pytest
import yaml

_ROOT = Path(__file__).resolve().parents[2]
_TESTS = Path(__file__).resolve().parent
_WORKFLOW = _ROOT / ".github/workflows/ci.yml"
_SUITES = (
    "test_asset_involvement_postgres.py",
    "test_dns_expiry_postgres.py",
    # The user/RBAC wave's PostgreSQL half: the refresh-family cascade (RWI-10)
    # and the administrator-set advisory lock (RWI-11). Both are properties SQLite
    # cannot host, so a suite that exists and is never selected is the same defect
    # this gate was written for.
    "test_users_rbac_postgres.py",
)
_JOB = "production-integration"

if not _WORKFLOW.is_file():
    # A trimmed checkout cannot answer a question about the workflow.
    pytest.skip(f"not a repository checkout: {_WORKFLOW} missing", allow_module_level=True)


def _job() -> dict:
    workflow = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    jobs = workflow.get("jobs") or {}
    assert _JOB in jobs, f"the workflow no longer has the {_JOB} job"
    return jobs[_JOB]


def _steps() -> list[dict]:
    steps = _job().get("steps") or []
    assert steps, f"{_JOB} has no steps"
    return steps


def _runs() -> str:
    """Every command the job executes, as one string."""
    return "\n".join(str(step.get("run") or "") for step in _steps())


def test_the_job_that_migrates_a_database_also_runs_both_suites() -> None:
    commands = _runs()
    assert "alembic upgrade head" in commands, (
        "the PostgreSQL-only suites need a migrated database, and this job is "
        "where one exists"
    )
    for suite in _SUITES:
        assert f"tests/{suite}" in commands, (
            f"{suite} is not selected by any step of {_JOB}, so nothing runs it"
        )


def test_a_missing_database_fails_the_job_instead_of_skipping() -> None:
    """The step that runs the suites must forbid a skip, and check the report."""

    selecting = [
        step
        for step in _steps()
        if any(f"tests/{suite}" in str(step.get("run") or "") for suite in _SUITES)
    ]
    assert len(selecting) == 1, "expected exactly one step to select the suites"
    step = selecting[0]
    environment = step.get("env") or {}
    assert environment.get("REQUIRE_INTEGRATION") == "1", (
        "without REQUIRE_INTEGRATION=1 a job that lost its database reports the "
        "suites as skipped — the failure mode this file exists for"
    )
    assert environment.get("INTEGRATION_MIGRATION_DATABASE_URL"), (
        "the suites read INTEGRATION_MIGRATION_DATABASE_URL"
    )
    assert "--junitxml=" in str(step.get("run") or ""), (
        "the report is what the skip assertion below reads"
    )

    verifying = [
        str(other.get("run") or "")
        for other in _steps()
        if "check_integration_ran.py" in str(other.get("run") or "")
    ]
    assert any("postgres-only.xml" in command for command in verifying), (
        "no step verifies the report of the PostgreSQL-only suites, so a skip "
        "would still look like a pass"
    )


def test_the_skip_assertion_would_actually_reject_a_skipped_run(tmp_path: Path) -> None:
    """The report the wiring above feeds into: a skip has to fail it.

    Asserted by running the check against a report that contains one skip, so
    the pair (``--junitxml``, ``check_integration_ran.py``) is exercised as the
    pair CI runs rather than trusted as two halves that each look right.
    """

    import subprocess
    import sys

    # `backend/scripts/`, which is where CI runs it from (`python
    # scripts/check_integration_ran.py` with `backend/` as the working directory).
    script = _TESTS.parent / "scripts" / "check_integration_ran.py"
    assert script.is_file(), f"the integration gate script is missing: {script}"

    report = tmp_path / "postgres-only.xml"
    suite = ElementTree.Element("testsuite", {"name": "pytest"})
    passed = ElementTree.SubElement(suite, "testcase", {"classname": "t", "name": "passed"})
    ElementTree.SubElement(passed, "system-out")
    skipped = ElementTree.SubElement(suite, "testcase", {"classname": "t", "name": "skipped"})
    ElementTree.SubElement(skipped, "skipped", {"message": "dedicated database required"})
    ElementTree.ElementTree(suite).write(report, encoding="utf-8", xml_declaration=True)

    result = subprocess.run(
        [sys.executable, str(script), str(report), "--min-passed", "2"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1, (
        "a report with a skipped test must fail the gate; got "
        f"{result.returncode}: {result.stdout}{result.stderr}"
    )
    assert "skipped" in result.stdout


@pytest.mark.parametrize("suite", _SUITES)
def test_each_suite_is_marked_integration_and_refuses_a_silent_skip(suite: str) -> None:
    source = (_TESTS / suite).read_text(encoding="utf-8")
    assert re.search(r"pytestmark\s*=\s*pytest\.mark\.integration", source), (
        f"{suite} must be selected by `-m integration` and deselected by "
        "`-m 'not integration'`; without the marker the SQLite job runs it and "
        "the integration job skips it"
    )
    assert re.search(
        r'os\.environ\.get\(\s*"REQUIRE_INTEGRATION"\s*\)\s*==\s*"1"', source
    ), (
        f"{suite} must fail rather than skip when the job set "
        "REQUIRE_INTEGRATION=1 and the database is still missing"
    )
    assert "INTEGRATION_MIGRATION_DATABASE_URL" in source
