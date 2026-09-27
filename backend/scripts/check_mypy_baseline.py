"""Ratchet gate: mypy must never report more errors than the recorded baseline.

Purpose
-------
mypy is a declared dev dependency but was never enforced in CI. This gate pins
the *current* error count as a baseline so any change that adds type errors
fails CI, while existing errors only disappear as modules are refactored
(safe-refactoring plan, Step 0). Lower the number in ``MYPY_ERROR_BASELINE``
as errors get fixed; never raise it.

Baseline history (per-file counts, ``mypy app`` from ``backend/``):

* 0 (2026-09-12, security hardening: python-jose replaced with PyJWT and
  passlib replaced with direct bcrypt, so the jose.*/passlib.* mypy
  overrides were dropped from pyproject.toml; the rewritten
  core/security.py is fully annotated):
  (none — zero errors)
* 0 (2026-09-11, safe-refactoring plan Step 11: ALL type errors fixed.
  Config-level: stub-less third-party imports (celery, whois, dateutil,
  jose, passlib, fpdf) silenced via [tool.mypy] overrides in
  pyproject.toml. Code fixes: report_service KPI box-height var renamed
  (6 reuse errors), models/settings hybrid setters annotated with
  type-ignore[no-redef], schemas user/connector/asset narrowing,
  core/security passlib monkeypatch annotations, connector_service
  params dict-narrowing, alerts SMTP host/port narrowing, phishing
  router typed predicate list + no-arg and_(), connectors router
  params dict-narrowing + TypeAdapter annotation):
  (none — zero errors)
* 28 (2026-09-10, safe-refactoring plan Step 9: core/rate_limit.py errors
  fixed — pipeline commands queued as statements instead of chained on
  redis-py union types):
  report_service.py 7, models/settings.py 4, core/security.py 4,
  whois_service.py 2, connector_service.py 2, schemas/user.py 2,
  routers/connectors.py 2, routers/alerts.py 2,
  schemas/connector.py 1, schemas/asset.py 1, routers/phishing.py 1
* 33 (2026-09-10, safe-refactoring plan Step 6: audit.py errors fixed):
  report_service.py 7, models/settings.py 4, core/security.py 4,
  scheduler_tasks.py 2, whois_service.py 2,
  connector_service.py 2, schemas/user.py 2,
  core/rate_limit.py 2, routers/connectors.py 2, routers/alerts.py 2,
  schemas/connector.py 1, schemas/asset.py 1,
  core/celery_app.py 1, routers/phishing.py 1
* 36 (2026-09-10, safe-refactoring plan Steps 4-5: event_hooks.py and
  ingestion_service.py errors fixed):
  report_service.py 7, models/settings.py 4, core/security.py 4,
  audit.py 3, scheduler_tasks.py 2, whois_service.py 2,
  connector_service.py 2, schemas/user.py 2,
  core/rate_limit.py 2, routers/connectors.py 2, routers/alerts.py 2,
  schemas/connector.py 1, schemas/asset.py 1,
  core/celery_app.py 1, routers/phishing.py 1
* 39 (2026-09-10, safe-refactoring plan Step 3: auth.py errors fixed):
  report_service.py 7, models/settings.py 4, core/security.py 4,
  audit.py 3, scheduler_tasks.py 2, whois_service.py 2,
  ingestion_service.py 2, connector_service.py 2, schemas/user.py 2,
  core/rate_limit.py 2, routers/connectors.py 2, routers/alerts.py 2,
  event_hooks.py 1, schemas/connector.py 1, schemas/asset.py 1,
  core/celery_app.py 1, routers/phishing.py 1
* 47 (2026-09-10, safe-refactoring plan Step 2: job_service.py errors fixed):
  auth.py 8, report_service.py 7, models/settings.py 4, core/security.py 4,
  audit.py 3, scheduler_tasks.py 2, whois_service.py 2,
  ingestion_service.py 2, connector_service.py 2, schemas/user.py 2,
  core/rate_limit.py 2, routers/connectors.py 2, routers/alerts.py 2,
  event_hooks.py 1, schemas/connector.py 1, schemas/asset.py 1,
  core/celery_app.py 1, routers/phishing.py 1
* 49 (2026-09-10, safe-refactoring plan Step 1: users.py errors fixed):
  auth.py 8, report_service.py 7, models/settings.py 4, core/security.py 4,
  audit.py 3, scheduler_tasks.py 2, whois_service.py 2, job_service.py 2,
  ingestion_service.py 2, connector_service.py 2, schemas/user.py 2,
  core/rate_limit.py 2, routers/connectors.py 2, routers/alerts.py 2,
  event_hooks.py 1, schemas/connector.py 1, schemas/asset.py 1,
  core/celery_app.py 1, routers/phishing.py 1
* 53 (2026-09-10, initial baseline):
  auth.py 8, report_service.py 7, models/settings.py 4, core/security.py 4,
  users.py 4, audit.py 3, scheduler_tasks.py 2, whois_service.py 2,
  job_service.py 2, ingestion_service.py 2, connector_service.py 2,
  schemas/user.py 2, core/rate_limit.py 2, routers/connectors.py 2,
  routers/alerts.py 2, event_hooks.py 1, schemas/connector.py 1,
  schemas/asset.py 1, core/celery_app.py 1, routers/phishing.py 1

Usage
-----
    python scripts/check_mypy_baseline.py            # standard gate
    python scripts/check_mypy_baseline.py <args...>  # extra mypy args forwarded
"""

from __future__ import annotations

import re
import subprocess
import sys

MYPY_ERROR_BASELINE = 0

_SUMMARY_RE = re.compile(
    r"Found (?P<count>\d+) errors? in (?P<files>\d+) files? \(checked (?P<checked>\d+) source files?\)"
)
_SUCCESS_RE = re.compile(
    r"Success: no issues found in (?P<checked>\d+) source files?"
)


def _run_mypy(extra_args: list[str]) -> tuple[int | None, str]:
    proc = subprocess.run(
        ["mypy", "app", *extra_args],
        capture_output=True,
        text=True,
    )
    output = proc.stdout + proc.stderr
    match = _SUMMARY_RE.search(output)
    if match is None:
        # mypy exits cleanly with a Success line once the error count hits 0.
        if _SUCCESS_RE.search(output):
            return 0, output
        return None, output
    return int(match.group("count")), output


def main(argv: list[str]) -> int:
    count, output = _run_mypy(argv)

    if count is None:
        # No summary line: mypy crashed or misconfigured. Fail loudly instead
        # of silently passing the gate.
        print("mypy baseline gate: FAILED — no error summary found in mypy output")
        print(output.rstrip()[-2000:])
        return 2

    if count > MYPY_ERROR_BASELINE:
        print(
            f"mypy baseline gate: FAILED — {count} errors exceed baseline "
            f"{MYPY_ERROR_BASELINE}. Do not add type errors; fix the new ones."
        )
        for line in output.splitlines():
            if ": error:" in line:
                print(f"  {line}")
        return 1

    print(
        f"mypy baseline gate: OK — {count} errors (baseline {MYPY_ERROR_BASELINE}). "
        "Lower MYPY_ERROR_BASELINE in scripts/check_mypy_baseline.py as you fix errors."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
