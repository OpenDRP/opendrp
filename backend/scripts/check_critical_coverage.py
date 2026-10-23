"""Enforce per-module coverage thresholds for critical backend boundaries.

pytest-cov's ``--cov-fail-under`` applies to the combined report. This small
CI gate closes that loophole by reading the JSON report and checking every
required source file independently.

The runs measure the whole ``app`` package: ``--cov-args`` prints the one
``--cov=app`` flag CI and the Makefile substitute, instead of each carrying a
second copy of the flag list. It used to print one dotted ``--cov=app.<module>``
per gated module — the spelling `pytest-cov` documents — but resolving such a name
imports the module chain before ``conftest`` loads, and on the Windows development
venv that aborts the run inside ``bcrypt``
(``PyO3 modules … may only be initialized once per interpreter process``) before a
single test executes. Measuring the package costs nothing here and is stronger:
the report holds every file, so a module cannot be gated without being measured.
That missing-measurement failure — a job reporting a module absent while the
coverage it asked about was fine — is what the dotted list existed to prevent, and
the package flag prevents it by construction.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


# Keep thresholds explicit and reviewable. The aggregate gate remains in CI;
# these module gates prevent strong coverage in one module from hiding a weak
# security boundary in another.
THRESHOLDS: dict[str, float] = {
    "app/core/security.py": 75.0,
    "app/core/crypto.py": 75.0,
    # Batch 01 of the coverage program measured the request boundary after its
    # tests landed: `deps.py` at 99.5% (from 84.8%) and `auth.py` at 94.9% (from
    # 85.4%). These floors are the measured value minus three points, rounded
    # down to the whole percent the readiness table prints. The measurement is
    # the CI baseline's covered lines united with the batch's own runs, which is
    # exact for files the batch did not change; see
    # docs/exec-plans/006-coverage-program/batch-01-authentication-boundary.md.
    "app/api/v1/routers/auth.py": 91.0,
    "app/api/deps.py": 96.0,
    # Batch 02 measured the account surface at 94.3% (`users.py`) and 100%
    # (`schemas/settings.py`) on the suites that own them, up from 85.1% and
    # 81.6%. The floors are the measured value minus three points, rounded down:
    # 91 and 97. The lines still missing from `users.py` are unreachable through
    # the API (the bulk last-admin branch), unused (the `_count_active_admins`
    # wrapper), or storage failures the route re-raises; they are named in the
    # batch file rather than mocked.
    "app/api/v1/routers/users.py": 91.0,
    "app/schemas/settings.py": 97.0,
    # The connector/plugin boundary: untrusted registration declarations are
    # validated here, so a regression is a security regression.
    # Batch 03 measured these at 97.2% (manifest), 92.0% (service) and 94.1%
    # (schemas) on the connector suites; floors are measured minus three, rounded
    # down. See docs/exec-plans/006-coverage-program/batch-03-connector-boundary.md.
    "app/services/connector_manifest.py": 94.0,
    "app/services/connector_service.py": 89.0,
    "app/schemas/connector.py": 91.0,
    # Batch 05 measured the finding write path and the report snapshot at 96.99%
    # (ingestion: 419 of 432 statements — the page rounds it to 97.0) and 92.3%
    # (report); floors are measured minus three, rounded down, so 93.99 floors to
    # 93. That is why the ingestion floor sits a point below the displayed 97.0%:
    # 94 would be above what the rule allows, and the floor is never raised past
    # it to look tidier. The report service had no floor of its own until this
    # batch. See docs/exec-plans/006-coverage-program/batch-05-ingestion-and-reports.md.
    "app/services/ingestion_service.py": 93.0,
    "app/services/report_service.py": 89.0,
    # Batch 06 measured the certificate review path at 99.5% (the service) and
    # 100% (the router) on the TLS and DNS Security suites, from 85.3% and 76.8%.
    # These two modules are what an operator acts on when the platform says a
    # certificate of theirs is served somewhere else, so both floors are new and
    # set to measured minus three, rounded down. Two lines in the service stay
    # missing on purpose (a sighting whose identity row is gone, and the
    # address-less guard inside a group that R1 already filtered); both are named
    # in docs/exec-plans/006-coverage-program/batch-06-tls-and-dns.md.
    "app/services/tls_identity_service.py": 96.0,
    "app/api/v1/routers/dns_security.py": 97.0,
    # Credential issuance/resolution: a regression here would let one connector
    # authenticate as another, so it is gated like the rest of the boundary.
    "app/services/connector_credentials.py": 80.0,
    # Modules are declared data, so this is the validation boundary for what the
    # platform can collect and store. Batch 10 of the coverage program measured
    # it at 100% after the sweep, and disabling a module is now pinned to cancel
    # the work it had queued; the floor moves 70 → 97 (measured minus three).
    "app/services/module_registry.py": 97.0,
    # The third limiter: without it a single authenticated credential can drive
    # unbounded audit writes. A regression here is a availability regression.
    "app/core/request_rate_limit.py": 85.0,
    # Credential-carrying outbound delivery (SMTP, Telegram) and the probes an
    # operator trusts to tell a working channel from a broken one. Delivery has
    # exactly one path — the queue — so a regression here is a lost alert.
    # Batch 04 measured the alert path at 97.2% (service), 97.6% (delivery),
    # 100% (message) and 99.1% (health cache) on the suites that own them; floors
    # are measured minus three, rounded down. The message and health-cache floors
    # are new. See docs/exec-plans/006-coverage-program/batch-04-alerts-and-delivery.md.
    "app/services/alert_service.py": 94.0,
    "app/services/alert_delivery_service.py": 94.0,
    "app/services/alert_message.py": 97.0,
    "app/services/alert_health_cache.py": 96.0,
    "app/tasks/alert_tasks.py": 80.0,
    "app/api/v1/routers/alerts.py": 80.0,
    # Readiness decides whether an orchestrator keeps a replica in rotation, so
    # a silently always-healthy probe is a deployment-level failure.
    "app/core/health.py": 90.0,
    # Terminal report transitions; the deletion race fixed here is reported to
    # operators as a job failure, so the branch needs to stay covered.
    "app/tasks/report_tasks.py": 80.0,
    # WHOIS is an untrusted external API; its parsing/error branches must stay
    # covered because enrichment feeds the phishing findings.
    "app/services/phishing/whois_service.py": 80.0,
    # The next five were the gap the audit named: they sat outside every
    # per-module gate while the aggregate floor hid them, and each is a place
    # where a regression costs data or quota rather than a wrong pixel. The
    # matcher decides which asset a finding belongs to (and a bug there is a
    # finding attributed to the wrong customer), the scan admission decides how
    # much work a scan may start, the quota service decides how many provider
    # requests an account may spend, retention is the only code that deletes
    # history, and the integrity pass is what reads the audit chain.
    "app/services/asset_matching.py": 90.0,
    "app/services/scan_admission.py": 90.0,
    # Batch 07 of the coverage program measured the lifecycle code: retention at
    # 99.3%, the quota at 99.0%, the audit archive at 95.7% (locally; the six lines
    # it misses are a POSIX-only fsync block and two symlink refusals whose tests
    # skip on Windows) and `config.py` at 96.6%, which had no floor of its own
    # until this batch. Floors are measured minus three, rounded down. The few
    # lines each still misses are guards against state the validators refuse to
    # construct; they are named in
    # docs/exec-plans/006-coverage-program/batch-07-lifecycle-and-limits.md.
    "app/tasks/retention_tasks.py": 96.0,
    "app/services/provider_quota.py": 96.0,
    "app/services/audit_archive.py": 92.0,
    "app/core/config.py": 93.0,
    # Batch 08 of the coverage program measured the long tail: the connector
    # admin/protocol surface at 99.6%, the asset inventory at 99.6%, the phishing
    # router at 100%, the settings service at 98.7%, and the two task bodies that
    # executed no test before it (`user_tasks.py`, `integrity_tasks.py`) plus the
    # notification service at 100%. Floors are measured minus three, rounded
    # down, and every one of them is either new or raised — the integrity pass
    # was gated at 70 before its page had a suite. What each module still misses
    # is named in docs/exec-plans/006-coverage-program/batch-08-long-tail.md: a
    # findings-batch size check the wire schema makes unreachable, a bulk-selection
    # check behind the schema's own bound, a label guard pydantic coerces before
    # the validator sees it, and the PostgreSQL half of the settings upsert.
    "app/tasks/integrity_tasks.py": 97.0,
    "app/api/v1/routers/connectors.py": 96.0,
    "app/api/v1/routers/phishing.py": 97.0,
    "app/services/settings_service.py": 95.0,
    "app/api/v1/routers/assets.py": 96.0,
    "app/services/user_notifications.py": 97.0,
    "app/tasks/user_tasks.py": 97.0,
    # The boundaries this release adds. Each is a place where an untrusted input,
    # a secret or the platform's own record is handled: the scrape token gate and
    # the label shaping that keeps a request value out of a metric, the two halves
    # of the audit pair (one reads the chain, the other deletes history only after
    # the archive verifies — its floor moved to batch 07 above, which is why it is
    # not repeated here), the validator for provider observations and the write
    # path a declared module's findings arrive through, the outbox drain that
    # settles a claim over a network call, the provider-credential store, the
    # redaction every outbound message passes, and the resolution a connector's
    # stored identity depends on.
    "app/api/v1/routers/metrics.py": 90.0,
    "app/core/metrics.py": 85.0,
    "app/services/audit_verification.py": 90.0,
    "app/services/dns_security_service.py": 85.0,
    "app/services/source_observations.py": 90.0,
    "app/services/ingestion_events.py": 90.0,
    "app/services/alert_content.py": 80.0,
    "app/services/module_aliases.py": 90.0,
    # The candidate's score and the band it routes into (WI-08/WI-12, W1.7). Every
    # alert decision reads this number — the budget asks it what to send, the digest
    # asks it what to hold, and the list shows it as the reason a candidate is worth
    # a morning — so a regression here is a message an operator never got or a channel
    # that never stops, not a wrong pixel. Measured at 96% by the phishing tests alone
    # (158 statements), so 90 is a floor rather than a target; the gate exists to keep
    # a later change from quietly spending that margin.
    "app/services/phishing_score_service.py": 90.0,
    # The other half of that decision (W1.8): which values the budget routes by,
    # where each came from, and whether a stored row is allowed to be honoured at
    # all. A defect here does not produce a wrong number — it produces a threshold
    # nobody saved, or a contradictory row that is obeyed instead of refused, and
    # both read on the channel as "the platform got quieter today". Measured at 100%
    # by the alert-policy and phishing-digest suites (47 statements), so 95 is a
    # floor the module already clears on its own tests.
    "app/services/alert_policy.py": 95.0,
    # The breach triage and catalogue rules the list, the report and the dashboard read
    # (F-09, F-13, WI-16). Severity decides what an operator handles first, the KPI rule
    # decides what number two surfaces print for the same fact, and the catalogue diff is
    # what makes a new incident visible before an address is added. A regression in any
    # of them is a quieter platform or a number that disagrees with itself, not a wrong
    # pixel. Measured at 98%, 100% and 91% by their own suites, so these are floors.
    "app/services/breach_catalogue.py": 90.0,
    "app/services/breach_kpi.py": 95.0,
    "app/services/breach_severity.py": 85.0,
    # The invitation is a credential that never passes through the administrator
    # who creates the account (U-7): the token is issued here, only its digest is
    # stored, and spending it is what sets the first password. A regression either
    # mails a link that does not work or accepts one that should have expired, so
    # it is gated with the other issuers. Measured at 91% by
    # tests/test_user_invitations.py (46 statements), so 90 is a floor.
    "app/services/invitations.py": 90.0,
    # Batch 10 of the coverage program swept the modules batches 01–09 left under
    # fifteen missed statements each, taking the ones whose miss is a refusal or a
    # boundary: the destination policy (an address the platform declines to
    # connect to), the artifact store (a stored value it declines to serve), the
    # refusal camera, the provider-account service, the source-inventory routes,
    # and the jobs view. Each was measured on its own suite and is at 100% except
    # `artifact_path.py` at 95.2%, whose three remaining lines are a redundant
    # absolute-path check and the exception arm of an already-checked containment
    # test; floors are measured minus three, rounded down. Five are new and two
    # are raised (`module_registry.py` 70 → 97 above, `source_accounts.py`
    # 80 → 97 here, which is why its earlier entry is gone rather than repeated).
    # See docs/exec-plans/006-coverage-program/batch-10-boundary-sweep.md.
    "app/core/outbound.py": 97.0,
    "app/core/artifact_path.py": 92.0,
    "app/core/authorization_audit.py": 97.0,
    "app/services/source_accounts.py": 97.0,
    "app/api/v1/routers/source_inventory.py": 97.0,
    "app/api/v1/routers/jobs.py": 97.0,
}


def _normalized_files(report: dict) -> dict[str, dict]:
    files = report.get("files")
    if not isinstance(files, dict):
        raise ValueError("coverage report does not contain a 'files' object")
    return {
        str(Path(name).as_posix()).lstrip("./"): data
        for name, data in files.items()
        if isinstance(data, dict)
    }


def check_report(report_path: Path) -> list[str]:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    files = _normalized_files(report)
    failures: list[str] = []
    for module, threshold in THRESHOLDS.items():
        data = files.get(module)
        if data is None:
            failures.append(f"{module}: missing from coverage report")
            continue
        summary = data.get("summary")
        percent = summary.get("percent_covered") if isinstance(summary, dict) else None
        if not isinstance(percent, (int, float)):
            failures.append(f"{module}: missing percent_covered")
            continue
        if percent < threshold:
            failures.append(f"{module}: {percent:.2f}% < required {threshold:.2f}%")
    return failures


def main(argv: list[str]) -> int:
    if argv == ["--cov-args"]:
        # What a run needs to measure every module this gate checks: the package
        # they all live in. Printed for a shell to substitute, so the runs and this
        # gate cannot drift, and kept to one flag because a dotted
        # `--cov=app.<module>` resolves by import — on the Windows development venv
        # that import aborts inside `bcrypt`'s PyO3 init before `conftest` loads.
        # The report measured over `app` holds the same files, and every threshold
        # below is still read per file.
        print("--cov=app")
        return 0
    if len(argv) != 1:
        print(
            "usage: python scripts/check_critical_coverage.py [--cov-args] "
            "COVERAGE_JSON"
        )
        return 2
    report_path = Path(argv[0])
    if not report_path.is_file():
        print(f"critical coverage gate: FAILED — report not found: {report_path}")
        return 2
    try:
        failures = check_report(report_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"critical coverage gate: FAILED — cannot read report: {exc}")
        return 2
    if failures:
        print("critical coverage gate: FAILED")
        for failure in failures:
            print(f"  {failure}")
        return 1
    print("critical coverage gate: OK — all required modules meet thresholds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
