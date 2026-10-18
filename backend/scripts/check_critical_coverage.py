"""Enforce per-module coverage thresholds for critical backend boundaries.

pytest-cov's ``--cov-fail-under`` applies to the combined report. This small
CI gate closes that loophole by reading the JSON report and checking every
required source file independently.

The module list is also the list the runs measure: ``--cov-args`` prints the
``--cov=`` flags for `THRESHOLDS`, and CI and the Makefile call it instead of
carrying a second copy. Two lists drift, and the way this gate fails when they
do is the worst kind — the report holds no entry for a module the gate names,
so the job reports a missing measurement while the coverage it asked about was
fine. A release shipped exactly that, and the second and third copies are gone:
adding a module here now measures it as well.
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
    "app/api/deps.py": 75.0,
    # The connector/plugin boundary: untrusted registration declarations are
    # validated here, so a regression is a security regression.
    "app/services/connector_manifest.py": 70.0,
    "app/services/connector_service.py": 70.0,
    "app/services/ingestion_service.py": 70.0,
    # Credential issuance/resolution: a regression here would let one connector
    # authenticate as another, so it is gated like the rest of the boundary.
    "app/services/connector_credentials.py": 80.0,
    # Modules are declared data, so this is the validation boundary for what the
    # platform can collect and store.
    "app/services/module_registry.py": 70.0,
    # The third limiter: without it a single authenticated credential can drive
    # unbounded audit writes. A regression here is a availability regression.
    "app/core/request_rate_limit.py": 85.0,
    # Credential-carrying outbound delivery (SMTP, Telegram) and the probes an
    # operator trusts to tell a working channel from a broken one. Delivery has
    # exactly one path — the queue — so a regression here is a lost alert.
    "app/services/alert_service.py": 70.0,
    "app/services/alert_delivery_service.py": 70.0,
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
    "app/tasks/retention_tasks.py": 80.0,
    "app/services/provider_quota.py": 75.0,
    "app/tasks/integrity_tasks.py": 70.0,
    # The boundaries this release adds. Each is a place where an untrusted input,
    # a secret or the platform's own record is handled: the scrape token gate and
    # the label shaping that keeps a request value out of a metric, the two halves
    # of the audit pair (one reads the chain, the other deletes history only after
    # the archive verifies), the validator for provider observations and the write
    # path a declared module's findings arrive through, the outbox drain that
    # settles a claim over a network call, the provider-credential store, the
    # redaction every outbound message passes, and the resolution a connector's
    # stored identity depends on.
    "app/api/v1/routers/metrics.py": 90.0,
    "app/core/metrics.py": 85.0,
    "app/services/audit_verification.py": 90.0,
    "app/services/audit_archive.py": 75.0,
    "app/services/dns_security_service.py": 85.0,
    "app/services/source_observations.py": 90.0,
    "app/services/ingestion_events.py": 90.0,
    "app/services/source_accounts.py": 80.0,
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
        # What a run needs to measure every module this gate checks. Printed for
        # a shell to substitute, so the flags stay in one place. Dotted module
        # names, which is the spelling `pytest-cov` documents, not the file path
        # `THRESHOLDS` is keyed by.
        print(
            " ".join(
                "--cov=" + module.removesuffix(".py").replace("/", ".")
                for module in THRESHOLDS
            )
        )
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
