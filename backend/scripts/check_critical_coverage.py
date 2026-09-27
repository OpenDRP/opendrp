"""Enforce per-module coverage thresholds for critical backend boundaries.

pytest-cov's ``--cov-fail-under`` applies to the combined report. This small
CI gate closes that loophole by reading the JSON report and checking every
required source file independently.
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
    if len(argv) != 1:
        print("usage: python scripts/check_critical_coverage.py COVERAGE_JSON")
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
