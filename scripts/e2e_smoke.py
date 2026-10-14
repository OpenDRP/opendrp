#!/usr/bin/env python3
"""The end-to-end smoke: does a finding travel the whole way, and is it accounted for?

Every other test in this repository stops at a boundary -- the suite covers the
core against a temporary database, the connector tests cover the SDK, the
frontend tests cover the SPA against a mocked API, and the Compose gates prove the
stack *parses*. None of them answers the question an operator actually asks
before a release: with the real installation running, does a scan become a
finding, does the finding reach the alert queue, and is the whole path in the
audit trail?

This script answers exactly that, against a **running stack**, through the
interfaces the platform documents:

1. the API is up and its dependencies answer (`/health`, `/ready`);
2. an administrator signs in with the operator API;
3. the asset the scan is for exists in the inventory;
4. an administrator provisions a connector and the connector receives its own
   credential -- the bootstrap every connector container does;
5. the alert channel is configured, so a finding has somewhere to go (and so the
   run does not silently pass on an installation where nothing is configured);
6. a scan is queued for that connector, the connector claims the work, submits
   one finding, and completes the job;
7. the finding is visible to the operator through the module's own listing;
8. the alert queue grew by that finding, read back from the platform's own
   metrics endpoint;
9. the audit trail carries the events that make each step attributable.

What this deliberately is not
-----------------------------

* **Not a connector test.** The "connector" here is this script speaking the
  documented work-poll protocol. That is what makes the journey deterministic: it
  asserts the *core's* hand-offs, and it does not depend on Shodan, HIBP, CT logs
  or any provider's uptime, quota or network path. The real connectors have their
  own suites and their own live checks.
* **Not a delivery test.** The SMTP sink is deliberately a name that does not
  resolve, because the property under test is that a finding *becomes a queued
  notification* without operator action -- not that an administrator's mail relay
  is reachable from here. Delivery, retries and recipient holds are covered by
  the alert reliability suite and by an operator's own channel test.
* **Not a browser test.** The SPA check is an HTTP check: the frontend serves the
  application shell, and the API path a browser uses answers through the reverse
  proxy the SPA is served behind. Rendering, keyboard flow and the HttpOnly
  session cookie in a real browser are not asserted here -- a `urllib` request
  cannot see them, and pretending otherwise would be the kind of green that says
  nothing.
* **Not an MFA test.** A deployment that requires a second factor for
  administrators is a posture this run does not change: `E2E_ADMIN_TOTP_SECRET`
  supplies that factor's codes when the account has one, and when the policy is
  what refuses the first read the run stops and says so rather than enrolling a
  factor on an account it would then leave the next run unable to sign in with.
  The second factor's own behaviour is covered by the authentication suite and
  the security page's tests.

Configuration (environment)
---------------------------

``E2E_BASE_URL``          API base URL. Default ``http://127.0.0.1:8000``.
``E2E_FRONTEND_URL``      Optional frontend origin; enables the SPA/proxy check.
``E2E_ADMIN_EMAIL``       Administrator to sign in as. Required.
``E2E_ADMIN_PASSWORD``    That administrator's password. Required.
``E2E_METRICS_TOKEN``     Value of the stack's ``METRICS_TOKEN``. Required: the
                          alert-queue assertion reads the metrics endpoint.
``E2E_ADMIN_TOTP_SECRET`` Base32 secret of that administrator's authenticator,
                          for a deployment (or an account) that already has a
                          second factor. Optional.
``E2E_MODULE``            Module to queue work for. Default ``phishing``.
``E2E_TIMEOUT_SECONDS``   Per-request timeout. Default 30.
``E2E_WORK_TIMEOUT``      How long to wait for the scan job. Default 90.
``E2E_ALERT_TIMEOUT``     How long to wait for the alert queue to grow. 120.

Exit code 0 means every step held; any failure prints the step, the response body
that disproved it and exits 1.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.request
import uuid

API = os.environ.get("E2E_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
FRONTEND = os.environ.get("E2E_FRONTEND_URL", "").rstrip("/")
ADMIN_EMAIL = os.environ.get("E2E_ADMIN_EMAIL", "")
ADMIN_PASSWORD = os.environ.get("E2E_ADMIN_PASSWORD", "")
METRICS_TOKEN = os.environ.get("E2E_METRICS_TOKEN", "")
TOTP_SECRET = os.environ.get("E2E_ADMIN_TOTP_SECRET", "")
MODULE = os.environ.get("E2E_MODULE", "phishing")
TIMEOUT = float(os.environ.get("E2E_TIMEOUT_SECONDS", "30"))
WORK_TIMEOUT = float(os.environ.get("E2E_WORK_TIMEOUT", "90"))
ALERT_TIMEOUT = float(os.environ.get("E2E_ALERT_TIMEOUT", "120"))

#: Where the smoke sends the alert an operator would normally receive. The name
#: is a reserved TLD that never resolves: the destination policy accepts it (it
#: cannot reach a blocked address), and the delivery attempt fails at the
#: resolver, which is the point -- this run asserts the queue, not the relay.
SMTP_HOST = os.environ.get("E2E_SMTP_HOST", "e2e-alerts.invalid")
SMTP_PORT = int(os.environ.get("E2E_SMTP_PORT", "1025"))

# A Windows console is often cp1251 or cp437, and a message copied out of a
# failing response can hold a character it cannot encode. A smoke test that dies
# with UnicodeEncodeError instead of printing what the API said is worse than a
# `?` in the output, so undecodable characters are replaced rather than raised.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(errors="replace")


class SmokeFailure(RuntimeError):
    """A step that did not hold, with the response that disproved it."""


class Client:
    """A tiny JSON client over the operator API and the connector protocol."""

    def __init__(self, base: str) -> None:
        self.base = base
        self.token: str | None = None

    def request(self, method, path, body=None, headers=None, token=None, timeout=None):
        payload = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(self.base + path, data=payload, method=method)
        request.add_header("Content-Type", "application/json")
        # Every request says where it came from, so the audit rows this run
        # produces can be told apart from an operator's own activity.
        request.add_header("User-Agent", "opendrp-e2e-smoke/1")
        for name, value in (headers or {}).items():
            request.add_header(name, value)
        bearer = token if token is not None else self.token
        if bearer:
            request.add_header("Authorization", f"Bearer {bearer}")
        try:
            with urllib.request.urlopen(request, timeout=timeout or TIMEOUT) as response:
                raw = response.read().decode("utf-8", "replace")
                return response.status, raw
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", "replace")

    def json(self, method, path, **kwargs):
        """One call that must succeed; returns the decoded body."""
        status, raw = self.request(method, path, **kwargs)
        if status >= 400:
            raise SmokeFailure(
                f"{method} {path} answered {status}: {raw[:500]}",
            )
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:  # pragma: no cover - a broken stack
            raise SmokeFailure(f"{method} {path} did not answer JSON: {raw[:200]}") from exc


def step(name: str) -> None:
    print(f"[e2e] {name}", flush=True)


def wait_for(describe: str, timeout: float, attempt, interval: float = 2.0):
    """Poll ``attempt`` until it returns a value, or fail with what we saw."""
    deadline = time.monotonic() + timeout
    while True:
        result = attempt()
        if result is not None:
            return result
        if time.monotonic() >= deadline:
            raise SmokeFailure(f"timed out after {timeout:.0f}s waiting for {describe}")
        time.sleep(interval)


def totp_code(secret: str) -> str:
    """The code an authenticator app shows for this secret, right now.

    Thirty-second steps and SHA-1, as RFC 6238 defines them for TOTP, computed
    here rather than taken from a dependency: the smoke runs with nothing but the
    standard library, so it can run from a runner, a container, or an operator's
    laptop without a second installation step.
    """
    key = base64.b32decode(secret.strip().upper() + "=" * (-len(secret.strip()) % 8))
    counter = int(time.time()) // 30
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{truncated % 1_000_000:06d}"


def sign_in(client: Client) -> None:
    """Sign in, with the second factor's code when the account has one.

    ``E2E_ADMIN_TOTP_SECRET`` is that account's authenticator secret. It is a
    parameter rather than something discovered here because a factor the smoke
    enrolled for itself would be a factor nobody else could answer -- every later
    run of the same smoke against the same stack would be locked out of its own
    administrator.
    """
    body: dict[str, str] = {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
    if TOTP_SECRET:
        body["totp_code"] = totp_code(TOTP_SECRET)
    status, raw = client.request("POST", "/api/v1/auth/login", body=body)
    if status >= 400:
        if "mfa" in raw.lower():
            raise SmokeFailure(
                f"{ADMIN_EMAIL} has a second factor enrolled, so the sign-in needs a "
                "code from it: set E2E_ADMIN_TOTP_SECRET to that factor's base32 "
                "secret, or run this against an account without one"
            )
        raise SmokeFailure(f"POST /api/v1/auth/login answered {status}: {raw[:300]}")
    session = json.loads(raw)
    client.token = session.get("access_token")
    if not client.token:
        raise SmokeFailure(f"login returned no access_token: {str(session)[:200]}")


def gated(client: Client, method: str, path: str, **kwargs):
    """A call behind the credential gates, with the refusals named.

    Three refusals are worth their own message rather than a status code: a
    deployment that wants a second factor, an account that still owes a password
    change, and a deployment whose metrics token this run does not know.
    """
    status, raw = client.request(method, path, **kwargs)
    if status >= 400 and "mfa_required" in raw:
        raise SmokeFailure(
            "this deployment requires a second factor for administrators, and "
            f"{ADMIN_EMAIL} has none: set E2E_ADMIN_TOTP_SECRET to that factor's "
            "base32 secret and re-run, or turn the policy off for this stack "
            "(REQUIRE_MFA_FOR_ADMINS=false in its .env)"
        )
    if status >= 400 and "onboarding_required" in raw:
        raise SmokeFailure(
            f"{ADMIN_EMAIL} still owes a credential step: {raw[:200]}\n"
            "clear it with: docker compose exec backend python -m scripts.manage_admin "
            f"onboarding-off -e {ADMIN_EMAIL}"
        )
    if status >= 400:
        raise SmokeFailure(f"{method} {path} answered {status}: {raw[:500]}")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:  # pragma: no cover - a broken stack
        raise SmokeFailure(f"{method} {path} did not answer JSON: {raw[:200]}") from exc


def alert_deliveries(client: Client) -> int:
    """The alert queue's total size, as the platform reports it to a scraper."""
    status, raw = client.request(
        "GET",
        "/api/v1/metrics",
        headers={"X-Metrics-Token": METRICS_TOKEN},
        token="",
    )
    if status != 200:
        raise SmokeFailure(
            f"GET /api/v1/metrics answered {status}: {raw[:200]} -- "
            "E2E_METRICS_TOKEN must match the stack's METRICS_TOKEN",
        )
    total = 0
    for line in raw.splitlines():
        if line.startswith("opendrp_alert_deliveries{"):
            total += int(float(line.rsplit(" ", 1)[1]))
    return total


def main() -> int:  # noqa: C901 - a journey, read top to bottom
    missing = [
        name
        for name, value in (
            ("E2E_ADMIN_EMAIL", ADMIN_EMAIL),
            ("E2E_ADMIN_PASSWORD", ADMIN_PASSWORD),
            ("E2E_METRICS_TOKEN", METRICS_TOKEN),
        )
        if not value
    ]
    if missing:
        print(
            "missing required environment: " + ", ".join(missing) + "\n"
            "see the module docstring for what each one is for",
            file=sys.stderr,
        )
        return 2

    client = Client(API)
    # Unique per run, so every assertion below can name this run's own data and a
    # red run cannot be satisfied by a previous one's leftovers.
    run = uuid.uuid4().hex[:8]
    asset_value = f"e2e-{run}.example"
    connector_name = f"e2e-smoke-{run}"
    phishing_domain = f"e2e-login-{run}.example"

    try:
        step("the API and its dependencies answer")
        health = client.json("GET", "/api/v1/health")
        if health.get("status") != "ok":
            raise SmokeFailure(f"/health is not ok: {health}")
        ready = client.json("GET", "/api/v1/ready")
        if ready.get("status") != "ready":
            raise SmokeFailure(f"/ready is not ready: {ready}")
        print(f"      version {health.get('version')}, checks {ready.get('checks')}")

        step("an administrator signs in")
        sign_in(client)

        step(f"the '{MODULE}' module is enabled")
        modules = gated(client, "GET", "/api/v1/modules")
        declared = {item["id"]: item for item in modules.get("modules", [])}
        module = declared.get(MODULE)
        if module is None:
            raise SmokeFailure(
                f"module '{MODULE}' is not declared; declared: {sorted(declared)}",
            )
        if not module.get("enabled", True):
            raise SmokeFailure(
                f"module '{MODULE}' is declared but disabled; enable it in Settings",
            )

        step(f"the asset the finding is attributed to exists ({asset_value})")
        asset = client.json(
            "POST",
            "/api/v1/assets",
            body={"asset_type": "domain", "asset_value": asset_value, "criticality": "high"},
        )
        asset_id = asset.get("id")
        if not asset_id:
            raise SmokeFailure(f"asset creation returned no id: {asset}")

        step(f"the alert channel is configured (email  ->  {SMTP_HOST}:{SMTP_PORT})")
        settings = client.json("GET", "/api/v1/settings")
        if not settings.get("email_alerts_enabled"):
            client.json(
                "PUT",
                "/api/v1/settings",
                body={
                    "email_alerts_enabled": True,
                    "smtp_host": SMTP_HOST,
                    "smtp_port": SMTP_PORT,
                    "smtp_security_mode": "plain",
                    "smtp_from_email": settings.get("smtp_from_email") or ADMIN_EMAIL,
                    "alert_recipient_email": settings.get("alert_recipient_email") or ADMIN_EMAIL,
                    "expected_version": settings.get("version"),
                },
            )
            reconfigured = True
        else:
            # An installation that already alerts somewhere keeps its channel: the
            # smoke asserts the queue, and switching an operator's channel is not
            # something a smoke test may do.
            reconfigured = False
        print(f"      {'configured here' if reconfigured else 'already configured'}")

        step(f"a connector is provisioned ({connector_name})")
        provisioned = client.json(
            "POST",
            "/api/v1/connectors/provision",
            body={"name": connector_name, "connector_type": MODULE},
        )
        connector_token = provisioned.get("token")
        if not connector_token:
            raise SmokeFailure(f"provision returned no token: {provisioned}")

        step("the connector reports in (the heartbeat an online worker sends)")
        client.json(
            "POST",
            "/api/v1/connectors/me/heartbeat",
            body={},
            headers={"X-Connector-Token": connector_token},
            token="",
        )

        step("before the scan: how large the alert queue is")
        deliveries_before = alert_deliveries(client)
        print(f"      alert_deliveries total = {deliveries_before}")

        step("a scan is queued for the module")
        scan = client.json("POST", f"/api/v1/modules/{MODULE}/scan")
        job_ids = scan.get("job_ids") or []
        if not job_ids:
            raise SmokeFailure(f"the scan queued no job: {scan}")
        print(f"      queued {len(job_ids)} job(s), sources {scan.get('sources')}")

        step("the connector claims the work")
        work = wait_for(
            "the connector to be given a job",
            WORK_TIMEOUT,
            lambda: _claim(client, connector_token),
        )
        job_id = work["job_id"]
        lease = work["lease_token"]
        print(f"      job {job_id}, type {work.get('job_type')}, lease {lease[:6]}...")

        step("the connector submits one finding")
        result = client.json(
            "POST",
            f"/api/v1/connectors/me/findings/{job_id}",
            body=[
                {
                    "phishing_domain": phishing_domain,
                    "matched_asset": asset_value,
                    "detection_source": connector_name,
                    "original_domain": asset_value,
                }
            ],
            headers={"X-Connector-Token": connector_token, "X-Connector-Lease": lease},
            token="",
        )
        if int(result.get("accepted") or 0) < 1:
            raise SmokeFailure(f"the finding was not accepted: {result}")
        print(f"      accepted {result.get('accepted')}, rejected {result.get('rejected')}")

        step("the connector completes the job")
        completed = client.json(
            "POST",
            f"/api/v1/connectors/me/complete/{job_id}",
            body={"ok": True, "lease_token": lease, "summary": {"findings": 1}},
            headers={"X-Connector-Token": connector_token},
            token="",
        )
        if completed.get("status") not in {"success", "partial"}:
            raise SmokeFailure(f"the job did not finish cleanly: {completed}")
        print(f"      job status {completed.get('status')}")

        step("the operator can see the finding")
        threats = wait_for(
            "the finding to reach the module's listing",
            WORK_TIMEOUT,
            lambda: _finding(client, phishing_domain),
        )
        print(f"      phishing threats total = {threats}")

        step("a notification for it is queued for delivery")
        deliveries_after = wait_for(
            "the alert queue to grow",
            ALERT_TIMEOUT,
            lambda: _growth(client, deliveries_before),
        )
        print(f"      alert_deliveries total = {deliveries_after} (+{deliveries_after - deliveries_before})")

        step("the audit trail attributes every step")
        for action, needle in (
            ("asset.create", asset_value),
            ("source.scan.queued", MODULE),
            ("connector.token.issued", connector_name),
            ("connector.findings.ingested", connector_name),
        ):
            rows = client.json(
                "GET", f"/api/v1/audit/logs?action={action}&size=20"
            ).get("items", [])
            if not any(needle in json.dumps(row) for row in rows):
                raise SmokeFailure(
                    f"no '{action}' entry for {needle!r} in the audit trail "
                    f"({len(rows)} row(s) for that action)",
                )
            print(f"      {action}: recorded")

        if FRONTEND:
            step("the frontend serves the SPA and proxies the API")
            request = urllib.request.Request(FRONTEND + "/")
            try:
                with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
                    html = response.read().decode("utf-8", "replace")
                    status = response.status
            except urllib.error.HTTPError as exc:
                status, html = exc.code, exc.read().decode("utf-8", "replace")
            if status != 200 or 'id="root"' not in html:
                raise SmokeFailure(f"the SPA shell was not served: HTTP {status}")
            # The same request a browser makes: the SPA talks to the API through
            # the reverse proxy, so a proxy that drops the API is a broken
            # installation even when the API answers directly.
            Client(FRONTEND).json(
                "POST",
                "/api/v1/auth/login",
                body={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
            )
            print("      SPA shell served, /api/v1/auth/login answered through the proxy")

    except SmokeFailure as failure:
        print(f"\n[e2e] FAILED: {failure}", file=sys.stderr)
        return 1

    print("\n[e2e] PASSED: scan  ->  finding  ->  alert queue  ->  audit trail")
    return 0


def _claim(client: Client, connector_token: str) -> dict | None:
    """Claim one job, or ``None`` when the queue has nothing for this connector."""
    status, raw = client.request(
        "GET",
        "/api/v1/connectors/me/work",
        headers={"X-Connector-Token": connector_token},
        token="",
    )
    if status == 204:
        return None
    if status >= 400:
        raise SmokeFailure(f"claiming work answered {status}: {raw[:300]}")
    return json.loads(raw)


def _finding(client: Client, phishing_domain: str) -> int | None:
    listing = client.json("GET", "/api/v1/phishing/threats?size=50")
    if any(row.get("phishing_domain") == phishing_domain for row in listing.get("items", [])):
        return int(listing.get("total") or 0)
    return None


def _growth(client: Client, before: int) -> int | None:
    now = alert_deliveries(client)
    return now if now > before else None


if __name__ == "__main__":
    raise SystemExit(main())
