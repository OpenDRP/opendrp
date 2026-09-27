"""OpenDRP Connector SDK.

Shared base class every connector container runs. Implements the core-side
protocol (OpenCTI-style pull model):

1. ``register``   — announce itself to the platform core on startup and
                    periodically (self-healing after core DB resets).
2. poll for work  — ``GET /connectors/me/work``; atomically claims one
                    pending scan job or receives 204.
3. ``run_scan``   — connector-specific logic (implemented by subclasses).
4. submit findings — batches posted to ``POST /connectors/me/findings/{job}``
                     as the scan progresses (small batches = smooth progress).
5. ``complete``   — report success/failure with a JSON summary.

Environment variables:
    CORE_URL            base URL of the platform core (required)
    CONNECTOR_TOKEN     this connector's own credential, issued by an operator
                        on the core (required — see below)
    CONNECTOR_NAME      registration name (required)
    CONNECTOR_TYPE      module this connector feeds, e.g. "phishing" (required)
    CONNECTOR_API_VERSION  optional, defaults to SDK version
    POLL_INTERVAL_SEC   work-poll interval when idle (default 5)
    RECONNECT_BACKOFF_MAX_SEC  max backoff when core is unreachable (default 60)
    CONNECTOR_LIVENESS_FILE  file the runtime touches while alive, read by the
                        container HEALTHCHECK (default: ``opendrp-connector-alive``
                        in the platform's temporary directory; set it to an empty
                        string to disable the watchdog)

Manifest variables (self-declaration — see ``manifest_payload``):
    CONNECTOR_JOB_TYPE      scan job type this connector alone claims
                            (default ``<module>.<name>``)
    CONNECTOR_FINDING_KIND  finding schema its submissions validate as
                            (default: the module's kind)
    CONNECTOR_ASSET_TYPES   comma-separated asset inventory sections it
                            consumes, e.g. "domain,email_account"
    CONNECTOR_CONFIG_SCHEMA JSON object of operator-editable settings, e.g.
                            ``{"scan_ssl": {"type": "bool", "default": true}}``

Declaring the manifest is what makes a connector plug-and-play: the core
stores it, validates submissions against it, and renders the operator's config
form from it, so adding a data source needs no core or frontend change.

Credentials are per connector and issued *before* the container first runs:

    docker compose exec backend python -m scripts.manage_connector_tokens issue <name> --type <module> --env CONNECTOR_TOKEN

Identity comes from the token, so there is no platform-wide secret and one
connector can never poll, report or submit as another. A rejected credential is
therefore fatal rather than retryable — ``run_forever`` raises
``ConnectorCredentialError`` and exits, because only an operator can issue a
replacement token.

Any other ``<UPPERCASE>_`` variables are connector-specific and exposed via
``self.env``. Name them after the connector (``SHODAN_API_KEY``,
``SHODAN_SCAN_SSL_TEXT``): ``.env`` is one namespace shared by every service in
the Compose file set, so an unprefixed name is a collision waiting for the
second connector that wants the same word. `scripts/check_env_template.py`
enforces this for anything documented in ``.env.example``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import signal
import sys
import tempfile
import time
import uuid
from typing import Any

import httpx
import structlog

log = structlog.get_logger()


def configure_connector_logging() -> None:
    """Emit connector logs as one JSON object per line, like the core's.

    Without this the SDK renders ``key=value`` through structlog's development
    renderer, so a log pipeline receives one shape from the core and a different
    one from every connector: the fields an operator wants to filter on (job id,
    level, connector name) are not parseable fields, they are text.

    Called from :meth:`ConnectorBase.main` rather than at import: a library that
    reconfigures the process's logging as a side effect of being imported is a
    trap for whoever embeds it — including this repository's own test suite,
    which imports the SDK into the same process as the core.

    ``CONNECTOR_LOG_LEVEL`` (default ``INFO``) is the only knob; ``getattr``
    falls back to INFO so an unrecognised value cannot silence a connector.
    """
    level = getattr(logging, os.environ.get("CONNECTOR_LOG_LEVEL", "INFO").upper(), logging.INFO)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer(ensure_ascii=False),
        ],
        # A bound wrapper that drops below-level events in-process: there is no
        # stdlib logger underneath to do it, because PrintLogger writes straight
        # to stdout and needs no handler and no level arithmetic to be correct.
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

SDK_VERSION = "1.2.0"

#: Default liveness file. Lives on the connector's tmpfs, so it costs no disk
#: and always starts absent after a container restart. The directory is asked
#: for rather than spelled out: the connector images set
#: ``CONNECTOR_LIVENESS_FILE`` explicitly, so this is only the fallback for a
#: process started outside them, and a spelled-out ``/tmp`` would be the wrong
#: answer on any host that moved its temporary directory.
_DEFAULT_LIVENESS_FILE = os.path.join(tempfile.gettempdir(), "opendrp-connector-alive")

_REQUIRED_ENV = ("CORE_URL", "CONNECTOR_TOKEN", "CONNECTOR_NAME", "CONNECTOR_TYPE")
_MODULE_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


class ConnectorAPIError(RuntimeError):
    def __init__(self, status_code: int, detail: str, retry_after: float | None = None):
        super().__init__(f"core API error {status_code}: {detail[:300]}")
        self.status_code = status_code
        self.retry_after = retry_after


class ConnectorCredentialError(RuntimeError):
    """The core refused this connector's credential (401/403).

    Fatal by design: the credential *is* the connector's identity, so no amount
    of retrying or re-registering can fix a revoked, rotated or never-issued
    token — only an operator issuing a new one can.
    """

    def __init__(self, status_code: int, connector_name: str):
        super().__init__(
            f"the core rejected the credential for '{connector_name}' "
            f"(HTTP {status_code}). Issue a new token on the core "
            f"(`python -m scripts.manage_connector_tokens rotate "
            f"{connector_name}`), set CONNECTOR_TOKEN for this container, and "
            f"recreate it: a restart is not enough, because a container keeps "
            f"the environment it was created with."
        )
        self.status_code = status_code


class ConnectorBase:
    """Base class / runtime for OpenDRP connectors."""

    #: Subclasses may pre-load expensive state here (e.g. binaries).
    def __init__(self) -> None:
        missing = [k for k in _REQUIRED_ENV if not os.environ.get(k)]
        if missing:
            raise RuntimeError(
                f"Missing required environment variables: {', '.join(missing)}"
            )
        self.core_url = os.environ["CORE_URL"].rstrip("/")
        self.token = os.environ["CONNECTOR_TOKEN"].strip()
        self.name = os.environ["CONNECTOR_NAME"].strip().lower()
        self.connector_type = os.environ["CONNECTOR_TYPE"].strip().lower()
        # The module set is core-owned data (a module exists once the core can
        # persist its findings), so the SDK validates the *shape* of the value
        # and lets the core reject an unknown module with a clear message.
        if not _MODULE_RE.match(self.connector_type):
            raise RuntimeError(
                "CONNECTOR_TYPE must be a lowercase module identifier, "
                f"got {self.connector_type!r}"
            )
        self.api_version = os.environ.get("CONNECTOR_API_VERSION", SDK_VERSION)
        self.poll_interval = float(os.environ.get("POLL_INTERVAL_SEC", "5"))
        self.backoff_max = float(os.environ.get("RECONNECT_BACKOFF_MAX_SEC", "60"))

        # Connector-specific env (everything not consumed by the SDK).
        _sdk_keys = {
            "CORE_URL",
            "CONNECTOR_TOKEN",
            "CONNECTOR_NAME",
            "CONNECTOR_TYPE",
            "CONNECTOR_API_VERSION",
            "POLL_INTERVAL_SEC",
            "RECONNECT_BACKOFF_MAX_SEC",
            "CONNECTOR_JOB_TYPE",
            "CONNECTOR_FINDING_KIND",
            "CONNECTOR_ASSET_TYPES",
            "CONNECTOR_CONFIG_SCHEMA",
        }
        self.env: dict[str, str] = {
            k: v for k, v in os.environ.items() if k.isupper() and k not in _sdk_keys
        }

        self._stop = asyncio.Event()
        self._client: httpx.AsyncClient | None = None
        #: ``(job_id, lease_token)`` of the scan being executed. The token is
        #: part of the claim, never absent: every job-scoped call proves it.
        self._active_job: tuple[str, str] | None = None
        #: The declaration this connector registers with, validated once here so
        #: a missing job type fails at start-up instead of restart-looping
        #: against the core.
        self.manifest: dict[str, Any] = self.manifest_payload()

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "X-Connector-Token": self.token,
            "X-Connector-Name": self.name,
            "User-Agent": f"OpenDRP-Connector/{self.api_version}",
        }

    def _client_session(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.core_url,
                timeout=httpx.Timeout(35.0, connect=10.0),
                headers=self._headers(),
            )
        return self._client

    async def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        client = self._client_session()
        # One id per outbound call, sent as ``X-Request-ID``. The core records it
        # in the audit row for anything this call causes, so a job an operator
        # sees in the UI can be traced into the connector's own log even when the
        # connector and the core are on different hosts. Prefixed with the
        # connector name because the core's logs are where the two streams meet.
        request_headers = dict(kwargs.pop("headers", None) or {})
        request_headers.setdefault(
            "X-Request-ID", f"conn-{self.name}-{uuid.uuid4().hex[:16]}"
        )
        try:
            resp = await client.request(
                method, path, headers=request_headers, **kwargs
            )
        except httpx.HTTPError as exc:
            raise ConnectorAPIError(0, f"network: {type(exc).__name__}") from exc
        if resp.status_code >= 400:
            detail = resp.text[:300]
            retry_after = None
            raw_retry_after = resp.headers.get("Retry-After")
            if raw_retry_after:
                try:
                    retry_after = max(0.0, float(raw_retry_after))
                except ValueError:
                    retry_after = None
            raise ConnectorAPIError(resp.status_code, detail, retry_after=retry_after)
        return resp

    async def _request_with_retry(self, method: str, path: str, **kwargs) -> httpx.Response:
        """Retry only transient core transport failures.

        Findings ingestion is idempotent in the core (the finding's dedup key is
        unique), and completion is a safe terminal update. Retrying these two
        operations closes the common failure window where the core commits the
        request but the connector times out before receiving its response. Never
        retry authentication or validation errors: those are deterministic and
        a retry would only amplify load.
        """
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                return await self._request(method, path, **kwargs)
            except ConnectorAPIError as exc:
                transient = exc.status_code == 0 or exc.status_code in {408, 425, 429} or exc.status_code >= 500
                if not transient or attempt == max_attempts - 1:
                    raise
                delay = min(4.0, 2 ** attempt)
                retry_after = getattr(exc, "retry_after", None)
                if retry_after is not None:
                    delay = min(30.0, max(0.0, float(retry_after)))
                log.warning(
                    "connector_core_request_retry",
                    method=method,
                    path=path,
                    status=exc.status_code,
                    attempt=attempt + 1,
                    delay=delay,
                )
                await asyncio.sleep(delay)
        raise AssertionError("unreachable")

    # ------------------------------------------------------------------
    # Protocol operations
    # ------------------------------------------------------------------

    def manifest_payload(self) -> dict[str, Any]:
        """Self-declaration sent with registration.

        The job type is mandatory: it is what the core hands work out by, and a
        connector that declares none could claim nothing. The SDK refuses to
        start rather than registering a partly-described worker. The remaining
        keys are optional and default from the module's own record.
        """
        payload: dict[str, Any] = {}
        job_type = (os.environ.get("CONNECTOR_JOB_TYPE") or "").strip()
        if not job_type:
            raise RuntimeError(
                "CONNECTOR_JOB_TYPE is required: declare the namespaced scan job "
                "type this connector alone claims, e.g. 'phishing.dnstwist'"
            )
        payload["default_job_type"] = job_type
        finding_kind = (os.environ.get("CONNECTOR_FINDING_KIND") or "").strip()
        if finding_kind:
            payload["finding_kind"] = finding_kind
        asset_types = [
            item.strip()
            for item in (os.environ.get("CONNECTOR_ASSET_TYPES") or "").split(",")
            if item.strip()
        ]
        if asset_types:
            payload["asset_types"] = asset_types
        raw_schema = (os.environ.get("CONNECTOR_CONFIG_SCHEMA") or "").strip()
        if raw_schema:
            try:
                parsed = json.loads(raw_schema)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"CONNECTOR_CONFIG_SCHEMA is not valid JSON: {exc}"
                ) from exc
            if not isinstance(parsed, dict):
                raise RuntimeError("CONNECTOR_CONFIG_SCHEMA must be a JSON object")
            payload["config_schema"] = parsed
        return payload

    async def register(self) -> None:
        payload = {
            "name": self.name,
            "connector_type": self.connector_type,
            "api_version": self.api_version,
            "info": {
                "version": self.api_version,
                "python": sys.version.split()[0],
                "hostname": os.uname().nodename if hasattr(os, "uname") else "container",
                "platform": sys.platform,
            },
            **self.manifest,
        }
        await self._request("POST", "/api/v1/connectors/register", json=payload)
        log.info(
            "connector_registered",
            name=self.name,
            type=self.connector_type,
            job_type=payload.get("default_job_type"),
        )

    async def poll_work(self) -> dict[str, Any] | None:
        """Claim one scan job; returns the work payload or None (204)."""
        resp = await self._request("GET", "/api/v1/connectors/me/work")
        if resp.status_code == 204 or not resp.content:
            return None
        payload = resp.json()
        lease_token = str(payload.get("lease_token") or "")
        if not lease_token:
            raise ConnectorAPIError(
                0,
                "core returned a job without a lease token; refusing to run "
                "work it could not have claimed",
            )
        self._active_job = (str(payload.get("job_id")), lease_token)
        return payload

    def _lease_for(self, job_id: str) -> str:
        """The lease token for ``job_id``, or a protocol error.

        Every job-scoped call carries it. A connector that never polled for the
        job has no claim to act on, and one whose lease expired is refused by
        the core with 403 — both fail here, before a request is sent.
        """
        job, lease_token = self._active_job or ("", "")
        if not lease_token or job != job_id:
            raise ConnectorAPIError(
                0,
                f"no active lease for job {job_id}; poll for work before reporting on it",
            )
        return lease_token

    async def submit_findings(self, job_id: str, findings: list[dict]) -> dict:
        if not findings:
            return {"accepted": 0, "rejected": 0}
        resp = await self._request_with_retry(
            "POST",
            f"/api/v1/connectors/me/findings/{job_id}",
            headers={"X-Connector-Lease": self._lease_for(job_id)},
            json=findings,
        )
        return resp.json()

    async def complete(self, job_id: str, summary: dict) -> None:
        await self._request_with_retry(
            "POST",
            f"/api/v1/connectors/me/complete/{job_id}",
            json={
                "ok": True,
                "summary": summary,
                "lease_token": self._lease_for(job_id),
            },
        )
        self._active_job = None

    async def report_failure(self, job_id: str, error: str) -> None:
        try:
            lease_token = self._lease_for(job_id)
        except ConnectorAPIError as exc:
            log.error("connector_failure_report_unowned", job_id=job_id, err=str(exc)[:200])
            return
        try:
            await self._request(
                "POST",
                f"/api/v1/connectors/me/complete/{job_id}",
                json={"ok": False, "error": error[:4000], "lease_token": lease_token},
            )
        except Exception as exc:
            log.error("connector_failure_report_failed", job_id=job_id, err=str(exc)[:200])

    async def heartbeat(self) -> None:
        """Report liveness. Idle heartbeats are bare: no job, no lease.

        A job heartbeat renews that job's lease and therefore always carries its
        token, which is what the core requires before it moves the expiry.
        """
        active = self._active_job
        payload: dict[str, Any] = (
            {"job_id": active[0], "lease_token": active[1]} if active else {}
        )
        await self._request("POST", "/api/v1/connectors/me/heartbeat", json=payload)

    async def _job_heartbeat_loop(self, job_id: str, lease_token: str) -> None:
        """Renew an active job lease without waiting for provider work to finish."""
        interval = max(5.0, min(30.0, float(os.environ.get("JOB_HEARTBEAT_INTERVAL_SEC", "15"))))
        while self._active_job and self._active_job[0] == job_id and not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval)
            except asyncio.TimeoutError:
                try:
                    await self._request(
                        "POST",
                        "/api/v1/connectors/me/heartbeat",
                        json={"job_id": job_id, "lease_token": lease_token},
                    )
                except Exception as exc:
                    log.warning("connector_job_heartbeat_failed", job_id=job_id, err=str(exc)[:200])

    # ------------------------------------------------------------------
    # Hook for subclasses — the actual scan
    # ------------------------------------------------------------------

    async def run_scan(self, work: dict[str, Any]) -> tuple[list[dict], dict]:
        """Execute one scan.

        Returns ``(findings, summary)``. Subclasses should submit findings in
        batches themselves via ``submit_findings`` for large result sets and
        return only what remains unsubmitted, OR return everything here and
        let the runtime submit — both are supported.
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Runtime loop
    # ------------------------------------------------------------------

    async def _execute_job(self, work: dict[str, Any]) -> None:
        job_id = str(work.get("job_id"))
        started = time.monotonic()
        lease_token = str(work.get("lease_token") or "")
        if not lease_token:
            raise ConnectorAPIError(
                0, f"work payload for job {job_id} carries no lease token"
            )
        self._active_job = (job_id, lease_token)
        heartbeat_task = asyncio.create_task(self._job_heartbeat_loop(job_id, lease_token))
        try:
            findings, summary = await self.run_scan(work)
            if findings:
                result = await self.submit_findings(job_id, findings)
                summary.setdefault("accepted", result.get("accepted", 0))
                summary.setdefault("rejected", result.get("rejected", 0))
            summary.setdefault("duration_sec", round(time.monotonic() - started, 1))
            await self.complete(job_id, summary)
            log.info("connector_job_completed", job_id=job_id, summary=summary)
        except Exception as exc:
            log.error("connector_job_failed", job_id=job_id, err=str(exc)[:500])
            await self.report_failure(job_id, f"{type(exc).__name__}: {exc}")
        finally:
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except asyncio.CancelledError:
                pass
            if self._active_job and self._active_job[0] == job_id:
                self._active_job = None

    async def _liveness_watchdog(self) -> None:
        """Touch the liveness file while the event loop keeps making progress.

        Deliberately a task of its own rather than a line in the poll loop: a
        connector running a long scan is *working*, not unhealthy. Anchoring
        the probe to the poll loop would report a 30-minute dnstwist scan as a
        dead container, so the file is written on a fixed timer that only stops
        if the event loop stops running it.

        A read-only or missing path is logged once and never fatal: liveness is
        observability, and it must not be the reason a connector stops
        collecting data.
        """
        path = (os.environ.get("CONNECTOR_LIVENESS_FILE", _DEFAULT_LIVENESS_FILE) or "").strip()
        if not path:
            return
        interval = max(self.poll_interval, 1.0)
        warned = False
        while not self._stop.is_set():
            try:
                with open(path, "w", encoding="ascii") as handle:
                    handle.write(str(int(time.time())))
                warned = False
            except OSError as exc:
                if not warned:
                    log.warning(
                        "connector_liveness_write_failed",
                        path=path,
                        err=str(exc)[:200],
                    )
                    warned = True
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass

    async def run_forever(self) -> None:
        """Main loop: register, then poll-execute-heartbeat until stopped.

        Raises ``ConnectorCredentialError`` if the core rejects the credential:
        a revoked or rotated token cannot be repaired from inside the container.
        """
        await self._register_or_fail()
        watchdog = asyncio.create_task(self._liveness_watchdog())

        try:
            await self._poll_loop()
        finally:
            watchdog.cancel()
            # Suppress only the watchdog's own cancellation; an outer cancel of
            # run_forever propagates because ``await watchdog`` cannot produce
            # the outer CancelledError.
            try:
                await watchdog
            except asyncio.CancelledError:
                pass
            if self._client and not self._client.is_closed:
                await self._client.aclose()

    async def _poll_loop(self) -> None:
        backoff = 1.0
        last_heartbeat = 0.0
        while not self._stop.is_set():
            try:
                work = await self.poll_work()
                backoff = 1.0  # core reachable again
                if work:
                    await self._execute_job(work)
                    continue  # drain the queue before sleeping
                # Idle: heartbeat at most every 30 s to keep last_seen fresh.
                if time.monotonic() - last_heartbeat >= 30:
                    try:
                        await self.heartbeat()
                        last_heartbeat = time.monotonic()
                    except Exception as exc:
                        log.warning("connector_heartbeat_failed", err=str(exc)[:200])
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self.poll_interval)
                except asyncio.TimeoutError:
                    pass
            except ConnectorAPIError as exc:
                if exc.status_code in (401, 403):
                    # Not self-healing any more: the token has been revoked or
                    # rotated, or belongs to another connector. Retrying would
                    # only flood the core with requests that cannot succeed.
                    log.error(
                        "connector_credential_rejected",
                        name=self.name,
                        status=exc.status_code,
                    )
                    raise ConnectorCredentialError(exc.status_code, self.name) from exc
                log.warning("connector_poll_error", err=str(exc)[:200])
                await self._sleep_backoff()
                backoff = min(backoff * 2, self.backoff_max)
            except Exception as exc:
                log.error("connector_loop_error", err=str(exc)[:500])
                await self._sleep_backoff()

    async def _register_or_fail(self) -> None:
        """Register on startup, mapping a refused credential to a fatal error."""
        try:
            await self.register()
        except ConnectorAPIError as exc:
            if exc.status_code in (401, 403):
                log.error(
                    "connector_credential_rejected",
                    name=self.name,
                    status=exc.status_code,
                )
                raise ConnectorCredentialError(exc.status_code, self.name) from exc
            raise

    async def _sleep_backoff(self) -> None:
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=self.poll_interval)
        except asyncio.TimeoutError:
            pass

    def stop(self) -> None:
        self._stop.set()

    def install_signal_handlers(self) -> None:
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self.stop)
            except NotImplementedError:
                # Windows / limited environments.
                signal.signal(sig, lambda s, f: self.stop())

    def main(self) -> None:
        """Entrypoint: run the connector until SIGTERM/SIGINT."""
        async def _runner():
            await self.run_forever()

        configure_connector_logging()
        self.install_signal_handlers()
        try:
            asyncio.run(_runner())
        except ConnectorCredentialError as exc:
            # Fail loudly with the one instruction that fixes it; the container
            # exits non-zero so orchestrators surface the misconfiguration.
            print(f"[FATAL] {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
