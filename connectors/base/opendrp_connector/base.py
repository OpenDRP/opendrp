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
from urllib.parse import urlsplit

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
        # Deliberately not ``cache_logger_on_first_use``: that flag is process
        # global, and it hard-caches *every* logger bound while a connector runs,
        # not just this module's. Embedded in the core — which is exactly what
        # this repository's connector tests do, and what any future in-process
        # use would do — it left the core's audit logger bound to the connector's
        # chain for the rest of the process, so audit lines came out in the
        # connector's shape (``event`` and ``level`` beside the five published
        # fields) instead of the contract in ``docs/description.md``, and no
        # later reconfiguration could undo it. One object per log call is cheap
        # next to the HTTP request that follows it.
        cache_logger_on_first_use=False,
    )

#: The version this connector runtime reports to the core as ``api_version``.
#: It is the release the worker was built from, so it is the platform's own
#: version — the same value ``backend/app/__init__.py`` declares, which
#: ``scripts/check_version_consistency.py`` enforces. The wire-protocol revision
#: is a separate number (``protocol_version``), and it is an integer.
SDK_VERSION = "0.2.1"

#: Default liveness file. Lives on the connector's tmpfs, so it costs no disk
#: and always starts absent after a container restart. The directory is asked
#: for rather than spelled out: the connector images set
#: ``CONNECTOR_LIVENESS_FILE`` explicitly, so this is only the fallback for a
#: process started outside them, and a spelled-out ``/tmp`` would be the wrong
#: answer on any host that moved its temporary directory.
_DEFAULT_LIVENESS_FILE = os.path.join(tempfile.gettempdir(), "opendrp-connector-alive")

#: The largest findings batch the core accepts in one request (its own
#: ``MAX_FINDINGS_PER_BATCH``). Declared here rather than imported because a
#: connector image does not ship the core; ``tests/test_connector_sdk_contract``
#: pins the two numbers together. A worker with a smaller batch must say in a
#: comment why the smaller size buys something (progress visibility), because
#: 25 findings per request is twenty requests and twenty audit rows per 500
#: findings and no other gain.
DEFAULT_SUBMIT_BATCH = 500
#: The same bound for a source catalogue sweep (the core's
#: ``MAX_CATALOGUE_ENTRIES_PER_BATCH``).
DEFAULT_CATALOGUE_BATCH = 500

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


class ConnectorPreflightError(RuntimeError):
    """A startup check failed: this connector cannot run jobs correctly here.

    Fatal by design, like ``ConnectorCredentialError``. The alternative — start
    anyway and mark each job ``partial`` — is the failure mode this exists to
    remove: for a scanner, "I could not run my tool" and "I found nothing" must not
    look the same in the job history. The message carries the fix; the process
    exits non-zero so the container's restart policy and `docker compose ps`
    surface the misconfiguration instead of a quiet stream of empty scans.
    """


class ConnectorBase:
    """Base class / runtime for OpenDRP connectors."""

    #: What this worker can answer about, in the core's own vocabulary: one
    #: identifier per asset type or record class it can be asked for. The core
    #: admits a scan on the capabilities its worker reported, so a subclass must
    #: declare here exactly what it produces rather than the module's whole list.
    CAPABILITIES: tuple[str, ...] = ()
    #: Provider quota buckets this worker may reserve against. Empty for a worker
    #: that asks no metered provider: declaring a bucket it never spends would
    #: claim a budget it does not have.
    OPERATIONS: tuple[str, ...] = ()
    #: Environment variables that may carry this worker's provider key. Empty for
    #: a connector that needs none (dnstwist is compute-only): readiness then says
    #: ``credentials_configured: false`` truthfully instead of implying a missing
    #: key. A key stored in the core is not visible here, so this is refreshed
    #: after every credential read.
    CREDENTIAL_ENV: tuple[str, ...] = ()

    #: Readiness state, kept on the SDK so every worker reports the same fields
    #: and a partly constructed worker (a unit test building one with
    #: ``__new__``) can still describe itself.
    credential_state: str = "unknown"
    provider_error: str | None = None
    #: The source's own names for its data classes, when it publishes them.
    data_class_labels: dict[str, str] = {}

    #: Subclasses may pre-load expensive state here (e.g. binaries).
    def __init__(self) -> None:
        missing = [k for k in _REQUIRED_ENV if not os.environ.get(k)]
        if missing:
            raise RuntimeError(
                f"Missing required environment variables: {', '.join(missing)}"
            )
        self.core_url = os.environ["CORE_URL"].rstrip("/")
        # The connector token travels in a header on every call. Plain http is
        # accepted inside the connector segment (and for a Compose service name,
        # which is one label) because that segment is a declared trust boundary;
        # anywhere else it puts the credential on the wire, so say so once at
        # start-up rather than waiting for an operator to notice a leaked token.
        parsed_core = urlsplit(self.core_url)
        core_host = (parsed_core.hostname or "").strip()
        if parsed_core.scheme == "http" and not (
            core_host in {"localhost", "127.0.0.1", "::1"}
            or (core_host and "." not in core_host)
        ):
            log.warning(
                "connector_core_url_insecure",
                core_url=self.core_url,
                reason=(
                    "plain http to a non-loopback host discloses the connector "
                    "token; use https outside the connector segment"
                ),
            )
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

        # Instance copies of the readiness fields, so a worker that changes one
        # does not change the class-level default another instance reads.
        self.credential_state = "unknown"
        self.provider_error = None
        self.data_class_labels: dict[str, str] = {}

        #: Whether this job already published a readiness row (HIBP and intelligence
        #: do, mid-scan, because a refused key is worth reporting at once). The
        #: runtime publishes one after completion otherwise, so every worker's row
        #: reflects what the scan did without two identical posts for one job.
        self._readiness_reported_since_job = False
        #: How many findings batches this job has sent, so the core can record an
        #: ordered delivery sequence rather than rows that all look alike. Reset
        #: when a job is claimed.
        self._batch_index = 0

        self._stop = asyncio.Event()
        self._client: httpx.AsyncClient | None = None
        #: ``(job_id, lease_token)`` of the scan being executed. The token is
        #: part of the claim, never absent: every job-scoped call proves it.
        self._active_job: tuple[str, str] | None = None
        self._lease_deadline: float | None = None
        self._lease_lost = False
        self._scan_task: asyncio.Task | None = None
        #: The declaration this connector registers with, validated once here so
        #: a missing job type fails at start-up instead of restart-looping
        #: against the core.
        self.manifest: dict[str, Any] = self.manifest_payload()

    # ------------------------------------------------------------------
    # Readiness
    # ------------------------------------------------------------------

    def readiness_capabilities(self) -> list[str]:
        """The asset types and record classes this worker accepts right now.

        A method rather than only the class attribute because the answer can
        depend on runtime state: HIBP advertises its stealer-log route only when
        the operator turned that pass on, and intelligence narrows its provider's
        list by module. The default is the declared tuple.
        """
        return list(self.CAPABILITIES)

    def readiness_operations(self) -> list[str]:
        """The provider quota buckets this worker may reserve against."""
        return list(self.OPERATIONS)

    def credentials_configured(self) -> bool:
        """Whether the container's environment carries a provider key.

        A key stored in the core is fetched at scan time and is not visible here,
        so an absent variable is not proof that no key exists; the readiness row
        is refreshed after every credential read for exactly that reason.
        """
        return any((self.env.get(name) or "").strip() for name in self.CREDENTIAL_ENV)

    def readiness_payload(self) -> dict[str, Any]:
        """The declaration posted to ``/connectors/me/readiness``."""
        payload: dict[str, Any] = {
            "credentials_configured": self.credentials_configured(),
            "credential_state": self.credential_state,
            "provider_error": self.provider_error,
            "capabilities": self.readiness_capabilities(),
            "operations": self.readiness_operations(),
        }
        if self.data_class_labels:
            payload["data_class_labels"] = dict(self.data_class_labels)
        return payload

    async def report_readiness(self) -> bool:
        """Publish what this worker can be asked and whether its key works.

        Never raises: readiness is observability. A scan that produced findings
        must not be reported as failed because the row describing the worker could
        not be written, so the failure is logged and ``False`` is returned.
        """
        try:
            await self._request(
                "POST",
                "/api/v1/connectors/me/readiness",
                json=self.readiness_payload(),
            )
            self._readiness_reported_since_job = True
            return True
        except Exception as exc:
            log.warning(
                "connector_readiness_report_failed",
                name=getattr(self, "name", None),
                err=f"{type(exc).__name__}: {str(exc)[:200]}",
            )
            return False

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
            "protocol_version": 2,
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
        if self._lease_lost or (self._lease_deadline is not None and time.monotonic() >= self._lease_deadline):
            raise ConnectorAPIError(403, "local job lease expired; stop work")
        if not lease_token or job != job_id:
            raise ConnectorAPIError(
                0,
                f"no active lease for job {job_id}; poll for work before reporting on it",
            )
        return lease_token

    async def reserve_virustotal_request(self) -> None:
        """Reserve a globally shared public VT quota slot before each request."""
        if not self._active_job:
            raise ConnectorAPIError(403, "Active lease required for provider quota")
        await self.reserve_provider_request("lookup")

    async def reserve_provider_request(self, bucket: str = "search") -> dict:
        """Charge one provider request to the account, and report what is left.

        Answers the core's own accounting — the account's day budget and how much of
        it remains — so a worker's job summary can say what a scan cost rather than
        only what it found. A body that is not a JSON object answers an empty mapping:
        the reservation itself is what the caller needed, and a core that answered
        with a shape this version does not know is not a failed reservation.
        """
        if not self._active_job:
            raise ConnectorAPIError(403, "Active lease required for provider quota")
        job_id = self._active_job[0]
        response = await self._request(
            "POST", "/api/v1/connectors/me/quota/provider",
            params={"job_id": job_id, "bucket": bucket},
            headers={"X-Connector-Lease": self._lease_for(job_id)})
        try:
            payload = response.json()
        except ValueError:
            return {}
        return payload if isinstance(payload, dict) else {}

    async def submit_findings(
        self, job_id: str, findings: list[dict], *, batch_total: int | None = None
    ) -> dict:
        if not findings:
            return {"accepted": 0, "rejected": 0}
        if len(findings) > DEFAULT_SUBMIT_BATCH:
            # The core rejects an oversized body wholesale, losing every finding in
            # it. Refusing here names the bug at its source instead of after a scan.
            raise ValueError(
                f"findings batch of {len(findings)} exceeds the core limit of "
                f"{DEFAULT_SUBMIT_BATCH}; submit in batches"
            )
        self._batch_index += 1
        headers = {
            "X-Connector-Lease": self._lease_for(job_id),
            "X-Connector-Batch-Index": str(self._batch_index),
        }
        if batch_total is not None:
            headers["X-Connector-Batch-Total"] = str(batch_total)
        resp = await self._request_with_retry(
            "POST",
            f"/api/v1/connectors/me/findings/{job_id}",
            headers=headers,
            json=findings,
        )
        result = resp.json()
        if result.get("rejected", 0):
            raise ConnectorAPIError(422, "core rejected connector observations")
        if result.get("accepted") != len(findings):
            raise ConnectorAPIError(502, "core returned inconsistent ingestion counts")
        return result

    async def submit_catalogue(self, job_id: str, entries: list[dict]) -> dict:
        """Hand the core a batch of this source's incident catalogue (WI-13).

        A batch rather than the whole catalogue: the core stores what it is given and
        answers the diff it computed, so a sweep that was cut short keeps what the
        earlier batches achieved. The answer is that diff — how many entries were new to
        the installation, how many changed, and how many named a domain somebody watches.
        """
        if not entries:
            return {"received": 0, "created": 0, "updated": 0, "new_incidents": 0}
        resp = await self._request_with_retry(
            "POST",
            f"/api/v1/connectors/me/catalogue/{job_id}",
            headers={"X-Connector-Lease": self._lease_for(job_id)},
            json=entries,
        )
        result = resp.json()
        if not isinstance(result, dict) or "received" not in result:
            raise ConnectorAPIError(502, "core returned no catalogue diff")
        if result.get("received") != len(entries):
            raise ConnectorAPIError(502, "core returned inconsistent catalogue counts")
        return result

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
                    renewed_from = time.monotonic()
                    await self._request(
                        "POST",
                        "/api/v1/connectors/me/heartbeat",
                        json={"job_id": job_id, "lease_token": lease_token},
                    )
                    self._lease_deadline = renewed_from + getattr(self, "_lease_seconds", 180)
                except Exception as exc:
                    log.warning("connector_job_heartbeat_failed", job_id=job_id, err=str(exc)[:200])
                    if (isinstance(exc, ConnectorAPIError) and exc.status_code in (401, 403, 404, 409)) or time.monotonic() >= (self._lease_deadline or 0):
                        self._lease_lost = True
                        task = getattr(self, "_scan_task", None)
                        if task:
                            task.cancel()
                        return

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
        self._readiness_reported_since_job = False
        self._batch_index = 0
        self._lease_seconds = float(work.get("lease_seconds", 180))
        self._lease_deadline = time.monotonic() + self._lease_seconds
        self._lease_lost = False
        async def execute_and_publish():
            findings, summary = await self.run_scan(work)
            if findings:
                accepted = rejected = 0
                batches = range(0, len(findings), DEFAULT_SUBMIT_BATCH)
                total_batches = (len(findings) + DEFAULT_SUBMIT_BATCH - 1) // DEFAULT_SUBMIT_BATCH
                for start in batches:
                    result = await self.submit_findings(
                        job_id,
                        findings[start : start + DEFAULT_SUBMIT_BATCH],
                        batch_total=total_batches,
                    )
                    accepted += int(result.get("accepted", 0))
                    rejected += int(result.get("rejected", 0))
                summary.setdefault("accepted", accepted)
                summary.setdefault("rejected", rejected)
            summary.setdefault("duration_sec", round(time.monotonic() - started, 1))
            await self.complete(job_id, summary)
            # The row says what a scan found and whether the key still works; a
            # worker that reported during the scan (a refused key) has already
            # said so, and a second identical post would only add noise.
            if not self._readiness_reported_since_job:
                await self.report_readiness()
            log.info("connector_job_completed", job_id=job_id, summary=summary)

        async def lease_watchdog():
            while self._active_job and not self._lease_lost:
                delay = (self._lease_deadline or 0) - time.monotonic()
                if delay <= 0:
                    self._lease_lost = True
                    if self._scan_task:
                        self._scan_task.cancel()
                    return
                await asyncio.sleep(min(delay, 0.25))

        scan_task = asyncio.create_task(execute_and_publish())
        self._scan_task = scan_task
        heartbeat_task = asyncio.create_task(self._job_heartbeat_loop(job_id, lease_token))
        watchdog_task = asyncio.create_task(lease_watchdog())
        try:
            await scan_task
        except asyncio.CancelledError:
            if getattr(self, "_lease_lost", False):
                log.warning("connector_job_lease_lost", job_id=job_id)
            else:
                raise
        except Exception as exc:
            log.error("connector_job_failed", job_id=job_id, err=str(exc)[:500])
            if not self._lease_lost and time.monotonic() < (self._lease_deadline or 0):
                await self.report_failure(job_id, f"{type(exc).__name__}: {exc}")
        finally:
            scan_task.cancel()
            heartbeat_task.cancel()
            watchdog_task.cancel()
            await asyncio.gather(scan_task, heartbeat_task, watchdog_task, return_exceptions=True)
            self._scan_task = None
            self._lease_deadline = None
            self._lease_lost = False
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

    async def preflight(self) -> None:
        """Startup checks, run once before the connector registers or claims work.

        A subclass overrides this to refuse to run against a component it cannot
        work with — a tool of the wrong version, a missing binary — by raising
        ``ConnectorPreflightError``. Deliberately before registration: a connector
        that declares itself ready and then cannot scan is what an operator has to
        discover from a job history rather than from the container log.
        """
        return None

    async def run_forever(self) -> None:
        """Main loop: preflight, register, then poll-execute-heartbeat until stopped.

        Raises ``ConnectorCredentialError`` if the core rejects the credential:
        a revoked or rotated token cannot be repaired from inside the container.
        Raises ``ConnectorPreflightError`` if a startup check refuses to run.
        """
        await self.preflight()
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
                await self._sleep_backoff(backoff)
                backoff = min(backoff * 2, self.backoff_max)
            except Exception as exc:
                log.error("connector_loop_error", err=str(exc)[:500])
                # An unexpected error is retried with the same capped backoff:
                # waiting ``poll_interval`` here would ignore the setting an
                # operator tuned for a core that is failing in an odd way.
                await self._sleep_backoff(backoff)
                backoff = min(backoff * 2, self.backoff_max)

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

    async def _sleep_backoff(self, delay: float | None = None) -> None:
        """Wait before retrying, returning early when the connector is stopped.

        The delay is the caller's current backoff, clamped to ``backoff_max``
        so ``RECONNECT_BACKOFF_MAX_SEC`` is what actually reaches the sleep;
        without a delay the idle poll interval is used.
        """
        timeout = self.poll_interval if delay is None else min(delay, self.backoff_max)
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=timeout)
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
        except (ConnectorCredentialError, ConnectorPreflightError) as exc:
            # Fail loudly with the one instruction that fixes it; the container
            # exits non-zero so orchestrators surface the misconfiguration.
            print(f"[FATAL] {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
