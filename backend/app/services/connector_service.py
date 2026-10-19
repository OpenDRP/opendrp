"""Connector registry service.

The registry is **data, not code**: a connector declares its own manifest at
registration (module, job type, finding kind, consumed inventory, config
schema — see ``connector_manifest``), and this service stores and enforces it.
Nothing here names a provider, so adding a data source is a connector-side
change.

Implements the core side of the connector protocol (OpenCTI-style):

    * ``register``   — upsert a connector by (name, connector_type) and store
      its self-declared manifest.
    * ``claim_work`` — atomic long-poll claim of one pending scan job owned
      by this connector (matching the job type it declared). Uses ``SELECT ...
      FOR UPDATE SKIP LOCKED`` so two connectors can never claim the same
      scan request.
    * ``complete`` / ``fail`` — job finalization reported by the connector.
    * ``heartbeat``  — liveness update.
"""

import secrets
import uuid
from datetime import datetime, timedelta, timezone

import structlog
from sqlalchemy import select, or_, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import (
    BadRequestException,
    ForbiddenException,
    NotFoundException,
)
from app.models import Connector, ConnectorStatus, Job, JobStatus
from app.services.connector_manifest import (
    build_manifest,
    provisioning_job_type,
    resolve_manifest,
)
from app.services.job_service import JobService
from app.services.module_aliases import canonical_module_id
from app.services.scan_admission import (
    NoEnabledConnector,
    acquire as acquire_scan_slot,
    release as release_scan_slot,
)
from app.core.safe_errors import sanitize_external_error
from app.services.module_registry import (
    get_module,
    load_modules,
    require_enabled_module,
)

log = structlog.get_logger()

# Safe connection-info keys accepted at registration (strict allowlist).
_ALLOWED_INFO_KEYS = {"version", "python", "hostname", "platform"}


def normalize_connector_name(raw: str) -> str:
    s = (raw or "").strip().lower()
    # Keep it DNS-label-like: [a-z0-9-]{1,100}
    out = []
    for ch in s:
        if ch.isascii() and (ch.isalnum() or ch == "-"):
            out.append(ch)
        else:
            out.append("-")
    name = "".join(out).strip("-")
    if not name:
        raise BadRequestException("connector name must contain alphanumeric characters")
    return name[:100]


#: How many confirmed candidates one scan is handed. A confirmation is a human
#: decision, so the list is short by nature - and every entry costs the worker three
#: provider questions, so the bound is what keeps a heavily triaged installation from
#: queueing a scan larger than the job budget that pays for it.
MAX_SCAN_CANDIDATES = 20


class ConnectorService:
    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------
    # Registration & lookup
    # ------------------------------------------------------------------

    async def get_by_name(self, name: str) -> Connector | None:
        stmt = select(Connector).where(Connector.name == name)
        row = (await self.db.execute(stmt)).scalar_one_or_none()
        if row is not None:
            return row
        # A label resolves to a connector; it never determines authentication or
        # UUID ownership.
        for connector in (await self.db.execute(select(Connector))).scalars():
            if name in (connector.aliases or []):
                return connector
        return None

    async def list_connectors(self) -> list[Connector]:
        stmt = select(Connector).order_by(Connector.connector_type, Connector.name)
        return list((await self.db.execute(stmt)).scalars().all())

    @staticmethod
    def is_online(connector: Connector) -> bool:
        """Liveness only; a prior provider error does not mean a worker is offline."""
        seen = connector.last_seen_at
        if seen is None or not connector.is_enabled:
            return False
        if seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - seen <= timedelta(
            seconds=settings.CONNECTOR_HEALTH_STALE_AFTER_SECONDS
        )

    async def list_enabled_by_type(self, connector_type: str) -> list[Connector]:
        stmt = select(Connector).where(
            Connector.connector_type == connector_type,
            Connector.status == ConnectorStatus.ENABLED,
        )
        return list((await self.db.execute(stmt)).scalars().all())

    async def register(
        self,
        *,
        name: str,
        connector_type: str,
        api_version: str | None = None,
        info: dict | None = None,
        default_job_type: str | None = None,
        finding_kind: str | None = None,
        asset_types: list[str] | None = None,
        config_schema: dict | None = None,
    ) -> Connector:
        """Upsert a connector by name (self-registration).

        The connector declares its own manifest — job type, finding kind,
        consumed asset types and operator-editable config schema — so a new
        data source needs no core change. The job type is the work this connector
        alone claims, and a connector without one could claim nothing while still
        looking registered, so the registration API requires it. Only the
        provisioning path (the admin API and the CLI), which creates the row
        before a credential exists, may omit it: the row then reserves
        ``<module>.<name>`` and the connector re-declares its own type when it
        first registers. The core only checks that the declaration is coherent
        (module matches the finding kind) and that no other connector already
        claims the same job type.

        ``api_version`` is informational — the registration API requires it
        (the SDK always sends it), and re-registration records the version of
        the build that last wrote the row.
        """
        # The module is data: it has to exist in the registry and be enabled.
        # An unknown id is refused with the list of modules that do exist.
        connector_type = canonical_module_id(connector_type)
        module_spec = await require_enabled_module(self.db, connector_type)
        clean = normalize_connector_name(name)
        safe_info: dict = {}
        for k, v in (info or {}).items():
            if str(k) in _ALLOWED_INFO_KEYS:
                safe_info[str(k)] = str(v)[:200]

        existing = await self.get_by_name(clean)
        requested_name = clean
        alias_match = existing is not None and clean in (existing.aliases or [])
        if alias_match and existing is not None:
            # A worker may keep registering under its old environment label
            # after the safe display-name migration. Keep its UUID and stored
            # name; the alias resolves to the same registry row, never a second one.
            clean = existing.name
        if existing is not None and existing.connector_type != connector_type:
            raise BadRequestException(
                f"connector '{clean}' is already registered as type '{existing.connector_type}'"
            )

        manifest = build_manifest(
            module_spec=module_spec,
            job_type=default_job_type
            if default_job_type
            else provisioning_job_type(connector_type, clean),
            finding_kind=finding_kind,
            asset_types=asset_types,
            config_schema=config_schema,
        )
        await self._assert_job_type_available(
            manifest["job_type"], owner=existing.name if existing else clean
        )

        if existing is None:
            existing = Connector(
                name=clean,
                connector_type=connector_type,
                status=ConnectorStatus.ENABLED,
            )
            self.db.add(existing)
        existing.default_job_type = manifest["job_type"]
        existing.manifest = manifest
        existing.aliases = list(existing.aliases or [])
        if alias_match and requested_name not in existing.aliases:
            existing.aliases.append(requested_name)
        if api_version:
            existing.api_version = api_version[:32]
        if safe_info:
            existing.info = safe_info
        existing.touch()
        existing.last_error = None
        await self.db.commit()
        await self.db.refresh(existing)
        return existing

    async def _assert_job_type_available(self, job_type: str, *, owner: str) -> None:
        """Reject a job type another connector already claims.

        Job-type ownership is what makes work distribution unambiguous, and it
        is exclusive: a pending job is claimed by exactly one declared job type,
        so two connectors sharing one type would race for each other's scans.
        """
        stmt = select(Connector.name).where(Connector.default_job_type == job_type)
        if owner:
            stmt = stmt.where(Connector.name != owner)
        holder = (await self.db.execute(stmt)).scalars().first()
        if holder is not None:
            raise BadRequestException(
                f"job type '{job_type}' is already declared by connector '{holder}'"
            )

    async def set_status(self, connector_id: uuid.UUID, status: str, *, commit: bool = True) -> Connector:
        if status not in ConnectorStatus.ALL:
            raise BadRequestException("status must be 'enabled' or 'disabled'")
        conn = await self.db.get(Connector, connector_id)
        if conn is None:
            raise NotFoundException("Connector not found")
        conn.status = status
        if status == ConnectorStatus.DISABLED:
            jobs = list(
                (
                    await self.db.execute(
                        select(Job).where(
                            Job.connector_id == conn.id,
                            Job.status.in_([JobStatus.pending, JobStatus.running]),
                        )
                    )
                ).scalars()
            )
            for job in jobs:
                job.status = JobStatus.cancelled
                job.finished_at = datetime.now(timezone.utc)
                job.lease_token = None
                job.lease_expires_at = None
                job.error_message = "Source disabled by administrator"
                await release_scan_slot(
                    conn.name,
                    (job.params if isinstance(job.params, dict) else {}).get(
                        "scan_admission_token"
                    ),
                )
        await self.db.flush()
        if commit:
            await self.db.commit()
            await self.db.refresh(conn)
        return conn

    async def set_config(self, connector_id: uuid.UUID, config: dict, *, commit: bool = True) -> Connector:
        if not isinstance(config, dict):
            raise BadRequestException("config must be an object")
        conn = await self.db.get(Connector, connector_id)
        if conn is None:
            raise NotFoundException("Connector not found")
        if conn.provider:
            from app.services.provider_quota import validate_policy

            try:
                validate_policy(config)
            except ValueError as exc:
                raise BadRequestException(str(exc)) from exc
        conn.config = config
        await self.db.flush()
        if commit:
            await self.db.commit()
            await self.db.refresh(conn)
        return conn

    # ------------------------------------------------------------------
    # Work distribution (pull model)
    # ------------------------------------------------------------------

    async def claim_work(self, connector: Connector) -> Job | None:
        """Atomically claim one pending scan job for this connector.

        A connector only claims jobs tagged with the job type it declared in its
        manifest (e.g. ``phishing.dnstwist``). Job types are uniquely owned and
        required at registration, so this is the whole isolation guarantee: a
        connector can never claim a sibling's work, and a breaches connector can
        never claim phishing work.
        Returns the claimed job (moved to ``running``) or ``None`` when the
        queue is empty. SKIP LOCKED keeps concurrent connectors from grabbing
        the same job; ordering is FIFO by creation time.
        """
        if not connector.is_enabled:
            return None
        conditions = [
            Job.status == JobStatus.pending,
            or_(
                Job.connector_id == connector.id,
                and_(
                    Job.connector_id.is_(None),
                    Job.job_type == connector.default_job_type,
                ),
            ),
        ]
        module = await get_module(self.db, connector.connector_type)
        if module is None:
            return None
        if not module.enabled:
            return None
        if connector.provider and (
            not (connector.readiness or {}).get("credentials_configured")
            or (connector.readiness or {}).get("credential_state")
            in {"invalid", "unsupported"}
        ):
            return None
        await self.recover_expired_jobs()
        stmt = (
            select(Job)
            .where(*conditions)
            .order_by(Job.created_at.asc())
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        job = (await self.db.execute(stmt)).scalar_one_or_none()
        if job is None:
            return None
        params = job.params if isinstance(job.params, dict) else {}
        if connector.provider and (
            job.connector_id == connector.id or job.connector_id is None
        ):
            account_id = params.get("source_account_id")
            from app.models.source_account import SourceAccount

            account = None
            if account_id:
                try:
                    account = await self.db.get(
                        SourceAccount, uuid.UUID(str(account_id))
                    )
                except (TypeError, ValueError, AttributeError):
                    account = None
            account_ok = (
                account is not None
                and account.source_id == connector.provider
                and (account.policy or {}).get("approved") is True
            )
            if not account_ok:
                # Queued source work remains bound to its original account and
                # does not silently adopt a reassigned connector quota group.
                job.status = JobStatus.cancelled
                job.finished_at = datetime.now(timezone.utc)
                job.error_message = (
                    (
                        "provider_account_missing"
                        if account is None
                        else "account_policy_unapproved"
                    )
                    + ": queued source work is bound to its original account"
                )
                await self.db.commit()
                return None
        now = datetime.now(timezone.utc)
        await self.recover_expired_jobs(now=now)
        job.status = JobStatus.running
        job.started_at = now
        job.last_heartbeat_at = now
        job.attempt_count = (job.attempt_count or 0) + 1
        job.connector_id = connector.id
        job.claimed_by_connector = connector.name
        job.lease_token = secrets.token_urlsafe(32)
        job.lease_expires_at = now + timedelta(
            seconds=settings.CONNECTOR_JOB_LEASE_SECONDS
        )
        connector.touch()
        await self.db.commit()
        await self.db.refresh(job)
        return job

    async def complete_job(
        self,
        connector: Connector,
        job_id: uuid.UUID,
        *,
        result_summary: dict | None,
        lease_token: str,
    ) -> Job:
        job = await self._owned_job(connector, job_id, lease_token=lease_token)
        summary_status = (
            result_summary.get("status") if isinstance(result_summary, dict) else None
        )
        if summary_status == "error":
            error_code = (
                result_summary.get("error_code")
                if isinstance(result_summary, dict)
                else None
            )
            await JobService(self.db).fail_job(
                job_id,
                error_message=sanitize_external_error(
                    error_code or "connector provider error", limit=8000
                ),
                result_summary=result_summary,
            )
        else:
            await JobService(self.db).complete_job(
                job_id, result_summary=result_summary
            )
        if summary_status == "partial":
            job.status = JobStatus.partial
        elif summary_status == "skipped":
            job.status = JobStatus.skipped
        job_params = job.params if isinstance(job.params, dict) else {}
        await release_scan_slot(connector.name, job_params.get("scan_admission_token"))
        job.lease_expires_at = None
        job.last_heartbeat_at = datetime.now(timezone.utc)
        job.lease_token = None
        connector.touch()
        connector.last_error = (
            sanitize_external_error(
                (result_summary or {}).get("error_code") or "provider error", limit=2000
            )
            if summary_status == "error"
            else None
        )
        if summary_status not in {"error", "partial", "skipped"}:
            connector.last_success_at = datetime.now(timezone.utc)
        await self.db.commit()
        await self.db.refresh(job)
        return job

    async def fail_job(
        self, connector: Connector, job_id: uuid.UUID, *, error: str, lease_token: str
    ) -> Job:
        job = await self._owned_job(connector, job_id, lease_token=lease_token)
        await JobService(self.db).fail_job(
            job_id, error_message=error or "connector failure"
        )
        job_params = job.params if isinstance(job.params, dict) else {}
        await release_scan_slot(connector.name, job_params.get("scan_admission_token"))
        job.lease_expires_at = None
        job.last_heartbeat_at = datetime.now(timezone.utc)
        job.lease_token = None
        connector.touch()
        connector.last_error = sanitize_external_error(
            error or "connector failure", limit=2000
        )
        await self.db.commit()
        await self.db.refresh(job)
        return job

    async def heartbeat(
        self,
        connector: Connector,
        *,
        job_id: uuid.UUID | None = None,
        lease_token: str | None = None,
    ) -> None:
        """Renew the lease on the job this connector is running.

        A heartbeat that names a job must carry that job's lease token, for the
        same reason completion does: the token is the only proof that the claim
        is still current.
        """
        connector.touch()
        if job_id is not None:
            if not lease_token:
                raise ForbiddenException("Job lease token is required")
            job = await self._owned_job(connector, job_id, lease_token=lease_token)
            if job.status != JobStatus.running:
                raise ForbiddenException("Job is no longer running")
            now = datetime.now(timezone.utc)
            job.last_heartbeat_at = now
            job.lease_expires_at = now + timedelta(
                seconds=settings.CONNECTOR_JOB_LEASE_SECONDS
            )
        await self.db.commit()

    async def recover_expired_jobs(self, *, now: datetime | None = None) -> int:
        """Recover connector jobs whose owner stopped renewing its lease."""
        current = now or datetime.now(timezone.utc)
        result = await self.db.execute(
            select(Job)
            .where(
                Job.status == JobStatus.running,
                Job.lease_expires_at.is_not(None),
                Job.lease_expires_at < current,
            )
            .with_for_update(skip_locked=True)
        )
        recovered = 0
        for job in result.scalars().all():
            owner = (
                await self.db.get(Connector, job.connector_id)
                if job.connector_id
                else await self.get_by_name(job.claimed_by_connector or "")
            )
            module = await get_module(self.db, owner.connector_type) if owner else None
            if not owner or not owner.is_enabled or not module or not module.enabled:
                job.status = JobStatus.cancelled
                job.error_message = "Source or module disabled after lease expiry"
                job.finished_at = current
                job.lease_token = None
                job.lease_expires_at = None
                job_params = job.params if isinstance(job.params, dict) else {}
                await release_scan_slot(
                    str(job_params.get("connector") or job.claimed_by_connector or ""),
                    job_params.get("scan_admission_token"),
                )
            elif (job.attempt_count or 0) < settings.CONNECTOR_JOB_MAX_ATTEMPTS:
                job.status = JobStatus.pending
                job.error_message = (
                    "Connector lease expired; job returned to the queue."
                )
                job.started_at = None
                job.finished_at = None
                job.claimed_by_connector = None
                job.lease_token = None
                job.lease_expires_at = None
                job.last_heartbeat_at = current
            else:
                # No connector will report completion for an exhausted lease.
                # Release the provider admission slot here; otherwise one lost
                # worker can suppress all future scans until the one-hour TTL.
                job_params = job.params if isinstance(job.params, dict) else {}
                await release_scan_slot(
                    str(job_params.get("connector") or job.claimed_by_connector or ""),
                    job_params.get("scan_admission_token"),
                )
                job.status = JobStatus.error
                job.error_message = "Connector lease expired after the retry limit."
                job.finished_at = current
                job.lease_expires_at = None
                job.lease_token = None
            recovered += 1
        if recovered:
            await self.db.commit()
        return recovered

    async def _owned_job(
        self, connector: Connector, job_id: uuid.UUID, *, lease_token: str
    ) -> Job:
        """Fetch a job this connector has claimed; 403/404 otherwise.

        Ownership is read from ``claimed_by_connector`` and proved with the lease
        token the claim handed out. Both are required: the connector name says
        which worker may touch the job, and the token says whether the claim it
        is acting on is still the current one, so a stale worker cannot finalize
        a job that was reclaimed after its lease expired.
        """
        job = (
            await self.db.execute(
                select(Job)
                .where(Job.id == job_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        if job is None:
            raise NotFoundException("Job not found")
        if (
            job.connector_id != connector.id
            if job.connector_id
            else job.claimed_by_connector != connector.name
        ):
            raise ForbiddenException("Job not claimed by this connector")
        if job.lease_token is None or lease_token != job.lease_token:
            raise ForbiddenException("Job lease is no longer valid")
        expiry = job.lease_expires_at
        if expiry and expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if (
            job.status != JobStatus.running
            or not expiry
            or expiry <= datetime.now(timezone.utc)
        ):
            raise ForbiddenException("Job lease expired or job is no longer running")
        return job

    # ------------------------------------------------------------------
    # Scan requests
    # ------------------------------------------------------------------

    async def enqueue_module_scan(
        self,
        *,
        connector_type: str,
        created_by: uuid.UUID | None,
        title: str,
        params: dict | None = None,
        connector_name: str | None = None,
        require_online: bool = False,
        commit: bool = True,
        admitted_out: list[tuple[str, str | None]] | None = None,
        admission: bool = True,
    ) -> list[Job]:
        """Create pending scan jobs for enabled connectors of a module.

        With ``connector_name`` set, only that single (enabled) connector gets
        a job — used by the manual per-source endpoints. Without it, every
        enabled connector of the module gets a job — used by the scheduler so
        all sources of a module run on their schedule. Connectors pick the work
        up via their work-poll; the core stays stateless with respect to
        connector execution.

        Each job carries the connector's own declared job type and the subset of
        the asset inventory that connector said it consumes. Paid provider
        connectors must be bound to an approved source account.

        ``admission=False`` creates the job without the per-connector scan slot, for
        work that is not a scan: a domain-verification step is one question an operator
        asked about one domain (WI-20), it cannot be duplicated by a second caller into
        two spends of the same quota, and refusing it because a scheduled scan holds the
        slot would block the very step that makes a domain scannable — right after the
        record is published.
        """
        # Registry-driven: any declared module can be scanned, and an unknown
        # module is refused with the list of modules that do exist.
        connector_type = canonical_module_id(connector_type)
        module_spec = await require_enabled_module(self.db, connector_type)
        connector_type = module_spec.id
        connectors = await self.list_enabled_by_type(connector_type)
        if connector_name:
            wanted = normalize_connector_name(connector_name)
            connectors = [
                c for c in connectors if c.name == wanted or wanted in (c.aliases or [])
            ]
        if require_online:
            connectors = [conn for conn in connectors if self.is_online(conn)]
        if not connectors:
            target = connector_name or connector_type
            raise NoEnabledConnector(
                f"No {'online' if require_online else 'enabled'} connector is available for '{target}'. "
                "Start the worker container and wait for it to register."
            )
        caller = dict(params or {})
        trigger = caller.pop("trigger", None)
        specs = await load_modules(self.db)
        jobs: list[Job] = []
        admitted: list[tuple[str, str | None]] = []
        for conn in connectors:
            schedule_key = f"{conn.id}:{caller['scheduled_at']}" if caller.get("scheduled_at") else None
            if schedule_key:
                from app.models.job import ScheduleOccurrence
                occurrence = await self.db.get(ScheduleOccurrence, schedule_key)
                if occurrence is not None:
                    existing_job = await self.db.get(Job, occurrence.job_id) if occurrence.job_id else None
                    if existing_job is not None:
                        jobs.append(existing_job)
                    continue
            # One distributed slot per connector prevents two users, the
            # scheduler, or separate API replicas from spending the same
            # provider quota on identical work. The token is carried in the job
            # params and released when the connector reports a terminal result.
            try:
                admission_token = (
                    await acquire_scan_slot(conn.name, ttl_seconds=3600)
                    if admission
                    else None
                )
                admitted.append((conn.name, admission_token))
                source = conn.provider or (
                    conn.aliases[0] if conn.aliases else conn.name
                )
                # The manifest says which inventory sections this connector
                # consumes. The scan target list is frozen into the job params so
                # every connector sees exactly what it was asked to scan (and
                # audit/job history stays deterministic). Keys are the stable
                # contract connectors consume: ``domains`` (look-alike/breach),
                # ``emails`` (account exposure), ``keyword_domains`` /
                # ``keyword_titles`` (brand hunting), ``exclude`` (owned hosts).
                manifest = resolve_manifest(
                    module_spec=specs.get(conn.connector_type),
                    connector_type=conn.connector_type,
                    default_job_type=conn.default_job_type,
                    manifest=conn.manifest,
                )
                snapshot = await self._active_asset_snapshot(
                    manifest["asset_types"],
                    include_candidates=canonical_module_id(conn.connector_type)
                    == "phishing",
                )
                account_policy = {}
                account = None
                if conn.source_account_id:
                    from app.models.source_account import SourceAccount

                    account = await self.db.get(SourceAccount, conn.source_account_id)
                if conn.provider and account is None:
                    from app.models.source_account import SourceAccount

                    account = (
                        await self.db.execute(
                            select(SourceAccount).where(
                                SourceAccount.source_id == conn.provider,
                                SourceAccount.name == (conn.quota_group or "default"),
                            )
                        )
                    ).scalar_one_or_none()
                if account is not None:
                    account_policy = {
                        key: value
                        for key, value in (account.policy or {}).items()
                        if key in {
                            "approved", "requests_per_minute", "daily_budget",
                                                    }
                    }
                    if conn.provider:
                        conn.source_account_id = account.id
                if conn.provider:
                    if account is None:
                        # Named, not generic: an installation whose account row is
                        # missing has to read that from the refusal, and it is a
                        # different answer from an account nobody approved. The
                        # startup seeder creates the row; approving it stays the
                        # operator's step.
                        raise BadRequestException(
                            "provider_account_missing: no source account is bound "
                            f"to provider {conn.provider!r}"
                        )
                    if account.source_id != conn.provider:
                        raise BadRequestException("Matching provider account required")
                    readiness = conn.readiness or {}
                    if not readiness.get("credentials_configured") or readiness.get(
                        "credential_state"
                    ) in {"invalid", "unsupported"}:
                        raise BadRequestException("Source credentials are not ready")
                    if (
                        account is None
                        or (account.policy or {}).get("approved") is not True
                    ):
                        raise BadRequestException(
                            "Operator-approved source account policy required"
                        )
                    capabilities = set(readiness.get("capabilities") or [])
                    if conn.connector_type == "phishing":
                        # A brand asset is what turns a brand question into a scan: the
                        # certificate collection asked from the organisation, and page
                        # text asked for the brand itself. A confirmed candidate is the
                        # fourth way in - the platform already found the name, and the
                        # provider is asked what serves it.
                        brands = [
                            item
                            for item in snapshot["keyword_domains"]
                            if item.get("type") == "keyword_domain"
                        ]
                        usable = bool(
                            snapshot["domains"] and "certificate" in capabilities
                        ) or bool(
                            snapshot["keyword_titles"] and "title" in capabilities
                        ) or bool(brands and "certificate_brand" in capabilities) or bool(
                            snapshot["candidates"] and "hostname" in capabilities
                        )
                    elif canonical_module_id(conn.connector_type) == "breaches":
                        # A breach worker asks about identifiers, not hosts: an
                        # address is the account question and a domain is the
                        # leak-list question. Reading its capabilities as
                        # `hostname`/`ip` (the shape the host-oriented workers use)
                        # would refuse every breach scan the moment the worker is
                        # bound to an account, which is exactly the state HIBP now
                        # ships in.
                        usable = bool(
                            snapshot["emails"] and "email_account" in capabilities
                        ) or bool(
                            snapshot["domains"] and "domain" in capabilities
                        ) or bool(
                            "catalogue" in capabilities
                            and (snapshot["emails"] or snapshot["domains"])
                        )
                    else:
                        usable = bool(
                            snapshot["domains"] and "hostname" in capabilities
                        ) or bool(snapshot["ips"] and "ip" in capabilities)
                        if canonical_module_id(conn.connector_type) == "dns":
                            usable = usable or bool(
                                snapshot["domains"]
                                and "passive_dns" in capabilities
                            ) or bool(
                                snapshot["domains"] and "certificate" in capabilities
                            )
                    if not usable:
                        raise BadRequestException(
                            "No active assets or capabilities match this request"
                        )
                config_snapshot = {**dict(conn.config or {}), **account_policy}
                job_params = {
                    **snapshot,
                    **caller,
                    "connector_id": str(conn.id),
                    "source_account_id": str(conn.source_account_id)
                    if conn.source_account_id
                    else None,
                    "source_id": source,
                    "config_snapshot": config_snapshot,
                    "manifest_snapshot": manifest,
                    "connector": conn.name,
                    "module": conn.connector_type,
                    "trigger": trigger,
                    "scan_admission_token": admission_token,
                }
                if canonical_module_id(conn.connector_type) == "breaches":
                    # The incident catalogue's checkpoint (WI-13). The worker asks its
                    # source the cheap question first and sweeps the whole catalogue
                    # only when the answer changed; the checkpoint lives here because
                    # the core is what stores the diff, so a worker restarted against a
                    # fresh installation is told it has never synced rather than left to
                    # guess a window for itself.
                    from app.services.breach_catalogue import (
                        catalogue_window,
                        stealer_logs_window,
                    )

                    job_params["catalogue"] = await catalogue_window(self.db, source)
                    # The stealer-log pass is not every scan: it spends a separately
                    # priced allowance, so the worker is told when the last pass ran
                    # and decides whether the interval has elapsed (WI-18). The core
                    # holds that fact because the worker may have restarted since.
                    job_params["stealer_logs"] = await stealer_logs_window(self.db, source)
                job = await JobService(self.db).create_job(
                    job_type=manifest["job_type"],
                    created_by=created_by,
                    title=f"{title} [{conn.name}]",
                    params=job_params,
                )
                job.connector_id = conn.id
                job.schedule_key = schedule_key
                if schedule_key:
                    self.db.add(ScheduleOccurrence(key=schedule_key, job_id=job.id, created_at=datetime.now(timezone.utc)))
                    from app.core.audit import AuditLogger
                    await AuditLogger.emit(self.db, action="source.scan.queued", user_id=created_by, ip_address="internal:scheduler", details={"job_id": str(job.id), "connector": conn.name, "scheduled_at": caller["scheduled_at"]}, require_persistence=True, commit=False)
                jobs.append(job)
            except Exception:
                for admitted_name, admitted_token in admitted:
                    await release_scan_slot(admitted_name, admitted_token)
                raise
        if admitted_out is not None:
            # The caller may own the commit; it needs the tokens to release if
            # that commit fails.
            admitted_out.extend(admitted)
        if commit:
            try:
                await self.db.commit()
            except Exception:
                # A transaction failure must not leave provider admission slots held
                # until their hour-long safety TTL. Release only the tokens claimed
                # by this enqueue attempt; the Redis operation is ownership-checked.
                for admitted_name, admitted_token in admitted:
                    await release_scan_slot(admitted_name, admitted_token)
                raise
        return jobs

    async def enqueue_ready_sources(
        self, *, connector_type, created_by, title, params=None, connector_name=None,
        audit: dict | None = None,
    ):
        """Independent admission: a blocked sibling never rolls back ready work.

        ``audit`` names an event that must become durable with the queued Jobs
        (``action``, optional ``user_id`` / ``ip_address`` and any extra
        ``details``). Passing it makes one commit own the whole request: the Job
        rows and the record of who asked for them can no longer diverge. Callers
        that keep their own event (the scheduler) leave it unset and commit here.
        """
        spec = await require_enabled_module(self.db, connector_type)
        sources: list[dict[str, object]] = []
        jobs: list[Job] = []
        admitted: list[tuple[str, str | None]] = []
        for conn in await self.list_connectors():
            if conn.connector_type != spec.id or (
                connector_name
                and conn.name != connector_name
                and connector_name not in (conn.aliases or [])
            ):
                continue
            if connector_name and conn.name in (conn.aliases or []):
                conn.aliases = list(conn.aliases or [])
            account = None
            if conn.provider:
                from app.models.source_account import SourceAccount

                account = (
                    await self.db.get(SourceAccount, conn.source_account_id)
                    if conn.source_account_id
                    else None
                )
                if account is None:
                    account = (
                        await self.db.execute(
                            select(SourceAccount).where(
                                SourceAccount.source_id == conn.provider,
                                SourceAccount.name == (conn.quota_group or "default"),
                            )
                        )
                    ).scalar_one_or_none()
            reason = None
            if not conn.is_enabled:
                reason = "disabled"
            elif not self.is_online(conn):
                reason = "offline"
            elif conn.provider and account is None:
                # Readiness cannot answer this one: a worker with no account row
                # was never set up, which is a different statement from an
                # account an operator has not approved yet, and it is the state
                # an upgraded installation is in until the seeder has run.
                reason = "provider_account_missing"
            elif conn.provider and not (conn.readiness or {}).get(
                "credentials_configured"
            ):
                reason = "unconfigured"
            elif conn.provider and (conn.readiness or {}).get("credential_state") in {
                "invalid",
                "unsupported",
            }:
                readiness = conn.readiness or {}
                reason = (
                    "invalid_credentials"
                    if readiness.get("credential_state") == "invalid"
                    else "unsupported"
                )
            elif conn.provider and not (conn.readiness or {}).get("capabilities"):
                reason = "unsupported"
            elif conn.provider and conn.last_success_at:
                last_success = conn.last_success_at
                if last_success.tzinfo is None:
                    last_success = last_success.replace(tzinfo=timezone.utc)
                if (datetime.now(timezone.utc) - last_success).total_seconds() < (
                    conn.config or {}
                ).get("cooldown_seconds", 60):
                    reason = "cooldown"
            if reason is None and conn.provider:
                if (
                    account is None
                    or (account.policy or {}).get("approved") is not True
                ):
                    reason = "account_policy_unapproved"
                else:
                    conn.source_account_id = account.id
                    await self.db.flush()
            if reason:
                sources.append({"connector": conn.name, "status": reason})
                continue
            try:
                queued = await self.enqueue_module_scan(
                    connector_type=spec.id,
                    created_by=created_by,
                    title=title,
                    params=params,
                    connector_name=conn.name,
                    require_online=True,
                    commit=False,
                    admitted_out=admitted,
                )
                jobs.extend(queued)
                sources.append(
                    {
                        "connector": conn.name,
                        "status": "queued",
                        "job_ids": [str(j.id) for j in queued],
                    }
                )
            except Exception as exc:
                from fastapi import HTTPException

                if not isinstance(exc, HTTPException):
                    raise
                sources.append(
                    {
                        "connector": conn.name,
                        "status": "blocked",
                        "reason": str(exc.detail),
                    }
                )
        result = {
            "status": "scheduled" if jobs else "blocked",
            "job_ids": [str(j.id) for j in jobs],
            "sources": sources,
        }
        try:
            if audit is not None:
                from app.core.audit import AuditLogger

                await AuditLogger.emit(
                    self.db,
                    action=audit["action"],
                    user_id=audit.get("user_id"),
                    ip_address=audit.get("ip_address"),
                    details={**result, **(audit.get("details") or {})},
                    require_persistence=True,
                    commit=False,
                )
            await self.db.commit()
        except Exception:
            # A refused audit write and a failed commit are the same thing to a
            # provider: the work was not recorded, so its admission slot must not
            # stay held until the hour-long safety TTL.
            for admitted_name, admitted_token in admitted:
                await release_scan_slot(admitted_name, admitted_token)
            raise
        return result

    async def module_job_types(self) -> dict[str, dict]:
        """Registered modules and the job types their connectors declare.

        The module list comes from the registry (data), so a module declared
        after the frontend was built already appears in job history filters and
        on its own page — with no connector registered yet, if that is the case.
        """
        rows = await self.list_connectors()
        specs = await load_modules(self.db)
        modules: dict[str, dict] = {
            module_id: {
                "label": spec.label,
                "description": spec.description,
                "job_types": [],
                "connectors": [],
                "finding_kind": spec.finding_kind,
                "asset_types": list(spec.asset_types),
                "storage": spec.storage_kind,
                "builtin": spec.builtin,
                "enabled": spec.enabled,
            }
            for module_id, spec in sorted(specs.items())
        }
        for conn in rows:
            manifest = resolve_manifest(
                module_spec=specs.get(conn.connector_type),
                connector_type=conn.connector_type,
                default_job_type=conn.default_job_type,
                manifest=conn.manifest,
            )
            entry = modules.setdefault(
                conn.connector_type,
                {
                    "label": conn.connector_type,
                    "description": "",
                    "job_types": [],
                    "connectors": [],
                    "finding_kind": "",
                    "asset_types": [],
                    "storage": "generic",
                    "builtin": False,
                    "enabled": False,
                },
            )
            entry["finding_kind"] = entry["finding_kind"] or manifest["finding_kind"]
            entry["connectors"].append(
                {
                    "name": conn.name,
                    "status": conn.status,
                    "job_type": manifest["job_type"],
                    "asset_types": manifest["asset_types"],
                    "config_schema": manifest["config_schema"],
                }
            )
            if manifest["job_type"] not in entry["job_types"]:
                entry["job_types"].append(manifest["job_type"])
        return modules

    async def registered_job_types(self) -> list[str]:
        """Flat list of every job type the registry can produce."""
        modules = await self.module_job_types()
        seen: list[str] = []
        for entry in modules.values():
            for job_type in entry["job_types"]:
                if job_type not in seen:
                    seen.append(job_type)
        return seen

    async def _active_asset_snapshot(
        self,
        asset_types: list[str] | None = None,
        *,
        include_candidates: bool = False,
    ) -> dict:
        """Return the active asset inventory in the connector scan-param shape.

        ``asset_types`` is the connector's declared inventory appetite: a
        phishing look-alike connector that declared only ``domain`` receives
        ``domains`` and an empty ``emails`` list, so it is not handed data it has
        no use for. A connector that declared no sections receives the whole
        inventory, which is what a source that consumes everything wants.
        ``domain`` values feed both ``domains`` and, paired with their type,
        ``keyword_domains``; ``domain``/``ip_address`` assets form the exclude
        set so owned hosts are never flagged.

        ``include_candidates`` adds the candidates an analyst has *confirmed*, each
        with the asset it was matched to. The point of the list is the opposite of the
        exclude set: an owned name is never scanned, and a confirmed look-alike is the
        one name a provider can usefully be asked about again (what it serves, when it
        was registered, whether it receives mail). Only the phishing module asks for
        it - every other module's question starts from the inventory, not from a
        finding - and only a confirmed verdict qualifies, because a candidate nobody
        has reviewed is a guess the platform is still making rather than a fact it
        would spend provider quota re-reading.
        """
        from sqlalchemy import select

        from app.models import Asset, AssetType

        wanted = {str(value) for value in (asset_types or [])}

        def _wants(asset_type: str) -> bool:
            return not wanted or asset_type in wanted

        from app.services.asset_matching import POLICY_SCAN, asset_scope

        rows = (
            await self.db.execute(
                select(Asset.asset_type, Asset.asset_value).where(*asset_scope(POLICY_SCAN))
            )
        ).all()
        ips: list[str] = []
        domains: list[str] = []
        emails: list[str] = []
        keyword_domains: list[dict] = []
        keyword_titles: list[str] = []
        exclude: list[str] = []
        for asset_type, raw_value in rows:
            # Deliberately the value as stored. The connector scans what the
            # operator entered, and `/me/work` has always handed out this form;
            # the canonical form belongs to the comparison that decides whether a
            # finding belongs to the scan (`ingestion_service._exposure`), which
            # canonicalizes both sides itself. Sending a canonicalized value from
            # here would leave that comparison looking at two different spellings
            # of the same asset and silently refuse correct findings.
            value = str(raw_value).strip()
            if not value:
                continue
            at = (
                asset_type.value
                if isinstance(asset_type, AssetType)
                else str(asset_type)
            )
            if at == AssetType.domain.value and _wants(AssetType.domain.value):
                domains.append(value)
                keyword_domains.append({"value": value, "type": "domain"})
                exclude.append(value)
            elif at == AssetType.email_account.value and _wants(
                AssetType.email_account.value
            ):
                emails.append(value)
            elif at == AssetType.keyword_domain.value and _wants(
                AssetType.keyword_domain.value
            ):
                keyword_domains.append({"value": value, "type": "keyword_domain"})
            elif at == AssetType.keyword_title.value and _wants(
                AssetType.keyword_title.value
            ):
                keyword_titles.append(value)
            elif at == AssetType.ip_address.value and _wants(
                AssetType.ip_address.value
            ):
                ips.append(value)
                exclude.append(value)
        candidates: list[dict] = []
        if include_candidates:
            from app.models import PhishingDomain

            blocked = set(exclude)
            confirmed = (
                await self.db.execute(
                    select(
                        PhishingDomain.phishing_domain, PhishingDomain.matched_asset
                    )
                    .where(PhishingDomain.verdict == "confirmed")
                    .order_by(
                        PhishingDomain.confidence.desc(),
                        PhishingDomain.created_at.desc(),
                    )
                    .limit(MAX_SCAN_CANDIDATES)
                )
            ).all()
            for candidate_domain, matched in confirmed:
                value = str(candidate_domain or "").strip().lower()
                if not value or value in blocked:
                    continue
                candidates.append(
                    {
                        "value": value,
                        "matched_asset": str(matched or "")[:512] or value,
                    }
                )
        return {
            "domains": domains,
            "ips": ips,
            "emails": emails,
            "keyword_domains": keyword_domains,
            "keyword_titles": keyword_titles,
            "exclude": exclude,
            "candidates": candidates,
        }
