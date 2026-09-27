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
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import BadRequestException, ForbiddenException, NotFoundException
from app.models import Connector, ConnectorStatus, Job, JobStatus
from app.services.connector_manifest import (
    build_manifest,
    provisioning_job_type,
    resolve_manifest,
)
from app.services.job_service import JobService
from app.services.scan_admission import NoEnabledConnector, acquire as acquire_scan_slot, release as release_scan_slot
from app.core.safe_errors import sanitize_external_error
from app.services.module_registry import (
    load_modules,
    require_enabled_module,
    require_module,
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


class ConnectorService:
    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------
    # Registration & lookup
    # ------------------------------------------------------------------

    async def get_by_name(self, name: str) -> Connector | None:
        stmt = select(Connector).where(Connector.name == name)
        return (await self.db.execute(stmt)).scalar_one_or_none()

    async def list_connectors(self) -> list[Connector]:
        stmt = select(Connector).order_by(Connector.connector_type, Connector.name)
        return list((await self.db.execute(stmt)).scalars().all())

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
        module_spec = await require_enabled_module(self.db, connector_type)
        clean = normalize_connector_name(name)
        safe_info: dict = {}
        for k, v in (info or {}).items():
            if str(k) in _ALLOWED_INFO_KEYS:
                safe_info[str(k)] = str(v)[:200]

        existing = await self.get_by_name(clean)
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
        await self._assert_job_type_available(manifest["job_type"], owner=clean)

        if existing is None:
            existing = Connector(
                name=clean,
                connector_type=connector_type,
                status=ConnectorStatus.ENABLED,
            )
            self.db.add(existing)
        existing.default_job_type = manifest["job_type"]
        existing.manifest = manifest
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

    async def set_status(self, connector_id: uuid.UUID, status: str) -> Connector:
        if status not in ConnectorStatus.ALL:
            raise BadRequestException("status must be 'enabled' or 'disabled'")
        conn = await self.db.get(Connector, connector_id)
        if conn is None:
            raise NotFoundException("Connector not found")
        conn.status = status
        await self.db.commit()
        await self.db.refresh(conn)
        return conn

    async def set_config(self, connector_id: uuid.UUID, config: dict) -> Connector:
        if not isinstance(config, dict):
            raise BadRequestException("config must be an object")
        conn = await self.db.get(Connector, connector_id)
        if conn is None:
            raise NotFoundException("Connector not found")
        conn.config = config
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
            Job.job_type == connector.default_job_type,
        ]
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
        now = datetime.now(timezone.utc)
        await self.recover_expired_jobs(now=now)
        job.status = JobStatus.running
        job.started_at = now
        job.last_heartbeat_at = now
        job.attempt_count = (job.attempt_count or 0) + 1
        job.claimed_by_connector = connector.name
        job.lease_token = secrets.token_urlsafe(32)
        job.lease_expires_at = now + timedelta(seconds=settings.CONNECTOR_JOB_LEASE_SECONDS)
        connector.touch()
        await self.db.commit()
        await self.db.refresh(job)
        return job

    async def complete_job(
        self, connector: Connector, job_id: uuid.UUID, *, result_summary: dict | None,
        lease_token: str,
    ) -> Job:
        job = await self._owned_job(connector, job_id, lease_token=lease_token)
        summary_status = result_summary.get("status") if isinstance(result_summary, dict) else None
        if summary_status == "error":
            error_code = result_summary.get("error_code") if isinstance(result_summary, dict) else None
            await JobService(self.db).fail_job(
                job_id,
                error_message=sanitize_external_error(error_code or "connector provider error", limit=8000),
                result_summary=result_summary,
            )
        else:
            await JobService(self.db).complete_job(job_id, result_summary=result_summary)
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
        connector.last_error = None
        await self.db.commit()
        await self.db.refresh(job)
        return job

    async def fail_job(self, connector: Connector, job_id: uuid.UUID, *, error: str, lease_token: str) -> Job:
        job = await self._owned_job(connector, job_id, lease_token=lease_token)
        await JobService(self.db).fail_job(job_id, error_message=error or "connector failure")
        job_params = job.params if isinstance(job.params, dict) else {}
        await release_scan_slot(connector.name, job_params.get("scan_admission_token"))
        job.lease_expires_at = None
        job.last_heartbeat_at = datetime.now(timezone.utc)
        job.lease_token = None
        connector.touch()
        connector.last_error = sanitize_external_error(error or "connector failure", limit=2000)
        await self.db.commit()
        await self.db.refresh(job)
        return job

    async def heartbeat(self, connector: Connector, *, job_id: uuid.UUID | None = None, lease_token: str | None = None) -> None:
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
            job.lease_expires_at = now + timedelta(seconds=settings.CONNECTOR_JOB_LEASE_SECONDS)
        await self.db.commit()

    async def recover_expired_jobs(self, *, now: datetime | None = None) -> int:
        """Recover connector jobs whose owner stopped renewing its lease."""
        current = now or datetime.now(timezone.utc)
        result = await self.db.execute(
            select(Job).where(
                Job.status == JobStatus.running,
                Job.lease_expires_at.is_not(None),
                Job.lease_expires_at < current,
            ).with_for_update(skip_locked=True)
        )
        recovered = 0
        for job in result.scalars().all():
            if (job.attempt_count or 0) < settings.CONNECTOR_JOB_MAX_ATTEMPTS:
                job.status = JobStatus.pending
                job.error_message = "Connector lease expired; job returned to the queue."
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

    async def _owned_job(self, connector: Connector, job_id: uuid.UUID, *, lease_token: str) -> Job:
        """Fetch a job this connector has claimed; 403/404 otherwise.

        Ownership is read from ``claimed_by_connector`` and proved with the lease
        token the claim handed out. Both are required: the connector name says
        which worker may touch the job, and the token says whether the claim it
        is acting on is still the current one, so a stale worker cannot finalize
        a job that was reclaimed after its lease expired.
        """
        job = await self.db.get(Job, job_id)
        if job is None:
            raise NotFoundException("Job not found")
        if job.claimed_by_connector != connector.name:
            raise ForbiddenException("Job not claimed by this connector")
        if job.lease_token is None or lease_token != job.lease_token:
            raise ForbiddenException("Job lease is no longer valid")
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
    ) -> list[Job]:
        """Create pending scan jobs for enabled connectors of a module.

        With ``connector_name`` set, only that single (enabled) connector gets
        a job — used by the manual per-source endpoints. Without it, every
        enabled connector of the module gets a job — used by the scheduler so
        all sources of a module run on their schedule. Connectors pick the work
        up via their work-poll; the core stays stateless with respect to
        connector execution.

        Each job carries the connector's own declared job type and the subset of
        the asset inventory that connector said it consumes.
        """
        # Registry-driven: any declared module can be scanned, and an unknown
        # module is refused with the list of modules that do exist.
        module_spec = await require_module(self.db, connector_type)
        connector_type = module_spec.id
        connectors = await self.list_enabled_by_type(connector_type)
        if connector_name:
            wanted = normalize_connector_name(connector_name)
            connectors = [c for c in connectors if c.name == wanted]
        if not connectors:
            target = connector_name or connector_type
            raise NoEnabledConnector(
                f"No enabled connector is registered for '{target}'. "
                "Start the worker container and wait for it to register."
            )
        caller = dict(params or {})
        trigger = caller.pop("trigger", None)
        specs = await load_modules(self.db)
        jobs: list[Job] = []
        admitted: list[tuple[str, str | None]] = []
        for conn in connectors:
            # One distributed slot per connector prevents two users, the
            # scheduler, or separate API replicas from spending the same
            # provider quota on identical work. The token is carried in the job
            # params and released when the connector reports a terminal result.
            try:
                admission_token = await acquire_scan_slot(conn.name, ttl_seconds=3600)
                admitted.append((conn.name, admission_token))
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
                snapshot = await self._active_asset_snapshot(manifest["asset_types"])
                job = await JobService(self.db).create_job(
                    job_type=manifest["job_type"],
                    created_by=created_by,
                    title=f"{title} [{conn.name}]",
                    params={
                        **snapshot,
                        **caller,
                        "connector": conn.name,
                        "module": conn.connector_type,
                        "trigger": trigger,
                        "scan_admission_token": admission_token,
                    },
                )
                jobs.append(job)
            except Exception:
                for admitted_name, admitted_token in admitted:
                    await release_scan_slot(admitted_name, admitted_token)
                raise
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

    async def _active_asset_snapshot(self, asset_types: list[str] | None = None) -> dict:
        """Return the active asset inventory in the connector scan-param shape.

        ``asset_types`` is the connector's declared inventory appetite: a
        phishing look-alike connector that declared only ``domain`` receives
        ``domains`` and an empty ``emails`` list, so it is not handed data it has
        no use for. A connector that declared no sections receives the whole
        inventory, which is what a source that consumes everything wants.
        ``domain`` values feed both ``domains`` and, paired with their type,
        ``keyword_domains``; ``domain``/``ip_address`` assets form the exclude
        set so owned hosts are never flagged.
        """
        from sqlalchemy import select

        from app.models import Asset, AssetType

        wanted = {str(value) for value in (asset_types or [])}

        def _wants(asset_type: str) -> bool:
            return not wanted or asset_type in wanted

        rows = (
            await self.db.execute(
                select(Asset.asset_type, Asset.asset_value).where(Asset.is_active.is_(True))
            )
        ).all()
        domains: list[str] = []
        emails: list[str] = []
        keyword_domains: list[dict] = []
        keyword_titles: list[str] = []
        exclude: list[str] = []
        for asset_type, raw_value in rows:
            value = str(raw_value).strip()
            if not value:
                continue
            at = asset_type.value if isinstance(asset_type, AssetType) else str(asset_type)
            if at == AssetType.domain.value and _wants(AssetType.domain.value):
                domains.append(value)
                keyword_domains.append({"value": value, "type": "domain"})
                exclude.append(value)
            elif at == AssetType.email_account.value and _wants(AssetType.email_account.value):
                emails.append(value)
            elif at == AssetType.keyword_domain.value and _wants(AssetType.keyword_domain.value):
                keyword_domains.append({"value": value, "type": "keyword_domain"})
            elif at == AssetType.keyword_title.value and _wants(AssetType.keyword_title.value):
                keyword_titles.append(value)
            elif at == AssetType.ip_address.value and _wants(AssetType.ip_address.value):
                exclude.append(value)
        return {
            "domains": domains,
            "emails": emails,
            "keyword_domains": keyword_domains,
            "keyword_titles": keyword_titles,
            "exclude": exclude,
        }
