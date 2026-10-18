"""Connector protocol API (OpenCTI-style core+connector architecture).

Two route groups:

* Connector-side — authenticated by the connector's **own** credential in the
  ``X-Connector-Token`` header. Identity is derived from the credential, so a
  token cannot be used to act as another connector; an optional
  ``X-Connector-Name`` header is only checked for agreement. Used by connector
  containers to register, long-poll for scan work, submit findings, heartbeat
  and report completion.
* Admin-side — regular JWT auth. Used by the UI to list connectors, toggle
  their enabled/disabled status, edit per-connector config and issue or revoke
  their tokens.
"""

import re
import uuid
from datetime import datetime, timedelta, timezone

import structlog
from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field, StrictBool, StrictInt, ValidationError, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    enforce_connector_protocol_rate_limit,
    extract_ip,
    get_db,
    require_admin,
    require_active_account,
)
from app.core.audit import AuditLogger, bound_details
from app.core.config import settings
from app.core.exceptions import (
    BadRequestException,
    ForbiddenException,
    UnauthorizedException,
)
from app.models import Connector
from app.schemas.common import MAX_PAGE_SIZE, PaginatedResponse
from app.schemas.connector import (
    MAX_CATALOGUE_ENTRIES_PER_BATCH,
    MAX_FINDINGS_PER_BATCH,
    BreachCatalogueEntry,
)
from app.schemas.job import JobResponse
from app.services.connector_manifest import (
    ConfigField,
    ModuleSpec,
    finding_adapter_for,
    resolve_manifest,
    validate_connector_config,
)
from app.services.connector_credentials import (
    ConnectorCredentials,
    connector_name_from_token,
)
from app.services.connector_service import ConnectorService, normalize_connector_name
from app.services.module_registry import load_modules, require_enabled_module

log = structlog.get_logger()

#: A refused credential stays refused until an operator replaces it, and a
#: connector polls every few seconds — so the diagnostic line below is written
#: when the *situation* is new, not on every attempt. Keyed by what the line
#: says, so one connector's stale token cannot hide another's.
_REJECTION_LOG_INTERVAL = timedelta(minutes=1)
_REJECTION_LOG_MAX_KEYS = 512
_rejection_log_seen: dict[tuple[str, str], datetime] = {}


def _note_rejected_credential(request: Request, token: str | None) -> None:
    """Record *which* connector's credential was refused, on the platform's side.

    Without this, a stale token left the core answering a bare 401 for as long
    as the connector kept trying: the only explanation was the connector's own
    exit message, which an operator has to find among a crash loop's logs, and
    the registry showed the connector as merely unseen. The name is read from
    the token's own label (`opendrp_<name>_<random>`) as a hint for that line —
    never as identity, since a caller chooses it (see
    `connector_name_from_token`).
    """
    hint = connector_name_from_token(token) or "unlabelled"
    ip_address = extract_ip(request)
    now = datetime.now(timezone.utc)
    key = (hint, ip_address)
    last = _rejection_log_seen.get(key)
    if last is not None and now - last < _REJECTION_LOG_INTERVAL:
        return
    if len(_rejection_log_seen) >= _REJECTION_LOG_MAX_KEYS:
        _rejection_log_seen.clear()
    _rejection_log_seen[key] = now
    log.warning(
        "connector_credential_rejected",
        connector_name_hint=hint,
        path=request.url.path,
        ip_address=ip_address,
    )


router = APIRouter(prefix="/connectors", tags=["Connectors"])


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------


async def require_connector(
    request: Request,
    x_connector_token: str | None = Header(default=None),
    x_connector_name: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
) -> Connector:
    """Resolve the calling connector from its own credential.

    Authority comes from the stored digest of the presented token, never from a
    caller-supplied name. The name header is optional and, when present, only
    has to agree with the credential — so a leaked token cannot be replayed as a
    different connector, and a caller cannot claim work it does not own.

    A refusal is recorded in the log with the name the *token* carries, so the
    operator who has to replace a credential reads which connector needs it,
    rather than a 401 with no subject (see `_note_rejected_credential`).

    The per-address bound runs first, before the credential lookup: a flood of
    made-up tokens must not cost one database query per request.
    """
    await enforce_connector_protocol_rate_limit(request)
    credentials = ConnectorCredentials(db)
    connector = await credentials.resolve(x_connector_token or "")
    if connector is None:
        _note_rejected_credential(request, x_connector_token)
        raise UnauthorizedException("Invalid or missing connector token")
    if x_connector_name:
        try:
            claimed = normalize_connector_name(x_connector_name)
        except BadRequestException:
            claimed = ""
        if claimed and claimed != connector.name and claimed not in (connector.aliases or []):
            raise ForbiddenException("Connector token does not belong to that connector")
    await credentials.touch_last_used(connector)
    return connector


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ConnectorRegisterRequest(BaseModel):
    """Self-declaring registration payload.

    The declaration is the connector's identity in the registry, so it is
    required rather than inferred: ``default_job_type`` is the work this
    connector alone claims, and ``api_version`` is what tells a silent worker
    apart from a current one. ``finding_kind``, ``asset_types`` and
    ``config_schema`` may be omitted, and are then taken from the module whose
    record is the authority (see ``app/services/connector_manifest.py``).
    """

    model_config = {"extra": "forbid"}

    name: str = Field(min_length=1, max_length=100)
    connector_type: str = Field(min_length=1, max_length=32)
    api_version: str = Field(min_length=1, max_length=32)
    protocol_version: int = Field(default=2, ge=2, le=2)
    info: dict[str, str] | None = None
    #: Job type this connector alone claims, e.g. ``phishing.dnstwist``.
    default_job_type: str = Field(min_length=3, max_length=50)
    #: Kind of finding it submits; must belong to ``connector_type``.
    finding_kind: str | None = Field(default=None, max_length=32)
    #: Asset inventory sections it consumes.
    asset_types: list[str] | None = Field(default=None, max_length=16)
    #: Operator-editable settings it accepts.
    config_schema: dict[str, ConfigField] | None = Field(default=None, max_length=32)

    @field_validator("name", "connector_type", "api_version", "default_job_type", "finding_kind")
    @classmethod
    def _no_control_chars(cls, value: str | None) -> str | None:
        if value is not None and any(ch in value for ch in "\x00\r\n"):
            raise ValueError("connector metadata contains control characters")
        return value.strip() if value is not None else None


class ConnectorWorkResponse(BaseModel):
    job_id: str
    lease_token: str | None = None
    lease_seconds: int = 180
    protocol_version: int = 2
    job_type: str
    connector: str
    module: str | None = None
    config: dict = Field(default_factory=dict)
    params: dict | None = None
    created_at: datetime | None = None

    @field_validator("job_id", mode="before")
    @classmethod
    def _stringify_id(cls, v):
        return str(v) if v is not None else v


class ConnectorCompleteRequest(BaseModel):
    model_config = {"extra": "forbid"}

    ok: bool = True
    summary: dict[str, object] | None = Field(default=None, max_length=64)
    error: str | None = Field(default=None, max_length=4000)

    @field_validator("summary")
    @classmethod
    def _bound_summary(cls, value: dict[str, object] | None) -> dict[str, object] | None:
        """A connector's own account of a scan is bounded before it is stored.

        The summary is written to the job record and copied into the audit
        trail, so its size is decided by a half-trusted caller unless the wire
        schema decides it. The number of keys was already capped; strings,
        lists and nesting were not.
        """
        if value is None:
            return None
        return bound_details(value)  # type: ignore[return-value]
    #: The token this claim returned. Required: it is the proof that the claim
    #: being finalized is still the current one.
    lease_token: str = Field(min_length=16, max_length=64)

    @field_validator("error")
    @classmethod
    def _clean_error(cls, value: str | None) -> str | None:
        if value is not None and any(ch in value for ch in "\x00\r\n"):
            raise ValueError("error contains control characters")
        return value


class HeartbeatRequest(BaseModel):
    """Liveness report from a connector.

    A bare heartbeat (no job) only says the worker is alive. A heartbeat that
    names a job renews that job's lease and therefore carries the job's lease
    token, which the service requires.
    """

    status: str | None = Field(default=None, max_length=32)
    job_id: uuid.UUID | None = None
    lease_token: str | None = Field(default=None, min_length=16, max_length=64)


class ConnectorOut(BaseModel):
    id: uuid.UUID
    name: str
    connector_type: str
    status: str
    api_version: str | None
    default_job_type: str
    #: Self-declared manifest (module, job_type, finding_kind, asset_types,
    #: config_schema). The UI renders the config form from it instead of
    #: hardcoding per-vendor fields.
    manifest: dict | None = None
    config: dict | None
    last_seen_at: datetime | None
    last_error: str | None
    info: dict | None
    created_at: datetime
    updated_at: datetime
    #: Credential state. The digest is deliberately absent: only the public
    #: prefix travels, so an operator can tell *which* token is in use without
    #: being handed material they could authenticate with.
    provider: str | None = None
    source_account_id: uuid.UUID | None = None
    quota_group: str | None = None
    readiness: dict | None = None
    last_success_at: datetime | None = None
    has_token: bool = False
    token_prefix: str | None = None
    token_created_at: datetime | None = None
    token_last_used_at: datetime | None = None

    model_config = {"from_attributes": True}


#: What a source may report as its last provider error. The write endpoint
#: validates this already; the read repeats it because a row written before that
#: constraint existed, or restored from a backup, is still served to viewers, and
#: this field is meant to be a closed vocabulary with no provider prose in it.
_PROVIDER_ERROR_RE = re.compile(
    r"^(invalid_credentials|ip_restricted|access_denied|credits_exhausted|rate_limited|"
    r"provider_application_error|provider_rejected_request|network_or_invalid_response|"
    r"http_[0-9]{3})$"
)
_CREDENTIAL_STATES = frozenset({"valid", "invalid", "unsupported", "unknown"})


class ConnectorStatusUpdate(BaseModel):
    status: str

    @field_validator("status")
    @classmethod
    def _valid_status(cls, v: str) -> str:
        if v not in ("enabled", "disabled"):
            raise ValueError("status must be 'enabled' or 'disabled'")
        return v


def _manifest_of(conn: Connector, specs: dict[str, ModuleSpec]) -> dict:
    """Resolve a stored connector's declared manifest against the module registry."""
    return resolve_manifest(
        module_spec=specs.get(conn.connector_type),
        connector_type=conn.connector_type,
        default_job_type=conn.default_job_type,
        manifest=conn.manifest,
    )


def _connector_out(conn: Connector, specs: dict[str, ModuleSpec]) -> ConnectorOut:
    """Serialize a connector with its resolved (never-None) manifest."""
    return ConnectorOut(
        id=conn.id,
        name=conn.name,
        connector_type=conn.connector_type,
        status=conn.status,
        api_version=conn.api_version,
        default_job_type=conn.default_job_type,
        manifest=_manifest_of(conn, specs),
        config=conn.config,
        last_seen_at=conn.last_seen_at,
        last_error=conn.last_error,
        info=conn.info,
        created_at=conn.created_at,
        updated_at=conn.updated_at,
        provider=conn.provider,
        source_account_id=conn.source_account_id,
        quota_group=conn.quota_group,
        readiness=conn.readiness,
        last_success_at=conn.last_success_at,
        has_token=conn.has_token,
        token_prefix=conn.token_prefix,
        token_created_at=conn.token_created_at,
        token_last_used_at=conn.token_last_used_at,
    )


# ---------------------------------------------------------------------------
# Connector-side endpoints (X-Connector-Token)
# ---------------------------------------------------------------------------


@router.post("/register", response_model=ConnectorOut)
async def register_connector(
    request: Request,
    payload: ConnectorRegisterRequest,
    db: AsyncSession = Depends(get_db),
    caller: Connector = Depends(require_connector),
):
    """Let the authenticated connector (re)declare its own manifest.

    Identity comes from the credential, never from the payload: a connector may
    only describe itself. Without this check a valid token could create or
    rewrite another connector's registry row — and registration upserts by name,
    so the payload name must match the credential before anything is written.
    """
    if normalize_connector_name(payload.name) != caller.name and normalize_connector_name(payload.name) not in (caller.aliases or []):
        raise ForbiddenException("Connector token does not belong to that connector")
    svc = ConnectorService(db)
    conn = await svc.register(
        name=payload.name,
        connector_type=payload.connector_type,
        api_version=payload.api_version,
        info=payload.info,
        default_job_type=payload.default_job_type,
        finding_kind=payload.finding_kind,
        asset_types=payload.asset_types,
        config_schema=(
            {key: field.model_dump(exclude_none=True) for key, field in payload.config_schema.items()}
            if payload.config_schema
            else None
        ),
    )
    await AuditLogger.emit_background(
        db,
        action="connector.registered",
        ip_address=extract_ip(request),
        user_id=None,
        details={
            "name": conn.name,
            "type": conn.connector_type,
            "api_version": conn.api_version,
            "job_type": conn.default_job_type,
        },
    )
    return _connector_out(conn, await load_modules(db))


class SourceReadiness(BaseModel):
    model_config = {"extra": "forbid"}
    credentials_configured: bool
    credential_state: str = Field(default="unknown", pattern="^(unknown|valid|invalid|unsupported)$")
    provider_error: str | None = Field(default=None, pattern="^(invalid_credentials|ip_restricted|access_denied|credits_exhausted|rate_limited|provider_application_error|provider_rejected_request|network_or_invalid_response|http_[0-9]{3})$", max_length=64)
    capabilities: list[str] = Field(default_factory=list, max_length=32)
    operations: list[str] = Field(default_factory=list, max_length=32)
    #: The source's own names for the classes of data it reports, when it publishes them
    #: (``{"Email addresses": "Email addresses"}``): the page renders a stored class
    #: through this map so an analyst reads the provider's vocabulary instead of a label
    #: the platform invented (F-04). Bounded, because it is a provider's list.
    data_class_labels: dict[str, str] = Field(default_factory=dict)

    @field_validator("data_class_labels")
    @classmethod
    def _bounded_labels(cls, value: dict) -> dict:
        if len(value) > 200:
            raise ValueError("data_class_labels carries more than 200 entries")
        cleaned: dict[str, str] = {}
        for key, label in value.items():
            if not isinstance(key, str) or not isinstance(label, str):
                raise ValueError("data_class_labels is a map of strings to strings")
            if not key.strip() or not label.strip():
                raise ValueError("data_class_labels entries must not be empty")
            if len(key) > 128 or len(label) > 256:
                raise ValueError("data_class_labels entry is too long")
            cleaned[key.strip()] = label.strip()
        return cleaned

    @field_validator("capabilities", "operations")
    @classmethod
    def _namespaced_identifiers(cls, values):
        import re
        if any(not re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", value) for value in values):
            raise ValueError("Invalid capability or operation identifier")
        return list(dict.fromkeys(values))


@router.post("/me/readiness")
async def source_readiness(payload: SourceReadiness, db: AsyncSession = Depends(get_db), caller: Connector = Depends(require_connector)):
    # A later readiness heartbeat must not erase a recent actionable provider
    # error until a successful provider request clears it explicitly.
    incoming = payload.model_dump()
    previous_error = (caller.readiness or {}).get("provider_error")
    if incoming["provider_error"] is None and previous_error and payload.credential_state != "valid":
        incoming["provider_error"] = previous_error
    incoming["checked_at"] = datetime.now(timezone.utc).isoformat()
    caller.readiness = incoming
    await db.commit()
    return {"status": "ok", "enabled": caller.is_enabled}


@router.post("/me/quota/provider")
async def provider_reservation(job_id: uuid.UUID, x_connector_lease: str = Header(..., min_length=16, max_length=64), bucket: str = Query("search", pattern=r"^[a-z][a-z0-9_.-]{0,63}$"), db: AsyncSession = Depends(get_db), caller: Connector = Depends(require_connector)):
    from app.services.provider_quota import reserve
    await require_enabled_module(db, caller.connector_type)
    job = await ConnectorService(db)._owned_job(caller, job_id, lease_token=x_connector_lease)
    return await reserve(db, caller, bucket, job=job)


@router.get("/me/control")
async def source_control(db: AsyncSession = Depends(get_db), caller: Connector = Depends(require_connector)):
    modules = await load_modules(db)
    spec = modules.get(caller.connector_type)
    return {"enabled": caller.is_enabled and bool(spec and spec.enabled), "config": caller.config or {}}


@router.get("/me/credential", response_model=dict)
async def connector_credential(request: Request, response: Response, db: AsyncSession = Depends(get_db), caller: Connector = Depends(require_connector)):
    """The provider key bound to this connector's account, for its own use only.

    The response is never cacheable. Each disclosure is audited by connector and
    account, never by value.
    """
    from app.services.source_accounts import api_key_for_connector
    response.headers["Cache-Control"] = "no-store"
    api_key = await api_key_for_connector(db, caller)
    if api_key is None:
        return {"configured": False}
    await AuditLogger.emit(db, action="connector.credential.read", ip_address=extract_ip(request), user_id=None, details={"connector_id": str(caller.id), "account_id": str(caller.source_account_id)})
    await db.commit()
    return {"configured": True, "api_key": api_key}


@router.post("/me/quota/virustotal", response_model=dict)
async def reserve_virustotal_request(
    caller: Connector = Depends(require_connector),
):
    """Atomically reserve one public VT request against replica-shared quotas."""
    raise HTTPException(410, "Reserve quota through the lease-bound /me/quota/provider endpoint")


@router.get("/me/work", response_model=ConnectorWorkResponse | None)
async def get_work(
    db: AsyncSession = Depends(get_db),
    caller: Connector = Depends(require_connector),
) -> ConnectorWorkResponse | Response:
    """Long-poll: atomically claim one pending scan job (204 when empty).

    Work is claimed for the connector the credential identifies, so a leaked
    token cannot pick up another connector's scan queue.
    """
    svc = ConnectorService(db)
    conn = caller
    job = await svc.claim_work(conn)
    if job is None:
        return Response(status_code=204)
    return ConnectorWorkResponse(
        job_id=str(job.id),
        lease_token=job.lease_token,
        lease_seconds=settings.CONNECTOR_JOB_LEASE_SECONDS,
        job_type=job.job_type,
        connector=conn.name,
        module=conn.connector_type,
        config=(job.params if isinstance(job.params, dict) else {}).get("config_snapshot", conn.config or {}),
        # Claim flow always stores a dict under params; a JSON list payload
        # is not representable in the work response schema.
        params=job.params if isinstance(job.params, dict) else None,
        created_at=job.created_at,
    )


@router.post("/me/findings/{job_id}")
async def submit_findings(
    request: Request,
    job_id: uuid.UUID,
    payload: list[dict] = Body(..., max_length=MAX_FINDINGS_PER_BATCH),
    x_connector_lease: str = Header(..., min_length=16, max_length=64),
    #: The batch's position in this job, sent by the SDK. Optional: a connector
    #: built against the older protocol still submits, it just cannot be ordered.
    x_connector_batch_index: int | None = Header(default=None, ge=1, le=100_000),
    #: How many batches this scan will send. Known only when the SDK submits a
    #: complete list; a worker that streams as it scans honestly sends none.
    x_connector_batch_total: int | None = Header(default=None, ge=1, le=100_000),
    db: AsyncSession = Depends(get_db),
    caller: Connector = Depends(require_connector),
):
    """Validate and ingest a bounded batch of findings for a claimed job.

    The batch is bound to the job's lease: findings are accepted only from the
    connector that currently owns the claim, which is what stops a job whose
    lease expired from still writing data under the old worker's name.
    """
    from app.services.ingestion_service import ingest_findings

    svc = ConnectorService(db)
    conn = caller
    job = await svc._owned_job(conn, job_id, lease_token=x_connector_lease)
    if len(payload) > MAX_FINDINGS_PER_BATCH:
        raise BadRequestException(
            f"findings batch cannot contain more than {MAX_FINDINGS_PER_BATCH} items"
        )

    # Validate the wire payload before any persistence. The connector's own
    # manifest says which finding kind it emits, so the core never infers the
    # schema from the connector's identity — and never calls provider code.
    specs = await load_modules(db)
    manifest = (job.params if isinstance(job.params, dict) else {}).get("manifest_snapshot") or _manifest_of(conn, specs)
    module_spec = specs.get(manifest["module"])
    finding_adapter = finding_adapter_for(module_spec) if module_spec is not None else None
    if module_spec is None or finding_adapter is None:
        raise BadRequestException(
            f"connector '{conn.name}' belongs to module '{manifest.get('module')}', "
            "which this platform cannot persist findings for"
        )
    try:
        validated_findings = finding_adapter.validate_python(payload)
    except ValidationError as exc:
        raise BadRequestException(
            {"message": "invalid connector finding payload", "errors": exc.errors()[:20]}
        ) from exc

    # Snapshot scalar metadata before ingestion commits can expire ORM state.
    conn_name = conn.name
    conn_kind = manifest["finding_kind"]
    result = await ingest_findings(
        db,
        connector=conn,
        job_id=job.id,
        findings=[finding.model_dump(mode="json") for finding in validated_findings],
        connector_name=conn_name,
        connector_type=conn.connector_type,
        finding_kind=conn_kind,
        module_spec=module_spec,
    )
    accepted, rejected = result.accepted, result.rejected
    # Audit failure must not roll back an already acknowledged ingestion batch.
    await db.commit()
    await AuditLogger.emit_background(
        db,
        action="connector.findings.ingested",
        ip_address=extract_ip(request),
        user_id=None,
        details={
            "connector": conn_name,
            "job_id": str(job_id),
            # The batch is the unit this row records: without its size a reader
            # cannot tell one 10-finding delivery from one 500-finding delivery,
            # and the scan's row count has no denominator.
            "batch_size": len(payload),
            "batch_index": x_connector_batch_index,
            "batch_total": x_connector_batch_total,
            "accepted": accepted,
            "rejected": rejected,
        },
    )
    await db.commit()
    return result.payload()


@router.post("/me/catalogue/{job_id}")
async def submit_catalogue(
    request: Request,
    job_id: uuid.UUID,
    payload: list[BreachCatalogueEntry] = Body(
        ..., max_length=MAX_CATALOGUE_ENTRIES_PER_BATCH
    ),
    x_connector_lease: str = Header(..., min_length=16, max_length=64),
    db: AsyncSession = Depends(get_db),
    caller: Connector = Depends(require_connector),
):
    """Accept a bounded batch of a source's own incident catalogue (F-09, WI-13).

    The connector's read of its source's catalogue, not a finding: an entry describes an
    incident at large, and whether any address of ours is in it is what makes it this
    installation's incident. The core owns the diff — the provider has no "added since"
    question to ask — so what arrives is stored against ":attr:`BreachCatalogue` and an
    incident naming a monitored domain is announced from here.

    Bound to the job's lease exactly as a findings batch is: a worker whose claim
    expired cannot write catalogue rows under the old claim's name, and a module other
    than the one that stores incidents has no catalogue to report.
    """
    from app.services.breach_catalogue import sync_catalogue
    from app.services.source_observations import source_identity

    svc = ConnectorService(db)
    conn = caller
    job = await svc._owned_job(conn, job_id, lease_token=x_connector_lease)
    specs = await load_modules(db)
    manifest = (
        (job.params if isinstance(job.params, dict) else {}).get("manifest_snapshot")
        or _manifest_of(conn, specs)
    )
    if manifest.get("module") != "breaches":
        raise BadRequestException(
            f"connector '{conn.name}' belongs to module '{manifest.get('module')}', "
            "which has no incident catalogue to report"
        )

    conn_name = conn.name
    source = source_identity(conn)
    summary = await sync_catalogue(
        db,
        source=source,
        entries=[entry.model_dump() for entry in payload],
        job_id=job.id,
    )
    # The ingest is acknowledged before the audit line is written, for the same reason a
    # findings batch is: a failed audit must not roll back rows the connector was told
    # were accepted.
    await db.commit()
    await AuditLogger.emit_background(
        db,
        action="connector.catalogue.ingested",
        ip_address=extract_ip(request),
        user_id=None,
        details={
            "connector": conn_name,
            "job_id": str(job_id),
            "source": source,
            "received": summary["received"],
            "created": summary["created"],
            "updated": summary["updated"],
            "new_incidents": summary["new_incidents"],
        },
    )
    await db.commit()
    return summary


@router.post("/me/complete/{job_id}", response_model=dict)
async def complete_job(
    request: Request,
    job_id: uuid.UUID,
    payload: ConnectorCompleteRequest,
    db: AsyncSession = Depends(get_db),
    caller: Connector = Depends(require_connector),
):
    svc = ConnectorService(db)
    conn = caller
    if payload.ok:
        job = await svc.complete_job(conn, job_id, result_summary=payload.summary, lease_token=payload.lease_token)
    else:
        job = await svc.fail_job(conn, job_id, error=payload.error or "connector reported failure", lease_token=payload.lease_token)
    await AuditLogger.emit_background(
        db,
        action="connector.scan.completed" if payload.ok else "connector.scan.failed",
        # The same attribution the batch rows carry. A placeholder here made the
        # completion of a scan the one event in the chain whose address could not
        # be correlated with the deliveries that belong to it.
        ip_address=extract_ip(request),
        user_id=None,
        details={
            "connector": conn.name,
            "job_id": str(job_id),
            "summary": payload.summary,
            "error": (payload.error or "")[:500],
        },
    )
    return {"job_id": str(job.id), "status": job.status}


@router.post("/me/heartbeat", response_model=dict)
async def heartbeat(
    payload: HeartbeatRequest | None = None,
    db: AsyncSession = Depends(get_db),
    caller: Connector = Depends(require_connector),
):
    svc = ConnectorService(db)
    conn = caller
    await svc.heartbeat(conn, job_id=payload.job_id if payload else None, lease_token=payload.lease_token if payload else None)
    return {"status": "ok", "server_time": datetime.now(timezone.utc).isoformat()}


# ---------------------------------------------------------------------------
# Admin-side endpoints (JWT)
# ---------------------------------------------------------------------------


async def connector_health_items(
    db: AsyncSession, *, user, now: datetime | None = None
) -> tuple[list[dict], datetime]:
    """Generic, secret-free health rows for every registered connector.

    Shared by ``GET /connectors/health`` and the dashboard overview (DHP-10).
    The overview calls this function rather than the endpoint, which is what
    keeps a page load at one HTTP request and one audit row: a health row is a
    reading, not an event, so the caller decides which trail entry it makes.
    """
    now = now or datetime.now(timezone.utc)
    stale_after = timedelta(seconds=settings.CONNECTOR_HEALTH_STALE_AFTER_SECONDS)
    # ``role`` may be a plain string or a ``UserRole`` enum member, so compare
    # the value rather than its ``str()`` representation.
    is_admin = getattr(user.role, "value", user.role) == "admin"
    # The remainder is read from the account's own counter, never from the
    # provider: an operator checking health must not spend a request to find out
    # how many requests are left.
    from app.models.source_account import SourceAccount
    from app.services.provider_quota import remaining_today

    async def _blocked_reason(conn: Connector) -> str | None:
        """Why the core would refuse this provider's next scan, if it would.

        The worker's readiness row says what the *worker* observed about its
        key; this says what the *core* decided about the account. The two can
        disagree, and when no account row exists the worker cannot know at all -
        it reports an unconfigured key, while the reason work is refused is
        ``provider_account_missing``. Keeping the answer here means an operator
        reads one field instead of inferring it from a refusal in the job list.
        """
        if not conn.provider:
            return None
        account = None
        if conn.source_account_id:
            account = await db.get(SourceAccount, conn.source_account_id)
        if account is None:
            # Admission falls back to the account an installation declares by
            # provider and quota group; health must look the same way, or it
            # would report a block that a scan does not actually meet.
            account = (
                await db.execute(
                    select(SourceAccount).where(
                        SourceAccount.source_id == conn.provider,
                        SourceAccount.name == (conn.quota_group or "default"),
                    )
                )
            ).scalar_one_or_none()
        if account is None:
            return "provider_account_missing"
        if (account.policy or {}).get("approved") is not True:
            return "account_policy_unapproved"
        return None

    items = []
    for conn in await ConnectorService(db).list_connectors():
        if conn.status == "disabled":
            health = "disabled"
        elif conn.last_error:
            health = "failed"
        elif not conn.last_seen_at:
            health = "unknown"
        else:
            last_seen = conn.last_seen_at
            if last_seen.tzinfo is None:
                # SQLite hands back naive datetimes for a timezone-aware
                # column. They are stored as UTC instants.
                last_seen = last_seen.replace(tzinfo=timezone.utc)
            else:
                last_seen = last_seen.astimezone(timezone.utc)
            health = "degraded" if now - last_seen > stale_after else "healthy"
        quota = await remaining_today(conn) if is_admin else None
        blocked_reason = await _blocked_reason(conn) if is_admin else None
        # The source's own readiness report, reduced to the closed vocabulary
        # every role may see (D5). It answers the question `health` does not:
        # a worker can be online and healthy while its provider key is invalid,
        # and until this was published the dashboard showed only the badge.
        readiness = conn.readiness or {}
        credential_state = str(readiness.get("credential_state") or "unknown")
        if credential_state not in _CREDENTIAL_STATES:
            credential_state = "unknown"
        provider_error = readiness.get("provider_error")
        if provider_error is not None and not (
            isinstance(provider_error, str) and _PROVIDER_ERROR_RE.fullmatch(provider_error)
        ):
            provider_error = None
        ready_checked_at = readiness.get("checked_at")
        if not isinstance(ready_checked_at, str):
            ready_checked_at = None
        last_success = conn.last_success_at
        if last_success is not None:
            if last_success.tzinfo is None:
                last_success = last_success.replace(tzinfo=timezone.utc)
            else:
                last_success = last_success.astimezone(timezone.utc)
        items.append({
            "name": conn.name,
            "connector_type": conn.connector_type,
            "status": conn.status,
            "health": health,
            # Liveness, not an overall verdict: a worker whose last scan failed
            # still answers here, and the DNS page refuses to queue a scan to a
            # source whose heartbeat this says is missing. ``health`` cannot
            # stand in for it, because a stale heartbeat with an older provider
            # error is ``failed`` while the worker is in fact offline.
            "online": ConnectorService.is_online(conn),
            "last_seen_at": conn.last_seen_at,
            "last_error": conn.last_error if is_admin else None,
            # Admin-only, like ``last_error``: the page that shows the budget is
            # the operator's, and a viewer has no decision to make with it. The
            # keys stay present and null for a viewer so the shape is stable.
            "quota_remaining": quota["remaining_today"] if quota else None,
            "quota_budget": quota["request_budget"] if quota else None,
            "quota_reason": quota["reason"] if quota else None,
            # Admin-only, like ``last_error``: it names an operator action. The
            # key stays present and null for a viewer so the shape is stable.
            "blocked_reason": blocked_reason,
            # Readiness, in the closed vocabulary. `credentials_configured` is
            # what the worker can see for itself; a key stored in the core is
            # not visible there, which is why the state beside it is the
            # authoritative answer when the two disagree.
            "credentials_configured": readiness.get("credentials_configured") is True,
            "credential_state": credential_state,
            "provider_error": provider_error,
            "checked_at": ready_checked_at,
            # When collection last succeeded, separate from the heartbeat: a
            # live worker that has never completed a scan is online and idle.
            "last_success_at": last_success,
            "last_success_age_seconds": (
                int((now - last_success).total_seconds()) if last_success else None
            ),
            # Admin-only: the broad readiness document (capabilities, operations,
            # provider's data-class labels). The derived fields above are for
            # every role; this one is for the operator who acts on it.
            "readiness": conn.readiness if is_admin else None,
            "info": {
                key: value for key, value in (conn.info or {}).items()
                if key in {"api_version", "version", "hostname", "python_version", "capabilities"}
                and isinstance(value, (str, int, float, bool, list, dict, type(None)))
            },
        })
    return items, now


@router.get("/health", response_model=dict, dependencies=[Depends(require_active_account)])
async def connector_health(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_active_account),
):
    """Return generic, secret-free health information for registered connectors.

    The raw ``last_error`` text is admin-only. Connector messages routinely echo
    the upstream request URL, and upstream APIs commonly carry their key as a
    query parameter, so an unfiltered message can hand a credential to any
    signed-in viewer. Non-admin callers get the derived ``health`` state, which
    is what the status page needs.
    """
    items, now = await connector_health_items(db, user=user)
    await AuditLogger.emit_background(
        db, action="connectors.health.view", ip_address=extract_ip(request),
        user_id=user.id, details={"count": len(items)},
    )
    return {"items": items, "generated_at": now}


@router.get("", response_model=list[ConnectorOut], dependencies=[Depends(require_admin)])
async def list_connectors(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    items = await ConnectorService(db).list_connectors()
    await AuditLogger.emit_background(
        db,
        action="connectors.list",
        ip_address=extract_ip(request),
        user_id=None,
        details={"count": len(items)},
    )
    specs = await load_modules(db)
    return [_connector_out(conn, specs) for conn in items]


@router.get("/modules", response_model=dict, dependencies=[Depends(require_active_account)])
async def list_modules(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_active_account),
):
    """Modules and the job types their connectors declare.

    The module pages use this to filter job history, so a connector added after
    the frontend was built appears without a frontend change.
    """
    modules = await ConnectorService(db).module_job_types()
    await AuditLogger.emit_background(
        db,
        action="connectors.modules.view",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={"modules": sorted(modules)},
    )
    return {"modules": modules}


@router.get("/jobs", response_model=PaginatedResponse[JobResponse], dependencies=[Depends(require_admin)])
async def connector_jobs(
    request: Request,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=MAX_PAGE_SIZE),
    db: AsyncSession = Depends(get_db),
):
    from math import ceil

    from sqlalchemy import func, select
    from app.models import Job

    svc = ConnectorService(db)
    # Registry-driven: never a hardcoded job type, so a new connector's jobs
    # show up here as soon as it registers.
    job_types = await svc.registered_job_types()
    skip = (page - 1) * size
    stmt = select(Job).where(Job.job_type.in_(job_types))
    count_stmt = select(func.count(Job.id)).where(Job.job_type.in_(job_types))
    total = (await db.execute(count_stmt)).scalar_one()
    items = list(
        (await db.execute(stmt.order_by(Job.created_at.desc(), Job.id.desc()).offset(skip).limit(size))).scalars().all()
    )
    serialized = [JobResponse.model_validate(j) for j in items]
    return PaginatedResponse[JobResponse](
        items=serialized, total=int(total), page=page, size=size, pages=ceil(total / size) if size else 0
    )


@router.patch("/{connector_id}/status", response_model=ConnectorOut)
async def update_connector_status(
    connector_id: uuid.UUID,
    payload: ConnectorStatusUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    conn = await ConnectorService(db).set_status(connector_id, payload.status, commit=False)
    await AuditLogger.emit(
        db,
        action="connector.status.updated",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={"connector": conn.name, "status": conn.status},
        require_persistence=True,
        commit=False,
    )
    await db.commit()
    return _connector_out(conn, await load_modules(db))


@router.patch("/{connector_id}/config", response_model=ConnectorOut)
async def update_connector_config(
    connector_id: uuid.UUID,
    payload: dict,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    from app.models import Connector as _C

    conn_obj = await db.get(_C, connector_id)
    if conn_obj is None:
        from app.core.exceptions import NotFoundException

        raise NotFoundException("Connector not found")
    # Validated against the connector's own declared config_schema, so the core
    # holds no per-vendor settings model.
    specs = await load_modules(db)
    validated = validate_connector_config(_manifest_of(conn_obj, specs), payload)
    conn = await ConnectorService(db).set_config(connector_id, validated, commit=False)
    await AuditLogger.emit(
        db,
        action="connector.config.updated",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={"connector": conn.name, "config": sorted(conn.config or {})},
        require_persistence=True,
        commit=False,
    )
    await db.commit()
    return _connector_out(conn, await load_modules(db))


# ---------------------------------------------------------------------------
# Credential provisioning (admin/JWT)
# ---------------------------------------------------------------------------


class SourceAccountRequest(BaseModel):
    model_config = {"extra": "forbid"}
    source_id: str = Field(min_length=1, max_length=32, pattern=r"^[a-z][a-z0-9_-]{0,31}$")
    name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    credential_ref: str | None = Field(default=None, max_length=128, pattern=r"^[A-Z][A-Z0-9_]{0,127}$")


class SourceAccountPolicyRequest(BaseModel):
    model_config = {"extra": "forbid"}
    approved: StrictBool
    requests_per_minute: StrictInt = Field(ge=1, le=600)
    daily_budget: StrictInt = Field(ge=1, le=100000)

@router.get("/accounts", dependencies=[Depends(require_admin)])
async def list_source_accounts(db: AsyncSession = Depends(get_db)):
    from sqlalchemy import select
    from app.models.source_account import SourceAccount
    rows = list((await db.execute(select(SourceAccount).order_by(SourceAccount.source_id, SourceAccount.name))).scalars())
    return [{"id": row.id, "source_id": row.source_id, "name": row.name, "credential_ref": row.credential_ref, "policy": row.policy, "access_state": row.access_state, "has_api_key": bool(row.api_key_encrypted), "api_key_hint": row.api_key_hint} for row in rows]


@router.post("/accounts")
async def create_source_account(payload: SourceAccountRequest, request: Request, db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    from app.services.source_accounts import provision_account
    account, created, credential_ref_updated = await provision_account(db, **payload.model_dump())
    if created or credential_ref_updated:
        await AuditLogger.emit(db, action="source_account.provisioned" if created else "source_account.credential_ref.updated", ip_address=extract_ip(request), user_id=user.id, details={"account_id": str(account.id), "source_id": account.source_id, "credential_ref_set": bool(account.credential_ref)})
    await db.commit()
    return {"id": account.id}


@router.patch("/accounts/{account_id}/policy")
async def update_account_policy(account_id: uuid.UUID, payload: SourceAccountPolicyRequest, request: Request, db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    from app.services.source_accounts import approve_policy
    account = await approve_policy(
        db, account_id, payload.model_dump(exclude_none=True)
    )
    await AuditLogger.emit(db, action="source_account.policy.updated", ip_address=extract_ip(request), user_id=user.id, details={"account_id": str(account.id), "policy": account.policy})
    await db.commit()
    return {"id": account.id, "policy": account.policy}


class SourceAccountApiKeyRequest(BaseModel):
    model_config = {"extra": "forbid"}
    api_key: str = Field(min_length=1, max_length=512, pattern=r"^[\x21-\x7e]+$")


def _api_key_state(account) -> dict:
    return {"id": account.id, "has_api_key": bool(account.api_key_encrypted), "api_key_hint": account.api_key_hint}


@router.put("/accounts/{account_id}/api-key")
async def set_source_account_api_key(account_id: uuid.UUID, payload: SourceAccountApiKeyRequest, request: Request, db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    from app.services.source_accounts import set_api_key
    account = await set_api_key(db, account_id, payload.api_key)
    await AuditLogger.emit(db, action="source_account.api_key.updated", ip_address=extract_ip(request), user_id=user.id, details={"account_id": str(account.id), "source_id": account.source_id, "api_key_hint": account.api_key_hint})
    await db.commit()
    return _api_key_state(account)


@router.delete("/accounts/{account_id}/api-key")
async def clear_source_account_api_key(account_id: uuid.UUID, request: Request, db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    from app.services.source_accounts import clear_api_key
    account = await clear_api_key(db, account_id)
    await AuditLogger.emit(db, action="source_account.api_key.cleared", ip_address=extract_ip(request), user_id=user.id, details={"account_id": str(account.id), "source_id": account.source_id})
    await db.commit()
    return _api_key_state(account)


@router.patch("/{connector_id}/account")
async def bind_source_account(connector_id: uuid.UUID, account_id: uuid.UUID, request: Request, db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    from app.models.source_account import SourceAccount
    conn, account = await db.get(Connector, connector_id), await db.get(SourceAccount, account_id)
    if conn is None or account is None:
        raise BadRequestException("Connector or account not found")
    if conn.provider and conn.provider != account.source_id:
        raise BadRequestException("Account provider mismatch")
    if not conn.provider and conn.name not in {"netlas"}:
        raise BadRequestException("Account provider cannot be inferred for this connector")
    if conn.source_account_id != account.id:
        conn.provider, conn.source_account_id, conn.quota_group = account.source_id, account.id, account.name
    else:
        return _connector_out(conn, await load_modules(db))
    await AuditLogger.emit(db, action="connector.account.bound", ip_address=extract_ip(request), user_id=user.id, details={"connector_id": str(conn.id), "account_id": str(account.id)})
    await db.commit()
    return _connector_out(conn, await load_modules(db))


class ConnectorProvisionRequest(BaseModel):
    """Create a connector's registry row before the container ever runs."""

    model_config = {"extra": "forbid"}

    name: str = Field(min_length=1, max_length=100)
    connector_type: str = Field(min_length=1, max_length=32)

    @field_validator("name", "connector_type")
    @classmethod
    def _required_text(cls, value: str) -> str:
        if any(ch in value for ch in "\x00\r\n"):
            raise ValueError("connector metadata contains control characters")
        clean = value.strip()
        if not clean:
            raise ValueError("value must not be blank")
        return clean


class ConnectorTokenOut(BaseModel):
    """A freshly issued credential. The plaintext is returned exactly once."""

    connector: ConnectorOut
    token: str
    rotated: bool = False


@router.post("/provision", response_model=ConnectorTokenOut)
async def provision_connector(
    payload: ConnectorProvisionRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    """Register a connector and issue its credential in one step.

    A connector authenticates with its *own* token, so its row must exist before
    the container first registers — this endpoint is that bootstrap. The
    plaintext is returned here once; the core stores only a digest.
    """
    svc = ConnectorService(db)
    clean = normalize_connector_name(payload.name)
    conn = await svc.get_by_name(clean)
    if conn is None:
        conn = await svc.register(name=clean, connector_type=payload.connector_type)
    elif conn.connector_type != payload.connector_type:
        raise BadRequestException(
            f"connector '{clean}' is already registered as type '{conn.connector_type}'"
        )
    token, rotated = await ConnectorCredentials(db).issue(conn)
    await AuditLogger.emit(
        db,
        action="connector.token.issued",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={"connector": conn.name, "token_prefix": conn.token_prefix, "rotated": rotated},
    )
    return ConnectorTokenOut(
        connector=_connector_out(conn, await load_modules(db)), token=token, rotated=rotated
    )


@router.post("/{connector_id}/token", response_model=ConnectorTokenOut)
async def issue_connector_token(
    connector_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    """Issue or rotate a connector's credential (the old token stops working)."""
    credentials = ConnectorCredentials(db)
    conn = await credentials.get(connector_id)
    token, rotated = await credentials.issue(conn)
    await AuditLogger.emit(
        db,
        action="connector.token.rotated" if rotated else "connector.token.issued",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={"connector": conn.name, "token_prefix": conn.token_prefix, "rotated": rotated},
    )
    return ConnectorTokenOut(
        connector=_connector_out(conn, await load_modules(db)), token=token, rotated=rotated
    )


@router.delete("/{connector_id}/token", response_model=ConnectorOut)
async def revoke_connector_token(
    connector_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    """Revoke a connector's credential without deleting the connector.

    The registry row, its configuration and its job history survive, so a
    compromised credential can be cut off in isolation and re-issued later.
    """
    credentials = ConnectorCredentials(db)
    conn = await credentials.get(connector_id)
    await credentials.revoke(conn)
    await AuditLogger.emit(
        db,
        action="connector.token.revoked",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={"connector": conn.name},
    )
    return _connector_out(conn, await load_modules(db))
