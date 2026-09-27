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

import uuid
from datetime import datetime, timedelta, timezone

import structlog
from fastapi import APIRouter, Body, Depends, Header, Query, Request, Response
from pydantic import BaseModel, Field, ValidationError, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import extract_ip, get_db, require_admin, require_viewer_plus
from app.core.audit import AuditLogger
from app.core.config import settings
from app.core.exceptions import (
    BadRequestException,
    ForbiddenException,
    UnauthorizedException,
)
from app.models import Connector
from app.schemas.common import PaginatedResponse
from app.schemas.connector import MAX_FINDINGS_PER_BATCH
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
from app.services.module_registry import load_modules

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
    """
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
        if claimed and claimed != connector.name:
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
    has_token: bool = False
    token_prefix: str | None = None
    token_created_at: datetime | None = None
    token_last_used_at: datetime | None = None

    model_config = {"from_attributes": True}


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
    if normalize_connector_name(payload.name) != caller.name:
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
        job_type=job.job_type,
        connector=conn.name,
        module=conn.connector_type,
        config=conn.config or {},
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
    manifest = _manifest_of(conn, specs)
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
    accepted, rejected = await ingest_findings(
        db,
        connector=conn,
        job_id=job.id,
        findings=[finding.model_dump(mode="json") for finding in validated_findings],
        connector_name=conn_name,
        connector_type=conn.connector_type,
        finding_kind=conn_kind,
        module_spec=module_spec,
    )
    await AuditLogger.emit_background(
        db,
        action="connector.findings.ingested",
        ip_address=extract_ip(request),
        user_id=None,
        details={"connector": conn_name, "job_id": str(job_id), "accepted": accepted, "rejected": rejected},
    )
    await db.commit()
    return {"accepted": accepted, "rejected": rejected}


@router.post("/me/complete/{job_id}", response_model=dict)
async def complete_job(
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
        ip_address="internal:connector",
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


@router.get("/health", response_model=dict, dependencies=[Depends(require_viewer_plus)])
async def connector_health(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_viewer_plus),
):
    """Return generic, secret-free health information for registered connectors.

    The raw ``last_error`` text is admin-only. Connector messages routinely echo
    the upstream request URL, and upstream APIs commonly carry their key as a
    query parameter, so an unfiltered message can hand a credential to any
    signed-in viewer. Non-admin callers get the derived ``health`` state, which
    is what the status page needs.
    """
    now = datetime.now(timezone.utc)
    stale_after = timedelta(seconds=settings.CONNECTOR_HEALTH_STALE_AFTER_SECONDS)
    # ``role`` may be a plain string or a ``UserRole`` enum member, so compare
    # the value rather than its ``str()`` representation.
    is_admin = getattr(user.role, "value", user.role) == "admin"
    items = []
    for conn in await ConnectorService(db).list_connectors():
        if conn.status == "disabled":
            health = "disabled"
        elif conn.last_error:
            health = "failed"
        elif not conn.last_seen_at:
            health = "unknown"
        elif now - conn.last_seen_at > stale_after:
            health = "degraded"
        else:
            health = "healthy"
        items.append({
            "name": conn.name,
            "connector_type": conn.connector_type,
            "status": conn.status,
            "health": health,
            "last_seen_at": conn.last_seen_at,
            "last_error": conn.last_error if is_admin else None,
            "info": {
                key: value for key, value in (conn.info or {}).items()
                if key in {"api_version", "version", "hostname", "python_version", "capabilities"}
                and isinstance(value, (str, int, float, bool, list, dict, type(None)))
            },
        })
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


@router.get("/modules", response_model=dict, dependencies=[Depends(require_viewer_plus)])
async def list_modules(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_viewer_plus),
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
    size: int = Query(50, ge=1, le=200),
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
    conn = await ConnectorService(db).set_status(connector_id, payload.status)
    await AuditLogger.emit(
        db,
        action="connector.status.updated",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={"connector": conn.name, "status": conn.status},
    )
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
    conn = await ConnectorService(db).set_config(connector_id, validated)
    await AuditLogger.emit(
        db,
        action="connector.config.updated",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={"connector": conn.name, "config": sorted(conn.config or {})},
    )
    return _connector_out(conn, await load_modules(db))


# ---------------------------------------------------------------------------
# Credential provisioning (admin/JWT)
# ---------------------------------------------------------------------------


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
