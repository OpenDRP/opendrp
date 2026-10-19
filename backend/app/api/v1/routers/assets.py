import asyncio
import csv
import io
import math
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Body, Depends, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    extract_ip,
    get_db,
    require_admin,
    require_analyse,
    require_active_account,
)
from app.core.audit import AuditLogger
from app.core.exceptions import (
    BadRequestException,
    ConflictException,
    ForbiddenException,
    NotFoundException,
)
from app.core.manual_rate_limit import SCOPE_ASSETS, enforce_manual_rate_limit
from app.schemas.asset import (
    BULK_MAX_IDS,
    EXPORT_MAX_ROWS,
    IMPORT_MAX_BYTES,
    IMPORT_MAX_ITEMS,
    AssetBulkRequest,
    AssetBulkResponse,
    AssetCreate,
    AssetCriticality,
    AssetImportItem,
    AssetImportRequest,
    AssetImportResponse,
    AssetImportRow,
    AssetListResponse,
    AssetResponse,
    AssetSortField,
    AssetUpdate,
    SortDirection,
    validate_and_normalize_asset_value,
)
from app.schemas.common import MAX_PAGE_SIZE, PaginatedResponse
from app.schemas.user import AssetType
from app.services.asset_matching import (
    RELATED_FINDING_MODULES,
    related_finding_models,
    related_finding_predicates,
)
from app.services.asset_service import (
    AssetService,
    asset_audit_snapshot,
    asset_type_value,
    diff_audit_snapshots,
)

router = APIRouter(prefix="/assets", tags=["Assets"])

#: The time budget of an asset read whose cost grows with the inventory
#: (AST-50). It sits below the browser's 50 s timeout and above the measured
#: budget of the queries it covers, so the API answers with a named refusal
#: before the client gives up. The list without ``has_findings`` and a single
#: asset's own reads are cheap enough to run unbounded.
ASSET_QUERY_DEADLINE_SECONDS = 40.0


def _deadline_exceeded() -> JSONResponse:
    """A bounded, machine-readable refusal for a read that ran out of budget.

    A 503 rather than a 500: nothing is broken, the query was stopped on purpose
    and the same request may succeed once the operator narrows it. ``code`` is
    what lets the SPA tell this apart from a network failure or a database
    timeout and show "narrow the filter" instead of "something went wrong".
    """
    return JSONResponse(
        status_code=503,
        content={
            "detail": (
                "This asset query exceeded its time budget. Narrow the filter "
                "(for example by asset type, search term or criticality) and "
                "try again."
            ),
            "code": "query_deadline_exceeded",
        },
        headers={"Retry-After": "5"},
    )


async def _read_inventory(
    service: AssetService, **paging
) -> tuple[list, int, dict]:
    """A page of assets together with their involvement summaries.

    Split out so the caller can put a deadline around the whole read: the list
    and its counters are one answer, and a deadline around only the first query
    would let the second outlive it.
    """
    items, total = await service.list_assets(**paging)
    summaries = await service.related_finding_summaries(items)
    return items, total, summaries


async def _read_export(service: AssetService, **paging) -> tuple[list, int, dict]:
    """The export read: the rows, the total, and their counters.

    The cap is checked before the counters are computed: an export that will be
    refused anyway must not pay for the involvement lookups.
    """
    items, total = await service.list_assets(**paging)
    if total > EXPORT_MAX_ROWS:
        return items, total, {}
    return items, total, await service.related_finding_summaries(items)


def _latest_seen(summary) -> str:
    """The newest observation about an asset, as the text the module published.

    The stored values mix a disclosure *date* with scan *timestamps*, so they are
    parsed rather than compared as strings; an unparseable value is skipped
    instead of becoming the answer by accident.
    """
    latest: tuple[datetime, str] | None = None
    for moment in (getattr(summary, "last_seen", None) or {}).values():
        if not moment:
            continue
        text = str(moment)
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            continue
        if parsed.tzinfo is None:
            # A disclosure date has no offset; treat it as the UTC day it names
            # rather than comparing a naive value with an aware one, which would
            # raise instead of answering.
            parsed = parsed.replace(tzinfo=timezone.utc)
        if latest is None or parsed > latest[0]:
            latest = (parsed, text)
    return latest[1] if latest else ""


def _related_row(module: str, row) -> dict:
    """One related finding, in the same shape for every module.

    The view answers "what is this asset involved in", so it reports what an
    analyst needs to triage — what was seen, from which source, and when — rather
    than each module's full payload (the module's own list endpoint serves that).
    """
    if module == "phishing":
        return {
            "id": str(row.id), "module": module, "title": row.phishing_domain,
            "matched_asset": row.matched_asset, "source": row.detection_source,
            "status": row.status, "observed_at": row.created_at,
        }
    if module == "breaches":
        return {
            "id": str(row.id), "module": module, "title": row.breach_name,
            "matched_asset": row.matched_email or row.matched_domain,
            "source": row.source_id, "status": row.status, "observed_at": row.breach_date,
        }
    if module == "dns":
        return {
            "id": str(row.id), "module": module,
            "title": f"{row.observation_type} {row.subject}".strip(),
            "matched_asset": row.value or row.subject, "source": row.source,
            "status": row.status, "observed_at": row.last_seen_at,
        }
    if module == "exposure":
        return {
            "id": str(row.id), "module": module, "title": row.subject,
            "matched_asset": row.matched_asset, "source": row.source,
            "status": row.status, "observed_at": row.observed_at or row.last_seen_at,
        }
    return {
        "id": str(row.id), "module": module, "title": row.title,
        "matched_asset": row.matched_asset, "source": row.connector_name,
        "status": row.status, "observed_at": row.created_at,
    }


def _related_model(module: str):
    """The finding table behind a module name (one mapping, in ``asset_matching``)."""
    return related_finding_models()[module]


@router.get("", response_model=AssetListResponse)
async def list_assets(
    request: Request,
    asset_type: AssetType | None = None,
    criticality: AssetCriticality | None = None,
    is_active: bool | None = None,
    has_findings: bool | None = None,
    search: str | None = None,
    sort: AssetSortField = Query("created_at"),
    order: SortDirection = Query("desc"),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=MAX_PAGE_SIZE),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_active_account),
):
    """The asset inventory, filtered, sorted and paged by the server.

    ``sort``/``order`` are declared as literal allowlists, not free strings: the
    value ends up in ``ORDER BY``, where caller input must never be concatenated
    into a statement — an unknown field is a 422 from the framework before any
    query is built (WI-16). ``search`` answers a subnet (``10.0.0.0/24``) as well
    as a substring, and ``has_findings`` answers "is this asset involved in
    anything", so the inventory can be read as "what is monitored" rather than as
    "what is configured" (WI-20).
    """
    skip = (page - 1) * size
    service = AssetService(db)
    paging = dict(
        asset_type=asset_type,
        criticality=criticality,
        is_active=is_active,
        has_findings=has_findings,
        search=search,
        sort=sort,
        order=order,
        skip=skip,
        limit=size,
    )
    # ``has_findings`` is the one filter whose cost grows with the inventory:
    # answering it reads every asset's matching keys (AST-40). The deadline turns
    # "the client timed out while the server kept working" into one bounded
    # answer that names the condition (AST-50). Cheap list reads stay unbounded.
    try:
        if has_findings is None:
            items, total, summaries = await _read_inventory(service, **paging)
        else:
            items, total, summaries = await asyncio.wait_for(
                _read_inventory(service, **paging),
                timeout=ASSET_QUERY_DEADLINE_SECONDS,
            )
    except asyncio.TimeoutError:
        return _deadline_exceeded()
    # Each row carries its own involvement count, computed from the same
    # predicates the asset page and the cascade use (WI-20). Without it, an
    # operator cannot tell an asset that is being monitored from one that is
    # only configured, which is the difference the audit called out.
    rows = [
        AssetResponse.model_validate(asset).model_copy(
            update={"findings": summaries.get(asset.id)}
        )
        for asset in items
    ]
    # Read auditing is per result set, not per keystroke (WI-17/AST-13). The list
    # used to be recorded on every request, so one search typed into the filter
    # box wrote a `drp_audit_logs` row per debounced keystroke and per page
    # scrolled — the audit chain grew with the operator's scrolling instead of
    # with the number of distinct reads. A listing is recorded once, on its first
    # page; the pages that continue it are the same read. `asset.view` still
    # records every individual asset lookup, which is the read that names a row.
    if page == 1:
        await AuditLogger.emit_background(
            db,
            action="asset.list",
            ip_address=extract_ip(request),
            user_id=user.id,
            details={
                # The plain value, never `str(enum)`: the same field is written by
                # asset.create and by the promotion routes, and a SIEM index cannot
                # filter on a Python repr.
                "asset_type": asset_type_value(asset_type) if asset_type else None,
                "criticality": str(criticality) if criticality else None,
                "is_active": is_active,
                "has_findings": has_findings,
                "search_used": bool(search),
                "sort": sort,
                "order": order,
                "page": page,
                "size": size,
                "results": int(total),
            },
        )
    pages = math.ceil(total / size) if size > 0 else 0
    return PaginatedResponse(items=rows, total=total, page=page, size=size, pages=pages)


@router.post("", response_model=AssetResponse, status_code=201)
async def create_asset(
    request: Request,
    data: AssetCreate,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyse),
):
    # Creating an asset is not a free operation: it adds a value to every scan
    # that monitors its type, so it is subject to the same per-user throttle as a
    # manual rescan (WI-22/AST-32). A blocked attempt is audited by the limiter
    # itself (`rate_limit.manual_action_blocked`) and answered with 429.
    await enforce_manual_rate_limit(
        db=db,
        user=user,
        scope=SCOPE_ASSETS,
        action="asset creation",
        ip_address=extract_ip(request),
    )
    asset = await AssetService(db).create_asset(data, commit=False)
    snapshot = asset_audit_snapshot(asset)
    # One transaction for the mutation and the record of it: the asset must not
    # become durable without its audit row, which is what `require_persistence`
    # with `commit=False` means here. A refusal answers 503 `audit_unavailable`
    # and the INSERT is rolled back with it.
    await AuditLogger.emit(
        db,
        action="asset.create",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={
            "asset_id": str(asset.id),
            **snapshot,
        },
        require_persistence=True,
        commit=False,
    )
    await db.commit()
    await db.refresh(asset)
    return asset


def _is_admin(user) -> bool:
    """The role as a plain string, whatever the column hands back (see ``asset_type_value``)."""
    return str(getattr(user.role, "value", user.role)) == "admin"


def _csv_rows(raw: bytes) -> tuple[list[tuple[int, AssetImportItem]], list[AssetImportRow]]:
    """Parse a CSV import into items and the line errors found while reading it.

    Line numbers are the file's own, header included, so the report can be read
    against the file the operator is looking at.
    """
    if len(raw) > IMPORT_MAX_BYTES:
        raise BadRequestException(
            f"An inventory file must be at most {IMPORT_MAX_BYTES} bytes "
            f"({IMPORT_MAX_ITEMS} rows); split the file and import it in parts"
        )
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise BadRequestException("An inventory file must be UTF-8 encoded") from exc

    reader = csv.DictReader(io.StringIO(text))
    columns = {(name or "").strip().lower() for name in (reader.fieldnames or [])}
    if not {"asset_type", "asset_value"} <= columns:
        raise BadRequestException(
            "A CSV import needs an `asset_type` and an `asset_value` column "
            "(`criticality` is optional)"
        )

    items: list[tuple[int, AssetImportItem]] = []
    invalid: list[AssetImportRow] = []
    for line, raw_row in enumerate(reader, start=2):
        values = {
            (key or "").strip().lower(): (value or "").strip()
            for key, value in raw_row.items()
        }
        asset_type = values.get("asset_type", "")
        asset_value = values.get("asset_value", "")
        try:
            item = AssetImportItem.model_validate(
                {
                    "asset_type": asset_type,
                    "asset_value": asset_value,
                    "criticality": values.get("criticality") or "medium",
                }
            )
        except ValidationError as exc:
            invalid.append(
                AssetImportRow(
                    line=line,
                    outcome="invalid",
                    asset_type=asset_type or None,
                    asset_value=asset_value or None,
                    detail=exc.errors()[0].get("msg", "Invalid row") if exc.errors() else "Invalid row",
                )
            )
            continue
        items.append((line, item))
    if len(items) + len(invalid) > IMPORT_MAX_ITEMS:
        raise BadRequestException(
            f"An import carries at most {IMPORT_MAX_ITEMS} rows; "
            f"this file has {len(items) + len(invalid)}"
        )
    return items, invalid


async def _import_assets(
    request: Request,
    db: AsyncSession,
    user,
    rows: list[tuple[int, AssetImportItem]],
    invalid: list[AssetImportRow],
    *,
    dry_run: bool,
) -> AssetImportResponse:
    """Create every valid row, and report each line either way (WI-18/AST-24).

    One transaction with a savepoint per row: a row that fails (or that is a
    duplicate) rolls back only itself, while the rows around it stand or fall
    together with the single summary audit row — an inventory that arrives
    without the record of who imported it is not a change this platform makes.
    A dry run takes the same code path and then rolls the transaction back, so
    the report describes the commit that would follow rather than a different
    question answered by a cheaper route.
    """
    if dry_run:
        return await _predict_import(db, rows, invalid)

    # Import is a manual inventory change like any other (WI-22). A preview is
    # not throttled here: it writes nothing, and the authenticated request limit
    # already bounds how often it can be asked.
    await enforce_manual_rate_limit(
        db=db,
        user=user,
        scope=SCOPE_ASSETS,
        action="inventory import",
        ip_address=extract_ip(request),
    )

    service = AssetService(db)
    item_reports: list[AssetImportRow] = []
    created = duplicate = invalid_count = 0
    for line, item in rows:
        entry = AssetImportRow(
            line=line,
            outcome="created",
            asset_type=item.asset_type,
            asset_value=item.asset_value,
        )
        try:
            async with db.begin_nested():
                # ``model_validate`` rather than the constructor: the row's type is
                # a plain string here (it is validated as part of the request, and
                # a wrong one must fail as a row, not as a 422 on the file).
                await service.create_asset(
                    AssetCreate.model_validate(
                        {
                            "asset_type": item.asset_type,
                            "asset_value": item.asset_value,
                            "criticality": item.criticality,
                        }
                    ),
                    commit=False,
                )
        except ConflictException:
            duplicate += 1
            entry.outcome = "duplicate"
            entry.detail = "This value is already monitored"
        except (BadRequestException, ValidationError, ValueError) as exc:
            invalid_count += 1
            entry.outcome = "invalid"
            entry.detail = _error_detail(exc)
        else:
            created += 1
        item_reports.append(entry)

    # The rows the file could not even be read into, plus the rows the platform
    # refused: both are "invalid" in the report the operator reads.
    invalid_total = invalid_count + len(invalid)
    report = sorted([*invalid, *item_reports], key=lambda row: row.line)
    await AuditLogger.emit(
        db,
        action="asset.import",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={
            "created": created,
            "duplicate": duplicate,
            "invalid": invalid_total,
            "rows_requested": len(rows) + len(invalid),
            # The report itself, bounded: a SIEM needs to see which line failed
            # and why, not a megabyte of details on every import.
            "report": [row.model_dump() for row in report[:200]],
            "report_truncated": len(report) > 200,
        },
        require_persistence=True,
        commit=False,
    )
    await db.commit()
    return AssetImportResponse(
        dry_run=False,
        created=created,
        duplicate=duplicate,
        invalid=invalid_total,
        rows=report,
    )


async def _predict_import(
    db: AsyncSession,
    rows: list[tuple[int, AssetImportItem]],
    invalid: list[AssetImportRow],
) -> AssetImportResponse:
    """What the same import would do, without writing anything (WI-18).

    Read-only, and deliberately so. The earlier shape of this preview ran the
    real create path and rolled the transaction back, which makes the answer
    depend on transaction semantics rather than on the rules being previewed —
    and a preview that can leave rows behind is worse than no preview. What a
    dry run actually needs to answer is decided by the two things every write
    goes through anyway: the validator, and the duplicate lookup. Both are called
    here, and the only claim the report makes is the one those two support.

    A value that repeats inside one file is reported as a duplicate for the
    second line, because that is what happens once the first line is written.
    A concurrent writer can still turn a predicted ``created`` into a duplicate:
    the real run reports that itself, per line.
    """
    service = AssetService(db)
    item_reports: list[AssetImportRow] = []
    created = duplicate = invalid_count = 0
    seen: set[tuple[str, str]] = set()
    for line, item in rows:
        entry = AssetImportRow(
            line=line,
            outcome="created",
            asset_type=item.asset_type,
            asset_value=item.asset_value,
        )
        try:
            # The same validator the import itself runs, so a row this preview
            # rejects is a row the real run refuses, for the same reason.
            candidate = AssetCreate.model_validate(
                {
                    "asset_type": item.asset_type,
                    "asset_value": item.asset_value,
                    "criticality": item.criticality,
                }
            )
            normalized = validate_and_normalize_asset_value(
                candidate.asset_type, candidate.asset_value
            )
        except (ValidationError, ValueError) as exc:
            invalid_count += 1
            entry.outcome = "invalid"
            entry.detail = _error_detail(exc)
        else:
            key = (str(candidate.asset_type), normalized)
            if key in seen or await service.asset_exists(*key):
                duplicate += 1
                entry.outcome = "duplicate"
                entry.detail = "This value is already monitored"
            else:
                seen.add(key)
                created += 1
        item_reports.append(entry)

    invalid_total = invalid_count + len(invalid)
    return AssetImportResponse(
        dry_run=True,
        created=created,
        duplicate=duplicate,
        invalid=invalid_total,
        rows=sorted([*invalid, *item_reports], key=lambda row: row.line),
    )


def _error_detail(exc: Exception) -> str:
    """One line of reason for a rejected import row."""
    if isinstance(exc, ValidationError):
        errors = exc.errors()
        return str(errors[0].get("msg", "Invalid value")) if errors else "Invalid value"
    return str(getattr(exc, "detail", exc))


def _assets_as_csv(items, summaries: dict) -> str:
    """The export rows, with the same involvement the list shows (AST-49).

    The columns keep the original five first — a consumer that read the old file
    by position still finds them where they were — and append the counters and
    the newest observation. ``findings_other`` is the generic module bucket, so
    the per-module and generic numbers add up to ``findings_total``.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "asset_type",
            "asset_value",
            "criticality",
            "is_active",
            "created_at",
            "findings_total",
            "findings_phishing",
            "findings_breaches",
            "findings_dns",
            "findings_exposure",
            "findings_other",
            "last_seen",
        ]
    )
    for asset in items:
        summary = summaries.get(asset.id)
        writer.writerow(
            [
                asset_type_value(asset.asset_type),
                asset.asset_value,
                asset.criticality,
                "true" if asset.is_active else "false",
                asset.created_at.isoformat() if asset.created_at else "",
                summary.total if summary else 0,
                summary.phishing if summary else 0,
                summary.breaches if summary else 0,
                summary.dns if summary else 0,
                summary.exposure if summary else 0,
                summary.findings if summary else 0,
                _latest_seen(summary) if summary else "",
            ]
        )
    return buffer.getvalue()


@router.post("/import", response_model=AssetImportResponse)
async def import_assets(
    request: Request,
    payload: AssetImportRequest,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyse),
):
    """JSON import: ``{"items": [...], "dry_run": false}`` (WI-18)."""
    rows = [(index, item) for index, item in enumerate(payload.items, start=1)]
    return await _import_assets(
        request, db, user, rows, [], dry_run=payload.dry_run
    )


@router.post("/import/csv", response_model=AssetImportResponse)
async def import_assets_csv(
    request: Request,
    raw: bytes = Body(..., media_type="text/csv"),
    dry_run: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyse),
):
    """CSV import: ``asset_type,asset_value,criticality`` with a header row (WI-18)."""
    rows, invalid = _csv_rows(raw)
    return await _import_assets(request, db, user, rows, invalid, dry_run=dry_run)


@router.get("/export")
async def export_assets(
    request: Request,
    asset_type: AssetType | None = None,
    criticality: AssetCriticality | None = None,
    is_active: bool | None = None,
    has_findings: bool | None = None,
    search: str | None = None,
    sort: AssetSortField = Query("created_at"),
    order: SortDirection = Query("desc"),
    format: Literal["csv", "json"] = Query("csv"),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_active_account),
):
    """The inventory behind the current filter, as a file (WI-18/AST-24).

    Rows are the same rows the list would show, under the same matching, sorting
    and ordering: an export that re-implemented the filter would eventually
    disagree with the table the operator checked before downloading it.
    """
    # An export can carry ten thousand rows; the rows and their counters are one
    # answer, so the deadline covers both (AST-50). A file that took longer is
    # refused with a named reason rather than left half-built.
    try:
        items, total, summaries = await asyncio.wait_for(
            _read_export(
                AssetService(db),
                asset_type=asset_type,
                criticality=criticality,
                is_active=is_active,
                has_findings=has_findings,
                search=search,
                sort=sort,
                order=order,
                skip=0,
                limit=EXPORT_MAX_ROWS,
            ),
            timeout=ASSET_QUERY_DEADLINE_SECONDS,
        )
    except asyncio.TimeoutError:
        return _deadline_exceeded()
    if total > EXPORT_MAX_ROWS:
        raise BadRequestException(
            f"This filter matches {total} assets; an export carries at most "
            f"{EXPORT_MAX_ROWS}. Narrow the filter and export in parts."
        )
    await AuditLogger.emit_background(
        db,
        action="asset.export",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={
            "asset_type": asset_type_value(asset_type) if asset_type else None,
            "criticality": str(criticality) if criticality else None,
            "is_active": is_active,
            "has_findings": has_findings,
            "search_used": bool(search),
            "format": format,
            "rows": int(total),
        },
    )
    if format == "json":
        return {
            "items": [
                {
                    "id": str(asset.id),
                    **asset_audit_snapshot(asset),
                    # The same ``AssetFindingSummary`` a list row carries, so a
                    # consumer reads one shape for the table and the file.
                    "findings": (
                        summaries[asset.id].model_dump()
                        if asset.id in summaries
                        else None
                    ),
                    "last_seen": _latest_seen(summaries.get(asset.id)),
                }
                for asset in items
            ],
            "total": int(total),
        }
    return Response(
        content=_assets_as_csv(items, summaries),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="assets.csv"'},
    )


@router.post("/bulk", response_model=AssetBulkResponse)
async def bulk_update_assets(
    request: Request,
    payload: AssetBulkRequest,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyse),
):
    """One action over many assets, with one summary audit row (WI-18/AST-24).

    The whole batch is one transaction: either every named asset is changed and
    the summary row is written, or nothing is. Deleting is administrator-only,
    exactly as it is per asset, and the cascade keeps its per-asset meaning.
    """
    if payload.operation == "delete" and not _is_admin(user):
        raise ForbiddenException("Only administrators can delete assets")
    if payload.operation == "criticality" and payload.criticality is None:
        raise BadRequestException(
            "The `criticality` operation needs a `criticality` value"
        )
    if len(payload.ids) > BULK_MAX_IDS:
        raise BadRequestException(
            f"A bulk action names at most {BULK_MAX_IDS} assets"
        )

    service = AssetService(db)
    applied = 0
    missing: list[str] = []
    deleted = {"phishing_findings": 0, "breach_findings": 0, "generic_findings": 0}
    # De-duplicated but in the caller's order: naming one asset twice must not
    # apply the change twice (a second delete would raise, a second deactivate
    # would be a no-op) or inflate the reported count.
    for asset_id in dict.fromkeys(payload.ids):
        asset = await service.get_asset(asset_id)
        if asset is None:
            missing.append(str(asset_id))
            continue
        if payload.operation == "delete":
            phishing, breach, generic = await service.delete_asset(
                asset, cascade_findings=payload.cascade_findings, commit=False
            )
            deleted["phishing_findings"] += phishing
            deleted["breach_findings"] += breach
            deleted["generic_findings"] += generic
        elif payload.operation == "criticality":
            await service.update_asset(
                asset,
                AssetUpdate.model_validate({"criticality": payload.criticality}),
                commit=False,
            )
        else:
            await service.update_asset(
                asset,
                AssetUpdate.model_validate(
                    {"is_active": payload.operation == "activate"}
                ),
                commit=False,
            )
        applied += 1

    details: dict = {
        "operation": payload.operation,
        "requested": len(payload.ids),
        "applied": applied,
        "missing_count": len(missing),
        # Naming the assets that were not found is the difference between "some
        # of that batch did nothing" and "which part of it did nothing".
        "missing": missing[:50],
    }
    if payload.operation == "delete":
        details["cascade_findings"] = payload.cascade_findings
        details["findings_deleted"] = deleted
    if payload.operation == "criticality":
        details["criticality"] = payload.criticality
    await AuditLogger.emit(
        db,
        action=f"asset.bulk.{payload.operation}",
        ip_address=extract_ip(request),
        user_id=user.id,
        details=details,
        require_persistence=True,
        commit=False,
    )
    await db.commit()
    return AssetBulkResponse(
        operation=payload.operation,
        requested=len(payload.ids),
        applied=applied,
        missing=missing,
        cascade_findings=payload.cascade_findings,
        findings_deleted=deleted if payload.operation == "delete" else {},
    )


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(
    request: Request,
    asset_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_active_account),
):
    asset = await AssetService(db).get_asset(asset_id)
    if not asset:
        raise NotFoundException("Asset not found")
    await AuditLogger.emit_background(
        db,
        action="asset.view",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={
            "asset_id": str(asset.id),
            **asset_audit_snapshot(asset),
        },
    )
    return asset


@router.patch("/{asset_id}", response_model=AssetResponse)
async def update_asset(
    request: Request,
    asset_id: uuid.UUID,
    data: AssetUpdate,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyse),
):
    service = AssetService(db)
    asset = await service.get_asset(asset_id)
    if not asset:
        raise NotFoundException("Asset not found")
    # Snapshot the row before the write, then diff the row after it. Reporting the
    # request's keys instead would name the fields the caller typed and miss what
    # the update actually did — canonicalization rewrites `asset_value` on every
    # write, so a criticality-only patch can still change the stored value.
    before = asset_audit_snapshot(asset)
    updated = await service.update_asset(asset, data, commit=False)
    after = asset_audit_snapshot(updated)
    changes = diff_audit_snapshots(before, after)
    await AuditLogger.emit(
        db,
        action="asset.update",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={
            "asset_id": str(asset_id),
            **after,
            "changed_fields": sorted(changes),
            "changes": changes,
        },
        require_persistence=True,
        commit=False,
    )
    await db.commit()
    await db.refresh(updated)
    return updated


@router.delete("/{asset_id}", status_code=204)
async def delete_asset(
    request: Request,
    asset_id: uuid.UUID,
    cascade_findings: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    service = AssetService(db)
    asset = await service.get_asset(asset_id)
    if not asset:
        raise NotFoundException("Asset not found")
    details = {
        "asset_id": str(asset.id),
        **asset_audit_snapshot(asset),
        "cascade_findings": cascade_findings,
    }
    phishing_deleted, breach_deleted, generic_deleted = await service.delete_asset(
        asset, cascade_findings=cascade_findings, commit=False
    )
    details.update(
        {
            "phishing_findings_deleted": phishing_deleted,
            "breach_findings_deleted": breach_deleted,
            "generic_findings_deleted": generic_deleted,
        }
    )
    await AuditLogger.emit(
        db,
        action="asset.delete",
        ip_address=extract_ip(request),
        user_id=user.id,
        details=details,
        require_persistence=True,
        commit=False,
    )
    await db.commit()
    return None


@router.get("/{asset_id}/findings")
async def list_asset_findings(
    asset_id: uuid.UUID,
    request: Request,
    module: str | None = Query(None, pattern=f"^({'|'.join(RELATED_FINDING_MODULES)})$"),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=MAX_PAGE_SIZE),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_active_account),
):
    """What the platform holds about one asset, across every module (WI-12/AST-22).

    The relationship between an asset and the findings about it was observable in
    one direction only: a finding named its asset, while the asset page could not
    say what it was involved in — and finding it meant searching four modules by
    hand. The counters come from the same matching rule the cascade uses (WI-08),
    so this view and a delete affect exactly the same rows.
    """
    service = AssetService(db)
    asset = await service.get_asset(asset_id)
    if not asset:
        raise NotFoundException("Asset not found")

    # Counts and last-seen come from the shared summary (WI-20), so the counters
    # here and the counter in a list row are one computation, not two.
    summary = (await service.related_finding_summaries([asset]))[asset.id]
    counts = {name: int(getattr(summary, name)) for name in RELATED_FINDING_MODULES}
    predicates = related_finding_predicates(asset.asset_type, asset.asset_value)

    selected = module or RELATED_FINDING_MODULES[0]
    model = _related_model(selected)
    rows = (
        (
            await db.execute(
                select(model)
                .where(predicates[selected])
                .order_by(model.created_at.desc(), model.id)
                .offset((page - 1) * size)
                .limit(size)
            )
        )
        .scalars()
        .all()
    )

    total = counts[selected]
    all_counts = {**counts, "total": summary.total}
    # Read auditing is per result set, like `asset.list` (AST-44): the card asks
    # for one page per module tab, and paging through a tab must not append a row
    # per click to the audit chain. The first page of a tab is the read; the
    # pages that continue it are the same read.
    if page == 1:
        await AuditLogger.emit_background(
            db,
            action="asset.findings.list",
            ip_address=extract_ip(request),
            user_id=user.id,
            details={
                "asset_id": str(asset.id),
                "asset_type": asset_type_value(asset.asset_type),
                "asset_value": asset.asset_value,
                "module": selected,
                "counts": all_counts,
            },
        )

    return {
        "asset": {
            "id": str(asset.id),
            "asset_type": asset_type_value(asset.asset_type),
            "asset_value": asset.asset_value,
            "is_active": asset.is_active,
        },
        "counts": all_counts,
        # When each module last saw a finding about this asset (WI-20): a count
        # says an asset is involved, the date says whether that is current.
        "last_seen": summary.last_seen,
        "module": selected,
        "items": [_related_row(selected, row) for row in rows],
        "total": total,
        "page": page,
        "size": size,
        "pages": math.ceil(total / size) if size else 0,
    }
