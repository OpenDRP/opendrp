"""Module registry — reading and writing the module set as data.

The set of modules used to be a constant in core code, which meant a new data
source needed a core release. It is now a table: this service loads it, validates
new definitions and hands callers :class:`~app.services.connector_manifest.ModuleSpec`
objects.

Reads deliberately hit the database instead of a process cache. The registry is a
handful of rows, read once per registration or submission batch (not per
finding), and a stale cache would mean a freshly declared module is rejected or —
worse — a disabled one keeps accepting findings.
"""

from __future__ import annotations

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import BadRequestException, NotFoundException
from app.models import Module
from app.services.connector_manifest import (
    GENERIC_ADAPTER,
    ModuleSpec,
    normalize_asset_types,
    normalize_declared_fields,
    normalize_dedup_fields,
    normalize_finding_kind,
    normalize_module_id,
)

log = structlog.get_logger()

#: Storage block written for every module an operator declares: the generic
#: writer, storing the validated payload as JSON.
GENERIC_STORAGE: dict[str, str] = {"kind": "generic", "adapter": GENERIC_ADAPTER}

#: The modules this platform ships with. The baseline migration seeds the same
#: definitions (a migration must describe *its* revision rather than import
#: application code), and ``tests/test_module_registry.py`` asserts the two stay
#: in agreement. They are also what a freshly created schema is seeded with, so
#: ``create_all`` databases (dev, tests) behave like migrated ones.
BUILTIN_MODULE_DEFINITIONS: tuple[dict, ...] = (
    {
        "id": "phishing",
        "label": "Phishing",
        "description": "Look-alike and malicious domains impersonating your assets.",
        "finding_kind": "phishing",
        "asset_types": ["domain"],
        "fields": {},
        "dedup_fields": ["phishing_domain"],
        "title_field": "phishing_domain",
        "storage": {"kind": "table", "table": "drp_phishing_domains", "adapter": "phishing"},
    },
    {
        "id": "breaches",
        "label": "Credential breaches",
        "description": "Credential exposures affecting your monitored accounts and domains.",
        "finding_kind": "breach",
        "asset_types": ["email_account", "domain"],
        "fields": {},
        "dedup_fields": ["breach_name"],
        "title_field": "breach_name",
        "storage": {"kind": "table", "table": "drp_breaches", "adapter": "breach"},
    },
)


async def ensure_builtin_modules(db: AsyncSession) -> int:
    """Insert the platform's own modules if they are missing. Returns how many.

    Idempotent and never destructive: an existing row is left exactly as it is,
    so an admin renaming or disabling a built-in module stays in effect.
    """
    present = set((await db.execute(select(Module.id))).scalars().all())
    added = 0
    for definition in BUILTIN_MODULE_DEFINITIONS:
        if definition["id"] in present:
            continue
        db.add(Module(**definition, enabled=True, builtin=True))
        added += 1
    if added:
        await db.commit()
    return added


def spec_from_row(row: Module) -> ModuleSpec:
    """Turn a stored row into the immutable spec the rest of the core uses."""
    return ModuleSpec(
        id=str(row.id),
        label=str(row.label),
        description=str(row.description or ""),
        finding_kind=str(row.finding_kind),
        asset_types=tuple(str(item) for item in (row.asset_types or [])),
        fields={str(name): dict(spec) for name, spec in (row.fields or {}).items()},
        dedup_fields=tuple(str(name) for name in (row.dedup_fields or [])),
        title_field=str(row.title_field) if row.title_field else None,
        storage=dict(row.storage or {}),
        enabled=bool(row.enabled),
        builtin=bool(row.builtin),
    )


async def load_modules(db: AsyncSession) -> dict[str, ModuleSpec]:
    """Every registered module, including disabled ones, keyed by id."""
    rows = (await db.execute(select(Module))).scalars().all()
    return {str(row.id): spec_from_row(row) for row in rows}


async def get_module(db: AsyncSession, module_id: str) -> ModuleSpec | None:
    row = await db.get(Module, str(module_id or "").strip().lower())
    return spec_from_row(row) if row is not None else None


async def require_module(db: AsyncSession, module_id: str) -> ModuleSpec:
    """Load a module or fail with the list of modules that do exist."""
    spec = await get_module(db, module_id)
    if spec is None:
        known = sorted((await load_modules(db)).keys())
        raise BadRequestException(
            f"unknown module '{module_id}': this platform has {known}"
        )
    return spec


async def require_enabled_module(db: AsyncSession, module_id: str) -> ModuleSpec:
    """Load a module a connector may register against (enabled only)."""
    spec = await require_module(db, module_id)
    if not spec.enabled:
        raise BadRequestException(f"module '{spec.id}' is disabled")
    return spec


async def create_module(
    db: AsyncSession,
    *,
    module_id: str,
    label: str,
    description: str | None = None,
    fields: dict | None = None,
    dedup_fields: list | None = None,
    title_field: str | None = None,
    asset_types: list | None = None,
) -> ModuleSpec:
    """Declare a new module backed by generic storage.

    A declared module must say how its findings are identified (at least one
    dedup field) and validated (its field specification), because that is what
    makes accepting a new data source possible without a core change.
    """
    clean_id = normalize_module_id(module_id)
    clean_label = str(label or "").strip()
    if not clean_label or len(clean_label) > 120:
        raise BadRequestException("module label must be 1-120 characters")

    existing = await get_module(db, clean_id)
    if existing is not None:
        raise BadRequestException(f"module '{clean_id}' already exists")

    declared_fields = normalize_declared_fields(fields)
    if not declared_fields:
        raise BadRequestException("a module must declare the fields its findings carry")
    clean_dedup = normalize_dedup_fields(dedup_fields, declared=declared_fields)
    if not clean_dedup:
        raise BadRequestException(
            "a module must declare at least one dedup field: without it the same "
            "finding would be stored on every submission"
        )
    clean_title = str(title_field or "").strip() or clean_dedup[0]
    if clean_title not in declared_fields:
        raise BadRequestException(f"title_field '{clean_title}' is not a declared field")
    # Each module owns exactly one finding kind: submissions are validated
    # against the module whose kind the connector declared.
    finding_kind = normalize_finding_kind(clean_id)
    clash = (
        await db.execute(select(Module.id).where(Module.finding_kind == finding_kind))
    ).scalars().first()
    if clash is not None:
        raise BadRequestException(
            f"finding kind '{finding_kind}' is already used by module '{clash}'"
        )

    row = Module(
        id=clean_id,
        label=clean_label,
        description=(str(description).strip()[:2000] or None) if description else None,
        finding_kind=finding_kind,
        asset_types=normalize_asset_types(asset_types),
        fields=declared_fields,
        dedup_fields=clean_dedup,
        title_field=clean_title,
        storage=dict(GENERIC_STORAGE),
        enabled=True,
        builtin=False,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    spec = spec_from_row(row)
    log.info(
        "module_declared",
        module=spec.id,
        finding_kind=spec.finding_kind,
        fields=len(spec.fields),
    )
    return spec


async def set_module_enabled(db: AsyncSession, module_id: str, *, enabled: bool) -> ModuleSpec:
    """Enable or disable a module.

    Disabling stops new registrations for it; already-registered connectors keep
    their jobs (the module may be temporarily off, not deleted), while ingestion
    stays available so queued work can still land.
    """
    row = await db.get(Module, normalize_module_id(module_id))
    if row is None:
        raise NotFoundException("Module not found")
    row.enabled = bool(enabled)
    await db.commit()
    await db.refresh(row)
    log.info("module_toggled", module=row.id, enabled=row.enabled)
    return spec_from_row(row)


async def update_module_metadata(
    db: AsyncSession,
    module_id: str,
    *,
    label: str | None = None,
    description: str | None = None,
) -> ModuleSpec:
    """Rename/redescribe a module. Fields are immutable: findings already stored
    against the previous specification would otherwise silently change shape."""
    row = await db.get(Module, normalize_module_id(module_id))
    if row is None:
        raise NotFoundException("Module not found")
    if label is not None:
        clean = str(label).strip()
        if not clean or len(clean) > 120:
            raise BadRequestException("module label must be 1-120 characters")
        row.label = clean
    if description is not None:
        row.description = str(description).strip()[:2000] or None
    await db.commit()
    await db.refresh(row)
    return spec_from_row(row)


__all__ = [
    "BUILTIN_MODULE_DEFINITIONS",
    "GENERIC_STORAGE",
    "create_module",
    "ensure_builtin_modules",
    "get_module",
    "load_modules",
    "require_enabled_module",
    "require_module",
    "set_module_enabled",
    "spec_from_row",
    "update_module_metadata",
]
