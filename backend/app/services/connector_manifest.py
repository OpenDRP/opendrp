"""Connector manifests and module specifications — the plugin boundary.

The platform must not need a core code change to accept a new data source. Two
things make that true:

**A connector declares itself** at registration:

======================  ====================================================
``module``              the module whose data it produces
``job_type``            the scan job type only this connector claims
                        (provisioning reserves ``<module>.<name>`` until then)
``finding_kind``        which finding shape its submissions validate as
``asset_types``         asset-inventory sections it consumes
``config_schema``       operator-editable settings (key -> type/label/default)
======================  ====================================================

**A module is data** (:class:`ModuleSpec`, stored in ``drp_modules``): its
label, finding kind, declared field specification, deduplication fields, title
field and which write adapter persists its findings. The core therefore keeps no
closed set of modules or finding kinds — onboarding a source means inserting a
module row and pointing a connector at it.

What stays in code is the *shape machinery*: this module turns a
:class:`ModuleSpec` into a validator (the module's own declared fields, or a
built-in schema for the two modules that predate the registry) and computes the
declared dedup key and title. It still names no provider — it describes *kinds of
work* and *shapes of data*.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field as dataclass_field
from datetime import date
from functools import lru_cache
from typing import Any, Literal, Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StringConstraints,
    TypeAdapter,
    create_model,
    field_validator,
)
from typing_extensions import Annotated

from app.core.exceptions import BadRequestException
from app.models.asset import AssetType
from app.schemas.connector import BreachFinding, PhishingFinding, sanitize_attributes

# ---------------------------------------------------------------------------
# Grammars and limits
# ---------------------------------------------------------------------------

#: Job types the core creates for itself. A connector may never claim one, and
#: every other job type in the installation is declared by the connector that
#: owns it — there is no shared bucket.
CORE_OWNED_JOB_TYPES = frozenset({"system", "report.generate"})

#: Namespaced job type, e.g. ``phishing.dnstwist`` or ``supply_chain.repo_scan``.
JOB_TYPE_RE = re.compile(r"^[a-z][a-z0-9_-]*(?:\.[a-z0-9_-]+)+$")
MODULE_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
FINDING_KIND_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
CONFIG_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
FIELD_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
CONTROL_CHARS_RE = re.compile(r"[\x00\r\n]")
CONNECTOR_SLUG_RE = re.compile(r"[^a-z0-9_-]")

MAX_CONFIG_SCHEMA_FIELDS = 32
MAX_JOB_TYPE_LEN = 50
MAX_ASSET_TYPES = 16
MAX_DECLARED_FIELDS = 32
MAX_DEDUP_FIELDS = 3
MAX_TITLE_LEN = 512
MAX_MATCHED_ASSET_LEN = 512
MAX_STR_LEN = 512
MAX_TEXT_LEN = 2000
MAX_LIST_ITEMS = 100
MAX_LIST_ITEM_LEN = 255

ConfigFieldType = Literal["bool", "int", "float", "str"]
_CONFIG_TYPES: frozenset[str] = frozenset({"bool", "int", "float", "str"})

#: Types a module may declare for its own finding fields.
DECLARED_FIELD_TYPES = ("str", "text", "int", "float", "bool", "date", "list_str")

#: Platform-provided fields every declared module gets for free: the asset the
#: finding matched, and the source's own payload (validated separately).
PLATFORM_FINDING_FIELDS = ("matched_asset", "attributes")

#: Write adapters implemented in code, by name. A module's ``storage`` block
#: selects one; anything else must use ``generic``.
NATIVE_ADAPTER_MODELS: dict[str, type[BaseModel]] = {
    "phishing": PhishingFinding,
    "breach": BreachFinding,
}
GENERIC_ADAPTER = "generic"


class ConfigField(BaseModel):
    """One operator-editable connector setting, declared by the connector."""

    model_config = ConfigDict(extra="forbid")

    type: ConfigFieldType
    label: str | None = None
    default: bool | int | float | str | None = None
    description: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(exclude_none=True)


class DeclaredField(BaseModel):
    """One finding field a module declares."""

    model_config = ConfigDict(extra="forbid")

    type: str
    label: str | None = None
    description: str | None = None
    required: bool = False

    @field_validator("type")
    @classmethod
    def _known_type(cls, value: str) -> str:
        if value not in DECLARED_FIELD_TYPES:
            raise ValueError(f"field type must be one of {list(DECLARED_FIELD_TYPES)}")
        return value

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(exclude_none=True)


# ---------------------------------------------------------------------------
# The module specification (data, not code)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModuleSpec:
    """Everything the core needs to know about a module.

    Built from a ``drp_modules`` row, so the set of modules is data: the core
    validates submissions against ``fields``, deduplicates on ``dedup_fields``
    and persists through the adapter named by ``storage``.
    """

    id: str
    label: str
    description: str
    finding_kind: str
    asset_types: tuple[str, ...]
    fields: dict[str, dict[str, Any]] = dataclass_field(default_factory=dict)
    dedup_fields: tuple[str, ...] = ()
    title_field: str | None = None
    storage: dict[str, Any] = dataclass_field(default_factory=dict)
    enabled: bool = True
    builtin: bool = False

    @property
    def adapter(self) -> str:
        """Name of the write adapter this module uses."""
        return str(self.storage.get("adapter") or GENERIC_ADAPTER)

    @property
    def storage_kind(self) -> str:
        """``table`` for a built-in adapter, ``generic`` for generic storage."""
        return str(self.storage.get("kind") or "generic")

    @property
    def declared_field_names(self) -> tuple[str, ...]:
        return tuple(self.fields)

    def to_public_dict(self) -> dict[str, Any]:
        """Registry view for the API and UI (no internal table names)."""
        return {
            "id": self.id,
            "label": self.label,
            "description": self.description,
            "finding_kind": self.finding_kind,
            "asset_types": list(self.asset_types),
            "fields": {name: dict(spec) for name, spec in self.fields.items()},
            "dedup_fields": list(self.dedup_fields),
            "title_field": self.title_field,
            "storage": self.storage_kind,
            "enabled": self.enabled,
            "builtin": self.builtin,
        }


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------


def normalize_module_id(raw: str) -> str:
    """Validate the *shape* of a module id; existence is a registry question."""
    module = str(raw or "").strip().lower()
    if not MODULE_RE.match(module):
        raise BadRequestException(
            "module must be a lowercase identifier (letters, digits, underscore)"
        )
    return module


def normalize_finding_kind(raw: str) -> str:
    kind = str(raw or "").strip().lower()
    if not FINDING_KIND_RE.match(kind):
        raise BadRequestException(
            "finding_kind must be a lowercase identifier (letters, digits, underscore)"
        )
    return kind


def normalize_job_type(raw: str) -> str:
    """Validate a declared job type. A connector must declare one.

    Job-type ownership is what isolates connectors from each other, so there is
    no default: a connector without a declaration could claim nothing while
    still looking registered.
    """
    job_type = str(raw or "").strip().lower()
    if not job_type:
        raise BadRequestException(
            "job type is required: declare '<module>.<connector>' so this "
            "connector owns exactly the work it claims"
        )
    if len(job_type) > MAX_JOB_TYPE_LEN:
        raise BadRequestException(f"job type may be at most {MAX_JOB_TYPE_LEN} characters")
    if job_type in CORE_OWNED_JOB_TYPES:
        raise BadRequestException(
            f"job type '{job_type}' is owned by the core and cannot be declared"
        )
    if not JOB_TYPE_RE.match(job_type):
        raise BadRequestException(
            "job type must be namespaced, e.g. '<module>.<connector>' "
            "(lowercase letters, digits, underscore, hyphen, dot)"
        )
    return job_type


def provisioning_job_type(module: str, name: str) -> str:
    """The job type reserved for a connector that has not registered yet.

    Provisioning (the admin API and the CLI) creates the registry row *before*
    the connector can authenticate, so the row must already own a job type: none
    is a placeable claim. The connector replaces the reservation with the type it
    declares at registration — a connector is always allowed to re-declare its
    own type — and until it does, the reservation is what the registry shows.
    """
    module_id = str(module or "").strip().lower()
    slug = CONNECTOR_SLUG_RE.sub("-", str(name or "").strip().lower()).strip("-")
    budget = max(1, MAX_JOB_TYPE_LEN - len(module_id) - 1)
    candidate = f"{module_id}.{slug[:budget]}"
    try:
        return normalize_job_type(candidate)
    except BadRequestException as exc:
        raise BadRequestException(
            f"cannot reserve a job type for connector '{name}' in module '{module}': {exc.detail}"
        ) from exc


def normalize_asset_types(raw: Any) -> list[str]:
    """Validate consumed inventory sections against the platform's inventory.

    Asset types describe what the *platform* tracks (its inventory vocabulary),
    not what a module knows, so they are validated against ``AssetType``.
    """
    if raw in (None, [], ()):
        return []
    if not isinstance(raw, (list, tuple)):
        raise BadRequestException("asset_types must be a list of asset type identifiers")
    if len(raw) > MAX_ASSET_TYPES:
        raise BadRequestException(f"asset_types may declare at most {MAX_ASSET_TYPES} entries")
    known = {member.value for member in AssetType}
    cleaned: list[str] = []
    for item in raw:
        value = str(item).strip().lower()
        if value not in known:
            raise BadRequestException(
                f"unknown asset type '{value}': this core tracks {sorted(known)}"
            )
        if value not in cleaned:
            cleaned.append(value)
    return cleaned


def normalize_config_schema(raw: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not raw:
        return {}
    if not isinstance(raw, dict):
        raise BadRequestException("config_schema must be an object of field descriptors")
    if len(raw) > MAX_CONFIG_SCHEMA_FIELDS:
        raise BadRequestException(
            f"config_schema may declare at most {MAX_CONFIG_SCHEMA_FIELDS} fields"
        )
    normalized: dict[str, dict[str, Any]] = {}
    for raw_key, raw_field in raw.items():
        key = str(raw_key).strip()
        if not CONFIG_KEY_RE.match(key):
            raise BadRequestException(f"config key '{key}' must be a lowercase identifier")
        if isinstance(raw_field, ConfigField):
            config_field = raw_field
        else:
            try:
                config_field = ConfigField.model_validate(raw_field)
            except Exception as exc:  # pydantic ValidationError
                raise BadRequestException(
                    f"config field '{key}' is invalid: {exc}"
                ) from exc
        if config_field.label is not None and len(str(config_field.label)) > 120:
            raise BadRequestException(f"config field '{key}' label is too long")
        normalized[key] = config_field.to_dict()
    return normalized


def normalize_declared_fields(raw: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    """Validate a module's declared finding-field specification."""
    if not raw:
        return {}
    if not isinstance(raw, dict):
        raise BadRequestException("fields must be an object of field descriptors")
    if len(raw) > MAX_DECLARED_FIELDS:
        raise BadRequestException(f"a module may declare at most {MAX_DECLARED_FIELDS} fields")
    normalized: dict[str, dict[str, Any]] = {}
    for raw_key, raw_field in raw.items():
        name = str(raw_key).strip()
        if name in PLATFORM_FINDING_FIELDS:
            raise BadRequestException(
                f"'{name}' is provided by the platform and cannot be declared"
            )
        if not FIELD_NAME_RE.match(name):
            raise BadRequestException(f"field name '{name}' must be a lowercase identifier")
        try:
            declared = (
                raw_field
                if isinstance(raw_field, DeclaredField)
                else DeclaredField.model_validate(raw_field)
            )
        except Exception as exc:  # pydantic ValidationError
            raise BadRequestException(f"field '{name}' is invalid: {exc}") from exc
        if declared.label is not None and len(str(declared.label)) > 120:
            raise BadRequestException(f"field '{name}' label is too long")
        normalized[name] = declared.to_dict()
    return normalized


def normalize_dedup_fields(
    raw: Any, *, declared: dict[str, dict[str, Any]] | None = None
) -> list[str]:
    """Validate the fields that identify a finding, in order."""
    if raw in (None, [], ()):
        return []
    if not isinstance(raw, (list, tuple)):
        raise BadRequestException("dedup_fields must be a list of field names")
    if len(raw) > MAX_DEDUP_FIELDS:
        raise BadRequestException(f"dedup_fields may name at most {MAX_DEDUP_FIELDS} fields")
    cleaned: list[str] = []
    for item in raw:
        name = str(item).strip()
        if not FIELD_NAME_RE.match(name):
            raise BadRequestException(f"invalid dedup field '{name}'")
        if declared is not None and name not in declared:
            raise BadRequestException(f"dedup field '{name}' is not a declared field")
        if name not in cleaned:
            cleaned.append(name)
    return cleaned


# ---------------------------------------------------------------------------
# Declared-schema validation (dynamic, built from the module's own fields)
# ---------------------------------------------------------------------------

_TYPE_HINTS: dict[str, Any] = {
    "str": Annotated[str, StringConstraints(max_length=MAX_STR_LEN)],
    "text": Annotated[str, StringConstraints(max_length=MAX_TEXT_LEN)],
    "int": StrictInt,
    "float": float,
    "bool": StrictBool,
    "date": date,
    "list_str": Annotated[
        list[Annotated[str, StringConstraints(max_length=MAX_LIST_ITEM_LEN)]],
        Field(max_length=MAX_LIST_ITEMS),
    ],
}


def _reject_control_characters(cls, value):  # noqa: ANN001 - pydantic validator
    if isinstance(value, str) and CONTROL_CHARS_RE.search(value):
        raise ValueError("control characters are not allowed")
    return value


def _clean_attributes(cls, value):  # noqa: ANN001 - pydantic validator
    if value is None:
        return {}
    # The same sanitizer the wire schema uses: a module's own payload may not
    # smuggle nested objects or oversized blobs into the JSON column.
    return sanitize_attributes(value, strict=True)


_VALIDATORS = {
    "reject_control_characters": field_validator("*", mode="before")(
        _reject_control_characters
    ),
    "clean_attributes": field_validator("attributes", mode="before")(_clean_attributes),
}


@lru_cache(maxsize=64)
def _declared_model_cached(finding_kind: str, fields_json: str) -> type[BaseModel]:
    fields: dict[str, dict[str, Any]] = json.loads(fields_json)
    annotations: dict[str, Any] = {}
    for name, spec in fields.items():
        expected = _TYPE_HINTS.get(str(spec.get("type") or "str"), _TYPE_HINTS["str"])
        if spec.get("required"):
            annotations[name] = (expected, Field(...))
        else:
            annotations[name] = (expected | None, Field(default=None))
    # ``Optional[...]`` rather than ``Annotated[...] | None``: mypy resolves a bare
    # ``Annotated`` subscript to ``object`` in expression (non-annotation) position,
    # so the ``|`` operator is rejected there even though it is valid at runtime.
    annotations["matched_asset"] = (
        Optional[Annotated[str, StringConstraints(max_length=MAX_MATCHED_ASSET_LEN)]],
        Field(default=None),
    )
    annotations["attributes"] = (dict[str, Any] | None, Field(default=None))
    return create_model(  # type: ignore[call-overload]
        f"DeclaredFinding_{finding_kind}",
        __config__=ConfigDict(extra="forbid", str_strip_whitespace=True),
        __validators__=_VALIDATORS,
        **annotations,
    )


def declared_finding_model(spec: ModuleSpec) -> type[BaseModel]:
    """The validator for a module's own declared finding shape.

    Built once per (kind, fields) and cached: a module's schema is changed by an
    admin action, not per request, so rebuilding it per submission would be
    wasted work — but the cache key includes the fields, so a change takes effect
    immediately.
    """
    return _declared_model_cached(
        spec.finding_kind,
        json.dumps(spec.fields, sort_keys=True, separators=(",", ":")),
    )


class FindingBatchValidator:
    """Validates a connector's whole submission batch against one module."""

    def __init__(self, model: type[BaseModel]) -> None:
        self.model = model
        # mypy cannot subscript a variable as a type; listing the schemas again
        # here is exactly the hardcoding this module exists to remove.
        self._adapter = TypeAdapter(list[model])  # type: ignore[valid-type]

    def validate_python(self, payload: Any) -> list[BaseModel]:
        return self._adapter.validate_python(payload)


def finding_adapter_for(spec: ModuleSpec) -> FindingBatchValidator | None:
    """The validator a module's submissions must satisfy, or ``None``.

    ``None`` means the module names a write adapter this core does not
    implement — a hard error, never a silent fallback to another shape.
    """
    if spec.adapter == GENERIC_ADAPTER:
        return FindingBatchValidator(declared_finding_model(spec))
    model = NATIVE_ADAPTER_MODELS.get(spec.adapter)
    if model is None:
        return None
    return FindingBatchValidator(model)


def declared_dedup_key(spec: ModuleSpec, finding: dict[str, Any]) -> str:
    """Comparison key of a finding, from the module's declared dedup fields."""
    parts: list[str] = []
    for name in spec.dedup_fields:
        raw = finding.get(name)
        value = "" if raw is None else re.sub(r"\s+", " ", str(raw).strip())
        parts.append(value)
    return "|".join(parts)[:512]


def declared_title(spec: ModuleSpec, finding: dict[str, Any]) -> str:
    """Headline for lists and alerts: the module's title field, then fallbacks."""
    candidates: list[str] = []
    if spec.title_field:
        candidates.append(spec.title_field)
    candidates.extend(spec.dedup_fields)
    candidates.extend(spec.declared_field_names)
    for name in candidates:
        raw = finding.get(name)
        if raw not in (None, "", []):
            text = str(raw).strip()
            if text:
                return text[:MAX_TITLE_LEN]
    return spec.label[:MAX_TITLE_LEN]


# ---------------------------------------------------------------------------
# Manifest construction and resolution
# ---------------------------------------------------------------------------


def build_manifest(
    *,
    module_spec: ModuleSpec,
    job_type: str,
    finding_kind: str | None = None,
    asset_types: Any = None,
    config_schema: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate and normalize a connector manifest into a JSON-safe dict.

    The module's own record is the authority for which finding kind exists, so a
    connector cannot invent one and cannot attach its findings to another
    module's storage.
    """
    effective_job_type = normalize_job_type(job_type)
    kind = normalize_finding_kind(finding_kind or module_spec.finding_kind)
    if kind != module_spec.finding_kind:
        raise BadRequestException(
            f"module '{module_spec.id}' declares finding_kind "
            f"'{module_spec.finding_kind}', not '{kind}'"
        )
    return {
        "module": module_spec.id,
        "job_type": effective_job_type,
        "finding_kind": kind,
        "asset_types": normalize_asset_types(asset_types),
        "config_schema": normalize_config_schema(config_schema),
    }


def resolve_manifest(
    *,
    module_spec: ModuleSpec | None,
    connector_type: str,
    default_job_type: str,
    manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The manifest a stored connector row resolves to.

    Registration always stores a manifest, so this is a read-side normalisation
    rather than a repair: the resolved shape is derived from the module's own
    record, and an unknown module (a row written by a newer core, or one whose
    module was removed) resolves to a shape with no finding kind instead of
    inventing one.
    """
    stored = dict(manifest or {})
    module = stored.get("module") or connector_type
    if module_spec is None or module_spec.id != module:
        return {
            "module": str(module),
            "job_type": str(default_job_type or ""),
            "finding_kind": "",
            "asset_types": [],
            "config_schema": {},
        }
    return build_manifest(
        module_spec=module_spec,
        # ``default_job_type`` is the authoritative column: it is what work
        # claiming filters on, so the resolved manifest must never disagree with
        # it. The copy inside the manifest is a snapshot of the same declaration.
        job_type=default_job_type,
        finding_kind=stored.get("finding_kind"),
        asset_types=stored.get("asset_types"),
        config_schema=stored.get("config_schema"),
    )


# ---------------------------------------------------------------------------
# Per-connector configuration validation
# ---------------------------------------------------------------------------


def _coerce_field(key: str, field: dict[str, Any], value: Any) -> Any:
    expected = str(field.get("type") or "str")
    if expected == "bool":
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value.strip().lower() in {"true", "false"}:
            return value.strip().lower() == "true"
        raise BadRequestException(f"config '{key}' must be a boolean")
    if expected == "int":
        if isinstance(value, bool):
            raise BadRequestException(f"config '{key}' must be an integer")
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.strip().lstrip("-").isdigit():
            return int(value.strip())
        raise BadRequestException(f"config '{key}' must be an integer")
    if expected == "float":
        if isinstance(value, bool):
            raise BadRequestException(f"config '{key}' must be a number")
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value.strip())
            except ValueError as exc:
                raise BadRequestException(f"config '{key}' must be a number") from exc
        raise BadRequestException(f"config '{key}' must be a number")
    if not isinstance(value, str):
        raise BadRequestException(f"config '{key}' must be a string")
    if len(value) > 2000:
        raise BadRequestException(f"config '{key}' is too long")
    return value


def validate_connector_config(manifest: dict[str, Any], config: Any) -> dict[str, Any]:
    """Validate a config payload against the connector's own declared schema.

    A connector that declared a schema gets strict treatment: only declared keys
    are stored, every value is coerced to the declared type, and declared
    defaults are materialized so the connector always receives a complete
    config. A connector that declared no schema accepts scalars only, which is
    what stops a nested object from being smuggled into the JSON column.
    """
    if not isinstance(config, dict):
        raise BadRequestException("config must be an object")
    schema = dict((manifest or {}).get("config_schema") or {})
    cleaned: dict[str, Any] = {}
    for raw_key, raw_value in config.items():
        key = str(raw_key)
        if not CONFIG_KEY_RE.match(key):
            raise BadRequestException(f"invalid config key '{key}'")
        field = schema.get(key)
        if field is None:
            if not schema and isinstance(raw_value, (bool, int, float, str)):
                cleaned[key] = raw_value
            continue
        cleaned[key] = _coerce_field(key, field, raw_value)
    # Materialize declared defaults so the connector always receives them.
    for key, field in schema.items():
        if key not in cleaned and field.get("default") is not None:
            cleaned[key] = field["default"]
    return cleaned


__all__ = [
    "CORE_OWNED_JOB_TYPES",
    "DECLARED_FIELD_TYPES",
    "GENERIC_ADAPTER",
    "NATIVE_ADAPTER_MODELS",
    "PLATFORM_FINDING_FIELDS",
    "ConfigField",
    "DeclaredField",
    "FindingBatchValidator",
    "ModuleSpec",
    "build_manifest",
    "declared_dedup_key",
    "declared_finding_model",
    "declared_title",
    "finding_adapter_for",
    "normalize_asset_types",
    "normalize_config_schema",
    "normalize_declared_fields",
    "normalize_dedup_fields",
    "normalize_finding_kind",
    "normalize_job_type",
    "normalize_module_id",
    "provisioning_job_type",
    "resolve_manifest",
    "validate_connector_config",
]
