import ipaddress
import re
import uuid
from datetime import date, datetime
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    TypeAdapter,
    field_validator,
)

from app.schemas.common import PaginatedResponse
from app.schemas.email import EmailAddress
from app.schemas.user import AssetType

AssetCriticality = Literal["low", "medium", "high", "critical"]

#: The fields ``GET /assets`` may be sorted by (WI-16). An allowlist rather than
#: a free string, because the value reaches ``ORDER BY`` and caller input must
#: never be concatenated into a statement: FastAPI rejects anything outside this
#: set with 422 before the service sees it, and
#: ``AssetService.ASSET_SORT_COLUMNS`` maps each member to a real column —
#: ``tests/test_assets_integration.py`` fails if the two sets drift apart.
AssetSortField = Literal[
    "created_at", "updated_at", "asset_value", "asset_type", "criticality", "is_active"
]
SortDirection = Literal["asc", "desc"]
_AssetTypeLiteralValues = {"domain", "ip_address", "email_account", "keyword_domain", "keyword_title"}

_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

_IP_ADAPTER: TypeAdapter = TypeAdapter(IPvAnyAddress)
_EMAIL_ADAPTER: TypeAdapter = TypeAdapter(EmailAddress)

#: Longest keyword the platform accepts. A phrase this long is already far past
#: what any provider query budget can use, and the column is wider than it.
KEYWORD_MAX_LENGTH = 200
#: Characters a keyword may not contain (AST-10). A quote or backslash is the
#: escape and phrase delimiter of the provider search grammars, so such a value
#: could close the phrase and add filters of its own; control characters are
#: never part of a brand or page title. The connectors that build queries from
#: keywords apply the same set (``connectors/shodan/main.py``), so a value the
#: API accepts is a value a scan can safely quote.
_KEYWORD_FORBIDDEN_RE = re.compile(r'["\\\x00-\x1f]')


def normalize_asset_value(asset_type: str, value: str) -> str:
    """Return the canonical value used for matching, indexing and deduplication."""
    raw = value.strip()
    if asset_type == "domain":
        return raw.rstrip(".").lower().encode("idna").decode("ascii")
    if asset_type == "email_account":
        local, separator, domain = raw.partition("@")
        return f"{local}@{domain.lower()}" if separator else raw.lower()
    if asset_type == "ip_address":
        return str(ipaddress.ip_address(raw))
    return raw


def validate_and_normalize_asset_value(asset_type: str, value: str) -> str:
    """Validate an asset value for its type and return its canonical form."""
    try:
        normalized = normalize_asset_value(asset_type, value)
    except (ValueError, UnicodeError) as exc:
        if asset_type == "ip_address":
            raise ValueError("Invalid IP address format") from exc
        if asset_type == "domain":
            raise ValueError("Invalid domain format") from exc
        raise ValueError("Invalid asset value") from exc
    if asset_type == "domain" and not _HOSTNAME_RE.match(normalized):
        raise ValueError("Invalid domain format")
    if asset_type == "ip_address":
        try:
            _IP_ADAPTER.validate_python(normalized)
        except Exception as exc:
            raise ValueError("Invalid IP address format") from exc
    if asset_type == "email_account":
        try:
            _EMAIL_ADAPTER.validate_python(normalized)
        except Exception as exc:
            raise ValueError("Invalid email format") from exc
    if asset_type in ("keyword_domain", "keyword_title"):
        if not normalized:
            raise ValueError("Keyword cannot be empty")
        if len(normalized) > KEYWORD_MAX_LENGTH:
            raise ValueError(f"A keyword must be at most {KEYWORD_MAX_LENGTH} characters")
        if _KEYWORD_FORBIDDEN_RE.search(normalized):
            raise ValueError(
                "A keyword cannot contain quotes, backslashes or control characters"
            )
    return normalized


#: Import and bulk limits (WI-18/AST-24).
#:
#: One call must not become an unbounded transaction: a bounded number of rows, a
#: bounded decoded body, and a bounded number of ids per bulk action. They are
#: named here rather than inline so the UI and the API cannot disagree about what
#: "too many" means — the reconciliation gate (`frontend/src/lib/api.ts` reads
#: them through the API's own refusals) starts from one number.
IMPORT_MAX_ITEMS = 1000
IMPORT_MAX_BYTES = 1_048_576
BULK_MAX_IDS = 500

#: The largest inventory an export will render in one file. Exporting is a read,
#: but a single response carrying a million rows is a memory incident, so past
#: this the export is refused with the filter that would narrow it.
EXPORT_MAX_ROWS = 10_000


class AssetImportItem(BaseModel):
    """One row of an import, as the file states it — *not* validated per row yet.

    ``asset_type`` is a plain string rather than the ``AssetType`` literal on
    purpose: a wrong type on line 3 of a 200-line file must come back as a row
    error next to the other rows, not as a 422 that rejects the whole request and
    names no line (WI-18/AST-24). The row reaches the same validator every other
    write uses when it is turned into an ``AssetCreate``.
    """

    asset_type: str = Field(..., max_length=32)
    asset_value: str = Field(..., max_length=512)
    criticality: AssetCriticality = "medium"

    model_config = ConfigDict(use_enum_values=True)


class AssetImportRequest(BaseModel):
    items: list[AssetImportItem] = Field(..., max_length=IMPORT_MAX_ITEMS)
    #: Report what the import would do without creating anything. The rows go
    #: through the same validation and duplicate check, then the transaction is
    #: rolled back — a dry run that took a different code path would answer a
    #: different question from the one the operator then commits to.
    dry_run: bool = False

    model_config = ConfigDict(use_enum_values=True)


class AssetImportRow(BaseModel):
    """One line of the import report, so a failure names its own row."""

    line: int
    outcome: Literal["created", "duplicate", "invalid"]
    asset_type: str | None = None
    asset_value: str | None = None
    detail: str | None = None


class AssetImportResponse(BaseModel):
    dry_run: bool
    created: int
    duplicate: int
    invalid: int
    rows: list[AssetImportRow]


class AssetBulkRequest(BaseModel):
    operation: Literal["activate", "deactivate", "criticality", "delete"]
    ids: list[uuid.UUID] = Field(..., min_length=1, max_length=BULK_MAX_IDS)
    #: Required by ``criticality``, ignored otherwise.
    criticality: AssetCriticality | None = None
    #: Only meaningful for ``delete``; the same flag as the single-asset route.
    cascade_findings: bool = False

    model_config = ConfigDict(use_enum_values=True)


class AssetBulkResponse(BaseModel):
    operation: str
    requested: int
    applied: int
    missing: list[str]
    cascade_findings: bool = False
    findings_deleted: dict[str, int] = Field(default_factory=dict)


class AssetBase(BaseModel):
    asset_type: AssetType
    asset_value: str = Field(..., max_length=512)
    criticality: AssetCriticality = "medium"
    is_active: bool = True

    model_config = ConfigDict(from_attributes=True, use_enum_values=True)

    @field_validator("asset_type", mode="before")
    @classmethod
    def _coerce_asset_type(cls, v):
        if v is None:
            return v
        if hasattr(v, "value"):
            s = v.value
        else:
            s = str(v)
        if s in _AssetTypeLiteralValues:
            return s
        return v

    @field_validator("criticality", mode="before")
    @classmethod
    def _coerce_criticality(cls, v):
        if v is None:
            return v
        if hasattr(v, "value"):
            return v.value
        return str(v)


class AssetCreate(AssetBase):
    @field_validator("asset_value")
    @classmethod
    def validate_asset_value(cls, v: str, info) -> str:
        asset_type = info.data.get("asset_type")
        if not asset_type:
            return v
        validate_and_normalize_asset_value(asset_type, v)
        return v


class AssetUpdate(BaseModel):
    asset_type: AssetType | None = None
    asset_value: str | None = Field(None, max_length=512)
    criticality: AssetCriticality | None = None
    is_active: bool | None = None

    @field_validator("asset_value")
    @classmethod
    def validate_asset_value(cls, v: str | None, info) -> str | None:
        if v is None:
            return v
        asset_type = info.data.get("asset_type")
        if not asset_type:
            return v
        validate_and_normalize_asset_value(asset_type, v)
        return v


class AssetFindingSummary(BaseModel):
    """How much of the platform's data names one asset, per module (WI-20).

    Declared once and filled from one place (:func:`asset_matching.related_finding_summary_columns`),
    so the counter in a list row and the tab counters on the asset page are the
    same number, computed by the same predicates.
    """

    total: int = 0
    phishing: int = 0
    breaches: int = 0
    dns: int = 0
    exposure: int = 0
    findings: int = 0
    #: When each module last saw a finding about this asset, as ISO text. A
    #: breach reports a disclosure *date* while a scan reports a timestamp, so
    #: the two are published as text instead of being compared as datetimes.
    last_seen: dict[str, str | None] = Field(default_factory=dict)


class AssetResponse(AssetBase):
    id: uuid.UUID
    normalized_value: str | None = None
    created_at: datetime
    updated_at: datetime
    #: Present on list rows: the asset's involvement, so "present in the table"
    #: and "actually monitored" are distinguishable without opening each asset.
    findings: AssetFindingSummary | None = None

    model_config = ConfigDict(from_attributes=True)


class PromotedAssetResponse(BaseModel):
    """What the four promotion routes answer: the asset, and whether it existed.

    `asset` reuses :class:`AssetResponse` rather than restating its fields, because a
    promotion and a read return the same resource and two declarations of it would
    drift. Until this model existed the nested object was a SQLAlchemy row serialized
    by `jsonable_encoder`, so the payload was whatever columns the table happened to
    have; now it is the set of fields the rest of the API describes.

    `source` is optional: the DNS and exposure promotions name the observation's
    source, the breach and phishing ones have no such field, and the routes exclude
    nulls so an absent key stays absent.
    """

    already_exists: bool
    asset: AssetResponse
    source: str | None = None


#: The modules whose findings can name an asset, spelled as
#: `services/asset_matching.RELATED_FINDING_MODULES` spells them. A `Literal` rather
#: than a free string, because a row can only name a module the view can list.
RelatedFindingModule = Literal["phishing", "breaches", "dns", "exposure", "findings"]


class AssetFindingSubject(BaseModel):
    """The asset a findings view is about — the header, not the whole row.

    The page names the asset it is showing and nothing else from `assets`, so this
    is the four fields it reads rather than an `AssetResponse`: a column added to
    the table is not something this answer has to decide about.
    """

    id: uuid.UUID
    asset_type: AssetType
    asset_value: str
    is_active: bool


class AssetFindingCounts(BaseModel):
    """One number per module that can name an asset, plus their sum.

    The names are the contract: `RELATED_FINDING_MODULES` drives the counters and
    the SPA reads them as a closed record, so a module added to that tuple has to
    be added here and in the client type rather than arriving as an extra key the
    interface does not describe.
    """

    phishing: int
    breaches: int
    dns: int
    exposure: int
    findings: int
    total: int


class AssetFindingItem(BaseModel):
    """One related finding, in the one shape every module answers with.

    `observed_at` is deliberately not a single type. A breach reports the *date* it
    was disclosed while a scan reports the timestamp it recorded, and the matching
    module publishes each in its own kind on purpose — declaring `datetime` would
    turn `2024-01-01` into midnight, a moment the platform never observed.
    """

    id: uuid.UUID
    module: RelatedFindingModule
    title: str
    matched_asset: str | None = None
    source: str | None = None
    status: str | None = None
    observed_at: date | datetime | None = None


class AssetFindingsResponse(BaseModel):
    """What the platform holds about one asset, across every module (WI-12/AST-22).

    The optional row fields are sent as `null` rather than omitted, which is why the
    route declares this model without `response_model_exclude_none`: the client
    types them `string | null`, and a key that disappears would be a different
    answer from the one it was written against.
    """

    asset: AssetFindingSubject
    counts: AssetFindingCounts
    #: When each module last saw a finding about this asset (WI-20), as the ISO text
    #: that module publishes: a disclosure date or a scan timestamp.
    last_seen: dict[str, str | None] = Field(default_factory=dict)
    module: RelatedFindingModule
    items: list[AssetFindingItem]
    total: int
    page: int
    size: int
    pages: int


class AssetListResponse(PaginatedResponse[AssetResponse]):
    items: list[AssetResponse]
