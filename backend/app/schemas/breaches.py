import re
import uuid
from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.common import PaginatedResponse
from app.schemas.email import EmailAddress

#: How loud a finding is, from the classes of data it exposed (F-13). A closed set,
#: because a filter built on anything else could only ask a question with no answer;
#: ``unknown`` is what a row whose classes the platform does not recognize is.
BreachSeverity = Literal["critical", "high", "medium", "low", "unknown"]

#: The sortable fields of the list, keyed by exactly the literals the API accepts, so
#: no caller input ever reaches ``ORDER BY`` as text (the phishing list's pattern).
BreachSortField = Literal["created_at", "breach_date", "pwn_count", "severity"]

#: The source-declared flags a list can be filtered by. They live in ``attributes``
#: because they are the reporting source's statements, not the platform's.
BreachFlag = Literal["verified", "spam", "fabricated", "sensitive"]

SortDirection = Literal["asc", "desc"]

# The vendor's REST payload schema used to live here, when the core called the
# upstream API itself. Scanning lives in connector containers, so validating a
# specific vendor's response shape is the connector's job and the core keeps
# only the provider-neutral result (see BreachResponse).

#: Hostnames this module will put in front of a provider, normalised to the spelling a
#: provider stores. One rule for every request that names a domain — a scan, a targeted
#: lookup, a verification — because two spellings of the same host were how a domain could
#: be refused as unverified while the list showed it as monitored.
_FQDN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")


def _validate_fqdn(value: str) -> str:
    cleaned = str(value).strip().lower()
    if not _FQDN.match(cleaned):
        raise ValueError("domain: invalid FQDN format")
    return cleaned


class BreachResponse(BaseModel):
    """A breach finding.

    Fields are the ones every breach source can supply; whatever the reporting
    source knows beyond that is returned in ``attributes`` and rendered
    generically by the UI, so a new source needs no API change.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source_id: str = "unattributed"
    breach_name: str
    title: str
    domain: str
    breach_date: date
    pwn_count: int
    description: str | None
    data_classes: list[str]
    matched_email: str | None
    matched_domain: str | None
    status: str
    #: Which class of exposure this row records: ``breach`` (an account was compromised),
    #: ``paste`` (it appeared in a paste) or ``stealer_log`` (a site was found in a
    #: stealer log). The module's dedup keys do not move for it, and a row stored before
    #: the column existed is a breach, which is what the module represented then (WI-21).
    exposure_kind: str = "breach"
    #: How loud this row is, from the classes of data it exposed (F-13): ``critical``
    #: is a plaintext credential or payment data, ``low`` an address list. Stored on
    #: the row when it is written, so the list's filter and its sort read one value.
    severity: str = "unknown"
    #: Provider-specific payload (e.g. verification flags, catalog timestamps).
    attributes: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    #: When the source last reported this incident, and when it first confirmed it.
    last_seen_at: datetime | None = None
    verified_at: datetime | None = None
    #: True when the row was stored without the facts that normally describe an
    #: incident. The page says so instead of presenting the stored date as the
    #: incident's own (F-02).
    metadata_incomplete: bool = False
    matched_asset: str | None = None
    matched_asset_type: str | None = None
    #: How many incidents the platform holds about the same address. A row is one
    #: incident about one account, so a leaked address that already appears in three
    #: others is a triage fact this list would otherwise hide (F-13). Present only
    #: when the row names an address.
    email_incident_count: int | None = None


class BreachListResponse(PaginatedResponse):
    items: list[BreachResponse]
    #: How many breach findings have arrived and not been announced to anyone yet:
    #: the notifications still in the outbox, which is what an installation with no
    #: configured channel used to lose sight of entirely (F-06). It counts what is
    #: *undelivered*, so a save that configures a channel brings it to zero, and a
    #: finding the noise policy consumed on purpose is not in it.
    unannounced: int = 0
    #: The instant "new since the last scan" is measured from: the completion of the
    #: most recent terminal breach scan, or ``None`` when no scan has finished. The
    #: page names it rather than showing a filtered list that cannot be explained.
    new_since: datetime | None = None


class BreachDomainReadiness(BaseModel):
    """What the last scan could ask about one domain it was given (F-04, WI-14).

    ``unscanned`` is a refusal by the provider and always names why; ``asked`` is a
    domain the scan did ask its source about, so "no findings" is an answer about the
    domain rather than about the account; ``unknown`` is a domain the scan never reached
    because it stopped early. The three are kept apart because only one of them means
    "nothing was found".
    """

    domain: str
    status: str = Field(pattern="^(asked|unscanned|unknown)$")
    reason: str | None = None


class BreachProviderEntitlements(BaseModel):
    """What the source says this account may do, in neutral words.

    Every field is optional: a provider that does not publish one leaves it ``None``,
    which the page renders as "not stated" rather than as a negative answer. Nothing
    here names a vendor — the facts are the subscription's own name, the rate it
    states, whether the account includes stealer logs and k-anonymity ranges, and how
    many domains it has verified.
    """

    subscription: str | None = None
    requests_per_minute: int | None = None
    includes_stealer_logs: bool | None = None
    includes_kanon: bool | None = None
    domains_verified: int | None = None


class BreachDomainVerificationReadiness(BaseModel):
    """The last verification attempt for one domain, as the core read it back (WI-20).

    Verification is not a scan and stores no finding: its result is a fact about the
    *account's* access to the domain, and the page needs it beside the domains the last
    scan was refused. ``generated`` carries the record the operator has to publish;
    ``verified`` means the provider has accepted it, which is what turns a domain from
    "not scanned" into something a scan can ask about.
    """

    domain: str
    action: str = Field(pattern="^(generate|verify)$")
    status: str = Field(pattern="^(generated|verified|not_verified|failed)$")
    reason: str | None = None
    #: The TXT value exactly as the provider stated it, for an operator to publish.
    txt_record_value: str | None = None
    job_id: uuid.UUID | None = None
    requested_at: datetime | None = None


class BreachDomainVerificationRequest(BaseModel):
    """One operator-requested step of the domain-verification flow (WI-20).

    The domain is the one to enrol in the source's account, the action says whether to
    ask for the record or to check it, and ``connector`` names the worker that should do
    it — required only when more than one enabled source could be asked, because a
    verification belongs to one source's account rather than to the module.
    """

    domain: str = Field(..., min_length=3, max_length=255)
    action: Literal["generate", "verify"]
    connector: str | None = Field(default=None, max_length=100)

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, v: str) -> str:
        return _validate_fqdn(v)


class BreachProviderReadinessResponse(BaseModel):
    """What the last breach scan was allowed to ask, and what it could not (WI-14).

    Read from the scan's own summary rather than from the provider: the platform reports
    what it did with the account it holds, and the page can then tell "this domain was
    refused" from "this domain has no breaches" instead of presenting both as an empty
    list. ``data_class_labels`` is the source's own words for the classes of data it
    reports (F-04), so a page renders the provider's vocabulary instead of its own.
    """

    scan_job_id: uuid.UUID | None = None
    #: The source the reported scan ran on. A verification request has to name one source
    #: when several could be asked, so the page offers the one that produced the readiness
    #: it is showing rather than making an operator remember which.
    connector: str | None = None
    scanned_at: datetime | None = None
    #: The scan's own verdict, as Jobs reports it, and the reasons behind a partial one
    #: — one wording for both surfaces, because two would eventually disagree.
    status: str | None = None
    partial: bool = False
    reasons: dict[str, int] = Field(default_factory=dict)
    entitlements: BreachProviderEntitlements | None = None
    pacing: dict[str, Any] = Field(default_factory=dict)
    domains: list[BreachDomainReadiness] = Field(default_factory=list)
    unscanned_total: int = 0
    data_class_labels: dict[str, str] = Field(default_factory=dict)
    #: The newest verification attempt per domain (WI-20), read from the jobs that asked
    #: for one. Kept beside the domains rather than in them: a verification is a fact
    #: about the account's access, and it outlives the scan that reported a refusal.
    verifications: list[BreachDomainVerificationReadiness] = Field(default_factory=list)


class BreachScanEmailRequest(BaseModel):
    email: EmailAddress = Field(
        ..., max_length=255, description="Email address to scan for breaches"
    )


class BreachScanDomainRequest(BaseModel):
    domain: str = Field(
        ..., min_length=3, max_length=255, description="Domain name to scan for breaches"
    )

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, v: str) -> str:
        return _validate_fqdn(v)
