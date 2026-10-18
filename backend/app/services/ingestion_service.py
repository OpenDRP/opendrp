"""Validated, idempotent connector ingestion with caller-owned transactions."""

from datetime import date as _date, datetime, timezone
from dataclasses import dataclass, field
import hashlib
import json
import re

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from app.core.config import settings as core_settings
from app.models import Finding, PhishingDomain, Breach, Job
from app.services.alert_policy import AlertPolicy, policy_from_environment, resolve_alert_policy
from app.services.breach_severity import severity_for_data_classes
from app.services.alert_delivery_service import (
    AlertDeliveryService,
)  # findings reach the alert queue through this service
from app.schemas.connector import sanitize_attributes, MAX_FINDINGS_PER_BATCH
from app.services.connector_manifest import (
    GENERIC_ADAPTER,
    declared_dedup_key,
    declared_title,
)
from app.services.module_registry import get_module
from app.services.dns_security_service import ingest_dns_observations
from app.services.source_observations import persist, source_identity
from app.services.ingestion_events import record_event
from app.services.phishing_score_service import record_stored_signals

__all__ = ["AlertDeliveryService"]

_MAX_FINDINGS_PER_BATCH = MAX_FINDINGS_PER_BATCH


def _json_safe(value):
    """Round-trip a finding into strict JSON-native primitives.

    The HTTP adapter already serializes Pydantic models this way, but service
    callers and plugins are also untrusted boundaries. Handle only stable scalar
    conversions rather than leaking Python reprs into persisted payloads.
    """

    def encode(item):
        if isinstance(item, (_date, datetime)):
            return str(item)
        if hasattr(item, "hex") and item.__class__.__module__ == "uuid":
            return str(item)
        raise TypeError(f"unsupported finding value: {type(item).__name__}")

    try:
        return json.loads(json.dumps(value, default=encode, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise ValueError("finding is not JSON serializable") from exc


def _clean_str(value, limit):
    return str(value).strip()[:limit] if value is not None else ""


def _parse_nonnegative_int(value):
    try:
        return max(0, int(value or 0))
    except (ValueError, TypeError):
        return 0


def _parse_date(value):
    if isinstance(value, _date):
        return value
    try:
        return _date.fromisoformat(str(value)[:10])
    except (ValueError, TypeError):
        return _date(1970, 1, 1)


def _parse_breach_date(value):
    """The day an incident happened, or ``None`` when the finding carried none.

    Deliberately not :func:`_parse_date`: that one answers *some* usable date for
    every caller, and its answer for a missing or malformed value is 1970-01-01 —
    a date no breach can have, which the page, the report and an alert then present
    as a fact (F-02). A breach with no date is a finding with no date, and the
    caller decides what to do about that.
    """
    if isinstance(value, _date) and not isinstance(value, datetime):
        return value
    if value is None:
        return None
    try:
        return _date.fromisoformat(str(value)[:10])
    except (ValueError, TypeError):
        return None


def _breach_attributes(finding):
    return sanitize_attributes(finding.get("attributes") or {}, strict=False)


#: The classes of exposure the breach module represents: a breach of an account, a
#: paste it appeared in, and a stealer log a site was found in. The vocabulary is
#: closed at the core — a class nothing recognizes would become a filter nobody can
#: select and a label the page cannot write — so a declaration outside it is refused
#: by name rather than stored under the wrong heading (WI-21).
BREACH_EXPOSURE_KINDS: tuple[str, ...] = ("breach", "paste", "stealer_log")

#: What a source that declares no class means. Every source that existed before the
#: column did reported breaches of accounts, which is also all a breach row with no
#: declaration can honestly claim to be.
DEFAULT_BREACH_EXPOSURE_KIND = "breach"


def _breach_exposure_kind(finding) -> str:
    """The class of exposure a finding declares, validated against the known set.

    A refusal rather than a fallback: storing an unrecognized class as a breach of an
    account would put exposure on the page under a heading the source never claimed,
    and the batch result names the reason so the reporter can be fixed.
    """
    declared = finding.get("exposure_kind")
    if declared is None or (isinstance(declared, str) and not declared.strip()):
        return DEFAULT_BREACH_EXPOSURE_KIND
    cleaned = str(declared).strip().lower()
    if cleaned not in BREACH_EXPOSURE_KINDS:
        raise ValueError("invalid_exposure_kind")
    return cleaned


#: What a re-reported incident says, in the words the alert message renders. Most
#: significant first: one delivery reports one event, so an incident that both grew
#: and gained a class reports the arrival of a new class of data, which is the fact
#: an operator has to act on.
BREACH_CHANGE_CLASSES: tuple[str, ...] = (
    "reappeared",
    "new_data_class",
    "incident_grew",
    "now_verified",
    "date_corrected",
)


def _breach_change_class(
    previous: dict, row: Breach, attributes: dict, *, growth_floor: int
) -> str | None:
    """What a re-report of a stored incident says, or ``None`` for nothing new.

    The comparison is against what the platform had *before* this finding was
    applied, which is why the caller copies those fields out first: the update below
    overwrites them. Five facts can each be news, and only one of them is delivered:

    * ``reappeared`` - the incident was resolved by an operator and the source is
      reporting it again. A resolution is an analyst's decision, so it is not
      undone, but silence would be wrong: the data is still out there;
    * ``new_data_class`` - the incident now exposes a class of data it did not;
    * ``incident_grew`` - the number of affected accounts rose by at least the
      configured floor, which is what keeps a source's bookkeeping edits out of the
      channel;
    * ``now_verified`` - the source has confirmed an incident it had not;
    * ``date_corrected`` - the incident's date moved.

    A row that only changed its title or description answers ``None``: those are the
    source's own wording, not a fact about our exposure.
    """
    if previous.get("status") == "resolved":
        return "reappeared"
    now_classes = {str(item) for item in (row.data_classes or [])}
    if now_classes - {str(item) for item in previous.get("data_classes") or []}:
        return "new_data_class"
    if row.pwn_count - int(previous.get("pwn_count") or 0) >= growth_floor:
        return "incident_grew"
    if previous.get("is_verified") is not True and attributes.get("is_verified") is True:
        return "now_verified"
    if previous.get("breach_date") != row.breach_date:
        return "date_corrected"
    return None


def _breach_change_signature(change_class: str, row: Breach) -> str:
    """A short digest of the *change* one delivery reports.

    The outbox key is what makes a delivery once-only, and for a refreshable row it
    has to name the change rather than the row: an incident that grows twice is two
    events, while a scan that repeats the same finding is not a second event. The
    digest is of the facts that decide the class plus the values that arrived, so an
    identical rediscovery stays suppressed and a real one is delivered.
    """
    material = "|".join(
        (
            change_class,
            str(row.pwn_count),
            ",".join(sorted(str(item) for item in row.data_classes or [])),
            str(row.breach_date),
            "verified" if (row.attributes or {}).get("is_verified") is True else "unverified",
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


@dataclass
class IngestionResult:
    received: int = 0
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    rejected: int = 0
    errors: list = field(default_factory=list)

    @property
    def accepted(self):
        return self.created + self.updated + self.unchanged

    def __iter__(self):
        yield self.accepted
        yield self.rejected

    def payload(self):
        return {
            "received": self.received,
            "created": self.created,
            "updated": self.updated,
            "unchanged": self.unchanged,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "errors": self.errors,
        }


async def _phishing(db, connector, finding, job_id, module_spec):
    source = source_identity(connector)
    domain = _clean_str(finding.get("phishing_domain"), 253)
    if not domain:
        raise ValueError("missing_subject")
    finding = {
        **finding,
        "matched_asset": _clean_str(finding.get("matched_asset"), 512) or "unknown",
    }
    row = (
        await db.execute(
            select(PhishingDomain).where(PhishingDomain.phishing_domain == domain)
        )
    ).scalar_one_or_none()
    created = row is None
    # The fields a revision is reported for are copied out *before* the row is
    # touched: the arrival rule compares what the platform already stored with what
    # the connector has just reported, and the update below overwrites the former.
    previous = (
        None
        if created
        else {name: getattr(row, name) for name, _ in _PHISHING_TRACKED_FIELDS}
    )
    if row is None:
        row = PhishingDomain(
            phishing_domain=domain,
            matched_asset=finding["matched_asset"],
            ip_address=finding.get("ip_address"),
            web_ports=finding.get("web_ports"),
            detection_source=source,
            original_domain=finding.get("original_domain"),
            status="active",
        )
        db.add(row)
        await db.flush()
    row_changed = False
    if not created:
        for field_name in (
            "matched_asset",
            "ip_address",
            "web_ports",
            "original_domain",
        ):
            if (
                field_name in finding
                and finding[field_name] is not None
                and getattr(row, field_name) != finding[field_name]
            ):
                setattr(row, field_name, finding[field_name])
                row_changed = True
    changed = await persist(
        db,
        module="phishing",
        source=source,
        finding=finding,
        candidate_id=row.id,
        job_id=job_id,
        connector=connector,
        commit=False,
    )
    # Every observation re-derives the signals the platform can answer for by
    # itself — how many sources have reported the candidate, how old its
    # registration is, whether that registration names a marketplace — so the
    # arrival below is queued with a score an operator can act on rather than with
    # one that appears after some later pass (WI-07/WI-09). The call is idempotent
    # and reads only what is already stored: no provider is called for it.
    await record_stored_signals(db, candidate=row)
    # Only a revision asks the alert policy anything: a first sighting is always
    # reported, while whether a *change* is worth a message is the operator's
    # choice (ALERT_CANDIDATE_CHANGE_NOTIFICATIONS). Reading it here rather than for
    # every finding keeps the extra read off the path a scan walks most of the time.
    policy = None if created else await resolve_alert_policy(db)
    arrival = phishing_arrival(previous, row, finding, source, policy=policy)
    if arrival is not None:
        # One aggregated message carries a first sighting and a revision alike, so
        # the outbox row is the ordinary notification the other modules use. A
        # revision passes its own digest: the candidate keeps one identity across
        # revisions, so keying the row by the entity alone would let the first change
        # collide with the creation event and be swallowed.
        await record_event(
            db,
            kind="notification",
            module="phishing",
            entity_id=row.id,
            job_id=job_id,
            payload=arrival["payload"],
            dedup=arrival["dedup"],
        )
    if created:
        # Enrichment is asked for once, when the candidate first appears.
        await record_event(
            db,
            kind="whois",
            module="phishing",
            entity_id=row.id,
            job_id=job_id,
            payload={},
        )
    return (
        "created" if created else "updated" if changed or row_changed else "unchanged"
    )


async def _breach(db, connector, finding, job_id, module_spec):
    source = source_identity(connector)
    name = _clean_str(finding.get("breach_name"), 255)
    email, domain = finding.get("matched_email"), finding.get("matched_domain")
    if not name or not (email or domain):
        raise ValueError("missing_breach_match")
    conditions = [Breach.source_id == source, Breach.breach_name == name]
    conditions += (
        [Breach.matched_email == email]
        if email
        else [Breach.matched_email.is_(None), Breach.matched_domain == domain]
    )
    attributes = _breach_attributes(finding)
    declared_date = _parse_breach_date(finding.get("breach_date"))
    breach_date = declared_date
    if breach_date is None:
        # A finding with no usable date is refused unless its reporter says the
        # metadata did not arrive (a paste, a leak dump with no catalogue entry):
        # refusing everything would drop real exposure, and inventing a date would
        # store a fact nobody stated. The observation instant is what the row records
        # when the reporter admits the gap -- and the fact that it is not the
        # incident's date travels with the row, so nothing downstream presents it as
        # one (F-02).
        if attributes.get("metadata_incomplete") is not True:
            raise ValueError("missing_breach_date")
        breach_date = datetime.now(timezone.utc).date()
        attributes = {**attributes, "metadata_incomplete": True}
    # Resolved before anything is written: a class the core does not know refuses the
    # finding instead of being stored under a heading nobody asked for (WI-21).
    exposure_kind = _breach_exposure_kind(finding)
    row = (await db.execute(select(Breach).where(*conditions))).scalar_one_or_none()
    created = row is None
    # The fields a re-report is compared against are copied out *before* the row is
    # touched: the change classifier reads what the platform had, and the update
    # below overwrites the former (WI-08).
    previous = (
        None
        if created
        else {
            "pwn_count": row.pwn_count,
            "data_classes": list(row.data_classes or []),
            "status": row.status,
            "breach_date": row.breach_date,
            "is_verified": (row.attributes or {}).get("is_verified"),
        }
    )
    seen_at = datetime.now(timezone.utc)
    if row is None:
        row = Breach(
            source_id=source,
            breach_name=name,
            title=_clean_str(finding.get("title") or name, 255),
            domain=_clean_str(finding.get("domain"), 255),
            breach_date=breach_date,
            pwn_count=_parse_nonnegative_int(finding.get("pwn_count")),
            description=_clean_str(finding.get("description"), 10000) or None,
            data_classes=finding.get("data_classes")
            if isinstance(finding.get("data_classes"), list)
            else [],
            matched_email=email,
            matched_domain=domain,
            exposure_kind=exposure_kind,
            # What can be done with the data, from the classes it exposed (F-13).
            # Computed here, once, rather than in each reader: the list filters and
            # sorts on the stored value (see `app/services/breach_severity.py`).
            severity=severity_for_data_classes(
                finding.get("data_classes")
                if isinstance(finding.get("data_classes"), list)
                else []
            ),
            attributes=attributes,
            last_seen_at=seen_at,
        )
        db.add(row)
        await db.flush()
    row_changed = False
    if not created:
        refreshed = {
            "title": _clean_str(finding.get("title") or name, 255),
            "attributes": _breach_attributes(finding),
        }
        declared_kind = finding.get("exposure_kind")
        if declared_kind is not None and str(declared_kind).strip():
            # A source that was reporting the wrong class can correct it, and the row
            # follows the declaration rather than staying under the old heading. A
            # re-report that declares nothing leaves the stored class alone: absence is
            # not a claim that the row is a breach of an account again.
            refreshed["exposure_kind"] = exposure_kind
        if "domain" in finding:
            refreshed["domain"] = _clean_str(finding.get("domain"), 255)
        if declared_date is not None:
            # Only a date the source *stated* may replace the stored one. When the date
            # above is the observation instant of a row whose metadata did not arrive, it
            # is a fact about the first sighting, not about the incident: re-reading it on
            # every scan would move the row's date each time and report that move as
            # ``date_corrected`` — a weekly notification about nothing (WI-17, WI-18).
            refreshed["breach_date"] = declared_date
        if "pwn_count" in finding:
            refreshed["pwn_count"] = _parse_nonnegative_int(finding.get("pwn_count"))
        if "description" in finding:
            refreshed["description"] = (
                _clean_str(finding.get("description"), 10000) or None
            )
        if isinstance(finding.get("data_classes"), list):
            refreshed["data_classes"] = finding["data_classes"]
        for field_name, value in refreshed.items():
            if getattr(row, field_name) != value:
                setattr(row, field_name, value)
                row_changed = True
        # The severity follows the classes it was derived from, and is recomputed on a
        # re-report as well: a source that corrects its data classes changes what can
        # be done with the leak, and a row stored before the rule existed stops reading
        # as ``unknown`` the first time its incident is reported again.
        severity = severity_for_data_classes(row.data_classes)
        if row.severity != severity:
            row.severity = severity
            row_changed = True
        # A sighting is not a change to the row's facts, which is why it is written
        # outside the comparison above: the source reporting the incident again is
        # what ``last_seen_at`` records, and what makes "is this incident still
        # arriving?" a question the platform can answer (WI-08, WI-11). A source that
        # confirms an incident it had not also leaves the instant of that statement.
        if refreshed.get("attributes", {}).get("is_verified") is True and (
            previous or {}
        ).get("is_verified") is not True:
            row.verified_at = seen_at
    row.last_seen_at = seen_at
    evidence = {
        **finding,
        "subject": email or domain,
        "matched_asset": email or domain,
        "attributes": _breach_attributes(finding),
    }
    changed = await persist(
        db,
        module="breaches",
        source=source,
        finding=evidence,
        job_id=job_id,
        connector=connector,
        commit=False,
    )
    # What this finding *says* about an incident the platform already had, if
    # anything: a first sighting is an incident, and a later sighting is only news
    # when one of the five facts above moved (WI-08, WI-11). The outbox key carries
    # the change, so the same re-report is delivered once and the next real change
    # is delivered again.
    change_class = (
        "new_incident"
        if created
        else _breach_change_class(
            previous or {},
            row,
            attributes,
            growth_floor=core_settings.ALERT_BREACH_GROWTH_FLOOR,
        )
    )
    if change_class is not None:
        await record_event(
            db,
            kind="notification",
            module="breach",
            entity_id=row.id,
            job_id=job_id,
            dedup=None
            if created
            else _breach_change_signature(change_class, row),
            payload={
                "finding_id": str(row.id),
                "source": source,
                "description": row.description,
                "status": row.status,
                "created_at": row.created_at.isoformat(),
                "breach_name": name,
                "title": row.title,
                "domain": row.domain,
                "breach_date": str(row.breach_date),
                "pwn_count": row.pwn_count,
                "data_classes": row.data_classes,
                "matched_email": email,
                "matched_domain": domain,
                "attributes": row.attributes,
                #: The class of exposure this row is — a breach of an account, a paste,
                #: or a stealer-log site. Read from the row rather than the finding, so
                #: a message sent later names what the platform actually stores; a batch
                #: of mixed classes is what makes the column necessary at all (WI-17).
                "exposure_kind": row.exposure_kind,
                #: Why this incident is in the channel at all, in the vocabulary the
                #: message renders as its first column.
                "change_class": change_class,
                "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
            },
        )
    # A row whose facts are identical can still be an arrival: a reappearance
    # carries no change to the row at all (the analyst's resolution stands), so the
    # outcome has to consult the event rather than the row. Reporting it as
    # ``unchanged`` would tell the connector nothing arrived while a notification
    # was queued (WI-08, WI-11).
    if created:
        return "created"
    if changed or row_changed or change_class is not None:
        return "updated"
    return "unchanged"


async def _generic(db, connector, finding, job_id, module_spec):
    source = source_identity(connector)
    key = declared_dedup_key(module_spec, finding)
    if not key or set(key.split("|")) == {""}:
        raise ValueError("missing_dedup_key")
    row = (
        await db.execute(
            select(Finding).where(
                Finding.module == module_spec.id, Finding.dedup_key == key
            )
        )
    ).scalar_one_or_none()
    if row:
        if row.payload == finding:
            return "unchanged"
        row.payload = finding
        return "updated"
    row = Finding(
        module=module_spec.id,
        finding_kind=module_spec.finding_kind,
        connector_name=connector.name,
        job_id=job_id,
        dedup_key=key,
        title=declared_title(module_spec, finding),
        matched_asset=finding.get("matched_asset"),
        status="active",
        payload=finding,
    )
    db.add(row)
    await db.flush()
    await record_event(
        db,
        kind="notification",
        module=f"module:{module_spec.id}",
        entity_id=row.id,
        job_id=job_id,
        payload={
            "module_label": module_spec.label,
            "module": module_spec.id,
            "title": row.title,
            "fields": finding,
            "source": source,
        },
    )
    return "created"


#: EPP statuses that take a domain out of service or move it towards deletion. These
#: are the registration emergencies an operator acts on today (F-07 in the DNS & TLS
#: audit); every other status is either ordinary or a lock, which is reported when it
#: *disappears* instead.
_HOLD_STATUSES = frozenset({"clienthold", "serverhold", "pendingdelete", "redemptionperiod"})

#: Transfer/update/delete locks. Their removal is the fact worth reporting - it is what
#: makes a hijack possible - while gaining one is a routine consequence of a transfer.
_LOCK_STATUSES = frozenset({
    "clienttransferprohibited",
    "clientupdateprohibited",
    "clientdeleteprohibited",
    "clientrenewprohibited",
    "servertransferprohibited",
    "serverupdateprohibited",
    "serverdeleteprohibited",
    "serverrenewprohibited",
})


#: RDAP spells EPP statuses as prose or camel case depending on the registry. The
#: stored tokens are canonical (the worker normalizes them), and they are normalized
#: again here: a comparison must not report a spelling change as a registration change,
#: and a row written before this rule existed must still classify correctly.
_EPP_TOKEN_STRIP = re.compile(r"[^a-z0-9]")


def _status_list(value: object) -> list[str] | None:
    """A registry status list as canonical tokens, or None when none was answered."""
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return None
    return sorted(token for token in {_EPP_TOKEN_STRIP.sub("", item.lower())[:64] for item in value} if token)


def _registration_status_arrival(seen: dict, metadata: dict, subject: str) -> dict | None:
    """R5: a registration emergency or a removed lock, from the RDAP answer itself.

    The worker already downloads ``status[]`` and ``secureDNS`` for every monitored
    domain and the platform read neither, so `clientHold` (the domain stops resolving),
    `pendingDelete` and a silently removed transfer lock were visible only to an analyst
    who opened the registry's own page. Only transitions are reported, and the
    severity follows the plan: a hold or a deletion is high, losing a lock or a change
    of DNSSEC delegation is informational.

    A source that did not answer the field at all contributes nothing: an absent
    ``status`` member is silence about the registration, not a registry stating the
    domain holds no status.
    """
    before = _status_list(seen.get("epp_status"))
    after = _status_list(metadata.get("epp_status"))
    previous_dnssec = seen.get("secure_dns") if isinstance(seen.get("secure_dns"), bool) else None
    current_dnssec = metadata.get("secure_dns") if isinstance(metadata.get("secure_dns"), bool) else None
    dnssec_changed = previous_dnssec is not None and current_dnssec is not None and previous_dnssec != current_dnssec
    added = removed = []
    if before is not None and after is not None:
        added = [status for status in after if status not in before]
        removed = [status for status in before if status not in after]
    holds = [status for status in added if status in _HOLD_STATUSES]
    locks_lost = [status for status in removed if status in _LOCK_STATUSES]
    if not holds and not locks_lost and not dnssec_changed:
        return None
    severity = "high" if holds else "info"
    if holds:
        title = f"{subject}: registration status now includes {holds[0]}"
    elif locks_lost:
        title = f"{subject}: registration lock removed ({locks_lost[0]})"
    else:
        title = f"{subject}: DNSSEC delegation {'enabled' if current_dnssec else 'disabled'}"
    digest = hashlib.sha256(f"dns.registration.status|{subject}|{severity}|{added}|{removed}|{current_dnssec}".encode()).hexdigest()[:32]
    current_status = "unknown" if after is None else ("; ".join(after) or "none")
    payload = {
        "severity": severity,
        "rule": "dns.registration.status",
        "title": title,
        "host": subject,
        "Registration status": current_status,
        "Status added": "; ".join(added) or "none",
        "Status removed": "; ".join(removed) or "none",
    }
    if dnssec_changed:
        payload["DNSSEC delegation signed"] = "yes" if current_dnssec else "no"
    return {"payload": payload, "dedup": digest}


#: The candidate fields a revision is reported for, in the order a message names
#: them (WI-03). Everything else the platform learns about a candidate is
#: either a fact of its first sighting — the WHOIS fields, which the enrichment
#: event covers on its own — or a human's decision, while these four are what a
#: connector actually revises on a live candidate.
_PHISHING_TRACKED_FIELDS = (
    ("ip_address", "IP address"),
    ("web_ports", "Web ports"),
    ("original_domain", "Original domain"),
    ("matched_asset", "Matched asset"),
)


def _phishing_field_text(value) -> str:
    """One side of a revision as a bounded string, or `N/A` when it is empty."""
    text = str(value).strip()[:255] if value is not None else ""
    return text or "N/A"


def phishing_arrival(
    previous: dict | None,
    row,
    finding: dict,
    source: str,
    *,
    policy: AlertPolicy | None = None,
) -> dict | None:
    """The phishing arrivals, as `{payload, dedup}` or None (WI-03, W0.1).

    The module used to alert on the first sighting of a candidate and never again,
    so a lookalike that moved to a new address, published new ports or was
    re-attributed to another monitored brand was indistinguishable from one nobody
    had touched since the day it was found (F-04 in the phishing audit: a change, a
    return to silence and a comeback were all invisible). Both facts now travel the
    same outbox the other modules use, so a scan produces one aggregated message
    rather than one message per finding.

    `previous` is the stored value of the tracked fields taken *before* the row was
    updated, and `None` means this ingest created the candidate. A revision is
    reported as a single event naming every field that moved, and its digest keys
    the outbox row by what changed — re-observing the same pair is therefore silence,
    while the same candidate changing again is a new fact.

    `finding` is the report this arrival was derived from, and it is deliberately not
    copied into the event: the raw observation is stored once, as the source
    observation the message links to and the page prints, so evidence does not travel
    inside every queue row nor outlive the retention of the observation it came from.

    The severity here is the arrival's own: a candidate nobody has scored yet is
    reported, and the scoring band replaces this value once the platform has signals
    to judge it by.

    Whether a revision is a *message* is the resolved alert policy's answer
    (``ALERT_CANDIDATE_CHANGE_NOTIFICATIONS``, settable in Settings): with it off,
    a change is still stored — the candidate's fields are updated by the caller
    before this runs — and still visible in the list and its evidence. Only the
    notification is withheld, which is what an installation whose lookalikes flap on
    a shared host has asked for. ``None`` means the environment's answer.
    """
    if previous is None:
        return {
            "payload": {
                "severity": "info",
                "rule": "phishing.candidate.created",
                "title": f"New candidate {row.phishing_domain}",
                "finding_id": str(row.id),
                "phishing_domain": row.phishing_domain,
                "matched_asset": row.matched_asset,
                "detection_source": row.detection_source,
                "ip_address": row.ip_address,
                "web_ports": row.web_ports,
                "original_domain": row.original_domain,
                "status": row.status,
                "source": source,
                "created_at": row.created_at.isoformat(),
            },
            # The candidate is its own identity on first sighting; only a revision
            # needs a digest to tell one change from the next.
            "dedup": None,
        }
    revised = [
        (name, label, previous.get(name), getattr(row, name))
        for name, label in _PHISHING_TRACKED_FIELDS
        if previous.get(name) != getattr(row, name)
    ]
    if not revised:
        return None
    if not (policy or policy_from_environment()).candidate_change_notifications:
        return None
    digest = hashlib.sha256(
        "|".join(
            f"{name}|{_phishing_field_text(after)}" for name, _, _, after in revised
        ).encode()
    ).hexdigest()[:32]
    labels = "; ".join(label for _, label, _, _ in revised)
    return {
        "payload": {
            "severity": "info",
            "rule": "phishing.candidate.changed",
            "title": f"{row.phishing_domain}: {labels} changed",
            "finding_id": str(row.id),
            "phishing_domain": row.phishing_domain,
            "matched_asset": row.matched_asset,
            "detection_source": row.detection_source,
            "source": source,
            "Field": labels,
            "Previous value": "; ".join(
                _phishing_field_text(before) for _, _, before, _ in revised
            ),
            "Current value": "; ".join(
                _phishing_field_text(after) for _, _, _, after in revised
            ),
        },
        "dedup": digest,
    }


def dns_arrival(previous: dict | None, finding: dict, source: str) -> dict | None:
    """The arrivals this module alerts on, as `{payload, dedup}` or None.

    Before this existed the section alerted on one thing only - an expiry date - and
    was silent about everything that *arrived* (F-01 in the DNS & TLS audit): a
    certificate for a monitored name that the platform had never seen, a served
    certificate that changed, and a record set that changed. All three are facts an
    operator acts on, and each is delivered through the same outbox the phishing and
    breach modules use, so a scan produces one aggregated message rather than one
    message per finding.

    Severity is carried per event: an arrival is informational next to an expiry
    reminder, and the alert subject says which this is. The dedup digest keys the
    outbox row by *what* arrived, because these observations are current facts that
    are updated in place - keying by the row alone would report the first change and
    swallow every later one.
    """
    observation_type = finding.get("observation_type")
    metadata = finding.get("metadata") or {}
    subject = finding.get("subject")
    if previous is None:
        if observation_type in {"certificate", "tls_certificate"}:
            identity = metadata.get("id") or metadata.get("fingerprint_sha256") or finding.get("value")
            return {
                "payload": {
                    "severity": "info",
                    "rule": "dns.certificate.new",
                    "title": f"New certificate for {subject}",
                    "host": subject,
                    "Certificate ID": str(identity or "unknown")[:128],
                    "Expires at (UTC)": finding.get("expires_at"),
                    "Source": source,
                },
                "dedup": hashlib.sha256(f"dns.certificate.new|{subject}|{identity}".encode()).hexdigest()[:32],
            }
        return None
    # ``previous`` is a copy of the stored observation taken before ingestion. The
    # upsert refreshes the ORM instance in place, so reading the row itself here
    # would compare the new observation with itself and report no change at all.
    seen = previous.get("metadata") or {}
    if observation_type == "rdap":
        # A registration-status arrival is about a named domain: its title, the host it
        # points at and its digest all carry the subject, so a finding that arrived
        # without one has nothing to report rather than something to report blankly.
        if not subject:
            return None
        return _registration_status_arrival(seen, metadata, subject)
    if observation_type == "tls_probe":
        before = str(seen.get("certificate_id") or "")
        after = str(metadata.get("certificate_id") or "")
        if before and after and before != after:
            return {
                "payload": {
                    "severity": "info",
                    "rule": "dns.certificate.changed",
                    "title": f"Served certificate changed on {subject}",
                    "host": subject,
                    "Previous certificate": before[:128],
                    "Current certificate": after[:128],
                    "Expires at (UTC)": finding.get("expires_at"),
                },
                "dedup": hashlib.sha256(f"dns.certificate.changed|{subject}|{after}".encode()).hexdigest()[:32],
            }
        return None
    if observation_type == "dns_record":
        before_values = seen.get("record_values")
        after_values = metadata.get("record_values")
        if isinstance(before_values, list) or isinstance(after_values, list):
            before_text = "; ".join(before_values or [])[:400] or "none"
            after_text = "; ".join(after_values or [])[:400] or "none"
            if before_text != after_text:
                return {
                    "payload": {
                        "severity": "info",
                        "rule": "dns.record.changed",
                        "title": f"{finding.get('record_type')} record changed for {subject}",
                        "host": subject,
                        "Record": finding.get("record_type"),
                        "Previous values": before_text,
                        "Current values": after_text,
                    },
                    "dedup": hashlib.sha256(f"dns.record.changed|{subject}|{finding.get('record_type')}|{after_text}".encode()).hexdigest()[:32],
                }
    return None


async def _ingest_dns_batch(db, *, connector, findings, job_id, finding_kind, result):
    """Store a whole DNS batch with one upsert and one control read (F-17).

    The worker submits up to 50 observations per request and that protocol is the
    platform's own, yet every observation used to run its own upsert and re-read the
    expiry control rows it feeds, so a 500-observation scan cost 500 of each. The batch
    is validated item by item here - so one malformed observation is refused on its own
    rather than failing its neighbours - the previous state of every key is read in a
    single statement, all of it is stored in a single upsert, and the arrival rules are
    evaluated against the state that was read before that upsert.
    """
    from app.models.dns_observation import DNSObservation
    from app.schemas.connector import DNSObservationPayload
    from app.services.dns_security_service import observation_key

    source = source_identity(connector)
    prepared: list[tuple[int, dict, str, str]] = []
    for index, raw in enumerate(findings):
        if not isinstance(raw, dict) or (finding_kind and finding_kind != "dns_observation"):
            result.rejected += 1
            result.errors.append(
                {"index": index, "code": "invalid_contract", "retryable": False}
            )
            continue
        try:
            finding = _json_safe(raw)
            # Validated once before anything is read or written, so the single upsert
            # below cannot fail on a payload after the previous state was read.
            DNSObservationPayload.model_validate(finding)
            key = observation_key(source, finding)
        except (ValueError, KeyError, TypeError):
            result.rejected += 1
            result.errors.append(
                {"index": index, "code": "invalid_observation", "retryable": False}
            )
            continue
        prepared.append((index, finding, key, finding.get("observation_type")))
    if not prepared:
        return result
    keys = [key for _, _, key, _ in prepared]
    # One statement, and copies rather than ORM instances: the upsert refreshes the
    # stored row in place, so a snapshot taken here is what the arrival rules compare
    # against.
    previous = {
        row.observation_key: (row.value, dict(row.metadata_json or {}))
        for row in (
            await db.execute(
                select(DNSObservation.observation_key, DNSObservation.value, DNSObservation.metadata_json).where(
                    DNSObservation.source == source, DNSObservation.observation_key.in_(keys)
                )
            )
        ).all()
    }
    try:
        async with db.begin_nested():
            await ingest_dns_observations(db, source=source, findings=[finding for _, finding, _, _ in prepared], commit=False)
    except IntegrityError:
        # A concurrent writer took one of these keys. The batch savepoint rolled back,
        # so the observations are stored one at a time, each in its own savepoint and
        # with the same single retry the ordinary per-item path uses. The arrivals are
        # still queued from the snapshots taken before the batch, so a race costs
        # round-trips and never a missed arrival.
        for _index, finding, _key, _kind in prepared:
            for _attempt in (1, 2):
                try:
                    async with db.begin_nested():
                        await ingest_dns_observations(
                            db, source=source, findings=[finding], commit=False
                        )
                    break
                except IntegrityError:
                    if _attempt == 2:
                        raise
    arrivals = {}
    for index, finding, key, _kind in prepared:
        seen = previous.get(key)
        arrival = dns_arrival(
            None if seen is None else {"metadata": dict(seen[1])}, finding, source
        )
        if arrival is not None:
            arrivals[index] = (key, arrival)
    # Only the rows that produced an arrival are read back, and as columns: the entity
    # a notification is about keeps its identity across re-observations, so it is the
    # stored id rather than a guess.
    ids: dict[str, object] = {}
    if arrivals:
        ids = {
            row.observation_key: row.id
            for row in (
                await db.execute(
                    select(DNSObservation.observation_key, DNSObservation.id).where(
                        DNSObservation.source == source,
                        DNSObservation.observation_key.in_({key for key, _ in arrivals.values()}),
                    )
                )
            ).all()
        }
    for index, finding, key, _kind in prepared:
        seen = previous.get(key)
        identical = (
            seen is not None
            and seen[0] == finding.get("value")
            and seen[1] == (finding.get("metadata") or {})
        )
        outcome = "created" if seen is None else "unchanged" if identical else "updated"
        setattr(result, outcome, getattr(result, outcome) + 1)
        if index in arrivals and key in ids:
            await record_event(
                db,
                kind="notification",
                module="dns",
                entity_id=ids[key],
                job_id=job_id,
                payload=arrivals[index][1]["payload"],
                dedup=arrivals[index][1]["dedup"],
            )
    return result


async def _dns(db, connector, finding, job_id, module_spec):
    """One observation, for a caller that has a single finding to store.

    A submitted batch takes `_ingest_dns_batch` instead, which does the same work for
    all of its observations at once (F-17). This path keeps the per-observation shape
    the direct service callers expect, and both share `dns_arrival` and the storage
    service, so the rules cannot drift between them.
    """
    from app.models.dns_observation import DNSObservation
    from app.services.dns_security_service import observation_key

    source = source_identity(connector)
    key = observation_key(source, finding)
    old = (
        await db.execute(
            select(DNSObservation.observation_key, DNSObservation.value, DNSObservation.metadata_json).where(
                DNSObservation.source == source, DNSObservation.observation_key == key
            )
        )
    ).first()
    # A snapshot taken before the upsert, not the row itself: the upsert refreshes the
    # stored observation in place, so the tracked fields are copied out here.
    previous = None if old is None else (old.value, dict(old.metadata_json or {}))
    await ingest_dns_observations(db, source=source, findings=[finding], commit=False)
    arrival = dns_arrival(
        None if previous is None else {"metadata": dict(previous[1])}, finding, source
    )
    if arrival is not None:
        # The observation row is the entity a notification is about, and it keeps its
        # identity across re-observations, so it is read back here rather than guessed.
        row = (
            await db.execute(
                select(DNSObservation.observation_key, DNSObservation.id).where(
                    DNSObservation.source == source, DNSObservation.observation_key == key
                )
            )
        ).first()
        if row is not None:
            await record_event(
                db,
                kind="notification",
                module="dns",
                entity_id=row.id,
                job_id=job_id,
                payload=arrival["payload"],
                dedup=arrival["dedup"],
            )
    same = (
        previous is not None
        and previous[0] == finding.get("value")
        and previous[1] == (finding.get("metadata") or {})
    )
    return "created" if previous is None else "unchanged" if same else "updated"


async def _exposure(db, connector, finding, job_id, module_spec):
    from app.models import Job
    from app.services.dns_security_service import normalize_subject

    job = await db.get(Job, job_id)
    params = job.params if job and isinstance(job.params, dict) else {}
    target = normalize_subject(finding["matched_asset"])
    subject = normalize_subject(finding["subject"])
    # Both sides of this comparison are canonicalized here, and this is the side
    # that owns it. The scan parameters carry each monitored asset exactly as the
    # operator stored it in ``Asset.asset_value`` — that is the value the
    # connector was asked to scan, and it is what ``/me/work`` hands out — while
    # the finding carries whatever the source reported. An asset entered as
    # ``Example.COM``, with a trailing dot, or in an expanded IPv6 spelling
    # therefore used to compare unequal to the canonical name coming back, and the
    # check that exists to reject an unrelated finding rejected a correct one
    # instead: the whole response was refused as ``unrelated_asset``, the job was
    # marked failed, and findings the operator never learned about were dropped.
    # ``normalize_subject`` is the platform's one canonical form for a DNS name or
    # an address (see ``app.services.dns_security_service``), so the fix belongs
    # on the comparing side rather than on the snapshot, which must keep sending
    # the stored value.
    allowed = set()
    for raw in (*params.get("domains", []), *params.get("ips", [])):
        try:
            allowed.add(normalize_subject(raw))
        except (ValueError, TypeError):
            # A value that is not a DNS name or an address cannot match a subject
            # that is, so it contributes nothing to the membership test below.
            continue
    if target not in allowed or not (
        subject == target or subject.endswith("." + target)
    ):
        raise ValueError("unrelated_asset")
    changed = await persist(
        db,
        module="exposure",
        source=source_identity(connector),
        finding=finding,
        job_id=job_id,
        connector=connector,
        commit=False,
    )
    return "updated" if changed else "unchanged"


_HANDLERS = {
    "phishing": _phishing,
    "breach": _breach,
    "dns_observation": _dns,
    "exposure": _exposure,
    GENERIC_ADAPTER: _generic,
}


async def ingest_findings(
    db,
    *,
    connector,
    job_id,
    findings,
    connector_name=None,
    connector_type=None,
    finding_kind=None,
    module_spec=None,
):
    result = IngestionResult(
        received=len(findings) if isinstance(findings, list) else 0
    )
    if not isinstance(findings, list):
        return result
    if connector is None:
        result.rejected = len(findings)
        result.errors = [
            {"index": index, "code": "invalid_contract", "retryable": False}
            for index in range(min(len(findings), MAX_FINDINGS_PER_BATCH))
        ]
        return result
    selected_type = connector_type or connector.connector_type
    spec = module_spec or await get_module(db, selected_type)
    handler = _HANDLERS.get(spec.adapter) if spec else None
    if selected_type != connector.connector_type or (
        module_spec is not None and module_spec.id != connector.connector_type
    ):
        handler = None
    if job_id is not None and await db.get(Job, job_id) is None:
        # A service caller may supply a scan correlation id without a
        # persisted job; do not write an invalid FK into the durable outbox.
        job_id = None
    findings = findings[:MAX_FINDINGS_PER_BATCH]
    if handler is _dns:
        # One upsert and one control read for the whole batch: the worker submits this
        # module's observations in batches, and storing them one at a time was the
        # protocol being used against itself (F-17 in the DNS & TLS audit).
        return await _ingest_dns_batch(
            db,
            connector=connector,
            findings=findings,
            job_id=job_id,
            finding_kind=finding_kind,
            result=result,
        )
    # The HTTP contract rejects an over-limit request before this service is
    # called. A direct caller keeps the original bounded-prefix behavior;
    # never perform unbounded validation or persistence work.
    for index, raw in enumerate(findings):
        if (
            not handler
            or (finding_kind and finding_kind != spec.finding_kind)
            or not isinstance(raw, dict)
        ):
            result.rejected += 1
            result.errors.append(
                {"index": index, "code": "invalid_contract", "retryable": False}
            )
            continue
        try:
            raw = _json_safe(raw)
            async with db.begin_nested():
                outcome = await handler(db, connector, raw, job_id, spec)
            setattr(result, outcome, getattr(result, outcome) + 1)
        except IntegrityError:
            # Retry a uniqueness race after only the item's savepoint rolls back.
            async with db.begin_nested():
                outcome = await handler(db, connector, raw, job_id, spec)
            setattr(result, outcome, getattr(result, outcome) + 1)
        except (ValueError, KeyError):
            result.rejected += 1
            result.errors.append(
                {"index": index, "code": "invalid_observation", "retryable": False}
            )
    await db.flush()
    return result


async def _direct(
    handler, db, connector, finding, job_id=None, module_spec=None, **kwargs
):
    if connector is None:
        return False
    if job_id is not None and await db.get(Job, job_id) is None:
        job_id = None
    spec = module_spec or await get_module(db, connector.connector_type)
    if spec is None or spec.id != connector.connector_type:
        return False
    try:
        finding = _json_safe(finding)
        outcome = await handler(db, connector, finding, job_id, spec)
        await db.flush()
        return outcome != "unchanged"
    except (ValueError, KeyError):
        return False


async def ingest_phishing_finding(db, connector, finding, **kwargs):
    return await _direct(_phishing, db, connector, finding, **kwargs)


async def ingest_breach_finding(db, connector, finding, **kwargs):
    return await _direct(_breach, db, connector, finding, **kwargs)


async def ingest_generic_finding(db, connector, finding, **kwargs):
    return await _direct(_generic, db, connector, finding, **kwargs)


async def ingest_dns_observation_finding(db, connector, finding, **kwargs):
    return await _direct(_dns, db, connector, finding, **kwargs)


async def ingest_exposure(db, connector, finding, **kwargs):
    return await _direct(_exposure, db, connector, finding, **kwargs)
