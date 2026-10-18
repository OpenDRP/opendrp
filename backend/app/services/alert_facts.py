"""What a message says about a finding, read from the row as it stands at send time.

A module whose message is assembled from its own table declares that here rather
than in the delivery path. What the platform was *told* when the finding arrived
is not what it knows when the message is sent — a registrar resolved minutes
later, an incident corrected after the fact — and the message has to say the
latter. A module with no such row (or a caller that holds no database) answers
nothing, and the delivery path renders its payload instead.

Keeping this out of :mod:`app.services.alert_service` is what leaves that module
with orchestration only: this one owns SQL, the delivery path owns the batch.
"""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Breach, PhishingDomain
from app.services.alert_message import (
    breach_event_label,
    breach_exposure_label,
    clip,
)
from app.services.phishing.age import domain_age_days, utc_instant
from app.services.phishing_score_service import fired_signals


def phishing_message_facts(row, sources: list[str] | None = None) -> dict[str, str]:
    """The facts of one candidate, read from the row the platform stores (WI-01).

    The registrar, the abuse contact and the age of a registration are usually
    resolved by the enrichment worker minutes after the candidate was first
    reported, so a payload captured at ingestion time cannot carry them. Reading
    the row when the message is sent is what lets the same alert say who the
    registrar is, without a second rendering path and without shipping a copy of
    the row inside every event.

    ``sources`` comes from the evidence rows with the same reasoning and one more
    (WI-30): "how many independent providers saw this" is the corroboration the
    score rewards, and a reader deciding whether to act on a look-alike has to be
    able to see that the two reports were two providers rather than one.
    """
    age = domain_age_days(row.domain_created_at)
    first_seen = utc_instant(row.created_at)
    fired = fired_signals(row.signals)
    reported_by = list(sources or [])
    return {
        "Domain": clip(row.phishing_domain),
        "Matched asset": clip(row.matched_asset),
        "Source": clip(row.detection_source),
        "Sources": clip(
            f"{len(reported_by)} ({', '.join(reported_by)})"
            if reported_by
            else None
        ),
        "Age (days)": "N/A" if age is None else str(age),
        "Registrar": clip(row.whois_registrar),
        "Abuse contact": clip(row.whois_abuse_email),
        # ASN and organisation join this same fact once the free host lookup
        # (wave 3) records them; this wave holds the address itself.
        "IP / ASN / Org": clip(row.ip_address),
        # The score and the signals it came from travel with the message: a
        # digest of the middle band is only actionable if the reader can see why
        # these candidates were not worth a message of their own, and the same
        # two facts are what the alert of a high-confidence candidate explains
        # itself with (WI-08, §4.5 of the audit).
        "Confidence": str(int(row.confidence or 0)),
        "Signals": clip(
            "; ".join(f"{name} ({points:+d})" for name, points in fired.items())
            or "none"
        ),
        "First seen": clip(first_seen.isoformat() if first_seen else None),
    }


async def stored_message_facts(
    db: AsyncSession, threat_type: str, findings: list[dict]
) -> dict[str, dict]:
    """The module's own row behind each event of one batch, when it has one.

    Phishing and breaches both declare it here. A module with no such row (or
    with no database to read it from) answers nothing, and its payload is
    rendered instead.
    """
    if threat_type == "phishing":
        return await stored_phishing_facts(db, findings)
    if threat_type == "breach":
        return await stored_breach_facts(db, findings)
    return {}


def _finding_ids(findings: list[dict]) -> dict[UUID, str]:
    """The entity ids a batch names, skipping payloads nothing recognises as one.

    An event written before the id was part of the contract contributes nothing
    instead of failing the delivery.
    """
    ids: dict[UUID, str] = {}
    for item in findings:
        raw = item.get("finding_id")
        if not raw:
            continue
        try:
            ids[UUID(str(raw))] = str(raw)
        except (ValueError, TypeError, AttributeError):
            continue
    return ids


async def stored_phishing_facts(db: AsyncSession, findings: list[dict]) -> dict[str, dict]:
    """The stored candidate behind each event of one batch, keyed by its id.

    One statement answers the whole batch, so a hundred-finding alert costs one
    read rather than a hundred.
    """
    ids = _finding_ids(findings)
    if not ids:
        return {}
    rows = list(
        (await db.execute(select(PhishingDomain).where(PhishingDomain.id.in_(ids)))).scalars()
    )
    from app.services.source_observations import sources_for_candidates

    reported_by = await sources_for_candidates(db, [row.id for row in rows])
    return {
        str(row.id): phishing_message_facts(
            row, sources=reported_by.get(str(row.id), [])
        )
        for row in rows
    }


def data_class_text(value) -> str:
    """The exposed classes as a list a person reads, never as JSON.

    ``data_classes`` is what the reader acts on - passwords and card numbers are
    a different incident from a list of email addresses - and a JSON array of
    quoted strings pushes every other fact out of a narrow message and tells them
    nothing. The count is stated when the list was bounded, so a truncated line
    cannot read as the whole truth.
    """
    if not isinstance(value, list):
        return "unknown"
    names = [" ".join(str(item).split())[:60] for item in value if str(item).strip()]
    if not names:
        return "unknown"
    shown = names[:6]
    text = ", ".join(shown)
    if len(names) > len(shown):
        text = f"{text} (+{len(names) - len(shown)} more)"
    return text


def breach_verification(attributes) -> str | None:
    """The source's own statement about an incident, or nothing at all.

    Only what arrived is printed: a row with no flags shows no column, because an
    empty "Verification: unknown" reads as a claim the platform cannot make.
    ``metadata_incomplete`` rides here too - it is the same kind of statement,
    that the incident was stored without the facts that would normally describe
    it.
    """
    facts = attributes if isinstance(attributes, dict) else {}
    if facts.get("is_fabricated") is True:
        state = "fabricated list"
    elif facts.get("is_spam_list") is True:
        state = "spam list"
    elif facts.get("is_verified") is True:
        state = "verified"
    elif facts.get("is_verified") is False:
        state = "unverified"
    else:
        state = None
    if facts.get("metadata_incomplete") is True:
        state = f"{state}, metadata incomplete" if state else "metadata incomplete"
    return state


def breach_message_facts(row) -> dict[str, str]:
    """What a message says about one stored incident.

    Read from the row rather than from the event payload: the payload is the
    finding as it arrived, and the row is what the platform knows at the moment
    the message is sent. A registration or a correction that landed between the
    two belongs in the message, which is the same reason phishing's facts are
    read at send time.
    """
    attributes = getattr(row, "attributes", None)
    incomplete = isinstance(attributes, dict) and attributes.get("metadata_incomplete") is True
    facts = {
        "Incident": clip(getattr(row, "title", None) or getattr(row, "breach_name", None)),
        "Account": clip(getattr(row, "matched_email", None) or getattr(row, "matched_domain", None)),
        "Vendor domain": clip(getattr(row, "domain", None), 253),
        # A row whose source did not state when the incident happened stores the
        # instant the platform first saw it. Saying so is the point: printed as a
        # bare date it would read as the incident's own (F-02).
        "Breach date": (
            clip(f"not stated (observed {getattr(row, 'breach_date', None)})")
            if incomplete
            else clip(getattr(row, "breach_date", None))
        ),
        "Data classes": clip(data_class_text(getattr(row, "data_classes", None)), 400),
        "Accounts affected": str(int(getattr(row, "pwn_count", 0) or 0)),
    }
    exposure = breach_exposure_label(getattr(row, "exposure_kind", None))
    if exposure:
        facts["Exposure"] = exposure
    marker = breach_verification(attributes)
    if marker:
        facts["Verification"] = marker
    return facts


async def stored_breach_facts(db: AsyncSession, findings: list[dict]) -> dict[str, dict]:
    """The stored incident behind each event of one batch, keyed by its id.

    One statement answers the whole batch - a fifty-incident alert costs one read
    rather than fifty. The fallback in :func:`message_facts` renders the payload
    of an event whose incident no longer exists.
    """
    ids = _finding_ids(findings)
    if not ids:
        return {}
    rows = list((await db.execute(select(Breach).where(Breach.id.in_(ids)))).scalars())
    return {str(row.id): breach_message_facts(row) for row in rows}


def message_facts(
    threat_type: str, item: dict, stored: dict | None = None
) -> tuple[dict[str, str], dict[str, str]]:
    """What a message says about one finding, and what the summary counts.

    The module decides both, not the alert path: the two built-in modules name
    their neutral fields, and a module declared at runtime contributes the fields
    it declared — which is what lets a source onboarded as data arrive in an
    operator's inbox without a line of rendering code. The second half holds only
    what a count is useful for; a module that names nothing there is simply not
    broken down.

    `stored` is the module's own row as it stands at send time, when the caller
    could read it. Phishing uses it because its facts are resolved *after* the
    finding is reported; a batch whose candidate no longer exists (or a payload
    from a caller that holds no database) falls back to what the event carries.
    """
    if threat_type == "phishing":
        if stored:
            return (
                dict(stored),
                {
                    "Source": stored.get("Source") or "N/A",
                    "Matched asset": stored.get("Matched asset") or "N/A",
                },
            )
        return (
            {
                "Domain": item.get("phishing_domain") or "N/A",
                "Matched asset": item.get("matched_asset") or "N/A",
                "Source": item.get("detection_source") or "N/A",
            },
            {
                "Source": item.get("detection_source") or "N/A",
                "Matched asset": item.get("matched_asset") or "N/A",
            },
        )
    if threat_type == "breach":
        # The class of *this* delivery leads the row and comes from the event, not
        # from the row: the row is an incident, and the event is the change about
        # it that an operator is being told about now (WI-08). It is the first
        # column because it is the answer to "why am I reading about this again?"
        # -- the same incident reported twice means two different things.
        event_column = {"Event": breach_event_label(item.get("change_class"))}
        if stored:
            facts = {**event_column, **stored}
        else:
            # No stored row (a caller that holds only the finding, or an event
            # whose incident was since removed). The payload is all there is, so
            # its own facts are named as the columns they are — and nothing else
            # is: the keys it also carries (an id, a status, a source, the raw
            # attributes) are not in ``BREACH_COLUMNS`` and so cannot be printed.
            attributes = item.get("attributes")
            facts = {
                **event_column,
                "Incident": clip(item.get("title") or item.get("breach_name")),
                "Account": clip(item.get("matched_email") or item.get("matched_domain")),
                "Vendor domain": clip(item.get("domain"), 253),
                "Breach date": clip(item.get("breach_date")),
                "Data classes": clip(data_class_text(item.get("data_classes")), 400),
                "Accounts affected": str(int(item.get("pwn_count") or 0)),
            }
            exposure = breach_exposure_label(item.get("exposure_kind"))
            if exposure:
                facts["Exposure"] = exposure
            if isinstance(attributes, dict) and attributes.get("metadata_incomplete") is True:
                facts["Breach date"] = clip(
                    f"not stated (observed {item.get('breach_date')})"
                )
            marker = breach_verification(attributes)
            if marker:
                facts["Verification"] = marker
        return (
            facts,
            {
                # The counted breakdown keeps the words it always had: the
                # module's own name for an incident as a whole -- the dedup key, so
                # it cannot differ from the stored row -- and the vendor domain,
                # which is read from the row when there is one: a summary that
                # names a domain the incident no longer has is the same defect as
                # a column that does.
                "Breach": item.get("breach_name") or "N/A",
                "Domain": (
                    facts.get("Vendor domain")
                    if stored
                    else item.get("domain")
                )
                or "N/A",
            },
        )
    declared = item.get("fields")
    declared_facts: dict[str, str] = {"Finding": item.get("title") or "N/A"}
    if isinstance(declared, dict):
        declared_facts.update({str(key): value for key, value in declared.items()})
    return declared_facts, {}
