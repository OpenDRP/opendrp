"""The provider's incident catalogue, and what its diff means (F-09, WI-13).

A finding is what happened to an account somebody put in the inventory: the platform
learns about an incident only once an operator has added an address, and only for the
addresses it holds. The catalogue is the other half of the picture — what the source
knows about incidents at large — and it is the only way a breach of a domain this
platform monitors is seen *before* somebody adds the address to that domain.

The diff belongs to the core and the sweep to the connector. The provider has no
"added since" question to ask, so a connector reads its source's catalogue under its
own pace and request budget and hands the core the entries it read; the core stores
one row per ``(source, breach_name)``, refreshes ``last_synced_at``, and — for an
incident it has never seen that names a domain the inventory watches — records exactly
one ``new_incident`` notification. The core computes the diff because the core is what
holds the inventory and the notification outbox; the connector sweeps because the
connector is what holds the provider's key and its budget.

What a row means is stated rather than inferred. ``created_at`` is when *this*
installation first saw the incident, and the source's own ``added_date`` sits beside it:
a source that corrects a date must not make an old incident look new, and "new" is then
a claim about this platform's own history rather than about the provider's calendar.

An empty catalogue is not an empty finding set. Nothing here reports zero incidents as
"the domain is clean": the state says the catalogue has never been synced, which is a
different sentence, and the page that renders it says so (F-04).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from app.core.logging_config import get_logger
from app.models.asset import Asset, AssetType
from app.models.breach import Breach, BreachCatalogue
from app.services.asset_matching import (
    POLICY_SCAN,
    asset_scope,
    key_variants,
    keys_predicate,
)
from app.services.ingestion_events import record_event

log = get_logger(__name__)

#: How long a stored row stays trusted as "the source still reports this" before the
#: state calls it stale. It is what a later pass reads to find rows no sync confirmed —
#: a source that withdraws an incident leaves a row nothing reports, and a row nobody
#: re-reads would otherwise look current forever.
CATALOGUE_STALE_AFTER_HOURS = 24 * 14


def _as_utc(value: datetime | None) -> datetime | None:
    """A stored timestamp as an aware UTC datetime.

    The column is declared without a zone on the models and stored with one in
    PostgreSQL, and the unit suite's SQLite hands back what it was given: both spellings
    are the same instant here, which is what makes a comparison between a checkpoint and
    a provider date mean anything.
    """
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _iso(value: datetime | None) -> str | None:
    aware = _as_utc(value)
    return aware.isoformat() if aware else None


async def catalogue_window(db, source: str) -> dict:
    """The checkpoint a scan of this source is given, and what the catalogue holds.

    Handed to the connector in the job's params: with ``last_synced_at`` set, a worker
    asks its source the cheap question ("has anything been added or changed since?") and
    only sweeps when the answer is yes; with it unset — an installation that has never
    synced this source — the sweep is what tells it where it stands. The count travels
    with it so the first sweep's cost is somebody's decision rather than a surprise.
    """
    row = (
        await db.execute(
            select(
                func.count(BreachCatalogue.id),
                func.max(BreachCatalogue.last_synced_at),
            ).where(BreachCatalogue.source == source)
        )
    ).one()
    incidents, last_synced = int(row[0] or 0), row[1]
    return {
        "source": source,
        "incidents": incidents,
        "last_synced_at": _iso(last_synced),
        "stale": bool(
            last_synced
            and (_as_utc(last_synced) or datetime.now(timezone.utc))
            < datetime.now(timezone.utc) - timedelta(hours=CATALOGUE_STALE_AFTER_HOURS)
        ),
    }


async def stealer_logs_window(db, source: str) -> dict:
    """When this installation last saw stealer-log exposure from this source (WI-18).

    The worker's pass spends a separately priced, much lower allowance, so it is not part
    of every scan. The core is what knows when the last pass actually stored something —
    a worker is restarted, rescheduled and run by hand — so the moment travels in the
    job's params and the worker decides whether the week is up. ``None`` means this
    installation has never seen stealer-log exposure from this source, which is when the
    first pass is due rather than skipped.

    ``last_seen_at`` is the newest sighting, not ``created_at``: a row reported again
    this week says the pass ran, even if the row itself is months old.
    """
    last_seen = (
        await db.execute(
            select(func.max(Breach.last_seen_at)).where(
                Breach.source_id == source,
                Breach.exposure_kind == "stealer_log",
            )
        )
    ).scalar()
    return {"source": source, "last_seen_at": _iso(last_seen)}


async def catalogue_state(db, *, source: str | None = None) -> dict:
    """What the catalogue holds for one source, or for every source.

    The page and the API read this to tell "no incidents are stored" from "this source
    has never been synced": the first is an answer about the provider's catalogue, the
    second is an answer about this installation, and only one of them means anything
    about the domains being watched.
    """
    conditions = [BreachCatalogue.source == source] if source else []
    incidents, last_synced, newest_added = (
        await db.execute(
            select(
                func.count(BreachCatalogue.id),
                func.max(BreachCatalogue.last_synced_at),
                func.max(BreachCatalogue.added_date),
            ).where(*conditions)
        )
    ).one()
    grouped = (
        await db.execute(
            select(
                BreachCatalogue.source,
                func.count(BreachCatalogue.id),
                func.max(BreachCatalogue.last_synced_at),
            )
            .where(*conditions)
            .group_by(BreachCatalogue.source)
            .order_by(BreachCatalogue.source)
        )
    ).all()
    newest = _as_utc(newest_added)
    return {
        "incidents": int(incidents or 0),
        "last_synced_at": _iso(last_synced),
        "newest_added_date": newest.date().isoformat() if newest else None,
        # A source list rather than a bare number: an installation that monitors two
        # providers has two catalogues with two sync histories, and one timestamp for
        # both would claim a freshness that half the rows do not have.
        "sources": [
            {
                "source": row[0],
                "incidents": int(row[1] or 0),
                "last_synced_at": _iso(row[2]),
            }
            for row in grouped
        ],
    }


def _same_moment(stored: datetime | None, incoming: datetime | None) -> bool:
    """Whether two timestamps are the same instant, in either of their spellings.

    The columns are declared without a zone on the models and stored with one in
    PostgreSQL, while the unit suite's SQLite hands a naive value back: comparing the
    two directly would call every entry changed on one engine and unchanged on the
    other, and a diff that disagrees with itself is not a diff.
    """
    if stored is None or incoming is None:
        return stored is None and incoming is None
    return _as_utc(stored) == _as_utc(incoming)


def _same_facts(row: BreachCatalogue, entry: dict) -> bool:
    """Whether a stored row already says everything this entry says.

    Data classes are compared as sets and attributes as mappings: a source that
    reorders a list, or a flag that travelled as a string, is the same fact and must not
    be counted as a change. Everything that *is* a change — a corrected date, a grown
    count, a new class of data — is compared, because a store that silently keeps the
    older of two answers is how a page ends up arguing with the provider it read.
    """
    return (
        row.title == entry["title"]
        and row.domain == entry["domain"]
        and row.breach_date == entry["breach_date"]
        and _same_moment(row.added_date, entry["added_date"])
        and _same_moment(row.modified_date, entry["modified_date"])
        and int(row.pwn_count or 0) == int(entry["pwn_count"] or 0)
        and sorted(row.data_classes or []) == sorted(entry["data_classes"] or [])
        and (row.attributes or {}) == (entry["attributes"] or {})
    )


async def _monitored_domains(db, domains: list[str]) -> dict[str, str]:
    """Which of these vendor domains the asset inventory watches, and as what.

    Returns ``variant key -> the asset's stored value``, so an incident's vendor domain
    matches an active domain asset under the platform's own matching rule (case, a
    trailing dot, and IDNA spellings included) rather than under a string comparison
    invented here. Only active assets count: an incident about a domain nobody is
    watching is catalogue knowledge, not this installation's incident.
    """
    keys: set[str] = set()
    for domain in domains:
        keys |= key_variants(domain)
    if not keys:
        return {}
    column = func.coalesce(Asset.normalized_value, Asset.asset_value)
    rows = (
        await db.execute(
            select(column).where(
                Asset.asset_type == AssetType.domain.value,
                *asset_scope(POLICY_SCAN),
                keys_predicate(column, keys),
            )
        )
    ).scalars()
    watched: dict[str, str] = {}
    for value in rows:
        if not value:
            continue
        for variant in key_variants(value):
            watched[variant] = str(value)
    return watched


async def sync_catalogue(
    db,
    *,
    source: str,
    entries: list[dict],
    job_id: uuid.UUID | None = None,
) -> dict:
    """Store one connector's read of its source's catalogue, and report the diff.

    ``entries`` are already validated wire payloads (one per incident), so this function
    models no vendor: it stores what every breach source can supply and keeps anything
    beyond that in ``attributes``, exactly as the finding path does.

    Only an incident this installation has never stored *and* whose vendor domain is a
    monitored asset records a notification, and it records one: the outbox key is the
    catalogue row, so a repeated sync of an unchanged catalogue is a no-op, and the
    second half of a sweep that was cut short by a request budget does not re-announce
    what the first half already did. Growth and confirmation of a known incident are
    already events of the finding path (WI-08) — this pass adds the incident nobody's
    address had reached yet, not a second way to say the same thing.
    """
    now = datetime.now(timezone.utc)
    created: list[BreachCatalogue] = []
    updated = unchanged = 0
    seen: set[str] = set()

    for entry in entries:
        name = str(entry["breach_name"])
        if name in seen:
            # One row per incident per source: a caller that repeats a name inside one
            # batch is describing the same incident twice, and the second copy must not
            # overwrite the first with the same facts (or, worse, with fewer of them).
            continue
        seen.add(name)
        row = (
            await db.execute(
                select(BreachCatalogue).where(
                    BreachCatalogue.source == source,
                    BreachCatalogue.breach_name == name,
                )
            )
        ).scalar_one_or_none()
        if row is None:
            row = BreachCatalogue(
                source=source,
                breach_name=name,
                title=entry["title"],
                domain=entry["domain"],
                breach_date=entry["breach_date"],
                added_date=entry["added_date"],
                modified_date=entry["modified_date"],
                pwn_count=entry["pwn_count"],
                data_classes=entry["data_classes"],
                attributes=entry["attributes"],
                last_synced_at=now,
            )
            db.add(row)
            created.append(row)
            continue
        if _same_facts(row, entry):
            # A sync still says "the source reports this": the freshness column moves
            # even when nothing else does, which is what makes a stale row findable.
            row.last_synced_at = now
            unchanged += 1
            continue
        row.title = entry["title"]
        row.domain = entry["domain"]
        row.breach_date = entry["breach_date"]
        row.added_date = entry["added_date"]
        row.modified_date = entry["modified_date"]
        row.pwn_count = entry["pwn_count"]
        row.data_classes = entry["data_classes"]
        row.attributes = entry["attributes"]
        row.last_synced_at = now
        updated += 1

    if created:
        # The rows need their ids before an event can name one, and the matching below
        # reads the inventory: both are one flush away from what the loop wrote.
        await db.flush()

    matched = await _monitored_domains(db, [row.domain for row in created])
    announced: list[dict] = []
    for row in created:
        asset_value = next(
            (matched[key] for key in key_variants(row.domain) if key in matched), None
        )
        if asset_value is None:
            # Stored, and not this installation's incident: the catalogue is wider than
            # the inventory on purpose, and announcing all of it would be a news feed.
            continue
        await _announce(db, source=source, row=row, asset_value=asset_value, job_id=job_id)
        announced.append({"breach_name": row.breach_name, "matched_asset": asset_value})

    return {
        "received": len(entries),
        "created": len(created),
        "updated": updated,
        "unchanged": unchanged,
        "new_incidents": len(announced),
        "announced": announced[:20],
        # An answer of zero entries is the source saying nothing, and it must not read as
        # a clean catalogue: the caller states which it was.
        "empty": not entries,
    }


async def _announce(
    db,
    *,
    source: str,
    row: BreachCatalogue,
    asset_value: str,
    job_id: uuid.UUID | None,
) -> None:
    """Record the one notification a new incident naming a monitored domain produces.

    The payload is the shape the breach module's own events travel in, so the alert path
    renders it without a second renderer and the noise policy (WI-05) reads the same
    attributes it reads for a finding. It carries no ``finding_id`` because there is no
    finding behind it: no address of ours was in this incident yet, which is exactly why
    the event exists.
    """
    written = await record_event(
        db,
        kind="notification",
        module="breach",
        entity_id=row.id,
        job_id=job_id,
        payload={
            "source": source,
            "change_class": "new_incident",
            "catalogue": True,
            "breach_name": row.breach_name,
            "title": row.title,
            "domain": row.domain,
            "breach_date": str(row.breach_date) if row.breach_date else None,
            "pwn_count": row.pwn_count,
            "data_classes": row.data_classes,
            # The vendor domain is the account this incident is about: no address of
            # ours is in it, and the domain is what the operator acts on.
            "matched_email": None,
            "matched_domain": asset_value,
            "attributes": row.attributes,
        },
    )
    if written:
        log.info(
            "breach_catalogue_incident_announced",
            source=source,
            breach_name=row.breach_name,
            matched_asset=asset_value,
        )
