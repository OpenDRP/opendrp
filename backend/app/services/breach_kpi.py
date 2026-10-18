"""One definition of the breach numbers the dashboard and the report publish (WI-16).

Two different questions used to be answered by one number. "How much credential
exposure do we have" is a question about *findings*: a finding is what happened to one
of our own accounts, and it can only exist for an address or domain somebody put in the
inventory. "Is there new trouble out there" is a question about *incidents*: a breach of
a vendor we use exists whether or not any of our addresses is in it, and the sources'
own catalogues are where that is visible (F-09) — a scan that traverses a newly added
address produces findings about incidents that are years old, so counting rows for seven
days answers neither question honestly.

Both surfaces read this module rather than each computing its own version of the same
figures: the report and the dashboard had already drifted apart once (REP-01), where the
report counted recent phishing rows without their status and the dashboard counted
active phishing *and* breach findings. A single function plus its captions is what makes
`active_threats_7d` and `new_incidents_7d` mean the same thing on every page that prints
them.
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Breach, BreachCatalogue
from app.services.ingestion_service import BREACH_EXPOSURE_KINDS

#: The window both surfaces report over. Named once so the captions cannot promise a
#: window the queries do not use.
BREACH_KPI_WINDOW_DAYS = 7

#: A finding is "active" while an analyst still has something to do about it — the same
#: pair the dashboard, the report and the list page already agree on.
OPEN_FINDING_STATUSES = ("active", "investigating")


def _as_utc(value: datetime | None) -> datetime | None:
    """A stored timestamp as an aware UTC datetime.

    The catalogue's ``added_date`` is declared without a zone on the model, and a
    source's own date carries no offset: both spellings are read as the same instant,
    which is what makes a comparison against the window mean anything.
    """
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _iso(value: datetime | None) -> str | None:
    aware = _as_utc(value)
    return aware.isoformat() if aware else None


def breach_kpi_captions(days: int = BREACH_KPI_WINDOW_DAYS) -> dict[str, str]:
    """What each breach number counts, in the words every surface prints.

    Kept beside the queries so a number and its caption cannot be changed one at a time:
    a figure that reads "breach findings" while counting incidents is exactly the
    confusion this module exists to end.
    """
    return {
        "total_findings": (
            "findings stored from the configured breach sources, at any status; a finding "
            "exists only for an address or domain in the inventory"
        ),
        "active_findings_7d": (
            f"findings that are active or under investigation and were created in the last "
            f"{days} days — scanning a newly added address can create one about an old incident"
        ),
        "new_incidents_7d": (
            f"incidents the configured sources added to their own catalogues in the last "
            f"{days} days, whether or not any monitored address is in them"
        ),
        "findings_by_exposure_kind": (
            "stored findings by class of exposure (an account compromised, a paste, a "
            "stealer log)"
        ),
    }


async def breach_kpi(
    db: AsyncSession,
    *,
    now: datetime | None = None,
    days: int = BREACH_KPI_WINDOW_DAYS,
) -> dict:
    """The breach half of every KPI an operator reads, over one window.

    Read-only and bounded: four aggregate queries, no rows loaded. The catalogue half
    reports how many incidents the platform holds and how many of them the source did
    not date at all, because "nothing was added" and "half this catalogue cannot be
    dated" are different answers and only one of them means the window is quiet.
    """
    aware_now = _as_utc(now) or datetime.now(timezone.utc)
    start = aware_now - timedelta(days=days)
    # The column is naive on the model while the window is an aware instant, so the
    # bound is handed over in the same UTC-without-offset spelling the value is stored
    # in — a timezone suffix here would compare a string against a timestamp on SQLite
    # and be re-interpreted in the session's zone on PostgreSQL.
    start_naive = start.replace(tzinfo=None)

    total_findings = int((await db.execute(select(func.count(Breach.id)))).scalar_one())
    active_findings = int(
        (
            await db.execute(
                select(func.count(Breach.id)).where(
                    Breach.created_at >= start,
                    Breach.status.in_(OPEN_FINDING_STATUSES),
                )
            )
        ).scalar_one()
    )
    new_incidents = int(
        (
            await db.execute(
                select(func.count(BreachCatalogue.id)).where(
                    BreachCatalogue.added_date.is_not(None),
                    BreachCatalogue.added_date >= start_naive,
                )
            )
        ).scalar_one()
    )
    # The class of exposure is what an operator acts on: a compromised account is a
    # password reset, a stealer log is a session to revoke. Counted here rather than on a
    # page so the report and the dashboard split the same total the same way (WI-16).
    kind_counts = {
        str(kind): int(count or 0)
        for kind, count in (
            await db.execute(
                select(Breach.exposure_kind, func.count(Breach.id)).group_by(
                    Breach.exposure_kind
                )
            )
        ).all()
    }
    findings_by_exposure_kind = {kind: kind_counts.get(kind, 0) for kind in BREACH_EXPOSURE_KINDS}
    # A row whose class this build does not know — an adopted database that was written
    # before the column was closed, or by hand — is reported under its own name rather
    # than dropped from a total it is part of.
    findings_by_exposure_kind.update(
        {kind: count for kind, count in kind_counts.items() if kind not in findings_by_exposure_kind}
    )
    catalogue_incidents, undated, sources, last_synced = (
        await db.execute(
            select(
                func.count(BreachCatalogue.id),
                func.sum(case((BreachCatalogue.added_date.is_(None), 1), else_=0)),
                func.count(func.distinct(BreachCatalogue.source)),
                func.max(BreachCatalogue.last_synced_at),
            )
        )
    ).one()

    return {
        "window_days": days,
        "total_findings": total_findings,
        "active_findings_7d": active_findings,
        "new_incidents_7d": new_incidents,
        "findings_by_exposure_kind": findings_by_exposure_kind,
        # What the catalogue holds and how much of it can be dated at all: a source that
        # answers without an ``added_date`` cannot contribute to the window, and an
        # operator reading a small number has to be able to tell that from a quiet week.
        "catalogue_incidents": int(catalogue_incidents or 0),
        "undated_incidents": int(undated or 0),
        "catalogue_sources": int(sources or 0),
        "catalogue_synced_at": _iso(last_synced),
        "captions": breach_kpi_captions(days),
    }
