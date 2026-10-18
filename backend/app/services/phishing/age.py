"""How old a registration is, in whole days (WI-04/WI-05, waves 0–1).

One function rather than three, because three callers have to agree on the number:
the alert a human reads, the list the API sorts by, and the scoring signal that
weighs a young registration. A registration timestamp a source never answered is
not "zero days old" — it is unknown, and `None` says so, so a caller cannot mistake
"the registry did not tell us" for "registered today".

Instants come back from the database without a timezone on SQLite while the
platform stores UTC, so a naive instant is read as UTC. Treating it as local time
would move the age by up to a day depending on where the worker runs, and the age
of a registration is exactly the kind of fact two operators compare with each other.
"""

from datetime import datetime, timezone


def utc_instant(value: datetime | None) -> datetime | None:
    """A stored instant as aware UTC, or None when the platform does not know it."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def domain_age_days(created_at: datetime | None, *, now: datetime | None = None) -> int | None:
    """Whole days since registration, or None when no source answered the date.

    A registration in the future — a registry clock ahead of ours, or a source that
    answered garbage — is clamped to zero rather than reported as a negative age.
    """
    created = utc_instant(created_at)
    if created is None:
        return None
    moment = utc_instant(now) or datetime.now(timezone.utc)
    return max(0, (moment - created).days)
