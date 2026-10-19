"""The dashboard's finding timeline, built from the module registry (DHP-11).

The series used to be two hardcoded keys in ``dashboard.py`` — ``phishing`` from
``drp_phishing_domains`` and ``breaches`` from ``drp_breaches`` — so a module that
declared itself through the registry protocol never appeared, and removing one
would have left a line reading zero forever. The row is now built from the
declarations:

* a module whose ``storage.adapter`` names a native findings table is counted
  from that table (``phishing``, ``breach``);
* a module stored through the generic adapter is counted from ``drp_findings``,
  filtered by its own id — that is what makes a newly declared module show up
  without a core or frontend release;
* an adapter that stores *current state* rather than dated findings is excluded
  explicitly, with a reason code, instead of silently contributing zero.

The exclusion list is data, not a default: ``tests/test_dashboard_timeline_registry.py``
walks every module the platform ships and every module an installation declares,
and fails when one is neither counted nor excluded. That is the half of the
registry promise a test can keep — a module that reports findings nobody counts
is worse than one that never appears.

One statement answers "how many findings per module per day" (a ``UNION ALL`` of
one grouped aggregate per series, the shape DSH-07 asked for), and one more
answers the previous window's totals for U-4. Days with no findings are filled in
Python, never by a query per day.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Iterable, Mapping

from sqlalchemy import Date, String, cast, func, literal, select, union_all
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Breach, DrpPhishingDomain as PhishingDomain, Finding
from app.services.connector_manifest import GENERIC_ADAPTER, ModuleSpec
from app.services.module_registry import load_modules

#: Native findings tables that carry a creation time, by write adapter.
#: A module naming one of these is counted from its own table, not from the
#: generic store: the native writer never writes ``drp_findings``.
NATIVE_TIMELINE_MODELS = {
    "phishing": PhishingDomain,
    "breach": Breach,
}

#: Adapters that deliberately do not join the finding timeline, with the reason
#: code the API publishes. These store the *current* state of an asset (what DNS
#: answers today, which service the provider sees open), not a dated finding; a
#: daily count would describe edits to the inventory rather than discoveries.
EXCLUDED_ADAPTERS: dict[str, str] = {
    "dns_observation": "current_state_observations",
    "exposure": "current_state_observations",
}


@dataclass(frozen=True)
class TimelineSeries:
    """One line of the chart: a registry module that records dated findings."""

    key: str
    label: str
    module_id: str
    adapter: str


@dataclass(frozen=True)
class ExcludedModule:
    """A registry module the chart does not count, and why."""

    module_id: str
    label: str
    reason: str


@dataclass(frozen=True)
class Timeline:
    rows: list[dict]
    series: list[TimelineSeries]
    excluded: list[ExcludedModule]
    comparison: dict[str, dict[str, int]]
    start: date
    end: date


def timeline_layout(
    modules: Mapping[str, ModuleSpec],
) -> tuple[list[TimelineSeries], list[ExcludedModule]]:
    """Split the registry into counted series and named exclusions.

    Disabled modules stay in the chart: disabling a module stops ingestion, it
    does not erase the findings already recorded, and a line that vanished on a
    settings change would make the history unreadable. The order is by module id
    so the row and the legend do not depend on insertion order.
    """
    series: list[TimelineSeries] = []
    excluded: list[ExcludedModule] = []
    for module_id in sorted(modules):
        spec = modules[module_id]
        adapter = spec.adapter
        if adapter == GENERIC_ADAPTER or adapter in NATIVE_TIMELINE_MODELS:
            series.append(
                TimelineSeries(
                    key=spec.id,
                    label=spec.label,
                    module_id=spec.id,
                    adapter=adapter,
                )
            )
        else:
            excluded.append(
                ExcludedModule(
                    module_id=spec.id,
                    label=spec.label,
                    reason=EXCLUDED_ADAPTERS.get(adapter, "unsupported_storage"),
                )
            )
    return series, excluded


def _day_expr(column, dialect: str):
    """The UTC calendar day of ``column``, in the form the dialect can group by.

    SQLite must receive ``DATE(timestamp)`` directly: ``CAST(timestamp AS DATE)``
    turns an ISO timestamp into an integer year and moves the row to a bogus day.
    PostgreSQL's ``timezone()`` makes the bucket explicitly UTC regardless of the
    connection's session timezone.
    """
    if dialect == "sqlite":
        return func.date(column)
    return cast(func.timezone("UTC", column), Date)


def _series_select(series: TimelineSeries, *, dialect: str, start: datetime, end: datetime):
    """``(series, day, count)`` for one module, grouped by UTC day."""
    # The native models differ by adapter; only the columns both mixins provide
    # (`id`, `created_at`) are used, so the union is expressed once here.
    model: Any
    extra: tuple[Any, ...] = ()
    if series.adapter == GENERIC_ADAPTER:
        model = Finding
        extra = (Finding.module == series.key,)
    else:
        model = NATIVE_TIMELINE_MODELS[series.adapter]
    day = _day_expr(model.created_at, dialect)
    return (
        select(
            # Cast, not a bare bind: PostgreSQL has to resolve the union column's
            # type, and an untyped parameter leaves that to chance.
            cast(literal(series.key), String).label("series"),
            day.label("day"),
            func.count(model.id).label("total"),
        )
        .where(model.created_at >= start, model.created_at < end, *extra)
        .group_by(day)
    )


def _totals_select(series: TimelineSeries, *, start: datetime, end: datetime):
    """``(series, count)`` for one module over a window, no day grouping."""
    model: Any
    extra: tuple[Any, ...] = ()
    if series.adapter == GENERIC_ADAPTER:
        model = Finding
        extra = (Finding.module == series.key,)
    else:
        model = NATIVE_TIMELINE_MODELS[series.adapter]
    # No GROUP BY: the series key is a constant and the other column is an
    # aggregate. Grouping by the bind parameter would compile to
    # ``GROUP BY %(param)s``, which PostgreSQL refuses because it cannot infer a
    # type for a bare parameter; SQLite accepts it, so only a plan-based review
    # or this test would have caught it.
    return (
        select(
            cast(literal(series.key), String).label("series"),
            func.count(model.id).label("total"),
        ).where(model.created_at >= start, model.created_at < end, *extra)
    )


def _union(statements: Iterable):
    """One statement for every series: ``UNION ALL`` of the grouped aggregates.

    Built in a single call rather than by chaining ``.union_all`` — a
    ``CompoundSelect`` does not accept another union, and a loop over modules is
    exactly the shape that would otherwise turn into one query per module.
    """
    statements = list(statements)
    if not statements:
        return None
    if len(statements) == 1:
        return statements[0]
    return union_all(*statements)


def _as_date(value) -> date:
    """A grouped day from either dialect (``date`` on PG, ``str`` on SQLite)."""
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value)[:10])


async def _daily_counts(
    db: AsyncSession, series: list[TimelineSeries], *, start: datetime, end: datetime
) -> dict[str, dict[date, int]]:
    dialect = db.get_bind().dialect.name
    statement = _union(
        _series_select(item, dialect=dialect, start=start, end=end) for item in series
    )
    if statement is None:
        return {}
    counts: dict[str, dict[date, int]] = {}
    for key, day, total in (await db.execute(statement)).all():
        counts.setdefault(str(key), {})[_as_date(day)] = int(total or 0)
    return counts


async def _window_totals(
    db: AsyncSession, series: list[TimelineSeries], *, start: datetime, end: datetime
) -> dict[str, int]:
    statement = _union(_totals_select(item, start=start, end=end) for item in series)
    if statement is None:
        return {}
    return {
        str(key): int(total or 0)
        for key, total in (await db.execute(statement)).all()
    }


async def build_timeline(db: AsyncSession, *, now: datetime, days: int = 30) -> Timeline:
    """The last ``days`` days by module, plus the window before it (U-4)."""
    modules = await load_modules(db)
    series, excluded = timeline_layout(modules)

    end_date = now.date()
    start_date = end_date - timedelta(days=days - 1)
    start = datetime.combine(start_date, time.min, tzinfo=timezone.utc)
    # Tomorrow's midnight, so today's findings are inside the window while a
    # clock-skewed future row cannot land in the last bucket.
    end = datetime.combine(end_date + timedelta(days=1), time.min, tzinfo=timezone.utc)
    previous_start = start - timedelta(days=days)

    by_day = await _daily_counts(db, series, start=start, end=end)
    previous = await _window_totals(db, series, start=previous_start, end=start)

    rows: list[dict] = []
    for offset in range(days):
        day = start_date + timedelta(days=offset)
        row: dict = {"date": day.isoformat()}
        for item in series:
            row[item.key] = by_day.get(item.key, {}).get(day, 0)
        rows.append(row)

    comparison = {
        item.key: {
            "current": sum(by_day.get(item.key, {}).values()),
            "previous": previous.get(item.key, 0),
        }
        for item in series
    }
    return Timeline(
        rows=rows,
        series=series,
        excluded=excluded,
        comparison=comparison,
        start=start_date,
        end=end_date,
    )
__all__ = [
    "EXCLUDED_ADAPTERS",
    "NATIVE_TIMELINE_MODELS",
    "ExcludedModule",
    "Timeline",
    "TimelineSeries",
    "build_timeline",
    "timeline_layout",
]
