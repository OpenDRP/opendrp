import inspect

from app.api.v1.routers import dashboard
from app.services import dashboard_timeline


def test_dashboard_timeline_is_aggregate_not_per_day_loop() -> None:
    """One aggregate per window, never a query per day or per module.

    The aggregate moved out of the HTTP handler twice: into `_stats_payload`
    (DHP-10, so `/dashboard/stats` and `/dashboard/overview` share it) and into
    `app/services/dashboard_timeline.py` (DHP-11, so the series come from the
    module registry). The check follows the code that builds the query; its
    intent is unchanged, and it still fails if anyone reintroduces a loop that
    calls the database once per day.
    """
    params = inspect.signature(dashboard._stats_payload).parameters
    assert list(params)[:2] == ["db", "now"], "the summary must stay a pure read"

    source = inspect.getsource(dashboard_timeline)
    # Every series is combined into one statement, not queried one by one.
    assert "union_all(*statements)" in source
    # Dialect-correct UTC buckets: SQLite's DATE() and PostgreSQL's timezone().
    assert 'func.timezone("UTC"' in source
    assert "func.date(column)" in source
    # Two statements per build — current window by day, previous window as a
    # total — and no more. A third would be the per-day loop coming back.
    assert source.count("db.execute(") == 2

    # The calendar is completed in Python: no execute call inside that loop.
    build = inspect.getsource(dashboard_timeline.build_timeline)
    day_loop = build.split("for offset in range(days):", 1)[1].split("comparison =", 1)[0]
    assert "db.execute" not in day_loop
    assert "timedelta(days=offset)" in day_loop
