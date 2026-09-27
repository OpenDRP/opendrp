import inspect

from app.api.v1.routers import dashboard


def test_dashboard_timeline_is_aggregate_not_per_day_loop():
    source = inspect.getsource(dashboard.dashboard_stats)
    assert "timeline_rows" in source
    assert ".union_all(" in source
    assert "for i in range(29, -1, -1)" in source
    # The only loop is response shaping; no execute call may occur inside it.
    response_loop = source.split("timeline = []", 1)[1].split("pb =", 1)[0]
    assert "db.execute" not in response_loop
