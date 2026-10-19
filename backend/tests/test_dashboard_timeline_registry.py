"""The dashboard timeline is the registry's list, not a hardcoded pair (DHP-11).

The chart used to sum two tables by name. A module the platform's own protocol
lets an operator declare therefore never appeared, and nothing failed when it did
not — the row simply showed the two modules someone had written into the core.
These tests hold the two halves of the promise:

* every module is either counted or excluded *by name with a reason*, so a newly
  declared module cannot silently contribute nothing;
* a module stored generically changes the series and the row without any change
  to `DashboardPage.tsx`, because the series keys and labels come from the
  response.

The previous 30-day window (U-4) is checked here too: it must count the earlier
period and only it.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.models.breach import Breach
from app.models.finding import Finding
from app.models.module import Module
from app.models.phishing import PhishingDomain
from app.services.dashboard_timeline import (
    EXCLUDED_ADAPTERS,
    NATIVE_TIMELINE_MODELS,
    timeline_layout,
)
from app.services.module_registry import load_modules


async def _declare_generic_module(db, module_id: str = "brand_abuse", label: str = "Brand abuse"):
    db.add(
        Module(
            id=module_id,
            label=label,
            description="Look-alike pages hosted outside the domain space.",
            finding_kind=f"{module_id}_finding",
            asset_types=["domain"],
            fields={},
            dedup_fields=["url"],
            title_field="url",
            storage={"kind": "generic", "adapter": "generic"},
            enabled=True,
            builtin=False,
        )
    )
    await db.commit()
    return module_id


def _generic_finding(module_id: str, *, when: datetime) -> Finding:
    return Finding(
        module=module_id,
        finding_kind=f"{module_id}_finding",
        connector_name="test-connector",
        dedup_key=uuid.uuid4().hex,
        title=f"https://evil-{uuid.uuid4().hex[:6]}.example",
        payload={},
        created_at=when,
    )


@pytest.mark.asyncio
async def test_every_registered_module_is_counted_or_excluded_by_name(db_session):
    """The gate the plan asks for: no module may be silently uncounted."""
    modules = await load_modules(db_session)
    counted, excluded = timeline_layout(modules)

    seen = {item.module_id for item in counted} | {item.module_id for item in excluded}
    assert seen == set(modules), (
        "these modules are neither in the timeline nor excluded with a reason: "
        f"{sorted(set(modules) - seen)}"
    )
    # The split is also a statement about storage, not about names: a counted
    # module must use an adapter the service can actually read.
    for item in counted:
        assert item.adapter == "generic" or item.adapter in NATIVE_TIMELINE_MODELS
    for item in excluded:
        assert item.reason in set(EXCLUDED_ADAPTERS.values()) | {"unsupported_storage"}
    # Today's built-ins: phishing and breaches are counted; DNS and exposure are
    # current-state observations, so they say so instead of contributing zero.
    by_key = {item.key: item for item in counted}
    assert {"phishing", "breaches"} <= set(by_key)
    assert {item.module_id for item in excluded} >= {"dns", "exposure"}


@pytest.mark.asyncio
async def test_a_newly_declared_module_appears_without_a_frontend_change(
    client, auth_headers_viewer, db_session
):
    module_id = await _declare_generic_module(db_session)
    now = datetime.now(timezone.utc)
    db_session.add_all(
        [
            _generic_finding(module_id, when=now - timedelta(hours=1)),
            _generic_finding(module_id, when=now - timedelta(days=5)),
        ]
    )
    await db_session.commit()

    body = (await client.get("/api/v1/dashboard/stats", headers=auth_headers_viewer)).json()

    series = {item["key"]: item for item in body["timeline_series"]}
    assert module_id in series, "a declared module's findings are nowhere in the row"
    # The label travels with the key: the chart names the line from the response.
    assert series[module_id]["label"] == "Brand abuse"
    assert series[module_id]["module_id"] == module_id
    # Counted from `drp_findings` by module id, on the days they were created.
    dates = {row["date"]: row for row in body["timeline"]}
    assert dates[now.date().isoformat()][module_id] == 1
    assert dates[(now - timedelta(days=5)).date().isoformat()][module_id] == 1
    assert body["timeline_comparison"][module_id] == {"current": 2, "previous": 0}


@pytest.mark.asyncio
async def test_the_previous_window_is_counted_separately(client, auth_headers_viewer, db_session):
    """U-4: "more than last month" comes from the same data, not a new endpoint."""
    now = datetime.now(timezone.utc)
    suffix = uuid.uuid4().hex[:8]
    db_session.add_all(
        [
            PhishingDomain(
                id=uuid.uuid4(),
                phishing_domain=f"recent-{suffix}.example",
                matched_asset="example.test",
                detection_source="dnstwist",
                created_at=now - timedelta(days=2),
            ),
            PhishingDomain(
                id=uuid.uuid4(),
                phishing_domain=f"previous-{suffix}.example",
                matched_asset="example.test",
                detection_source="dnstwist",
                created_at=now - timedelta(days=40),
            ),
            # Outside both windows: it must appear in neither number.
            PhishingDomain(
                id=uuid.uuid4(),
                phishing_domain=f"older-{suffix}.example",
                matched_asset="example.test",
                detection_source="dnstwist",
                created_at=now - timedelta(days=90),
            ),
            Breach(
                id=uuid.uuid4(),
                breach_name=f"PreviousBreach-{suffix}",
                title="Previous breach",
                domain="example.test",
                breach_date=(now - timedelta(days=50)).date(),
                pwn_count=10,
                matched_email=f"old-{suffix}@example.test",
                created_at=now - timedelta(days=50),
            ),
        ]
    )
    await db_session.commit()

    body = (await client.get("/api/v1/dashboard/stats", headers=auth_headers_viewer)).json()

    assert body["timeline_comparison"]["phishing"] == {"current": 1, "previous": 1}
    assert body["timeline_comparison"]["breaches"] == {"current": 0, "previous": 1}
    # The row itself only covers the current window.
    assert sum(row["phishing"] for row in body["timeline"]) == 1
    assert body["timeline"][0]["date"] < body["timeline"][-1]["date"]


def test_the_statement_compiles_for_postgres_without_a_typed_group_by_parameter():
    """The SQLite-only runs cannot catch this class of defect (no PG server here).

    The first version of these totals grouped by the series key, which compiled
    to ``GROUP BY %(param)s`` — PostgreSQL refuses a bare parameter there because
    it cannot infer its type, while SQLite accepts it and every local test stayed
    green. Compiling under the PostgreSQL dialect pins the fix offline: the
    series key is a cast constant, no bind parameter appears in a ``GROUP BY``,
    and both windows are still one ``UNION ALL``.
    """
    from sqlalchemy.dialects import postgresql, sqlite

    from app.services import dashboard_timeline as timeline
    from app.services.dashboard_timeline import TimelineSeries

    now = datetime.now(timezone.utc)
    series = [
        TimelineSeries("breaches", "Credential breaches", "breaches", "breach"),
        TimelineSeries("phishing", "Phishing", "phishing", "phishing"),
        TimelineSeries("brand_abuse", "Brand abuse", "brand_abuse", "generic"),
    ]
    start = now - timedelta(days=30)

    for dialect in (postgresql.dialect(), sqlite.dialect()):
        daily = str(
            timeline._union(
                timeline._series_select(item, dialect=dialect.name, start=start, end=now)
                for item in series
            ).compile(dialect=dialect)
        )
        assert daily.count("UNION ALL") == len(series) - 1
        # Every branch may group by a day expression, never by a parameter.
        assert "GROUP BY" in daily
        assert "GROUP BY %(param" not in daily

    totals = str(
        timeline._union(
            timeline._totals_select(item, start=start - timedelta(days=30), end=start)
            for item in series
        ).compile(dialect=postgresql.dialect())
    )
    assert totals.count("UNION ALL") == len(series) - 1
    assert "GROUP BY" not in totals
    # The union column is a typed constant, so PG does not have to infer it.
    assert "CAST(%(param_1)s AS VARCHAR)" in totals
    assert "timezone(" in str(
        timeline._series_select(
            series[0], dialect="postgresql", start=start, end=now
        ).compile(dialect=postgresql.dialect())
    )


@pytest.mark.asyncio
async def test_excluded_modules_are_absent_from_the_row_and_named_in_the_response(
    client, auth_headers_viewer
):
    body = (await client.get("/api/v1/dashboard/stats", headers=auth_headers_viewer)).json()

    excluded = {item["module_id"]: item for item in body["timeline_excluded"]}
    assert excluded["dns"]["reason"] == "current_state_observations"
    assert excluded["exposure"]["reason"] == "current_state_observations"
    for item in excluded.values():
        assert item["label"], "an exclusion must name the module it excludes"
    keys = {item["key"] for item in body["timeline_series"]}
    assert not keys & set(excluded), "a module cannot be both counted and excluded"
    for row in body["timeline"]:
        assert not set(excluded) & set(row)
