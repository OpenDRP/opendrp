"""WI-16: the breach numbers mean one thing wherever they are read.

Two questions were being answered by one figure. "How much credential exposure do we
have" is a question about findings, and a finding can only exist for an address somebody
put in the inventory. "Is there new trouble out there" is a question about incidents,
which exist in the sources' own catalogues whether or not any address of ours is in them
(F-09) — a scan of a newly added address creates findings about incidents that are years
old, so a seven-day row count answers neither question. The report and the dashboard had
already drifted apart once (REP-01), which is why both now call one rule.

These tests pin the two numbers apart, pin the window the captions promise, and pin the
report and the dashboard to the same payload.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.models.breach import Breach, BreachCatalogue
from app.services.breach_kpi import (
    BREACH_KPI_WINDOW_DAYS,
    breach_kpi,
    breach_kpi_captions,
)


async def _clean(db) -> None:
    """Start from an empty module.

    The unit suite's SQLite database is shared across files, and a leftover catalogue row
    would change the numbers under test rather than fail the test that left it.
    """
    from sqlalchemy import text

    for name in ("breach_catalogue", "drp_breaches"):
        await db.execute(text(f"DELETE FROM {name}"))
    await db.commit()


def _finding(now: datetime, *, days_ago: int, status: str, suffix: str) -> Breach:
    return Breach(
        id=uuid.uuid4(),
        breach_name=f"incident-{suffix}",
        title="Vendor incident",
        domain="vendor.example",
        breach_date=(now - timedelta(days=days_ago)).date(),
        pwn_count=10,
        matched_email=f"user-{suffix}@example.com",
        status=status,
        created_at=now - timedelta(days=days_ago),
    )


def _incident(now: datetime, *, added_days_ago: int | None, suffix: str) -> BreachCatalogue:
    # ``added_date`` is stored the way a source reports it: UTC with no offset.
    naive_now = now.replace(tzinfo=None)
    return BreachCatalogue(
        id=uuid.uuid4(),
        source="hibp",
        breach_name=f"incident-{suffix}",
        title="Vendor incident",
        domain="vendor.example",
        pwn_count=1000,
        data_classes=["Email addresses"],
        attributes={},
        last_synced_at=now,
        added_date=None if added_days_ago is None else naive_now - timedelta(days=added_days_ago),
    )


class TestBreachKpiRule:
    @pytest.mark.asyncio
    async def test_findings_and_incidents_are_two_different_numbers(self, db_session):
        await _clean(db_session)
        now = datetime.now(timezone.utc)
        db_session.add_all(
            [
                _finding(now, days_ago=2, status="active", suffix="recent"),
                _finding(now, days_ago=30, status="resolved", suffix="old"),
                _incident(now, added_days_ago=3, suffix="fresh-a"),
                _incident(now, added_days_ago=5, suffix="fresh-b"),
                _incident(now, added_days_ago=20, suffix="stale"),
            ]
        )
        await db_session.commit()

        kpi = await breach_kpi(db_session, now=now)

        assert kpi["total_findings"] == 2
        assert kpi["active_findings_7d"] == 1
        # Three catalogue rows describe two incidents the sources added this week, and
        # one of those incidents has no finding row of ours at all — which is the whole
        # reason the number exists.
        assert kpi["new_incidents_7d"] == 2
        assert kpi["catalogue_incidents"] == 3
        assert kpi["catalogue_sources"] == 1
        assert kpi["undated_incidents"] == 0

    @pytest.mark.asyncio
    async def test_the_incident_number_does_not_move_with_our_own_inventory(self, db_session):
        await _clean(db_session)
        now = datetime.now(timezone.utc)
        db_session.add(_incident(now, added_days_ago=1, suffix="only"))
        await db_session.commit()

        before = await breach_kpi(db_session, now=now)
        db_session.add(_finding(now, days_ago=1, status="active", suffix="new-address"))
        await db_session.commit()
        after = await breach_kpi(db_session, now=now)

        # Scanning an address we had not scanned before adds a finding about an incident
        # that is not new; the incident count is the fact that did not move.
        assert after["total_findings"] == before["total_findings"] + 1
        assert after["new_incidents_7d"] == before["new_incidents_7d"]

    @pytest.mark.asyncio
    async def test_an_undated_incident_cannot_be_counted_in_the_window(self, db_session):
        await _clean(db_session)
        now = datetime.now(timezone.utc)
        db_session.add(_incident(now, added_days_ago=None, suffix="undated"))
        await db_session.commit()

        kpi = await breach_kpi(db_session, now=now)

        # A source that answers without a date contributes to the catalogue and to
        # neither window: the count says so instead of quietly dropping the row.
        assert kpi["new_incidents_7d"] == 0
        assert kpi["catalogue_incidents"] == 1
        assert kpi["undated_incidents"] == 1

    @pytest.mark.asyncio
    async def test_the_window_is_measured_from_the_instant_it_is_given(self, db_session):
        await _clean(db_session)
        now = datetime.now(timezone.utc)
        db_session.add_all(
            [
                _incident(now, added_days_ago=8, suffix="outside"),
                _incident(now, added_days_ago=6, suffix="inside"),
            ]
        )
        await db_session.commit()

        this_week = await breach_kpi(db_session, now=now)
        assert this_week["new_incidents_7d"] == 1

        # Three days later the same row has fallen out of the window, and the row that
        # was outside it is now further outside: a window measured from an instant, not
        # a lifetime counters table.
        later = await breach_kpi(db_session, now=now + timedelta(days=3))
        assert later["new_incidents_7d"] == 0
        assert later["catalogue_incidents"] == 2

    @pytest.mark.asyncio
    async def test_the_total_is_split_by_class_of_exposure(self, db_session):
        await _clean(db_session)
        now = datetime.now(timezone.utc)
        breach = _finding(now, days_ago=1, status="active", suffix="acct")
        paste = _finding(now, days_ago=1, status="active", suffix="paste")
        paste.exposure_kind = "paste"
        stealer = _finding(now, days_ago=1, status="active", suffix="stealer")
        stealer.exposure_kind = "stealer_log"
        db_session.add_all([breach, paste, stealer])
        await db_session.commit()

        kpi = await breach_kpi(db_session, now=now)

        assert kpi["findings_by_exposure_kind"] == {
            "breach": 1,
            "paste": 1,
            "stealer_log": 1,
        }
        # The split is of the same total, never a second count of something else.
        assert sum(kpi["findings_by_exposure_kind"].values()) == kpi["total_findings"]
        assert set(kpi["captions"]) >= {
            "total_findings",
            "active_findings_7d",
            "new_incidents_7d",
            "findings_by_exposure_kind",
        }

    @pytest.mark.asyncio
    async def test_a_class_this_build_does_not_know_is_still_counted(self, db_session):
        await _clean(db_session)
        now = datetime.now(timezone.utc)
        # An adopted database may hold a class written before the vocabulary was closed;
        # it belongs to the total and is named rather than dropped from the split.
        legacy = _finding(now, days_ago=1, status="active", suffix="legacy")
        legacy.exposure_kind = "paste_dump"
        db_session.add(legacy)
        await db_session.commit()

        kpi = await breach_kpi(db_session, now=now)

        assert kpi["findings_by_exposure_kind"]["paste_dump"] == 1
        assert kpi["findings_by_exposure_kind"]["breach"] == 0
        assert sum(kpi["findings_by_exposure_kind"].values()) == kpi["total_findings"] == 1

    @pytest.mark.asyncio
    async def test_captions_name_the_window_they_count_and_travel_with_the_payload(self, db_session):
        await _clean(db_session)
        now = datetime.now(timezone.utc)

        kpi = await breach_kpi(db_session, now=now)

        assert kpi["window_days"] == BREACH_KPI_WINDOW_DAYS
        assert kpi["captions"] == breach_kpi_captions()
        assert "findings_by_exposure_kind" in kpi["captions"]
        assert f"last {BREACH_KPI_WINDOW_DAYS} days" in kpi["captions"]["new_incidents_7d"]
        assert "whether or not any monitored address is in them" in kpi["captions"]["new_incidents_7d"]
        # A caller that measures a different window gets captions that say so, rather
        # than a sentence promising seven days beside a thirty-day number.
        assert "last 30 days" in (await breach_kpi(db_session, now=now, days=30))["captions"]["new_incidents_7d"]


class TestSurfacesAgree:
    @pytest.mark.asyncio
    async def test_the_report_and_the_dashboard_publish_the_same_breach_payload(
        self, client, auth_headers_viewer, db_session, tmp_path
    ):
        """WI-16's acceptance: the figure in the PDF and the figure on the page.

        Asserted over one seeded installation, reading the dashboard through its
        endpoint and the report through the service the PDF renderer is handed, so a
        change to either definition fails here rather than in an operator's inbox.
        """
        from app.services.report_service import ReportService, _breach_kpi_caption

        await _clean(db_session)
        now = datetime.now(timezone.utc)
        db_session.add_all(
            [
                _finding(now, days_ago=1, status="active", suffix="recent"),
                _incident(now, added_days_ago=2, suffix="fresh"),
                _incident(now, added_days_ago=40, suffix="old"),
            ]
        )
        await db_session.commit()

        stats = await client.get("/api/v1/dashboard/stats", headers=auth_headers_viewer)
        assert stats.status_code == 200, stats.text
        dashboard_kpi = stats.json()["kpi"]

        report_data = await ReportService(db_session).gather_report_data()
        report_kpi = report_data["kpi"]

        # One payload, two surfaces, captions included.
        assert dashboard_kpi["breach"] == report_kpi["breach_kpi"]
        assert report_kpi["new_breach_incidents_7d"] == dashboard_kpi["new_breach_incidents_7d"]
        assert report_kpi["total_breaches"] == dashboard_kpi["total_breaches"] == 1
        assert report_kpi["new_breach_incidents_7d"] == 1
        # The active-threat KPI keeps the meaning the dashboard and the reports audit
        # agreed on (active/investigating findings created in the window) and gains
        # nothing from the incident count.
        assert report_kpi["active_threats_7d"] == dashboard_kpi["active_threats_7d"] == 1

        # What the PDF prints beside the number is the caption the rule wrote, not a
        # second sentence written by the renderer.
        assert (
            _breach_kpi_caption(report_kpi, "new_incidents_7d")
            == report_kpi["breach_kpi"]["captions"]["new_incidents_7d"]
        )

        path = tmp_path / "kpi.pdf"
        ReportService.generate_pdf_sync(str(path), report_data, "analyst@example.com")
        assert path.read_bytes().startswith(b"%PDF-")
        assert path.stat().st_size > 1000
