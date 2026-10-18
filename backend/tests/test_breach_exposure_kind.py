"""The breach module says which class of exposure each row records (WI-21).

A compromised account, a name that turned up in a paste and a site that turned up in a
stealer log are three different findings about the same address, with three different
responses, and the module could only represent the first. The class travels on the row —
`exposure_kind` — and the module's dedup keys do not move for it, so an installation that
adopts the column keeps its unique pairs and indexes.

The vocabulary is closed where a finding enters: a class nothing recognizes would become
a filter nobody can select and a heading nobody chose, so a source that declares one is
refused by name rather than stored under the wrong class.
"""

from __future__ import annotations

import uuid
from datetime import date
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text

from app.main import app
from app.models import Breach, Connector
from app.schemas.connector import BreachFinding

BASE = "http://test"


@pytest.fixture()
async def client(db_session) -> AsyncGenerator[AsyncClient, None]:
    from app.api.deps import get_db

    async def _override():
        yield db_session

    app.dependency_overrides[get_db] = _override
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url=BASE) as c:
            yield c
    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest_asyncio.fixture()
async def breaches_connector(db_session):
    connector = Connector(
        name=f"conn-exposure-{uuid.uuid4().hex[:8]}",
        connector_type="breaches",
        status="enabled",
        default_job_type="breaches.test",
    )
    db_session.add(connector)
    await db_session.commit()
    await db_session.refresh(connector)
    return connector


async def _ingest(db, connector, finding: dict) -> bool:
    from app.services.ingestion_service import ingest_breach_finding

    return await ingest_breach_finding(db, connector, finding)


async def _rows(db, name: str) -> list[Breach]:
    return list(
        (await db.execute(select(Breach).where(Breach.breach_name == name))).scalars().all()
    )


async def _audit_rows(db, action: str) -> list[dict]:
    rows = (
        await db.execute(
            text(
                "SELECT details FROM drp_audit_logs WHERE action = :a ORDER BY timestamp"
            ),
            {"a": action},
        )
    ).all()
    import json

    return [json.loads(row[0]) if isinstance(row[0], str) else row[0] for row in rows]


class TestDeclaredVocabulary:
    def test_a_source_may_declare_the_class_of_exposure(self):
        finding = BreachFinding(
            breach_name="paste:abc123",
            matched_email="user@corp.example",
            exposure_kind="paste",
        )
        assert finding.exposure_kind == "paste"

    def test_a_class_the_core_does_not_know_is_refused_at_the_boundary(self):
        # "stealerlog" is the spelling of the breach_name prefix, not of the class: a
        # near miss is exactly the value that would otherwise be stored as a breach.
        for bad in ("stealerlog", "paste_dump", "BREACH "):
            with pytest.raises(ValueError):
                BreachFinding(
                    breach_name="incident", matched_email="user@corp.example", exposure_kind=bad
                )

    def test_a_source_that_declares_nothing_declares_nothing(self):
        # None rather than "breach": the wire says what the source claimed, and the
        # storage decides what an absent claim means.
        assert BreachFinding(breach_name="incident", matched_email="u@c.example").exposure_kind is None


class TestStorage:
    def test_the_model_carries_the_class_with_a_default(self):
        column = Breach.__table__.columns["exposure_kind"]
        assert column.nullable is False
        assert column.default.arg == "breach"
        assert column.server_default is not None

    @pytest.mark.asyncio
    async def test_a_finding_without_a_class_is_a_breach_of_an_account(
        self, db_session, breaches_connector, monkeypatch
    ):
        monkeypatch.setattr(
            "app.services.ingestion_service.AlertDeliveryService.enqueue",
            _never_called,
        )
        ok = await _ingest(
            db_session,
            breaches_connector,
            {
                "breach_name": "Undeclared",
                "matched_email": "u@undeclared.example",
                "breach_date": "2026-01-01",
            },
        )
        assert ok is True
        (row,) = await _rows(db_session, "Undeclared")
        assert row.exposure_kind == "breach"

    @pytest.mark.asyncio
    async def test_a_declared_class_is_stored_on_the_row(
        self, db_session, breaches_connector, monkeypatch
    ):
        monkeypatch.setattr(
            "app.services.ingestion_service.AlertDeliveryService.enqueue",
            _never_called,
        )
        ok = await _ingest(
            db_session,
            breaches_connector,
            {
                "breach_name": "paste:def456",
                "matched_email": "u@paste.example",
                "breach_date": "2026-01-01",
                "exposure_kind": "paste",
            },
        )
        assert ok is True
        (row,) = await _rows(db_session, "paste:def456")
        assert row.exposure_kind == "paste"

    @pytest.mark.asyncio
    async def test_an_unknown_class_never_reaches_the_row(
        self, db_session, breaches_connector
    ):
        # The service refuses it as well as the wire schema — a direct caller cannot put
        # a class into storage that no filter can select — and the refusal comes back as
        # a refused finding, which is how the batch reports a violation of the contract.
        ok = await _ingest(
            db_session,
            breaches_connector,
            {
                "breach_name": "Wrong",
                "matched_email": "u@wrong.example",
                "breach_date": "2026-01-01",
                "exposure_kind": "stealerlog",
            },
        )
        assert ok is False
        assert await _rows(db_session, "Wrong") == []

    @pytest.mark.asyncio
    async def test_a_re_report_can_correct_the_class(self, db_session, breaches_connector, monkeypatch):
        monkeypatch.setattr(
            "app.services.ingestion_service.AlertDeliveryService.enqueue",
            _never_called,
        )
        finding = {
            "breach_name": "paste:ghi789",
            "matched_email": "u@corrected.example",
            "breach_date": "2026-01-01",
            "exposure_kind": "paste",
        }
        await _ingest(db_session, breaches_connector, finding)
        await _ingest(db_session, breaches_connector, {**finding, "exposure_kind": "stealer_log"})

        rows = await _rows(db_session, "paste:ghi789")
        assert len(rows) == 1, "correcting the class must not create a second row"
        assert rows[0].exposure_kind == "stealer_log"

    @pytest.mark.asyncio
    async def test_a_re_report_that_declares_nothing_leaves_the_class_alone(
        self, db_session, breaches_connector, monkeypatch
    ):
        monkeypatch.setattr(
            "app.services.ingestion_service.AlertDeliveryService.enqueue",
            _never_called,
        )
        finding = {
            "breach_name": "paste:jkl012",
            "matched_email": "u@kept.example",
            "breach_date": "2026-01-01",
            "exposure_kind": "paste",
        }
        await _ingest(db_session, breaches_connector, finding)
        # A worker that predates the field re-reports the same incident without it.
        await _ingest(
            db_session,
            breaches_connector,
            {key: value for key, value in finding.items() if key != "exposure_kind"},
        )

        (row,) = await _rows(db_session, "paste:jkl012")
        assert row.exposure_kind == "paste"


class TestObservationDate:
    """A row whose source stated no date is dated once, not once per scan (WI-17/18).

    Pastes and stealer-log sites arrive without an incident date, so the core records the
    instant it first saw them and marks ``metadata_incomplete``. Re-computing that instant
    on every scan would move the row's date each time, and the change classifier would
    report the move as ``date_corrected`` — a weekly notification about the platform's
    own clock rather than about anything the source said.
    """

    async def _events(self, db) -> list:
        from app.models import IngestionEvent

        return list((await db.execute(select(IngestionEvent))).scalars().all())

    @pytest.mark.asyncio
    async def test_the_observation_date_is_written_once(
        self, db_session, breaches_connector, monkeypatch
    ):
        monkeypatch.setattr(
            "app.services.ingestion_service.AlertDeliveryService.enqueue",
            _never_called,
        )
        finding = {
            "breach_name": "stealerlog:netflix.com",
            "matched_email": "u@observed.example",
            "exposure_kind": "stealer_log",
            "attributes": {"metadata_incomplete": True, "stealer_log_site": "netflix.com"},
        }
        await _ingest(db_session, breaches_connector, finding)
        (row,) = await _rows(db_session, "stealerlog:netflix.com")
        # A week later, in this test's own terms: the stored instant is the first
        # sighting, not a value the next scan may re-derive.
        row.breach_date = date(2026, 1, 1)
        await db_session.commit()
        before = len(await self._events(db_session))

        await _ingest(db_session, breaches_connector, finding)

        (again,) = await _rows(db_session, "stealerlog:netflix.com")
        assert again.breach_date == date(2026, 1, 1)
        assert len(await self._events(db_session)) == before, (
            "a repeated sighting of an undated row must not notify"
        )

    @pytest.mark.asyncio
    async def test_a_date_the_source_states_still_corrects_the_row(
        self, db_session, breaches_connector, monkeypatch
    ):
        """The fix is about undated rows only: a stated correction is still news."""
        monkeypatch.setattr(
            "app.services.ingestion_service.AlertDeliveryService.enqueue",
            _never_called,
        )
        finding = {
            "breach_name": "stealerlog:corrected.example",
            "matched_email": "u@corrected-date.example",
            "exposure_kind": "stealer_log",
            "attributes": {"metadata_incomplete": True},
        }
        await _ingest(db_session, breaches_connector, finding)
        await _ingest(
            db_session,
            breaches_connector,
            {**finding, "breach_date": "2024-05-05"},
        )

        (row,) = await _rows(db_session, "stealerlog:corrected.example")
        assert row.breach_date == date(2024, 5, 5)


class TestStealerLogsWindow:
    """The core tells the next scan when the last stealer pass actually ran (WI-18)."""

    @pytest.mark.asyncio
    async def test_a_source_that_never_saw_stealer_exposure_is_due_now(self, db_session):
        from app.services.breach_catalogue import stealer_logs_window

        assert await stealer_logs_window(db_session, "source-never") == {
            "source": "source-never",
            "last_seen_at": None,
        }

    @pytest.mark.asyncio
    async def test_the_window_is_the_newest_stealer_sighting_of_that_source(
        self, db_session
    ):
        from datetime import datetime, timezone

        from app.services.breach_catalogue import stealer_logs_window

        old = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
        new = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)
        for name, seen, kind, source in (
            ("stealerlog:old", old, "stealer_log", "src-window"),
            ("stealerlog:new", new, "stealer_log", "src-window"),
            # A paste seen later is not evidence that the stealer pass ran.
            ("paste:later", datetime(2026, 10, 16, tzinfo=timezone.utc), "paste", "src-window"),
            # Nor is another source's stealer exposure.
            ("stealerlog:other", datetime(2026, 10, 17, tzinfo=timezone.utc), "stealer_log", "src-other"),
        ):
            db_session.add(
                Breach(
                    source_id=source,
                    breach_name=name,
                    title=name,
                    domain="corp.example",
                    breach_date=date(2026, 1, 1),
                    pwn_count=0,
                    matched_email=f"{name}@corp.example",
                    exposure_kind=kind,
                    last_seen_at=seen,
                )
            )
        await db_session.commit()

        window = await stealer_logs_window(db_session, "src-window")

        assert window["last_seen_at"].startswith("2026-10-10T12:00:00")


class TestApiFilter:
    async def _seed(self, db) -> None:
        for name, kind in (
            ("class-breach", "breach"),
            ("class-paste", "paste"),
            ("class-stealer", "stealer_log"),
        ):
            db.add(
                Breach(
                    breach_name=name,
                    title="T",
                    domain="corp.example",
                    breach_date=date(2024, 1, 1),
                    pwn_count=10,
                    matched_email=f"{name}@corp.example",
                    exposure_kind=kind,
                )
            )
        await db.commit()

    @pytest.mark.asyncio
    async def test_the_list_returns_only_the_requested_class(
        self, client, db_session, auth_headers_viewer
    ):
        await self._seed(db_session)

        response = await client.get(
            "/api/v1/breaches", params={"exposure_kind": "paste"}, headers=auth_headers_viewer
        )

        assert response.status_code == 200, response.text
        body = response.json()
        assert [item["breach_name"] for item in body["items"]] == ["class-paste"]
        assert body["total"] == 1
        assert body["items"][0]["exposure_kind"] == "paste"

    @pytest.mark.asyncio
    async def test_every_declared_class_can_be_selected(
        self, client, db_session, auth_headers_viewer
    ):
        from app.services.ingestion_service import BREACH_EXPOSURE_KINDS

        await self._seed(db_session)

        seen = []
        for kind in BREACH_EXPOSURE_KINDS:
            response = await client.get(
                "/api/v1/breaches", params={"exposure_kind": kind}, headers=auth_headers_viewer
            )
            assert response.status_code == 200, response.text
            seen.append(response.json()["total"])

        # One row per class, and the filter is not a synonym for "everything".
        assert seen == [1, 1, 1]

    @pytest.mark.asyncio
    async def test_a_class_outside_the_vocabulary_is_a_validation_error(
        self, client, auth_headers_viewer
    ):
        response = await client.get(
            "/api/v1/breaches", params={"exposure_kind": "stealerlog"}, headers=auth_headers_viewer
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_the_report_renders_the_class_beside_the_incident(self, db_session, tmp_path):
        """The class reaches the report's own cells, not only the summary split.

        Asserted on the values the PDF renderer is handed, which is the layer that can be
        checked without a text extractor: a report a reader prints has to say whether the
        finding is a compromised account, a paste or a stealer log.
        """
        from app.services.report_service import (
            ReportService,
            _report_pdf_text_values,
        )

        db_session.add(
            Breach(
                breach_name="paste:report",
                title="P",
                domain="corp.example",
                breach_date=date(2024, 1, 1),
                pwn_count=1,
                matched_email="u@report.example",
                exposure_kind="paste",
            )
        )
        await db_session.commit()

        data = await ReportService(db_session).gather_report_data()
        assert data["kpi"]["breach_kpi"]["findings_by_exposure_kind"]["paste"] == 1
        assert "paste" in _report_pdf_text_values(data, "analyst@example.com")

        path = tmp_path / "exposure.pdf"
        ReportService.generate_pdf_sync(str(path), data, "analyst@example.com")
        assert path.read_bytes().startswith(b"%PDF-")

    @pytest.mark.asyncio
    async def test_the_filter_is_recorded_in_the_audit_row(
        self, client, db_session, auth_headers_viewer
    ):
        await self._seed(db_session)

        await client.get(
            "/api/v1/breaches", params={"exposure_kind": "stealer_log"}, headers=auth_headers_viewer
        )

        rows = await _audit_rows(db_session, "breach.list")
        assert rows, "the list read must leave an audit row"
        assert rows[-1]["exposure_kind"] == "stealer_log"
        assert rows[-1]["results"] == 1


async def _never_called(*args, **kwargs):  # pragma: no cover - defensive
    raise AssertionError("alert delivery is not part of this test")
