import uuid
from datetime import datetime, timezone
from typing import AsyncGenerator
from unittest.mock import MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.models.report import Report


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


@pytest.fixture()
def report_store(tmp_path, monkeypatch):
    """Point the report store at a temporary directory for one test.

    The store is configuration rather than part of the stored value, so an
    artifact only ever resolves where the deployment says it lives. A test that
    wants a downloadable report has to give it a store.
    """
    from app.core.config import settings as core_settings

    store = tmp_path / "reports_store"
    store.mkdir()
    monkeypatch.setattr(core_settings, "REPORTS_STORE_DIR", str(store))
    return store


def _write_artifact(store, report_id, body: bytes = b"%PDF-1.4 fake body bytes") -> str:
    """Create the artifact a report row would reference, and return its *name*."""
    name = f"{report_id}.pdf"
    (store / name).write_bytes(body)
    return name


class TestReportsGenerate:
    @pytest.mark.asyncio
    async def test_generate_report_returns_503_when_celery_unavailable(
        self, client, db_session, auth_headers_analyst, test_analyst
    ):
        with patch(
            "app.tasks.report_tasks.generate_report_task.apply_async",
            side_effect=RuntimeError("celery down"),
        ) as broken:
            r = await client.post(
                "/api/v1/reports/generate",
                json={"report_name": "Quarterly Report"},
                headers=auth_headers_analyst,
            )
        broken.assert_called_once()
        assert r.status_code == 503, r.text
        report_id = (await db_session.execute(
            __import__("sqlalchemy").select(Report.id).order_by(Report.created_at.desc())
        )).scalar_one()
        assert report_id is not None
        saved = await db_session.get(Report, report_id)
        assert saved is not None
        assert saved.status == "failed"
        assert saved.report_name == "Quarterly Report"
        assert saved.created_by == test_analyst.id

    @pytest.mark.asyncio
    async def test_generate_report_celery_apply_async_success_schedules(
        self, client, auth_headers_admin
    ):
        mock_result = MagicMock()
        mock_result.id = "celery-task-abc123"
        with patch(
            "app.tasks.report_tasks.generate_report_task.apply_async",
            return_value=mock_result,
        ) as good:
            r = await client.post(
                "/api/v1/reports/generate",
                json={},
                headers=auth_headers_admin,
            )
        good.assert_called_once()
        assert r.status_code == 202
        assert r.json()["estimated_seconds"] == 15
        new_name = r.json()
        assert "scheduled" == new_name["status"]

    @pytest.mark.asyncio
    async def test_generate_report_allows_viewer(
        self, client, db_session, auth_headers_viewer, test_viewer
    ):
        """Generating a report is a read-only consolidation, so viewers may do it."""
        mock_result = MagicMock()
        mock_result.id = "celery-task-viewer"
        with patch(
            "app.tasks.report_tasks.generate_report_task.apply_async",
            return_value=mock_result,
        ) as scheduled:
            r = await client.post(
                "/api/v1/reports/generate", json={}, headers=auth_headers_viewer
            )
        assert r.status_code == 202, r.text
        scheduled.assert_called_once()
        from sqlalchemy import select as _select

        saved = (
            await db_session.execute(
                _select(Report).where(Report.created_by == test_viewer.id)
            )
        ).scalars().all()
        assert saved and saved[-1].status == "pending"

    @pytest.mark.asyncio
    async def test_generate_report_unauthenticated_401(self, client):
        r = await client.post("/api/v1/reports/generate", json={})
        assert r.status_code in (401, 403), r.text


class TestReportsListAndDownload:
    @pytest.mark.asyncio
    async def test_list_reports_pagination_200_new_item_in_page(
        self, client, db_session, auth_headers_viewer, test_analyst
    ):
        from sqlalchemy import text

        await db_session.execute(text("DELETE FROM reports"))
        await db_session.commit()
        created = []
        for i in range(3):
            r = Report(
                id=uuid.uuid4(),
                report_name=f"Report Paginated {i}",
                created_by=test_analyst.id,
                file_path="",
                status="pending",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            db_session.add(r)
            created.append(r)
        await db_session.commit()
        r = await client.get(
            "/api/v1/reports?page=1&size=2", headers=auth_headers_viewer
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["total"] == 3
        assert body["size"] == 2
        assert body["pages"] == 2
        assert len(body["items"]) == 2
        first_email = body["items"][0].get("created_by_email")
        assert first_email == test_analyst.email

    @pytest.mark.asyncio
    async def test_download_report_completed_pdf_returns_file_response(
        self, client, db_session, auth_headers_viewer, test_analyst, report_store
    ):
        r_id = uuid.uuid4()
        stored = _write_artifact(
            report_store, r_id, b"%PDF-1.4 fake body bytes here sample"
        )
        rep = Report(
            id=r_id,
            report_name="Sample Download",
            created_by=test_analyst.id,
            file_path=stored,
            status="completed",
        )
        db_session.add(rep)
        await db_session.commit()
        r = await client.get(
            f"/api/v1/reports/{r_id}/download", headers=auth_headers_viewer
        )
        assert r.status_code == 200, r.text
        assert r.headers["content-type"] == "application/pdf"
        assert b"%PDF-1.4" in r.content
        cd = r.headers.get("content-disposition", "")
        assert "Sample_Download" in cd or "Sample Download" in cd or ".pdf" in cd

    @pytest.mark.asyncio
    async def test_download_report_not_found_404_for_pending(
        self, client, db_session, auth_headers_viewer, test_analyst
    ):
        r_id = uuid.uuid4()
        rep = Report(
            id=r_id,
            report_name="Still pending",
            created_by=test_analyst.id,
            file_path="",
            status="pending",
        )
        db_session.add(rep)
        await db_session.commit()
        r = await client.get(
            f"/api/v1/reports/{r_id}/download", headers=auth_headers_viewer
        )
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_download_missing_artifact_404_explains_and_audits(
        self, client, db_session, auth_headers_viewer, test_analyst
    ):
        """A completed row whose file vanished must not look like a random 404.

        This is the operator-visible half of the bug report: the row said
        ``completed``, the store had no file, and the download produced an
        opaque 404 with no audit trail.
        """
        from sqlalchemy import select as _select

        from app.models.audit import AuditLog

        r_id = uuid.uuid4()
        rep = Report(
            id=r_id,
            report_name="Vanished report",
            created_by=test_analyst.id,
            # A valid artifact name with no file behind it: the store was
            # restored without the volume, or someone cleaned it out.
            file_path="report-artifact.pdf",
            status="completed",
        )
        db_session.add(rep)
        await db_session.commit()

        r = await client.get(
            f"/api/v1/reports/{r_id}/download", headers=auth_headers_viewer
        )
        assert r.status_code == 404
        assert "no longer available" in r.json()["detail"]

        await db_session.commit()
        rows = list(
            (
                await db_session.execute(
                    _select(AuditLog).where(
                        AuditLog.action == "report.download.missing"
                    )
                )
            ).scalars()
        )
        assert len(rows) == 1
        assert rows[0].details["report_id"] == str(r_id)
        assert rows[0].details["reason"] == "missing"

    @pytest.mark.asyncio
    async def test_download_refuses_a_stored_path_and_audits_it_separately(
        self, client, db_session, auth_headers_viewer, test_analyst, report_store
    ):
        """A row pointing outside the store is a different event from a lost file.

        The caller is told nothing either way — a 404 that reveals the host's
        layout would be worse than the 404 it already gets — but the operator gets
        an audit action that says the *row* is wrong rather than the file missing,
        and the file is not served whatever it contains.
        """
        from sqlalchemy import select as _select

        from app.models.audit import AuditLog

        secret = report_store.parent / "secret.pdf"
        secret.write_bytes(b"%PDF-1.4 not a report")

        r_id = uuid.uuid4()
        rep = Report(
            id=r_id,
            report_name="Hand-edited row",
            created_by=test_analyst.id,
            file_path=str(secret),
            status="completed",
        )
        db_session.add(rep)
        await db_session.commit()

        r = await client.get(
            f"/api/v1/reports/{r_id}/download", headers=auth_headers_viewer
        )
        assert r.status_code == 404
        assert b"not a report" not in r.content

        await db_session.commit()
        rejected = list(
            (
                await db_session.execute(
                    _select(AuditLog).where(
                        AuditLog.action == "report.artifact.rejected"
                    )
                )
            ).scalars()
        )
        missing = list(
            (
                await db_session.execute(
                    _select(AuditLog).where(
                        AuditLog.action == "report.download.missing"
                    )
                )
            ).scalars()
        )
        assert len(rejected) == 1
        assert missing == []
        assert rejected[0].details["reason"] == "not_a_name"
        assert rejected[0].details["had_directory_component"] is True
        # The audit record names the artifact, not the host path it was found on.
        assert "artifact_name" in rejected[0].details
        assert str(secret) not in str(rejected[0].details)

    @pytest.mark.asyncio
    async def test_list_reports_reports_file_availability(
        self, client, db_session, auth_headers_viewer, test_analyst, report_store
    ):
        """The UI hides the download when the artifact is gone."""
        present_id = uuid.uuid4()
        stored = _write_artifact(report_store, present_id, b"%PDF-1.4 present")
        present = Report(
            id=present_id,
            report_name="Present report",
            created_by=test_analyst.id,
            file_path=stored,
            status="completed",
        )
        missing = Report(
            id=uuid.uuid4(),
            report_name="Missing report",
            created_by=test_analyst.id,
            file_path="missing-report-artifact.pdf",
            status="completed",
        )
        db_session.add_all([present, missing])
        await db_session.commit()

        r = await client.get("/api/v1/reports", headers=auth_headers_viewer)
        assert r.status_code == 200, r.text
        items = {i["report_name"]: i for i in r.json()["items"]}
        assert items["Present report"]["file_available"] is True
        assert items["Missing report"]["file_available"] is False

        # A pending report has no artifact yet, so the flag is False too;
        # the UI keys off ``status`` first and this flag second.


class TestReportsDelete:
    @pytest.mark.asyncio
    async def test_delete_report_admin_204_removes_db_and_file(
        self, client, db_session, auth_headers_admin, test_analyst, report_store
    ):
        r_id = uuid.uuid4()
        stored = _write_artifact(report_store, r_id, b"content")
        path = report_store / stored
        assert path.exists()
        rep = Report(
            id=r_id,
            report_name="to be deleted",
            created_by=test_analyst.id,
            file_path=stored,
            status="completed",
        )
        db_session.add(rep)
        await db_session.commit()
        r = await client.delete(
            f"/api/v1/reports/{r_id}", headers=auth_headers_admin
        )
        assert r.status_code == 204
        gone = await db_session.get(Report, r_id)
        assert gone is None
        assert not path.exists()

    @pytest.mark.asyncio
    async def test_delete_removes_the_row_but_never_a_file_outside_the_store(
        self, client, db_session, auth_headers_admin, test_analyst, report_store
    ):
        """An administrator deleting a report must not be able to unlink a file.

        The row is still deleted — refusing would leave an undeletable report in
        the list forever — but a path the platform cannot prove it wrote is left
        exactly where it is, with the reason recorded on the audit row.
        """
        from sqlalchemy import select as _select

        from app.models.audit import AuditLog

        outsider = report_store.parent / "not-ours.pdf"
        outsider.write_bytes(b"must survive")

        r_id = uuid.uuid4()
        rep = Report(
            id=r_id,
            report_name="points elsewhere",
            created_by=test_analyst.id,
            file_path=str(outsider),
            status="completed",
        )
        db_session.add(rep)
        await db_session.commit()

        r = await client.delete(f"/api/v1/reports/{r_id}", headers=auth_headers_admin)
        assert r.status_code == 204
        assert outsider.exists()
        assert await db_session.get(Report, r_id) is None

        await db_session.commit()
        rows = list(
            (
                await db_session.execute(
                    _select(AuditLog).where(AuditLog.action == "report.delete")
                )
            ).scalars()
        )
        assert len(rows) == 1
        assert rows[0].details["artifact_removed"] is False
        assert rows[0].details["reason"] == "not_a_name"

    @pytest.mark.asyncio
    async def test_delete_report_viewer_403_not_owner_anyway(
        self, client, db_session, auth_headers_viewer, test_analyst
    ):
        r_id = uuid.uuid4()
        rep = Report(
            id=r_id,
            report_name="any",
            created_by=test_analyst.id,
            file_path="",
            status="pending",
        )
        db_session.add(rep)
        await db_session.commit()
        r = await client.delete(
            f"/api/v1/reports/{r_id}", headers=auth_headers_viewer
        )
        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_delete_unknown_report_404(self, client, auth_headers_admin):
        missing = uuid.uuid4()
        r = await client.delete(
            f"/api/v1/reports/{missing}", headers=auth_headers_admin
        )
        assert r.status_code == 404
