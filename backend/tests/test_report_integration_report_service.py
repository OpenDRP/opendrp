import uuid

import pytest

from app.models.asset import Asset, AssetType
from app.models.breach import Breach
from app.models.phishing import PhishingDomain
from app.services.report_service import ReportService


class TestReportServiceUnit:
    @pytest.mark.asyncio
    async def test_gather_report_data_empty_db_returns_kpi_zeroes_assets_lists(self, db_session):
        from sqlalchemy import text
        from tests.conftest import safe_sql_identifier

        for n in ("drp_breaches", "drp_phishing_domains",
                   "reports", "assets"):
            await db_session.execute(text(f"DELETE FROM {safe_sql_identifier(n)}"))
        await db_session.commit()
        svc = ReportService(db_session)
        data = await svc.gather_report_data()
        assert isinstance(data, dict)
        for k in ("generated_at_iso", "kpi", "assets", "assets_by_criticality",
                   "phishing", "phishing_by_source", "breaches"):
            assert k in data
        assert data["kpi"]["total_assets"] == 0
        assert data["kpi"]["total_phishing"] == 0
        assert data["kpi"]["total_breaches"] == 0
        assert isinstance(data["kpi"]["active_threats_7d"], int)
        assert data["assets"] == []
        assert data["assets_by_criticality"] == {}
        assert data["truncation"]["truncated"] is False

    @pytest.mark.asyncio
    async def test_gather_report_data_populated_matches_count(self, db_session):
        from datetime import datetime, timezone, timedelta
        from sqlalchemy import text
        from tests.conftest import safe_sql_identifier

        for n in ("drp_breaches", "drp_phishing_domains",
                   "reports", "assets"):
            await db_session.execute(text(f"DELETE FROM {safe_sql_identifier(n)}"))
        await db_session.commit()

        now = datetime.now(timezone.utc)
        suffix = uuid.uuid4().hex[:10]
        a = Asset(
            id=uuid.uuid4(),
            asset_type=AssetType.domain,
            asset_value=f"populated-{suffix}.com",
            criticality="high",
            is_active=True,
        )
        b = Asset(
            id=uuid.uuid4(),
            asset_type=AssetType.email_account,
            asset_value=f"ops@{suffix}.com",
            criticality="medium",
            is_active=True,
        )
        db_session.add_all([a, b])
        phishing = PhishingDomain(
            id=uuid.uuid4(),
            phishing_domain=f"evil-{suffix}.com",
            matched_asset=a.asset_value,
            detection_source="dnstwist",
            created_at=now - timedelta(days=2),
        )
        db_session.add(phishing)
        hibp = Breach(
            id=uuid.uuid4(),
            breach_name=f"Breach-{suffix}",
            title="Old",
            domain="zombo.com",
            breach_date=now.date(),
            matched_email=b.asset_value,
            pwn_count=99,
        )
        db_session.add(hibp)
        await db_session.commit()

        data = await ReportService(db_session).gather_report_data()
        assert data["kpi"]["total_assets"] == 2
        assert data["kpi"]["total_phishing"] == 1
        assert data["kpi"]["total_breaches"] == 1
        assert data["assets_by_criticality"].get("high") == 1
        assert data["assets_by_criticality"].get("medium") == 1
        assert data["phishing_by_source"]["dnstwist"] == 1
        assert data["truncation"]["truncated"] is False


class TestGenerateAndSave:
    @pytest.mark.asyncio
    async def test_timeout_cleans_a_late_render_without_racing_the_writer(
        self, db_session, tmp_path, monkeypatch
    ):
        import asyncio
        from app.core import artifact_path as artifact_module
        from app.core import config as config_module

        monkeypatch.setattr(artifact_module.settings, "REPORTS_STORE_DIR", str(tmp_path))
        monkeypatch.setattr(config_module.settings, "REPORT_GENERATION_TIMEOUT_SECONDS", 0.01)
        service = ReportService(db_session)

        async def fake_data():
            return {"truncation": {"truncated": False}}

        def slow_pdf(path, data, email):
            import time

            time.sleep(0.08)
            with open(path, "wb") as output:
                output.write(b"%PDF-1.7 late render")

        service.gather_report_data = fake_data
        service.generate_pdf_sync = slow_pdf
        with pytest.raises(TimeoutError, match="configured time limit"):
            await service.generate_and_save(report_id=uuid.uuid4(), user_email="qa@example.com")

        # The executor thread is allowed to finish, but its late temporary file
        # is removed by the completion callback and no final artifact is
        # published after the timeout.
        await asyncio.sleep(0.12)
        assert list(tmp_path.glob("*.pdf")) == []
        assert list(tmp_path.glob(".*.pdf.tmp")) == []

    @pytest.mark.asyncio
    async def test_each_generation_attempt_gets_an_isolated_temporary_name(
        self, db_session, tmp_path, monkeypatch
    ):
        from app.core import artifact_path as artifact_module

        monkeypatch.setattr(artifact_module.settings, "REPORTS_STORE_DIR", str(tmp_path))
        service = ReportService(db_session)
        seen: list[str] = []

        async def fake_data():
            return {"truncation": {"truncated": False}}

        def fake_pdf(path, data, email):
            seen.append(path)
            with open(path, "wb") as output:
                output.write(b"%PDF-1.7")

        service.gather_report_data = fake_data
        service.generate_pdf_sync = fake_pdf
        report_id = uuid.uuid4()
        await service.generate_and_save(report_id=report_id, user_email="qa@example.com")
        await service.generate_and_save(report_id=report_id, user_email="qa@example.com")
        assert len(seen) == 2
        assert seen[0] != seen[1]
        assert list(tmp_path.glob("*.pdf")) == [tmp_path / f"{report_id}.pdf"]

    @pytest.mark.asyncio
    async def test_generate_and_save_publishes_atomically_with_metadata(self, db_session, tmp_path, monkeypatch):
        from app.core import artifact_path as artifact_module

        monkeypatch.setattr(artifact_module.settings, "REPORTS_STORE_DIR", str(tmp_path))
        service = ReportService(db_session)
        async def fake_data():
            return {"truncation": {"truncated": True, "limit": 10}}

        def fake_pdf(path, data, email):
            with open(path, "wb") as output:
                output.write(b"%PDF-1.7")

        service.gather_report_data = fake_data
        service.generate_pdf_sync = fake_pdf
        name, metadata = await service.generate_and_save(
            report_id=uuid.uuid4(), user_email="qa@example.com"
        )
        assert name.endswith(".pdf")
        assert metadata == {"truncated": True, "limit": 10}
        assert list(tmp_path.glob("*.pdf"))
        assert not list(tmp_path.glob(".*.tmp"))


class TestGeneratePdfSync:
    @pytest.mark.asyncio
    async def test_generate_pdf_minimal_data_writes_valid_pdf_file(self, tmp_path, db_session):
        from sqlalchemy import text
        from tests.conftest import safe_sql_identifier

        for n in ("drp_breaches", "drp_phishing_domains",
                   "reports", "assets"):
            await db_session.execute(text(f"DELETE FROM {safe_sql_identifier(n)}"))
        await db_session.commit()
        data = await ReportService(db_session).gather_report_data()
        out_path = tmp_path / "report_test_minimal.pdf"
        ReportService.generate_pdf_sync(str(out_path), data, "qa@example.com")
        assert out_path.exists()
        size = out_path.stat().st_size
        assert size > 5000
        raw = out_path.read_bytes()
        assert raw.startswith(b"%PDF-1.")

    @pytest.mark.asyncio
    async def test_generate_pdf_populated_includes_opendrp_content(self, tmp_path, db_session):
        from datetime import datetime, timezone, timedelta
        from sqlalchemy import text
        from tests.conftest import safe_sql_identifier

        for n in ("drp_breaches", "drp_phishing_domains",
                   "reports", "assets"):
            await db_session.execute(text(f"DELETE FROM {safe_sql_identifier(n)}"))
        await db_session.commit()
        now = datetime.now(timezone.utc)
        suffix = uuid.uuid4().hex[:10]
        a = Asset(
            id=uuid.uuid4(),
            asset_type=AssetType.domain,
            asset_value=f"pdf-test-{suffix}.com",
            criticality="critical",
            is_active=True,
        )
        db_session.add(a)
        for i in range(3):
            db_session.add(PhishingDomain(
                id=uuid.uuid4(),
                phishing_domain=f"pdf-evil-{suffix}-{i}.com",
                matched_asset=a.asset_value,
                detection_source=("shodan" if i == 0 else "dnstwist"),
                created_at=now - timedelta(days=i),
            ))
        await db_session.commit()
        data = await ReportService(db_session).gather_report_data()
        out_path = tmp_path / "report_populated.pdf"
        ReportService.generate_pdf_sync(str(out_path), data, "tester@example.com")
        size = out_path.stat().st_size
        assert size > 7000
        raw = out_path.read_bytes()
        assert raw.startswith(b"%PDF-1.")
        assert raw.rstrip().endswith(b"%%EOF")
        page_count_approx = raw.count(b"/Type /Page\n") + raw.count(b"/Type /Page\r")
        assert page_count_approx >= 1
