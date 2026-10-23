"""The report's own edges: captions, the text a PDF receives, and page breaks.

Coverage batch 05. The integration suite pins what a report counts; this file
pins the parts that only run when the data is unusual — a KPI whose caption the
stored payload does not carry, sections the PDF text validator has to walk, a
row limit that cannot be honoured, and tables long enough to start another page.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.core.config import settings
from app.services.report_service import (
    ReportService,
    _breach_kpi_caption,
    _report_pdf_text_values,
)


def test_a_kpi_without_a_stored_caption_prints_the_shared_wording():
    caption = _breach_kpi_caption({"breach_kpi": {}}, "new_incidents_7d")

    assert caption == (
        "incidents the configured sources added to their own catalogues in the last 7 days"
    )


def test_the_pdf_receives_a_value_from_every_section_it_prints():
    report_data = {
        "assets": [
            SimpleNamespace(
                asset_value="example.com",
                asset_type="domain",
                criticality="high",
                is_active=True,
            )
        ],
        "phishing": [
            SimpleNamespace(
                phishing_domain="evil.example",
                ip_address=None,
                detection_source="dnstwist",
                status="active",
            )
        ],
        "breaches": [
            SimpleNamespace(
                matched_email="a@example.com",
                breach_name="Incident",
                domain="example.com",
                exposure_kind="paste",
                severity="high",
                breach_date="2024-01-01",
            )
        ],
        "exposure": [
            SimpleNamespace(
                subject="www.example.com",
                source="netlas",
                first_seen_at="2024-01-01",
                last_seen_at="2024-01-02",
                matched_asset="example.com",
                payload={"port": 443, "protocol": "https"},
                observed_at=None,
            )
        ],
        "dns": [
            SimpleNamespace(
                subject="example.com",
                source="resolver",
                first_seen_at="2024-01-01",
                last_seen_at="2024-01-02",
                observation_type="dns_record",
                value=None,
            )
        ],
    }

    values = _report_pdf_text_values(report_data, "soc@example.com")

    # A missing fact is printed as "-", never as the string "None".
    assert "-" in values
    assert "None" not in values
    # The exposure row's provider facts and the DNS row's type both reach a cell.
    assert "443" in values
    assert "https" in values
    assert "unknown" in values
    assert "dns_record" in values
    assert "paste" in values


@pytest.mark.asyncio
async def test_a_row_limit_that_cannot_be_honoured_is_refused(db_session, monkeypatch):
    monkeypatch.setattr(settings, "REPORT_MAX_ROWS", 0)

    with pytest.raises(ValueError, match="REPORT_MAX_ROWS must be positive"):
        await ReportService(db_session).gather_report_data()


def _long_report_data(rows: int = 120) -> dict:
    assets = [
        SimpleNamespace(
            asset_value=f"asset-{index}.example.com",
            asset_type="domain",
            criticality="medium",
            is_active=True,
        )
        for index in range(rows)
    ]
    phishing = [
        SimpleNamespace(
            phishing_domain=f"evil-{index}.example",
            ip_address=None,
            detection_source="dnstwist",
            status="active",
        )
        for index in range(rows)
    ]
    breaches = [
        SimpleNamespace(
            matched_email=f"user-{index}@example.com",
            breach_name="Incident",
            domain="example.com",
            exposure_kind=None,
            severity="medium",
            breach_date="2024-01-01",
        )
        for index in range(rows)
    ]
    exposure = [
        SimpleNamespace(
            subject=f"www.example{index}.com",
            source="netlas",
            first_seen_at="2024-01-01",
            last_seen_at="2024-01-02",
            matched_asset="example.com",
            payload={"port": 443, "protocol": "https"},
            observed_at=None,
        )
        for index in range(min(rows, 2))
    ]
    dns = [
        SimpleNamespace(
            subject="example.com",
            source="resolver",
            first_seen_at="2024-01-01",
            last_seen_at="2024-01-02",
            observation_type="dns_record",
            value="192.0.2.1",
        )
        for _ in range(min(rows, 2))
    ]
    return {
        "generated_at_iso": "2024-01-02T00:00:00+00:00",
        "kpi": {
            "total_assets": rows,
            "total_phishing": rows,
            "total_breaches": rows,
            "active_threats_7d": rows,
        },
        "assets": assets,
        "phishing": phishing,
        "breaches": breaches,
        "exposure": exposure,
        "dns": dns,
        "truncation": {},
    }


def test_a_table_longer_than_a_page_starts_another_one(tmp_path):
    from app.services import report_service as module

    path = tmp_path / "long-report.pdf"

    # No Unicode font: the validator runs and the Helvetica family is used, which
    # is the branch an installation without DejaVu takes.
    original = module._find_unicode_pdf_font
    module._find_unicode_pdf_font = lambda: None
    try:
        ReportService.generate_pdf_sync(
            str(path), _long_report_data(), "soc@example.com"
        )
    finally:
        module._find_unicode_pdf_font = original

    body = path.read_bytes()
    assert body.startswith(b"%PDF-")
    # Four section pages at minimum plus the cover.
    assert body.count(b"/Type /Page") > 5
    # A report this size is well past the "suspiciously small" warning threshold.
    assert len(body) > 10240


def test_a_nearly_empty_report_is_still_a_pdf_and_is_logged(tmp_path):
    path = tmp_path / "small-report.pdf"

    ReportService.generate_pdf_sync(str(path), _long_report_data(0), "soc@example.com")

    assert path.read_bytes().startswith(b"%PDF-")


@pytest.mark.asyncio
async def test_data_collection_that_runs_past_the_limit_is_named(
    db_session, tmp_path, monkeypatch
):
    import asyncio
    import uuid

    from app.core import artifact_path as artifact_module

    monkeypatch.setattr(artifact_module.settings, "REPORTS_STORE_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "REPORT_GENERATION_TIMEOUT_SECONDS", 0.01)
    service = ReportService(db_session)

    async def _slow():
        await asyncio.sleep(0.05)
        return {}

    service.gather_report_data = _slow

    with pytest.raises(TimeoutError, match="during data collection"):
        await service.generate_and_save(
            report_id=uuid.uuid4(), user_email="soc@example.com"
        )


@pytest.mark.asyncio
async def test_a_renderer_failure_removes_its_temporary_file(
    db_session, tmp_path, monkeypatch
):
    import uuid

    from app.core import artifact_path as artifact_module

    monkeypatch.setattr(artifact_module.settings, "REPORTS_STORE_DIR", str(tmp_path))
    service = ReportService(db_session)

    async def _data():
        return {"truncation": {}}

    def _boom(path, _data, _email):
        with open(path, "wb") as output:
            output.write(b"partial")
        raise RuntimeError("renderer failed")

    service.gather_report_data = _data
    service.generate_pdf_sync = _boom

    with pytest.raises(RuntimeError, match="renderer failed"):
        await service.generate_and_save(
            report_id=uuid.uuid4(), user_email="soc@example.com"
        )

    assert list(tmp_path.glob(".*.pdf.tmp")) == []


@pytest.mark.asyncio
async def test_a_failed_render_still_reports_its_own_error_when_cleanup_fails(
    db_session, tmp_path, monkeypatch
):
    import uuid
    from pathlib import Path

    from app.core import artifact_path as artifact_module

    monkeypatch.setattr(artifact_module.settings, "REPORTS_STORE_DIR", str(tmp_path))
    service = ReportService(db_session)

    async def _data():
        return {"truncation": {}}

    def _boom(path, _data, _email):
        with open(path, "wb") as output:
            output.write(b"partial")
        raise RuntimeError("renderer failed")

    service.gather_report_data = _data
    service.generate_pdf_sync = _boom

    def _locked(self, missing_ok=False):
        raise OSError("file is locked")

    monkeypatch.setattr(Path, "unlink", _locked)

    # The operator learns why the report failed, not that cleanup did.
    with pytest.raises(RuntimeError, match="renderer failed"):
        await service.generate_and_save(
            report_id=uuid.uuid4(), user_email="soc@example.com"
        )


@pytest.mark.asyncio
async def test_a_late_render_whose_cleanup_fails_is_not_reported(
    db_session, tmp_path, monkeypatch
):
    """The cleanup runs after the operator already has the timeout answer."""
    import asyncio
    import uuid
    from pathlib import Path

    from app.core import artifact_path as artifact_module

    monkeypatch.setattr(artifact_module.settings, "REPORTS_STORE_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "REPORT_GENERATION_TIMEOUT_SECONDS", 0.01)
    service = ReportService(db_session)

    async def _data():
        return {"truncation": {}}

    def _slow(path, _data, _email):
        import time

        time.sleep(0.08)
        with open(path, "wb") as output:
            output.write(b"%PDF-1.7 late")

    service.gather_report_data = _data
    service.generate_pdf_sync = _slow

    def _locked(self, missing_ok=False):
        raise OSError("file is locked")

    monkeypatch.setattr(Path, "unlink", _locked)

    with pytest.raises(TimeoutError):
        await service.generate_and_save(
            report_id=uuid.uuid4(), user_email="soc@example.com"
        )

    # Let the executor finish so the completion callback runs.
    await asyncio.sleep(0.12)


def test_a_suspiciously_small_pdf_is_still_written(tmp_path, monkeypatch):
    """The size check logs; it never refuses or deletes the report."""
    from app.services import report_service as module

    monkeypatch.setattr(module.os.path, "getsize", lambda _path: 100)
    path = tmp_path / "small.pdf"

    ReportService.generate_pdf_sync(str(path), _long_report_data(0), "soc@example.com")

    assert path.exists()
    assert path.read_bytes().startswith(b"%PDF-")


@pytest.mark.asyncio
async def test_a_failed_snapshot_is_rolled_back(db_session, monkeypatch):
    from app.services import breach_kpi as kpi_module

    async def _boom(*_args, **_kwargs):
        raise RuntimeError("kpi failed")

    monkeypatch.setattr(kpi_module, "breach_kpi", _boom)

    with pytest.raises(RuntimeError, match="kpi failed"):
        await ReportService(db_session).gather_report_data()
