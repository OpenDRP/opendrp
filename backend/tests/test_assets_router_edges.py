"""The inventory's edges: a broken file, a repeated row, a row that is not there.

``test_asset_bulk_operations`` pins import, export and bulk on well-formed input.
This file pins what the router answers when the input is not: a file that is not
UTF-8, a line the validator refuses, a filter whose export is too large to build,
a selection larger than the schema allows, and the 404s that keep a missing row
from reading as an empty one.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.api.v1.routers.assets import _error_detail, _latest_seen, _related_row
from app.core.exceptions import BadRequestException
from app.models.asset import Asset


class TestLatestSeen:
    def test_an_unparseable_observation_is_skipped_rather_than_becoming_the_answer(
        self,
    ):
        """The modules publish dates and scan timestamps; one bad value is not newest."""
        summary = SimpleNamespace(
            last_seen={
                "phishing": "not a timestamp",
                "breaches": "2026-01-02T03:04:05Z",
                "dns": "",
            }
        )

        assert _latest_seen(summary) == "2026-01-02T03:04:05Z"

    def test_a_naive_date_is_read_as_the_utc_day_it_names(self):
        """A disclosure date carries no offset; comparing it must not raise."""
        summary = SimpleNamespace(last_seen={"breaches": "2026-02-03", "dns": "2026-02-01T00:00:00Z"})

        assert _latest_seen(summary) == "2026-02-03"

    def test_no_observations_answers_with_nothing(self):
        assert _latest_seen(SimpleNamespace(last_seen=None)) == ""
        assert _latest_seen(SimpleNamespace(last_seen={})) == ""


class TestRelatedRows:
    def test_a_dns_row_reports_the_observation_and_its_source(self):
        row = SimpleNamespace(
            id=uuid.uuid4(),
            observation_type="certificate",
            subject="prod.egov.kz",
            value="egov.kz",
            source="ctlogs",
            status="historical",
            last_seen_at=datetime(2026, 3, 4, tzinfo=timezone.utc),
        )

        shaped = _related_row("dns", row)

        assert shaped["module"] == "dns"
        assert shaped["title"] == "certificate prod.egov.kz"
        assert shaped["matched_asset"] == "egov.kz"
        assert shaped["source"] == "ctlogs"

    def test_a_generic_finding_reports_the_connector_and_the_row_s_own_title(self):
        row = SimpleNamespace(
            id=uuid.uuid4(),
            title="Exposed .env on the marketing host",
            matched_asset="marketing.example",
            connector_name="exposure_endpoints",
            status="open",
            created_at=datetime(2026, 3, 6, tzinfo=timezone.utc),
        )

        shaped = _related_row("findings", row)

        assert shaped["module"] == "findings"
        assert shaped["title"] == "Exposed .env on the marketing host"
        assert shaped["source"] == "exposure_endpoints"

    def test_an_exposure_row_falls_back_to_last_seen_when_it_has_no_observed_at(self):
        row = SimpleNamespace(
            id=uuid.uuid4(),
            subject="10.0.0.5:8443",
            matched_asset="10.0.0.0/24",
            source="netlas",
            status="open",
            observed_at=None,
            last_seen_at=datetime(2026, 3, 5, tzinfo=timezone.utc),
        )

        shaped = _related_row("exposure", row)

        assert shaped["module"] == "exposure"
        assert shaped["observed_at"] == datetime(2026, 3, 5, tzinfo=timezone.utc)


class TestCsvReading:
    @pytest.mark.asyncio
    async def test_a_file_that_is_not_utf8_is_refused(
        self, client, auth_headers_analyst
    ):
        """The report names the encoding, because the operator has to re-save it."""
        response = await client.post(
            "/api/v1/assets/import/csv",
            headers={**auth_headers_analyst, "Content-Type": "text/csv"},
            content=b"asset_type,asset_value\ndomain,\xff\xfe.example\n",
        )

        assert response.status_code == 400
        assert "UTF-8" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_a_line_the_validator_refuses_is_reported_with_its_line_number(
        self, client, db_session, auth_headers_analyst
    ):
        """One bad row costs that row, not the file — and the report says which."""
        csv_body = (
            "asset_type,asset_value\n"
            "domain,good.example\n"
            "not-a-type,bad.example\n"
        )

        response = await client.post(
            "/api/v1/assets/import/csv",
            headers={**auth_headers_analyst, "Content-Type": "text/csv"},
            content=csv_body.encode("utf-8"),
        )

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["created"] == 1
        assert body["invalid"] == 1
        assert [(row["line"], row["outcome"]) for row in body["rows"]] == [
            (2, "created"),
            (3, "invalid"),
        ]
        assert body["rows"][1]["detail"]
        assert body["rows"][1]["asset_type"] == "not-a-type"

    @pytest.mark.asyncio
    async def test_a_row_the_file_reader_cannot_build_is_reported_as_invalid(
        self, client, db_session, auth_headers_analyst
    ):
        """A bad criticality is refused where the row is read, with the file's line."""
        csv_body = (
            "asset_type,asset_value,criticality\n"
            "domain,kept.example,high\n"
            "domain,rejected.example,urgent\n"
        )

        response = await client.post(
            "/api/v1/assets/import/csv",
            headers={**auth_headers_analyst, "Content-Type": "text/csv"},
            content=csv_body.encode("utf-8"),
        )

        assert response.status_code == 200, response.text
        body = response.json()
        assert (body["created"], body["invalid"]) == (1, 1)
        rejected = next(row for row in body["rows"] if row["line"] == 3)
        assert rejected["outcome"] == "invalid"
        assert rejected["detail"]
        assert rejected["asset_value"] == "rejected.example"

    @pytest.mark.asyncio
    async def test_a_file_with_more_rows_than_the_bound_is_refused_before_import(
        self, client, db_session, auth_headers_analyst
    ):
        """The cap is on the file, so a second import part is the answer."""
        from app.schemas.asset import IMPORT_MAX_ITEMS

        lines = ["asset_type,asset_value"] + [
            f"domain,host-{index}.example" for index in range(IMPORT_MAX_ITEMS + 1)
        ]

        response = await client.post(
            "/api/v1/assets/import/csv",
            headers={**auth_headers_analyst, "Content-Type": "text/csv"},
            content="\n".join(lines).encode("utf-8"),
        )

        assert response.status_code == 400
        assert str(IMPORT_MAX_ITEMS) in response.json()["detail"]
        assert (await db_session.execute(select(Asset))).scalars().all() == []


class TestImportRaceKeepsEarlierRows:
    @pytest.mark.asyncio
    async def test_a_lost_insert_race_does_not_undo_the_rows_before_it(
        self, client, db_session, auth_headers_analyst, monkeypatch
    ):
        """A row that loses an insert race rolls back itself, not the rows before it.

        The import documents one savepoint per row: a failing row rolls back only itself.
        When another writer takes a value between the duplicate check and the insert, the
        insert fails on the unique index, and the create path rolled back the whole
        session, which discarded the rows the same import had already written while the
        report still counted them as created.
        """
        from app.models.asset import Asset, AssetType
        from app.services.asset_service import AssetService

        db_session.add(
            Asset(asset_type=AssetType.domain, asset_value="taken.example", normalized_value="taken.example")
        )
        await db_session.commit()

        async def check_misses(self, asset_type, normalized_value):
            return False

        monkeypatch.setattr(AssetService, "asset_exists", check_misses)
        response = await client.post(
            "/api/v1/assets/import/csv",
            headers={**auth_headers_analyst, "Content-Type": "text/csv"},
            content=b"asset_type,asset_value\ndomain,first.example\ndomain,taken.example\n",
        )

        assert response.status_code == 200, response.text
        assert response.json()["created"] == 1, response.json()
        stored = {
            row.normalized_value
            for row in (await db_session.execute(select(Asset))).scalars().all()
        }
        assert "first.example" in stored


class TestExportCannotCarryAFormula:
    @pytest.mark.asyncio
    async def test_a_keyword_that_starts_like_a_formula_is_neutralised_in_the_csv(
        self, client, db_session, auth_headers_analyst
    ):
        """A spreadsheet reads a cell that starts with ``=`` as a formula.

        A keyword may begin with ``=``, ``+``, ``-`` or ``@``, and the export wrote it as
        the cell's text, so a file exported and opened in a spreadsheet could evaluate it
        for whoever opens it. The cell is prefixed so it is read as text.
        """
        from app.models.asset import Asset, AssetType

        db_session.add(
            Asset(
                asset_type=AssetType.keyword_title,
                asset_value="=SUM(1,1)",
                normalized_value="=SUM(1,1)",
                is_active=True,
            )
        )
        await db_session.commit()

        response = await client.get("/api/v1/assets/export?format=csv", headers=auth_headers_analyst)

        assert response.status_code == 200, response.text
        assert 'keyword_title,"=SUM(1,1)",' not in response.text
        assert 'keyword_title,"\'=SUM(1,1)",' in response.text


class TestDryRun:
    @pytest.mark.asyncio
    async def test_a_dry_run_reports_a_value_the_file_repeats_as_a_duplicate(
        self, client, db_session, auth_headers_analyst
    ):
        """What happens once the first line is written is what the preview predicts."""
        db_session.add(
            Asset(
                asset_type="domain",
                asset_value="already.example",
                # What ``create_asset`` writes for the duplicate lookup to read.
                normalized_value="already.example",
                criticality="medium",
                is_active=True,
            )
        )
        await db_session.commit()

        response = await client.post(
            "/api/v1/assets/import",
            headers=auth_headers_analyst,
            json={
                "dry_run": True,
                "items": [
                    {"asset_type": "domain", "asset_value": "already.example"},
                    {"asset_type": "domain", "asset_value": "fresh.example"},
                    {"asset_type": "domain", "asset_value": "fresh.example"},
                ],
            },
        )

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["dry_run"] is True
        assert (body["created"], body["duplicate"], body["invalid"]) == (1, 2, 0)
        assert [row["outcome"] for row in body["rows"]] == [
            "duplicate",
            "created",
            "duplicate",
        ]
        # Nothing was written: a preview that leaves rows behind is worse than none.
        values = {
            row.asset_value
            for row in (await db_session.execute(select(Asset))).scalars()
        }
        assert values == {"already.example"}


class TestErrorDetail:
    def test_a_service_refusal_keeps_its_own_message(self):
        """A line is reported with the reason the service gave, not a generic one."""
        assert _error_detail(BadRequestException("value collides with a reserved name")) == (
            "value collides with a reserved name"
        )


class TestBulkSelection:
    @pytest.mark.asyncio
    async def test_a_selection_beyond_the_bound_is_refused_by_the_schema(
        self, client, auth_headers_analyst
    ):
        """The wire schema decides the batch size; the route never sees the list."""
        from app.schemas.asset import BULK_MAX_IDS

        response = await client.post(
            "/api/v1/assets/bulk",
            headers=auth_headers_analyst,
            json={
                "operation": "deactivate",
                "ids": [str(uuid.uuid4()) for _ in range(BULK_MAX_IDS + 1)],
            },
        )

        assert response.status_code == 422


class TestMissingRows:
    @pytest.mark.asyncio
    async def test_patching_or_deleting_an_absent_asset_is_a_404(
        self, client, db_session, auth_headers_admin
    ):
        missing = uuid.uuid4()

        patched = await client.patch(
            f"/api/v1/assets/{missing}",
            headers=auth_headers_admin,
            json={"criticality": "high"},
        )
        deleted = await client.delete(f"/api/v1/assets/{missing}", headers=auth_headers_admin)
        read = await client.get(f"/api/v1/assets/{missing}", headers=auth_headers_admin)
        findings = await client.get(
            f"/api/v1/assets/{missing}/findings", headers=auth_headers_admin
        )

        assert [patched.status_code, deleted.status_code, read.status_code, findings.status_code] == [
            404,
            404,
            404,
            404,
        ]
        assert patched.json()["detail"] == "Asset not found"
