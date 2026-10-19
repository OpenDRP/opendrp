"""WI-18 · bulk inventory operations, import and export (AST-24).

An inventory is naturally created in batches — a domain list, a CIDR block, an
export from another tool — and there was no way to add one: assets arrived one
HTTP request at a time, and nothing could leave the platform as a file. These
tests pin the parts that make a batch operation safe rather than merely
convenient: a per-line report instead of a first-error abort, idempotency, hard
row/size/id limits, role separation for destructive operations, and the audit
summary that keeps one call from writing a hundred rows.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.core.audit import AuditLog
from app.schemas.asset import BULK_MAX_IDS, EXPORT_MAX_ROWS, IMPORT_MAX_ITEMS


async def _create(client, headers, asset_type: str, value: str) -> dict:
    response = await client.post(
        "/api/v1/assets",
        headers=headers,
        json={"asset_type": asset_type, "asset_value": value},
    )
    assert response.status_code == 201, response.text
    return response.json()


@pytest.mark.anyio
class TestAssetImport:
    async def test_a_batch_is_created_and_reported_line_by_line(
        self, client, auth_headers_analyst
    ):
        response = await client.post(
            "/api/v1/assets/import",
            headers=auth_headers_analyst,
            json={
                "items": [
                    {"asset_type": "domain", "asset_value": "one.example"},
                    {"asset_type": "domain", "asset_value": "two.example"},
                    {"asset_type": "ip_address", "asset_value": "10.1.2.3"},
                ]
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert (body["created"], body["duplicate"], body["invalid"]) == (3, 0, 0)
        assert [row["line"] for row in body["rows"]] == [1, 2, 3]
        assert {row["outcome"] for row in body["rows"]} == {"created"}

        # The batch is really there, through the ordinary list endpoint.
        listed = await client.get("/api/v1/assets?size=200", headers=auth_headers_analyst)
        values = {item["asset_value"] for item in listed.json()["items"]}
        assert {"one.example", "two.example", "10.1.2.3"} <= values

    async def test_one_bad_row_is_reported_without_discarding_the_others(
        self, client, auth_headers_analyst
    ):
        """A first-error abort would make a 200-line file a guessing game."""
        response = await client.post(
            "/api/v1/assets/import",
            headers=auth_headers_analyst,
            json={
                "items": [
                    {"asset_type": "domain", "asset_value": "keep-one.example"},
                    {"asset_type": "domain", "asset_value": "not a domain!!"},
                    {"asset_type": "domain", "asset_value": "keep-two.example"},
                    {"asset_type": "nonsense", "asset_value": "whatever"},
                ]
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert (body["created"], body["invalid"]) == (2, 2)
        by_line = {row["line"]: row for row in body["rows"]}
        assert by_line[1]["outcome"] == "created"
        assert by_line[2]["outcome"] == "invalid" and by_line[2]["detail"]
        assert by_line[3]["outcome"] == "created"
        assert by_line[4]["outcome"] == "invalid"

        listed = await client.get("/api/v1/assets?size=200", headers=auth_headers_analyst)
        values = {item["asset_value"] for item in listed.json()["items"]}
        assert {"keep-one.example", "keep-two.example"} <= values
        assert "not a domain!!" not in values

    async def test_an_import_is_idempotent(self, client, auth_headers_analyst):
        first = await client.post(
            "/api/v1/assets/import",
            headers=auth_headers_analyst,
            json={"items": [{"asset_type": "domain", "asset_value": "twice.example"}]},
        )
        assert first.json()["created"] == 1

        second = await client.post(
            "/api/v1/assets/import",
            headers=auth_headers_analyst,
            json={"items": [{"asset_type": "domain", "asset_value": "twice.example"}]},
        )
        assert second.status_code == 200, second.text
        assert second.json()["duplicate"] == 1
        assert second.json()["created"] == 0
        assert second.json()["rows"][0]["outcome"] == "duplicate"

    async def test_a_dry_run_reports_without_creating(
        self, client, auth_headers_analyst
    ):
        response = await client.post(
            "/api/v1/assets/import",
            headers=auth_headers_analyst,
            json={
                "items": [
                    {"asset_type": "domain", "asset_value": "dry.example"},
                    {"asset_type": "domain", "asset_value": "broken domain!"},
                ],
                "dry_run": True,
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["dry_run"] is True
        assert (body["created"], body["invalid"]) == (1, 1)

        listed = await client.get("/api/v1/assets?size=200", headers=auth_headers_analyst)
        assert "dry.example" not in {item["asset_value"] for item in listed.json()["items"]}

    async def test_the_row_limit_is_a_refusal(self, client, auth_headers_analyst):
        items = [
            {"asset_type": "domain", "asset_value": f"limit-{index}.example"}
            for index in range(IMPORT_MAX_ITEMS + 1)
        ]
        refused = await client.post(
            "/api/v1/assets/import",
            headers=auth_headers_analyst,
            json={"items": items},
        )
        assert refused.status_code == 422, refused.text

        allowed = await client.post(
            "/api/v1/assets/import",
            headers=auth_headers_analyst,
            json={"items": items[:1]},
        )
        assert allowed.status_code == 200, allowed.text

    async def test_viewers_cannot_import(self, client, auth_headers_viewer):
        refused = await client.post(
            "/api/v1/assets/import",
            headers=auth_headers_viewer,
            json={"items": [{"asset_type": "domain", "asset_value": "viewer.example"}]},
        )
        assert refused.status_code == 403, refused.text

    async def test_the_import_writes_one_summary_audit_row(
        self, client, db_session, auth_headers_analyst
    ):
        response = await client.post(
            "/api/v1/assets/import",
            headers=auth_headers_analyst,
            json={
                "items": [
                    {"asset_type": "domain", "asset_value": "audited-one.example"},
                    {"asset_type": "domain", "asset_value": "audited-one.example"},
                    {"asset_type": "domain", "asset_value": "bad value!"},
                ]
            },
        )
        assert response.status_code == 200, response.text

        rows = list(
            (
                await db_session.execute(select(AuditLog).where(AuditLog.action == "asset.import"))
            ).scalars()
        )
        assert len(rows) == 1
        assert rows[0].details["created"] == 1
        assert rows[0].details["duplicate"] == 1
        assert rows[0].details["invalid"] == 1
        assert [entry["line"] for entry in rows[0].details["report"]] == [1, 2, 3]


@pytest.mark.anyio
class TestAssetImportCsv:
    async def test_a_csv_body_is_parsed_line_by_line(self, client, auth_headers_analyst):
        csv_body = (
            "asset_type,asset_value,criticality\n"
            "domain,csv-one.example,high\n"
            "domain,csv-two.example,\n"
            "ip_address,10.9.9.9,critical\n"
            "domain,,high\n"
            "nonsense,whatever,\n"
        )
        response = await client.post(
            "/api/v1/assets/import/csv",
            headers={**auth_headers_analyst, "Content-Type": "text/csv"},
            content=csv_body,
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert (body["created"], body["invalid"]) == (3, 2)
        by_line = {row["line"]: row for row in body["rows"]}
        # Line 1 is the header, so the first data row is line 2.
        assert by_line[2]["outcome"] == "created"
        assert by_line[5]["outcome"] == "invalid"
        assert by_line[6]["outcome"] == "invalid"

        listed = await client.get(
            "/api/v1/assets?size=200&sort=asset_value&order=asc",
            headers=auth_headers_analyst,
        )
        items = {item["asset_value"]: item for item in listed.json()["items"]}
        assert items["csv-one.example"]["criticality"] == "high"
        assert items["csv-two.example"]["criticality"] == "medium"

    async def test_a_file_without_the_required_columns_is_refused(
        self, client, auth_headers_analyst
    ):
        refused = await client.post(
            "/api/v1/assets/import/csv",
            headers={**auth_headers_analyst, "Content-Type": "text/csv"},
            content="value,criticality\nplain.example,high\n",
        )
        assert refused.status_code == 400, refused.text
        assert "asset_type" in refused.json()["detail"]

    async def test_a_file_over_the_size_limit_is_refused(
        self, client, auth_headers_analyst
    ):
        from app.schemas.asset import IMPORT_MAX_BYTES

        filler = "x" * 1024
        lines = "\n".join(
            f"domain,{index}-{filler}.example,medium"
            for index in range(IMPORT_MAX_BYTES // len(filler) + 4)
        )
        refused = await client.post(
            "/api/v1/assets/import/csv",
            headers={**auth_headers_analyst, "Content-Type": "text/csv"},
            content=f"asset_type,asset_value,criticality\n{lines}\n",
        )
        assert refused.status_code == 400, refused.text
        assert "at most" in refused.json()["detail"]


@pytest.mark.anyio
class TestAssetExport:
    async def test_the_export_carries_the_current_filter(self, client, auth_headers_analyst):
        await _create(client, auth_headers_analyst, "domain", "export-a.example")
        await _create(client, auth_headers_analyst, "ip_address", "10.4.4.4")

        csv_response = await client.get(
            "/api/v1/assets/export?asset_type=domain", headers=auth_headers_analyst
        )
        assert csv_response.status_code == 200, csv_response.text
        assert csv_response.headers["content-type"].startswith("text/csv")
        assert "attachment" in csv_response.headers["content-disposition"]
        lines = csv_response.text.strip().splitlines()
        # The original five stay first — a positional consumer is not broken by
        # columns appended for the list's counters (AWI-12/AST-49).
        assert lines[0] == (
            "asset_type,asset_value,criticality,is_active,created_at,"
            "findings_total,findings_phishing,findings_breaches,findings_dns,"
            "findings_exposure,findings_other,last_seen"
        )
        assert any("export-a.example" in line for line in lines[1:])
        assert not any("10.4.4.4" in line for line in lines[1:])

        json_response = await client.get(
            "/api/v1/assets/export?format=json", headers=auth_headers_analyst
        )
        assert json_response.status_code == 200
        exported = {item["asset_value"] for item in json_response.json()["items"]}
        assert {"export-a.example", "10.4.4.4"} <= exported

    async def test_the_export_row_bound_is_a_refusal_not_a_truncation(
        self, client, db_session, auth_headers_admin
    ):
        """Past the bound the file is refused, so it is never quietly partial.

        A truncated inventory file looks exactly like a complete one to the tool
        that imports it next, which is why the answer is a refusal that names the
        filters to narrow rather than a shorter file.
        """
        from app.models.asset import Asset

        db_session.add_all(
            [
                Asset(
                    asset_type="domain",
                    asset_value=f"many-{index}.example",
                    normalized_value=f"many-{index}.example",
                    criticality="medium",
                    is_active=True,
                )
                for index in range(EXPORT_MAX_ROWS + 1)
            ]
        )
        await db_session.commit()

        refused = await client.get("/api/v1/assets/export", headers=auth_headers_admin)
        assert refused.status_code == 400, refused.text
        assert "at most" in refused.json()["detail"]

    async def test_viewers_may_export_and_unauthenticated_callers_may_not(
        self, client, auth_headers_viewer
    ):
        exported = await client.get("/api/v1/assets/export", headers=auth_headers_viewer)
        assert exported.status_code == 200, exported.text
        assert (await client.get("/api/v1/assets/export")).status_code == 401


@pytest.mark.anyio
class TestAssetBulk:
    async def test_deactivate_and_activate_apply_to_every_named_asset(
        self, client, auth_headers_analyst
    ):
        first = await _create(client, auth_headers_analyst, "domain", "bulk-a.example")
        second = await _create(client, auth_headers_analyst, "domain", "bulk-b.example")

        off = await client.post(
            "/api/v1/assets/bulk",
            headers=auth_headers_analyst,
            json={"operation": "deactivate", "ids": [first["id"], second["id"]]},
        )
        assert off.status_code == 200, off.text
        assert off.json()["applied"] == 2

        listed = await client.get(
            "/api/v1/assets?is_active=false&size=200", headers=auth_headers_analyst
        )
        assert {item["asset_value"] for item in listed.json()["items"]} >= {
            "bulk-a.example",
            "bulk-b.example",
        }

        on = await client.post(
            "/api/v1/assets/bulk",
            headers=auth_headers_analyst,
            json={"operation": "activate", "ids": [first["id"]]},
        )
        assert on.json()["applied"] == 1

    async def test_a_single_bad_id_does_not_hide_the_rest(
        self, client, auth_headers_analyst
    ):
        created = await _create(client, auth_headers_analyst, "domain", "bulk-c.example")
        unknown = str(uuid.uuid4())
        response = await client.post(
            "/api/v1/assets/bulk",
            headers=auth_headers_analyst,
            json={"operation": "deactivate", "ids": [created["id"], unknown]},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["requested"] == 2
        assert body["applied"] == 1
        assert body["missing"] == [unknown]

    async def test_criticality_requires_a_value_and_is_applied(
        self, client, auth_headers_analyst
    ):
        created = await _create(client, auth_headers_analyst, "domain", "bulk-d.example")
        missing = await client.post(
            "/api/v1/assets/bulk",
            headers=auth_headers_analyst,
            json={"operation": "criticality", "ids": [created["id"]]},
        )
        assert missing.status_code == 400, missing.text

        applied = await client.post(
            "/api/v1/assets/bulk",
            headers=auth_headers_analyst,
            json={
                "operation": "criticality",
                "ids": [created["id"]],
                "criticality": "critical",
            },
        )
        assert applied.status_code == 200, applied.text
        assert applied.json()["applied"] == 1
        fetched = await client.get(
            f"/api/v1/assets/{created['id']}", headers=auth_headers_analyst
        )
        assert fetched.json()["criticality"] == "critical"

    async def test_only_an_administrator_may_delete_a_batch(
        self, client, auth_headers_analyst, auth_headers_admin
    ):
        created = await _create(client, auth_headers_analyst, "domain", "bulk-e.example")
        refused = await client.post(
            "/api/v1/assets/bulk",
            headers=auth_headers_analyst,
            json={"operation": "delete", "ids": [created["id"]]},
        )
        assert refused.status_code == 403, refused.text

        deleted = await client.post(
            "/api/v1/assets/bulk",
            headers=auth_headers_admin,
            json={"operation": "delete", "ids": [created["id"]], "cascade_findings": True},
        )
        assert deleted.status_code == 200, deleted.text
        assert deleted.json()["applied"] == 1
        assert deleted.json()["findings_deleted"] == {
            "phishing_findings": 0,
            "breach_findings": 0,
            "generic_findings": 0,
        }
        gone = await client.get(
            f"/api/v1/assets/{created['id']}", headers=auth_headers_admin
        )
        assert gone.status_code == 404

    async def test_the_id_limit_is_a_refusal(self, client, auth_headers_analyst):
        refused = await client.post(
            "/api/v1/assets/bulk",
            headers=auth_headers_analyst,
            json={
                "operation": "deactivate",
                "ids": [str(uuid.uuid4()) for _ in range(BULK_MAX_IDS + 1)],
            },
        )
        assert refused.status_code == 422, refused.text

    async def test_the_batch_writes_one_summary_audit_row(
        self, client, db_session, auth_headers_analyst
    ):
        first = await _create(client, auth_headers_analyst, "domain", "bulk-f.example")
        second = await _create(client, auth_headers_analyst, "domain", "bulk-g.example")
        await client.post(
            "/api/v1/assets/bulk",
            headers=auth_headers_analyst,
            json={"operation": "deactivate", "ids": [first["id"], second["id"]]},
        )

        rows = list(
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "asset.bulk.deactivate")
                )
            ).scalars()
        )
        assert len(rows) == 1
        assert rows[0].details["operation"] == "deactivate"
        assert rows[0].details["requested"] == 2
        assert rows[0].details["applied"] == 2
        assert rows[0].details["missing_count"] == 0

    async def test_an_empty_id_list_is_refused(self, client, auth_headers_analyst):
        refused = await client.post(
            "/api/v1/assets/bulk",
            headers=auth_headers_analyst,
            json={"operation": "deactivate", "ids": []},
        )
        assert refused.status_code == 422, refused.text
