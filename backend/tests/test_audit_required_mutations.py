"""An asset change and the audit row that records it are one transaction.

AGENTS.md requires that adding and deleting assets is audited. Recording it on a
best-effort basis is not that: the mutation used to commit first and the audit row
was written afterwards, so a failing audit write left an inventory change nobody
could trace while the API answered 201/204 as if it had all worked.

The failure is injected at the chain's position allocation — the first thing the
write does and the one thing a caller cannot work around — and then the mutation is
looked for in the database. What the platform owes the operator is the other half:
the change must not be there.
"""

from __future__ import annotations

import pytest


async def _fail_the_audit_write(*args, **kwargs) -> None:
    raise RuntimeError("audit store unavailable")


@pytest.mark.anyio
class TestAssetMutationsRequireAudit:
    async def test_a_create_is_refused_and_rolled_back_when_the_audit_write_fails(
        self, client, auth_headers_admin, monkeypatch
    ):
        from app.core import audit as audit_module

        monkeypatch.setattr(audit_module, "prepare_entry", _fail_the_audit_write)
        refused = await client.post(
            "/api/v1/assets",
            headers=auth_headers_admin,
            json={"asset_type": "domain", "asset_value": "unaudited.example.com"},
        )
        monkeypatch.undo()

        assert refused.status_code == 503
        assert refused.json()["code"] == "audit_unavailable"

        listed = await client.get(
            "/api/v1/assets?search=unaudited.example.com", headers=auth_headers_admin
        )
        assert listed.json()["total"] == 0, "an asset was stored without its audit row"

    async def test_an_update_is_refused_when_the_audit_write_fails(
        self, client, auth_headers_admin, monkeypatch
    ):
        created = await client.post(
            "/api/v1/assets",
            headers=auth_headers_admin,
            json={"asset_type": "domain", "asset_value": "unaudited-update.example.com"},
        )
        asset_id = created.json()["id"]

        from app.core import audit as audit_module

        monkeypatch.setattr(audit_module, "prepare_entry", _fail_the_audit_write)
        refused = await client.patch(
            f"/api/v1/assets/{asset_id}",
            headers=auth_headers_admin,
            json={"criticality": "critical"},
        )
        monkeypatch.undo()

        assert refused.status_code == 503
        current = await client.get(f"/api/v1/assets/{asset_id}", headers=auth_headers_admin)
        assert current.json()["criticality"] == "medium"

    async def test_a_delete_is_refused_when_the_audit_write_fails(
        self, client, auth_headers_admin, monkeypatch
    ):
        created = await client.post(
            "/api/v1/assets",
            headers=auth_headers_admin,
            json={"asset_type": "domain", "asset_value": "unaudited-delete.example.com"},
        )
        asset_id = created.json()["id"]

        from app.core import audit as audit_module

        monkeypatch.setattr(audit_module, "prepare_entry", _fail_the_audit_write)
        refused = await client.delete(f"/api/v1/assets/{asset_id}", headers=auth_headers_admin)
        monkeypatch.undo()

        assert refused.status_code == 503
        still_there = await client.get(f"/api/v1/assets/{asset_id}", headers=auth_headers_admin)
        assert still_there.status_code == 200, "an asset was deleted without its audit row"

    async def test_a_successful_mutation_writes_exactly_one_audit_row(
        self, client, db_session, auth_headers_admin
    ):
        """One transaction means one row, and it is the row that describes it."""
        from sqlalchemy import select

        from app.models.audit import AuditLog

        created = await client.post(
            "/api/v1/assets",
            headers=auth_headers_admin,
            json={"asset_type": "domain", "asset_value": "audited-once.example.com"},
        )
        asset_id = created.json()["id"]
        rows = list(
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "asset.create")
                )
            ).scalars()
        )
        mine = [row for row in rows if str(row.details.get("asset_id")) == asset_id]
        assert len(mine) == 1
        # The row carries a chain position and a signature: it went through the
        # same writer as every other event, not around it.
        assert mine[0].entry_hash
        assert mine[0].prev_hash
        assert mine[0].seq > 0
