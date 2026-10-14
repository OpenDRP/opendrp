"""WI-16/WI-17 · the asset list contract: sort, subnet search, count, read audit.

The list endpoint answers three questions the client must not answer for itself:
in which order the rows come back, which rows match a subnet, and how many rows
matched (`AST-08`, `AST-09`). Each was previously either impossible or wrong:
there was no sort parameter at all, a substring match cannot find the assets
inside `10.0.0.0/24`, and `items` and `total` came from two separate statements
whose snapshots could disagree while an operator scrolled.

The read-audit policy is pinned here too (`AST-13`): a listing is one read, so it
is recorded once, on its first page.
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import select

from app.models.audit import AuditLog


@pytest.mark.anyio
class TestAssetListSortingAndSearch:
    async def _create(self, client, headers, asset_type: str, value: str) -> dict:
        response = await client.post(
            "/api/v1/assets",
            headers=headers,
            json={"asset_type": asset_type, "asset_value": value},
        )
        assert response.status_code == 201, response.text
        return response.json()

    async def test_the_sort_field_is_an_allowlist(self, client, auth_headers_admin):
        """Caller input reaches `ORDER BY`, so only declared fields may get there."""
        injected = await client.get(
            "/api/v1/assets?sort=created_at;drop%20table%20assets",
            headers=auth_headers_admin,
        )
        assert injected.status_code == 422, injected.text
        unknown = await client.get(
            "/api/v1/assets?sort=normalized_value", headers=auth_headers_admin
        )
        assert unknown.status_code == 422, unknown.text
        sideways = await client.get(
            "/api/v1/assets?order=sideways", headers=auth_headers_admin
        )
        assert sideways.status_code == 422, sideways.text

    async def test_the_schema_allowlist_and_the_service_column_map_agree(self):
        """A field the API accepts must have a column, and the reverse.

        The two sets live in different modules — the literal in
        ``schemas/asset.py``, the column map in ``asset_service.py`` — so the
        pairing is pinned here rather than by a ``KeyError`` in production.
        """
        from typing import get_args

        from app.schemas.asset import AssetSortField
        from app.services.asset_service import ASSET_SORT_COLUMNS

        assert set(get_args(AssetSortField)) == set(ASSET_SORT_COLUMNS)

    async def test_sorting_orders_the_list_in_both_directions(
        self, client, auth_headers_admin
    ):
        for value in ("c-sort.example", "a-sort.example", "b-sort.example"):
            await self._create(client, auth_headers_admin, "domain", value)

        ascending = await client.get(
            "/api/v1/assets?sort=asset_value&order=asc&size=200",
            headers=auth_headers_admin,
        )
        assert ascending.status_code == 200, ascending.text
        values = [item["asset_value"] for item in ascending.json()["items"]]
        assert values == sorted(values)
        assert values[0] == "a-sort.example"

        descending = await client.get(
            "/api/v1/assets?sort=asset_value&order=desc&size=200",
            headers=auth_headers_admin,
        )
        assert [
            item["asset_value"] for item in descending.json()["items"]
        ] == sorted(values, reverse=True)

    async def test_subnet_search_selects_the_addresses_inside_the_subnet(
        self, client, auth_headers_admin
    ):
        """A substring match cannot answer "which assets sit in 10.0.0.0/24"."""
        for value in ("10.0.0.1", "10.0.0.200", "10.0.1.5", "2001:db8::1"):
            await self._create(client, auth_headers_admin, "ip_address", value)

        body = (
            await client.get(
                "/api/v1/assets?search=10.0.0.0/24", headers=auth_headers_admin
            )
        ).json()
        assert sorted(item["asset_value"] for item in body["items"]) == [
            "10.0.0.1",
            "10.0.0.200",
        ]
        assert body["total"] == 2

        # IPv6 as well, with a prefix narrow enough to enumerate. A ``/64`` is
        # refused rather than enumerated: it holds 2^64 addresses (see the
        # refusal test below), which is the honest limit of an exact answer.
        network_v6 = (
            await client.get(
                "/api/v1/assets?search=2001:db8::/120", headers=auth_headers_admin
            )
        ).json()
        assert [item["asset_value"] for item in network_v6["items"]] == ["2001:db8::1"]

        # A single address with an explicit prefix is still a subnet of one.
        single = (
            await client.get(
                "/api/v1/assets?search=10.0.0.1/32", headers=auth_headers_admin
            )
        ).json()
        assert [item["asset_value"] for item in single["items"]] == ["10.0.0.1"]

    async def test_a_subnet_too_large_to_answer_exactly_is_refused(
        self, client, auth_headers_admin
    ):
        """A truncated inventory answer is worse than a refused one.

        ``10.0.0.0/8`` contains 16 million addresses: enumerating it would be a
        statement timeout, and answering with only the addresses that fitted
        would be a wrong answer that looks complete. ``2001:db8::/64`` is the
        same case for IPv6, and the one an operator is most likely to type —
        the refusal is what tells them to narrow the prefix instead of leaving
        them with a short list that looks complete.
        """
        for search in ("10.0.0.0/8", "2001:db8::/64"):
            refused = await client.get(
                f"/api/v1/assets?search={search}", headers=auth_headers_admin
            )
            assert refused.status_code == 400, refused.text
            assert "at most" in refused.json()["detail"]
            assert "Narrow the prefix" in refused.json()["detail"]

    async def test_a_term_that_only_looks_like_a_subnet_stays_a_substring(
        self, client, auth_headers_admin
    ):
        await self._create(client, auth_headers_admin, "domain", "prefix.example")

        # `/33` is not a valid prefix for IPv4, so the term is not a subnet and
        # must fall back to substring search instead of being refused.
        invalid_prefix = await client.get(
            "/api/v1/assets?search=10.0.0.0/33", headers=auth_headers_admin
        )
        assert invalid_prefix.status_code == 200, invalid_prefix.text
        assert invalid_prefix.json()["total"] == 0

        substring = await client.get(
            "/api/v1/assets?search=prefix", headers=auth_headers_admin
        )
        assert [item["asset_value"] for item in substring.json()["items"]] == [
            "prefix.example"
        ]

    async def test_the_page_and_the_total_come_from_one_snapshot(
        self, client, auth_headers_admin
    ):
        for index in range(5):
            await self._create(
                client, auth_headers_admin, "domain", f"snap-{index}.example"
            )

        first = (
            await client.get("/api/v1/assets?size=2&page=1", headers=auth_headers_admin)
        ).json()
        assert first["total"] == 5
        assert first["pages"] == 3
        assert len(first["items"]) == 2

        last = (
            await client.get("/api/v1/assets?size=2&page=3", headers=auth_headers_admin)
        ).json()
        assert last["total"] == 5
        assert len(last["items"]) == 1

    async def test_a_page_past_the_end_still_reports_the_total(
        self, client, auth_headers_admin
    ):
        for index in range(3):
            await self._create(
                client, auth_headers_admin, "domain", f"tail-{index}.example"
            )

        body = (
            await client.get("/api/v1/assets?size=10&page=9", headers=auth_headers_admin)
        ).json()
        assert body["items"] == []
        assert body["total"] == 3
        assert body["pages"] == 1


@pytest.mark.anyio
class TestAssetListAuditPolicy:
    async def test_only_the_first_page_of_a_listing_is_recorded(
        self, client, db_session, auth_headers_admin
    ):
        """Scrolling is the same read continued; a new page is not a new read.

        The list used to write a ``drp_audit_logs`` row — and extend the HMAC
        audit chain — on every request, so paging through one result set cost as
        much audit as one result set per page viewed.
        """
        for index in range(5):
            created = await client.post(
                "/api/v1/assets",
                headers=auth_headers_admin,
                json={
                    "asset_type": "domain",
                    "asset_value": f"audit-page-{index}.example",
                },
            )
            assert created.status_code == 201, created.text

        for page in (1, 2, 3):
            response = await client.get(
                f"/api/v1/assets?size=2&page={page}", headers=auth_headers_admin
            )
            assert response.status_code == 200, response.text

        # ``emit_background`` writes on its own task, so wait for pending work the
        # same way the other audit tests do before counting rows.
        pending = [
            task for task in asyncio.all_tasks() if task is not asyncio.current_task()
        ]
        await asyncio.gather(*pending, return_exceptions=True)
        await asyncio.sleep(0.05)

        rows = list(
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "asset.list")
                )
            ).scalars()
        )
        assert len(rows) == 1, f"scrolling wrote {len(rows)} audit rows instead of 1"
        assert rows[0].details["page"] == 1
        assert rows[0].details["sort"] == "created_at"
        assert rows[0].details["order"] == "desc"
