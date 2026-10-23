"""Characterization tests: audit router filters and RBAC matrix (Step 6).

Pins the CURRENT behavior of ``app/api/v1/routers/audit.py`` before the
typed filter-builder refactor:

* ``GET /audit/actions`` — grouped catalog, total count, labels map;
* ``GET /audit/logs`` — action filter (case-insensitive, unknown values are
  matched literally, never rejected), user_id / user_email subquery filters,
  from/to date windows with naive-datetime UTC coercion, full-text search
  over action/ip/details-JSON, pagination and the ``audit.log.view`` event;
* admin-only access for both endpoints (viewer/analyst -> 403).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.core.audit import AUDIT_ALLOWED_ACTIONS, AuditLogger
from app.models.audit import AuditLog
from app.models.user import User

ENDPOINT = "/api/v1/audit/logs"


async def _emit(db, *, action: str, ip: str, user_id=None, details=None):
    await AuditLogger.emit(
        db, action=action, ip_address=ip, user_id=user_id, details=details or {}
    )


@pytest.fixture
async def audit_rows(db_session, test_admin, test_viewer):
    """Three distinguishable audit rows plus one real-user link."""
    user = (
        await db_session.execute(select(User).where(User.id == test_viewer.id))
    ).scalar_one()

    await _emit(
        db_session,
        action="asset.create",
        ip="203.0.113.10",
        user_id=user.id,
        details={"asset": "alpha.example.com"},
    )
    await _emit(
        db_session,
        action="asset.delete",
        ip="203.0.113.11",
        user_id=None,
        details={"asset": "beta.example.com"},
    )
    await _emit(
        db_session,
        action="report.download",
        ip="198.51.100.7",
        user_id=user.id,
        details={"report": "q3.pdf"},
    )
    await db_session.commit()
    return user


class TestAuditActionsCatalog:
    @pytest.mark.asyncio
    async def test_actions_catalog_shape(self, client, auth_headers_admin):
        r = await client.get("/api/v1/audit/actions", headers=auth_headers_admin)
        assert r.status_code == 200, r.text
        body = r.json()

        # The four keys the filter menu reads, all of them always sent: the client
        # marks them optional, but the route builds every one.
        assert set(body) == {"groups", "total", "actions", "labels"}
        assert body["total"] == len(AUDIT_ALLOWED_ACTIONS)
        assert body["actions"] == sorted(AUDIT_ALLOWED_ACTIONS)
        assert isinstance(body["labels"], dict)

        # Grouped by first prefix segment, alphabetically sorted inside.
        categories = {g["category"] for g in body["groups"]}
        assert "auth" in categories and "asset" in categories
        grouped: list[str] = []
        for group in body["groups"]:
            assert set(group) == {"category", "actions"}
            assert group["actions"] == sorted(group["actions"])
            for a in group["actions"]:
                assert a in AUDIT_ALLOWED_ACTIONS
            grouped.extend(group["actions"])

        # The groups partition the flat list: every action appears in exactly one
        # group, and nothing is listed twice or left out. The response model declares
        # the shape; this is the invariant the model cannot express.
        assert sorted(grouped) == body["actions"]
        assert len(grouped) == len(set(grouped)) == body["total"]
        # A label exists for the actions the page can print one for, and every label
        # key is an action the catalogue publishes.
        assert set(body["labels"]) <= set(body["actions"])

    @pytest.mark.asyncio
    async def test_actions_requires_admin(self, client, auth_headers_viewer):
        r = await client.get("/api/v1/audit/actions", headers=auth_headers_viewer)
        assert r.status_code == 403, r.text


class TestAuditLogsFilters:
    @pytest.mark.asyncio
    async def test_requires_admin(self, client, auth_headers_analyst):
        r = await client.get(ENDPOINT, headers=auth_headers_analyst)
        assert r.status_code == 403, r.text

    @pytest.mark.asyncio
    async def test_unfiltered_list_returns_rows_newest_first(
        self, client, auth_headers_admin, audit_rows
    ):
        r = await client.get(ENDPOINT, headers=auth_headers_admin)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["total"] >= 3
        stamps = [i["timestamp"] for i in body["items"]]
        assert stamps == sorted(stamps, reverse=True)

        row = next(i for i in body["items"] if i["action"] == "asset.create")
        assert row["user_email"] == "test_viewer@example.com"
        assert row["ip_address"] == "203.0.113.10"
        # The caller's own detail is untouched; the chain link sits beside it, and
        # the API deliberately does not expose the link as top-level fields — the
        # documented audit shape is unchanged.
        assert row["details"]["asset"] == "alpha.example.com"
        assert set(row["details"]) == {"asset", "actor_email", "audit_hash", "audit_prev_hash", "audit_key_id"}
        assert row["actor_identity_source"] == "snapshot"
        assert row["seq"] > 0

    @pytest.mark.asyncio
    async def test_a_row_answers_the_eleven_fields_the_page_declares(
        self, client, auth_headers_admin, audit_rows
    ):
        """Plan 035: the audit page's row was `PaginatedResponse[Any]` until now.

        The key sets are asserted whole, so a field dropped from
        `AuditLogRowResponse` fails here instead of rendering as a blank cell in the
        page an operator opens during an incident.
        """
        r = await client.get(ENDPOINT, headers=auth_headers_admin)
        assert r.status_code == 200, r.text
        body = r.json()
        assert set(body) == {"items", "total", "page", "size", "pages"}
        row = next(i for i in body["items"] if i["action"] == "asset.create")
        assert set(row) == {
            "id",
            "timestamp",
            "user_id",
            "user_email",
            "actor_identity_source",
            "seq",
            "entry_hash",
            "key_id",
            "action",
            "ip_address",
            "details",
        }
        # `key_id` is declared although the page does not read it: the payload sends
        # it, the column is not nullable, and a model may not narrow a row.
        assert row["key_id"] >= 0
        assert row["entry_hash"]
        assert isinstance(row["seq"], int)
        # A row written without an actor sends `null` rather than omitting the key,
        # and says which resolution the email went through.
        anonymous = next(i for i in body["items"] if i["action"] == "asset.delete")
        assert anonymous["user_id"] is None and anonymous["user_email"] is None
        assert anonymous["actor_identity_source"] == "current_user_lookup"

    @pytest.mark.asyncio
    async def test_action_filter_case_insensitive_and_literal_fallback(
        self, client, auth_headers_admin, audit_rows
    ):
        r = await client.get(
            ENDPOINT, headers=auth_headers_admin, params={"action": "ASSET.CREATE"}
        )
        assert r.status_code == 200, r.text
        actions = {i["action"] for i in r.json()["items"]}
        assert actions == {"asset.create"}

        # Unknown action is matched literally (empty result), not rejected.
        r = await client.get(
            ENDPOINT, headers=auth_headers_admin, params={"action": "no.such.action"}
        )
        assert r.status_code == 200, r.text
        assert r.json()["items"] == []
        assert r.json()["total"] == 0

    @pytest.mark.asyncio
    async def test_user_id_filter(self, client, auth_headers_admin, audit_rows):
        r = await client.get(
            ENDPOINT, headers=auth_headers_admin, params={"user_id": str(audit_rows.id)}
        )
        assert r.status_code == 200, r.text
        items = r.json()["items"]
        assert items, "expected rows for the viewer user"
        assert all(i["user_id"] == str(audit_rows.id) for i in items)
        assert all(i["action"] in {"asset.create", "report.download"} for i in items)

    @pytest.mark.asyncio
    async def test_user_email_filter_uses_subquery(
        self, client, auth_headers_admin, audit_rows
    ):
        r = await client.get(
            ENDPOINT,
            headers=auth_headers_admin,
            params={"user_email": "test_viewer@"},
        )
        assert r.status_code == 200, r.text
        items = r.json()["items"]
        assert items
        assert all(i["user_email"] == "test_viewer@example.com" for i in items)

    @pytest.mark.asyncio
    async def test_user_email_partial_match_no_hits(
        self, client, auth_headers_admin, audit_rows
    ):
        r = await client.get(
            ENDPOINT, headers=auth_headers_admin, params={"user_email": "nobody@"}
        )
        assert r.status_code == 200, r.text
        assert r.json()["items"] == []

    @pytest.mark.asyncio
    async def test_from_to_date_window(
        self, client, auth_headers_admin, db_session, audit_rows
    ):
        # One fresh row inside the window, one older than the window start.
        await _emit(
            db_session,
            action="settings.view",
            ip="203.0.113.99",
            user_id=None,
            details={"window": "in"},
        )
        await db_session.commit()

        r = await client.get(
            ENDPOINT,
            headers=auth_headers_admin,
            params={
                "from_date": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()
            },
        )
        assert r.status_code == 200, r.text
        # Future window: only rows stamped 'now or later' match; settings.view
        # was written moments ago, so it must be excluded.
        actions = {i["action"] for i in r.json()["items"]}
        assert "settings.view" not in actions

    @pytest.mark.asyncio
    async def test_search_matches_ip_and_details_json(
        self, client, auth_headers_admin, audit_rows
    ):
        r = await client.get(
            ENDPOINT, headers=auth_headers_admin, params={"search": "198.51.100.7"}
        )
        assert r.status_code == 200, r.text
        actions = {i["action"] for i in r.json()["items"]}
        assert actions == {"report.download"}

        r = await client.get(
            ENDPOINT, headers=auth_headers_admin, params={"search": "beta.example.com"}
        )
        assert r.status_code == 200, r.text
        actions = {i["action"] for i in r.json()["items"]}
        assert actions == {"asset.delete"}

    @pytest.mark.asyncio
    async def test_pagination_meta_and_audit_event(
        self, client, auth_headers_admin, db_session, audit_rows
    ):
        r = await client.get(
            ENDPOINT, headers=auth_headers_admin, params={"page": 1, "size": 2}
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["page"] == 1 and body["size"] == 2
        assert len(body["items"]) == 2
        assert body["pages"] >= 2

        rows = list(
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "audit.log.view")
                )
            ).scalars()
        )
        assert rows, "audit listing must itself be audited"
        assert rows[-1].details.get("results") == body["total"]

    @pytest.mark.asyncio
    async def test_combining_action_and_search(self, client, auth_headers_admin, audit_rows):
        r = await client.get(
            ENDPOINT,
            headers=auth_headers_admin,
            params={"action": "asset.create", "search": "alpha.example.com"},
        )
        assert r.status_code == 200, r.text
        items = r.json()["items"]
        assert len(items) == 1
        assert items[0]["action"] == "asset.create"

        r = await client.get(
            ENDPOINT,
            headers=auth_headers_admin,
            params={"action": "asset.create", "search": "beta.example.com"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["items"] == []

    @pytest.mark.asyncio
    async def test_naive_datetimes_are_coerced_to_utc(
        self, client, auth_headers_admin, audit_rows
    ):
        """Naive from/to datetimes are treated as UTC (pinned coercion)."""
        r = await client.get(
            ENDPOINT,
            headers=auth_headers_admin,
            params={
                "from_date": (datetime.now(timezone.utc) - timedelta(hours=1)).replace(
                    tzinfo=None
                ).isoformat(),
                "to_date": (datetime.now(timezone.utc) + timedelta(hours=1)).replace(
                    tzinfo=None
                ).isoformat(),
            },
        )
        assert r.status_code == 200, r.text
        assert r.json()["total"] >= 3

        # A naive to_date in the near past excludes everything.
        r = await client.get(
            ENDPOINT,
            headers=auth_headers_admin,
            params={
                "to_date": (datetime.now(timezone.utc) - timedelta(hours=1))
                .replace(tzinfo=None)
                .isoformat()
            },
        )
        assert r.status_code == 200, r.text
        assert r.json()["items"] == []


class TestGroupActionsHelper:
    """Unit pins for the pure grouping helper (no HTTP involved)."""

    def test_groups_are_sorted_and_cover_all_actions(self):
        from app.api.v1.routers.audit import _group_actions_by_prefix

        groups = _group_actions_by_prefix()
        covered = [a for g in groups for a in g["actions"]]
        assert sorted(covered) == sorted(AUDIT_ALLOWED_ACTIONS)
        categories = [g["category"] for g in groups]
        assert categories == sorted(categories)

    def test_dotless_action_falls_into_other_group(self, monkeypatch):
        """Defensive branch: an action without a dot lands in "other"."""
        import app.api.v1.routers.audit as audit_mod

        monkeypatch.setattr(audit_mod, "AUDIT_ALLOWED_ACTIONS", {"dotless_action"})
        groups = audit_mod._group_actions_by_prefix()
        assert groups == [{"category": "other", "actions": ["dotless_action"]}]
