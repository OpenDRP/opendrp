"""WI-20/AST-27 · telling a monitored asset from a configured one.

The inventory answered "what have I configured" and nothing else: an asset that
no module ever reported anything about looked exactly like one that is being
scanned every day. These tests pin the three answers the list now gives — a
per-row involvement count, a ``has_findings`` filter, and when each module last
saw that asset — to the *same* matching rule the asset page and the cascade use
(``asset_matching``), so the inventory cannot report a different relationship
than the one a delete would act on.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta, timezone

import pytest

MARK = "involvement"


@pytest.mark.anyio
class TestAssetInvolvement:
    async def _create(self, client, headers, value: str, asset_type: str = "domain") -> dict:
        response = await client.post(
            "/api/v1/assets",
            headers=headers,
            json={"asset_type": asset_type, "asset_value": value},
        )
        assert response.status_code == 201, response.text
        return response.json()

    async def _phishing(self, db_session, matched_asset: str) -> datetime:
        """One phishing row and the moment it was recorded."""
        from app.models.phishing import PhishingDomain

        created = datetime.now(timezone.utc)
        db_session.add(
            PhishingDomain(
                phishing_domain="look-alike.example",
                matched_asset=matched_asset,
                detection_source="dnstwist",
                created_at=created,
            )
        )
        await db_session.commit()
        return created

    async def _breach_email_at(self, db_session, domain: str, mailbox: str) -> None:
        """A breach about a mailbox at ``domain`` — linked by the email-to-domain rule."""
        from app.models.breach import Breach

        db_session.add(
            Breach(
                breach_name=f"Br-{MARK}",
                title="T",
                domain=domain,
                breach_date=date(2024, 1, 1),
                pwn_count=10,
                matched_email=mailbox,
            )
        )
        await db_session.commit()

    async def _list(self, client, headers, **params) -> dict:
        response = await client.get(
            "/api/v1/assets", headers=headers, params={"size": 200, **params}
        )
        assert response.status_code == 200, response.text
        return response.json()

    async def test_a_list_row_reports_what_the_asset_page_reports(
        self, client, db_session, auth_headers_admin
    ):
        """One asset's counter is the asset page's counter, from one computation.

        Two numbers about the same relationship drifting apart is exactly the
        defect the matching module exists to prevent, so the list row is checked
        against the view rather than against a hardcoded expectation.
        """
        involved = await self._create(client, auth_headers_admin, f"involved.{MARK}")
        await self._create(client, auth_headers_admin, f"quiet.{MARK}")
        created = await self._phishing(db_session, f"involved.{MARK}")
        await self._breach_email_at(db_session, f"involved.{MARK}", f"analyst@involved.{MARK}")

        listed = await self._list(client, auth_headers_admin)
        rows = {item["asset_value"]: item for item in listed["items"]}
        assert rows[f"involved.{MARK}"]["findings"]["total"] == 2
        assert rows[f"quiet.{MARK}"]["findings"]["total"] == 0
        assert rows[f"quiet.{MARK}"]["findings"]["phishing"] == 0

        page = (
            await client.get(
                f"/api/v1/assets/{involved['id']}/findings",
                headers=auth_headers_admin,
            )
        ).json()
        reported = rows[f"involved.{MARK}"]["findings"]
        for module in ("phishing", "breaches", "dns", "exposure", "findings", "total"):
            assert reported[module] == page["counts"][module], module

        # A breach reports a disclosure date while a scan reports a timestamp;
        # both are published as ISO text, so nothing compares the two kinds.
        assert reported["last_seen"]["breaches"] == "2024-01-01"
        assert reported["last_seen"]["phishing"].startswith(
            created.strftime("%Y-%m-%dT%H:%M")
        )
        assert reported["last_seen"]["dns"] is None

    async def test_has_findings_answers_which_assets_are_involved(
        self, client, db_session, auth_headers_admin
    ):
        await self._create(client, auth_headers_admin, f"involved.{MARK}")
        await self._create(client, auth_headers_admin, f"quiet.{MARK}")
        await self._phishing(db_session, f"involved.{MARK}")

        involved = await self._list(client, auth_headers_admin, has_findings=True)
        assert [item["asset_value"] for item in involved["items"]] == [f"involved.{MARK}"]
        assert involved["total"] == 1

        quiet = await self._list(client, auth_headers_admin, has_findings=False)
        assert [item["asset_value"] for item in quiet["items"]] == [f"quiet.{MARK}"]

    async def test_the_filter_applies_the_email_to_domain_rule(
        self, client, db_session, auth_headers_admin
    ):
        """The suffix branch is part of the filter, not only of the counter.

        A mailbox breach names no domain, so an asset whose only link to the
        platform is "mailboxes at this domain were breached" must be selected by
        the filter — and counted — or the two answers would disagree about the
        one case the email-to-domain rule exists for.
        """
        await self._create(client, auth_headers_admin, f"mail.{MARK}")
        await self._create(client, auth_headers_admin, f"quiet.{MARK}")
        await self._breach_email_at(db_session, f"mail.{MARK}", f"analyst@mail.{MARK}")

        involved = await self._list(client, auth_headers_admin, has_findings=True)
        assert [item["asset_value"] for item in involved["items"]] == [f"mail.{MARK}"]
        assert involved["items"][0]["findings"]["breaches"] == 1

    async def test_the_filter_keeps_an_inactive_asset_that_still_owns_findings(
        self, client, db_session, auth_headers_admin
    ):
        """Deactivation stops scanning; it does not erase what was observed.

        The filter is read under the display policy, so an asset switched off
        after a finding was recorded still appears among the involved ones — the
        finding is evidence about the asset, and the status column already says
        it is no longer scanned.
        """
        asset = await self._create(client, auth_headers_admin, f"off.{MARK}")
        await self._phishing(db_session, f"off.{MARK}")
        deactivated = await client.patch(
            f"/api/v1/assets/{asset['id']}",
            headers=auth_headers_admin,
            json={"is_active": False},
        )
        assert deactivated.status_code == 200, deactivated.text

        involved = await self._list(client, auth_headers_admin, has_findings=True)
        assert [item["asset_value"] for item in involved["items"]] == [f"off.{MARK}"]
        assert involved["items"][0]["is_active"] is False

    async def test_has_findings_refuses_a_value_that_is_not_a_boolean(
        self, client, auth_headers_admin
    ):
        response = await client.get(
            "/api/v1/assets", headers=auth_headers_admin, params={"has_findings": "maybe"}
        )
        assert response.status_code == 422, response.text

    async def test_the_export_applies_the_involvement_filter(
        self, client, db_session, auth_headers_admin
    ):
        """The file behind the filter is the table the operator checked first."""
        await self._create(client, auth_headers_admin, f"involved.{MARK}")
        await self._create(client, auth_headers_admin, f"quiet.{MARK}")
        await self._phishing(db_session, f"involved.{MARK}")

        exported = await client.get(
            "/api/v1/assets/export",
            headers=auth_headers_admin,
            params={"format": "json", "has_findings": True},
        )
        assert exported.status_code == 200, exported.text
        body = exported.json()
        assert [item["asset_value"] for item in body["items"]] == [f"involved.{MARK}"]
        assert body["total"] == 1

    async def test_the_counter_and_the_filter_read_the_same_rule(
        self, client, db_session, auth_headers_admin
    ):
        """A non-ASCII hostname is one asset, whichever spelling a finding used.

        ``assets.normalized_value`` is stored in IDNA form while a finding may
        carry the Unicode spelling, and SQL cannot convert between the two — which
        is why both the counter and the filter are answered from the literal key
        set (``key_variants``) rather than from a correlated SQL comparison. A row
        the list counts is a row the filter selects, for the same reason the
        cascade removes it.
        """
        asset = await self._create(client, auth_headers_admin, f"münchen.{MARK}")
        assert asset["asset_value"].startswith("xn--"), asset["asset_value"]
        row_created = await self._phishing(db_session, f"münchen.{MARK}")

        listed = await self._list(client, auth_headers_admin)
        row = next(
            item for item in listed["items"] if item["id"] == asset["id"]
        )
        assert row["findings"]["total"] == 1
        assert row["findings"]["last_seen"]["phishing"].startswith(
            row_created.strftime("%Y-%m-%dT%H:%M")
        )

        selected = await self._list(client, auth_headers_admin, has_findings=True)
        assert asset["id"] in [item["id"] for item in selected["items"]]

        excluded = await self._list(client, auth_headers_admin, has_findings=False)
        assert asset["id"] not in [item["id"] for item in excluded["items"]]

    async def test_the_filter_does_not_read_more_statements_as_the_inventory_grows(
        self, client, db_session, auth_headers_admin
    ):
        """AWI-07: the filter is a database question, not an inventory load.

        The old form loaded every asset row into the request and summarised the
        whole inventory before choosing a page, so its statement count was
        constant but its *work* grew with the table. This counts statements for
        the same request against two inventory sizes: a per-asset lookup would
        show up as a growing count, and the union semi-join keeps it flat. The
        listener is attached to the ``Engine`` class because the API and the test
        session may run on different engine instances (PostgreSQL CI).
        """
        from sqlalchemy import event
        from sqlalchemy.engine import Engine

        await self._create(client, auth_headers_admin, f"involved.{MARK}")
        await self._phishing(db_session, f"involved.{MARK}")
        await db_session.commit()

        async def statement_count() -> int:
            counted = {"selects": 0}

            def before_cursor_execute(
                conn, cursor, statement, parameters, context, executemany
            ):
                if statement.lstrip().upper().startswith("SELECT"):
                    counted["selects"] += 1

            event.listen(Engine, "before_cursor_execute", before_cursor_execute)
            try:
                response = await self._list(client, auth_headers_admin, has_findings=True)
                assert response["items"], response
            finally:
                event.remove(Engine, "before_cursor_execute", before_cursor_execute)
            return counted["selects"]

        small = await statement_count()
        for index in range(40):
            await self._create(client, auth_headers_admin, f"extra{index}.{MARK}")
        large = await statement_count()

        assert small > 0, "the listener saw no statements; the count proves nothing"
        assert small == large, (small, large)


@pytest.mark.anyio
class TestAssetInvolvementOrdering:
    async def test_the_newest_finding_moves_last_seen_forward(
        self, client, db_session, auth_headers_admin
    ):
        """``last_seen`` is the latest moment, not the first row inserted."""
        from app.models.phishing import PhishingDomain

        asset = await self._create_for(client, auth_headers_admin)
        older = datetime.now(timezone.utc) - timedelta(days=3)
        newer = datetime.now(timezone.utc) - timedelta(hours=1)
        for created in (older, newer):
            db_session.add(
                PhishingDomain(
                    phishing_domain=f"look-alike-{uuid.uuid4().hex[:6]}.example",
                    matched_asset=asset["asset_value"],
                    detection_source="dnstwist",
                    created_at=created,
                )
            )
        await db_session.commit()

        listed = await client.get(
            "/api/v1/assets", headers=auth_headers_admin, params={"size": 200}
        )
        row = next(item for item in listed.json()["items"] if item["id"] == asset["id"])
        assert row["findings"]["total"] == 2
        assert row["findings"]["last_seen"]["phishing"].startswith(
            newer.strftime("%Y-%m-%dT%H:%M")
        )

    async def _create_for(self, client, headers) -> dict:
        response = await client.post(
            "/api/v1/assets",
            headers=headers,
            json={"asset_type": "domain", "asset_value": f"latest.{MARK}"},
        )
        assert response.status_code == 201, response.text
        return response.json()
