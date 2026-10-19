"""WI-08 · one rule for "which asset is this finding about" (AST-01/02/03/05).

The audit found three implementations of that question — the breach list, the
destructive cascade and orphan cleanup — that disagreed on case, on IDNA, on the
trailing dot and on the email-to-domain derivation. These tests pin the single
rule in ``app.services.asset_matching`` and then assert that all three callers
give the same answer for the same rows.
"""

from __future__ import annotations

import uuid
from datetime import date

import pytest

from app.services.asset_matching import (
    POLICY_CLEANUP,
    POLICY_DISPLAY,
    POLICY_SCAN,
    asset_key_variants,
    asset_scope,
    canonical_key,
    cidr_search_values,
    email_domain_variants,
    email_suffix_predicate,
    key_variants,
    keys_predicate,
    resolution_candidates,
    sql_key,
)


class TestKeyVariants:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("EXAMPLE.com.", {"example.com"}),
            ("example.com", {"example.com"}),
            ("  Example.COM  ", {"example.com"}),
            # IDNA: the Unicode spelling and the stored punycode spelling must
            # both be recognized, because SQL ``lower()`` cannot do IDNA.
            ("MÜNCHEN.de", {"münchen.de", "xn--mnchen-3ya.de"}),
            # Punycode and Unicode spellings must recognize each other in both
            # directions: the asset is stored as punycode while a connector may
            # have written the Unicode spelling into the finding.
            ("xn--mnchen-3ya.de", {"xn--mnchen-3ya.de", "münchen.de"}),
            # IP literals: compressed form plus the spelling SQL would see.
            ("2001:0DB8:0000::1", {"2001:db8::1", "2001:0db8:0000::1"}),
            ("192.0.2.7", {"192.0.2.7"}),
            # Addresses keep the local part and gain the fully lowercased
            # spelling the cascade compares through SQL.
            ("User@Example.COM", {"User@example.com", "user@example.com"}),
            # A keyword is not a hostname and must still get one stable key.
            ("MyBrandX", {"mybrandx"}),
        ],
    )
    def test_variants(self, raw, expected):
        assert key_variants(raw) == frozenset(expected)

    @pytest.mark.parametrize("raw", ["", "   ", None])
    def test_empty_values_have_no_variants(self, raw):
        assert key_variants(raw) == frozenset()
        assert canonical_key(raw) is None

    def test_canonical_key_is_one_of_the_variants(self):
        for raw in ("EXAMPLE.com.", "MÜNCHEN.de", "User@Example.COM", "2001:0DB8::1", "MyBrandX"):
            assert canonical_key(raw) in key_variants(raw)

    def test_keyword_assets_keep_the_stored_spelling_and_the_lowercased_one(self):
        assert asset_key_variants("keyword_domain", "MyBrandX") == {"MyBrandX", "mybrandx"}
        assert asset_key_variants("keyword_title", "Acme Corp") == {"Acme Corp", "acme corp"}

    @pytest.mark.parametrize(
        "asset_type,value",
        [
            ("domain", "Example.COM."),
            ("ip_address", "2001:0DB8::1"),
            ("email_account", "User@Example.COM"),
        ],
    )
    def test_asset_and_finding_spellings_intersect(self, asset_type, value):
        assert asset_key_variants(asset_type, value) & key_variants(value)


class TestResolutionCandidates:
    def test_mailbox_wins_over_its_domain(self):
        assert resolution_candidates("User@Example.COM") == (
            ("email_account", "User@example.com"),
            ("email_account", "user@example.com"),
            ("domain", "example.com"),
        )

    def test_domain_and_keyword_values_resolve_as_domains(self):
        assert resolution_candidates("Example.COM.") == (("domain", "example.com"),)
        assert resolution_candidates("MyBrandX") == (("domain", "mybrandx"),)

    def test_ip_values_resolve_as_addresses(self):
        assert ("ip_address", "2001:db8::1") in resolution_candidates("2001:0DB8::1")

    @pytest.mark.parametrize("raw", ["", None, "   "])
    def test_empty(self, raw):
        assert resolution_candidates(raw) == ()

    def test_email_domain_variants(self):
        assert email_domain_variants("User@Example.COM") == frozenset({"example.com"})
        assert email_domain_variants("no-address") == frozenset()


class TestPolicies:
    def test_scan_only_scans_active_assets(self):
        (condition,) = asset_scope(POLICY_SCAN)
        assert "is_active" in str(condition)

    @pytest.mark.parametrize("policy", [POLICY_DISPLAY, POLICY_CLEANUP])
    def test_display_and_cleanup_keep_inactive_assets(self, policy):
        assert asset_scope(policy) == ()

    def test_an_unknown_policy_is_a_programming_error(self):
        with pytest.raises(ValueError):
            asset_scope("whatever")


class TestSqlPredicates:
    """The SQL path must apply the same canonicalization as the Python path."""

    def test_keys_predicate_lowercases_and_strips_the_trailing_dot(self):
        from app.models.phishing import PhishingDomain

        compiled = str(
            keys_predicate(PhishingDomain.matched_asset, ["example.com"]).compile(
                compile_kwargs={"literal_binds": True}
            )
        )
        assert "lower" in compiled and "rtrim" in compiled and "trim" in compiled

    def test_sql_key_lowercases_and_strips_the_trailing_dot(self):
        from app.models.phishing import PhishingDomain

        compiled = str(
            sql_key(PhishingDomain.matched_asset).compile(compile_kwargs={"literal_binds": True})
        )
        assert compiled == "lower(rtrim(trim(drp_phishing_domains.matched_asset), '.'))"

    def test_asset_sql_key_uses_the_stored_canonical_column_when_present(self):
        from app.services.asset_matching import asset_sql_key

        compiled = str(asset_sql_key().compile(compile_kwargs={"literal_binds": True}))
        assert "normalized_value" in compiled and "asset_value" in compiled
        assert "coalesce" in compiled and "lower" in compiled

    def test_email_suffix_predicate_only_accepts_hostnames(self):
        from app.models.breach import Breach

        assert email_suffix_predicate(Breach.matched_email, ["user@example.com"]) is None
        assert email_suffix_predicate(Breach.matched_email, ["2001:db8::1"]) is None
        assert email_suffix_predicate(Breach.matched_email, ["example.com"]) is not None

    def test_the_email_to_domain_rule_is_an_indexable_equality(self):
        """AST-46: the rule must not be a correlated ``LIKE '%@' || key``.

        That form compares the address against an expression built from the
        asset row, so no index on the breach table can serve it. The equality on
        ``EmailDomain`` is the form ``ix_drp_breaches_matched_email_domain``
        indexes.
        """
        from sqlalchemy.dialects import postgresql

        from app.models.breach import Breach

        compiled = str(
            email_suffix_predicate(Breach.matched_email, ["example.com"]).compile(
                dialect=postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )
        # The domain part is an expression the index covers, not a pattern built
        # from the asset key (the old form's `'%@' || asset_key`).
        assert "split_part" in compiled
        assert "||" not in compiled


class TestTheThreeCallersAgree:
    """The DoD of WI-08: resolver, cascade and cleanup answer the same question."""

    @staticmethod
    async def _asset(db_session, asset_type="domain", value="example.com", *, is_active=True):
        from app.models.asset import Asset, AssetType
        from app.schemas.asset import normalize_asset_value

        asset = Asset(
            asset_type=AssetType(asset_type),
            asset_value=value,
            normalized_value=normalize_asset_value(asset_type, value),
            is_active=is_active,
        )
        db_session.add(asset)
        await db_session.commit()
        await db_session.refresh(asset)
        return asset

    @staticmethod
    async def _breach(db_session, *, matched_email=None, matched_domain=None):
        from app.models.breach import Breach

        breach = Breach(
            breach_name=f"Br-{uuid.uuid4().hex[:8]}",
            title="T",
            domain="example.com",
            breach_date=date(2024, 1, 1),
            pwn_count=1000,
            matched_email=matched_email,
            matched_domain=matched_domain,
        )
        db_session.add(breach)
        await db_session.commit()
        await db_session.refresh(breach)
        return breach

    @staticmethod
    async def _phishing(db_session, matched_asset):
        from app.models.phishing import PhishingDomain

        row = PhishingDomain(
            phishing_domain=f"p-{uuid.uuid4().hex[:8]}.test",
            matched_asset=matched_asset,
            detection_source="test",
        )
        db_session.add(row)
        await db_session.commit()
        await db_session.refresh(row)
        return row

    @pytest.mark.asyncio
    async def test_case_mismatched_findings_are_neither_orphaned_nor_invisible(self, db_session):
        from sqlalchemy import select

        from app.api.v1.routers.breaches import _asset_matches_for_breaches
        from app.models.breach import Breach
        from app.services.asset_service import AssetService

        # The operator typed the domain with the casing their registrar shows.
        await self._asset(db_session, value="Example.COM")
        linked = await self._breach(db_session, matched_domain="EXAMPLE.com")
        orphan = await self._breach(db_session, matched_domain="not-monitored.test")

        resolved = await _asset_matches_for_breaches(db_session, [linked, orphan])
        assert resolved[linked.id] == ("Example.COM", "domain")
        assert orphan.id not in resolved

        deleted = await AssetService(db_session).clean_orphan_breach_findings()
        assert deleted == 1
        remaining = list((await db_session.execute(select(Breach.id))).scalars())
        assert remaining == [linked.id]

    @pytest.mark.asyncio
    async def test_a_domain_asset_explains_the_mailboxes_at_that_domain(self, db_session):
        from sqlalchemy import select

        from app.api.v1.routers.breaches import _asset_matches_for_breaches
        from app.models.breach import Breach
        from app.services.asset_service import AssetService

        await self._asset(db_session, value="example.com")
        mailbox = await self._breach(db_session, matched_email="Analyst@Example.COM")

        resolved = await _asset_matches_for_breaches(db_session, [mailbox])
        assert resolved[mailbox.id] == ("example.com", "domain")

        # Cleanup agrees: the row is linked, so it must survive.
        assert await AssetService(db_session).clean_orphan_breach_findings() == 0
        assert list((await db_session.execute(select(Breach.id))).scalars()) == [mailbox.id]

    @pytest.mark.asyncio
    async def test_the_cascade_removes_what_the_list_displays(self, db_session):
        from sqlalchemy import select

        from app.models.breach import Breach
        from app.models.phishing import PhishingDomain
        from app.services.asset_service import AssetService

        asset = await self._asset(db_session, value="Example.COM")
        # Both spellings the resolver would name: the domain and a mailbox at it.
        await self._breach(db_session, matched_domain="example.com")
        await self._breach(db_session, matched_email="analyst@example.com")
        await self._phishing(db_session, "EXAMPLE.com")
        untouched = await self._breach(db_session, matched_domain="other.test")

        phishing_deleted, breach_deleted, generic_deleted = await AssetService(db_session).delete_asset(
            asset, cascade_findings=True
        )
        assert (phishing_deleted, breach_deleted, generic_deleted) == (1, 2, 0)
        remaining = list((await db_session.execute(select(Breach.id))).scalars())
        assert remaining == [untouched.id]
        assert list((await db_session.execute(select(PhishingDomain.id))).scalars()) == []

    @pytest.mark.asyncio
    async def test_deleting_a_mailbox_does_not_delete_its_domain(self, db_session):
        from sqlalchemy import select

        from app.models.breach import Breach
        from app.services.asset_service import AssetService

        asset = await self._asset(db_session, asset_type="email_account", value="analyst@example.com")
        mine = await self._breach(db_session, matched_email="analyst@example.com")
        colleague = await self._breach(db_session, matched_email="other@example.com")

        _, breach_deleted, _ = await AssetService(db_session).delete_asset(asset, cascade_findings=True)
        assert breach_deleted == 1
        assert list((await db_session.execute(select(Breach.id))).scalars()) == [colleague.id]
        assert (await db_session.get(Breach, mine.id)) is None

    @pytest.mark.asyncio
    async def test_an_inactive_asset_still_owns_its_findings(self, db_session):
        """``POLICY_DISPLAY``/``POLICY_CLEANUP`` keep inactive assets authoritative.

        Deactivating an asset stops scans; it must not silently orphan the
        findings that asset explains (AST-05).
        """
        from app.api.v1.routers.breaches import _asset_matches_for_breaches
        from app.services.asset_service import AssetService

        await self._asset(db_session, value="paused.example", is_active=False)
        row = await self._breach(db_session, matched_domain="paused.example")

        assert (await _asset_matches_for_breaches(db_session, [row]))[row.id] == (
            "paused.example",
            "domain",
        )
        assert await AssetService(db_session).clean_orphan_breach_findings() == 0

    @pytest.mark.asyncio
    async def test_a_unicode_finding_is_not_orphaned_by_its_punycode_asset(self, db_session, monkeypatch):
        """SQL cannot convert IDNA, so the anti-join must not delete these rows."""
        from sqlalchemy import select

        from app.models.breach import Breach
        from app.services.asset_service import AssetService

        await self._asset(db_session, value="xn--mnchen-3ya.de")
        unicode_row = await self._breach(db_session, matched_domain="münchen.de")
        await self._breach(db_session, matched_domain="nowhere.test")

        assert await AssetService(db_session).clean_orphan_breach_findings() == 1
        remaining = list((await db_session.execute(select(Breach.id))).scalars())
        assert remaining == [unicode_row.id]

    @pytest.mark.asyncio
    async def test_a_unicode_mailbox_at_a_punycode_domain_is_not_orphaned(self, db_session):
        """The indexed branch keeps exactly the rows the correlated one kept.

        SQL compares the lowercased domain part and cannot convert IDNA, so the
        punycode asset and the Unicode address only meet in the Python re-check.
        The equality form must therefore narrow candidates without ever deleting
        a row that check would call linked.
        """
        from sqlalchemy import select

        from app.models.breach import Breach
        from app.services.asset_service import AssetService

        await self._asset(db_session, value="xn--mnchen-3ya.de")
        kept = await self._breach(db_session, matched_email="Analyst@münchen.de")
        orphan = await self._breach(db_session, matched_email="analyst@nowhere.test")

        assert await AssetService(db_session).clean_orphan_breach_findings() == 1
        remaining = list((await db_session.execute(select(Breach.id))).scalars())
        assert remaining == [kept.id]
        assert orphan.id not in remaining

    @pytest.mark.asyncio
    async def test_cleanup_deletes_more_rows_than_one_batch(self, db_session, monkeypatch):
        from sqlalchemy import select

        from app.models.phishing import PhishingDomain
        from app.services.asset_service import AssetService

        monkeypatch.setattr(AssetService, "FINDING_BATCH_SIZE", 2)
        await self._asset(db_session, value="kept.example")
        await self._phishing(db_session, "kept.example")
        for _ in range(5):
            await self._phishing(db_session, "orphan.test")

        assert await AssetService(db_session).clean_orphan_phishing_findings() == 5
        assert len(list((await db_session.execute(select(PhishingDomain.id))).scalars())) == 1

    @pytest.mark.asyncio
    async def test_cascade_deletes_more_findings_than_one_batch(self, db_session, monkeypatch):
        from sqlalchemy import select

        from app.models.phishing import PhishingDomain
        from app.services.asset_service import AssetService

        monkeypatch.setattr(AssetService, "FINDING_BATCH_SIZE", 2)
        asset = await self._asset(db_session, value="batched.example")
        for _ in range(5):
            await self._phishing(db_session, "batched.example")

        phishing_deleted, _, _ = await AssetService(db_session).delete_asset(
            asset, cascade_findings=True
        )
        assert phishing_deleted == 5
        assert list((await db_session.execute(select(PhishingDomain.id))).scalars()) == []

    @pytest.mark.asyncio
    async def test_scans_only_receive_active_assets(self, db_session):
        from app.services.connector_service import ConnectorService

        await self._asset(db_session, value="active.example")
        await self._asset(db_session, value="inactive.example", is_active=False)

        snapshot = await ConnectorService(db_session)._active_asset_snapshot(["domain"])
        assert "active.example" in snapshot["domains"]
        assert "inactive.example" not in snapshot["domains"]


class TestCidrSearchValues:
    """WI-16 · a subnet search is an address set, not a substring (AST-08)."""

    def test_a_subnet_becomes_the_canonical_addresses_it_contains(self):
        values = cidr_search_values("10.0.0.0/30")
        # Canonical, because that is what ``normalized_value`` holds: an address
        # entered as ``10.0.0.01`` or ``2001:0db8::1`` is stored compressed.
        assert values == {"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"}
        assert cidr_search_values("2001:0db8:0000::/126") == {
            "2001:db8::",
            "2001:db8::1",
            "2001:db8::2",
            "2001:db8::3",
        }

    def test_host_bits_are_ignored_like_every_other_cidr_parser(self):
        # An operator who types the address of a host with the prefix of its
        # network means the network.
        assert cidr_search_values("10.0.0.7/24") == cidr_search_values("10.0.0.0/24")

    @pytest.mark.parametrize(
        "term",
        [
            "example.com",
            "10.0.0.0/33",
            "not/a/subnet",
            "10.0.0.0",
            "",
            None,
        ],
    )
    def test_a_term_that_is_not_a_subnet_is_left_to_substring_search(self, term):
        assert cidr_search_values(term) is None

    def test_a_subnet_larger_than_the_bound_is_refused(self):
        assert cidr_search_values("10.0.0.0/20") is not None
        with pytest.raises(ValueError) as refusal:
            cidr_search_values("10.0.0.0/8")
        assert "at most" in str(refusal.value)
