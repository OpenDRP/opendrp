"""Characterization tests: seed scripts (Step 10).

``scripts/seed_data.py`` (436 LOC) and ``scripts/seed_defaults.py`` (50 LOC)
had zero coverage. This file pins:

* ``_seed_all`` orchestration: which seeders run, in which order, and the
  idempotency contract — **re-running creates no duplicates**;
* ``_seed_users``: fixed demo accounts (admin/analyst/viewer) with hashed
  passwords and roles, idempotent per email;
* ``_seed_assets``: 15 demo assets across domain/ip/keyword types,
  idempotent per asset_value;
* ``_seed_phishing`` / ``_seed_breaches``: rows land with the expected
  shape (matched asset, data classes, statuses), idempotent per business key;
* ``seed_defaults``: creates the settings singleton exactly once (module
  imported lazily so the test's DATABASE_URL applies).
"""

from __future__ import annotations

from datetime import date

import pytest
from sqlalchemy import func, select

import scripts.seed_data as seed_data
from app.models import Asset, Breach, DrpPhishingDomain, SystemSettings, User


@pytest.fixture(autouse=True)
def _patch_session_factory(db_session, monkeypatch):
    """Point the seed script's AsyncSessionLocal at the test session factory."""
    from tests.conftest import _TestSessionLocal

    monkeypatch.setattr(seed_data, "AsyncSessionLocal", _TestSessionLocal)


class TestSeedUsers:
    @pytest.mark.asyncio
    async def test_creates_three_demo_users_with_roles(self, db_session):
        n = await seed_data._seed_users(force=False)
        assert n == 3
        emails = {
            e for (e,) in (await db_session.execute(select(User.email))).all()
        }
        assert {"admin@example.com", "analyst@example.com", "viewer@example.com"} <= emails
        admin = (
            await db_session.execute(select(User).where(User.email == "admin@example.com"))
        ).scalar_one()
        assert admin.role == "admin"
        assert admin.is_active is True
        assert admin.password_hash != "Password123"  # hashed, never plaintext
        # Demo accounts are not asked to rotate: the forced-change flag exists
        # because a password an administrator chose for somebody else is a shared
        # secret, whereas this password is published in the README on purpose so a
        # throwaway development database can be signed into as documented.
        assert admin.must_change_password is False
        assert admin.must_enrol_mfa is False

    @pytest.mark.asyncio
    async def test_idempotent_second_run_creates_zero(self, db_session):
        await seed_data._seed_users(force=False)
        assert await seed_data._seed_users(force=False) == 0


class TestSeedAssets:
    @pytest.mark.asyncio
    async def test_creates_expected_asset_inventory(self, db_session):
        n = await seed_data._seed_assets(force=False)
        assert n == 15
        total = (
            await db_session.execute(select(func.count(Asset.id)))
        ).scalar_one()
        assert total == 15
        google = (
            await db_session.execute(
                select(Asset).where(Asset.asset_value == "google.com")
            )
        ).scalar_one()
        assert getattr(google.asset_type, "value", google.asset_type) == "domain"
        assert google.criticality == "critical"
        assert google.is_active is True

    @pytest.mark.asyncio
    async def test_idempotent_second_run_creates_zero(self, db_session):
        await seed_data._seed_assets(force=False)
        assert await seed_data._seed_assets(force=False) == 0


class TestSeedPhishing:
    @pytest.mark.asyncio
    async def test_creates_rows_with_expected_shape(self, db_session):
        n = await seed_data._seed_phishing(force=False)
        assert n > 0
        row = (
            await db_session.execute(
                select(DrpPhishingDomain).where(
                    DrpPhishingDomain.phishing_domain == "googlee.com"
                )
            )
        ).scalar_one()
        assert row.matched_asset == "google.com"
        assert row.detection_source in {"dnstwist", "shodan_ssl", "shodan_title", "shodan_favicon"}
        # The seeder spreads rows over this set; read it from the seeder so the
        # two cannot drift and the assertion cannot depend on the draw.
        assert row.status in seed_data.PHISHING_STATUSES
        assert row.web_ports is not None
        # dnstwist-sourced rows carry original_domain; others do not.
        if row.detection_source == "dnstwist":
            assert row.original_domain == "google.com"
        else:
            assert row.original_domain is None

    @pytest.mark.asyncio
    async def test_idempotent_second_run_creates_zero(self, db_session):
        await seed_data._seed_phishing(force=False)
        assert await seed_data._seed_phishing(force=False) == 0


class TestSeedBreaches:
    @pytest.mark.asyncio
    async def test_creates_rows_with_expected_shape(self, db_session):
        n = await seed_data._seed_breaches(force=False)
        assert n > 0
        row = (
            await db_session.execute(
                select(Breach).where(
                    Breach.breach_name == "LinkedIn Data Scraping"
                )
            )
        ).scalar_one()
        assert row.matched_email == "admin@example.com"
        assert row.pwn_count == 72_000_000
        assert isinstance(row.breach_date, date)
        assert "Email addresses" in row.data_classes

    @pytest.mark.asyncio
    async def test_idempotent_second_run_creates_zero(self, db_session):
        await seed_data._seed_breaches(force=False)
        assert await seed_data._seed_breaches(force=False) == 0


class TestSeedAll:
    @pytest.mark.asyncio
    async def test_orchestrates_all_seeders_and_is_idempotent(self, db_session):
        await seed_data._seed_all(force=False)

        counts = {}
        for key, model in (
            ("User", User),
            ("Asset", Asset),
            ("PhishingDomain", DrpPhishingDomain),
            ("Breach", Breach),
        ):
            counts[key] = (
                await db_session.execute(select(func.count(model.id)))
            ).scalar_one()
        assert counts["User"] >= 3
        assert counts["Asset"] == 15
        assert counts["PhishingDomain"] > 0
        assert counts["Breach"] > 0

        settings_row = (
            await db_session.execute(select(SystemSettings).limit(1))
        ).scalar_one_or_none()
        assert settings_row is not None

        # Second full run: zero new rows anywhere.
        before = dict(counts)
        await seed_data._seed_all(force=False)
        for key, model in (
            ("User", User),
            ("Asset", Asset),
            ("PhishingDomain", DrpPhishingDomain),
            ("Breach", Breach),
        ):
            after = (
                await db_session.execute(select(func.count(model.id)))
            ).scalar_one()
            assert after == before[key], key


class TestSeedDefaults:
    @pytest.mark.asyncio
    async def test_creates_settings_singleton_once(self, db_session, monkeypatch):
        import importlib

        # Import lazily so its module-level state reflects the test env.
        sd = importlib.import_module("scripts.seed_defaults")

        # seed_defaults builds its own engine from
        # settings.DATABASE_URL_ASYNCPG; patch create_async_engine to return
        # an engine bound to the test DB so no real engine is created.
        from sqlalchemy.ext.asyncio import (
            async_sessionmaker as _mk,
            create_async_engine as _cae,
        )

        engine = _cae(str(db_session.bind.url), future=True)
        monkeypatch.setattr(sd, "create_async_engine", lambda *a, **kw: engine)
        monkeypatch.setattr(sd, "async_sessionmaker", lambda *a, **kw: _mk(engine))

        await sd._seed()  # first run creates
        row = (
            await db_session.execute(select(SystemSettings).limit(1))
        ).scalar_one_or_none()
        assert row is not None

        await sd._seed()  # second run is a no-op
        count = (
            await db_session.execute(select(func.count(SystemSettings.id)))
        ).scalar_one()
        assert count == 1
        await engine.dispose()
