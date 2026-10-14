"""WI-20 on PostgreSQL: the involvement summary and the ``has_findings`` filter.

SQLite accepts SQL that PostgreSQL refuses, and this feature adds the one
predicate in the plan that is *planned* by the database rather than interpreted
row by row: a correlated ``EXISTS`` over five modules, negated for
``has_findings=false``. The counters add five scalar subqueries per asset. Both
are checked here against a real database, because a filter that only compiles on
the test engine is a filter production does not have.

Set ``INTEGRATION_MIGRATION_DATABASE_URL`` to a dedicated, migrated PostgreSQL
database to run it. ``REQUIRE_INTEGRATION=1`` (what CI sets) turns a database
that is missing into a failure instead of a skip, so a misconfigured job cannot
report this file as green without having run it.
"""

import os
import uuid
from datetime import date, datetime, timezone

import pytest
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.models import Asset
from app.services.asset_service import AssetService

_DATABASE_URL = os.environ.get("INTEGRATION_MIGRATION_DATABASE_URL")
if not _DATABASE_URL:
    _message = (
        "set INTEGRATION_MIGRATION_DATABASE_URL to run the PostgreSQL involvement "
        "tests"
    )
    if os.environ.get("REQUIRE_INTEGRATION") == "1":
        raise RuntimeError(f"{_message} — REQUIRE_INTEGRATION=1 forbids skipping")
    pytest.skip(_message, allow_module_level=True)

# Marked like the rest of the real-services suite: CI selects it with
# `-m integration`, and the SQLite job deselects it with `-m "not integration"`.
pytestmark = pytest.mark.integration


async def test_the_involvement_summary_and_filter_work_on_postgres():
    url = _DATABASE_URL

    from app.models.breach import Breach
    from app.models.dns_observation import DNSObservation
    from app.models.finding import Finding
    from app.models.phishing import PhishingDomain
    from app.models.source_observation import SourceObservation

    engine = create_async_engine(url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    involved = Asset(
        asset_type="domain",
        asset_value="postgres-involvement.example",
        normalized_value="postgres-involvement.example",
        is_active=True,
    )
    quiet = Asset(
        asset_type="domain",
        asset_value="postgres-quiet.example",
        normalized_value="postgres-quiet.example",
        is_active=True,
    )
    now = datetime.now(timezone.utc)
    observation_key = uuid.uuid4().hex
    marker = f"wi20-{observation_key[:8]}"
    phishing = PhishingDomain(
        phishing_domain=f"look-alike-{marker}.example",
        # Mixed case on purpose: only the shared canonicalization links this row.
        matched_asset="Postgres-Involvement.Example",
        detection_source="dnstwist",
    )
    breach = Breach(
        breach_name=marker,
        title="T",
        domain=involved.asset_value,
        breach_date=date(2024, 1, 1),
        pwn_count=10,
        matched_email=f"analyst@{involved.asset_value}",
    )
    dns_row = DNSObservation(
        source="resolver",
        observation_type="dns_record",
        observation_key=f"a:{observation_key}",
        subject=involved.asset_value,
        record_type="A",
        value="203.0.113.40",
        first_seen_at=now,
        last_seen_at=now,
        status="current",
        metadata_json={},
        alerted_thresholds=[],
    )
    exposure = SourceObservation(
        module="exposure",
        source="shodan",
        observation_key=observation_key,
        subject="203.0.113.41",
        matched_asset=involved.asset_value,
        first_seen_at=now,
        last_seen_at=now,
        status="observed",
        payload={},
    )
    generic = Finding(
        module="phishing",
        finding_kind="phishing_domain",
        connector_name="dnstwist",
        dedup_key=observation_key,
        title=f"generic {marker}",
        matched_asset=involved.asset_value,
        payload={},
    )
    try:
        async with factory() as db:
            db.add_all([involved, quiet, phishing, breach, dns_row, exposure, generic])
            await db.commit()

        async with factory() as db:
            summary = (await AssetService(db).related_finding_summaries([involved]))[
                involved.id
            ]
            assert summary.total == 5, summary
            assert summary.phishing == 1
            assert summary.breaches == 1  # the mailbox at the monitored domain
            # The module id is `dns` — the rename that gave every connector a
            # `dns-*` name also renamed this counter, and this file never ran in
            # CI before `WI-18` wired it up, so the old spelling went unnoticed.
            assert summary.dns == 1
            assert summary.exposure == 1
            assert summary.findings == 1
            assert summary.last_seen["breaches"] == "2024-01-01"

        async with factory() as db:
            service = AssetService(db)
            with_findings, total = await service.list_assets(
                has_findings=True, limit=200
            )
            values = [asset.asset_value for asset in with_findings]
            assert involved.asset_value in values, values
            assert quiet.asset_value not in values, values
            assert total >= 1

            without_findings, _ = await service.list_assets(
                has_findings=False, limit=200
            )
            quiet_values = [asset.asset_value for asset in without_findings]
            assert quiet.asset_value in quiet_values, quiet_values
            assert involved.asset_value not in quiet_values, quiet_values
    finally:
        async with factory() as db:
            await db.execute(delete(PhishingDomain).where(PhishingDomain.id == phishing.id))
            await db.execute(delete(Breach).where(Breach.id == breach.id))
            await db.execute(delete(DNSObservation).where(DNSObservation.id == dns_row.id))
            await db.execute(delete(SourceObservation).where(SourceObservation.id == exposure.id))
            await db.execute(delete(Finding).where(Finding.id == generic.id))
            await db.execute(delete(Asset).where(Asset.id.in_([involved.id, quiet.id])))
            await db.commit()
        await engine.dispose()
