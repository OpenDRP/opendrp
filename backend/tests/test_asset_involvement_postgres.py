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

AWI-06 lives here too: ``test_the_has_findings_filter_is_measured_on_postgres``
is the measurement harness the assets plan requires before the filter's shape is
changed. It seeds a dataset sized by ``ASSET_MEASURE_ASSETS`` (default 200) and
``ASSET_MEASURE_FINDINGS`` (default 500), times the three service reads the plan
names (``has_findings=true``, ``has_findings=false``, an unfiltered page) and
prints ``EXPLAIN (ANALYZE, BUFFERS)`` for a page and for the candidate
``NOT EXISTS`` semi-join. It asserts only that the plans were produced and the
filter's answers are correct; timings are printed, never asserted. Run it with
``-s`` and record the numbers (and the dataset size) in
``docs/internal/assets-remediation-plan-2026-10-17.md`` §9.
"""

import os
import time
import uuid
from datetime import date, datetime, timezone

import pytest
from sqlalchemy import delete, text
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


#: AWI-06 dataset size. The default keeps CI bounded; an operator repeating the
#: plan's measurement sets these to the documented 50000 and 1000000.
_MEASURE_ASSETS = max(10, min(int(os.environ.get("ASSET_MEASURE_ASSETS", "200")), 50_000))
_MEASURE_FINDINGS = max(
    10, min(int(os.environ.get("ASSET_MEASURE_FINDINGS", "500")), 1_000_000)
)


async def _explain(db, label: str, statement: str) -> str:
    """Print one ``EXPLAIN (ANALYZE, BUFFERS)`` and return the plan text."""
    rows = (
        await db.execute(text(f"EXPLAIN (ANALYZE, BUFFERS) {statement}"))
    ).scalars().all()
    plan = "\n".join(rows)
    print(f"\n[AWI-06 {label}]\n{plan}")
    # ANALYZE is what makes the numbers real; a plain EXPLAIN would end with the
    # plan and no execution line, which is exactly the case a planner-only
    # report would silently hide.
    assert "Execution Time" in plan, f"EXPLAIN did not ANALYZE {label}"
    return plan


async def test_the_has_findings_filter_is_measured_on_postgres():
    """AWI-06: the numbers that decide the filter's shape, on a real database.

    The three service reads the plan names are timed on the same dataset
    (``has_findings=true``, ``has_findings=false`` and a plain page), and the
    page and candidate ``NOT EXISTS`` statements are printed as plans. The
    harness asserts only that every plan was produced and that the filter's
    answers are still correct — a wall-clock threshold on shared CI hardware
    would fail for reasons unrelated to the query. The numbers belong in the
    plan's §9.1, with the dataset size, because the absolute milliseconds depend
    on the host.
    """
    from app.models.phishing import PhishingDomain

    engine = create_async_engine(_DATABASE_URL)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    marker = f"measure-{uuid.uuid4().hex[:8]}"
    involved_value = f"{marker}-involved.example"
    quiet_value = f"{marker}-quiet.example"
    involved = Asset(
        asset_type="domain",
        asset_value=involved_value,
        normalized_value=involved_value,
        is_active=True,
    )
    quiet = Asset(
        asset_type="domain",
        asset_value=quiet_value,
        normalized_value=quiet_value,
        is_active=True,
    )
    link = PhishingDomain(
        phishing_domain=f"look-alike-{marker}.example",
        matched_asset=involved_value,
        detection_source="dnstwist",
    )
    try:
        async with factory() as db:
            db.add_all([involved, quiet, link])
            await db.commit()
            # The filler is written set-based rather than as ORM objects: the
            # plan's dataset is 50k assets and 1M findings, and a million
            # `PhishingDomain` instances would cost more memory than the query
            # under measurement. `generate_series` is PostgreSQL-only, which is
            # what this file already requires. Both tables carry server
            # defaults for `id`, `created_at` and the row defaults below.
            #
            # The measurement database is a throwaway seed, so durability is not
            # worth its cost here: with `synchronous_commit` on, flushing the
            # million-row insert through the trigram index took longer than the
            # dataset outlives. This affects only the seeding transaction.
            await db.execute(text("SET LOCAL synchronous_commit = off"))
            await db.execute(
                text(
                    "INSERT INTO assets (asset_type, asset_value, normalized_value) "
                    "SELECT 'domain', "
                    "       :marker || '-' || to_char(i, 'FM00000') || '.example', "
                    "       :marker || '-' || to_char(i, 'FM00000') || '.example' "
                    "FROM generate_series(1, :count) AS i"
                ),
                {"marker": marker, "count": _MEASURE_ASSETS},
            )
            # Findings are spread over the seeded assets, so the semi-join has to
            # answer for a table that is much larger than the page and not
            # trivially empty.
            await db.execute(
                text(
                    "INSERT INTO drp_phishing_domains "
                    "       (phishing_domain, matched_asset, detection_source) "
                    "SELECT 'filler-' || :marker || '-' || to_char(i, 'FM000000') || '.example', "
                    "       :marker || '-' || to_char((i % :count) + 1, 'FM00000') || '.example', "
                    "       'dnstwist' "
                    "FROM generate_series(1, :findings) AS i"
                ),
                {"marker": marker, "count": _MEASURE_ASSETS, "findings": _MEASURE_FINDINGS},
            )
            await db.commit()

        async with factory() as db:
            print(
                f"\n[AWI-06 dataset] assets={_MEASURE_ASSETS + 2} "
                f"phishing_findings={_MEASURE_FINDINGS + 1}"
            )
            # 1. The three reads the plan names, through the service the API
            #    calls. Timed rather than EXPLAINed: the cost of the old filter
            #    was mostly outside SQL (every asset row loaded into Python and
            #    summarised), and a plan of `SELECT * FROM assets` would have
            #    missed it entirely.
            service = AssetService(db)

            async def _timed(label: str, call) -> None:
                started = time.perf_counter()
                await call
                elapsed = (time.perf_counter() - started) * 1000
                print(f"\n[AWI-06 service {label}] {elapsed:.0f} ms")

            await _timed(
                "filter=true",
                service.list_assets(has_findings=True, limit=20),
            )
            await _timed(
                "filter=false",
                service.list_assets(has_findings=False, limit=20),
            )
            await _timed("page", service.list_assets(limit=20))

            # 2. A page of the list, which the filter wraps in an IN (...).
            await _explain(
                db,
                "page",
                "SELECT * FROM assets ORDER BY created_at DESC, id DESC LIMIT 20",
            )
            # 3. The candidate shape: one set-based NOT EXISTS, whose inner side
            #    compares the expression `ix_drp_phishing_domains_matched_asset_key`
            #    indexes. This is what AWI-07 would replace the inventory load with.
            await _explain(
                db,
                "filter=candidate NOT EXISTS",
                "SELECT a.id FROM assets a WHERE NOT EXISTS ("
                "SELECT 1 FROM drp_phishing_domains p "
                "WHERE lower(rtrim(trim(p.matched_asset), '.')) = "
                "lower(rtrim(trim(coalesce(a.normalized_value, a.asset_value)), '.'))"
                ")",
            )

            # The answers must stay correct whichever shape AWI-07 picks; asking
            # for each seeded value keeps the assertion independent of the page
            # size and of the number of fixture assets.
            involved_true, _ = await service.list_assets(
                has_findings=True, search=involved_value, limit=200
            )
            quiet_true, _ = await service.list_assets(
                has_findings=True, search=quiet_value, limit=200
            )
            quiet_false, _ = await service.list_assets(
                has_findings=False, search=quiet_value, limit=200
            )
            involved_false, _ = await service.list_assets(
                has_findings=False, search=involved_value, limit=200
            )

            assert [asset.asset_value for asset in involved_true] == [involved_value]
            assert quiet_true == []
            assert [asset.asset_value for asset in quiet_false] == [quiet_value]
            assert involved_false == []
    finally:
        async with factory() as db:
            await db.execute(
                delete(PhishingDomain).where(
                    PhishingDomain.matched_asset.like(f"{marker}%")
                )
            )
            await db.execute(
                delete(PhishingDomain).where(
                    PhishingDomain.phishing_domain.like(f"%{marker}%")
                )
            )
            await db.execute(delete(Asset).where(Asset.asset_value.like(f"{marker}%")))
            await db.commit()
        await engine.dispose()
