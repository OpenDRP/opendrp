"""The DNS expiry sweep on PostgreSQL.

Two sweeps started at the same moment must queue one alert rather than two, and
the guarantee is a row lock: SQLite cannot host the race this file exists for.
``REQUIRE_INTEGRATION=1`` (what CI sets) turns a missing database into a failure
instead of a skip, so a misconfigured job cannot report this file as green
without having run it.
"""

import asyncio
import os
from datetime import datetime,timedelta,timezone
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.ext.asyncio import create_async_engine,async_sessionmaker
from sqlalchemy import delete
from app.models import Asset,DNSObservation,DNSExpiryMonitor
from app.services.dns_expiry_service import queue_expiry_alerts

_DATABASE_URL=os.environ.get("INTEGRATION_MIGRATION_DATABASE_URL")
if not _DATABASE_URL:
    _message="set INTEGRATION_MIGRATION_DATABASE_URL to run the DNS expiry sweep tests"
    if os.environ.get("REQUIRE_INTEGRATION")=="1":
        raise RuntimeError(f"{_message} — REQUIRE_INTEGRATION=1 forbids skipping")
    pytest.skip(_message,allow_module_level=True)

# Selected by CI's `-m integration` run and deselected by the SQLite job.
pytestmark=pytest.mark.integration


@pytest.mark.asyncio
async def test_concurrent_expiry_sweeps_queue_once(monkeypatch):
    url=_DATABASE_URL
    engine=create_async_engine(url)
    factory=async_sessionmaker(engine,expire_on_commit=False)
    now=datetime.now(timezone.utc)
    async with factory() as db:
        asset=Asset(asset_type="domain",asset_value="concurrency-expiry.test",normalized_value="concurrency-expiry.test",is_active=True)
        evidence=DNSObservation(observation_key="c"*64,subject=asset.asset_value,source="rdap",observation_type="rdap",first_seen_at=now,last_seen_at=now,status="current",metadata_json={})
        db.add_all([asset,evidence])
        await db.flush()
        monitor=DNSExpiryMonitor(asset_id=asset.id,subject=asset.asset_value,kind="registration",state="verified",checked_at=now,successful_at=now,expires_at=now+timedelta(days=3),observation_id=evidence.id,alerted_thresholds=[])
        db.add(monitor)
        await db.commit()
    entered=asyncio.Event()
    release=asyncio.Event()
    async def enqueue(self,**kwargs):
        entered.set()
        await release.wait()
        return object()
    mock=AsyncMock(side_effect=enqueue)
    # The function descriptor receives self through this wrapper.
    async def wrapper(self,**kwargs):return await mock(self,**kwargs)
    monkeypatch.setattr("app.services.dns_expiry_service.AlertDeliveryService.enqueue",wrapper)
    try:
        async with factory() as first,factory() as second:
            task=asyncio.create_task(queue_expiry_alerts(first,now=now))
            await asyncio.wait_for(entered.wait(),timeout=10)
            assert await queue_expiry_alerts(second,now=now)==0
            release.set()
            assert await task==1
        assert mock.await_count==1
        async with factory() as db:
            saved=await db.get(DNSExpiryMonitor,monitor.id)
            assert saved.alerted_thresholds==[3]
    finally:
        release.set()
        async with factory() as db:
            await db.execute(delete(DNSExpiryMonitor).where(DNSExpiryMonitor.id==monitor.id))
            await db.execute(delete(DNSObservation).where(DNSObservation.id==evidence.id))
            await db.execute(delete(Asset).where(Asset.id==asset.id))
            await db.commit()
        await engine.dispose()
