"""Promoting a breach or phishing finding into the monitored inventory (AWI-13).

The DNS and exposure modules already answer "take this under monitoring". A
breach row names the mailbox that was exposed and a phishing candidate names the
look-alike; both are values the module itself matched, and both used to require
retyping the value on the assets page. These tests pin the promotion path:

* the created asset has the type the finding implies;
* the audit action is ``<module>.asset.promoted``, with the finding it came from;
* a second request on an already-monitored value is not an error and is recorded
  as ``already_exists`` rather than a silent success;
* a viewer cannot change the inventory.
"""

from __future__ import annotations

import uuid
from datetime import date

import pytest
from sqlalchemy import select

from app.core.audit import AuditLog
from app.models import Asset, AssetType, Breach, DrpPhishingDomain


def _breach(**overrides) -> Breach:
    values = dict(
        source_id="hibp",
        breach_name="ExampleBreach",
        title="Example Breach",
        domain="example.com",
        breach_date=date(2024, 1, 1),
        pwn_count=10,
        data_classes=["Email addresses"],
        matched_email="analyst@example.com",
        matched_domain="example.com",
    )
    values.update(overrides)
    return Breach(**values)


@pytest.mark.asyncio
async def test_a_breach_promotes_the_mailbox_it_names(
    client, db_session, auth_headers_analyst
):
    breach = _breach()
    db_session.add(breach)
    await db_session.commit()

    response = await client.post(
        f"/api/v1/breaches/{breach.id}/asset", headers=auth_headers_analyst
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["already_exists"] is False
    assert body["asset"]["asset_type"] == "email_account"
    assert body["asset"]["asset_value"] == "analyst@example.com"

    asset = (
        await db_session.execute(
            select(Asset).where(Asset.id == uuid.UUID(body["asset"]["id"]))
        )
    ).scalar_one()
    assert asset.asset_type == AssetType.email_account

    audit = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "breaches.asset.promoted")
        )
    ).scalar_one()
    assert audit.details["breach_id"] == str(breach.id)
    assert audit.details["promoted_from"] == "breaches"
    assert audit.details["asset_value"] == "analyst@example.com"


@pytest.mark.asyncio
async def test_a_breach_without_a_mailbox_promotes_its_domain(
    client, db_session, auth_headers_analyst
):
    breach = _breach(matched_email=None, matched_domain="corp.example")
    db_session.add(breach)
    await db_session.commit()

    response = await client.post(
        f"/api/v1/breaches/{breach.id}/asset", headers=auth_headers_analyst
    )

    assert response.status_code == 201, response.text
    assert response.json()["asset"]["asset_type"] == "domain"
    assert response.json()["asset"]["asset_value"] == "corp.example"


@pytest.mark.asyncio
async def test_a_repeat_promotion_is_audited_as_already_monitored(
    client, db_session, auth_headers_analyst
):
    breach = _breach()
    db_session.add(breach)
    await db_session.commit()
    url = f"/api/v1/breaches/{breach.id}/asset"

    first = await client.post(url, headers=auth_headers_analyst)
    second = await client.post(url, headers=auth_headers_analyst)

    assert first.status_code == 201, first.text
    assert second.status_code == 201, second.text
    assert second.json()["already_exists"] is True
    assert second.json()["asset"]["id"] == first.json()["asset"]["id"]

    audit = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "breaches.asset.already_exists"
            )
        )
    ).scalar_one()
    assert audit.details["asset_id"] == first.json()["asset"]["id"]


@pytest.mark.asyncio
async def test_a_phishing_candidate_promotes_its_domain(
    client, db_session, auth_headers_analyst
):
    threat = DrpPhishingDomain(
        phishing_domain="examp1e.com",
        matched_asset="example.com",
        detection_source="dnstwist",
    )
    db_session.add(threat)
    await db_session.commit()

    response = await client.post(
        f"/api/v1/phishing/threats/{threat.id}/asset", headers=auth_headers_analyst
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["already_exists"] is False
    assert body["asset"]["asset_type"] == "domain"
    assert body["asset"]["asset_value"] == "examp1e.com"

    audit = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "phishing.asset.promoted")
        )
    ).scalar_one()
    assert audit.details["threat_id"] == str(threat.id)
    assert audit.details["promoted_from"] == "phishing"


@pytest.mark.asyncio
async def test_a_viewer_cannot_promote(client, db_session, auth_headers_viewer):
    breach = _breach()
    db_session.add(breach)
    await db_session.commit()

    response = await client.post(
        f"/api/v1/breaches/{breach.id}/asset", headers=auth_headers_viewer
    )

    assert response.status_code == 403
    assert (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "breaches.asset.promoted")
        )
    ).scalar_one_or_none() is None
