"""The operator surface over Design B: review state and scope exceptions.

``test_tls_identities.py`` pins the sweep and ``test_tls_identity_service_gaps.py``
the scoping rules behind it. This file pins the HTTP routes the DNS Security page
calls, because a verdict an analyst records here is what keeps the next sweep quiet
and an exception an admin records here is what keeps a shared CDN out of the alerts.
"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.models.audit import AuditLog
from app.models.tls_certificate import CertificateScopeException, TLSCertificateIdentity, TLSCertificateSighting

NOW = datetime.now(timezone.utc)
CERTIFICATES = "/api/v1/dns-security/certificates"
EXCEPTIONS = "/api/v1/dns-security/certificate-exceptions"


def identity(fingerprint: str, **kwargs) -> TLSCertificateIdentity:
    values = {
        "fingerprint_sha256": fingerprint,
        "origin": "our_probe",
        "first_seen_at": NOW - timedelta(days=30),
        "last_seen_at": NOW,
        "san_dns": ["shop.example.com"],
        "issuer_dn": "CN=Example CA",
    }
    values.update(kwargs)
    return TLSCertificateIdentity(**values)


def sighting(row: TLSCertificateIdentity, **kwargs) -> TLSCertificateSighting:
    values = {
        "identity_id": row.id,
        "subject": "shop.example.com",
        "source": "shodan",
        "observed_at": NOW,
        "first_seen_at": NOW,
        "last_seen_at": NOW,
        "is_ours": False,
        "signals": {},
        "verdict": "candidate",
        "confidence": 0,
    }
    values.update(kwargs)
    return TLSCertificateSighting(**values)


@pytest.mark.asyncio
async def test_the_review_list_groups_sightings_and_filters_on_the_verdict(
    client, db_session, auth_headers_analyst, auth_headers_viewer
):
    """One certificate, two places it was seen, and a verdict that filters both.

    The page asks a different question than the sweep: "which certificates have a
    sighting in this state" rather than "what fired", so the filter has to narrow
    the *identities* and the total has to be the total of that narrowed set.
    """
    certificate = identity("a" * 64)
    db_session.add(certificate)
    await db_session.flush()
    own = sighting(certificate, ip="203.0.113.10", port=443, source="tlsprobe", is_ours=True)
    foreign = sighting(certificate, ip="198.51.100.7", port=443, source="shodan")
    db_session.add_all([own, foreign])
    # A second certificate with no sighting in the reviewed state is what the filter
    # must drop rather than return with an empty sighting list.
    bystander = identity("b" * 64)
    db_session.add(bystander)
    await db_session.flush()
    db_session.add(sighting(bystander, ip="198.51.100.8", source="shodan"))
    await db_session.commit()

    assert (await client.get(CERTIFICATES)).status_code == 401
    listed = await client.get(CERTIFICATES, headers=auth_headers_viewer)
    assert listed.status_code == 200
    payload = listed.json()
    assert payload["total"] == 2 and payload["pages"] == 1
    item = next(row for row in payload["items"] if row["fingerprint_sha256"] == "a" * 64)
    assert item["issuer_dn"] == "CN=Example CA"
    assert item["foreign_sightings"] == 1
    assert {row["ip"] for row in item["sightings"]} == {"203.0.113.10", "198.51.100.7"}

    reviewed_state = (await client.get(CERTIFICATES, headers=auth_headers_viewer, params={"verdict": "confirmed_foreign"})).json()
    assert reviewed_state["total"] == 0
    foreign_only = (await client.get(CERTIFICATES, headers=auth_headers_viewer, params={"foreign_only": "true"})).json()
    assert {row["fingerprint_sha256"] for row in foreign_only["items"]} == {"a" * 64, "b" * 64}
    paged = (await client.get(CERTIFICATES, headers=auth_headers_viewer, params={"size": 1, "page": 2})).json()
    assert paged["pages"] == 2 and len(paged["items"]) == 1

    target = f"{CERTIFICATES}/sightings/{foreign.id}"
    assert (await client.patch(target, headers=auth_headers_viewer, json={"verdict": "confirmed_foreign"})).status_code == 403
    assert (
        await client.patch(
            f"{CERTIFICATES}/sightings/{uuid4()}", headers=auth_headers_analyst, json={"verdict": "expected"}
        )
    ).status_code == 404
    assert (await client.patch(target, headers=auth_headers_analyst, json={"verdict": "maybe"})).status_code == 422
    reviewed = await client.patch(
        target, headers=auth_headers_analyst, json={"verdict": "confirmed_foreign", "note": "  old   edge  "}
    )
    assert reviewed.status_code == 200
    assert reviewed.json()["verdict"] == "confirmed_foreign"
    assert reviewed.json()["reviewed_at"]

    confirmed = (await client.get(CERTIFICATES, headers=auth_headers_viewer, params={"verdict": "confirmed_foreign"})).json()
    assert confirmed["total"] == 1
    stored = next(row for row in confirmed["items"][0]["sightings"] if row["id"] == str(foreign.id))
    assert stored["review_note"] == "old edge"

    audit = (await db_session.execute(select(AuditLog).where(AuditLog.action == "tls.sighting.confirmed_foreign"))).scalars().all()
    assert len(audit) == 1
    assert audit[0].user_id is not None and audit[0].ip_address
    assert audit[0].details["ip"] == "198.51.100.7"
    assert audit[0].details["note"] == "  old   edge  "


@pytest.mark.asyncio
async def test_a_certificate_and_its_sightings_answer_the_fields_the_page_declares(
    client, db_session, auth_headers_viewer
):
    """Plan 037: the review list was `PaginatedResponse[dict]` until now.

    Both levels are asserted whole, because the client declares both: a rename inside
    the nested sighting fails here rather than in `CertificateTriage`.
    """
    certificate = identity("c" * 64)
    db_session.add(certificate)
    await db_session.flush()
    db_session.add(
        sighting(
            certificate,
            ip="203.0.113.20",
            port=8443,
            source="shodan",
            signals={"org": "Example", "subjects": ["shop.example.com", "www.example.com"]},
        )
    )
    await db_session.commit()

    payload = (await client.get(CERTIFICATES, headers=auth_headers_viewer)).json()

    assert set(payload) == {"items", "total", "page", "size", "pages"}
    row = payload["items"][0]
    assert set(row) == {
        "id",
        "fingerprint_sha256",
        "fingerprint_sha1",
        "spki_sha256",
        "serial_hex",
        "subject_dn",
        "issuer_dn",
        "not_before",
        "not_after",
        "san_dns",
        "key_algo",
        "origin",
        "first_seen_at",
        "last_seen_at",
        "sightings",
        "foreign_sightings",
    }
    sight = row["sightings"][0]
    assert set(sight) == {
        "id",
        "subject",
        "subjects",
        "ip",
        "port",
        "source",
        "is_ours",
        "confidence",
        "signals",
        "verdict",
        "first_seen_at",
        "last_seen_at",
        "reviewed_at",
        "review_note",
    }
    # The hostnames a rule iterates (AUD-037) and the provider's facts are published
    # beside the endpoint they belong to, not flattened into the certificate.
    assert sight["subjects"] == ["shop.example.com", "www.example.com"]
    assert sight["signals"]["org"] == "Example"
    assert sight["verdict"] == "candidate"
    assert sight["reviewed_at"] is None and sight["review_note"] is None
    # A field the certificate does not carry is null rather than absent or empty.
    assert row["fingerprint_sha1"] is None and row["not_after"] is None
    assert row["san_dns"] == ["shop.example.com"]
    assert row["foreign_sightings"] == 1


@pytest.mark.asyncio
async def test_scope_exceptions_are_admin_decisions_that_say_why(
    client, db_session, auth_headers_admin, auth_headers_analyst, auth_headers_viewer
):
    """An exception is a statement with a reason, a lifetime and an author.

    It is also the one place a rule can be told to stay quiet, so the routes refuse a
    decision that could never match, keep one row per decision, and leave a trail that
    says who allowed what.
    """
    assert (await client.get(EXCEPTIONS, headers=auth_headers_viewer)).json() == []
    denied = await client.post(
        EXCEPTIONS, headers=auth_headers_analyst, json={"match_kind": "ip", "match_value": "198.51.100.7"}
    )
    assert denied.status_code == 403

    created = await client.post(
        EXCEPTIONS,
        headers=auth_headers_admin,
        json={"match_kind": "fingerprint", "match_value": "A" * 64, "reason": "Customer CDN"},
    )
    assert created.status_code == 201
    payload = created.json()
    assert payload["match_value"] == "a" * 64 and payload["reason"] == "Customer CDN"
    assert payload["expires_at"] is None

    # Re-stating the decision updates it in place: a second row with the same match
    # would make "which reason applies" ambiguous.
    renewed = await client.post(
        EXCEPTIONS,
        headers=auth_headers_admin,
        json={"match_kind": "fingerprint", "match_value": "a" * 64, "reason": "Customer CDN, renewed"},
    )
    assert renewed.status_code == 201 and renewed.json()["id"] == payload["id"]
    rows = list((await db_session.execute(select(CertificateScopeException))).scalars())
    assert len(rows) == 1 and rows[0].reason == "Customer CDN, renewed"

    bad_digest = await client.post(
        EXCEPTIONS, headers=auth_headers_admin, json={"match_kind": "spki", "match_value": "abc"}
    )
    assert bad_digest.status_code == 400 and "SHA-256" in bad_digest.json()["detail"]
    unproduced = await client.post(
        EXCEPTIONS, headers=auth_headers_admin, json={"match_kind": "asn", "match_value": "64500"}
    )
    assert unproduced.status_code == 400 and "none is enabled" in unproduced.json()["detail"]
    assert (
        await client.post(EXCEPTIONS, headers=auth_headers_admin, json={"match_kind": "serial", "match_value": "0a"})
    ).status_code == 422

    expired = await client.post(
        EXCEPTIONS,
        headers=auth_headers_admin,
        json={
            "match_kind": "ip",
            "match_value": "198.51.100.7",
            "reason": "Temporary partner range",
            "expires_at": (NOW - timedelta(days=1)).isoformat(),
        },
    )
    assert expired.status_code == 201
    listed = (await client.get(EXCEPTIONS, headers=auth_headers_viewer)).json()
    assert sorted(item["expired"] for item in listed) == [False, True]
    assert next(item for item in listed if item["match_kind"] == "ip")["expires_at"]

    assert (await client.delete(f"{EXCEPTIONS}/{uuid4()}", headers=auth_headers_admin)).status_code == 404
    assert (await client.delete(f"{EXCEPTIONS}/{payload['id']}", headers=auth_headers_analyst)).status_code == 403
    assert (await client.delete(f"{EXCEPTIONS}/{payload['id']}", headers=auth_headers_admin)).status_code == 204
    remaining = (await client.get(EXCEPTIONS, headers=auth_headers_viewer)).json()
    assert [item["match_kind"] for item in remaining] == ["ip"]

    added = (await db_session.execute(select(AuditLog).where(AuditLog.action == "tls.exception.added"))).scalars().all()
    assert len(added) == 3 and all(row.user_id and row.ip_address for row in added)
    removed = (await db_session.execute(select(AuditLog).where(AuditLog.action == "tls.exception.removed"))).scalars().all()
    assert len(removed) == 1 and removed[0].details["match_kind"] == "fingerprint"
