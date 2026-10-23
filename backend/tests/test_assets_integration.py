import uuid

import pytest


@pytest.mark.anyio
class TestAssetsCreate:
    @pytest.mark.parametrize(
        "asset_type,asset_value,expect_status",
        [
            ("domain", "google.com", 201),
            ("domain", "sub.domain.co.uk", 201),
            ("ip_address", "8.8.8.8", 201),
            ("ip_address", "2001:4860:4860::8888", 201),
            ("email_account", "admin@company.com", 201),
            ("keyword_domain", "mybrand", 201),
            ("keyword_title", "My Official Portal", 201),
            ("domain", "not-a-domain!!!", 422),
            ("ip_address", "999.999.999.999", 422),
            ("email_account", "invalid-email@@.", 422),
            ("keyword_domain", "", 422),
        ],
    )
    async def test_asset_validation_matrix(
        self, client, auth_headers_admin, asset_type, asset_value, expect_status
    ):
        r = await client.post(
            "/api/v1/assets",
            headers=auth_headers_admin,
            json={"asset_type": asset_type, "asset_value": asset_value},
        )
        assert r.status_code == expect_status, f"{asset_type}={asset_value} -> {r.status_code}: {r.text}"
        if expect_status == 201:
            data = r.json()
            assert data["asset_type"] == asset_type
            assert data["asset_value"] == asset_value
            assert data["criticality"] == "medium"
            assert data["is_active"] is True

    async def test_duplicate_domain_returns_409(self, client, auth_headers_admin):
        payload = {"asset_type": "domain", "asset_value": "dup-domain.com"}
        r1 = await client.post("/api/v1/assets", headers=auth_headers_admin, json=payload)
        assert r1.status_code == 201
        r2 = await client.post("/api/v1/assets", headers=auth_headers_admin, json=payload)
        assert r2.status_code == 409

    async def test_asset_values_are_normalized_and_case_duplicates_are_rejected(
        self, client, auth_headers_admin
    ):
        first = await client.post(
            "/api/v1/assets", headers=auth_headers_admin,
            json={"asset_type": "domain", "asset_value": "Example.COM."},
        )
        assert first.status_code == 201
        assert first.json()["asset_value"] == "example.com"
        duplicate = await client.post(
            "/api/v1/assets", headers=auth_headers_admin,
            json={"asset_type": "domain", "asset_value": "EXAMPLE.com"},
        )
        assert duplicate.status_code == 409


@pytest.mark.anyio
class TestAssetsCRUD:
    async def test_get_list_pagination_and_newly_created_in_list(
        self, client, auth_headers_admin
    ):
        await client.post(
            "/api/v1/assets",
            headers=auth_headers_admin,
            json={"asset_type": "domain", "asset_value": "list-check-1.com"},
        )
        r = await client.get("/api/v1/assets?size=5", headers=auth_headers_admin)
        assert r.status_code == 200
        body = r.json()
        assert "items" in body
        assert "total" in body
        assert body["total"] >= 1
        assert body["size"] == 5
        assert len(body["items"]) <= 5

        # One spelling of page size: an unknown parameter cannot silently change
        # how many rows come back.
        ignored = await client.get("/api/v1/assets?limit=5", headers=auth_headers_admin)
        assert ignored.status_code == 200
        assert ignored.json()["size"] == 50

    async def test_get_by_id_404_when_missing(self, client, auth_headers_admin):
        r = await client.get(
            f"/api/v1/assets/{uuid.uuid4()}", headers=auth_headers_admin
        )
        assert r.status_code == 404

    async def test_patch_revalidates_the_existing_type_and_returns_422(self, client, auth_headers_admin):
        created = await client.post(
            "/api/v1/assets", headers=auth_headers_admin,
            json={"asset_type": "ip_address", "asset_value": "192.0.2.10"},
        )
        assert created.status_code == 201
        updated = await client.patch(
            f"/api/v1/assets/{created.json()['id']}",
            headers=auth_headers_admin,
            json={"asset_value": "not-an-ip"},
        )
        assert updated.status_code == 400

    async def test_patch_criticality_updates(self, client, auth_headers_admin):
        r = await client.post(
            "/api/v1/assets",
            headers=auth_headers_admin,
            json={"asset_type": "keyword_domain", "asset_value": "MyBrandX"},
        )
        created_id = r.json()["id"]
        p = await client.patch(
            f"/api/v1/assets/{created_id}",
            headers=auth_headers_admin,
            json={"criticality": "critical", "is_active": False},
        )
        assert p.status_code == 200
        assert p.json()["criticality"] == "critical"
        assert p.json()["is_active"] is False

    async def test_delete_then_get_is_404(self, client, auth_headers_admin):
        r = await client.post(
            "/api/v1/assets",
            headers=auth_headers_admin,
            json={"asset_type": "domain", "asset_value": "delete-me.com"},
        )
        created_id = r.json()["id"]
        d = await client.delete(
            f"/api/v1/assets/{created_id}", headers=auth_headers_admin
        )
        assert d.status_code == 204
        g = await client.get(
            f"/api/v1/assets/{created_id}", headers=auth_headers_admin
        )
        assert g.status_code == 404

    async def test_delete_domain_removes_related_phishing_and_breach_findings(self, client, db_session, auth_headers_admin):
        from datetime import date
        from sqlalchemy import select

        from app.models.breach import Breach
        from app.models.phishing import PhishingDomain

        asset_value = "cascade-domain.example.com"
        created = await client.post(
            "/api/v1/assets",
            headers=auth_headers_admin,
            json={"asset_type": "domain", "asset_value": asset_value},
        )
        assert created.status_code == 201, created.text
        asset_id = created.json()["id"]

        related_phishing = PhishingDomain(
            phishing_domain="lookalike-cascade-domain.example",
            matched_asset=asset_value,
            detection_source="test",
        )
        unrelated_phishing = PhishingDomain(
            phishing_domain="unrelated-cascade-domain.example",
            matched_asset="other-domain.example",
            detection_source="test",
        )
        related_breach = Breach(
            breach_name="CascadeDomainBreach",
            title="CascadeDomainBreach",
            domain="example.com",
            breach_date=date(2024, 1, 1),
            matched_domain=asset_value,
        )
        unrelated_breach = Breach(
            breach_name="UnrelatedCascadeDomainBreach",
            title="UnrelatedCascadeDomainBreach",
            domain="example.com",
            breach_date=date(2024, 1, 1),
            matched_domain="other-domain.example",
        )
        db_session.add_all([
            related_phishing,
            unrelated_phishing,
            related_breach,
            unrelated_breach,
        ])
        await db_session.commit()

        deleted = await client.delete(
            f"/api/v1/assets/{asset_id}?cascade_findings=true",
            headers=auth_headers_admin,
        )
        assert deleted.status_code == 204, deleted.text

        related_phishing_id = related_phishing.id
        related_breach_id = related_breach.id
        unrelated_phishing_id = unrelated_phishing.id
        unrelated_breach_id = unrelated_breach.id
        db_session.expire_all()
        assert await db_session.get(PhishingDomain, related_phishing_id) is None
        assert await db_session.get(Breach, related_breach_id) is None
        assert await db_session.get(PhishingDomain, unrelated_phishing_id) is not None
        assert await db_session.get(Breach, unrelated_breach_id) is not None

        from app.models.audit import AuditLog
        audit = (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "asset.delete")
            )
        ).scalars().one()
        assert audit.details["phishing_findings_deleted"] == 1
        assert audit.details["breach_findings_deleted"] == 1
        assert audit.details["generic_findings_deleted"] == 0

    async def test_delete_without_cascade_preserves_related_findings(self, client, db_session, auth_headers_admin):
        from datetime import date

        from app.models.breach import Breach
        from app.models.phishing import PhishingDomain

        asset_value = "preserve-findings.example.com"
        created = await client.post(
            "/api/v1/assets",
            headers=auth_headers_admin,
            json={"asset_type": "domain", "asset_value": asset_value},
        )
        assert created.status_code == 201, created.text
        asset_id = created.json()["id"]

        phishing = PhishingDomain(
            phishing_domain="preserve-findings-phishing.example",
            matched_asset=asset_value,
            detection_source="test",
        )
        breach = Breach(
            breach_name="PreservedBreach",
            title="PreservedBreach",
            domain="example.com",
            breach_date=date(2024, 1, 1),
            matched_domain=asset_value,
        )
        db_session.add_all([phishing, breach])
        await db_session.commit()
        phishing_id = phishing.id
        breach_id = breach.id

        deleted = await client.delete(
            f"/api/v1/assets/{asset_id}", headers=auth_headers_admin
        )
        assert deleted.status_code == 204, deleted.text
        db_session.expire_all()
        assert await db_session.get(PhishingDomain, phishing_id) is not None
        assert await db_session.get(Breach, breach_id) is not None

    async def test_delete_keyword_title_with_cascade_removes_related_findings(self, client, db_session, auth_headers_admin):
        from app.models.phishing import PhishingDomain

        asset_value = "KEDEN"
        created = await client.post(
            "/api/v1/assets",
            headers=auth_headers_admin,
            json={"asset_type": "keyword_title", "asset_value": asset_value},
        )
        assert created.status_code == 201, created.text
        asset_id = created.json()["id"]
        finding = PhishingDomain(
            phishing_domain="185.129.51.198",
            matched_asset=asset_value,
            detection_source="shodan_title",
        )
        db_session.add(finding)
        await db_session.commit()
        finding_id = finding.id

        deleted = await client.delete(
            f"/api/v1/assets/{asset_id}?cascade_findings=true",
            headers=auth_headers_admin,
        )
        assert deleted.status_code == 204, deleted.text
        db_session.expire_all()
        assert await db_session.get(PhishingDomain, finding_id) is None

    async def test_delete_email_asset_removes_related_breach_findings(self, client, db_session, auth_headers_admin):
        from datetime import date

        from app.models.breach import Breach

        asset_value = "cascade-user@example.com"
        created = await client.post(
            "/api/v1/assets",
            headers=auth_headers_admin,
            json={"asset_type": "email_account", "asset_value": asset_value},
        )
        assert created.status_code == 201, created.text
        asset_id = created.json()["id"]

        related = Breach(
            breach_name="CascadeEmailBreach",
            title="CascadeEmailBreach",
            domain="example.com",
            breach_date=date(2024, 1, 1),
            matched_email=asset_value,
        )
        unrelated = Breach(
            breach_name="UnrelatedCascadeEmailBreach",
            title="UnrelatedCascadeEmailBreach",
            domain="example.com",
            breach_date=date(2024, 1, 1),
            matched_email="other@example.com",
        )
        db_session.add_all([related, unrelated])
        await db_session.commit()

        deleted = await client.delete(
            f"/api/v1/assets/{asset_id}?cascade_findings=true",
            headers=auth_headers_admin,
        )
        assert deleted.status_code == 204, deleted.text
        related_id = related.id
        unrelated_id = unrelated.id
        db_session.expire_all()
        assert await db_session.get(Breach, related_id) is None
        assert await db_session.get(Breach, unrelated_id) is not None

    async def test_viewer_delete_rejected(self, client, auth_headers_admin, auth_headers_viewer):
        r = await client.post(
            "/api/v1/assets",
            headers=auth_headers_admin,
            json={"asset_type": "domain", "asset_value": "protected-by-rbac.com"},
        )
        created_id = r.json()["id"]
        d = await client.delete(
            f"/api/v1/assets/{created_id}", headers=auth_headers_viewer
        )
        assert d.status_code == 403


@pytest.mark.anyio
class TestAssetTypeIsNotRetyped:
    """A type change is an operation, not a side effect of a patch.

    Reproduced defect: ``PATCH {"asset_type": "keyword_domain"}`` alone answered
    200 and turned a monitored domain into a keyword. The per-type value rules
    could not run — they only see a value the payload carries — so the row's
    existing value was re-interpreted under another type: it dropped out of DNS
    and breach matching, and the scanners were handed a different inventory. The
    audit row meanwhile recorded only that some field had changed.
    """

    async def test_a_type_change_without_a_new_value_is_refused(
        self, client, auth_headers_admin
    ):
        created = await client.post(
            "/api/v1/assets",
            headers=auth_headers_admin,
            json={"asset_type": "domain", "asset_value": "retyped.example.com"},
        )
        assert created.status_code == 201
        asset_id = created.json()["id"]

        retyped = await client.patch(
            f"/api/v1/assets/{asset_id}",
            headers=auth_headers_admin,
            json={"asset_type": "keyword_domain"},
        )
        assert retyped.status_code == 400

        unchanged = await client.get(
            f"/api/v1/assets/{asset_id}", headers=auth_headers_admin
        )
        assert unchanged.json()["asset_type"] == "domain"

    async def test_a_type_change_with_a_value_for_the_new_type_is_audited(
        self, client, db_session, auth_headers_admin
    ):
        """The explicit form still exists, and the trail says what moved."""
        from sqlalchemy import select

        from app.models.audit import AuditLog

        created = await client.post(
            "/api/v1/assets",
            headers=auth_headers_admin,
            json={"asset_type": "domain", "asset_value": "explicit-retype.example.com"},
        )
        asset_id = created.json()["id"]

        retyped = await client.patch(
            f"/api/v1/assets/{asset_id}",
            headers=auth_headers_admin,
            json={"asset_type": "keyword_domain", "asset_value": "explicit-retype"},
        )
        assert retyped.status_code == 200
        assert retyped.json()["asset_type"] == "keyword_domain"

        rows = list(
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "asset.update")
                )
            ).scalars()
        )
        details = [
            row for row in rows if str(row.details.get("asset_id")) == asset_id
        ][-1].details
        assert details["changes"]["asset_type"] == {
            "from": "domain",
            "to": "keyword_domain",
        }
        assert details["changes"]["asset_value"]["to"] == "explicit-retype"


@pytest.mark.anyio
class TestAssetAuditDetails:
    """What the trail says, in the shape a SIEM index can filter.

    Reproduced defects: ``asset.update`` recorded only the request's field names,
    so the audit page rendered "Updated asset <uuid>"; and ``asset.create``
    recorded ``"AssetType.domain"`` — the ``str()`` of the enum member — where the
    promotion routes recorded ``"domain"`` for the same fact.
    """

    async def _details_for(self, db_session, action: str, asset_id: str) -> dict:
        from sqlalchemy import select

        from app.models.audit import AuditLog

        rows = list(
            (
                await db_session.execute(select(AuditLog).where(AuditLog.action == action))
            ).scalars()
        )
        mine = [row for row in rows if str(row.details.get("asset_id")) == asset_id]
        assert mine, f"no {action} row for {asset_id}"
        return mine[-1].details

    async def test_create_records_the_plain_type_and_the_value(
        self, client, db_session, auth_headers_admin
    ):
        created = await client.post(
            "/api/v1/assets",
            headers=auth_headers_admin,
            json={"asset_type": "domain", "asset_value": "Audit-Shape.example.com"},
        )
        asset_id = created.json()["id"]
        details = await self._details_for(db_session, "asset.create", asset_id)
        assert details["asset_type"] == "domain"
        assert details["asset_value"] == "audit-shape.example.com"
        assert details["criticality"] == "medium"
        assert details["is_active"] is True

    async def test_update_records_what_changed_with_before_and_after(
        self, client, db_session, auth_headers_admin
    ):
        created = await client.post(
            "/api/v1/assets",
            headers=auth_headers_admin,
            json={"asset_type": "domain", "asset_value": "audit-update.example.com"},
        )
        asset_id = created.json()["id"]
        await client.patch(
            f"/api/v1/assets/{asset_id}",
            headers=auth_headers_admin,
            json={"criticality": "high"},
        )
        details = await self._details_for(db_session, "asset.update", asset_id)
        assert details["asset_value"] == "audit-update.example.com"
        assert details["changed_fields"] == ["criticality"]
        assert details["changes"]["criticality"] == {"from": "medium", "to": "high"}

    async def test_patch_of_other_fields_preserves_legacy_asset_identity(
        self, client, db_session, auth_headers_admin
    ):
        """A metadata-only PATCH must not silently canonicalize legacy rows.

        Older rows can retain operator-entered spelling with no normalized
        value. The pre-fix update path normalized the identity on every PATCH,
        while the audit listed only the metadata field as changed.
        """
        from app.models.asset import Asset, AssetType

        legacy = Asset(
            asset_type=AssetType.domain,
            asset_value="Legacy.Example.COM.",
            normalized_value=None,
            criticality="medium",
            is_active=True,
        )
        db_session.add(legacy)
        await db_session.commit()
        await db_session.refresh(legacy)
        asset_id = str(legacy.id)

        updated = await client.patch(
            f"/api/v1/assets/{asset_id}",
            headers=auth_headers_admin,
            json={"criticality": "high"},
        )
        assert updated.status_code == 200, updated.text
        assert updated.json()["asset_value"] == "Legacy.Example.COM."
        assert updated.json()["normalized_value"] is None

        details = await self._details_for(db_session, "asset.update", asset_id)
        assert details["changed_fields"] == ["criticality"]
        assert details["changes"] == {"criticality": {"from": "medium", "to": "high"}}

    async def test_an_explicit_legacy_identity_change_is_normalized_and_audited(
        self, client, db_session, auth_headers_admin
    ):
        """Identity canonicalization occurs on an identity edit, not by surprise."""
        from app.models.asset import Asset, AssetType

        legacy = Asset(
            asset_type=AssetType.domain,
            asset_value="Legacy.Edit.Example.COM.",
            normalized_value=None,
            criticality="medium",
            is_active=True,
        )
        db_session.add(legacy)
        await db_session.commit()
        await db_session.refresh(legacy)
        asset_id = str(legacy.id)

        updated = await client.patch(
            f"/api/v1/assets/{asset_id}",
            headers=auth_headers_admin,
            json={"asset_value": "New.Example.COM."},
        )
        assert updated.status_code == 200, updated.text
        assert updated.json()["asset_value"] == "new.example.com"
        details = await self._details_for(db_session, "asset.update", asset_id)
        assert details["changed_fields"] == ["asset_value"]
        assert details["changes"]["asset_value"] == {
            "from": "Legacy.Edit.Example.COM.",
            "to": "new.example.com",
        }

    async def test_the_list_filter_is_recorded_as_the_plain_type(
        self, client, db_session, auth_headers_admin
    ):
        from sqlalchemy import select

        from app.models.audit import AuditLog

        await client.get(
            "/api/v1/assets?asset_type=domain&size=1", headers=auth_headers_admin
        )
        rows = list(
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "asset.list")
                )
            ).scalars()
        )
        matched = [row for row in rows if row.details.get("asset_type") == "domain"]
        assert matched, "the asset_type filter was recorded as something other than 'domain'"

    async def test_an_exposure_promotion_records_its_provider(
        self, client, db_session, auth_headers_analyst
    ):
        """The other promotion route: same fields, its own source (WI-13).

        Exposure promotions are the ones an operator is most likely to need to
        retrace: a shared IP or CDN address does not prove ownership, and the
        provider that observed it is part of judging whether it does.
        """
        from datetime import datetime, timezone

        from app.models.source_observation import SourceObservation

        now = datetime.now(timezone.utc)
        observation = SourceObservation(
            module="exposure",
            source="netlas",
            observation_key=uuid.uuid4().hex,
            subject="promoted-exposure.example.com",
            matched_asset="promoted-exposure.example.com",
            first_seen_at=now,
            last_seen_at=now,
            status="observed",
            payload={},
        )
        db_session.add(observation)
        await db_session.commit()

        promoted = await client.post(
            f"/api/v1/exposure/observations/{observation.id}/asset",
            headers=auth_headers_analyst,
        )
        assert promoted.status_code == 201, promoted.text
        assert promoted.json()["source"] == "netlas"
        asset_id = promoted.json()["asset"]["id"]
        details = await self._details_for(db_session, "exposure.asset.promoted", asset_id)
        assert details["promoted_from"] == "exposure"
        assert details["source"] == "netlas"
        assert details["subject"] == "promoted-exposure.example.com"
        assert details["asset_type"] == "domain"
        assert details["criticality"] == "medium"
        assert details["already_exists"] is False

        # Promoting the same observation twice reports the existing asset with
        # the same traceability, so the second click is as explainable as the first.
        again = await client.post(
            f"/api/v1/exposure/observations/{observation.id}/asset",
            headers=auth_headers_analyst,
        )
        assert again.status_code == 201 and again.json()["already_exists"] is True
        existing_details = await self._details_for(
            db_session, "exposure.asset.already_exists", asset_id
        )
        assert existing_details["source"] == "netlas"
        assert existing_details["criticality"] == "medium"

    async def test_promotion_records_the_same_plain_type_as_asset_create(
        self, client, db_session, auth_headers_admin, auth_headers_analyst
    ):
        """One spelling of the type across every action that writes it.

        ``asset.create`` logged the ``str()`` of the enum member while the DNS
        promotion route logged ``"domain"`` for the same fact, so a SIEM rule on
        ``details.asset_type`` matched only some of the writes.
        """
        from datetime import datetime, timezone

        from app.models.dns_observation import DNSObservation

        now = datetime.now(timezone.utc)
        observation = DNSObservation(
            source="resolver",
            observation_type="dns_record",
            observation_key=f"a:{uuid.uuid4().hex}",
            subject="promoted-format.example.com",
            record_type="A",
            value="203.0.113.11",
            first_seen_at=now,
            last_seen_at=now,
            status="current",
            metadata_json={},
        )
        db_session.add(observation)
        await db_session.commit()

        promoted = await client.post(
            f"/api/v1/dns-security/observations/{observation.id}/asset",
            headers=auth_headers_analyst,
        )
        assert promoted.status_code == 201, promoted.text
        promoted_details = await self._details_for(
            db_session, "dns_security.asset.promoted", promoted.json()["asset"]["id"]
        )
        assert promoted_details["asset_type"] == "domain"
        # WI-13: the promotion is traceable to the observation that produced it,
        # so the durable answer to "where did this asset come from" is the trail
        # and not only a toast that disappears.
        assert promoted_details["promoted_from"] == "dns_security"
        assert promoted_details["source"] == "resolver"
        assert promoted_details["observation_type"] == "dns_record"
        assert promoted_details["asset_value"] == "promoted-format.example.com"
        assert promoted_details["criticality"] == "medium"
        assert promoted.json()["source"] == "resolver"

        created = await client.post(
            "/api/v1/assets",
            headers=auth_headers_admin,
            json={"asset_type": "domain", "asset_value": "promoted-format-two.example.com"},
        )
        created_details = await self._details_for(
            db_session, "asset.create", created.json()["id"]
        )
        assert created_details["asset_type"] == promoted_details["asset_type"]


class TestAssetFindings:
    """WI-12 / AST-22: the asset → findings direction.

    The relationship used to be observable one way only: a finding named its
    asset, while the asset said nothing about what it was involved in, so an
    operator had to search four modules by hand. These tests pin that the view
    reports what the cascade would delete — the same matching rule, not a second
    interpretation of it.
    """

    async def _asset(self, db_session, value="findings.example"):
        from app.models.asset import Asset, AssetType
        from app.schemas.asset import normalize_asset_value

        asset = Asset(
            asset_type=AssetType.domain,
            asset_value=value,
            normalized_value=normalize_asset_value("domain", value),
            is_active=True,
        )
        db_session.add(asset)
        await db_session.commit()
        await db_session.refresh(asset)
        return asset

    async def _related_rows(self, db_session, *, domain="findings.example"):
        """One row per module plus one row that must *not* be counted."""
        from datetime import date, datetime, timezone

        from app.models.breach import Breach
        from app.models.dns_observation import DNSObservation
        from app.models.finding import Finding
        from app.models.phishing import PhishingDomain
        from app.models.source_observation import SourceObservation

        now = datetime.now(timezone.utc)
        db_session.add_all(
            [
                # Case differs from the asset on purpose: the shared rule is the
                # only reason this row is linked at all.
                PhishingDomain(
                    phishing_domain="look-alike.example",
                    matched_asset="Findings.Example",
                    detection_source="dnstwist",
                ),
                # Breach about a mailbox at the monitored domain — the
                # email-to-domain rule, which the cascade applies too.
                Breach(
                    breach_name="Br-findings",
                    title="T",
                    domain=domain,
                    breach_date=date(2024, 1, 1),
                    pwn_count=10,
                    matched_email=f"analyst@{domain}",
                ),
                # A breach about somewhere else entirely.
                Breach(
                    breach_name="Br-elsewhere",
                    title="T",
                    domain="not-monitored.test",
                    breach_date=date(2024, 1, 1),
                    pwn_count=10,
                    matched_domain="not-monitored.test",
                ),
                DNSObservation(
                    source="resolver",
                    observation_type="dns_record",
                    observation_key=f"a:{uuid.uuid4().hex}",
                    subject=domain,
                    record_type="A",
                    value="203.0.113.30",
                    first_seen_at=now,
                    last_seen_at=now,
                    status="current",
                    metadata_json={},
                ),
                SourceObservation(
                    module="exposure",
                    source="shodan",
                    observation_key=uuid.uuid4().hex,
                    subject="203.0.113.31",
                    matched_asset=domain,
                    first_seen_at=now,
                    last_seen_at=now,
                    status="observed",
                    payload={},
                ),
                Finding(
                    module="phishing",
                    finding_kind="phishing_domain",
                    connector_name="dnstwist",
                    dedup_key=uuid.uuid4().hex,
                    title="generic finding",
                    matched_asset=domain,
                    payload={},
                ),
            ]
        )
        await db_session.commit()

    async def test_counters_and_rows_use_the_shared_matching_rule(
        self, client, db_session, auth_headers_admin
    ):
        asset = await self._asset(db_session)
        await self._related_rows(db_session)

        listed = await client.get(
            f"/api/v1/assets/{asset.id}/findings", headers=auth_headers_admin
        )
        assert listed.status_code == 200, listed.text
        body = listed.json()
        assert body["counts"] == {
            "phishing": 1,
            "breaches": 1,
            "dns": 1,
            "exposure": 1,
            "findings": 1,
            "total": 5,
        }
        # The default tab is the first module in the documented order.
        assert body["module"] == "phishing"
        assert [item["module"] for item in body["items"]] == ["phishing"]
        # The shape the asset page renders: changing it silently would leave the
        # UI with empty cells rather than a failing build.
        assert set(body["items"][0]) == {
            "id",
            "module",
            "title",
            "matched_asset",
            "source",
            "status",
            "observed_at",
        }
        assert set(body) == {
            "asset",
            "counts",
            # When each module last saw a finding about this asset (WI-20); a
            # date-only moment (a breach disclosure) and a timestamp are both
            # published as text, so the client never compares the two kinds.
            "last_seen",
            "module",
            "items",
            "total",
            "page",
            "size",
            "pages",
        }
        assert set(body["last_seen"]) == {
            "phishing",
            "breaches",
            "dns",
            "exposure",
            "findings",
        }
        assert body["last_seen"]["phishing"], body["last_seen"]

        breaches = await client.get(
            f"/api/v1/assets/{asset.id}/findings",
            headers=auth_headers_admin,
            params={"module": "breaches"},
        )
        assert breaches.status_code == 200
        assert [item["matched_asset"] for item in breaches.json()["items"]] == [
            "analyst@findings.example"
        ]
        assert breaches.json()["total"] == 1

    async def test_an_asset_nothing_matches_reports_zeros(
        self, client, db_session, auth_headers_admin
    ):
        asset = await self._asset(db_session, "quiet.example")
        await self._related_rows(db_session)

        body = (
            await client.get(
                f"/api/v1/assets/{asset.id}/findings", headers=auth_headers_admin
            )
        ).json()
        assert body["counts"] == {
            "phishing": 0,
            "breaches": 0,
            "dns": 0,
            "exposure": 0,
            "findings": 0,
            "total": 0,
        }
        assert body["items"] == []

    async def test_the_view_is_viewer_plus_and_404s_on_unknown_assets(
        self, client, db_session, auth_headers_viewer
    ):
        asset = await self._asset(db_session)
        url = f"/api/v1/assets/{asset.id}/findings"
        assert (await client.get(url)).status_code == 401
        assert (await client.get(url, headers=auth_headers_viewer)).status_code == 200
        unknown = f"/api/v1/assets/{uuid.uuid4()}/findings"
        assert (await client.get(unknown, headers=auth_headers_viewer)).status_code == 404

    async def test_an_unknown_module_is_refused(self, client, db_session, auth_headers_viewer):
        asset = await self._asset(db_session)
        refused = await client.get(
            f"/api/v1/assets/{asset.id}/findings",
            headers=auth_headers_viewer,
            params={"module": "everything"},
        )
        assert refused.status_code == 422

    async def test_the_view_is_audited_with_the_counters(
        self, client, db_session, auth_headers_admin
    ):
        from sqlalchemy import select

        from app.models.audit import AuditLog

        asset = await self._asset(db_session)
        await self._related_rows(db_session)
        await client.get(f"/api/v1/assets/{asset.id}/findings", headers=auth_headers_admin)

        rows = list(
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "asset.findings.list")
                )
            ).scalars()
        )
        assert rows, "the asset → findings view left no audit row"
        details = rows[-1].details
        assert details["asset_value"] == "findings.example"
        assert details["module"] == "phishing"
        assert details["counts"]["total"] == 5
