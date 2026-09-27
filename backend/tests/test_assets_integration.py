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
