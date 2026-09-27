"""Breach findings are provider-neutral.

Breach storage used to model one vendor's catalogue: six classification flags
plus a masked secret, a logo path and the source's own timestamps were
first-class columns, so a different breach source had to be squeezed into that
shape. Those belong to the *source*, not to the core, and now travel in a
validated ``attributes`` payload alongside the fields every source can supply.

These tests pin both halves of that contract: what the core stores, and what it
refuses to model.
"""

import uuid
from datetime import date

import pytest
import pytest_asyncio
from sqlalchemy import select

from app.models import Breach, Connector
from app.schemas.connector import BreachFinding
from app.services.connector_credentials import ConnectorCredentials


def _connector_headers(token: str, name: str) -> dict[str, str]:
    """Headers carrying a connector's own credential (no shared secret exists)."""
    return {"X-Connector-Token": token, "X-Connector-Name": name}


@pytest_asyncio.fixture()
async def breaches_connector(db_session):
    connector = Connector(
        name=f"conn-breach-{uuid.uuid4().hex[:8]}",
        connector_type="breaches",
        status="enabled",
        default_job_type="breaches.test",
    )
    db_session.add(connector)
    await db_session.commit()
    await db_session.refresh(connector)
    return connector

_VENDOR_COLUMNS = (
    "is_verified",
    "is_fabricated",
    "is_sensitive",
    "is_retired",
    "is_spam_list",
    "is_malware",
    "masked_password",
    "logo_path",
    "added_date",
    "modified_date",
)


# ---------------------------------------------------------------------------
# Wire contract
# ---------------------------------------------------------------------------


class TestWireContract:
    def test_a_source_may_declare_its_own_payload(self):
        # Nothing here resembles the previously modelled vendor: a source id, a
        # confidence score, its own tags and a classification of its own naming.
        finding = BreachFinding(
            breach_name="Vault Leak",
            matched_domain="corp.example",
            attributes={
                "source_id": "VL-2026-1",
                "confidence": 0.9,
                "tags": ["credentials", "internal"],
                "catalog_state": "published",
            },
        )
        assert finding.attributes["source_id"] == "VL-2026-1"
        assert finding.attributes["confidence"] == 0.9
        assert finding.attributes["tags"] == ["credentials", "internal"]

    def test_a_source_field_belongs_in_attributes_or_nowhere(self):
        # The wire shape and the stored shape are the same shape: a field the
        # core does not model has exactly one place to live, and a source that
        # sends it at the top level is told so instead of being reinterpreted.
        finding = BreachFinding(
            breach_name="Source specific",
            matched_email="user@corp.example",
            attributes={"is_verified": True, "confidence": 0.9},
        )
        assert finding.attributes == {"is_verified": True, "confidence": 0.9}
        with pytest.raises(ValueError):
            BreachFinding(
                breach_name="Top level", matched_email="user@corp.example", is_verified=True
            )

    def test_unknown_top_level_fields_are_still_rejected(self):
        # Neutralizing the payload must not turn the schema into a free-form bag:
        # only the core's own fields are accepted outside ``attributes``.
        with pytest.raises(ValueError):
            BreachFinding(breach_name="L", matched_email="a@b.example", vendor_flag=True)

    def test_attribute_keys_must_be_identifiers(self):
        with pytest.raises(ValueError):
            BreachFinding(breach_name="L", attributes={"Bad-Key": "x"})
        with pytest.raises(ValueError):
            BreachFinding(breach_name="L", attributes={"1leading": "x"})

    def test_attribute_values_must_be_scalars_or_string_lists(self):
        with pytest.raises(ValueError):
            BreachFinding(breach_name="L", attributes={"nested": {"a": 1}})
        with pytest.raises(ValueError):
            BreachFinding(breach_name="L", attributes={"deep": [[1, 2]]})

    def test_attribute_payload_is_bounded(self):
        with pytest.raises(ValueError):
            BreachFinding(breach_name="L", attributes={f"key_{i}": i for i in range(40)})
        with pytest.raises(ValueError):
            BreachFinding(breach_name="L", attributes={"blob": "x" * 5000})

    def test_attribute_values_are_control_character_free(self):
        # Control characters split log and alert lines, so they never survive
        # the protocol boundary — not even as part of an otherwise fine value.
        for raw in ("clean\r\nline", "bad\x00value"):
            with pytest.raises(ValueError):
                BreachFinding(breach_name="L", attributes={"note": raw})


# ---------------------------------------------------------------------------
# Storage contract
# ---------------------------------------------------------------------------


class TestStorageContract:
    def test_model_has_no_vendor_specific_columns(self):
        columns = {column.name for column in Breach.__table__.columns}
        for gone in _VENDOR_COLUMNS:
            assert gone not in columns, f"{gone} is a provider field, not core data"
        assert "attributes" in columns

    def test_core_no_longer_models_the_vendor_api_payload(self):
        # The upstream REST payload schema belonged to the core when the core
        # called that API itself; scanning lives in connector containers now.
        import app.schemas.breaches as breach_schemas

        assert not hasattr(breach_schemas, "HibpBreachExternal")
        assert not hasattr(breach_schemas, "HibpBreachResponse")

    @pytest.mark.asyncio
    async def test_ingest_persists_declared_attributes(
        self, db_session, breaches_connector, monkeypatch
    ):
        from app.services.ingestion_service import ingest_breach_finding

        monkeypatch.setattr(
            "app.services.ingestion_service.AlertDeliveryService.enqueue",
            _never_called,
        )
        ok = await ingest_breach_finding(
            db_session,
            breaches_connector,
            {
                "breach_name": "Generalized",
                "matched_email": "analyst@generalized.example",
                "breach_date": "2026-02-03",
                "pwn_count": 42,
                "data_classes": ["Emails"],
                "attributes": {"source_id": "GEN-9", "confidence": 0.75},
            },
        )
        assert ok is True
        row = (
            await db_session.execute(
                select(Breach).where(Breach.breach_name == "Generalized")
            )
        ).scalar_one()
        assert row.attributes == {"source_id": "GEN-9", "confidence": 0.75}
        # Neutral columns are unaffected by the generalization.
        assert row.pwn_count == 42
        assert row.data_classes == ["Emails"]

    @pytest.mark.asyncio
    async def test_ingest_re_sanitizes_attributes_for_direct_callers(
        self, db_session, breaches_connector, monkeypatch
    ):
        from app.services.ingestion_service import ingest_breach_finding

        monkeypatch.setattr(
            "app.services.ingestion_service.AlertDeliveryService.enqueue",
            _never_called,
        )
        ok = await ingest_breach_finding(
            db_session,
            breaches_connector,
            {
                "breach_name": "DirectRisky",
                "matched_email": "risky@direct.example",
                # A service caller can hand over anything; the payload is still
                # filtered before it reaches the JSON column.
                "attributes": {"ok_key": "value", "Bad-Key": "dropped", "nested": {"a": 1}},
            },
        )
        assert ok is True
        row = (
            await db_session.execute(
                select(Breach).where(Breach.breach_name == "DirectRisky")
            )
        ).scalar_one()
        assert row.attributes == {"ok_key": "value"}


async def _never_called(*args, **kwargs):  # pragma: no cover - assertion helper
    raise AssertionError("alert fan-out must not be reached in these tests")


# ---------------------------------------------------------------------------
# API surface
# ---------------------------------------------------------------------------


class TestApiSurface:
    @pytest.mark.asyncio
    async def test_breach_response_exposes_attributes_not_vendor_fields(
        self, db_session, client, auth_headers_admin
    ):
        db_session.add(
            Breach(
                breach_name="ApiNeutral",
                title="Api Neutral",
                domain="neutral.example",
                breach_date=date(2026, 1, 1),
                matched_email="user@neutral.example",
                data_classes=["Emails"],
                attributes={"source_id": "N-1", "is_verified": True},
            )
        )
        await db_session.commit()

        resp = await client.get("/api/v1/breaches", headers=auth_headers_admin)
        assert resp.status_code == 200
        item = [i for i in resp.json()["items"] if i["breach_name"] == "ApiNeutral"][0]
        assert item["attributes"] == {"source_id": "N-1", "is_verified": True}
        for gone in _VENDOR_COLUMNS:
            assert gone not in item, f"{gone} leaked back into the API response"

    @pytest.mark.asyncio
    async def test_findings_endpoint_accepts_a_new_sources_payload(self, db_session, client):
        """End-to-end: a connector submits its own shape over HTTP."""
        connector = Connector(
            name="newsource",
            connector_type="breaches",
            default_job_type="breaches.newsource",
            manifest={
                "module": "breaches",
                "job_type": "breaches.newsource",
                "finding_kind": "breach",
                "asset_types": [],
                "config_schema": {},
            },
        )
        db_session.add(connector)
        await db_session.commit()
        # The connector authenticates with its own credential, so the row and
        # the token are provisioned together (as the admin API/CLI does).
        token, _ = await ConnectorCredentials(db_session).issue(connector)

        from app.services.job_service import JobService

        await JobService(db_session).create_job(
            job_type="breaches.newsource",
            created_by=None,
            title="Newsource scan",
            params={"connector": "newsource", "module": "breaches"},
        )
        await db_session.commit()
        # Ownership is a lease now: the connector claims the work through the
        # protocol and submits the findings under the token that claim returned.
        from app.services.connector_service import ConnectorService

        job = await ConnectorService(db_session).claim_work(connector)
        assert job is not None and job.lease_token

        resp = await client.post(
            f"/api/v1/connectors/me/findings/{job.id}",
            headers={**_connector_headers(token, "newsource"), "X-Connector-Lease": job.lease_token},
            json=[
                {
                    "breach_name": "Newsource Leak",
                    "matched_domain": "newsource.example",
                    "attributes": {"feed": "underground-forum", "records": 1200},
                }
            ],
        )
        assert resp.status_code == 200, resp.text
        assert resp.json() == {"accepted": 1, "rejected": 0}

        row = (
            await db_session.execute(
                select(Breach).where(Breach.breach_name == "Newsource Leak")
            )
        ).scalar_one()
        assert row.attributes == {"feed": "underground-forum", "records": 1200}
