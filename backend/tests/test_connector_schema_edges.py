"""The connector wire schema's sanitizers and refusals, at the boundary.

Coverage batch 03. A connector payload is untrusted even when the connector is a
first-party container, and this module is where it stops being trusted: the
attribute sanitizer, the text cleaner, the host/domain validators, and the four
finding shapes. The branches here are the difference between a refused payload
and one that stores a control character, a nested object, or a 20 kB blob in a
JSON column.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal

import pytest
from pydantic import ValidationError

from app.schemas.connector import (
    BreachCatalogueEntry,
    BreachFinding,
    DNSObservationPayload,
    ExposureFinding,
    PhishingFinding,
    _clean_text,
    _validate_host_or_ip,
    sanitize_attributes,
)


class TestSanitizeAttributes:
    def test_absent_attributes_and_absent_values_are_dropped(self):
        assert sanitize_attributes(None) == {}
        assert sanitize_attributes({"note": None}) == {}

    def test_a_non_object_is_refused_or_dropped(self):
        with pytest.raises(ValueError, match="must be an object"):
            sanitize_attributes("not-an-object")
        assert sanitize_attributes("not-an-object", strict=False) == {}

    def test_control_characters_are_refused_or_stripped(self):
        with pytest.raises(ValueError, match="control characters"):
            sanitize_attributes({"note": "a\x00b"})
        assert sanitize_attributes({"note": "a\x00b"}, strict=False) == {"note": "ab"}

    def test_an_invalid_key_is_refused_or_dropped(self):
        with pytest.raises(ValueError, match="lowercase identifier"):
            sanitize_attributes({"Bad Key": "x"})
        assert sanitize_attributes({"Bad Key": "x"}, strict=False) == {}

    def test_the_key_count_is_bounded(self):
        payload = {f"key{index}": index for index in range(33)}
        with pytest.raises(ValueError, match="more than"):
            sanitize_attributes(payload)
        assert len(sanitize_attributes(payload, strict=False)) == 32

    def test_list_items_are_cleaned_and_truncated(self):
        parsed = sanitize_attributes(
            {"tags": [{"nested": 1}, None, " ok ", 123, "x" * 300]},
            strict=False,
        )
        assert parsed["tags"] == ["ok", "123", "x" * 255]

    def test_a_long_scalar_is_refused_or_truncated(self):
        with pytest.raises(ValueError, match="too long"):
            sanitize_attributes({"note": "x" * 2001})
        assert sanitize_attributes({"note": "x" * 2001}, strict=False)["note"] == (
            "x" * 2000
        )

    def test_non_string_scalars_are_stringified_only_on_the_service_path(self):
        stamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
        parsed = sanitize_attributes(
            {
                "stamp": stamp,
                "id": uuid.UUID("00000000-0000-0000-0000-000000000001"),
                "amount": Decimal("1.5"),
                "nested": {"not": "a scalar"},
            },
            strict=False,
        )
        assert parsed["stamp"] == str(stamp)
        assert parsed["amount"] == "1.5"
        assert "nested" not in parsed


class TestTextHelpers:
    def test_absent_and_blank_text(self):
        assert _clean_text(None, field_name="x") is None
        assert _clean_text("   ", field_name="x") is None
        with pytest.raises(ValueError, match="control characters"):
            _clean_text("a\rb", field_name="x")

    def test_a_host_or_ip_must_parse(self):
        assert _validate_host_or_ip(None, field_name="domain") is None
        assert _validate_host_or_ip("   ", field_name="domain") is None
        assert _validate_host_or_ip("Example.COM", field_name="domain") == "example.com"
        with pytest.raises(ValueError, match="invalid hostname or IP"):
            _validate_host_or_ip("not a host", field_name="domain")


class TestPhishing:
    def test_metadata_is_strict(self):
        with pytest.raises(ValidationError, match="lowercase identifier"):
            PhishingFinding(
                phishing_domain="evil.example",
                matched_asset="example.com",
                metadata={"Bad Key": "x"},
            )

    def test_an_ip_address_must_parse(self):
        assert (
            PhishingFinding(
                phishing_domain="evil.example",
                matched_asset="example.com",
                ip_address="   ",
            ).ip_address
            is None
        )
        with pytest.raises(ValidationError, match="invalid IP address"):
            PhishingFinding(
                phishing_domain="evil.example",
                matched_asset="example.com",
                ip_address="not-an-ip",
            )

    def test_the_empty_domain_refusal_is_kept_for_a_direct_caller(self):
        with pytest.raises(ValueError, match="must not be empty"):
            PhishingFinding.validate_phishing_domain("   ")


class TestDnsObservation:
    def test_unknown_type_record_type_and_status_are_refused(self):
        with pytest.raises(ValidationError, match="unsupported DNS observation type"):
            DNSObservationPayload(observation_type="made_up", subject="example.com")
        with pytest.raises(ValidationError, match="unsupported DNS record type"):
            DNSObservationPayload(
                observation_type="dns_record",
                subject="example.com",
                record_type="HINFO",
            )
        with pytest.raises(ValidationError, match="unsupported DNS observation status"):
            DNSObservationPayload(
                observation_type="dns_record", subject="example.com", status="gone"
            )

    def test_an_empty_subject_refusal_is_kept_for_a_direct_caller(self):
        with pytest.raises(ValueError, match="must not be empty"):
            DNSObservationPayload._valid_subject("   ")

    def test_a_subject_that_cannot_be_idna_encoded_is_refused(self):
        with pytest.raises(ValidationError, match="invalid IDNA encoding"):
            DNSObservationPayload(
                observation_type="dns_record", subject="\u200b.example.com"
            )

    def test_a_valid_subject_is_normalised(self):
        payload = DNSObservationPayload(
            observation_type="dns_record",
            subject="EXample.COM.",
            record_type="tls:8443",
            value="   ",
            expires_at=datetime(2026, 1, 1),
        )
        assert payload.subject == "example.com"
        assert payload.record_type == "TLS:8443"
        assert payload.value is None
        assert payload.expires_at.tzinfo is not None

    def test_metadata_is_bounded(self):
        with pytest.raises(ValidationError, match="metadata payload is too large"):
            DNSObservationPayload(
                observation_type="dns_record",
                subject="example.com",
                metadata={f"key{index}": "x" * 2000 for index in range(6)},
            )


class TestExposure:
    def test_metadata_is_strict_and_text_is_cleaned(self):
        finding = ExposureFinding(
            subject="Example.COM",
            matched_asset="example.com",
            port=443,
            protocol="   ",
        )
        assert finding.subject == "example.com"
        assert finding.protocol is None
        with pytest.raises(ValidationError, match="lowercase identifier"):
            ExposureFinding(
                subject="example.com",
                matched_asset="example.com",
                port=443,
                metadata={"Bad Key": "x"},
            )


class TestBreach:
    def test_the_empty_name_refusal_is_kept_for_a_direct_caller(self):
        with pytest.raises(ValueError, match="must not be empty"):
            BreachFinding.validate_breach_name("   ")

    def test_title_and_domain_are_cleaned(self):
        finding = BreachFinding(
            breach_name="Leak",
            title="   ",
            domain="",
            description="   ",
            matched_domain="Example.COM",
        )
        assert finding.title == ""
        assert finding.domain == ""
        assert finding.description is None
        assert finding.matched_domain == "example.com"

    def test_an_invalid_domain_is_refused(self):
        with pytest.raises(ValidationError, match="invalid hostname or IP"):
            BreachFinding(breach_name="Leak", domain="not a host")

    def test_attributes_are_bounded(self):
        with pytest.raises(ValidationError, match="attributes payload is too large"):
            BreachFinding(
                breach_name="Leak",
                matched_email="user@example.com",
                attributes={f"key{index}": "x" * 2000 for index in range(11)},
            )


class TestCatalogueEntry:
    def test_title_and_domain_are_cleaned_and_attributes_are_bounded(self):
        entry = BreachCatalogueEntry(breach_name="Leak", title="  ", domain="")
        assert entry.title == ""
        assert entry.domain == ""
        with pytest.raises(ValueError, match="must not be empty"):
            BreachCatalogueEntry.validate_breach_name("   ")
        with pytest.raises(ValidationError, match="attributes payload is too large"):
            BreachCatalogueEntry(
                breach_name="Leak",
                attributes={f"key{index}": "x" * 2000 for index in range(11)},
            )
