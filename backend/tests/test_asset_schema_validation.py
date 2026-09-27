"""Asset input validation.

``asset_value`` is valid or not *depending on* ``asset_type``, which is what
makes this worth testing rather than trusting a single regex: ``1.2.3.4`` is a
fine IP and a fine keyword, but it is not a domain, and an operator pasting a
mailbox into the wrong type has to be told so at the edge rather than when a scan
silently matches nothing.

The same rules apply to updates: a client that changes an asset's type and value
together must be validated against the new type.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.schemas.asset import AssetCreate, AssetUpdate


def _create(asset_type: str, value: str, **extra):
    return AssetCreate(asset_type=asset_type, asset_value=value, **extra)


def _update(asset_type: str, value: str):
    return AssetUpdate(asset_type=asset_type, asset_value=value)


class TestAcceptedValues:
    @pytest.mark.parametrize(
        ("asset_type", "value"),
        [
            ("domain", "example.com"),
            ("domain", "a-b.corp.example.co.uk"),
            ("ip_address", "192.0.2.10"),
            ("ip_address", "2001:db8::1"),
            ("email_account", "analyst@example.com"),
            ("email_account", "admin@localdomain.local"),
            ("keyword_domain", "acme-phishing"),
            ("keyword_title", "  Sign in  "),
        ],
    )
    def test_valid_values_by_type(self, asset_type, value):
        asset = _create(asset_type, value)
        assert asset.asset_value == value
        assert asset.criticality == "medium"
        assert asset.is_active is True


class TestRejectedValues:
    @pytest.mark.parametrize(
        ("asset_type", "value", "fragment"),
        [
            ("domain", "not a domain", "Invalid domain format"),
            ("domain", "localhost", "Invalid domain format"),
            ("domain", "http://example.com", "Invalid domain format"),
            ("ip_address", "999.999.999.999", "Invalid IP address format"),
            ("ip_address", "example.com", "Invalid IP address format"),
            ("email_account", "not-an-email", "Invalid email format"),
            ("keyword_domain", "   ", "Keyword cannot be empty"),
            ("keyword_title", "", "Keyword cannot be empty"),
        ],
    )
    def test_invalid_values_are_refused_with_a_reason(self, asset_type, value, fragment):
        with pytest.raises(ValidationError) as excinfo:
            _create(asset_type, value)
        assert fragment in str(excinfo.value)

    def test_a_value_longer_than_the_column_is_refused(self):
        with pytest.raises(ValidationError):
            _create("keyword_title", "x" * 513)

    def test_an_unknown_type_is_refused(self):
        with pytest.raises(ValidationError):
            AssetCreate(asset_type="subdomain", asset_value="a.example.com")

    def test_an_unknown_criticality_is_refused(self):
        with pytest.raises(ValidationError):
            _create("domain", "example.com", criticality="urgent")


class TestTypeCoercion:
    def test_an_enum_instance_is_accepted_for_the_type(self):
        from app.models.asset import AssetType

        asset = AssetCreate(asset_type=AssetType.domain, asset_value="example.com")
        # Stored as the plain string, so JSON/DB round-trips do not depend on the
        # enum class staying importable at the same path.
        assert asset.asset_type == "domain"

    def test_an_enum_instance_is_accepted_for_criticality(self):
        class _Criticality:
            value = "high"

        asset = _create("domain", "example.com", criticality=_Criticality())
        assert asset.criticality == "high"

    def test_an_unknown_enum_value_falls_through_to_validation(self):
        class _Type:
            value = "subdomain"

        with pytest.raises(ValidationError):
            AssetCreate(asset_type=_Type(), asset_value="a.example.com")


class TestNormalization:
    @pytest.mark.parametrize(
        ("asset_type", "value"),
        [
            ("domain", " Example.COM. "),
            ("domain", "bücher.example"),
            ("email_account", "Admin@EXAMPLE.COM"),
            ("ip_address", "2001:0db8:0:0:0:0:0:1"),
            ("keyword_domain", " Brand " ),
        ],
    )
    def test_normalization_is_idempotent_for_canonical_values(self, asset_type, value):
        from app.schemas.asset import validate_and_normalize_asset_value

        first = validate_and_normalize_asset_value(asset_type, value)
        assert validate_and_normalize_asset_value(asset_type, first) == first

    def test_domain_normalization_is_type_aware(self):
        from app.schemas.asset import validate_and_normalize_asset_value

        assert validate_and_normalize_asset_value("domain", " Example.COM. ") == "example.com"
        assert validate_and_normalize_asset_value("email_account", "Admin@EXAMPLE.COM") == "Admin@example.com"
        assert validate_and_normalize_asset_value("ip_address", "2001:0db8:0:0:0:0:0:1") == "2001:db8::1"


class TestUpdates:
    def test_matching_type_and_value_are_accepted(self):
        update = _update("ip_address", "192.0.2.10")
        assert update.asset_value == "192.0.2.10"

    def test_a_mismatched_value_is_refused(self):
        with pytest.raises(ValidationError) as excinfo:
            _update("domain", "192.0.2.10")
        assert "Invalid domain format" in str(excinfo.value)

    def test_a_value_without_a_type_is_left_to_the_service(self):
        """A partial update cannot be validated here: the type lives in the row."""
        update = AssetUpdate(asset_value="anything at all")
        assert update.asset_value == "anything at all"

    def test_an_empty_patch_is_allowed(self):
        update = AssetUpdate()
        assert update.model_dump(exclude_unset=True) == {}

    def test_toggling_activity_alone_is_allowed(self):
        update = AssetUpdate(is_active=False)
        assert update.is_active is False
        assert update.asset_value is None
