"""The manifest boundary's refusals, one branch at a time.

Coverage batch 03. A connector's manifest is untrusted input that becomes the
core's description of what the connector may do, so each normalizer is a
security decision: a job type that overlaps another connector's, an unknown
asset section, a config key nobody may set, or a coercion that silently turns
"false" into truthy text. The tests call the normalizers directly — that is the
boundary that owns the rule — and assert the message names the offending field.
"""

from __future__ import annotations

import pytest

from app.core.exceptions import BadRequestException
from app.services import connector_manifest as manifest
from app.services.connector_manifest import (
    ConfigField,
    ModuleSpec,
    _clean_attributes,
    _coerce_field,
    finding_adapter_for,
    normalize_asset_types,
    normalize_config_schema,
    normalize_declared_fields,
    normalize_dedup_fields,
    normalize_finding_kind,
    normalize_job_type,
    normalize_module_id,
    provisioning_job_type,
    validate_connector_config,
)


class TestIdentifiers:
    def test_module_and_finding_kind_refuse_a_non_identifier(self):
        with pytest.raises(BadRequestException, match="module must be"):
            normalize_module_id("Bad ID")
        with pytest.raises(BadRequestException, match="finding_kind must be"):
            normalize_finding_kind("Bad Kind")

    def test_a_job_type_is_bounded(self):
        with pytest.raises(BadRequestException, match="at most"):
            normalize_job_type("a." + "b" * manifest.MAX_JOB_TYPE_LEN)

    def test_a_reserved_job_type_names_the_connector_and_module(self):
        with pytest.raises(BadRequestException, match="cannot reserve"):
            provisioning_job_type("bad module!", "worker")


class TestAssetTypes:
    def test_a_scalar_is_not_a_list(self):
        with pytest.raises(BadRequestException, match="must be a list"):
            normalize_asset_types("domain")

    def test_the_list_is_bounded(self):
        with pytest.raises(BadRequestException, match="at most"):
            normalize_asset_types(["domain"] * (manifest.MAX_ASSET_TYPES + 1))


class TestConfigSchema:
    def test_a_non_object_is_refused(self):
        with pytest.raises(BadRequestException, match="must be an object"):
            normalize_config_schema("not-a-schema")

    def test_the_schema_is_bounded(self):
        with pytest.raises(BadRequestException, match="at most"):
            normalize_config_schema(
                {
                    f"field{index}": {"type": "str"}
                    for index in range(manifest.MAX_CONFIG_SCHEMA_FIELDS + 1)
                }
            )

    def test_a_config_key_must_be_a_lowercase_identifier(self):
        with pytest.raises(BadRequestException, match="lowercase identifier"):
            normalize_config_schema({"Bad Key": {"type": "str"}})

    def test_a_parsed_field_is_accepted_as_is(self):
        parsed = normalize_config_schema(
            {"enabled": ConfigField(type="bool", label="Enabled")}
        )
        assert parsed["enabled"]["type"] == "bool"

    def test_an_invalid_field_is_named(self):
        with pytest.raises(BadRequestException, match="config field 'enabled' is invalid"):
            normalize_config_schema({"enabled": {"type": "not-a-type"}})

    def test_a_label_is_bounded(self):
        with pytest.raises(BadRequestException, match="label is too long"):
            normalize_config_schema(
                {"enabled": {"type": "bool", "label": "x" * 121}}
            )


class TestDeclaredFields:
    def test_a_non_object_is_refused(self):
        with pytest.raises(BadRequestException, match="fields must be an object"):
            normalize_declared_fields("not-fields")

    def test_the_schema_is_bounded(self):
        with pytest.raises(BadRequestException, match="at most"):
            normalize_declared_fields(
                {
                    f"field{index}": {"type": "str"}
                    for index in range(manifest.MAX_DECLARED_FIELDS + 1)
                }
            )

    def test_a_label_is_bounded(self):
        with pytest.raises(BadRequestException, match="label is too long"):
            normalize_declared_fields({"field": {"type": "str", "label": "x" * 121}})


class TestDedupFields:
    def test_a_non_list_is_refused(self):
        with pytest.raises(BadRequestException, match="must be a list"):
            normalize_dedup_fields("field")

    def test_a_name_must_be_an_identifier(self):
        with pytest.raises(BadRequestException, match="invalid dedup field"):
            normalize_dedup_fields(["Bad Name"])


class TestAttributeCleaner:
    def test_no_attributes_is_an_empty_mapping(self):
        assert _clean_attributes(None, None) == {}


class TestAdapterSelection:
    def test_an_adapter_the_core_does_not_implement_has_no_validator(self):
        spec = ModuleSpec(
            id="custom",
            label="Custom",
            description="",
            finding_kind="generic",
            asset_types=(),
            storage={"adapter": "no-such-adapter"},
        )
        assert finding_adapter_for(spec) is None


class TestCoercion:
    def test_bool_accepts_bool_and_its_text_spelling(self):
        field = {"type": "bool"}
        assert _coerce_field("flag", field, True) is True
        assert _coerce_field("flag", field, " TRUE ") is True
        assert _coerce_field("flag", field, "false") is False
        with pytest.raises(BadRequestException, match="must be a boolean"):
            _coerce_field("flag", field, "yes")

    def test_int_refuses_bool_and_coerces_digits(self):
        field = {"type": "int"}
        with pytest.raises(BadRequestException, match="must be an integer"):
            _coerce_field("pages", field, True)
        assert _coerce_field("pages", field, 5) == 5
        assert _coerce_field("pages", field, " -5 ") == -5
        with pytest.raises(BadRequestException, match="must be an integer"):
            _coerce_field("pages", field, "5.5")

    def test_float_accepts_numbers_and_text_and_refuses_everything_else(self):
        field = {"type": "float"}
        with pytest.raises(BadRequestException, match="must be a number"):
            _coerce_field("ratio", field, True)
        assert _coerce_field("ratio", field, 1) == 1.0
        assert _coerce_field("ratio", field, "1.5") == 1.5
        with pytest.raises(BadRequestException, match="must be a number"):
            _coerce_field("ratio", field, "not-a-number")
        with pytest.raises(BadRequestException, match="must be a number"):
            _coerce_field("ratio", field, None)

    def test_string_refuses_non_strings_and_oversized_values(self):
        field = {"type": "str"}
        with pytest.raises(BadRequestException, match="must be a string"):
            _coerce_field("label", field, 5)
        with pytest.raises(BadRequestException, match="too long"):
            _coerce_field("label", field, "x" * 2001)
        assert _coerce_field("label", field, "ok") == "ok"


class TestConfigValidation:
    def test_a_non_object_payload_is_refused(self):
        with pytest.raises(BadRequestException, match="config must be an object"):
            validate_connector_config({}, "not-a-config")

    def test_a_key_with_the_wrong_grammar_is_named(self):
        with pytest.raises(BadRequestException, match="invalid config key"):
            validate_connector_config({}, {"Bad Key": 1})
