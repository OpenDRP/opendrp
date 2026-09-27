"""Modules are data: the registry, declared field specs and dedup keys.

Until this change the set of modules and their finding schemas were constants in
core code, so a data source whose findings fit neither table could not be
onboarded without a release. These tests pin what replaced that:

* the built-in modules are seeded from one definition, and the migration that
  inserts them cannot drift from it;
* a module definition is validated before it is stored (id grammar, field types,
  dedup coherence, title field, finding-kind uniqueness);
* a declared module's payload is validated against *its own* field
  specification — unknown keys and wrong types are refused, and the source's
  attributes still cannot smuggle a nested object into the JSON column;
* the dedup key and headline come from the module's declaration.
"""

import importlib.util
import json
from pathlib import Path

import pytest

from app.core.exceptions import BadRequestException
from app.services.connector_manifest import (
    ModuleSpec,
    declared_dedup_key,
    declared_finding_model,
    declared_title,
    normalize_declared_fields,
    normalize_dedup_fields,
)
from app.services.module_registry import (
    BUILTIN_MODULE_DEFINITIONS,
    create_module,
    ensure_builtin_modules,
    load_modules,
    set_module_enabled,
)

_MODULES_DIR = Path(__file__).resolve().parents[1] / "alembic" / "versions"


def _load_migration(name: str):
    """Import a migration file (its name starts with a digit, so no ``import``)."""
    path = _MODULES_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _declared_spec(**overrides) -> ModuleSpec:
    """A module declared the way an operator would: own fields, own dedup."""
    base = {
        "id": "code_leak",
        "label": "Code leaks",
        "description": "Source code exposed in public repositories.",
        "finding_kind": "code_leak",
        "asset_types": ("domain",),
        "fields": {
            "repository": {"type": "str", "required": True},
            "file_path": {"type": "str"},
            "secret_kind": {"type": "str", "required": True},
            "lines": {"type": "int"},
            "first_seen": {"type": "date"},
            "tags": {"type": "list_str"},
            "is_public": {"type": "bool"},
        },
        "dedup_fields": ("repository", "file_path", "secret_kind"),
        "title_field": "repository",
        "storage": {"kind": "generic", "adapter": "generic"},
        "enabled": True,
        "builtin": False,
    }
    base.update(overrides)
    return ModuleSpec(**base)


# ---------------------------------------------------------------------------
# Built-in modules and the migration that seeds them
# ---------------------------------------------------------------------------


class TestBuiltinModules:
    def test_the_migration_seed_matches_the_applications_definition(self):
        """A migration is replayed verbatim; drift here would split deployments.

        The migration must not import application code (it describes its own
        revision), so the two copies are compared instead of shared. Every key is
        compared, ``storage`` included: the baseline is the state the whole chain
        ended in, so there is no later revision left for it to defer to.

        ``storage.adapter`` is the reason this test earns its place. It is not
        decoration — ``ingestion_service._NATIVE_INGESTORS`` dispatches on it, so a
        seeded adapter the application does not recognise sends every finding of
        that module down the generic path, into ``drp_findings`` instead of its own
        table, without raising anything. It shipped once as ``breaches`` against an
        application that knows ``breach``.
        """
        migration = _load_migration("0001_initial_schema")
        seeded = {row["id"]: row for row in migration._MODULE_SEED}
        declared = {row["id"]: row for row in BUILTIN_MODULE_DEFINITIONS}

        assert set(seeded) == set(declared)
        for module_id, row in declared.items():
            for key, value in row.items():
                assert seeded[module_id][key] == value, f"{module_id}.{key} drifted"
        # Named for what it stores, not for the first source that filled it.
        assert seeded["breaches"]["storage"]["table"] == "drp_breaches"

    @pytest.mark.asyncio
    async def test_builtin_modules_are_available_to_the_core(self, db_session):
        specs = await load_modules(db_session)
        assert {"phishing", "breaches"} <= set(specs)
        assert specs["phishing"].finding_kind == "phishing"
        assert specs["breaches"].finding_kind == "breach"
        # The built-in modules keep their own write adapters.
        assert specs["phishing"].adapter == "phishing"
        assert specs["breaches"].adapter == "breach"
        assert specs["phishing"].storage_kind == "table"
        assert all(spec.builtin for spec in specs.values())

    @pytest.mark.asyncio
    async def test_seeding_is_idempotent_and_never_overwrites_an_admin_decision(
        self, db_session
    ):
        assert await ensure_builtin_modules(db_session) == 0  # nothing missing
        await set_module_enabled(db_session, "breaches", enabled=False)
        await ensure_builtin_modules(db_session)
        assert (await load_modules(db_session))["breaches"].enabled is False


# ---------------------------------------------------------------------------
# Module definitions
# ---------------------------------------------------------------------------


class TestModuleDefinitionValidation:
    @pytest.mark.asyncio
    async def test_declaring_a_module_stores_its_declaration(self, db_session):
        spec = await create_module(
            db_session,
            module_id="Code_Leak",
            label="  Code leaks  ",
            fields={"repository": {"type": "str", "required": True}},
            dedup_fields=["repository"],
            asset_types=["domain", "domain"],
        )
        assert spec.id == "code_leak"  # normalized
        assert spec.label == "Code leaks"
        assert spec.finding_kind == "code_leak"
        assert spec.asset_types == ("domain",)
        assert spec.title_field == "repository"  # defaults to the first dedup field
        # Declared modules always use generic storage.
        assert spec.storage_kind == "generic" and spec.adapter == "generic"
        assert spec.builtin is False and spec.enabled is True

    @pytest.mark.asyncio
    async def test_a_module_must_declare_fields_and_a_dedup_key(self, db_session):
        with pytest.raises(BadRequestException, match="must declare the fields"):
            await create_module(db_session, module_id="empty", label="Empty", fields={})
        with pytest.raises(BadRequestException, match="at least one dedup field"):
            await create_module(
                db_session,
                module_id="nodedup",
                label="No dedup",
                fields={"repository": {"type": "str"}},
                dedup_fields=[],
            )

    @pytest.mark.asyncio
    async def test_declared_fields_dedup_and_title_must_be_coherent(self, db_session):
        with pytest.raises(BadRequestException, match="not a declared field"):
            await create_module(
                db_session,
                module_id="mismatch",
                label="Mismatch",
                fields={"repository": {"type": "str"}},
                dedup_fields=["file_path"],
            )
        with pytest.raises(BadRequestException, match="title_field"):
            await create_module(
                db_session,
                module_id="badtitl",
                label="Bad title",
                fields={"repository": {"type": "str"}},
                dedup_fields=["repository"],
                title_field="nope",
            )
        with pytest.raises(BadRequestException, match="invalid"):
            await create_module(
                db_session,
                module_id="badtype",
                label="Bad type",
                fields={"repository": {"type": "uuid"}},
                dedup_fields=["repository"],
            )

    @pytest.mark.asyncio
    async def test_duplicate_ids_and_finding_kinds_are_refused(self, db_session):
        await create_module(
            db_session,
            module_id="code_leak",
            label="Code leaks",
            fields={"repository": {"type": "str"}},
            dedup_fields=["repository"],
        )
        with pytest.raises(BadRequestException, match="already exists"):
            await create_module(
                db_session,
                module_id="code_leak",
                label="Again",
                fields={"repository": {"type": "str"}},
                dedup_fields=["repository"],
            )
        with pytest.raises(BadRequestException, match="already exists"):
            # The built-in modules own their ids too.
            await create_module(
                db_session,
                module_id="phishing",
                label="Hijack",
                fields={"domain": {"type": "str"}},
                dedup_fields=["domain"],
            )

    @pytest.mark.asyncio
    async def test_a_declared_module_is_visible_to_the_registry_immediately(
        self, db_session
    ):
        await create_module(
            db_session,
            module_id="code_leak",
            label="Code leaks",
            fields={"repository": {"type": "str"}},
            dedup_fields=["repository"],
        )
        specs = await load_modules(db_session)
        assert "code_leak" in specs
        # A declared field carries its full descriptor, defaults included.
        assert specs["code_leak"].fields == {
            "repository": {"type": "str", "required": False}
        }

    @pytest.mark.asyncio
    async def test_disabling_a_module_is_recorded(self, db_session):
        await create_module(
            db_session,
            module_id="code_leak",
            label="Code leaks",
            fields={"repository": {"type": "str"}},
            dedup_fields=["repository"],
        )
        spec = await set_module_enabled(db_session, "code_leak", enabled=False)
        assert spec.enabled is False
        assert (await load_modules(db_session))["code_leak"].enabled is False

    def test_platform_fields_cannot_be_redeclared(self):
        with pytest.raises(BadRequestException, match="provided by the platform"):
            normalize_declared_fields({"attributes": {"type": "str"}})
        with pytest.raises(BadRequestException, match="provided by the platform"):
            normalize_declared_fields({"matched_asset": {"type": "str"}})

    def test_field_and_dedup_grammars_are_bounded(self):
        with pytest.raises(BadRequestException, match="at most 3"):
            normalize_dedup_fields(["a", "b", "c", "d"])
        with pytest.raises(BadRequestException, match="lowercase identifier"):
            normalize_declared_fields({"Bad Name": {"type": "str"}})


# ---------------------------------------------------------------------------
# Validation of a declared module's payload
# ---------------------------------------------------------------------------


class TestDeclaredPayloadValidation:
    def _model(self):
        return declared_finding_model(_declared_spec())

    def test_a_declared_payload_is_accepted_and_typed(self):
        finding = self._model().model_validate(
            {
                "repository": "github.com/acme/app",
                "secret_kind": "aws_key",
                "lines": 12,
                "first_seen": "2026-01-02",
                "tags": ["prod", "backend"],
                "is_public": True,
            }
        ).model_dump(mode="json")
        assert finding["repository"] == "github.com/acme/app"
        assert finding["lines"] == 12
        assert finding["first_seen"] == "2026-01-02"
        assert finding["tags"] == ["prod", "backend"]
        assert finding["is_public"] is True

    def test_required_fields_and_unknown_keys_are_refused(self):
        with pytest.raises(Exception):
            self._model().model_validate({"repository": "r"})  # secret_kind missing
        with pytest.raises(Exception):
            self._model().model_validate(
                {"repository": "r", "secret_kind": "aws_key", "unexpected": 1}
            )

    def test_declared_types_are_enforced_not_coerced(self):
        with pytest.raises(Exception):
            self._model().model_validate(
                {"repository": "r", "secret_kind": "aws_key", "lines": "twelve"}
            )
        with pytest.raises(Exception):
            self._model().model_validate(
                {"repository": "r", "secret_kind": "aws_key", "is_public": "yes"}
            )
        with pytest.raises(Exception):
            self._model().model_validate(
                {"repository": "r", "secret_kind": "aws_key", "first_seen": "not-a-date"}
            )

    def test_control_characters_and_oversized_values_are_refused(self):
        with pytest.raises(Exception):
            self._model().model_validate(
                {"repository": "r\u0000x", "secret_kind": "aws_key"}
            )
        with pytest.raises(Exception):
            self._model().model_validate(
                {"repository": "r" * 600, "secret_kind": "aws_key"}
            )
        with pytest.raises(Exception):
            self._model().model_validate(
                {"repository": "r", "secret_kind": "aws_key", "tags": ["t"] * 200}
            )

    def test_source_attributes_stay_scalar_and_bounded(self):
        finding = self._model().model_validate(
            {
                "repository": "r",
                "secret_kind": "aws_key",
                "attributes": {"feed": "underground", "records": 12},
            }
        ).model_dump(mode="json")
        assert finding["attributes"] == {"feed": "underground", "records": 12}
        # A nested object can never reach the JSON column.
        with pytest.raises(Exception):
            self._model().model_validate(
                {
                    "repository": "r",
                    "secret_kind": "aws_key",
                    "attributes": {"nested": {"deep": 1}},
                }
            )
        with pytest.raises(Exception):
            self._model().model_validate(
                {"repository": "r", "secret_kind": "aws_key", "attributes": {"Bad-Key": 1}}
            )

    def test_the_platform_supplies_the_matched_asset(self):
        finding = self._model().model_validate(
            {"repository": "r", "secret_kind": "aws_key", "matched_asset": "acme.com"}
        ).model_dump(mode="json")
        assert finding["matched_asset"] == "acme.com"

    def test_a_changed_declaration_rebuilds_the_validator(self):
        """The cache key includes the fields, so edits take effect immediately."""
        first = declared_finding_model(_declared_spec())
        second = declared_finding_model(
            _declared_spec(fields={"repository": {"type": "str", "required": True}})
        )
        assert first is not second
        assert set(second.model_fields) == {"repository", "matched_asset", "attributes"}


# ---------------------------------------------------------------------------
# Declared dedup key and headline
# ---------------------------------------------------------------------------


class TestDeclaredDedupKeyAndTitle:
    def test_dedup_key_joins_the_declared_fields_in_order(self):
        key = declared_dedup_key(
            _declared_spec(),
            {"repository": " github.com/acme/app ", "file_path": "a/b.py", "secret_kind": "aws_key"},
        )
        assert key == "github.com/acme/app|a/b.py|aws_key"

    def test_dedup_key_is_whitespace_and_length_bounded(self):
        key = declared_dedup_key(
            _declared_spec(),
            {"repository": "r" * 700, "file_path": "  ", "secret_kind": "aws_key"},
        )
        assert len(key) <= 512
        assert declared_dedup_key(_declared_spec(), {}) == "||"

    def test_title_prefers_the_declared_field_then_falls_back(self):
        spec = _declared_spec()
        assert declared_title(spec, {"repository": "repo"}) == "repo"
        # No value for the title field: the dedup fields, then the module label.
        assert declared_title(spec, {"secret_kind": "aws_key"}) == "aws_key"
        assert declared_title(spec, {}) == "Code leaks"

    def test_a_module_without_a_title_field_still_gets_a_headline(self):
        # Falls back to the dedup fields, then any declared field, then the
        # module's own label — a finding never renders as an empty row.
        spec = _declared_spec(title_field=None, dedup_fields=("repository",))
        assert declared_title(spec, {"repository": "repo"}) == "repo"
        assert declared_title(spec, {"file_path": "x/y.py"}) == "x/y.py"
        assert declared_title(spec, {}) == "Code leaks"

    def test_the_public_view_exposes_declaration_not_implementation(self):
        public = _declared_spec().to_public_dict()
        assert public["storage"] == "generic"
        assert "table" not in json.dumps(public)
        assert public["fields"]["lines"]["type"] == "int"
