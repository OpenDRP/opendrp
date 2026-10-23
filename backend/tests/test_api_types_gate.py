"""The response-shape gate's own proof (AUD-060).

The gate exists because 56 request helpers returned `any`: the method, path and
body of every call were pinned by `endpoints.test.ts`, and the payload was not.
These tests drive each decision with a fixture, so a rule that stops matching
fails here rather than passing a build whose client reads a field the server
stopped sending.
"""

from __future__ import annotations

from scripts import check_api_types as gate


def _types(*body: str) -> str:
    return "\n".join(body)


class TestEveryHelperNamesItsResponse:
    def test_a_call_without_a_generic_is_reported(self):
        api = (
            "export const endpoints = {\n"
            '  listAssets: (params: QueryParams) => api.get("/assets", { params }).then((r) => r.data),\n'
            "};\n"
        )

        failures = gate.untyped_helpers(api)

        assert len(failures) == 1
        assert failures[0].startswith("listAssets:")
        assert "no response type" in failures[0]

    def test_a_typed_call_passes_and_void_counts_as_a_type(self):
        api = (
            "export const endpoints = {\n"
            "  listAssets: (params: QueryParams) =>\n"
            '    api.get<Paginated<Asset>>("/assets", { params }).then((r) => r.data),\n'
            "  deleteAsset: (id: string) =>\n"
            '    api.delete<void>(`/assets/${id}`).then(() => undefined),\n'
            "};\n"
        )

        assert gate.untyped_helpers(api) == []

    def test_every_call_of_a_multi_call_helper_must_be_typed(self):
        api = (
            "export const endpoints = {\n"
            "  logout: async () => {\n"
            '    await api.post("/auth/logout", undefined, CREDENTIAL_CHECK);\n'
            "  },\n"
            "};\n"
        )

        assert gate.untyped_helpers(api) == [
            "logout: `api.post(...)` declares no response type; add "
            "`api.post<T>(...)` (use `<void>` when the route sends no body)"
        ]


class TestAFieldTheSpaReadsMustExist:
    def test_a_field_removed_from_the_response_model_is_reported(self, monkeypatch):
        monkeypatch.setattr(gate, "SCHEMA_PAIRS", {"Asset": "AssetResponse"})
        types = _types(
            "export interface Asset {",
            "  id: string;",
            "  asset_value: string;",
            "}",
        )
        schemas = {"AssetResponse": {"properties": {"id": {}, "asset_value": {}}}}

        assert gate.check_text(api_text="export const endpoints = {};", types_text=types, schemas=schemas) == []

        schemas["AssetResponse"]["properties"].pop("asset_value")
        failures = gate.check_text(api_text="export const endpoints = {};", types_text=types, schemas=schemas)

        assert failures == [
            "Asset.asset_value: the SPA reads this field, AssetResponse no longer sends it"
        ]

    def test_a_model_field_the_spa_does_not_read_is_not_a_failure(self, monkeypatch):
        """A client models the half it uses; forcing a full mirror makes it stale."""
        monkeypatch.setattr(gate, "SCHEMA_PAIRS", {"Asset": "AssetResponse"})
        types = _types("export interface Asset {", "  id: string;", "}")
        schemas = {"AssetResponse": {"properties": {"id": {}, "updated_at": {}}}}

        assert gate.check_text(api_text="export const endpoints = {};", types_text=types, schemas=schemas) == []

    def test_a_missing_interface_or_model_is_reported_not_skipped(self, monkeypatch):
        monkeypatch.setattr(gate, "SCHEMA_PAIRS", {"Asset": "AssetResponse", "Ghost": "GhostResponse"})

        failures = gate.check_text(
            api_text="export const endpoints = {};",
            types_text=_types("export interface Asset {", "  id: string;", "}"),
            schemas={"AssetResponse": {"properties": {"id": {}}}},
        )

        assert "Ghost: the interface this gate watches is gone" in failures
        assert "GhostResponse: named by Ghost but missing from the OpenAPI document" in failures


class TestTheParserReadsTheShippedShape:
    def test_nested_objects_and_unions_are_not_mistaken_for_fields(self):
        types = _types(
            "export interface Example {",
            "  id: string;",
            "  status:",
            '    | "a"',
            '    | "b";',
            "  policy: {",
            "    approved: boolean;",
            "  };",
            "  optional?: string | null;",
            "}",
            "",
            "export interface Other extends Paginated<Example> {",
            "  total_count: number;",
            "}",
        )

        parsed = gate.parse_interfaces(types)

        assert parsed["Example"] == {"id", "status", "policy", "optional"}
        assert parsed["Other"] == {"total_count"}

    def test_a_body_closed_on_the_same_line_ends_there(self):
        """`interface Page extends Paginated<Row> {}` used to swallow the next one.

        The block walk stops at a line that is exactly `}`, so a body that opens and
        closes on the opening line made every following interface part of this one.
        In the client that was `ExposurePage` reading `{id, status}` — the fields of
        the interface after it — while `ExposureTriageResult` itself was invisible to
        every rule, including the one that inventories typed reads of a route that
        declares no response model. The measured hole was two routes where it is
        three.
        """
        types = _types(
            "export interface Page extends Paginated<Row> {}",
            "",
            "export interface Triage {",
            "  id: string;",
            "  status: string;",
            "}",
        )

        parsed = gate.parse_interfaces(types)

        assert parsed["Page"] == set()
        assert parsed["Triage"] == {"id", "status"}

    def test_a_member_written_beside_the_opening_brace_is_read(self):
        """The walk starts on the next line, so the first member used to be lost."""
        types = _types(
            "export interface OneLine { id: string; name?: string };",
            "export interface Split { id: string;",
            "  name: string;",
            "}",
        )

        parsed = gate.parse_interfaces(types)

        assert parsed["OneLine"] == {"id", "name"}
        assert parsed["Split"] == {"id", "name"}


class TestEveryPathIsARouteTheApiServes:
    """Removing a route has to fail a build, not a page.

    The readiness page said so plainly: the client's path literals were the one
    unchecked link between the browser and a handler. AUD-060's evidence counted
    them once ("all 99 calls match a live route"); these tests make that count
    something the suite recomputes.
    """

    SPEC = {
        "/api/v1/assets": {"get": {}, "post": {}},
        "/api/v1/assets/{asset_id}": {"get": {}, "delete": {}},
        "/api/v1/users/{user_id}": {"delete": {}},
    }

    def test_a_path_no_route_serves_is_reported(self):
        calls = gate.calls_in("api.ts", 'api.get<Asset>("/asset")')

        assert gate.check_calls(calls, self.SPEC) == [
            "api.ts:1: GET /api/v1/asset — no route the API serves has that path"
        ]

    def test_a_verb_the_route_does_not_serve_is_reported(self):
        calls = gate.calls_in("api.ts", 'api.delete<void>("/assets")')

        assert gate.check_calls(calls, self.SPEC) == [
            "api.ts:1: DELETE /api/v1/assets — /api/v1/assets serves GET, POST"
        ]

    def test_a_parameter_is_a_parameter_by_any_name(self):
        # The SPA spells the slot `${encodeURIComponent(id)}` and the router spells
        # it `{user_id}`; a comparison that needed the names to agree would report
        # every parameterised call in the client.
        calls = gate.calls_in("api.ts", 'api.delete<void>(`/users/${encodeURIComponent(id)}`)')

        assert gate.check_calls(calls, self.SPEC) == []

    def test_a_chained_call_and_a_generic_with_braces_are_read(self):
        source = "\n".join(
            [
                "  enable: (code: string) =>",
                "    api",
                '      .post<{ codes: string[] }>("/assets", { code })',
                "      .then((r) => r.data),",
            ]
        )

        calls = gate.calls_in("api.ts", source)

        assert [(call.verb, call.path, call.line) for call in calls] == [("POST", "/assets", 3)]
        assert gate.check_calls(calls, self.SPEC) == []

    def test_a_path_the_gate_cannot_read_is_reported(self):
        calls = gate.calls_in("api.ts", "api.get<Asset>(url)")

        assert gate.check_calls(calls, self.SPEC) == [
            "api.ts:1: GET — the path is not a string literal, so this gate cannot check it"
        ]

    def test_a_path_that_already_carries_the_prefix_is_reported(self):
        calls = gate.calls_in("api.ts", 'api.get<Asset>("/api/v1/assets")')

        assert gate.check_calls(calls, self.SPEC) == [
            "api.ts:1: GET /api/v1/assets — the client path is relative to "
            "`/api/v1`, which would be asked for twice"
        ]

    def test_a_query_string_is_not_part_of_the_route(self):
        # `params` is how the client sends a filter; a literal that carries one is
        # still asking for the route in front of it, and the route is what exists.
        calls = gate.calls_in("api.ts", 'api.get<Asset>("/assets?page=1")')

        assert gate.check_calls(calls, self.SPEC) == []

    def test_the_floor_notices_a_scanner_that_stopped_finding_calls(self):
        assert gate.corpus_floor(gate.MINIMUM_CALLS) is None
        assert gate.corpus_floor(12) is not None
        assert "12" in gate.corpus_floor(12)


class TestARouteWithNoResponseModelIsInventoried:
    """Rule 4: the hole is a list with a reason each, and the list can only shrink.

    Rule 2 compares two declarations; a route that returns a `dict` has only one,
    so 28 payloads the SPA reads were described by a sentence in the gate's
    docstring. A sentence cannot fail. The inventory can: it is exact in both
    directions — a new typed read of an undeclared response is a failure, and an
    entry whose route gained a model is a stale entry.
    """

    PATHS = {
        "/api/v1/audit/integrity": {
            "get": {"responses": {"200": {"content": {"application/json": {"schema": {}}}}}}
        },
        "/api/v1/assets": {
            "get": {
                "responses": {
                    "200": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/AssetPage"}
                            }
                        }
                    }
                }
            }
        },
        # The shape this plan is about: the envelope is described and its rows are not.
        "/api/v1/audit/logs": {
            "get": {
                "responses": {
                    "200": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/DictPage"}
                            }
                        }
                    }
                }
            }
        },
    }
    SCHEMAS = {
        "AssetPage": {
            "properties": {
                "items": {
                    "type": "array",
                    "items": {"$ref": "#/components/schemas/Asset"},
                },
                "total": {"type": "integer"},
            }
        },
        "Asset": {"properties": {"id": {"type": "string"}}},
        "DictPage": {
            "properties": {
                "items": {"type": "array", "items": {}},
                "total": {"type": "integer"},
            }
        },
    }
    INTERFACES = {
        "AuditIntegrity": {"committed"},
        "Asset": {"id"},
        "AuditLogRow": {"id"},
    }

    def test_a_typed_read_of_an_undeclared_response_is_reported(self):
        calls = gate.calls_in("api.ts", 'api.get<AuditIntegrity>("/audit/integrity")')

        assert gate.check_unmodelled(
            calls, self.PATHS, self.SCHEMAS, self.INTERFACES, {}
        ) == [
            "api.ts:1: AuditIntegrity — GET /api/v1/audit/integrity answers no declared "
            "row shape, so its fields are unchecked; declare a model (or a page whose "
            "`items` is one) on the route, or add `GET /api/v1/audit/integrity` to "
            "UNMODELLED with the reason"
        ]

    def test_a_page_whose_rows_describe_nothing_is_not_a_declaration(self):
        """`PaginatedResponse[Any]` names five counters and nothing a row holds.

        The gate used to answer "does the response carry a `$ref`", which the
        envelope satisfies on its own: `GET /audit/logs` declared `Any` and read as
        checked, while the ten fields the page renders were compared with nothing.
        """
        calls = gate.calls_in(
            "api.ts", 'api.get<Paginated<AuditLogRow>>("/audit/logs")'
        )

        assert gate.check_unmodelled(
            calls, self.PATHS, self.SCHEMAS, self.INTERFACES, {}
        ) == [
            "api.ts:1: AuditLogRow — GET /api/v1/audit/logs answers no declared row "
            "shape, so its fields are unchecked; declare a model (or a page whose "
            "`items` is one) on the route, or add `GET /api/v1/audit/logs` to "
            "UNMODELLED with the reason"
        ]

    def test_a_paginated_read_names_the_row_it_holds(self):
        """`Paginated<Asset>` is a read of `Asset`, not a container the rule skips.

        Since plan 016 the gate looked for a bare name or `Name[]`, so every
        paginated read in the client — most of its list helpers — was invisible to
        rule 4 whatever the server declared. Unwrapping the container is what made the
        three routes of plan 035 measurable at all.
        """
        calls = gate.calls_in("api.ts", 'api.get<Paginated<Asset>>("/assets")')

        assert gate.check_unmodelled(calls, self.PATHS, self.SCHEMAS, self.INTERFACES, {}) == []
        # A container over a name the client does not declare is not a declaration
        # either; the rule cannot compare what the SPA never wrote down.
        calls = gate.calls_in("api.ts", 'api.get<Paginated<Ghost>>("/assets")')
        assert gate.check_unmodelled(calls, self.PATHS, self.SCHEMAS, self.INTERFACES, {}) == []

    def test_an_inventoried_route_passes(self):
        calls = gate.calls_in("api.ts", 'api.get<AuditIntegrity>("/audit/integrity")')

        assert gate.check_unmodelled(
            calls,
            self.PATHS,
            self.SCHEMAS,
            self.INTERFACES,
            {"GET /api/v1/audit/integrity": "a dict"},
        ) == []

    def test_an_entry_whose_route_gained_a_model_is_stale(self):
        calls = gate.calls_in("api.ts", 'api.get<Asset>("/assets")')

        assert gate.check_unmodelled(
            calls,
            self.PATHS,
            self.SCHEMAS,
            self.INTERFACES,
            {"GET /api/v1/assets": "a dict"},
        ) == [
            "UNMODELLED: `GET /api/v1/assets` no longer names a route the SPA reads an "
            "undeclared response from; remove the entry (and the pair it made unnecessary)"
        ]

    def test_a_declared_schema_needs_no_entry(self):
        calls = gate.calls_in("api.ts", 'api.get<Asset>("/assets")')

        assert gate.check_unmodelled(calls, self.PATHS, self.SCHEMAS, self.INTERFACES, {}) == []

    def test_a_dom_type_is_not_an_interface(self):
        # `Blob` is a browser type, not a declaration the server could be compared
        # with, so it is not an unchecked response the inventory should hold. A
        # `Paginated<X>` used to be skipped for the same reason; plan 035 reads the
        # `X`, because the row is what the page renders.
        calls = gate.calls_in(
            "api.ts", 'api.get<Blob>("/audit/integrity", { responseType: "blob" })'
        )

        assert gate.check_unmodelled(calls, self.PATHS, self.SCHEMAS, self.INTERFACES, {}) == []


def test_the_shipped_tree_agrees_with_the_openapi_document():
    """The gate over the real files: 101 helpers and eight schema pairs."""
    from pathlib import Path

    from app.main import app

    root = Path(__file__).resolve().parents[2]
    failures = gate.check_text(
        api_text=(root / "frontend/src/lib/api.ts").read_text(encoding="utf-8"),
        types_text=(root / "frontend/src/types/api.ts").read_text(encoding="utf-8"),
        schemas=app.openapi()["components"]["schemas"],
    )

    assert failures == []


def test_the_unmodelled_inventory_is_exactly_the_routes_it_describes():
    """Rule 4 over the real tree: every entry is live and every live read is entered."""
    from pathlib import Path

    from app.main import app

    root = Path(__file__).resolve().parents[2]
    calls = gate.collect_calls(root / "frontend" / "src")
    interfaces = gate.parse_interfaces(
        (root / "frontend/src/types/api.ts").read_text(encoding="utf-8")
    )

    assert (
        gate.check_unmodelled(
            calls,
            app.openapi()["paths"],
            app.openapi()["components"]["schemas"],
            interfaces,
            gate.UNMODELLED,
        )
        == []
    )
    # No length assertion: the inventory is meant to reach zero as routes gain models,
    # and a size floor that has to be lowered with every plan is a test that edits
    # itself. A scanner that stopped reading calls is caught by rule 3's corpus floor
    # and by the two direction checks above, which is what a length was standing in for.
    assert all(reason for reason in gate.UNMODELLED.values())


def test_every_call_in_the_shipped_client_names_a_live_route():
    """The path rule over the real client — the client is more than `lib/api.ts`."""
    from pathlib import Path

    from app.main import app

    root = Path(__file__).resolve().parents[2]
    calls = gate.collect_calls(root / "frontend" / "src")

    assert len(calls) >= gate.MINIMUM_CALLS
    assert {call.source for call in calls} >= {
        "lib/api.ts",
        "lib/connectors.ts",
        "lib/findings.ts",
        "lib/modules.ts",
    }
    assert gate.check_calls(calls, app.openapi()["paths"]) == []

