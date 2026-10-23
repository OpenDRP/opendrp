# Plan 028 — the module inventory, three levels deep

**State:** done — 2026-10-23: `ConnectorModulesResponse` on the module inventory, the inventory is 7

## Goal

`GET /api/v1/connectors/modules` answers the modules the platform knows and the job
types their connectors declare. The SPA reads it as `ConnectorModulesResponse`; the
route declares `response_model=dict`, so the envelope, the nine keys of each module
entry and the five keys of each connector row are all checked by the compiler alone.

The payload is the first inventory entry with three levels, which is what the plan
has to name:

```
{ "modules": { "<module id>": { label, description, job_types[], finding_kind,
                                asset_types[], storage, builtin, enabled,
                                connectors: [ { name, status, job_type,
                                                asset_types[], config_schema } ] } } }
```

Decisions:

1. **The module map is a map, not a model with named modules.** Module ids are data
   (`drp_modules` rows); a declared module must appear in this answer without a code
   change, so `modules: dict[str, ConnectorModuleEntry]` is the only honest type. The
   composer's `setdefault` branch — a connector whose type no registry row declares —
   is why `label` and `description` are always strings rather than optional: the
   composer fills them (`connector_type`, `""`), so the client's `label?` is a
   reader's convenience, not a shape that varies.
2. **`storage` stays a string.** It is `storage["kind"]` from the module's own JSON,
   defaulting to `generic`, so a module may name a kind this build has never seen;
   a two-valued `Literal` would fail the whole page over data that is merely newer
   than the code. The client narrows it to `table | generic` because those are the
   two kinds that exist today.
3. **`config_schema` stays a free-form document.** It is the connector's manifest —
   per-vendor field specs the UI renders — and `ConnectorConfigField` on the client
   is a reading of it, not a contract the server enforces.
4. **`status` is closed.** Each connector row copies `conn.status`, and
   `ConnectorService.set_status` accepts only `ConnectorStatus.ALL`, so the row
   declares `enabled | disabled` like the health row does.

Nothing here is optional or null, so the route takes no `exclude_none` — a third
different decorator in three steps, each decided by the payload rather than by habit.

## Plan of Work

| File | Change |
|---|---|
| `backend/app/api/v1/routers/connectors.py` | `ConnectorModuleJob`, `ConnectorModuleEntry` and `ConnectorModulesResponse` beside the other admin models; the route declares the model and builds it |
| `backend/scripts/check_api_types.py` | the `ConnectorModuleEntry` and `ConnectorModulesResponse` pairs, the entry deleted, the count 8 → 7 |
| `docs/production-readiness.md` | the limitation says 7, and the closed list names this route |
| `docs/exec-plans/README.md` | one row for this plan |
| `backend/tests/test_connectors_protocol_api.py` | the contract test: the envelope, the nine entry keys and the five row keys on a registered connector |
| `backend/tests/test_declared_module_integration.py` | the declared-module test gains the same key sets, so data-driven metadata is covered too |

## Concrete Steps

1. **Red first.** Add both pairs and delete the entry: the gate reports the typed
   read of a route that declares no model.
2. **The models.** `ConnectorModuleJob` (`name`, `status`, `job_type`, `asset_types`,
   `config_schema`), `ConnectorModuleEntry` (the nine keys above) and
   `ConnectorModulesResponse` (`modules`).
3. **The route.** Keep `ConnectorService.module_job_types()` untouched — it is the one
   composer the module pages and the registry tests read — and validate its result
   through the response model.
   *Acceptance:* the gate is green, the entry is gone, and the payload is identical
     key for key and value for value: no timestamps, no nulls, no free-form field
     newly narrowed.

## Validation and Acceptance

- [x] Red before the model, green after: both pairs named a schema missing from the
      OpenAPI document and `lib/connectors.ts:20` was reported as a typed read of an
      undeclared response; after the model — 23 passed with `7 routes`.
- [x] A registered connector's entry answers exactly nine keys and its connector row
      exactly five; a registry-declared module (`code_leak`) answers the same nine,
      which the declared-module suite asserts. Both a registry type and a
      connector-only type are covered (`phishing` here is registered without a
      registry row).
- [x] The module suites stay green (`test_connectors_protocol_api.py`,
      `test_declared_module_integration.py`, `test_module_registry.py` — 126 passed).
- [x] `ruff check app tests scripts` clean; the documentation/type gates plus
      `test_api_docs_contract.py` — 105 passed. The mypy ratchet was not run: it lives
      in the tooling container and the Docker daemon was unreachable here.

## Progress and Milestones

- **2026-10-23 — opened.** Picked from the remaining eight to finish the connector
  admin group before moving to the alert and audit views; it is also the entry that
  exercises nested lists of models, which none of the previous steps did.
- **2026-10-23 — closed.** Seven routes remain: the alert queue, the audit views
  (actions and integrity), the dashboard overview, the account-binding patch, the
  exposure page and the phishing evidence view.
