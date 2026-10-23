# Plan 029 — binding an account answers the connector

**State:** done — 2026-10-23: `response_model=ConnectorOut` on the binding route, the inventory is 6

## Goal

`PATCH /api/v1/connectors/{connector_id}/account` binds a source account to a
connector and answers the connector. The SPA reads it as `Connector`; the route
declares no response model, so the answer is one of the last seven payloads whose
field names only the compiler checks.

This entry is the shortest in the inventory, and that is the point of taking it now:
the handler already builds the answer with `_connector_out`, the same function the
connector list and the registration route use, and `ConnectorOut` already exists. So
the fix is a declaration, not a shape — and the interesting work is proving that the
declaration *is* the answer, not a second one:

* **Same model, same values.** The binding answer and the connector list row describe
  one resource and are built by one function, so the test compares the two responses
  field for field instead of a hardcoded list: a change to `_connector_out` that
  reaches only one route would fail.
* **The pair already existed.** `SCHEMA_PAIRS` has compared `Connector` with
  `ConnectorOut` since the gate landed, because the list and registration routes
  already declared the model — but that comparison says nothing about *this* route
  until the route declares it too. This plan is what makes the inventory entry's
  removal provable rather than assumed.
* **No exclusion.** `ConnectorOut` sends every field, `null` where there is no value
  (`api_version`, `provider`, the token triple), and today's `jsonable_encoder`
  already emits them all; declaring the model without `exclude_none` keeps the
  payload byte-identical.

## Plan of Work

| File | Change |
|---|---|
| `backend/app/api/v1/routers/connectors.py` | `response_model=ConnectorOut` on `PATCH /{connector_id}/account`; the handler and `_connector_out` are untouched |
| `backend/scripts/check_api_types.py` | the entry deleted, the count 7 → 6 |
| `docs/production-readiness.md` | the limitation says 6, and the closed list names this route |
| `docs/exec-plans/README.md` | one row for this plan |
| `backend/tests/test_source_accounts_api.py` | the binding test already asserts three fields; it gains the agreement with the list row |

## Concrete Steps

1. **Red first.** Delete the entry: the gate reports the typed read of a route that
   declares no model.
2. **The declaration.** One decorator argument.
3. **The evidence.** In the existing lifecycle test, after binding, compare
   `bound.json()` with the connector's row from `GET /connectors` — equal as
   dictionaries, so neither keys nor values can drift between the two answers.
   *Acceptance:* the gate is green, the entry is gone, and the payload is unchanged.

## Validation and Acceptance

- [x] Red before the declaration, green after: the inventory reported
      `lib/api.ts:639: Connector — PATCH … answers no declared response model`, then
      the gate passed with `6 routes`.
- [x] The binding answer equals the connector list row for the same connector —
      asserted as whole-dictionary equality in the lifecycle test, which meant the
      test's own final audit assertion had to name its one exception
      (`connectors.list` writes its row with `user_id=None` by design).
- [x] The connector and account suites stay green (`test_source_accounts_api.py` 12
      passed; `test_connectors_protocol_api.py`, `test_connector_admin_edges.py` and
      `test_dashboard_overview.py` 80 passed).
- [x] `ruff check app tests scripts` clean; the documentation/type gates plus
      `test_api_docs_contract.py` — 105 passed. The mypy ratchet was not run: it lives
      in the tooling container and the Docker daemon was unreachable here.

## Progress and Milestones

- **2026-10-23 — opened.** Picked to finish the connector admin group: after this,
  every connector route the SPA reads declares its answer.
- **2026-10-23 — closed.** Six routes remain: the alert queue, the audit views
  (actions and integrity), the dashboard overview, the exposure page and the
  phishing evidence view.
