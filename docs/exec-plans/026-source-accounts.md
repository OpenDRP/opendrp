# Plan 026 — the account inventory, with its policy named

**State:** done — 2026-10-23: `SourceAccountOut` on the account list, the inventory is 9

## Goal

`GET /api/v1/connectors/accounts` answers the source accounts an operator can bind a
connector to: identity, the secret-manager reference, the quota policy, the access
state and whether a key is stored. The SPA reads it as `SourceAccount`; the route
builds a dict per row, so the eight field names and the three policy fields the
settings page renders are checked by nothing but the client.

Two properties of the payload decide the shape, and neither is the previous step's:

1. **`policy` is a JSON column, not a set of columns.** Today it holds
   `{"approved": false}` until an operator approves a quota, then the same three keys
   the approve route writes. A model that named only the three and dropped anything
   else would delete a value the column actually holds — a restored database, or a
   row written before the history-credit field was removed, is not restricted to
   today's writer. So the policy model declares the three fields the SPA reads and
   sets `extra="allow"`: a key it does not name is forwarded, not silently cut.
2. **Absence and null are mixed in one answer.** A row with no secret reference and
   no stored key carries `credential_ref: null` and `api_key_hint: null`, while the
   policy's budgets are *absent* until approval — and `{"approved": false}` must stay
   that one key, since the settings page reads a missing budget as "use the default".
   One decorator cannot keep both conventions: naming the budgets at all emits them
   as `null` unless the route excludes nulls. The route therefore takes
   `response_model_exclude_none=True`, which keeps the policy byte-identical and
   drops the two top-level null keys the client already declares optional
   (`credential_ref?`, `api_key_hint?`). That is the stated change: on a row with no
   value those keys disappear rather than arriving as `null`.

`has_api_key` and the hint stay derived from the encrypted column; the model names
them and never the ciphertext.

## Plan of Work

| File | Change |
|---|---|
| `backend/app/api/v1/routers/connectors.py` | `SourceAccountPolicy` and `SourceAccountOut` beside `ConnectorOut`; the list route takes `response_model=list[SourceAccountOut]` with `response_model_exclude_none=True`, and builds the model instead of a dict |
| `backend/scripts/check_api_types.py` | the `SourceAccount` pair, the entry deleted, the count 10 → 9 |
| `docs/production-readiness.md` | the limitation says 9, and the closed list names this route |
| `docs/exec-plans/README.md` | one row for this plan |
| `backend/tests/test_source_accounts_api.py` | the contract test: the keys the client reads, `policy` before and after approval, and an unnamed policy key surviving the model |

## Concrete Steps

1. **Red first.** Add the pair and delete the entry: the gate reports the typed read
   of a route that declares no model.
2. **The models.** In the router, where `ConnectorOut` already lives:
   * `SourceAccountPolicy` — `approved: bool = False`, `requests_per_minute: int |
     None`, `daily_budget: int | None`, `model_config = ConfigDict(extra="allow")`.
     `approved` defaults to `False` because the column's own default is `{}`, and an
     empty policy means "not approved" everywhere it is read.
   * `SourceAccountOut` — `id`, `source_id`, `name`, `credential_ref`, `policy`,
     `access_state`, `has_api_key`, `api_key_hint`.
3. **The route.** One decorator argument and one constructor; the query and the
   ordering are untouched.
   *Acceptance:* the gate is green, the entry is gone, and each row answers the same
     values — `policy` exactly as stored, six keys on a fresh row (the two nulls
     gone), eight on a row with a reference and a key.

## Validation and Acceptance

- [x] Red before the model, green after: two failures first — the pair named a
      schema missing from the OpenAPI document, and `lib/api.ts:632` was reported as
      a typed read of an undeclared response — then 23 passed with `9 routes`.
- [x] The payload is checked, not assumed: `test_source_accounts_api.py` asserts the
      six keys of a fresh row, `policy == {"approved": false}`, `has_api_key` false,
      the three policy keys after approval, and a stored policy key the model does
      not name
      (`max_certificate_history_credits`) still being forwarded.
- [x] The account suites stay green (`test_source_accounts_api.py` 12 passed,
      `test_connector_admin_edges.py` + `test_connectors_protocol_api.py` 74 passed),
      and the existing lifecycle test still asserts the list stays admin-only.
- [x] `ruff check app tests scripts` clean; `test_docs_consistency_gate.py`,
      `test_docs_numbers_gate.py`, `test_api_types_gate.py` and
      `test_critical_coverage_docs.py` — 97 passed. The mypy ratchet was not run: it
      lives in the tooling container and the Docker daemon was unreachable here.

## Progress and Milestones

- **2026-10-23 — opened.** The entry was picked from the remaining ten because it is
  the only one whose payload carries a JSON column, so the model has to decide
  whether it describes that column or truncates it.
- **2026-10-23 — closed.** Nine routes remain: the alert queue, the audit views
  (actions and integrity), the dashboard, the connector inventory (health, modules
  and the account patch), the exposure page and the phishing evidence view.
