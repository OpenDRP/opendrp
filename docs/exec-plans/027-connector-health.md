# Plan 027 — connector health, one shape for every role

**State:** done — 2026-10-23: `ConnectorHealthResponse` on the health page, the inventory is 8

## Goal

`GET /api/v1/connectors/health` answers one row per registered connector: what it
is, whether it is alive, what its provider credentials and last success say, and —
for an administrator only — the key's state, the day's remaining budget and why the
core would refuse the next scan. The SPA reads the envelope as
`ConnectorHealthResponse` and each row as `ConnectorHealth`; the route declares
`response_model=dict`, so nineteen field names are checked by the compiler alone.

This entry's shape decisions are its own, and each is written down because a later
step could copy the wrong one:

1. **Nulls are part of the contract here.** The admin-only fields (`last_error`,
   `quota_*`, `blocked_reason`, `readiness`) are sent as `null` to a viewer on
   purpose — the code says so, and
   `test_connector_admin_edges.py` asserts it — so the shape a viewer and an
   administrator see is the same and the page does not have to branch on which keys
   exist. So this route takes `response_model` with **no** `exclude_none`: the exact
   opposite of the source-account list, and the reason those two neighbouring
   endpoints get different decorators.
2. **`checked_at` is text, not a timestamp.** It is copied out of the worker's
   readiness document, where it is whatever the worker wrote; declaring a `datetime`
   would either refuse a value the worker sent or silently rewrite it. The model
   keeps `str | None`, and the composer's `isinstance(..., str)` guard stays the only
   thing that decides what can appear there.
3. **Two free-form documents stay free-form.** `readiness` (administrator only) and
   `info` (already filtered to an allowlist of keys, with a value-type check) are
   `dict[str, Any]`: the guard that keeps a provider's prose out of `info`, and the
   credential fields out of a viewer's answer, is in the composer, and a model must
   not pretend to re-encode it.
4. **The enums are closed.** `health`, `status` and `credential_state` are `Literal`s
   of the values the composer can produce (`ConnectorStatus.ALL`,
   `_CREDENTIAL_STATES`, and the four health branches), so a new state is a change to
   the declaration rather than a string nobody listed.

## Plan of Work

| File | Change |
|---|---|
| `backend/app/api/v1/routers/connectors.py` | `HealthState`, `ConnectorHealth` and `ConnectorHealthResponse` beside `ConnectorOut`; the route declares the response model and answers it (no `exclude_none`) |
| `backend/scripts/check_api_types.py` | the `ConnectorHealth` and `ConnectorHealthResponse` pairs, the entry deleted, the count 9 → 8 |
| `docs/production-readiness.md` | the limitation says 8, and the closed list names this route |
| `docs/exec-plans/README.md` | one row for this plan |
| `backend/tests/test_connector_admin_edges.py` | the viewer test gains the key set: nineteen keys on every row, the admin ones present and `null` |
| `backend/tests/test_connectors_protocol_api.py` | the administrator test: the same nineteen keys, `generated_at`, and `checked_at` staying the worker's text |

## Concrete Steps

1. **Red first.** Add both pairs and delete the entry: the gate reports the typed
   read of a route that declares no model.
2. **The models.** `ConnectorHealth` with the nineteen fields the composer already
   builds, typed as the composer's own values; `ConnectorHealthResponse` with `items`
   and `generated_at`.
3. **The route.** Replace `response_model=dict` with the model and return
   `ConnectorHealthResponse(items=items, generated_at=now)`. The rows stay dicts from
   `connector_health_items`, which the dashboard overview also calls — that function
   is untouched, so the dashboard keeps composing from the same list until its own
   entry is taken.
   *Acceptance:* the gate is green, the entry is gone, and both roles get the same
     nineteen keys with the same values; the only wire difference is that the three
     aware UTC timestamps (`last_seen_at`, `last_success_at`, `generated_at`) now end
     in `Z`.

## Validation and Acceptance

- [x] Red before the model, green after: two failures first — both new pairs named a
      schema missing from the OpenAPI document, and `lib/api.ts:502` was reported as
      a typed read of an undeclared response — then 23 passed with `8 routes`.
- [x] A viewer and an administrator receive the same nineteen keys, and the admin
      fields are `null` for the viewer rather than absent: asserted in
      `test_connector_admin_edges.py` (the viewer case) and in
      `test_connectors_protocol_api.py` (the administrator case).
- [x] `checked_at` is forwarded byte-for-byte: the new test stores
      `2026-10-23T05:00:00.123456+02:00` in the readiness document and requires that
      exact string back, which a `datetime` field would have normalized to UTC.
- [x] The connector suites stay green (`test_connector_admin_edges.py`,
      `test_connectors_protocol_api.py`, `test_dashboard_overview.py` — 80 passed),
      so the shared composer still feeds the dashboard.
- [x] `ruff check app tests scripts` clean; the four documentation/type gates — 97
      passed, and `test_api_docs_contract.py` — 8 passed. The mypy ratchet was not
      run: it lives in the tooling container and the Docker daemon was unreachable
      here.

## Progress and Milestones

- **2026-10-23 — opened.** Picked from the remaining nine because it is the first
  entry whose payload differs by role, which forces the plan to state why the nulls
  stay — a decision the two previous steps made the other way.
- **2026-10-23 — closed.** Eight routes remain: the alert queue, the audit views
  (actions and integrity), the dashboard overview, the connector module inventory
  and account patch, the exposure page and the phishing evidence view.
