# Plan 038 — the literals that already had a name

**State:** done — 2026-10-23: four literals named, four routes declared, 41 pairs, the inventory still empty

## Goal

Rule 4 compares a *declared* interface with the model a route sends. The client
writes four response shapes as inline object literals instead, so no rule can see
them, and two of those literals are duplicates of an interface that already exists:

| Helper | Literal today | Interface that already says it |
|---|---|---|
| `scanModule` → `POST /modules/{module_id}/scan` | `{ status; job_ids; sources: {connector; status; reason?}[] }` | `ScanStartResult` (plan 023 named six scan answers) |
| `cleanOrphanDNSObservations` → `POST /dns/observations/cleanup-orphans` | `{ status; deleted }` | `CleanupResult` (plan 017 named the other two cleanup routes) |
| `revokeOtherSessions` → `POST /auth/sessions/revoke-others` | `{ revoked: number }` | none — the same shape as the admin route below |
| `revokeUserSessions` → `DELETE /users/{user_id}/sessions` | `{ revoked: number }` | none |

Two consequences, both of them the class this program has been closing:

1. **The payload has two descriptions and neither is compared with the server.**
   `scanModule`'s literal is a third spelling of what `ScanStartResult` already
   says, so a field added to one is not a failure in the other. `CleanupResult` is
   compared with `CleanupResponse` — but the DNS cleanup route's own answer was
   never in that comparison, because the route declares no model and the client
   wrote the shape inline.
2. **Plan 023's own post-check could not see this route.** It declared
   `ScanStartResponse` on six scan routes and measured the client's helpers; the
   module scan was outside that measurement for the reason above, and it still
   answers an unmodelled dict.

The work is naming the literals and declaring the four answers, which takes the
inventory from "empty" to "empty and checked": the number does not move, the
surface the number covers does.

Decisions:

1. **`ScanStartResult` and `CleanupResult` are reused, not re-declared.** One payload
   with two names is exactly the drift this plan removes.
2. **The two revoke answers share one new interface, `RevokedSessions`.** Both send
   one key, both are a count of families ended, and the client's two helpers now
   cannot disagree about it. The server model goes in `common.py` beside
   `CleanupResponse`, which is the module for a shape two routers answer.
3. **The module scan declares `ScanStartResponse` with `exclude_none=True`.** Its
   dict has exactly `status`, `job_ids` and `sources`, so nothing becomes `null` and
   the answer is byte-identical; the refusal path (`409` with the same result as its
   detail) bypasses the model, as it did before.
4. **The DNS cleanup answers `CleanupResponse`.** The route already sent
   `{"status": "completed", "deleted": n}`; the shared model is the same two keys,
   and the audit row written beside it is untouched.

## Plan of Work

| File | Change |
|---|---|
| `frontend/src/lib/api.ts` | the four literals become `ScanStartResult`, `CleanupResult`, and `RevokedSessions` twice |
| `frontend/src/types/api.ts` | `RevokedSessions`, beside `CleanupResult` |
| `backend/app/schemas/common.py` | `RevokedSessionsResponse`, beside `CleanupResponse` |
| `backend/app/api/v1/routers/source_inventory.py` | `response_model=ScanStartResponse`, `exclude_none` |
| `backend/app/api/v1/routers/dns_security.py` | `response_model=CleanupResponse`; the route answers the model |
| `backend/app/api/v1/routers/auth.py` | `response_model=RevokedSessionsResponse`; the return annotation follows |
| `backend/app/api/v1/routers/users.py` | the same for the admin revocation |
| `backend/scripts/check_api_types.py` | the pair `RevokedSessions` → `RevokedSessionsResponse` |
| `backend/tests/test_api_types_gate.py` | red first: a named read of a route that answers an undescribed row is reported |
| `docs/production-readiness.md` | limitation 5 names the literals as the remaining blind spot, and the four that left |
| `docs/exec-plans/README.md` | one row for this plan |

## Concrete Steps

1. **Red first.** Name the four client reads. The gate then reports four
   disagreements — the inventory is empty and none of these routes declares a row —
   which is the measurement that proves the literals were the only thing hiding them.
2. **The shared model.** `RevokedSessionsResponse` in `common.py`, and the client's
   `RevokedSessions`.
3. **The four routes.** Declare, and answer the model where the route builds a dict.
   *Acceptance:* the gate is green again, `RevokedSessions` is compared field for
   field, and every payload keeps its keys.

## Validation and Acceptance

- [x] `python scripts/check_api_types.py` — red with exactly `4 disagreement(s)` after
      step 1, naming `RevokedSessions` on both revocation routes, `ScanStartResult` on
      `POST /modules/{module_id}/scan` and `CleanupResult` on the DNS cleanup; green
      after step 3 with `41 interfaces` compared, `109 request calls` and the
      inventory empty.
- [x] `pytest tests/test_api_types_gate.py` — green; the shipped-tree inventory test
      still passes with no entries, which is the assertion that would fail if a pair
      had been added without a model.
- [x] `pytest tests/test_source_inventory_api.py tests/test_dns_security_api.py
      tests/test_auth_integration.py tests/test_users_operator_surface.py
      tests/test_api_types_gate.py` — 92 passed, including the tests that already pin
      `{"revoked": n}`, the module-scan answer and the DNS cleanup's two keys.
- [x] `cd frontend && npx tsc -b` — the first run failed, and that is the part worth
      recording: `ExposurePage.tsx:104` and `PhishingPage.tsx:320` read
      `result.sources.map(…)` unguarded, which compiled only because `scanModule`'s
      literal promised `sources` as **required** while the shared `ScanStartResult`
      declares it optional (six scan routes, only some of which report per-source
      admission). Both pages now read `(result.sources ?? [])`, so the type and the
      code agree; the second `tsc -b` is clean. 156 client tests across five files
      pass (`endpoints.test.ts` included).
- [x] `ruff check app tests scripts` clean; with the four documentation/audit gates
      and `test_authorization_denials` the backend run was 116 passed. The mypy
      ratchet was not run: it lives in the tooling container, unreachable here (plans
      032–037 recorded the same).

## Progress and Milestones

- **2026-10-23 — opened.** Plan 037 emptied the inventory of undeclared rows; the
  literals are what the rule cannot ask about at all, and two of them name a payload
  the API already models elsewhere.
- **2026-10-23 — closed.** The measurement moved without the inventory moving: four
  literals became declarations, four routes gained models, the pair count went from
  40 to 41 and `UNMODELLED` stayed empty. The compiler's objection is the plan's best
  evidence that the literals were not merely untidy — a hand-written duplicate can
  claim a field is required while the interface the rest of the client uses says it
  is optional, and nothing reconciles the two. Plan 023 made the same six-route
  decision and could not check this route, because the client never named the type.
