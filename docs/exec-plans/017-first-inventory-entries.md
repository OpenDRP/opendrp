# Plan 017 — the first two entries leave the inventory

**State:** done — 2026-10-23: `CleanupResult` is modelled, and the inventory is 26

## Goal

Plan 016 turned the gate's "five of them" sentence into 28 routes with the interface
the SPA reads from each. It also wrote down the procedure for removing an entry:
declare a response model on the route, add the pair when the interface is one of the
schema-backed ones, and delete the entry — the rule reports it as stale until then.
This plan runs that procedure once, on the smallest pair in the list, so the loop is
proven before anybody batches the rest.

`CleanupResult` is the smallest entry by every measure:

- the payload is two keys, `{"status": "completed", "deleted": <count>}`, built in the
  same shape by both routes that answer it (`POST /api/v1/breaches/cleanup-orphans`
  and `POST /api/v1/phishing/threats/cleanup-orphans`);
- both values are always present, so no optional-field or null-exclusion decision is
  needed — the model either says exactly what the handlers send or the tests fail;
- the SPA already declares the interface exactly (`status: string`, `deleted: number`),
  so no page changes.

The other 26 stay for their own plans. `TestDeliveryResult` is the instructive
counter-example and is deliberately not here: one interface describes two routes that
send different payloads (`{status, to}` for mail, `{sent, total, results}` for
Telegram), so closing it is a client split first and a model second; `PromotedAsset`
returns an ORM object on two routes and a dict on two others; and the composed
payloads (`DashboardOverview`, `AuditIntegrity`, `RuntimeConfiguration`) are their own
contract each.

## Plan of Work

| File | Change |
|---|---|
| `backend/app/schemas/common.py` | `CleanupResponse`, the shape both cleanup routes send |
| `backend/app/api/v1/routers/breaches.py`, `backend/app/api/v1/routers/phishing.py` | `response_model=CleanupResponse` on the two cleanup routes |
| `backend/scripts/check_api_types.py` | the `CleanupResult` pair, both `UNMODELLED` entries deleted, and the docstring/inventory count brought from 28 to 26 |
| `backend/tests/test_api_types_gate.py` | the real-tree inventory test already proves the deletion; the schema pair is proven by the existing shipped-tree test, red before the model exists |
| `docs/production-readiness.md` | the limitation says 26, and what closing one looks like |
| `docs/exec-plans/README.md` | one row for this plan |

## Concrete Steps

1. **Red first, in both directions.** Add the pair and delete the two entries before
   the model exists: rule 2 then fails with `CleanupResponse: named by CleanupResult
   but missing from the OpenAPI document`, and rule 4 fails because the two routes now
   declare no model and are no longer listed. Both are the gate doing its job.
2. **The model.** `CleanupResponse` in `app/schemas/common.py`, beside the other
   response shapes that more than one router answers with. `status: str`,
   `deleted: int` — the same two fields `AssetService` counts, so the audit row and
   the response cannot disagree about what was deleted.
3. **The routes.** `response_model=CleanupResponse` on both decorators, which also
   puts the payload in the OpenAPI document where rule 2 can compare it with the
   client's interface.
   *Acceptance:* the gate is green, the two entries are gone, and both cleanup tests
   still see `{"status": "completed", "deleted": N}` — the model describes the payload
   rather than changing it.

## Validation and Acceptance

- [x] Both rules were red before the model existed and green after it; the red text is
      the gate's own (step 1), not a synthetic fixture.
- [x] `python scripts/check_api_types.py` prints `the 26 routes that declare no model
      are the ones listed`, and the `CleanupResult` pair is compared field by field.
- [x] The two cleanup routes' suites stay green, with the response unchanged:
      `tests/test_breaches_gaps.py`, `tests/test_assets_router_edges.py`,
      `tests/test_phishing_router_edges.py` and the router integration suites.
- [x] `ruff` clean and the mypy ratchet compared with its baseline; the OpenAPI
      document gained one schema and no route.
- [x] The documentation gates that read the edited pages stay green.

## Progress and Milestones

- **2026-10-23 — opened as one entry, deliberately.** The remaining 27 are not all the
  same kind of work, and batching them would hide that behind one number.
- **2026-10-23 — closed.** `CleanupResponse` is declared on both routes, the two
  entries are gone, and the inventory is 26. The procedure plan 016 wrote down works
  unchanged, which is what this plan existed to check.
