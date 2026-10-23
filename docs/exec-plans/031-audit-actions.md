# Plan 031 — the audit filter catalogue, declared

**State:** done — 2026-10-23: `AuditActionsCatalog` on the filter catalogue, the inventory is 4

## Goal

`GET /api/v1/audit/actions` answers the filter catalogue the audit page builds from:
the actions an operator may filter by, grouped by their first prefix segment, plus a
flat sorted list, a total and the human labels. The SPA reads it as
`AuditActionsCatalog`; the route returns a dict, so those four field names are
checked by the compiler alone.

This is the smallest remaining entry and it opens the audit pair. Two things are worth
stating:

1. **The four keys are always sent.** The client marks all four optional, but the
   route always builds them, and the models say so: `groups`, `total`, `actions`,
   `labels`. Optionality on the client is a reader's convenience here, not a shape
   that varies.
2. **The catalogue's invariant is not a schema.** That every label names an action,
   that `total` equals the length of `actions`, and that the groups partition the flat
   list are properties of the composer and of `AUDIT_ALLOWED_ACTIONS`; a response model
   cannot express them. The new test asserts them beside the keys, so declaring the
   shape does not lose the test that already pinned the grouping.

## Plan of Work

| File | Change |
|---|---|
| `backend/app/api/v1/routers/audit.py` | `AuditActionGroup` and `AuditActionsCatalog` beside `AUDIT_ACTION_LABELS`; the route declares the model and builds it |
| `backend/scripts/check_api_types.py` | the `AuditActionsCatalog` pair, the entry deleted, the count 5 → 4 |
| `docs/production-readiness.md` | the limitation says 4, and the closed list names this route |
| `docs/exec-plans/README.md` | one row for this plan |
| `backend/tests/test_audit_router_filters.py` | the shape test: four keys, two group keys, and the partition invariant beside them |

## Concrete Steps

1. **Red first.** Add the pair and delete the entry: the gate reports the typed read
   of a route that declares no model.
2. **The models.** `AuditActionGroup` (`category`, `actions`) and
   `AuditActionsCatalog` (`groups`, `total`, `actions`, `labels`).
3. **The route.** Replace the dict with the model; `_group_actions_by_prefix` and the
   label map are untouched, so the catalogue keeps the order and content it has.
   *Acceptance:* the gate is green, the entry is gone, and the payload is identical.

## Validation and Acceptance

- [x] Red before the model, green after: the inventory reported
      `lib/api.ts:606: AuditActionsCatalog — GET /api/v1/audit/actions answers no
      declared response model`, then the gate passed with `4 routes`.
- [x] The answer keeps its four keys and its two-key groups, and the groups partition
      the flat list exactly: the extended test collects every action from every group
      and requires the sorted union to equal `actions` with no duplicate, and every
      label key to be a published action.
- [x] The audit suites stay green (`test_audit_router_filters.py` 15 passed;
      `test_audit_routers_integration.py` and `test_audit_map_gate.py` — 36 passed
      together with it).
- [x] `ruff check app tests scripts` clean; the documentation/type gates plus
      `test_api_docs_contract.py` — 105 passed. The mypy ratchet was not run: it lives
      in the tooling container and the Docker daemon was unreachable here.

## Progress and Milestones

- **2026-10-23 — opened.** Picked as the first of the two audit views because it is  the one whose payload has no computed timestamps, so the declaration is the whole change.
- **2026-10-23 — closed.** Four routes remain: the alert queue, the audit integrity
  view, the exposure page and the phishing evidence view.
