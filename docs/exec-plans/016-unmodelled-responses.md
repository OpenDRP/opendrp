# Plan 016 — the responses the API does not describe

**State:** done — 2026-10-23: 28 routes inventoried, and the list fails in both directions

## Goal

Plan 015 closed the path half of the client contract. It left one sentence standing
in `backend/scripts/check_api_types.py`, where rule 2 is described:

> Routes that answer an undeclared dict (`GET /alerts/queue`, `GET /audit/integrity`,
> ...) have no schema to compare with

That sentence was a count nobody had taken: AUD-060's own row says "five of them
added for routes that answer a dict", and the tree holds **28**. Rule 2 compares two
declarations, and on these routes the server makes none — it returns a `dict`, the
OpenAPI document publishes `{}`, and the interface the SPA reads is checked by nobody.
A field renamed on the server still compiles, and the page still fails in the browser.

Declaring 28 response models in one change is not this plan. Each one changes a
payload: FastAPI validates and filters through `response_model`, so a model that
omits a field the client does not read silently removes it from the wire, and a
model that requires one the handler can omit turns a working response into a 500.
That is a contract change per route, and it needs a plan of its own — with the list
below as its work items. What this plan does is make the list exist and make it
hold:

1. **It is exact.** A typed read of a route that declares no model must be listed,
   and an entry whose route gained a model is stale and has to go. Both directions
   fail the build, so the list cannot grow by accident or rot after a fix.
2. **It is measured.** 28 routes, 19 interfaces — not a rounded number in a docstring.
3. **It is honest about what it is.** Every entry names the interface the SPA reads
   from that payload, so the remaining work is readable without opening the client.

## Plan of Work

| File | Change |
|---|---|
| `backend/scripts/check_api_types.py` | rule 4 and `UNMODELLED` (28 routes with the interface read from each); `Call.response` carries the generic, so the rule knows which declaration to look for; the docstring's sentence becomes a description of the rule |
| `backend/tests/test_api_types_gate.py` | the rule's proof: an unlisted read, an inventoried one, a stale entry, a declared schema needing no entry, a container and a DOM type that are not interfaces, and the real tree |
| `docs/production-readiness.md` | the "what is enforced" row and limitation 5 name the inventory and what it does and does not close |
| `docs/exec-plans/README.md` | one row for this plan |

## Concrete Steps

1. **Read the generic.** The scanner already skipped a generic to reach the path;
   it now keeps its text, so `api.get<AuditIntegrity>("/audit/integrity")` is a call
   that reads `AuditIntegrity` and `api.get<void>(...)` is not an interface read.
2. **Decide what counts as declared.** A `$ref` is a model; an array of `$ref` is a
   model of its rows; an empty schema is a route that returns a dict, which is the
   subject here. `properties` counts too, for an inline schema that says something.
3. **The inventory.** One line per route, keyed by the spec's own spelling so a
   renamed route cannot leave an entry silently matching nothing.
   *Acceptance:* the real tree passes, and both directions fail when perturbed —
   removing an entry reports the typed read that is now unchecked, adding a route
   that does not exist reports the stale key.
4. **The pages.** Limitation 5 said the client's path literals were unchecked; plan
   015 fixed that. It now also carries the response half: 28 routes whose payload the
   server does not describe, listed, and unable to grow unnoticed.

## Validation and Acceptance

- [x] The inventory is exact against the tree: `23 passed` in
      `tests/test_api_types_gate.py`, including the real-tree test that fails when an
      entry and a read disagree.
- [x] Both directions were observed failing on the shipped tree (no file edits, the
      inventory mutated in memory). Dropping `GET /api/v1/alerts/queue` reports
      `lib/api.ts:603: AlertQueueSummary — GET /api/v1/alerts/queue answers no declared
      response model, so its fields are unchecked`; adding a key no route matches
      reports the stale entry and asks for its removal.
- [x] `python scripts/check_api_types.py` passes and prints the count: *"the 28 routes
      that declare no model are the ones listed"*.
- [x] `ruff` clean on the two changed files; the mypy ratchet is unaffected (`app` is
      its only target and no application file changed).
- [x] The documentation gates that read the edited pages stay green.

## Progress and Milestones

- **2026-10-23 — opened from a measurement, not a suspicion.** A throwaway pass over
  the 109 calls and the OpenAPI document found 28 routes whose successful response
  publishes no schema and 19 interfaces read from them: `AlertQueueSummary`,
  `AuditIntegrity`, `AuditActionsCatalog`, `RuntimeConfiguration`, `DashboardOverview`,
  `ScanStartResult`, `PromotedAsset`, `CleanupResult`, `TestDeliveryResult` and nine
  more. The docstring said "five"; AUD-060's row said five; both were counts taken by
  hand at one moment and never again.
- **2026-10-23 — closed.** The inventory is the rule, not a table beside it. The gate
  now fails for a typed read that is not listed, and for a listed route that has been
  given a model — which is the procedure for closing an entry, written down where the
  next plan will find it.
