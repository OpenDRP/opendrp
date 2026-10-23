# Plan 032 — where the chain stands, declared

**State:** done — 2026-10-23: `AuditIntegrity` on the status view, the inventory is 3

## Goal

`GET /api/v1/audit/integrity` is the status the audit page prints: how far full
verification has run, what the chain has committed, what the archive holds, how much
history is retained, what retention has retired, when verification last passed, and
how many signing keys are configured. The SPA reads it as `AuditIntegrity`; the route
returns a dict, so the seven blocks and their seventeen field names are checked by the
compiler alone.

Decisions:

1. **Two spellings of "when", and both are kept.** `full_verification.at` is the chain
   state's `datetime`, passed through as-is; `last_verification.at` is already ISO text
   because the route calls `.isoformat()` on it. The model mirrors that instead of
   "correcting" it: declaring the second one a `datetime` would re-parse text the
   composer chose to publish as text, and an aware value would change suffix. Two
   fields with the same meaning are the composer's asymmetry, not a schema's to fix.
2. **One shape, two blocks.** `committed` and `retired` are both
   `{through_seq, tip_hash}` — the highest position the chain has written, and the
   highest it has removed — so one `AuditChainMark` describes both. A second identical
   model would be a second place to change.
3. **Nulls are the answer, not a gap.** `tip_hash: null` on an empty chain,
   `failure_seq: null` when nothing failed, `archive.last_seq: null` when nothing was
   archived. The route takes no `exclude_none`; a key that disappeared would leave the
   page unable to tell "never" from "not sent".
4. **The numbers are counts and positions.** `retained.rows/first_seq/last_seq` are
   computed before the request writes its own audit row (the route's comment says so),
   and `keys.configured` is a count of key material this process holds — not a list of
   keys, which is exactly what the model must not turn it into.

## Plan of Work

| File | Change |
|---|---|
| `backend/app/api/v1/routers/audit.py` | `AuditFullVerification`, `AuditChainMark`, `AuditArchiveState`, `AuditRetainedRange`, `AuditLastVerification`, `AuditKeyState`, `AuditIntegrity`; the route declares the model and builds it |
| `backend/scripts/check_api_types.py` | the `AuditIntegrity` pair, the entry deleted, the count 4 → 3 |
| `docs/production-readiness.md` | the limitation says 3, and the closed list names this route |
| `docs/exec-plans/README.md` | one row for this plan |
| `backend/tests/test_audit_routers_integration.py` | the existing integrity test gains the nested key sets of all seven blocks |

## Concrete Steps

1. **Red first.** Add the pair and delete the entry: the gate reports the typed read of
   a route that declares no model.
2. **The models.** Seven classes beside `AuditActionsCatalog`, sharing `AuditChainMark`
   between `committed` and `retired`.
3. **The route.** The audit row is written from the same locals as before — it quotes
   the retained count and the retirement cursor — and the return value becomes the
   model.
   *Acceptance:* the gate is green, the entry is gone, and the payload keeps every
     value the integration test already asserts, including both `at` spellings.

## Validation and Acceptance

- [x] Red before the models, green after: the inventory reported
      `lib/api.ts:604: AuditIntegrity — GET /api/v1/audit/integrity answers no declared
      response model`, then the gate passed with `3 routes`.
- [x] All seven blocks answer their declared keys — asserted field by field in
      `test_audit_routers_integration.py` — and every value that test already pinned
      is unchanged: retained range, retirement cursor, verification cursor and
      failure, both `at` spellings, the archive flags and the key count.
- [x] The audit suites stay green (`test_audit_routers_integration.py` 17 passed;
      `test_bounded_audit_lifecycle.py`, `test_audit_archive_reliability.py` and
      `test_audit_router_filters.py` — 29 passed together).
- [x] `ruff check app tests scripts` clean; the documentation/type gates plus
      `test_api_docs_contract.py` — 105 passed. The mypy ratchet was not run: it lives
      in the tooling container and the Docker daemon was unreachable here.

## Progress and Milestones

- **2026-10-23 — opened.** The second and last audit view; its payload is the largest
  nested one left (seven blocks), and the only one where two fields describe the same
  idea in two types.
- **2026-10-23 — closed.** Three routes remain: the alert queue, the exposure page and
  the phishing evidence view.
