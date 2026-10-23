# Plan 039 — the last literals, and the evidence that says so

**State:** open — opened 2026-10-23

## Goal

Two pieces of unfinished business are left after plan 038, and they are the same
kind of problem: a claim that nothing checks against the tree.

1. **Twelve client answers are still written as inline object literals.**
   `backend/scripts/check_api_types.py` compares *declarations* — an interface in
   `frontend/src/types/api.ts` against the model a route sends — and a literal is
   not one, so twelve helpers sit outside every rule. Four of them duplicate a
   payload the API already models, so the client and the server describe it twice
   and nothing reconciles the two. The other eight name routes that declare no
   response model at all, which is why no evidence exists on either side.

2. **The readiness page's record of the suite is four plans behind.** Limitation 17
   still opens with "the backend suite is not green outside a full stack" and cites
   18 failures out of 1,806 collected on 2026-10-08, while the 2026-10-23 single
   run recorded 3,539 passed, 16 skipped and no failures in 1:29:03. The appendix
   that is supposed to hold that run ends at the 2026-10-08 four-shard measurement,
   and the audit's own "what this audit did not verify" still says the suite was
   never run in one process, which plan 014 closed. An operator reading the page
   cannot tell a skip from a failure, and the best evidence the project has is
   recorded nowhere the page points at.

The work closes both without inventing a rule: it names the twelve payloads, so the
existing gate compares them, and it replaces a dated paragraph with the run that
exists. The measurement at the end is the pair count and `UNMODELLED` — not a new
gate.

What "done" means: the twelve helpers read a declared interface, the eight routes
answer a declared row, `check_api_types.py` is green with an empty `UNMODELLED` and
a pair count that names every one of them, the whole suite is green in one process
after the last model and the result is written on the readiness page, and the
generation question is answered in writing rather than left as an intention.

Decisions taken here, so a later step does not re-open them:

1. **A route that answers a projection declares the projection, not its source
   row.** `POST /connectors/accounts` answers `{"id": …}` and nothing else; the
   model names that key rather than reusing `SourceAccountOut` with seventeen
   fields missing.
2. **A payload with two spellings gets one interface.** The two `api-key` routes
   (`PUT`, `DELETE`) send `id`, `has_api_key` and `api_key_hint`, so they share
   `SourceAccountApiKey` — the same reason plan 038 gave `RevokedSessions` to both
   revocation routes.
3. **`null` stays distinguishable from absent, per route.** `api_key_hint` is
   declared nullable (the route sends `null` for a key it cannot show) and the
   answer is not `exclude_none`; `POST /breaches/domain-verification` sends `error`
   only on a refusal, so its model keeps it optional and the route stays as it is.
   This follows 026 (nulls kept) against 027 (nulls sent to everyone by role) —
   the payload decides, not a house style.
4. **The two literal shapes that already exist are reused, never re-declared.**
   `UserInviteResponse` covers both invitation routes and `UserBulkResponse` the
   batch, so the client's two copies of the invitation payload become one
   interface.
5. **The generation decision is written down, not built.** Replacing 41 hand-written
   interfaces with a client generated from `/openapi.json` is a migration with its
   own plan; this one records the comparison and the reasons in the readiness
   limitation that already describes the class.

## Plan of Work

| Step | Files | Change |
|---|---|---|
| 1. Land what exists | the working tree | the 291 changed and 79 untracked files become four commits: audit and register (009, 011, 012), test isolation and full-run findings (013, 014), the contract program (015–038), documentation. Staged by path, never `git add -A`. |
| 2. Evidence | `docs/production-readiness.md`, `docs/audit-findings.md`, `docs/project-map.md` | limitation 17 states the run that exists and separates skip from failure; the appendix gains the 2026-10-23 single-process row; the audit's third "did not verify" bullet becomes past tense with the plan that closed it; the map's test count moves from 3,363 to 3,539 with its date. |
| 3. Four answers whose model exists | `frontend/src/lib/api.ts`, `frontend/src/types/api.ts` | `UserInvite` (once, for both invitation helpers), `UserBulkResult`, `MfaRecoveryCodes` named; gate red first with four disagreements, then green. |
| 4. Connector-account writes | `backend/app/schemas/connector.py`, `backend/app/api/v1/routers/connectors.py`, `frontend/src/types/api.ts`, `frontend/src/lib/api.ts`, `backend/scripts/check_api_types.py` | `SourceAccountCreated`, `SourceAccountPolicy`, `SourceAccountApiKey` models and interfaces; `POST /connectors/accounts`, `PATCH /connectors/accounts/{account_id}/policy`, `PUT` and `DELETE /connectors/accounts/{account_id}/api-key` declare them; three pairs (four routes). |
| 5. The last four | `backend/app/schemas/report.py`, `backend/app/schemas/user.py`, `backend/app/api/v1/routers/reports.py`, `backend/app/api/v1/routers/auth.py`, `backend/app/api/v1/routers/breaches.py`, `backend/app/api/v1/routers/dns_security.py`, `frontend/src/types/api.ts`, `frontend/src/lib/api.ts` | `ReportQueued`, `InvitationAccepted`, `DomainVerificationStarted`, `TLSSightingReview` models and interfaces on `POST /reports/generate`, `POST /auth/accept-invitation`, `POST /breaches/domain-verification` and `PATCH /dns/certificates/sightings/{sighting_id}`; `response_model=dict` disappears from reports. |
| 6. The run and the record | `docs/production-readiness.md`, this plan | one-process backend suite, client suite, `tsc -b`, ruff; the numbers and the wall clock go into the appendix and into the progress log here. |
| 7. The decision | `docs/production-readiness.md`, this plan | limitation 5 keeps the class and gains the comparison: what generation removes, what it costs, and what would have to be true before it is worth doing. |
| — | `docs/exec-plans/README.md` | one row for this plan. |

## Concrete Steps

**Step 1 — land what exists.** Nothing below is safe to start on top of an
uncommitted tree of this size: a failed edit would take 24 plans of evidence with
it, and the four gates this program added have never run anywhere but this host.
*Acceptance:* `git status` clean; four commits whose messages name the plan range
each one lands; no file outside the four groups is staged.

**Step 2 — evidence first, before the models.** The page is corrected while the
number it describes is still true, so step 6 changes numbers rather than fixing a
claim. *Acceptance:* no sentence on the readiness page asserts a red suite; the
appendix holds the 2026-10-23 run with its command and wall clock; the audit's
bullet reads as history; `python -m pytest tests/test_docs_numbers_gate.py
tests/test_docs_consistency_gate.py tests/test_github_docs_claims.py
tests/test_audit_map_gate.py` is green.

**Step 3 — red first.** Name the four interfaces in `types/api.ts` and point the
helpers at them; the gate must answer exactly `4 disagreement(s)` — that is the
measurement that proves the literals were the only thing hiding these routes.
*Acceptance:* red with four, then green; `npx tsc -b` clean; `pytest
tests/test_api_types_gate.py` green; the tree inventory test still passes with no
entries.

**Step 4 — the writes that answer a receipt.** Declare the three shapes in
`schemas/connector.py`, where `SourceAccountOut` already lives, and answer them from
the four routes. `PATCH …/policy` keeps its `policy` as the ten-key object the page
reads; `api_key_hint` stays nullable and the answer keeps `null`. *Acceptance:* the
gate is red before the models and green after, with three new pairs; `pytest
tests/test_connectors_protocol_api.py tests/test_source_accounts_api.py
tests/test_connector_service_edges.py` green, and the existing assertions on
`{"id": …}` and on the two api-key keys unmoved.

**Step 5 — the four that never had a model.** `ReportQueued` names `status`,
`queue_state`, `report_id` and `job_id`, with the two literals typed as `Literal`
rather than free strings; `InvitationAccepted` names `status`;
`DomainVerificationStarted` names `status`, `domain`, `action`, `job_ids` and an
optional `error`; `TLSSightingReview` names `id`, `verdict` and the nullable
`reviewed_at` the page reads back. *Acceptance:* `response_model=dict` is gone from
`reports.py`; the gate is green with `UNMODELLED` empty and the pair count recorded
in the validation line (52 or 53 — the exact figure is a measurement, not an
assumption); `pytest tests/test_report_integration_report_service.py
tests/test_auth_integration.py tests/test_breaches_integration.py
tests/test_dns_certificates_api.py tests/test_api_types_gate.py` green; `tsc -b`
clean; `pytest` on the client suite for `endpoints.test.ts` and `api.test.ts` green.

**Step 6 — the run.** One process, not four shards: the point is that a single run
is the thing the page claims. *Acceptance:* the backend suite green with its skip
count unchanged at 16, the wall clock written down, ruff clean, and the appendix
row updated in the same commit as the plan's progress log.

**Step 7 — the decision.** Write the comparison in limitation 5: what a generated
client removes (the class, the literals, the hand-written paths), what it costs
(the error helpers, `describeApiError` and `flattenErrorDetail`, which are hand
shaped around the API's envelope), and the condition for doing it (a generated
client that keeps the envelope behaviour, or a wrapper that restores it).
*Acceptance:* the limitation names a decision and its condition; no code changes.

## Validation and Acceptance

- [ ] Step 1: `git status --porcelain` empty; `git log --oneline -4` names the four
      groups; `git show --stat` per commit contains no path from another group.
- [ ] Step 2: the four documentation gates green; the readiness page's limitation 17
      and appendix agree with each other; `grep -n "never once in one run"
      docs/audit-findings.md` finds no present-tense claim.
- [ ] Step 3: `python scripts/check_api_types.py` red with `4 disagreement(s)`, then
      green; `cd frontend && npx tsc -b` clean.
- [ ] Steps 4–5: the gate green at the end with `UNMODELLED` empty and every one of
      the twelve interfaces in the pair list; `grep -c "response_model=dict"
      backend/app/api/v1/routers/` returns 0.
- [ ] Step 6: `python -m pytest -q tests/` in one process — green, 16 skipped, the
      wall clock and count recorded here and in the appendix; `ruff check app tests
      scripts` clean.
- [ ] Step 7: limitation 5 names the decision and its condition.
- [ ] Not runnable here, and stated as such rather than assumed: the mypy ratchet
      (tooling container), the 16 PostgreSQL-only tests and the migration
      round-trip (Compose/CI), `docker compose up`, both E2E scripts.

## Progress and Milestones

- **2026-10-23 — opened.** Plan 038 left the inventory empty and the pair count at
  41, and named what the rule still cannot see: the inline literals. A measurement
  of the tree at `HEAD` found twelve of them on twelve routes, four with a server
  model already and eight with none, and the same pass found the readiness page's
  suite record four plans out of date. The plan was written to close both before any
  of it is described as finished.

## What this plan does not do

- **Generate the client.** It is a decision in step 7, not work here: 41 interfaces
  and 109 helpers across every page, and the error helpers are hand-shaped around
  the API envelope.
- **Re-open AUD-017.** The accepted risk keeps its sentence in the register and in
  `security.md`; nothing here changes the delivery path.
- **Give declared-module findings bulk transitions** (readiness limitation 7). It is
  a feature, not a contract, and it would widen a diff that is already 291 files.
- **Measure the providers.** Which endpoints a plan reaches stays a fact about an
  account, as the readiness page says.
