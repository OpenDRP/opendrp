# Plan 022 — the certificate scope, declared

**State:** done — 2026-10-23: both scope routes declare models, the inventory is 20

## Goal

`GET /dns/certificate-exceptions` is the list the certificate review reads: which
identities, keys, addresses, ASNs and issuers the scoring rules must not alert on.
It declared itself `response_model=list[dict]`, and the SPA reads eight fields from
it (`id`, `match_kind`, `match_value`, `reason`, `created_by`, `expires_at`,
`expired`, `created_at`). `expired` is the interesting one: it is computed at read
time from `expires_at`, so a model is where the rule "expired means the end date is
past, in UTC" can be stated.

Reading the pair surfaced a second defect, which this plan also closes because it is
the same resource two routes over: `POST /dns/certificate-exceptions` answers five
fields (`id`, `match_kind`, `match_value`, `reason`, `expires_at`), while the client
typed that answer as `Omit<CertificateScopeException, "expired" | "created_at">`,
which promises `created_by`. The field was never sent, nothing reads it, and rule 4
could not see the mismatch because the client's type is an expression rather than a
declared interface. That is the same class plan 018 fixed for the test-send answers,
found this time by modelling the neighbour.

## Plan of Work

| File | Change |
|---|---|
| `backend/app/api/v1/routers/dns_security.py` | `CertificateScopeExceptionResponse` (the list), `CertificateScopeExceptionCreated` (the 201 answer), both declared on their routes |
| `frontend/src/types/api.ts`, `frontend/src/lib/api.ts` | the created answer becomes its own interface with the five fields the route sends |
| `backend/scripts/check_api_types.py` | the `CertificateScopeException` pair, the inventory entry deleted, the count 21 → 20 |
| `docs/production-readiness.md` | the limitation says 20 |
| `docs/exec-plans/README.md` | one row for this plan |

## Concrete Steps

1. **Red first.** Declare the pair and delete the inventory entry: the gate reports
   the missing model and the read of a route that declares no model.
2. **The models.** `CertificateScopeExceptionResponse` declares the eight fields the
   service builds, with `match_kind` kept a `str` bounded by the same pattern the
   create payload uses rather than a second enum — the column stores those five
   spellings and the client types them as a union. `id` and `created_by` are
   `uuid.UUID`, the timestamps `datetime`, so the serialized form is the ISO string
   the SPA parses today. `CertificateScopeExceptionCreated` declares the five fields
   the 201 answer actually sends.
3. **The client.** A named `CertificateScopeExceptionCreated` replaces the `Omit<…>`
   expression, so the type says what the route sends; `created_by` was never read by
   any page, and a create result is discarded after the query invalidation.
   *Acceptance:* the gate is green, the entry is gone, the list answers the same eight
   keys, and the certificate-triage tests keep passing.

## Validation and Acceptance

- [x] Red before the models, green after: `15 interfaces`, `20 routes`.
- [x] The list payload is unchanged: the eight keys and their JSON forms are the ones
      `exceptions_payload` builds, including `expired` as a boolean computed in UTC.
- [x] The created answer is unchanged and the client's claim now matches it;
      `tsc -b` is clean.
- [x] `tests/test_api_types_gate.py`'s inventory test passes; the certificate suites
      and the DNS router edges stay green.
- [x] `ruff` clean; the mypy ratchet reports its baseline; the documentation gates
      that read the edited pages stay green.

## Progress and Milestones

- **2026-10-23 — opened.** The list entry is the inventory's, the created-answer
  mismatch is not: it was found by reading what the pair would have to declare.
- **2026-10-23 — closed.** Twenty routes remain, all of them composed or
  multi-variant payloads. The finding to carry forward: a client type written as an
  expression (`Omit<…>`, `{ a: string }`) is invisible to rule 4, and plan 018's
  lesson applies — the fix is a named interface, not a wider gate.
