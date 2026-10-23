# Plan 037 — the certificate review, and an empty inventory

**State:** done — 2026-10-23: two models, two pairs, `UNMODELLED` empty

## Goal

`GET /api/v1/dns-security/certificates` is the last entry in `UNMODELLED`: the
triage view of Design B, one row per certificate with every place it was observed.
It declares `PaginatedResponse[dict]`, so the sixteen fields of the certificate, the
fourteen of each sighting inside it, and the `signals` map a rule scored on are all
described by the client alone.

Closing it empties the inventory of routes whose rows are undeclared, which is the
state plan 016 set out to reach: every response the SPA reads an interface from has
a model saying what one row holds.

Decisions:

1. **Two models again, `TLSCertificateResponse` and
   `TLSCertificateSightingResponse`, plus the page.** The row nests a list of
   sightings, and the client declares both levels as interfaces — so both are
   compared field for field, which is the only way a rename inside the nested list
   fails here instead of in `CertificateTriage`.
2. **The projection stays in `tls_identity_service.identities_payload`.** It already
   composes the row from two reads (identities, then their sightings) and its
   docstring explains why the two are not a join. What this plan adds is the
   contract, not a second composer; the route validates each dict it receives into
   the model, so a key the composer drops is a failure at the boundary rather than a
   blank cell.
3. **`verdict`, `origin` and `source` stay strings.** The client closes `verdict`
   with a union and the sweep only writes five values, but a sighting written by an
   older build or by a connector this build does not know must still list; a model
   that refused it would hide the row an analyst needs to review.
4. **`id` is a `UUID` in the model and a string in JSON.** The composer passes the
   row's own id, and Pydantic serializes it the way the route did before —
   `test_dns_certificates_api.py` already asserts `row["id"] == str(foreign.id)`.
5. **`san_dns` is `list[str]`.** The column is JSON, but its only writer is
   `_as_list`, which keeps strings and at most a hundred of them.
6. **`signals` stays a map.** It is what a provider said, kept whole so a new signal
   needs no column; a model of its keys would be a second copy of the scoring rules.

## Plan of Work

| File | Change |
|---|---|
| `backend/app/api/v1/routers/dns_security.py` | `TLSCertificateSightingResponse`, `TLSCertificateResponse`, `TLSCertificatePageResponse`; the route declares the page and validates the composer's rows |
| `backend/scripts/check_api_types.py` | the pairs `TLSCertificate` and `TLSCertificateSighting`, the last entry deleted, the docstring and the summary say the inventory is empty |
| `backend/tests/test_dns_certificates_api.py` | the row's sixteen keys, the sighting's fourteen, the page's five, and `subjects`/`signals` as the composer sends them |
| `docs/production-readiness.md` | limitation 5: no route the SPA reads an interface from answers an undescribed row |
| `docs/exec-plans/README.md` | one row for this plan |

## Concrete Steps

1. **The models.** The nested sighting first, then the certificate, then the page —
   in that order, so the nesting reads top-down in the file.
2. **The route.** `response_model=TLSCertificatePageResponse`, and the composer's
   dicts validated into it.
   *Acceptance:* the payload keeps every key, the filters, the ordering and the
   total; the review route beside it is untouched.
3. **The inventory.** Two pairs, the entry deleted.
   *Acceptance:* the gate is red on the stale entry once the route declares, green
   after, and its summary says every route declares the rows it sends.

## Validation and Acceptance

- [x] `python scripts/check_api_types.py` — green: `40 interfaces` compared,
      `109 request calls`, and `every route the SPA reads an interface from declares
      the rows it sends`. `UNMODELLED` is `{}`; the rule and its two direction checks
      stay, so an undeclared row is still reported rather than skipped.
- [x] `pytest tests/test_dns_certificates_api.py` — 12 passed, including the grouping
      test that pinned the payload before this plan and the new key sets: the page's
      five, the certificate's sixteen, the sighting's fourteen, `subjects` from the
      signals, `null` for a field the certificate does not carry.
- [x] `pytest tests/test_api_types_gate.py tests/test_tls_identities.py` — green over
      the shipped tree with an empty inventory; with
      `test_tls_identity_service_gaps.py` and the four documentation/audit gates the
      run was 135 passed.
- [x] `ruff check app tests scripts` clean. The mypy ratchet was not run: it lives in
      the tooling container, unreachable here (plans 032–036 recorded the same).

## Progress and Milestones

- **2026-10-23 — opened.** The last entry, and the only one whose row nests a list of
  rows: two interfaces to compare, one of them fourteen fields inside the other.
- **2026-10-23 — closed.** The projection stayed where it was composed; the route
  validates the composer's dicts into `TLSCertificateResponse`, which is the half a
  response model adds — a key dropped in the service is a failure at the boundary
  rather than a blank cell in `CertificateTriage`. With this the inventory is empty
  for the second time: it was emptied of routes with no model in plan 034, refilled
  by asking about rows in plan 035, and emptied again here. What remains outside any
  model is the inline literal the client writes for `POST /reports/generate` and the
  four connector-protocol routes, which the SPA does not read.
