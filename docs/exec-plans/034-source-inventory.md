# Plan 034 — the last two, and the third they hid

**State:** done — 2026-10-23: three routes declared, `UNMODELLED` empty, the parser fixed

## Goal

`UNMODELLED` in `backend/scripts/check_api_types.py` holds two routes, both in
`backend/app/api/v1/routers/source_inventory.py`:

- `GET /api/v1/exposure/observations` — the exposure inventory, a page of twelve
  fields per observation;
- `GET /api/v1/phishing/threats/{candidate_id}/evidence` — up to 200 evidence rows
  of ten fields, one of them the allowlisted `fields` map.

Both answer a dict the route builds, so a field renamed there compiles in the SPA
and fails in a browser. Declaring the models closes the inventory, which is the
last item of the readiness page's limitation 5 and the procedure plan 016
started.

Reading the two entries turned up a third route the inventory never held. The
gate's interface parser treats a body that opens and closes on the same line as
the start of a block, so `export interface ExposurePage extends
Paginated<ExposureObservation> {}` swallowed the next interface whole:
`ExposureTriageResult` — the answer of `PATCH /api/v1/exposure/observations/{id}`,
which declares no model either — was not in `parse_interfaces` at all, so its
typed read produced neither an inventory entry nor a failure. The measured size
of the hole was two where it is three.

Decisions:

1. **One plan for the three routes.** They live in one file, they share one
   `SourceObservation` row, and closing two of three would leave the inventory
   unable to reach zero for a reason that is an accident of parsing rather than of
   design.
2. **The parser is fixed first, because it decides the size of the work.** A rule
   that silently skips an interface is the class of gate the audit spent a plan
   removing ("a check that could not fail", AUD-084/AUD-089): the fix is the
   smallest one that makes the interface visible, with a test that fails before it.
3. **`status` stays a string, and `payload`/`provenance` stay free-form maps.** The
   triage route accepts three values and the column can hold any of them; a row
   written before the rule existed must render rather than turn the page into a
   500, which is the decision plan 033 made for the delivery queue. `payload` is
   whatever a connector sent, and `provenance` is whatever the core recorded about
   where it came from — neither is a shape the platform promises, which is why the
   evidence list republishes an allowlisted half beside it (`evidence_fields`).
4. **`fields` is a map, not a model of sixteen names.** The names come from
   `EVIDENCE_FIELDS`, a tuple the module owns; a model with sixteen optional
   properties would have to be edited in two places every time the allowlist grows,
   and `Any` is honest about values a connector wrote (string, number, boolean, or
   a list of those).
5. **`matched_asset` is declared non-nullable, unlike the client's sibling field.**
   The column is `nullable=False` and the route copies it; `ExposureObservation` in
   the SPA types it `string | null` only because the page renders it defensively.
   The model says what the database says, which is what the comparison in rule 2
   reads.

## Plan of Work

| File | Change |
|---|---|
| `backend/app/api/v1/routers/source_inventory.py` | `ExposureObservationResponse`, `ExposureObservationListResponse`, `ExposureTriageResponse`, `PhishingEvidenceItem`, `PhishingEvidenceResponse`; the three routes declare them and build them |
| `backend/scripts/check_api_types.py` | three pairs added to `SCHEMA_PAIRS`, both `UNMODELLED` entries deleted, the docstring and the rule-2 comment say what is left; `parse_interfaces` reads a one-line body as an empty one |
| `backend/tests/test_api_types_gate.py` | a parser test: a body closed on the same line declares no fields of its own and the interface after it is still read |
| `backend/tests/test_source_inventory_api.py` | the three payloads: twelve keys and five envelope keys, the triage answer, ten keys per evidence row |
| `docs/production-readiness.md` | limitation 5 says zero, and names these three routes in the closed list |
| `docs/exec-plans/README.md` | one row for this plan |

## Concrete Steps

1. **The parser, red first.** Pin both readings — `ExposurePage` is empty and
   `ExposureTriageResult` exists — in `test_api_types_gate.py`; the second
   assertion fails against today's parser.
   *Acceptance:* the test is red for the named interface and green after the fix,
   and the gate then reports the triage route as an undeclared response.
2. **The models.** Five models in the router beside `ExposureTriageRequest`, each
   with the sentence that says why a field is nullable, a string or a map.
3. **The routes.** Declare, and build the model from the same query results; the
   ordering, the `size` bound and the 200-row evidence bound are untouched.
   *Acceptance:* the payload keeps every key it sent before — the tests assert the
   key sets rather than a diff of values.
4. **The inventory.** Add the three pairs, delete the two entries, re-measure.
   *Acceptance:* the gate prints `0 routes` and the pair count is 36; the three
   interfaces are compared field-for-field with their models.

## Validation and Acceptance

- [x] `python scripts/check_api_types.py` — red first: after the parser fix and
      before the models, the inventory test in `test_api_types_gate.py` reported
      `lib/api.ts:460: ExposureTriageResult — PATCH
      /api/v1/exposure/observations/{observation_id} answers no declared response
      model`; after the models the gate prints `36 interfaces`, `109 request calls`
      and `every route the SPA reads an interface from declares its response model`.
- [x] `parse_interfaces` holds `ExposureTriageResult` (`{id, status}`) and reads
      `ExposurePage` as empty; `ExposurePage` is deliberately not a pair, because an
      interface with no properties of its own compares nothing and a pair that cannot
      fail is the class of gate this plan is about. The row interface is the pair.
- [x] `pytest tests/test_source_inventory_api.py tests/test_api_types_gate.py` —
      `14 passed` and `25 passed`; the three key sets (five, twelve, ten), the triage
      answer's two keys, the null connector columns and the evidence allowlist tests
      that pinned the payload before this plan are all green.
- [x] `ruff check app tests scripts` clean; `test_docs_consistency_gate.py`,
      `test_docs_numbers_gate.py`, `test_skip_inventory_gate.py`,
      `test_audit_map_gate.py` and `test_mutation_audit_reliability.py` — 121 passed
      with the two files above. `test_source_intelligence.py`,
      `test_phishing_integration.py` and `test_api_docs_contract.py` — 35 passed, one
      skipped. The mypy ratchet was not run: it lives in the tooling container, which
      is unreachable here (the same limitation plans 032 and 033 recorded).

## Progress and Milestones

- **2026-10-23 — opened.** Two inventory entries; a third route found by reading
  the parser rather than the routes.
- **2026-10-23 — the parser.** `_on_the_opening_line` reads whatever shares the
  opening brace and says whether the body closed there; a body that closed there no
  longer runs the block walk into the next interface, and a member written beside
  the brace is no longer skipped. Two tests were red first: `ExposurePage` read as
  `{id, status}` (the fields of the interface after it) and `ExposureTriageResult`
  absent altogether (`assert {'id', 'status'} == set()` and
  `assert {'name'} == {'id', 'name'}`). The gate then reported the triage route.
- **2026-10-23 — closed.** Five models in `source_inventory.py`, the three routes
  declare them, `UNMODELLED` is empty and the readiness page's limitation 5 says the
  response half is closed. `payload`, `provenance` and the evidence `fields` stay
  maps: two of them are what a connector sent, and the third is the allowlist's own
  answer, which a sixteen-property model would have to be edited beside.
  `ExposureObservation` in the SPA types `matched_asset` nullable where the column is
  not; the model follows the column, and the page's defensive cell render is what
  the wider type was for.
