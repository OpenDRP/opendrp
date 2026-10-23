# Plan 035 — a model that describes nothing

**State:** done — 2026-10-23: the rule asks about rows, the audit page declares eleven of them, the inventory is 2

## Goal

Plan 034 emptied `UNMODELLED`, the inventory of routes the SPA reads a typed
response from that declare no model at all. Reading the rule it left behind turned
up a second half: a route that declares a model **whose rows are `dict` or `Any`**
still answers a payload the server describes nothing about, and the gate counts it
as declared because a `$ref` is present.

Measured on the shipped tree, three routes the SPA reads an interface from answer
that way:

| Route | What it declares | What the SPA reads |
|---|---|---|
| `GET /api/v1/audit/logs` | `PaginatedResponse[Any]` | `Paginated<AuditLogRow>`, ten fields |
| `GET /api/v1/dns/observations` | `PaginatedResponse[dict]` | `Paginated<DNSObservation>`, seventeen fields |
| `GET /api/v1/dns/certificates` | `PaginatedResponse[dict]` | `Paginated<TLSCertificate>` |

None of the three was visible for two independent reasons, and both are the same
kind of defect: a rule that cannot fail.

1. `declares_schema` answers "does the response carry a `$ref`". `PaginatedResponse[dict]`
   carries one, so the envelope's five counters satisfy it and the rows — the thing
   the page renders — are never asked about.
2. `_named_interface` reads a bare interface name or `Name[]`, so a
   `Paginated<AuditLogRow>` read named nothing the gate could look at. Rule 4 has
   therefore never seen a paginated row: every list the SPA reads has been outside
   it since plan 016, whatever the server declared.

The plan fixes the rule, takes the measured inventory, and closes the first entry —
the audit trail's own page, which is the one an operator opens during an incident.

Decisions:

1. **The rule asks about the rows, not about the presence of a model.** A response
   is described when its rows carry named fields, whether the shape is a bare model,
   `list[Model]`, or a paginated envelope whose `items` are `Model`. That is one
   question with one implementation, and the envelope's counters stop being able to
   answer it on the rows' behalf.
2. **One entry closes in this plan, not three.** The DNS rows are seventeen fields
   with a nested expiry monitor and a TLS sighting with its signals; each is a
   projection of a query, and closing them here would make this plan the DNS page's
   plan. They stay in the inventory with their interface names, which is how plan
   016 made the remaining work visible, and the next plan opens from the list.
3. **`GET /reports/generate` is not an entry.** It declares `dict` too, but the SPA
   reads it with an inline object literal, not a declared interface — and rule 4's
   question is what the client *declares*. Writing that literal as an interface is
   plan 023's procedure applied to one route, not a hole this rule can see; the plan
   records it rather than pretending the inventory is every `dict` in the tree.
4. **The audit row's `key_id` is declared although the page does not read it.** The
   payload sends it, the column is non-nullable, and a model that hid it would make
   the answer narrower than the route's own SELECT. Rule 2 is one-way by design: the
   client may model the half it uses.
5. **`user_email` is nullable in the model even though the client types it
   `string | undefined`.** It is a snapshot from `details.actor_email` or a lookup
   against `users`, and a row written by a writer that had neither sends `null`.

## Plan of Work

| File | Change |
|---|---|
| `backend/scripts/check_api_types.py` | `declares_schema` (and a `_describes` walk) asks about the rows, resolving `$ref`, `allOf`, arrays and a paginated `items`; `_named_interface` unwraps `Paginated<X>`; `check_unmodelled` takes the component schemas; three entries in `UNMODELLED`, then two |
| `backend/app/api/v1/routers/audit.py` | `AuditLogRowResponse`, `AuditLogPageResponse`; `/logs` declares the page and builds it |
| `backend/tests/test_api_types_gate.py` | red-first: a `$ref` to a dict-row page is not a declaration; `Paginated<X>` names `X` |
| `backend/tests/test_audit_routers_integration.py` | the eleven keys of a row and the five of the page, plus the nulls |
| `docs/production-readiness.md` | limitation 5 says the inventory holds two, and what the rule now asks |
| `docs/exec-plans/README.md` | one row for this plan |

## Concrete Steps

1. **The rule, red first.** Two tests in `test_api_types_gate.py`: a paginated
   schema whose `items` is `{}` is undeclared, and `api.get<Paginated<Row>>(…)` names
   `Row`. Both fail against today's gate for the stated reason.
2. **The rule.** `_describes` resolves wrappers; `check_unmodelled` receives
   `components.schemas`; the summary sentence says how many routes remain.
   *Acceptance:* the gate reports exactly the three routes above and nothing else.
3. **The inventory.** Three entries with a reason each; the count in the docstring
   and the summary move with it.
4. **The audit page.** The two models, the route builds them, `AuditLogRow` joins
   `SCHEMA_PAIRS`, and the entry is deleted.
   *Acceptance:* the payload keeps its eleven keys; the gate prints `2 routes`.

## Validation and Acceptance

- [x] `python scripts/check_api_types.py` — red first, after the rule was tightened
      and before the entries existed: `3 disagreement(s)`, naming
      `lib/api.ts:471: DNSObservation`, `:480: TLSCertificate` and
      `:603: AuditLogRow` — the third being the route the inventory had counted as
      checked. With the three entries: green, `3 routes`. After the audit page's
      models: green, `37 interfaces` and `2 routes`.
- [x] `pytest tests/test_api_types_gate.py` — 27 passed. The two new tests were red
      first as `TypeError: check_unmodelled() takes 4 positional arguments but 5 were
      given`, which is the gate being unable to ask the question at all; the
      rewording of the failure (`answers no declared row shape`) and the fixture's
      real component schemas are part of the same change.
- [x] `pytest tests/test_audit_router_filters.py` — 16 passed, including the new key
      sets: the page's five keys, the row's eleven, `key_id` present though the page
      does not read it, and an actor-less row answering `null` with
      `actor_identity_source: current_user_lookup`.
- [x] `ruff check app tests scripts` clean; `test_api_types_gate`,
      `test_audit_router_filters`, `test_audit_routers_integration`,
      `test_docs_consistency_gate`, `test_docs_numbers_gate`,
      `test_skip_inventory_gate` and `test_audit_map_gate` — 139 passed together;
      `test_api_docs_contract`, `test_authorization_denials` and
      `test_audit_delivery_interfaces` — 21 passed. The mypy ratchet was not run: it
      lives in the tooling container, unreachable here (as plans 032–034 recorded).

## Progress and Milestones

- **2026-10-23 — opened.** Plan 034 emptied the inventory of routes with no model;
  this is the same question asked of a model that says `dict`. The rule's blind spot
  for `Paginated<X>` reads was found by reading `_named_interface`, not by a report.
- **2026-10-23 — closed.** `declares_schema` now takes the component schemas and
  resolves `$ref`, `allOf`, arrays and a paginated `items` before asking whether one
  row is described; `_named_interface` unwraps `Paginated<X>`; `check_unmodelled`
  takes the schemas because a `$ref` cannot be resolved without them. The inventory
  is the two DNS lists, which the next plan opens with. `GET /reports/generate` is
  recorded here as a boundary rather than an entry: it declares `dict` too, but the
  client writes its four keys as an inline literal, so there is no declaration for
  rule 4 to compare — writing that literal as an interface is plan 023's procedure,
  not this rule's finding.
