# Plan 036 — the DNS inventory row, declared

**State:** done — 2026-10-23: eighteen row fields and the nine of the control it feeds, the inventory is 1

## Goal

`GET /api/v1/dns-security/observations` is the inventory behind the DNS Security
page: one row per DNS record member, registration, certificate sighting or TLS
control, with the expiry control each row feeds resolved for the page. It declares
`PaginatedResponse[dict]`, so the eighteen fields the SPA reads from `DNSObservation`
— and the nine the nested `expiry_monitor` carries — have been checked by the
compiler alone. It is the first of the two entries plan 035 left in `UNMODELLED`.

The row is the hardest payload the inventory has held so far: a value that may be
absent, three computed booleans about the inventory, a kind that is a label for a
control, and a nested control payload that is itself a projection of a row plus
`now`.

Decisions:

1. **Two models, `DNSObservationResponse` and `DNSExpiryMonitorResponse`.** The
   nested control is one shape in one place, and a reader of the schema can see that
   `expiry_monitor.kind` is the control's key (`tls:8443`) while `expiry_kind` is
   the label the column shows (`tls`) — the distinction AUD-036 made.
2. **`observation_type`, `source`, `status` and `expiry_kind` stay strings.** The
   client closes two of them with unions, but the columns are free text and the
   module's vocabulary has grown twice (the `vt_*` family, then the probe). A row
   written by a worker this build does not know must render; a model that made the
   page 500 would hide the row an operator needs to see during an incident.
3. **`expiry_monitor` is nullable.** `monitor_kind` answers `None` for an
   observation type no control tracks, and that `None` is a real answer: the row
   feeds nothing, and the page shows no expiry control rather than an empty one.
4. **`alerted_thresholds` appears twice on purpose.** The row's copy is the
   control's history (`AUD-038` made the monitor the single writer), and the nested
   `expiry_monitor` carries the same list because it is the whole control. Both are
   day counts (`list[int]`); the duplication is in the payload, not in the database.
5. **`remaining_seconds` is a float.** `monitor_payload` divides a timedelta by
   seconds, so the value is `201600.0`, not `201600`; the page prints it as a day
   count and the type says what the arithmetic produces.
6. **`metadata` is a map.** The worker retains the RRset (`record_values`), the
   wildcard flag and a provider document in it; the page reads three keys and the
   rest is the connector's own record.

## Plan of Work

| File | Change |
|---|---|
| `backend/app/api/v1/routers/dns_security.py` | `DNSExpiryMonitorResponse`, `DNSObservationResponse`, `DNSObservationPageResponse`; the route builds them, computing `value_asset_target` once per row |
| `backend/scripts/check_api_types.py` | the pair `DNSObservation` → `DNSObservationResponse`, the `dns/observations` entry deleted, the count 2 → 1 |
| `backend/tests/test_dns_security_api.py` | the row's eighteen keys, the page's five, and the nested control's nine with a real monitor behind them |
| `docs/production-readiness.md` | limitation 5 says one route remains, and names it |
| `docs/exec-plans/README.md` | one row for this plan |

## Concrete Steps

1. **The models.** A nested control model with the nine fields `monitor_payload`
   emits, and a row model with the eighteen the route composes.
2. **The route.** A loop instead of the dict comprehension, so the control and the
   asset target are computed once per row; the ordering, the `size` bound and the
   `in_assets` closure are untouched.
   *Acceptance:* the payload keeps every key and every value; the three computed
   booleans still answer from the same one page-wide lookup.
3. **The inventory.** Add the pair, delete the entry.
   *Acceptance:* the gate is red on the entry before the pair exists, green after,
   and prints `1 routes`.

## Validation and Acceptance

- [x] `python scripts/check_api_types.py` — before the routes changed it reported
      nothing for this route only because the entry existed; with the models and the
      entry deleted it is green: `38 interfaces` compared, `109 request calls`, and
      `UNMODELLED (1)` — the certificate review, which the next plan opens with.
- [x] `pytest tests/test_dns_security_api.py` — 20 passed, including the port-control
      test (`tls:443` / `tls:8443` in one asset) and the RRset/certificate grouping
      test that pinned the payload before this plan, plus the new key sets: the
      page's five, the row's eighteen, the control's nine, `expiry_monitor: null` for
      a record no control tracks, and `remaining_seconds` as a float.
- [x] `pytest tests/test_api_types_gate.py` — green over the shipped tree with the
      inventory at one entry; `test_dns_security.py`, `test_dns_expiry_service.py`
      and `test_dns_tls_probe.py` green beside it (166 passed with the API suite and
      the three documentation gates in one run).
- [x] `ruff check app tests scripts` clean. The mypy ratchet was not run: it lives in
      the tooling container, unreachable here (plans 032–035 recorded the same).

## Progress and Milestones

- **2026-10-23 — opened.** The larger of the two rows plan 035 left: seventeen
  top-level fields plus a nested control, three of them computed per page.
- **2026-10-23 — closed.** The comprehension became a loop, which is what let two
  per-row answers be computed once instead of twice (`value_asset_target` and the
  control lookup); the payload keeps every key and value, and the three computed
  booleans still answer from the same page-wide asset lookup. `expiry_kind` and
  `expiry_monitor.kind` stay two different answers — the label and the control's key
  — which is the distinction AUD-036 introduced and the reason both are published.
  The inventory is the certificate review; its row is a projection of a sighting
  with its signals, and it is the last entry.
