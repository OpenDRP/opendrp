# Plan 025 — the asset's own page, declared

**State:** done — 2026-10-23: `AssetFindingsResponse` on the asset findings route, the inventory is 10

## Goal

`GET /api/v1/assets/{asset_id}/findings` answers what one asset is involved in: the
asset itself, a counter per module, when each module last saw it, and one page of
rows in the same seven-field shape for every module. The SPA reads it as
`AssetFindingsResponse`; the route declares nothing, so the interface is checked by
the compiler and by nothing else.

Three decisions make this entry different from 024, and each is why the route's
payload cannot simply be poured into one model:

1. **The optional fields are already `null`, not absent.** `matched_asset`, `source`,
   `status` and `observed_at` are keys with `null` values in every row, and the
   client types them `string | null`. So this route takes `response_model` *without*
   `exclude_none` — the opposite of the promotion answer, where an absent key had to
   stay absent. A shared "exclude nulls" habit would silently change this payload.
2. **`observed_at` is two kinds of moment.** A breach publishes a disclosure *date*
   and every other module a scan *timestamp*; the matching module's own comment says
   the two are never compared. Declaring the field `datetime` would turn
   `2024-01-01` into `2024-01-01T00:00:00Z` — a value the platform invented — so the
   model declares `date | datetime | None` and keeps each module's own kind. An
   aware UTC timestamp now serializes as `...Z` rather than `...+00:00`, as on the
   promotion answers, because it goes through the same Pydantic serializer as the
   rest of the API; a naive value read back from SQLite is unchanged, suffix and
   all.
3. **The counters are a contract, not a dict.** The client reads
   `Record<RelatedFindingModule, number> & { total: number }`; the model names the
   five modules and `total` so a module added to `RELATED_FINDING_MODULES` without
   the schema is a failing test rather than a number that quietly stops being sent.

## Plan of Work

| File | Change |
|---|---|
| `backend/app/schemas/asset.py` | `AssetFindingsResponse` with `AssetFindingSubject`, `AssetFindingCounts` and `AssetFindingItem`; `RelatedFindingModule` as a `Literal` of the five modules |
| `backend/app/api/v1/routers/assets.py` | `response_model=AssetFindingsResponse` on `/{asset_id}/findings`; the handler builds the model instead of a dict (no `exclude_none`) |
| `backend/scripts/check_api_types.py` | the `AssetFindingsResponse` pair, the entry deleted, the count 11 → 10 |
| `docs/production-readiness.md` | the limitation says 10, and the list of closed entries names this one |
| `docs/exec-plans/README.md` | one row for this plan |
| `backend/tests/test_asset_involvement.py` | the contract test: the keys the client reads, the counters against the module tuple, and both kinds of `observed_at` |

## Concrete Steps

1. **Red first.** Add the pair and delete the entry: the gate reports the stale-free
   half — the route answers no declared model, so `AssetFindingsResponse` is a typed
   read of an undeclared response.
2. **The models.** In `schemas/asset.py`, beside `AssetResponse`:
   * `AssetFindingSubject` — `id`, `asset_type`, `asset_value`, `is_active`: the four
     fields the page's header needs, not the whole asset.
   * `AssetFindingCounts` — `phishing`, `breaches`, `dns`, `exposure`, `findings`,
     `total`.
   * `AssetFindingItem` — `id`, `module`, `title`, `matched_asset`, `source`,
     `status`, `observed_at`.
   * `AssetFindingsResponse` — `asset`, `counts`, `last_seen`, `module`, `items`,
     `total`, `page`, `size`, `pages`.
3. **The route.** The decorator gains the model; the handler returns
   `AssetFindingsResponse(...)` with the same values it composes today, and the
   `items` stay the dicts `_related_row` builds — Pydantic validates a dict as well
   as an object, which is what keeps the four module branches in one place.
   *Acceptance:* the gate is green, the entry is gone, and a response carries the
     same nine keys, the same nested counters and the same row fields as before,
     with the two stated differences: timestamp values end in `Z`, and a breach's
     `observed_at` is still a bare date.

## Validation and Acceptance

- [x] Red before the model, green after: two failures first — `AssetFindingsResponse:
      named by AssetFindingsResponse but missing from the OpenAPI document`, and the
      inventory reporting `lib/api.ts:515` as a typed read of an undeclared response
      — then 23 passed with `10 routes`.
- [x] The payload is unchanged except for the timestamp suffix, and that is asserted
      rather than assumed: `test_asset_involvement.py` checks the nine top-level
      keys, the four subject keys, the seven row keys, the counters as a closed set,
      both kinds of `observed_at` (a breach stays `2024-01-01`) and a `null`
      `last_seen` entry surviving as `null`.
- [x] A module added to `RELATED_FINDING_MODULES` fails the new test rather than
      disappearing from the response: the test compares both the response's counter
      keys and `AssetFindingCounts.model_fields` with the tuple.
- [x] The asset suites stay green (`test_asset_involvement.py` 10 passed,
      `test_assets_integration.py`, `test_assets_router_edges.py`).
- [x] `ruff check app tests scripts` clean; the documentation gates that read the
      edited pages stay green. The mypy ratchet was not run: it lives in the tooling
      container and the Docker daemon was unreachable in this session.

## Progress and Milestones

- **2026-10-23 — opened.** The entry was picked from the inventory's remaining
  eleven because it is the only one whose payload mixes two kinds of date and whose
  optional fields are already nulls, so the plan had to decide both rather than
  copy the previous step's decorator.
- **2026-10-23 — closed.** Ten routes remain: the alert queue, the audit views
  (actions and integrity), the dashboard, the connector inventory (accounts, health,
  modules and the account patch), the exposure page and the phishing evidence view.
