# Plan 024 — four promotions, one answer

**State:** done — 2026-10-23: `PromotedAssetResponse` on four routes, the inventory is 11

## Goal

Four routes take a finding under monitoring and answer the same thing: the asset, and
whether it already existed.

| Route | `source` |
|---|---|
| `POST /breaches/{breach_id}/asset` | absent |
| `POST /phishing/threats/{threat_id}/asset` | absent |
| `POST /dns/observations/{observation_id}/asset` | the observation's source |
| `POST /exposure/observations/{observation_id}/asset` | the observation's source |

The client types all four as `PromotedAsset`, and the shape they actually send has one
awkward property: `asset` is a SQLAlchemy object, not a dict, so today FastAPI
serializes it with `jsonable_encoder` and every column of the `assets` table reaches
the browser. That is also why this entry was left for last: declaring a model changes
what "the asset" means on the wire, and the change has to be a decision rather than an
accident of `vars()`.

The decision: **`asset` is `AssetResponse`**, the model `GET /assets/{id}` and the
asset list already answer with. It covers every column the ORM object carries
(`id`, `asset_type`, `asset_value`, `criticality`, `is_active`, `normalized_value`,
`created_at`, `updated_at`) plus the optional `findings` summary, which promotion does
not compute and which `response_model_exclude_none=True` therefore leaves out — so the
nested payload is the same set of keys as today, produced by a declaration instead of
a serializer's fallback. `source` is optional for the same reason as in plan 023: the
breach and phishing answers do not have one, and an absent key stays absent.

This is the first entry whose fix is also a contract statement: from now on a promotion
answers the asset as the rest of the API describes it, and a column added to the model
that is not part of `AssetResponse` will not leak through this route.

## Plan of Work

| File | Change |
|---|---|
| `backend/app/schemas/asset.py` | `PromotedAssetResponse` — `already_exists`, `asset: AssetResponse`, optional `source` |
| `backend/app/api/v1/routers/breaches.py`, `phishing.py`, `dns_security.py`, `source_inventory.py` | `response_model=PromotedAssetResponse, response_model_exclude_none=True` on the four promotion routes |
| `backend/scripts/check_api_types.py` | the `PromotedAsset` pair, four inventory entries deleted, the count 15 → 11 |
| `docs/production-readiness.md` | the limitation says 11 |
| `docs/exec-plans/README.md` | one row for this plan |
| `backend/tests/test_asset_promotion_from_findings.py`, `backend/tests/test_dns_security_api.py` | the contract test: a promotion's asset is the read's asset, `Z` timestamps, `source` only where there is one |

## Concrete Steps

1. **Red first.** Declare the pair and delete the four entries: the gate reports the
   missing model and four typed reads of routes that declare none.
2. **The model.** `PromotedAssetResponse` in `schemas/asset.py` beside `AssetResponse`,
   which it reuses rather than restating: the nested asset of a promotion and the asset
   of a read are the same resource, and two declarations of it would drift.
3. **The routes.** Four decorators gain the model and the null exclusion; the handlers
   are untouched, because `from_attributes=True` is what lets `AssetResponse` validate
   the object the service returned. A dict asset (the shape a future handler might
   return) validates the same way.
   *Acceptance:* the gate is green, four entries are gone, and each route answers the
   same keys as before — with `source` absent on the two that never had it.

## Validation and Acceptance

- [x] Red before the model, green after: `17 interfaces`, `11 routes`.
- [x] The payload carries the same eight keys and the same value types, with one
      stated difference: the two timestamps now serialize as `2026-10-23T00:00:00Z`
      rather than `+00:00`, because the route serializes through the same Pydantic
      machinery as `GET /assets/{id}` — which already answered `Z`. The instant is
      identical and the SPA parses both; the change removes an inconsistency between
      two answers about the same resource rather than creating one. `findings` stays
      absent because promotion does not compute it. The evidence is a test that was
      red before the model: `test_asset_promotion_from_findings.py`'s
      `test_a_promotion_answers_the_asset_a_read_answers` compares the promoted
      asset's keys with `GET /assets/{id}`'s and requires the `Z` suffix, and the
      DNS promotion test in `test_dns_security_api.py` requires the `source` field
      the DNS and exposure routes carry. The promotion tests in
      `test_breaches_integration.py` and `test_phishing_integration.py` stay green.
- [x] `tests/test_api_types_gate.py`'s inventory test passes, so the four deletions are
      justified by routes that declare a model.
- [x] `ruff check app tests scripts` clean. The mypy ratchet was **not run**: mypy
      lives in the tooling container (`make mypy-backend`), and the Docker daemon was
      not reachable on the host this step ran on, so `check_mypy_baseline.py` stops
      at "mypy is not installed". The change adds one `BaseModel` and four decorator
      arguments; `tsc -b` needs no run either, because no client file changed — the
      nested type the pages read already models only the fields they use.
- [x] The documentation gates that read the edited pages stay green.

## Progress and Milestones

- **2026-10-23 — opened with the open question written down.** The four routes were the
  only inventory entry where the payload's shape came from a serializer rather than
  from the handler; the plan's decision is to name the model the rest of the API uses.
- **2026-10-23 — closed.** Eleven routes remain: the audit views, the alert queue, the
  dashboard, the connector inventory, the asset findings tab, the exposure page and
  the phishing evidence view.
