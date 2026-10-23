# Plan 030 — the dashboard, declared from the top down

**State:** done — 2026-10-23: `DashboardOverview` on the first screen, the inventory is 5

## Goal

`GET /api/v1/dashboard/overview` is the page's single request: the summary block
(`DashboardStats`), the connector health envelope (`ConnectorHealthResponse`, already
declared in plan 027), the alert-channel envelope (`AlertChannelsHealthResponse`) and
one assembly timestamp. The route returns a dict, so every one of those field names —
eight in the summary, six in `kpi`, ten in the breach block, six in `platform`, eleven
in each channel row — is checked by the compiler and nothing else.

This is the largest remaining entry, and it is taken whole rather than in halves: a
model that named the four envelope keys and typed `summary` as `dict` would remove the
inventory entry while leaving the page's actual contract unchecked, which is the one
outcome this programme exists to prevent. So the plan reuses what exists and declares
the rest:

1. **Reuse before restating.** `connectors` is `ConnectorHealthResponse` from plan 027,
   unchanged — the overview already builds it from the same function `/connectors/health`
   uses, and a second model would be a second contract for one reading.
2. **The timeline row is data, not a schema.** A day carries `date` plus one count per
   registry series, and the series come from the module registry, so the row model has
   `extra="allow"`: a module that declares dated findings adds a key without a code
   change, exactly as the composer does.
3. **`breach` keeps its captions.** The block is the report's KPI object, captions
   included, because an operator comparing the report and the dashboard is comparing one
   definition; the model names the four caption fields so a caption cannot silently
   disappear from the payload the page prints.
4. **The channel vocabulary is shared.** A channel's `health` can also be
   `not_configured` (the probe's answer for incomplete settings), so `HealthState` moves
   to `app/schemas/common.py` with all six values the platform uses, and the connector
   model imports it instead of keeping a five-value alias. Types are compared with the
   client's single `HealthState` either way; the shared spelling is what stops the two
   routers from diverging.
5. **No exclusion, again decided by the payload.** Every key is present: nulls appear
   where the block has no value (`oldest_unresolved_at`, `longest_silence`, the
   `oldest_running_job_seconds`), and the client types them nullable. So the route takes
   `response_model` without `exclude_none`.

Out of scope, and stated so it is not assumed: `/dashboard/stats` and `/alerts/health`
answer the same two sub-shapes but only the overview is in the inventory (it is the only
one the SPA reads). They can adopt these models later without moving them, because the
models live beside the composers they describe.

## Plan of Work

| File | Change |
|---|---|
| `backend/app/schemas/common.py` | `HealthState` — the six states the platform publishes |
| `backend/app/api/v1/routers/connectors.py` | import `HealthState` instead of declaring the five-value alias |
| `backend/app/api/v1/routers/alerts.py` | `AlertDeliveryCounts`, `AlertDeliverySummary`, `AlertChannelHealth`, `AlertChannelsHealthResponse` beside `channel_health_payload` |
| `backend/app/api/v1/routers/dashboard.py` | `BreachKpi`, `DashboardKpi`, the timeline row/series/excluded/comparison models, `PlatformStatus` and its blocks, `DashboardStats`, `DashboardOverview`; the route declares the model and builds it |
| `backend/scripts/check_api_types.py` | pairs for `BreachKpi`, `PlatformStatus`, `DashboardStats`, `DashboardOverview`, `AlertDeliverySummary`, `AlertChannelHealth`, `AlertChannelsHealthResponse`; the entry deleted; the count 6 → 5 |
| `docs/production-readiness.md` | the limitation says 5, and the closed list names this route |
| `docs/exec-plans/README.md` | one row for this plan |
| `backend/tests/test_dashboard_overview.py` | the shape test: the envelope, the eight summary keys, `kpi`, `platform`, and the channel row and delivery blocks |

## Concrete Steps

1. **Red first.** Add the pairs and delete the entry: the gate reports seven schemas
   missing from the document and the typed read of the route as undeclared.
2. **The shared vocabulary.** Move `HealthState` to `schemas/common.py`, six values, and
   point the connector model at it.
3. **The channel envelope.** Declare it in `alerts.py`, where `channel_health_payload`
   already lives, so the route that owns the payload owns its shape.
4. **The dashboard.** Declare the remaining models in `dashboard.py`; the route returns
   `DashboardOverview(summary=DashboardStats(**summary), connectors=…, channels=…,
   generated_at=assembled_at)`. The composers are untouched.
   *Acceptance:* the gate is green, the entry is gone, and the payload is unchanged
     except that aware UTC timestamps now end in `Z`.

## Validation and Acceptance

- [x] Red before the models, green after: the gate reported seven schemas missing
      from the document and `lib/api.ts:469` as a typed read of an undeclared response;
      after the models — 23 passed with `5 routes`.
- [x] The payload keeps every key the page reads, level by level, in
      `test_dashboard_overview.py`: four envelope keys, eight summary keys, six `kpi`
      keys, the ten breach keys with four captions, six `platform` keys with both
      nested blocks, a timeline day whose extra keys are exactly the registry's
      series, three channel-envelope keys, the queue key, eleven channel-row keys and
      six delivery keys.
- [x] The existing agreement test still passes: the overview's `summary`,
      `connectors` and `channels` equal what `/dashboard/stats`,
      `/connectors/health` and `/alerts/health` answer — 115 passed across the
      dashboard, alert-health and connector suites.
- [x] `ruff check app tests scripts` clean; the documentation/type gates plus
      `test_api_docs_contract.py` — 105 passed. The mypy ratchet was not run: it lives
      in the tooling container and the Docker daemon was unreachable here.

## Progress and Milestones

- **2026-10-23 — opened.** Picked before the alert queue because it reuses two models
  the previous steps already declared, and because leaving it would leave the largest
  unchecked payload in the platform's first screen.
- **2026-10-23 — closed.** Five routes remain: the alert queue, the audit actions
  catalogue, the audit integrity view, the exposure page and the phishing evidence
  view.
