# Plan 033 — the delivery queue, declared

**State:** done — 2026-10-23: `AlertQueueSummary` on the delivery queue, the inventory is 2

## Goal

`GET /api/v1/alerts/queue` is the operator's view of the outbound alert queue: how many
deliveries are in each state, and the fifty most recent rows with their channel, status,
attempt count, part accounting and next attempt. The SPA reads it as
`AlertQueueSummary`; the route returns a dict, so the two envelope keys and the ten row
keys are checked by the compiler alone.

Decisions:

1. **`counts` is a map of what exists, not a model of all states.** The query groups by
   the statuses present in the table, so the key set is data. It stays
   `dict[str, int]`, and the row's `status` stays a string for the same reason: the
   delivery state machine is the service's, and a queue that refuses to render because
   a row holds a status this build has not seen would hide the very queue an operator
   opened the page to read.
2. **`batch_id` is nullable even though the client says otherwise.** The column is
   `str | None`, the route copies it as-is, and a delivery created outside a batch
   sends `null`. Declaring `str` would turn that row into a 500 for the whole listing;
   the model says what the database says.
3. **`next_attempt_at` is a timestamp.** The column is timezone-aware, the route passes
   the value through, and the page compares it against "now", so it is declared
   `datetime | None` and serializes like every other instant the API publishes.
4. **No `exclude_none`.** `job_id`, `last_error` and `next_attempt_at` are sent as
   `null` when absent, and the client types them nullable; a missing key would be a
   different answer from the one the page was written against.

## Plan of Work

| File | Change |
|---|---|
| `backend/app/api/v1/routers/alerts.py` | `AlertQueueItem` and `AlertQueueSummary`; the route declares the model and builds it |
| `backend/scripts/check_api_types.py` | the pair (`AlertQueueSummary`), the entry deleted, the count 3 → 2 |
| `docs/production-readiness.md` | the limitation says 2, and the closed list names this route |
| `docs/exec-plans/README.md` | one row for this plan |
| `backend/tests/test_alert_delivery_queue.py` | a queue test: rows in three states, the counters, the fifty-row bound and the nullable fields |

## Concrete Steps

1. **Red first.** Add the pair and delete the entry: the gate reports the typed read of
   a route that declares no model.
2. **The models.** `AlertQueueItem` (ten fields) and `AlertQueueSummary` (`counts`,
   `items`).
3. **The route.** Build the model from the same two queries; the ordering and the
   `limit(50)` bound are untouched.
   *Acceptance:* the gate is green, the entry is gone, and the payload is unchanged.

## Validation and Acceptance

- [x] Red before the models, green after: the inventory reported
      `lib/api.ts:605: AlertQueueSummary — GET /api/v1/alerts/queue answers no declared
      response model`, then the gate passed with `2 routes`.
- [x] The counters match the rows by status (three states, one row each), every row
      answers all ten keys, a resolved row sends `null` for batch, job, error and next
      attempt, and the listing stops at fifty while the counters describe all 52 rows —
      all asserted in `test_alert_delivery_queue.py`.
- [x] The alert suites stay green (`test_alert_delivery_queue.py` 11 passed;
      `test_alerts_reliability.py`, `test_alert_delivery_paths.py` and
      `test_alert_channels_schedules.py` — 82 passed together).
- [x] `ruff check app tests scripts` clean; the documentation/type gates plus
      `test_api_docs_contract.py` — 105 passed. The mypy ratchet was not run: it lives
      in the tooling container and the Docker daemon was unreachable here.

## Progress and Milestones

- **2026-10-23 — opened.** The last composite payload outside the module pages, and the
  only one whose client type is stricter than its column.
- **2026-10-23 — closed.** Two routes remain: the exposure page and the phishing
  evidence view.
