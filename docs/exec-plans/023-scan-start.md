# Plan 023 — five answers to "the scan is queued", declared once

**State:** done — 2026-10-23: one `ScanStartResponse` on six scan routes, the
inventory is 15

## Goal

Five routes the SPA reads answer a scan start with `ScanStartResult`, and they do not
send the same keys:

| Route | Keys today |
|---|---|
| `POST /breaches/scan`, `/phishing/scan/dnstwist`, `/phishing/scan/shodan` | `status`, `job_ids`, and `error` only when the queue refused |
| `POST /breaches/scan-email` | `status`, `job_ids`, `email` |
| `POST /breaches/scan-domain` | `status`, `job_ids`, `domain` |

A sixth, `POST /dns/scan`, sends `status`, `job_ids`, `sources` and
`offline_connectors`, and was typed inline on the client (`{status: string; job_ids:
string[]; offline_connectors: string[]}`) — an expression, so rule 4 never saw it.
Its payload belongs to the same family: it is the `enqueue_ready_sources` answer,
which is also where `sources` comes from.

One model can describe all six without changing a byte, because every extra key is
absent rather than null when it does not apply:

- `status` and `job_ids` are required, both always sent;
- `error`, `email`, `domain`, `sources` and `offline_connectors` are optional, and
  `response_model_exclude_none=True` on these routes keeps an absent field absent
  instead of publishing it as `null` — which is the only reason a union of six routes
  can share one declaration here;
- `sources` stays a list of connector objects (`connector`, `status`, and either
  `job_ids` or `reason`), because that is what `enqueue_ready_sources` builds, and the
  client already models the half it reads.

## Plan of Work

| File | Change |
|---|---|
| `backend/app/schemas/connector.py` | `ScanStartResponse` beside the other connector payloads |
| `backend/app/api/v1/routers/breaches.py`, `phishing.py`, `dns_security.py` | `response_model=ScanStartResponse, response_model_exclude_none=True` on the six scan routes; the two `response_model=dict` declarations go |
| `frontend/src/lib/api.ts` | `/dns/scan` names `ScanStartResult` instead of an inline object type |
| `backend/scripts/check_api_types.py` | the `ScanStartResult` pair, five inventory entries deleted, the count 20 → 15 |
| `docs/production-readiness.md` | the limitation says 15 |
| `docs/exec-plans/README.md` | one row for this plan |

## Concrete Steps

1. **Red first.** Declare the pair and delete the five entries: the gate reports the
   missing model and five typed reads of routes that declare none.
2. **The model.** `ScanStartResponse` in `schemas/connector.py`. `status` is a `str`
   rather than an enum because the handlers answer `scheduled`, `blocked` and
   `no_connector`, and the client treats it as text.
3. **The routes.** Six decorators gain the model and the null exclusion; the two that
   said `response_model=dict` (`dnstwist`, `shodan`) lose that statement, which is
   the point — a route that declares itself unmodelled cannot be checked.
   *Acceptance:* the gate is green, five entries are gone, and each route answers the
   same keys as before, with `error` still absent on success.

## Validation and Acceptance

- [x] Red before the model, green after: `16 interfaces`, `15 routes`.
- [x] The payload is unchanged on all six: `error` is added only when the queue
      refused, `email`/`domain` only by their own routes, and `sources` still carries
      the connector entries `enqueue_ready_sources` builds.
- [x] The scan suites stay green (`test_breaches_gaps.py`,
      `test_phishing_integration.py`, `test_dns_security_api.py`), and `tsc -b` is
      clean after the DNS helper names the shared interface.
- [x] `tests/test_api_types_gate.py`'s inventory test passes, so the five deletions are
      justified by routes that declare a model.
- [x] `ruff` clean; the mypy ratchet reports its baseline; the documentation gates
      that read the edited pages stay green.

## Progress and Milestones

- **2026-10-23 — opened.** The family was measurable in one read: three shapes plus the
  unmodelled DNS payload that shares its origin (`enqueue_ready_sources`).
- **2026-10-23 — closed.** Fifteen routes remain, and every one of them is composed:
  the dashboard, the audit views, the alert queue, the connector inventory and the
  four promotion answers that return an ORM object or a dict.
