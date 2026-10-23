# Plan 019 — a payload with two kinds of row

**State:** done — 2026-10-23: `POST /settings/validate-telegram` declares a model, the
inventory is 23

## Goal

Plan 018 modelled the two test-send routes. The third settings payload is
`POST /settings/validate-telegram`, and it is the first entry in the inventory whose
interesting part is a row rather than a count:

```
{"valid": n, "total": n, "results": [
  {"chat_id": "@a", "ok": true,  "chat_type": "private", "username": "a", "title": null},
  {"chat_id": "-100", "ok": false, "error_code": "chat_not_found", "error": "..."}
]}
```

`AlertService._telegram_chat_result` builds the first shape from Telegram's `getChat`
answer and the failure paths build the second, so the list holds two kinds of object —
five keys or four, sharing only `chat_id` and `ok`. Plan 018 left its sibling's
`results` as `list[dict]` for exactly this reason: a single entry model would add nulls
for the fields the other kind omits, which changes the bytes the SPA receives.

This plan does not take that shortcut, because the two kinds are separable:

- `ok` is `True` or `False`, never absent, and it is the discriminator — an entry is
  one variant or the other with no ambiguity;
- each variant's keys are the ones it always carries, so a strict model of each
  reproduces today's payload exactly, nulls included (`title: null` is a value
  Telegram sent, not a field this platform invented);
- Pydantic validates each dict into the variant its `ok` names and serializes that
  variant's own fields, so no null is added and none is dropped.

The client already says the same thing: `TelegramChatValidationResult` declares
`chat_id`, `ok` and the five optional extras. No frontend change is needed — which is
the test of whether the *server* was the side that was vague.

## Plan of Work

| File | Change |
|---|---|
| `backend/app/schemas/settings.py` | `TelegramChatOkResult`, `TelegramChatErrorResult` (discriminated on `ok`) and `TelegramValidationResponse` |
| `backend/app/api/v1/routers/settings.py` | `response_model=TelegramValidationResponse` on `/validate-telegram` |
| `backend/scripts/check_api_types.py` | the `TelegramChatValidationResponse` pair, its `UNMODELLED` entry deleted, the count 24 → 23 |
| `docs/production-readiness.md` | the limitation says 23 |
| `docs/exec-plans/README.md` | one row for this plan |

## Concrete Steps

1. **Red first.** Declare the pair and delete the inventory entry before the model
   exists. The gate reports the missing model and the now-unlisted read, which is the
   only state in which this plan is not done.
2. **The two variants.** `TelegramChatOkResult` is `chat_id`, `ok: Literal[True]` and
   the three chat metadata fields as `str | None` *without* defaults — they are
   required keys that may hold null, which is what the provider answer produces.
   `TelegramChatErrorResult` is `chat_id`, `ok: Literal[False]`, `error_code: str` and
   `error: str`, all required. The union is discriminated on `ok` so validation picks
   a variant rather than trying one and falling back.
3. **The response.** `TelegramValidationResponse` carries `valid`, `total` and the
   discriminated list, and the route declares it.
   *Acceptance:* the gate is green, the entry is gone, and the endpoint returns the
   same keys per row as before — the notification-endpoint suite asserts the counts
   and per-chat `ok`/`error` from the mocked provider and stays green.

## Validation and Acceptance

- [x] The gate was red before the model existed (missing model, unlisted read) and
      green after: `12 interfaces`, `23 routes`.
- [x] The per-row keys are unchanged, not merely compatible: the ok variant declares
      the five keys the service builds, the error variant the four, and neither is
      nullable by omission. `tests/test_settings_notification_endpoints.py` drives both
      paths through the mocked provider and stays green.
- [x] `tests/test_api_types_gate.py` — the two-directional inventory test — passes, so
      the deletion is justified by a route that declares a model.
- [x] `ruff` clean; the mypy ratchet reports its baseline; `tsc -b` is unaffected
      because the client's interface did not change.
- [x] The documentation gates that read the edited pages stay green.

## Progress and Milestones

- **2026-10-23 — opened from the shape, not from a defect.** The route worked; what was
  missing was a declaration, and the declaration had to be two declarations. A single
  entry model would have passed the gate and changed the payload, which is the failure
  mode this procedure exists to avoid.
- **2026-10-23 — closed.** Two variants, one discriminated list, no bytes moved. The
  settings module now has one route left in the inventory — none, once
  `/settings/runtime` gets its composed model — and the remaining 23 are the
  dashboard, audit, connector and asset payloads whose models are their own contracts.
