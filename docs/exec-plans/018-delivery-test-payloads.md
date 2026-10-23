# Plan 018 — one interface that described two payloads

**State:** done — 2026-10-23: `TestDeliveryResult` is two types, both routes declare
a model, and the inventory is 24

## Goal

Plan 017 ran the inventory procedure once on the simplest entry. This plan takes the
next one, and it is the entry plan 017 named as the counter-example: `TestDeliveryResult`
was one TypeScript interface over two routes that send different things.

- `POST /settings/test-email` answers `{"status": "sent", "to": "<recipient>"}`.
- `POST /settings/test-telegram` answers `{"sent": n, "total": n, "validated": n,
  "validation_failed": n, "results": [...]}`.

The interface that covered both was their union with every field optional — eight
optional fields, three of which (`ok`, `valid`, and a second meaning for `validated`)
no route sends at all. That is why it could not simply be given a model: a model must
say what one route sends, and rule 2 fails when the client declares a field the model
does not have. The client had to be right first, and the model second.

Two smaller decisions follow from the payloads rather than from taste:

- **`status` exists only in the mail answer.** The Telegram route answers counts and
  per-chat results, and never says "sent"; its `sent` is the count that succeeded. So
  the two interfaces are not variants of one another and do not share a base.
- **`results` stays `list[dict[str, Any]]` in the model.** Each entry is Telegram's own
  chat object (`chat_id`, `ok`, and either `chat_type`/`username`/`title` or
  `error_code`/`error`), forwarded from the provider; a strict entry model would have
  to invent nulls for the fields the other variant omits, which changes the bytes the
  SPA receives today. The top-level counts are what this route promises, and they are
  what the model declares. `TelegramChatValidationResult` in the client already
  describes the entry, and the route that serves those shapes as its own payload
  (`POST /settings/validate-telegram`) is still in the inventory.

## Plan of Work

| File | Change |
|---|---|
| `frontend/src/types/api.ts` | `TestDeliveryResult` becomes `TestEmailResult` and `TestTelegramResult`; the fields no route sends are not carried over |
| `frontend/src/lib/api.ts` | the two helpers name their own response type |
| `backend/app/schemas/settings.py` | `TestEmailResponse`, `TestTelegramResponse` |
| `backend/app/api/v1/routers/settings.py` | `response_model=` on both routes |
| `backend/scripts/check_api_types.py` | two pairs, the two `UNMODELLED` entries deleted, the count 26 → 24 |
| `docs/production-readiness.md` | the limitation says 24 |
| `docs/exec-plans/README.md` | one row for this plan |

## Concrete Steps

1. **Red first.** Declare the two pairs and delete the two inventory entries before
   either model or either client type exists. The gate then reports three kinds of
   disagreement at once: the two models are missing from the OpenAPI document, and the
   two reads are typed against routes that declare no model. That is the shape of the
   defect this plan removes, printed by the gate itself.
2. **The client split.** Two interfaces with required fields, because both routes
   always send them. `SettingsPage` reads `validated`, `sent`, `total` and `results`
   from the Telegram answer and `to` from the mail one; with required fields those
   reads lose their `??` fallbacks' purpose but keep compiling, and no page changes.
3. **The models.** `TestEmailResponse` mirrors the service's `{"status", "to"}`;
   `TestTelegramResponse` declares the four counts and forwards `results` as provider
   objects, with a comment saying why.
   *Acceptance:* the gate is green, the two entries are gone, and both routes answer
   the same bytes as before — the settings notification tests compare the mail answer
   literally.

## Validation and Acceptance

- [x] The gate was red before the models existed, naming both missing models and both
      unmodelled routes, and green after: `10 interfaces`, `24 routes`.
- [x] The bytes did not change: `tests/test_settings_notification_endpoints.py` asserts
      `{"status": "sent", "to": ...}` exactly and the Telegram counts from the mocked
      provider, and stays green.
- [x] The frontend type-checks after the split (`tsc -b`).
- [x] `ruff` clean; the mypy ratchet reports its baseline; the inventory test in
      `tests/test_api_types_gate.py` is the proof that no entry was forgotten.
- [x] The documentation gates that read the edited pages stay green.

## Progress and Milestones

- **2026-10-23 — opened.** The measurement: the interface had eight optional fields for
  two payloads whose union is six fields across two routes, three of them never sent by
  either. Splitting it is the fix AUD-060's typing pass left half-done — it typed the
  helper, not the payload.
- **2026-10-23 — closed.** `TestEmailResult` and `TestTelegramResult` are the client's
  declarations, `TestEmailResponse` and `TestTelegramResponse` the server's, and
  `POST /settings/validate-telegram` is the one settings route left in the inventory
  because its payload is a third shape.
