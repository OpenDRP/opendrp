# ExecPlan 002 — Alert service: transport policy and stored facts

## Goal

Finish the split started in ExecPlan 001 so `backend/app/services/alert_service.py`
holds orchestration and nothing else. Two more concerns leave it:

1. **Transport policy** — the delivery error taxonomy, the retry-wait policy and the
   bounded SMTP thread pool (`alert_transport.py`).
2. **Stored facts** — reading the module's own row at send time and mapping it to
   message columns (`alert_facts.py`), which is the only place in the alert path
   that speaks SQL.

Acceptance: every existing import path still resolves, the 214-test alert/delivery
suite stays green, and `alert_service.py` drops below 800 lines.

## Plan of Work

| Layer | Module | Contents |
|---|---|---|
| Transport policy | `app/services/alert_transport.py` (new) | `AlertDelivery{Transient,Ambiguous,Cancelled,Permanent}Error`, `alert_retry_wait`, `_SMTP_SLOTS`/`_SMTP_EXECUTOR`, `bounded_smtp` |
| Stored facts | `app/services/alert_facts.py` (new) | `phishing_message_facts`, `stored_phishing_facts`, `breach_message_facts`, `stored_breach_facts`, `data_class_text`, `breach_verification`, `message_facts`, plus the shared `_finding_ids` id parser |
| Facade | `app/services/alert_service.py` | keeps `AlertService` (settings snapshot, SMTP/Telegram senders, destination resolution, batch assembly, delivery orchestration); delegates `_stored_message_facts`/`_facts` to `alert_facts`; re-exports the moved names |

## Concrete Steps

1. Create `alert_transport.py` with the four exceptions, the retry policy and the
   SMTP slot pool, moved verbatim.
2. Create `alert_facts.py`; convert the service methods into module functions that
   take `db` explicitly, and factor the duplicated id-parsing loop into
   `_finding_ids`.
3. In `alert_service.py`: delete the moved blocks, import them, keep the historical
   aliases (`AlertDelivery*Error`, `bounded_smtp`, `_SMTP_SLOTS`, `_alert_retry_wait`)
   and leave `_stored_message_facts`/`_facts` as one-line delegates.
4. Drop the imports the move made unused (`tenacity.RetryCallState`,
   `ThreadPoolExecutor`, `domain_age_days`, `utc_instant`, `fired_signals`,
   `breach_event_label`, `breach_exposure_label`).
5. Add `tests/test_alert_transport_policy.py` for the retry-wait policy, which had
   no direct test.
6. Verify.

## Validation and Acceptance

| Check | Result |
|---|---|
| Alert/delivery suite (20 files, incl. the two new test files) | **214 passed** |
| `tests/test_alert_transport_policy.py` | 3 passed |
| `ruff check app` | clean |
| `python -m mypy app` (baseline gate: 0 errors) | Success, 128 files |
| Facade import check (`AlertService`, all four errors, `bounded_smtp`, `_SMTP_SLOTS`, `_alert_retry_wait`, `phishing_alert_route`, `digest_heading`) | all resolve |
| Import smoke over `app.*` (cycle check) | 109 modules, 0 failures |
| `alert_service.py` size | 1107 → **766 lines** |

Behaviour: no string, column label, threshold or SQL predicate changed — the moved
code is byte-identical apart from `self.` removal and the explicit `db` parameter.

## Progress and Milestones

- [x] `alert_transport.py` created (exceptions, retry wait, SMTP pool).
- [x] `alert_facts.py` created (stored phishing/breach facts, `message_facts`).
- [x] `alert_service.py` reduced to 766 lines; delegates keep the private API
      `alert_delivery_service` calls (`_build_notification`, `_stored_message_facts`).
- [x] Retry-wait policy covered by tests.
- [x] Verification green.

### Next slices

- **004** — split the SMTP and Telegram senders (`_send_email_smtp`,
  `_send_telegram`, `_telegram_provider_error`, `validate_telegram_chats`,
  `send_test_telegram`) into `alert_senders.py`. Careful: tests patch
  `app.services.alert_service.httpx.AsyncClient`, so `httpx` must stay imported in
  the facade.
- **005** — `_build_notification` + `_platform_link` into `alert_message.py`
  (they are pure once `stored_facts` is passed in).
