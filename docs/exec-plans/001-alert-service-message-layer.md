# ExecPlan 001 — Alert service: extract the pure message layer

## Goal

`backend/app/services/alert_service.py` is 1479 lines and mixes five concerns:
delivery error taxonomy, SMTP scheduling, message vocabulary/rendering, alert
routing policy, and the `AlertService` class itself (settings, transports,
per-module fact building, batch assembly). This plan starts the split with the
part that is purest and safest to move: **everything that turns facts into
words**, with no database, network or settings access beyond a constant.

Acceptance for this slice: `alert_service.py` no longer defines rendering
vocabulary or routing; two small modules own them; every existing import path
and every test keeps working unchanged; behaviour is byte-identical.

## Plan of Work

| Layer | Module | Contents |
|---|---|---|
| Pure message layer | `app/services/alert_message.py` (new) | clipping/escaping/counting helpers, column declarations, breach labels, severity ranking, `Notification`, Telegram/plain-text renderers, `digest_heading`, `breach_subject_class` |
| Routing policy | `app/services/alert_routing.py` (new) | `PhishingRoute`, `phishing_alert_route` |
| Facade (unchanged public surface) | `app/services/alert_service.py` | keeps `AlertService`, delivery errors, SMTP transport, fact building; re-exports the moved names under their old private aliases |

Deliberately **not** in this slice: the delivery error taxonomy, `bounded_smtp`,
SMTP/Telegram transports, stored-fact readers (`_stored_*_facts`), and
`_build_notification`. Those are slice 002 and 003, each with their own plan.

## Concrete Steps

1. Work on a green baseline: `pytest` over the alert-domain test files.
2. Create `alert_message.py` with the constants and functions moved verbatim
   (renamed without the leading underscore), keeping every docstring.
3. Create `alert_routing.py` with `PhishingRoute` and `phishing_alert_route`,
   moved verbatim.
4. Replace the moved blocks in `alert_service.py` with imports; keep
   compatibility aliases for names imported elsewhere (`_highest_severity`,
   `_breach_subject_class`, `_plain_text`, `digest_heading`,
   `phishing_alert_route`).
5. Update intra-module call sites to the new public names — mechanical rename
   only, no logic edits.
6. Re-run the same test set, `ruff`, and the mypy baseline.

## Validation and Acceptance

- `pytest` over `tests/test_alert_*.py`, `tests/test_breach_*alert*`,
  `tests/test_phishing_*`, `tests/test_dns_new_data_alerts.py`,
  `tests/test_user_notifications.py` — same pass count as baseline.
- `python scripts/check_mypy_baseline.py` — no new errors.
- `ruff check app` — clean.
- `alert_service.py` shrinks by roughly 480 lines; no public name disappears:
  `from app.services.alert_service import (AlertService, phishing_alert_route,
  digest_heading, _highest_severity, _breach_subject_class, _plain_text,
  AlertDelivery*Error, bounded_smtp, _SMTP_SLOTS)` all still resolve.
- `git diff` contains no changed string literal, column label, or threshold.

## Progress and Milestones

- [x] Baseline captured: `pytest` over 5 alert test files → **81 passed**.
- [x] Map of module structure, importers and test dependencies collected
      (importers: routers/alerts, routers/settings, alert_delivery_service,
      ingestion_events, settings_service, user_notifications; tests reach for
      `_highest_severity`, `_SMTP_SLOTS`, `phishing_alert_route`, `bounded_smtp`).
- [x] `alert_message.py` created: 362 lines, no I/O — vocabulary, `Notification`,
      Telegram/plain renderers, digest headings.
- [x] `alert_routing.py` created: 66 lines — `PhishingRoute` and
      `phishing_alert_route`, policy passed in or read from the environment.
- [x] `alert_service.py` reduced from **1479 → 1107 lines**; it keeps the error
      taxonomy, SMTP transport, settings snapshot, stored-fact readers and the
      delivery orchestration, and re-exports the moved names under their old
      private aliases.
- [x] Characterization tests added: `tests/test_alert_message_layer.py` (10 tests).
- [x] Verification green (see below).

### Verification results

| Check | Result |
|---|---|
| Alert domain suite (16 files) | 176 passed |
| Delivery queue / outbox / health / settings suites | 38 passed |
| `tests/test_alert_message_layer.py` | 10 passed |
| `ruff check app` (and the new test file) | clean |
| `python -m mypy app` (baseline gate: 0 errors) | Success, 126 files |
| Import smoke over all `app.*` modules (cycle check) | 107 modules, 0 failures |

The repo's `scripts/check_mypy_baseline.py` invokes a bare `mypy` executable,
which this workstation's venv does not expose; the equivalent command
(`python -m mypy app`, baseline 0) was run instead.

### Next slices

- **002** — transport errors, retry policy and `bounded_smtp` → `alert_transport.py`.
  **Done** — see [002-alert-transport-and-facts.md](002-alert-transport-and-facts.md).
- **003** — stored-fact readers → `alert_facts.py`. **Done** — same document.
- **004** — split SMTP and Telegram senders out of the service class.
