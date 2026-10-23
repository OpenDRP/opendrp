# Batch 04 — Alerts and delivery

**State:** done — message 100%, health cache 99.1%, delivery 97.6%, service 97.2%;
floors 97/96/94/94; closing run green (2026-10-20: 3 138 passed, 14 skipped)

**Scope:** the path a finding takes to a human: rendering, routing, the queue, the
provider call, and the health answer an operator trusts.

**Baseline:** the `backend` job of the CI run on `main` (2026-10-19): `app/` at
90.65%, 1 337 statements missed.

| Module | Statements | Missed | Covered |
|---|---|---|---|
| `app/services/alert_service.py` | 392 | 50 | 87.2% |
| `app/services/alert_message.py` | 144 | 37 | 74.3% |
| `app/services/alert_delivery_service.py` | 329 | 21 | 93.6% |
| `app/services/alert_health_cache.py` | 110 | 20 | 81.8% |

**Measured misses**

- `alert_service.py`: 96, 115-116, 135, 163-174, 191, 193, 219-227, 260-267,
  281-284, 291-294, 301, 343-344, 366-367, 379-380, 387-388, 421-422, 482-483,
  528, 576-577, 620, 692, 700
- `alert_message.py`: 182, 206, 248-254, 267-304
- `alert_delivery_service.py`: 63-71, 198-199, 205-207, 251, 283, 345, 590, 636,
  704-705, 708-709, 717, 721, 725
- `alert_health_cache.py`: 69, 85-99, 104-105, 179-180, 196-199

**First move**

```bash
cd backend
COVERAGE_CORE=sysmon python -m pytest -q --cov=app.services.alert_service --cov=app.services.alert_message --cov=app.services.alert_delivery_service --cov=app.services.alert_health_cache --cov-report=term-missing --cov-report=json:/tmp/batch04.json
```

**Work items**

- [x] Rendering edges: an empty fact set, a value that must be clipped, and a
      Telegram payload that exceeds the provider's limit — each renders something
      an operator can act on rather than an empty message.
- [x] Delivery outcomes: transient, ambiguous and permanent failures produce
      different queue rows, and an ambiguous row is held rather than retried.
- [x] Health: a degraded channel (queue backlog, saturated pool, provider timeout)
      reads `degraded` with `probe_state` naming why, and a disabled channel is
      never dialled.
- [x] Test sends: they ignore the enable toggle, and a test send to a bad
      credential reports the provider's own error rather than a generic failure.

**Done when**

- each module is at or above its current gate plus the batch's measured gain, and
  `alert_message.py` and `alert_health_cache.py` gain floors;
- the alert, delivery and health suites plus the full backend suite are green;
- the batch file records the provider failures that can only be simulated, and
  how they were simulated.

**Progress log**

| Date | Change | Measured |
|---|---|---|
| 2026-10-19 | batch written from the CI baseline | 87.2%, 74.3%, 93.6%, 81.8% |
| 2026-10-20 | measured on the alert/delivery suites before any change (156 passed) | service 84.95% (59 missed), message 74.31% (37), delivery 91.19% (29), health cache 81.82% (20) |
| 2026-10-20 | rendering: `telegram_text` / `telegram_finding_line` / `escaped` / `finding_path` tests in `test_alert_message_layer.py` (7 new) — counts, groups, link, empty row set, `showing N`, the budgeted drop of a long list with balanced markup, the missing-fact line, escaping after clipping, module links | message **100%** |
| 2026-10-20 | health cache: process-client build/reuse/TTL/rebuild, a client that cannot be built, a runtime without Redis, `reset_client_cache`, failed write and failed unlock in `test_alert_health_cache.py` (6 new) | health cache **99.1%** (1 missed: the unreachable `return Redis` behind the import) |
| 2026-10-20 | SMTP classification: a rejected login, rejected recipients, 5xx permanent vs 4xx transient, a lost connection, an unknown security mode and plain-mode credentials in `test_alert_delivery_paths.py` (6 new) | service 90.05% at this point; each outcome now has its own test |
| 2026-10-20 | Telegram classification and validation: connect error vs lost response, 429 retry hint from header and body, 4xx permanent, refused token, `getChat` result parsing, per-chat transport errors, spent deadlines, test-send passthrough in `test_alert_delivery_paths.py` and `test_alert_service.py`; plus severity/change-class subjects, the finding link, no-destination cancellation and a provider that declines (14 new) | service **97.2%** (11 missed) |
| 2026-10-20 | queue edges in `test_alerts_reliability.py` (6 new): idle group, unknown channel, empty finish, unknown recipient release, digest label, email change-class subject, provider refusal, selected-user destinations, missing recipient row, live lease, a hold that requeues only its own rows | delivery **97.6%** (8 missed) |
| 2026-10-20 | floors: service 70→94, delivery 70→94, message new at 97, health cache new at 96 | gate and readiness page |
| 2026-10-20 | closing run: full backend suite with `--cov=app` | **3 138 passed, 14 skipped**, critical-coverage gate OK; `app/` 93%, 933 missed (−108 in this batch) |

**Proven to fail:** breaking the omission note in `telegram_text` makes
`test_a_long_finding_list_is_dropped_line_by_line_never_mid_markup` fail with the
missing `+N more findings` line, then the mutation was reverted.

**Simulated provider failures**

- SMTP: `smtplib.SMTP`/`SMTP_SSL` are replaced by a client that raises the chosen
exception at `login` or `send_message`, and `ensure_allowed` is stubbed so the
destination policy does not mask the classification. That is the only way to
reach the mapping without a real provider.
- Telegram: `httpx.AsyncClient` is replaced by a context manager returning a
response with the status, headers and JSON body under test (429 with both hints,
400 with a description), or raising a connect/timeout error on `post`.
- Queue outcomes: the sender is replaced by one that raises the provider error or
returns `False`, so `mark_failed` sees the same exception type a real provider
produces.

**Deliberate gaps**

- `alert_service.py:115-116` — a failed audit write is swallowed on purpose.
- `alert_service.py:163-174` — the outbound-blocked path is pinned in
  `test_outbound_guard.py`; here it would only re-test `ensure_allowed`.
- `alert_service.py:482-483` — the selected-user lookup failure needs the session
  to fail; asserting the log is the mock, not a contract.
- `alert_service.py:96` and `135` — the settings snapshot fast path and the
  `send_email` wrapper; both are one-line delegations already exercised through
  their callers.
- `alert_delivery_service.py:704-709, 717, 725` — the per-part destination
  recheck, lease-loss, inter-part sleep and stale-acknowledgement branches need a
  second worker to change state mid-group; constructing that race would mock the
  unit under test.

**Closed since (plan 007, step 2):** a digest batch's label reads "Phishing
digest" while the Telegram counted line used to say "N new findings", where the
subject (email and `digest_heading`) said "candidates below the alert threshold".
This batch recorded the mismatch instead of changing it, as the program's own rule
says a behaviour that looks wrong gets its own change. That change is [plan 007](../README.md),
the follow-up plan for the gaps this program left: `Notification.counted()` now states the count
once, `digest_heading` returns the noun and its qualification beside the subject,
and every renderer prints that phrase. Closing the wording also surfaced a second
defect in the same line — a digest counted every delivery queued for the channel,
including alerts already sent, so a chat said "7 candidates" where the subject
said four; a digest now counts its own rows.
