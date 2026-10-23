# Batch 02 — Accounts, RBAC and the settings contract

**State:** done — `users.py` 94.3%, `schemas/settings.py` 100%, floors 91/97;
closing run green (2026-10-20: 3 089 passed, 14 skipped, critical-coverage gate
OK).

**Scope:** the administrator's surface over people and configuration: user
lifecycle, role changes, and the contract that refuses a settings payload before
it reaches storage.

**Baseline:** the `backend` job of the CI run on `main` (2026-10-19): `app/` at
90.65%, 1 337 statements missed.

| Module | Statements | Missed | Covered |
|---|---|---|---|
| `app/api/v1/routers/users.py` | 397 | 59 | 85.1% |
| `app/schemas/settings.py` | 282 | 52 | 81.6% |

**After the batch (2026-10-19):** measured on the suites that own these modules
(162 passed, 1 skipped), 88 of the 111 baseline misses are executed. The full
backend run is the closing measurement; for the code as it stands it can only add
coverage.
`users.py` gains three statements in this batch (the shared email-conflict
predicate), so its percentage is against the current 400; the baseline count is
kept above as the record it was planned from.

| Module | Statements | Missed | Covered |
|---|---|---|---|
| `app/api/v1/routers/users.py` | 400 | 23 | 94.3% |
| `app/schemas/settings.py` | 282 | 0 | 100% |

Floors: `users.py` enters the gate at 91, `schemas/settings.py` at 97 (measured
minus three, rounded down), mirrored in the readiness page's table.

**Baseline misses**

- `users.py`: 76, 78, 114, 420, 450, 466, 487-492, 525, 546-548, 620, 630,
  663-668, 713, 718-722, 824-831, 883, 910-915, 935, 983, 1006-1008, 1036,
  1079-1084, 1150-1151
- `schemas/settings.py`: 101-104, 110, 124, 127, 138, 141-142, 151, 154, 156,
  165, 167, 170, 179, 181, 192-193, 198-211, 217, 227, 240, 242, 249, 251-252,
  254, 257, 261, 269, 276, 286, 303, 408, 410, 413

**First move**

```bash
cd backend
COVERAGE_CORE=sysmon python -m pytest -q --cov=app.api.v1.routers.users --cov=app.schemas.settings --cov-report=term-missing --cov-report=json:/tmp/batch02.json
```

**Work items**

- [x] RBAC: the last administrator cannot be demoted, deleted or deactivated by
      the routes that would leave the installation without one — each refusal has
      its own status and audit action (`tests/test_users_integration.py`,
      `tests/test_users_operator_surface.py::TestBulk`, and the shared predicate
      in `tests/test_users_operator_surface.py::TestBulk::
      test_the_bulk_path_holds_the_same_last_admin_guard`).
- [x] Self-service boundaries: an analyst cannot raise their own role because the
      account surface is admin-only (`tests/test_authorization_denials.py` pins
      the 403 and its single audit row). The read-ownership half of the item —
      jobs, assets, findings — is enforced in those routers and belongs to
      batches 05 and 08; the batch file records the scope correction rather than
      duplicating those suites here.
- [x] Settings schemas: each validator's refusal names the field, and the
      alert-budget cross-field rule (digest threshold at or above the direct one)
      is refused as a whole. `tests/test_settings_contract.py` walks every
      validator branch (the module reaches 100%); the cross-field refusal is
      pinned at the API in `tests/test_alert_policy.py`.
- [x] Pagination and search: the shape a page returns for an empty result and for
      a filter that excludes everything is in
      `tests/test_users_read_paths.py`; the role/activation filters those pages
      were missing are in `tests/test_users_edges.py::TestListFilters`.

**Done when**

- [x] both modules are at or above 90%, with the gate extended to `users.py` and
      `schemas/settings.py` at measured-minus-three (91 and 97);
- [x] the users, RBAC and settings suites plus the full backend suite are green —
      the targeted set is (162 passed, 1 skipped, including 39 new tests); the
      full suite closed on 3 089 passed, 14 skipped;
- [x] the batch file records any refusal that turned out to be unreachable, with
      the reason.

**Progress log**

| Date | Change | Measured |
|---|---|---|
| 2026-10-19 | batch written from the CI baseline | `users.py` 85.1%, `schemas/settings.py` 81.6% |
| 2026-10-19 | `tests/test_settings_contract.py`: every SMTP field, recipient list, schedule shape and the response passthrough, including the branches that map an empty/None value to "absent" and the messages that name a field | `schemas/settings.py` 0 missed / **100%** |
| 2026-10-19 | `tests/test_users_edges.py`: role/activation filters, duplicate address on create and invite, inviting an administrator, reissuing a link, a bulk no-op, rate-limit update, naive unlock, unknown-account 404s on every per-account route, MFA reset (self refusal, no-factor refusal, success), and the storage-conflict answers for create, invite, bulk, update, unlock, delete and MFA reset | `users.py` 23 missed / **94.3%**; 88 of 111 closed |
| 2026-10-19 | the duplicate-create test failed before the fix: SQLite names the column (`UNIQUE constraint failed: users.email`), the router only recognised PostgreSQL's constraint name, and a taken address answered the generic "constraint violation". `users.py` now has one `_is_email_conflict` predicate shared by create and update; the test asserts the specific message | unchanged; the three added statements are why the module's denominator moved 397 → 400 |

**Deliberate gaps**

- `users.py:114` — `_count_active_admins` is an unused wrapper around the shared
  predicate; no route calls it. Removing it is a code change, not a test.
- `users.py:636` — the bulk route's last-active-admin refusal. Through the API it
  cannot be reached: the caller is an active administrator, deactivating
  themselves is refused first, and their own row is not in the selection, so the
  set can never become empty. The shared predicate is pinned directly in
  `TestBulk`; the route's duplicate check is defence in depth.
- `users.py:506-508, 562-564, 682-684, 845-847, 929-931, 1022-1024, 1098-1100` —
  the generic `except Exception` re-raises in invite, reissue, bulk, update,
  unlock, admin session revocation and MFA reset. The routes do not translate
  these; reaching them means making the session or the audit writer fail and then
  asserting an exception propagates, which tests the mock rather than a contract.
- `schemas/settings.py` has no remaining gap; the 100% is by the schema's own
  tests, without touching the database.

**Closing run**

- `COVERAGE_CORE=sysmon python -m pytest -q --cov=app` on 2026-10-20: 3 089 passed,
  14 skipped; the critical-coverage gate OK on that report, mypy 0 errors, version
  gate 0.2.1. This file and the index moved to `done`.
