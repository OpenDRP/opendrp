# Batch 07 — Data lifecycle and limits

**State:** done

**Scope:** the code that deletes, the code that proves what it deleted, the budget
that stops a provider bill, and the settings that decide all three.

**Baseline:** the `backend` job of the CI run on `main` (2026-10-19): `app/` at
90.65%, 1 337 statements missed.

| Module | Statements | Missed | Covered |
|---|---|---|---|
| `app/tasks/retention_tasks.py` | 274 | 33 | 88.0% |
| `app/core/config.py` | 349 | 29 | 91.7% |
| `app/services/audit_archive.py` | 139 | 21 | 84.9% |
| `app/services/provider_quota.py` | 100 | 20 | 80.0% |

**Measured misses**

- `retention_tasks.py`: 128-145, 149, 193-194, 252-255, 259-266, 293, 321, 379,
  395, 427, 504, 522, 537, 606, 654-655
- `config.py`: 62-63, 67, 476, 480, 482, 485-486, 518, 602, 605-606, 621-622,
  660-661, 669-670, 674-675, 692, 737-738, 743, 768-769, 794, 807, 858
- `audit_archive.py`: 24-26, 35-36, 40-42, 57, 62, 66, 69, 78, 83, 93, 103, 114,
  141-142, 149-150
- `provider_quota.py`: 88, 95, 98, 109-110, 119-132, 138, 148, 150, 152, 179-180,
  182-183, 231-232, 244-245

**Result**

| Module | Missed | Covered | Floor |
|---|---|---|---|
| `app/tasks/retention_tasks.py` | 2 | **99.3%** | 96 |
| `app/core/config.py` | 12 | **96.6%** | 93 (new) |
| `app/services/audit_archive.py` | 6 | **95.7%** | 92 (raise from 75) |
| `app/services/provider_quota.py` | 1 | **99.0%** | 96 (raise from 75) |

The archive's six local misses are platform-shaped, not behaviour-shaped: lines
44-48 are the POSIX directory `fsync` (not executed on Windows) and lines 57 and
69 are the two symlink refusals, whose tests `pytest.skip` where symlinks are
unavailable. On the Linux CI those tests run and the module measures about 99%.

**Work items**

- [x] Retention deletes nothing when the archive did not verify, and the refusal is
      reported rather than logged and continued.
      `test_audit_archive_edges.py` pins each stop: a checkpoint that does not
      describe the rows, a gap inside the prefix, a receipt naming another
      archive, a hold raised mid-sweep (deletion refused and the transaction
      rolled back), and a chunk the resumable full pass has not read. The sweep
      turns those into `audit_archive_retention_blocked` with the exception's type
      — the table's result stays at zero rather than reporting a partial success.
- [x] `AUDIT_RETENTION_DAYS=0` disables the sweep; a retention run with nothing to
      delete writes no audit row. `test_zero_days_keeps_the_audit_history` and
      `test_sweep_writes_nothing_when_it_deletes_nothing` (both predate this
      batch) cover the pair; `test_the_hold_switch_archives_and_deletes_nothing`
      covers the other switch that must leave both the table and the directory
      untouched.
- [x] Quota: a reservation that would exceed the account's budget is refused before
      the request, an exhausted account is not retried, and a shared-account
      approval is required for a second connector.
      `test_an_exhausted_budget_tells_the_worker_when_to_come_back` (429 with the
      script's `Retry-After`, and 1 when the script did not say), the three-case
      approval test (revoked, absent, another provider — each with its
      `source_account.quota_denied` row), and the existing shared-account test in
      `test_source_intelligence.py` that pins one Redis bucket pair for two
      connectors.
- [x] Configuration: the production safety rules refuse a default secret, a missing
      key and a value that only looks valid; each message names the variable.
      `TestProductionStartupRefusals`, `TestProxyAllowlistShapes`,
      `TestBreachNoisePolicy` and `TestCorsOriginShapes` in `test_config.py`; every
      assertion matches the message, and each message names its variable.

**Deliberately uncovered**

- `retention_tasks.py:293` — the PostgreSQL `pg_insert` for the report-queue lock
  row. The suite runs on SQLite and takes the `sqlite_insert` branch; the two
  statements are the same insert with a different dialect's `ON CONFLICT`.
- `retention_tasks.py:395` — `log.error("report_artifact_cleanup_pending")`. The
  count and the retry pass read the same predicate: an intent that is due is
  either removed, or backed off past `available_at` by the failure that kept it,
  so `pending` cannot be non-zero after the pass.
- `config.py:602, 605-606, 660-661` — guards inside `deployment_networks` and the
  trusted-proxy overlap check for a subnet string that
  `_validate_network_ranges` already refuses to construct.
- `config.py:669-670` — a trusted entry that is not an IP or CIDR never reaches
  the model validator: the field validator refuses it first (and is covered).
- `config.py:674-675` — `ip_network.overlaps` answers `False` for an IPv4 entry
  beside an IPv6 network instead of raising, so the `TypeError` arm never runs.
  The `supernet_of` call below does raise and is covered.
- `config.py:692` — a range that is a supernet of `OPENDRP_NETWORK_SUBNET` always
  overlaps the data or connector subnet, so the earlier refusal fires first.
- `config.py:743, 807` — the model validator's second copy of a check the field
  validator already failed on (a short `JWT_SECRET_KEY`, a `*`
  `UVICORN_FORWARDED_ALLOW_IPS`).
- `provider_quota.py:152` — the certificate-bucket check that repeats the
  `bucket not in operations` refusal directly above it; with `"certificate"`
  missing from the operations the earlier one wins, and with it present this one
  cannot fire.

**PostgreSQL-only paths**

- `retention_tasks.py:293` (above) is the only deletion path that a SQLite run
  cannot execute. The PostgreSQL behaviour itself is exercised by the
  `postgres` CI job's migration and integration suites, which create the queue
  rows through the same model.

**Done when**

- all four modules are at or above 90% and every floor is raised, `config.py`
  gaining one — 96/93/92/96 in `backend/scripts/check_critical_coverage.py`, all
  four listed in `docs/production-readiness.md`;
- the retention, audit, quota and config suites plus the full backend suite are
  green;
- the batch file records any deletion path that can only be exercised against
  PostgreSQL — above.

**Progress log**

| Date | Change | Measured |
|---|---|---|
| 2026-10-19 | batch written from the CI baseline | 88.0%, 91.7%, 84.9%, 80.0% |
| 2026-10-20 | `test_audit_archive_edges.py`: artifact immutability and both write races, manifest signature/name/version, symlink manifest and data file, envelope and chain tamper, hold, checkpoint mismatch, prefix gap, receipt mismatch, mid-sweep hold, unverified chunk | archive 95.7% |
| 2026-10-20 | `test_provider_quota_edges.py`: no provider identity, naive lease, unusable queued account, the three approval refusals with their audit row, deadline, declared operations, broker failure, 429 with `Retry-After`, and the four `remaining_today` answers | quota 99.0% |
| 2026-10-20 | `test_retention_task_edges.py`: chain positions handed to `on_batch`, unlink failures, refused and failing cleanup intents, empty artifact name, outside-store intents, chain/identity backlog truncation, alert history off and truncated, `details["truncated"]`, and a failed audit write after committed deletions | retention 99.3% |
| 2026-10-20 | `test_config.py`: CORS string/type shapes, proxy allowlist shapes, noise policy, subnet/database/broker URL refusals, insecure cookie, short JWT secret | config 96.6% |
| 2026-10-20 | floors raised (and `config.py` gated for the first time); readiness table updated | 96/93/92/96 |
| 2026-10-20 | closing run: full backend suite 3 234 passed, 16 skipped; `app/` at 95.32% (14 303 statements, 670 missed); critical-coverage gate OK; mypy 0 errors; docs, body-bound and version gates OK; version 0.2.1 | 99.3%, 96.6%, 95.7%, 99.0% |
