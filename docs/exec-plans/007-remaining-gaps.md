# Plan 007 — The gaps coverage program 006 left open

**State:** done — steps 1–4 landed on 2026-10-20, and step 3's acceptance run finished on 2026-10-21 (full suite, exit 0, gate OK against the report it wrote)

**Goal:** close the four items the closing audit left open, each with a check that
can be repeated by the next session: the untested `GET /audit/integrity` pinned by
an integration test and a measured coverage range, a digest that names its
candidates instead of calling them findings, a coverage command whose flags work on
both the container and the development host, and the one floor that sits below the
gate's own rule. Shipped behaviour changes in exactly one place — the digest
wording — and no coverage floor is lowered to make any of it pass.

**Scope:** the four items the closing audit of
[006-coverage-program](006-coverage-program/README.md) left behind, in the order
their cost puts them: an untested status endpoint, a wording mismatch the program
recorded instead of fixing, a coverage command that aborts on the development venv,
and one floor that sits a point below the gate's own rule. Nothing here is a new
feature; each item is a behaviour that already ships and is either untested,
mislabelled, unmeasurable on one platform, or enforced more loosely than the gate
claims.

**Baseline** (measured on 2026-10-20, this checkout):

| Evidence | Measurement |
|---|---|
| `app/api/v1/routers/audit.py` on its three suites (`test_audit_router_filters`, `test_audit_routers_integration`, `test_audit_service_unit`) | 42 passed, **84%**; `GET /integrity` executes only lines `147-148`, its body (`160-199`, nine statements) is entirely missing |
| `--cov=app`, `--cov=app.core` on the venv | pass (15 passed, ~24 s) |
| `--cov=app.core.security`, `--cov=app.api.v1.routers`, `--cov=app.api.v1.routers.audit` | exit 4 before any test: `ImportError: PyO3 modules … may only be initialized once per interpreter process` from `bcrypt` |
| digest Telegram header / plain text | `alert_content.py:31,38` print "new findings"; `alert_message.py:314` prints "Findings: N"; the subject from `digest_heading` says "candidates below the alert threshold" |
| `ingestion_service.py` floor | 93 in the gate, 97.0% measured per [the program README](006-coverage-program/README.md) → the stated rule (measured − 3) gives 94 |

**Measuring this router needs `COVERAGE_CORE=sysmon`.** With the default C

tracer, a run that exercises `GET /integrity` still reports its body as missing:
the handler's lines after the first `await` are never recorded, while the same
run under `sysmon` records all of them. The Makefile and CI already set the
variable (`Makefile:241`), so the gate has always used the accurate tracer; every
figure in this plan is taken with it. A probe with the C tracer once made this
endpoint look 75% instead of 84%, and a run of the new test alone 29% instead of
37% — do not measure here without it.

**What this plan does not do**

- It does not raise the aggregate 70% floor: [the program README](006-coverage-program/README.md) freezes it.
- It does not add a second coverage entry point. The Makefile target stays the one
  command, executed in the tooling container; the host run is a documented
  two-command sequence, not a `make` target, so there is still a single list of
  flags — the one the gate prints.
- It does not test `/integrity` by mocking the chain: the endpoint reads
  `chain_state` and two aggregates, all reachable through the real session.

## Plan of Work

| File | Change |
|---|---|
| `backend/tests/test_audit_routers_integration.py` | new tests: `/integrity` as admin (shape, aggregates, archive present and absent, the audit row it writes) and as analyst/viewer (403, no row) |
| `backend/app/services/alert_message.py` | `Notification.counted_noun` / `counted_tail` fields and one `counted()` method that pluralises them; `digest_heading` returns the noun and the qualification beside the subject; `plain_text` and `telegram_text` print `counted()` instead of their own phrases |
| `backend/app/services/alert_content.py` | `telegram_parts` prints `notification.counted()` in both header branches (the full one and the small-budget one) |
| `backend/app/services/alert_service.py` | `_build_notification` takes `counted_noun` / `counted_tail` and passes them to `Notification` |
| `backend/app/services/alert_delivery_service.py` | unpacks the wording from `digest_heading`, passes it to `_build_notification`, and counts a digest's own rows rather than the whole group |
| `backend/tests/test_alert_message_layer.py` | digest wording unit: the three counted forms; the updated plain-text assertion at line 134 |
| `backend/tests/test_phishing_digest.py` | Telegram digest case, end to end through the outbox: header says "4 candidates below the alert threshold" and contains no "new findings"; the email digest's plain part likewise |
| `backend/scripts/check_critical_coverage.py` | `--cov-args` prints `--cov=app`, with the comment saying why the per-module spelling cannot be the portable one |
| `backend/tests/test_critical_coverage_docs.py` | the `--cov-args` test asserts the single package flag; the module list itself stays checked against `THRESHOLDS` by the parity tests that already exist |
| `Makefile`, `.github/workflows/ci.yml` | comments only where they name the flag spelling; the substitution stays `$$(python scripts/check_critical_coverage.py --cov-args)` |
| `docs/production-readiness.md` | the sentence about the gate printing its own `--cov=` flags says "one package flag", plus the documented host command |
| `docs/exec-plans/006-coverage-program/batch-04-alerts-and-delivery.md` | the "noted, not fixed" paragraph becomes a closed item pointing at this plan |
| `docs/exec-plans/006-coverage-program/batch-06-tls-and-dns.md` | the measurement note is corrected: package-level `--cov=app.core` works, module-level paths abort |
| `docs/exec-plans/006-coverage-program/README.md` | the `ingestion_service` floor line, once the full run decides 93 or 94 |
| `CHANGELOG.md` | one entry for the digest wording (the other items change no shipped behaviour) |

## Concrete Steps

Each step ends with the command that proves it. Steps 1–2 are independent of
3, and 4 depends on the report step 3 produces.

**Step 1 — pin `GET /audit/integrity` (smallest, no production change).**

1. Read `audit_integrity` (`routers/audit.py:147-211`) and list the statements the
   test must reach: the two aggregates, the `retired`/`retained` locals, the
   `AuditLogger.emit` call, the archive lookup and both sides of `archive is None`.
2. Add the admin test to `test_audit_routers_integration.py`, using the existing
   `client` + `auth_headers_admin` + `db_session` fixtures: assert `200`, the seven
   top-level keys, `retained.rows` equal to the `AuditLog` count, `committed` and
   `retired` echoing `chain_state`, `archive.configured` following
   `settings.AUDIT_ARCHIVE_DIR`, and one `audit.integrity.view` row whose
   `details.retained_rows` matches the response.
3. Add the refusal: `auth_headers_analyst` and `auth_headers_viewer` get `403`,
   and no `audit.integrity.view` row appears.
4. Add the archive-present case by inserting an `AuditArchive` row, so
   `archive.last_seq` / `retired` are not only read as `None`.
5. Measure and prove the body is fully executed:
   `COVERAGE_CORE=sysmon pytest -q --cov=app --cov-report=json:cov_audit.json tests/test_audit_router_filters.py tests/test_audit_routers_integration.py tests/test_audit_service_unit.py`
   then check that `missing_lines ∩ [147, 212)` is empty in the JSON. A statement
   that stays missing must be named in the test file's docstring as unreachable,
   never mocked into existence.

**Step 1 result (2026-10-20).** Five tests added to
`test_audit_routers_integration.py`: the chain status with seeded chain state and
two signed rows; the archive present then retired; the empty chain, where an
aggregate that is ``None`` must read as `0` rather than `null`; the prefix
retention has retired, where the watermark and the surviving `first_seq` are
stated instead of implied; and the refusal to an analyst and a viewer with no
`audit.integrity.view` row (the `authz.denied` record is asserted too, because a
probe of this surface is meant to be visible).
`routers/audit.py` moved 84% → **94%**, and `missing_lines ∩ [147, 212)` went from
nine statements to none; the five statements left in the module are
`list_audit_logs` filter branches, outside this step.

One behaviour the test pinned rather than changed: the response computes
`retained` *before* writing its own `audit.integrity.view` row and reads
`committed` *after* it, so `retained.rows` excludes this request while
`committed.through_seq` includes it. That is a mixed snapshot of one moment. It is
now asserted, deliberately; if an operator should see one consistent point in
time, that is its own change and not part of this plan.

**Step 2 — make a digest count candidates, not findings (no plan reopened).**

1. Add `counted_phrase: str = "new findings"` to `Notification`
   (`alert_message.py:210`), last in the field list so every existing constructor
   keeps working.
2. Extend `digest_heading` (`:326`) to return `(label, subject, counted_phrase)`:
   phishing → "candidates below the alert threshold", breach → "new incidents from
   one scan". Keep the subject strings byte-identical, so no mail-client test moves.
3. `plain_text` (`:314`): print `f"{total} {counted_phrase}"`, keeping the
   "(showing the first N)" suffix. `telegram_parts` (`alert_content.py:31,38`):
   replace the hardcoded "new findings" in both branches.
4. `_build_notification` (`alert_service.py:551`) gains `counted_phrase="new
   findings"`; the delivery service (`:693`) passes the value it got at `:680`.
5. Tests: the three counted forms in `test_alert_message_layer.py`; the updated
   plain-text assertion; a Telegram digest case in `test_phishing_digest.py` that
   asserts the header *and* asserts `"new findings" not in text`, plus the email
   digest's plain part. A digest test that only checks the subject is what let the
   mismatch through, so the assertion is on the rendered body.
6. Close the batch-04 paragraph, citing this plan.

**Step 2 result (2026-10-20).** The count is stated once, in `Notification`:
`counted_noun` plus an optional `counted_tail`, pluralised by one `counted()`
method. Two fields rather than one phrase because the noun is what pluralises: a
stored phrase would print "1 candidates below the alert threshold" the first time
a digest carried one candidate. `digest_heading` returns the pair beside the
subject, `_build_notification` accepts it, and the delivery service passes it for
a digest batch only. All three renderers (`plain_text`, `telegram_text`,
`telegram_parts` in both its branches) now print that one phrase.

The end-to-end test found a second defect in the same line, which the wording fix
would otherwise have published: a digest's `total` was the group total — every
delivery queued for that channel and target, including the alerts already sent — so
its subject said four candidates while a chat header said seven. A digest now
counts its own rows; an ordinary alert keeps the group total, whose meaning is
"the batch you are being told about".

Measured: 30 passed in the two message suites, 153 passed across the eleven alert
suites (delivery paths, reliability, breach digest and announcement, channel
schedules and isolation), ruff clean. The batch-04 note is closed with a pointer
here, and `CHANGELOG.md` carries the wording under Unreleased → Fixed.

**Step 3 result (2026-10-20).** `--cov-args` prints one flag, `--cov=app`, and the
reason is in the gate's own docstring and the flag's comment: a dotted
`--cov=app.<module>` resolves by import, and on this venv that import aborts inside
`bcrypt`'s PyO3 init before `conftest` loads. Nothing about the thresholds moved:
the gate still reads each file's own percentage out of the report, and because the
report now covers the package, a gated module cannot be absent from it at all —
`check_report` still fails one that is, and a new test pins that
(`test_a_report_missing_a_gated_module_fails_the_gate`). The parity test was
rewritten to assert the literal single flag; the Makefile and CI comments, the
gate's docstring, the readiness sentence and the batch-06 measurement note now
describe the package flag instead of the dotted list.

Measured: `--cov-args` → `--cov=app`; `test_critical_coverage_docs.py` 4 passed
(3 before, +1 for the missing-module refusal); 48 passed across the portable
commands, docs and critical-coverage gate tests; docs gate OK (81 documents);
`python scripts/check_critical_coverage.py coverage.json` → OK against the
full-suite host report (128 files, `app/` 97%, every floor met).

**Step 3 acceptance run (2026-10-21).** The sequence the step names was executed
as written, on this venv, after the PyO3 abort was diagnosed:
`cd backend && COVERAGE_CORE=sysmon python -m pytest -q --cov=app --cov-report=json:coverage-critical.json tests/`
finished **3363 passed, 16 skipped in 6039.60 s (1:40:39), exit 0**, and wrote
`backend/coverage-critical.json` (timestamp `2026-10-21T00:43:33`, 128 files,
14310 statements, 96.86%). Running `python scripts/check_critical_coverage.py coverage-critical.json` then reported OK — every one of the 31 gated modules above
its floor, all 31 present in the report. The floors are unchanged by construction,
and `ingestion_service.py` reads 96.99% (432 statements) in this report too, which
is the figure step 4 decided on.

The run was one process, sharded and parallelised not at all, and it printed the
same summary shape an ordinary local run does. Its 16 skips were later classified
rather than left as a counter: four want a Redis broker, five are the PostgreSQL
integration modules, three need row locks only PostgreSQL provides, and four are
the symlink cases this Windows host cannot run. The breakdown — test ids, the
variable or stack that executes each group, and the run that shows the list is
complete — is in
[the readiness page](../production-readiness.md#what-a-host-run-skips-and-why).
Nothing in the container path changed: `make test-backend-critical-coverage` still
substitutes the flags the gate prints.

**Step 3 — one coverage flag that works everywhere.**

1. `--cov-args` prints `--cov=app`. The gate keeps reading per-file numbers from
   the JSON, so every threshold is unchanged and a gated module still cannot be
   missing from the report.
2. Rewrite the `--cov-args` test: exactly one flag, equal to `--cov=app`; add the
   negative case, that a report without a gated file fails the gate (if
   `check_report` does not already have such a test).
3. Update the three places that describe the spelling (gate docstring, Makefile
   comment, readiness sentence) and correct the batch-06 measurement note.
4. Prove the flags work on the host venv, not the container:
   `cd backend && COVERAGE_CORE=sysmon python -m pytest -q --cov=app --cov-report=json:coverage-critical.json tests/`
   and then `python scripts/check_critical_coverage.py coverage-critical.json`.
   This is the acceptance run and it is the full suite (~3 350 tests, about an
   hour on the development host): do not substitute a subset, because the gate
   would then fail on modules that suite does not import.
5. In CI nothing changes: the job already substitutes the printed flags.

**Step 4 — settle the one floor below the rule (depends on step 3's report).**

1. Read `ingestion_service.py` from `coverage-critical.json`.
2. If it is at or above 97.0, raise the floor 93 → 94 in
   `check_critical_coverage.py` and in the readiness table, and note it in
   [the program README](006-coverage-program/README.md). If the full run measures less than 96.0, leave 93 and correct
   the README arithmetic instead — the floor is never lowered.
3. No other floor moves: every other module already sits at measured − 3.

**Step 4 result (2026-10-20).** The full-suite host report — `backend/coverage.json`,
written the same day by a run of `tests/` under `COVERAGE_CORE=sysmon`; steps 1–2
touch only `alert_*`, so this module's figure is unaffected — measures
`ingestion_service.py` at **96.99%**, 419 of 432 statements: not the 97.0% the
programme README rounded it to. Measured minus three floors to 93.99, so **93 is
the floor the rule produces**: raising it to 94 would sit above the rule, and the
"one point below policy" this plan opened was a reading of a rounded display, not a
gap. No threshold moved. The gate's comment now carries the exact figure and the
arithmetic (`93.99` floors to `93`) so the next reader cannot repeat the mistake,
and the programme README prints 96.99% (419 of 432) instead of 97.0%. Every other
floor was left alone, as the plan requires.

## Validation and Acceptance

- [x] `GET /audit/integrity` returns `200` with the seven documented keys and
      writes `audit.integrity.view`; analyst and viewer get `403` with no row.
- [x] `missing_lines ∩ [147, 212)` for `routers/audit.py` is empty in a report
      produced by the three audit suites under `COVERAGE_CORE=sysmon` (measured
      2026-10-20: nine statements missing before, none after).
- [x] A digest Telegram message and a digest plain-text part both say
      "N candidates below the alert threshold" and contain no "new findings",
      asserted on the rendered text rather than the subject (measured 2026-10-20
      through the real outbox on both channels).
- [x] Non-digest alerts are unchanged: `test_alert_message_format`,
      `test_alert_service`, `test_breach_alert_content` and
      `test_alert_delivery_paths` pass untouched except the single plain-text
      assertion the new counted line requires (153 passed across the eleven alert
      suites).
- [x] `python scripts/check_critical_coverage.py --cov-args` prints `--cov=app`,
      and the gate accepts a report from the full suite and rejects one missing a
      gated file (both measured 2026-10-20: `coverage.json` OK, and
      `test_a_report_missing_a_gated_module_fails_the_gate` passes).
- [x] The host sequence in step 3 produces `coverage-critical.json` and the gate
      passes against it; the container target keeps working unchanged. Measured
      2026-10-21: the full suite under `--cov=app` finished 3363 passed, 16 skipped,
      exit 0 in 1:40:39 and wrote a 128-file report (96.86%), and the gate read that
      report as OK for all 31 modules. The container target was not executed here —
      `make` is not installed on this host and raising the tooling stack is its own
      heavy step — but it is unchanged in the one place that matters:
      `Makefile:242-243` still runs the same pytest with
      `$$(python scripts/check_critical_coverage.py --cov-args)` and `&&`-chains the
      gate behind it, so it measures the flag this run exercised.
- [x] `python scripts/check_docs_consistency.py`, `test_docs_consistency_gate`,
      `test_critical_coverage_docs` and the version gate are green; the version is
      not bumped (no shipped behaviour changes beyond the digest wording, which is
      recorded in `CHANGELOG.md`).
- [x] The one floor that looked a point low is justified against the exact
      measurement or raised: `ingestion_service.py` measured 96.99%, so the rule
      produces 93 and the floor stands; no other floor moved.

**Risks and limits**

- The digest change edits the shared message layer. The guard is the four
  non-digest suites above; if any of them needs an assertion changed beyond the
  plain-text line, the change has leaked into ordinary alerts and should be
  reverted rather than re-baselined.
- Step 3's acceptance costs an hour of wall clock and cannot be short-circuited.
  If the full run is not affordable in a session, the honest state is "flags
  changed, gate proven on a synthetic report, thresholds unproven on this host" —
  which is what the batch-06 note already records, and it must not be written up
  as a passing check.
- Step 4 cannot be decided without that report; do not raise the floor from the
  README's snapshot alone.

## Progress and Milestones

| Date | Change | Measured |
|---|---|---|
| 2026-10-20 | plan written; baseline measured — audit router 84% with the `/integrity` body missing, flag matrix on the venv, digest code paths read | see Baseline |
| 2026-10-20 | step 1: five tests in `test_audit_routers_integration.py` (chain status, archive and retirement, empty chain, retired prefix, refusal to non-admins); `COVERAGE_CORE=sysmon` established as the only accurate tracer for this router | `audit.py` 84% → 94%, 47 passed; `missing_lines ∩ [147, 212)`: 9 → 0 |
| 2026-10-20 | step 4: read `ingestion_service.py` from the full-suite host report — 96.99% (419 of 432), so measured-minus-three floors to 93; no threshold changed, the gate comment and the programme README now carry the exact figure | gate OK against `coverage.json` (97% overall, all 31 modules above their floors) |
| 2026-10-20 | step 3: `--cov-args` prints `--cov=app`; parity test rewritten, missing-module refusal pinned, gate docstring, Makefile, CI comment, readiness and batch-06 note updated | `--cov-args` → `--cov=app`; 4 gate-docs tests, 48 gate/doc tests; gate OK against the full-suite host report |
| 2026-10-20 | step 2: `Notification.counted()` + `counted_noun`/`counted_tail`, `digest_heading` returns the wording, all three renderers print it, a digest counts its own rows; batch-04 note closed, changelog entry added | 30 passed in the two message suites, 153 across the eleven alert suites; a digest says "4 candidates below the alert threshold" on email and Telegram and no longer says "new findings" |
| 2026-10-21 | step 3 acceptance: the documented host sequence run end to end on the venv — the whole suite under the package flag, then the gate against the report that run wrote | 3363 passed, 16 skipped, exit 0 in 1:40:39; `coverage-critical.json` 128 files, `app/` 96.86%, gate OK for all 31 modules |
