# ExecPlan 006 — Coverage program

## Goal

Raise the coverage that costs something when it is missing — a credential, a
customer's data, a deployment's readiness — by executing small batches that each
fit in one working session, and by recording every batch's state in its own file
so the next session resumes from the document instead of from a fresh measurement.

The tree is not badly covered. The run this program starts from measured **90.65%
of `app/` (14 300 statements, 1 337 missed)** with 2 918 tests passing. What is
left is a long tail of untested branches inside modules that matter, and the risk
is not the percentage: it is that a branch nobody executes is a branch nobody has
read.

This plan deliberately does not chase 100%. It targets the roughly 970 missed
statements that sit in security, connector, alerting, ingestion and lifecycle
modules — where a miss is a silent failure rather than a cosmetic one — and leaves
the thin remainder as a final sweep.

## Why batches, and why files

A single "cover the project" task loses the thread in a predictable way: after
several thousand lines of context the session knows the last module it read and
nothing about why it chose it. Batching fixes the size; files fix the memory.

The rules that make the files worth keeping:

- **This index is the status of record.** The batch table below is updated in the
  same change that starts or closes a batch.
- **A batch file carries its own numbers.** The measurement it was planned from,
  the work items, the floors it raised, and a dated progress log. A batch that
  stops half-way says exactly where, and the next session does not re-measure to
  find out.
- **One batch, one pull request.** The batch file moves with the tests it
  describes.
- **A batch closes only when its "Done when" section is true** — not when the
  suite is green, which it was before the batch started too.

## Method, per batch

1. **Measure the batch's modules**, not the world:
   `python -m pytest -q --cov=app.<module> ... --cov-report=json:batch.json`.
   A full-suite run is for closing a batch, not for starting one.
2. **Rank by evidence**: `python scripts/coverage_gaps.py batch.json --total`.
3. **Read the misses** with `--cov-report=term-missing` and name the behaviour each
   range represents. A line range that cannot be named is a range not to test yet.
4. **Write the test at the boundary that owns the behaviour** — the route for a
   request rule, the service for a storage rule — so one test covers the layers a
   unit test would need three to reach.
5. **Prove the test can fail.** Revert the behaviour locally (or assert on the old
   answer first) and watch it fail. A test that passes against the pre-batch tree
   is not a test of the batch.
6. **Ratchet the gate**: add or raise the module's floor in
   `backend/scripts/check_critical_coverage.py` to the measured value minus three
   points. Never lower a floor.
7. **Close**: targeted suites, then the full backend suite, then the gates the
   repository runs (`docs`, `connectors body bounds`, `mypy`). Record the result in
   the batch file.

## Measurement

The baseline of record is the `backend` job of the CI run on `main` — it prints the
per-file table this program ranks. Locally, the same numbers come from:

```bash
cd backend
COVERAGE_CORE=sysmon python -m pytest -q --cov=app --cov-report=term-missing --cov-report=json:coverage.json
python scripts/coverage_gaps.py coverage.json --total --limit 25 --format table
```

`COVERAGE_CORE=sysmon` is not optional: with the default tracer this repository's
async handlers are mis-attributed, and a hand-run without it understates coverage
by roughly nine points (limitation 1 in the readiness page).

## Batches

| Batch | Scope | Missed statements | State | File |
|---|---|---|---|---|
| 01 | Authentication and the request boundary: `auth` routes, `api/deps.py` | 109 | done — 81 closed, floors 91/96, closing run green | [batch-01](batch-01-authentication-boundary.md) |
| 02 | Accounts, RBAC and the settings contract: `users` routes, settings schemas | 111 | done — 88 closed, floors 91/97, closing run green | [batch-02](batch-02-accounts-and-settings.md) |
| 03 | The connector boundary: manifest, service, connector schemas | 150 | done — manifest 97.2%, schemas 94.1%, service 92.0%; floors 94/91/89, closing run green | [batch-03](batch-03-connector-boundary.md) |
| 04 | Alerts and delivery: message layer, service, queue, health cache | 128 | done — message 100%, health 99.1%, delivery 97.6%, service 97.2%; floors 97/96/94/94, closing run green | [batch-04](batch-04-alerts-and-delivery.md) |
| 05 | Ingestion and reports: the finding write path and report assembly | 116 | done — ingestion 97.0%, report 92.3%; floors 93/89, closing run green | [batch-05](batch-05-ingestion-and-reports.md) |
| 06 | TLS and DNS surface: certificate identities, DNS router | 110 | done — service 99.5%, router 100%; floors 96/97, closing run green | [batch-06](batch-06-tls-and-dns.md) |
| 07 | Data lifecycle and limits: retention, audit archive, quota, config | 103 | done — retention 99.3%, config 96.6%, archive 95.7%, quota 99.0%; floors 96/93/92/96 | [batch-07](batch-07-lifecycle-and-limits.md) |
| 08 | Long tail: remaining routers, services and task bodies | 146 | done — connectors 99.6%, phishing 100%, assets 99.6%, settings 98.7%, notifications and both task bodies 100%; floors 96/97/95/96/97/97/97, closing run green | [batch-08](batch-08-long-tail.md) |
| 09 | The SPA: statements, branches and functions against the current floors | — | done — 81.2/75.9/76.5/83.7, functions floor 55 → 73, closing run and build green | [batch-09](batch-09-frontend.md) |
| 10 | The thin sweep: the boundary modules left under fifteen misses each | 73 | done — all seven at 100% except `artifact_path.py` 95.2%; five floors new, two raised (registry 70 → 97, accounts 80 → 97), closing run green | [batch-10](batch-10-boundary-sweep.md) |

The eight backend rows account for about 970 of the 1 337 misses at the baseline.
The rest is spread across modules with fewer than fifteen each; batch 10 swept the
half of it that names a refusal or a boundary, and left the rest recorded rather
than mocking a line into existence. Batch 09 is the SPA and was measured from the
frontend suite's own numbers rather than from that count.

Batches 01–08 are closed on full runs (2026-10-20): 3 310 passed, 16 skipped, the
critical-coverage gate OK, mypy at 0 errors and the version gate at 0.2.1.
`app/` moved from 90.65% (1 337 missed) to **96.30% (529 missed)** — 808 of the 970
missed statements batches 01–08 were planned from.

Batch 10 closed the backend tail on a full run of its own (2026-10-20): 3 354
passed, 16 skipped, the critical-coverage gate OK with five new floors and two
raised, mypy at 0 errors and the version gate at 0.2.1. `app/` moved from 96.30%
(529 missed) to **96.79% (459 missed)** — 70 of the 73 statements the batch was
planned from; the three left are named in the batch file.

Batch 01 executed 81 of its 109 misses: `auth.py` 94.9%, `deps.py` 99.5%, floors
91 and 96. Its file records the remaining 28 lines and which are deliberate.

Batch 02 executed 88 of its 111: `schemas/settings.py` 100%, `users.py` 94.3%,
floors 97 and 91. The 23 lines left in `users.py` are unreachable through the API,
unused, or re-raised storage failures, all named in the batch file.

Batch 03 executed 82 of its 150: `connector_manifest.py` 97.2%,
`schemas/connector.py` 94.1%, `connector_service.py` 92.0%, floors 94, 91 and 89.

Batch 04 executed 108 of its 128: `alert_message.py` 100%,
`alert_health_cache.py` 99.1%, `alert_delivery_service.py` 97.6%,
`alert_service.py` 97.2%, floors 97, 96, 94 and 94.

Batch 05 executed 68 of its 116: `ingestion_service.py` 96.99% (419 of 432),
`report_service.py` 92.3%, floors 93 and 89. Its file lists the ranges that need
PostgreSQL, a font, or the event loop's internals.

Batch 06 closed 108 of its 110: `tls_identity_service.py` 99.5% and
`dns_security.py` 100%, floors 96 and 97, both new. The two lines left in the
service are a sighting whose identity row is gone and the address-less guard
inside a group R1 has already filtered; both are named in the batch file.

Batch 08 closed 144 of its 146: `routers/connectors.py` 99.6% (from 92.9%),
`routers/phishing.py` 100% (86.8%), `routers/assets.py` 99.6% (92.9%),
`services/settings_service.py` 98.7% (84.3%), `services/user_notifications.py` 100%
(85.8%), `tasks/user_tasks.py` 100% (61.3%) and `tasks/integrity_tasks.py` 100%
(75.0%). Six floors are new and the integrity floor moved 70 → 97. The four lines
left are named in the batch file: two bound checks the wire schemas refuse before
the route sees the list, a label guard pydantic coerces before its validator, and
the PostgreSQL half of the settings singleton upsert.

Batch 09 closed the frontend half: 53 files and 495 tests moved the SPA from
72.93 / 72.91 / 59.38 / 77.8 to **81.17 / 75.87 / 76.53 / 83.71**, the functions
floor rose 55 → 73 (the other three floors untouched), and `npm run test:coverage`
and `npm run build` are green. What it executed is listed in the
batch file: refused reads and failed mutations on the asset, DNS and security
pages, the second-factor enrolment flow with its "nothing is enabled until a code
verifies" invariant, and the helpers behind the endpoint map and the error
sentences. The functions left uncovered are named there too, starting with
`lib/audit.ts` (39.65%) and the Radix wrappers that only run inside a pointer
driven portal jsdom cannot open.

Batch 07 closed 82 of its 103: `retention_tasks.py` 99.3%, `config.py` 96.6%,
`audit_archive.py` 95.7% (about 99% on Linux, where the POSIX fsync block and the
symlink tests run) and `provider_quota.py` 99.0%; floors 96/93/92/96, of which
the config floor is new and the other three are raised. The 21 lines left are
named in the batch file: twelve guards in `config.py` that its own validators keep
unreachable, a PostgreSQL-only insert, one log line no reachable state produces, a
certificate check the refusal above it already makes, and the six platform-shaped
archive lines that the Linux CI run covers.

## How to resume

```bash
cd backend
python scripts/coverage_gaps.py coverage.json --total --limit 25 --format table
python -m pytest -q tests/test_coverage_gaps.py tests/test_critical_coverage_docs.py
```

All ten batches are `done`, so this command now ranks what the sweep left rather
than a batch's work. Read the lowest-performing module's misses, name the
behaviour each range represents, and add it to the batch file whose scope it
falls in (or open an eleventh batch if it falls in none) — a range that cannot be
named is still not a range to test, and batch 10's file records the ones it
judged deliberate.

## What this program does not do

- **It does not lower an aggregate floor to make room.** The 70% aggregate gate and
  every per-module floor stay where they are; batches only raise them.
- **It does not test for the sake of a line.** A range that can only be reached by
  mocking the thing under test is recorded as deliberate in the batch file instead.
- **It does not fix the defects it finds** unless the defect blocks the test. A
  behaviour that looks wrong gets a note in the batch file and its own change.
