# Plan 014 — what the first whole-suite run found

**State:** done — 2026-10-23: the suite is green in one process (3,539 passed, 16 skipped, 1:29:03)

## Goal

Plan 011's last validation item was the one thing no pass could claim: the whole
backend suite green in one run, not only the collections a pass touched. It was
attempted in four shards on 2026-10-22 and stopped, because four concurrent processes
on this host turned out slower than one. Run as a single process on 2026-10-23 it
finished — **3,532 passed, 16 skipped, 7 failed in 1:27:49** — and the seven failures
are the point of this plan.

None of them is in the audited code. Every one is fallout from the remediation
itself: a fix landed in the platform and left a guard, a fixture or a generated page
describing the old shape. That is precisely the class a full run catches and a
per-file run cannot, which is why the acceptance item existed.

They are recorded here rather than appended to [the register](../audit-findings.md):
the register's 89 rows describe what the audit found in the tree, it is closed with
every row `fixed`, and its counts are quoted in four pages. These are regressions the
remediation introduced and its own acceptance caught — the same evidence rule
applies, and each fix below cites the test that was red first.

| Defect | Introduced by | Red at `HEAD` |
|---|---|---|
| `tests/test_tls_identity_service_gaps.py` builds `DNSObservation(alerted_thresholds=…)`, a column AUD-038 deleted — three tests error at fixture construction | AUD-038 (011 pass B) | `TypeError: 'alerted_thresholds' is an invalid keyword argument` |
| the same file calls `monitor_kind("rdap")`, but AUD-036 changed the function to take the row so a probe's control can carry its port | AUD-036 (011 pass B) | `AttributeError: 'str' object has no attribute 'observation_type'` |
| `tests/test_celery_wiring.py` and `tests/test_connector_architecture.py` both assert `app.tasks.phishing_tasks` is **not** a Celery include, while AUD-033 added it and wired it in | AUD-033 (011 pass C) | the module is in `celery_app.conf["include"]` |
| the generated settings table in `docs/configuration.md` carried AUD-041's report ceiling as hand-written prose inside the generated block, so `scripts/settings_reference.py` rendered a shorter row and the page was "stale" against its own generator | AUD-041 (011 pass B) | `the settings table is stale` |

## Plan of Work

| File | Change |
|---|---|
| `backend/tests/test_tls_identity_service_gaps.py` | the fixture stops passing the dropped column; the `monitor_kind` test drives the row-taking function, including both port spellings |
| `backend/tests/test_celery_wiring.py` | the core-owned include list gains `app.tasks.phishing_tasks`, with the reason |
| `backend/tests/test_connector_architecture.py` | the same assertion, and the provider-import guard stops exempting `phishing_tasks.py` — it is core code now and must pass the guard |
| `backend/scripts/settings_reference.py` | the report ceiling becomes a generated note, derived from `MAX_RENDERED_REPORT_ROWS` and `MAX_REPORT_BYTES` rather than retyped |
| `docs/configuration.md` | regenerated section, now carrying the note from the generator |
| `docs/exec-plans/011-remediation-pass.md`, `docs/exec-plans/013-test-isolation.md` | the acceptance item records what the run measured |
| `docs/exec-plans/README.md` | one row for this plan |

## Concrete Steps

1. **The fixture and the switch.** Remove `alerted_thresholds` from the observation
   helper — the column has one home now, the control that sends the reminder
   (AUD-038) — and rewrite the `monitor_kind` test for the row-taking signature,
   including `tls:8443` from `metadata.port` and `tls:9443` from a `TLS:9443` record
   type, because that is the part of AUD-036 the test was written to protect.
2. **The Celery guards.** The two assertions were correct when written and became
   wrong when the nightly rescore became a core-owned task. They now assert inclusion
   and keep the provider-owned module excluded, so the test still separates the two
   kinds of task.
3. **The generated page.** The sentence AUD-041 added was written into the generated
   block by hand, so the generator could never reproduce it. It moves into the
   generator as a note appended to the field's rendered bounds, and the numbers come
   from the constants that enforce them.
   *Acceptance:* `python -m scripts.settings_reference` and the page agree;
   `tests/test_settings_reference.py` is green without editing the page by hand.

## Validation and Acceptance

- [x] The four files are green together (40 passed) and each was red at `HEAD`.
- [x] The whole backend suite is green in one process: **3,539 passed, 16 skipped,
      0 failed in 1:29:03** — the same command that answered 3,532 passed and 7
      failed before these fixes.
- [x] The gates that read the changed page stay green (documentation consistency,
      documentation numbers, settings reference — the last one now generated rather
      than hand-edited, and it fails again if the sentence and the constants part).

## Progress and Milestones

- **2026-10-23 — opened from the first complete run.** The run itself is the
  evidence: 1:27:49, 3,532 passed, 16 skipped, 7 failed, all seven reproduced in a
  single command over the four files. The settings table was the interesting one: the
  page was right and the generator was incomplete, which is the opposite of how a
  stale generated page usually fails.
- **2026-10-23 — closed by a clean whole-suite run.** Same command, same host,
  1:29:03: 3,539 passed, 16 skipped, none failed. `ruff check` clean on the four
  touched modules; the settings table is what the generator renders, with the report
  ceiling taken from `MAX_RENDERED_REPORT_ROWS` and `MAX_REPORT_BYTES` so the page
  cannot drift from the values that enforce it. The 16 skips are the inventoried
  ones — PostgreSQL-only cases and the host-dependent sites — unchanged by this plan.
