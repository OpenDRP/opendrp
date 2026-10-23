# Plan 011 — the remediation pass

**State:** done — passes A, B and C closed (2026-10-22)

## Goal

Nineteen findings were carried into this plan from [the register](../audit-findings.md),
and all nineteen are closed — eight in pass A, six in pass B, five in pass C. They are real defects, reproduced
with a failing test or a printed value, that step 009's attention budget could not
fix inside the step that found them. This plan carries them in three passes, ordered
by blast radius divided by cost — evidence that is lost or misattributed first, then
the numbers an operator acts on, then debt with a workaround.

The rule that made each of them a finding still applies: a row moves from `planned`
to `fixed` only when the change lands with a regression test that was red first.
`backend/tests/test_audit_register_gate.py` is what keeps the register honest in
between — a row that names a plan which does not exist, or no plan at all, fails the
build.

## Plan of Work

| File | Change |
|---|---|
| `backend/app/services/alert_message.py`, `alert_facts.py`, `alert_content.py` | render an empty fact as empty-and-explained, and give the Telegram line the breach date and the verification state (AUD-015, AUD-016) |
| `backend/app/services/connector_credentials.py`, `backend/app/api/v1/routers/connectors.py` | bound and filter the rejected-token name hint before it reaches a log line (AUD-018) |
| `backend/app/services/connector_manifest.py`, `backend/app/schemas/connector.py` | refuse `--5`, `nan` and `inf` with a 400 naming the setting, and bound a schemaless string (AUD-019) |
| `connectors/shodan/main.py` | make the favicon fetch's test seam explicit and warn when it is in force, without breaking the connector CI job that runs with `APP_ENV=test` (AUD-026) |
| `backend/app/services/asset_service.py`, `backend/app/api/v1/routers/breaches.py`, `backend/app/api/v1/routers/phishing.py` | capture the ids a bulk finding cleanup removes, beside the count, on both cleanup routes (AUD-030) |
| `backend/app/services/phishing/whois_service.py` | make every WHOIS hop pass the outbound guard, or pin the registry hop and disable the referral recursion (AUD-032) |
| `backend/app/services/ingestion_events.py` | report the backlog still held, not the remainder of the window the pass fetched (AUD-088) |
| `backend/app/services/provider_quota.py`, `connectors/base/opendrp_connector/` | report the budget `reserve` actually enforces, and move the per-provider cap into connector configuration (AUD-020, AUD-021) |
| `backend/app/services/dns_expiry_monitor_service.py`, `dns_security_service.py`, `dns_expiry_service.py`, `tls_identity_service.py`, `backend/app/api/v1/routers/dns_security.py`, `backend/app/models/dns_observation.py`, `backend/alembic/versions/0001_initial_schema.py` | key the control by port with a lazy backfill, record every subject on the sighting so R3 iterates them, and drop the observation's `alerted_thresholds` (AUD-036, AUD-037, AUD-038) |
| `backend/app/services/report_service.py` | refuse a document over 25,000 rows before rendering it, and remove a written file over 64 MiB instead of publishing it (AUD-041) |
| `connectors/dns_security/quota.py` | delete the second budget nothing calls (AUD-022) |
| `backend/app/services/phishing_score_service.py` | wire `score_pending` to a maintenance task, or delete it and say a stored score is historical (AUD-033) |
| `backend/requirements.txt` | pin a compatible Typer/Click pair and drop the per-option `flag_value` workaround (AUD-057) |
| `frontend/src/lib/api.ts`, `frontend/src/types/api.ts` | type the 56 untyped helpers against the OpenAPI components, with a response-shape gate in the `frontend` job (AUD-060) |
| `backend/tests/test_mypy_baseline_gate.py` | drive the ratchet gate's parse, comparison and three exit codes with `_run_mypy` stubbed (AUD-089) |

## Concrete Steps

### Pass A — evidence that is lost or misattributed (8 findings)

Each of these loses a row, a reason, a line or a subject from the record an
investigation reads, and each is small enough to fix in an afternoon.

1. **AUD-015, AUD-016 — alert composition.** An empty fact renders as empty *and
   explained*; the Telegram finding line carries the breach date and the
   verification state. *Acceptance:* the two renderings in
   `tests/test_alert_message_layer.py` agree about what missing means, and the
   breach Telegram line names both fields.
2. **AUD-018 — an unauthenticated caller chooses text for a log line.** Bound the
   hint length and strip non-printable and bidirectional characters. *Acceptance:*
   the 5000-character and RTL-override probes from the register return a short,
   printable hint.
3. **AUD-019 — a malformed connector setting answers 500.** Refuse `--5`, `nan` and
   `inf` with a 400 naming the setting, and bound a schemaless string.
   *Acceptance:* `validate_connector_config` returns an error for each of the three,
   and the route answers 400 rather than raising.
4. **AUD-026 — `APP_ENV=test` disables the favicon destination check.** Make the
   seam explicit (`TESTING` alone, with a warning naming what is off) while keeping
   CI's connector job green. *Acceptance:* the connector job's environment still runs
   the suite, and the register's probe prints the resolver being consulted under every
   `APP_ENV` other than the test one.
5. **AUD-030 — the bulk cleanup records a count and no identity.** Capture the ids
   per committed batch and record a bounded sample beside the count. *Acceptance:*
   the route's audit row names at least one deleted finding, a test drives the route
   and reads the row, and the sample is bounded so a ten-thousand-row cleanup cannot
   write a ten-thousand-id row.
6. **AUD-032 — the WHOIS referral hop escapes the egress guard.** Either validate
   each hop through a bounded client of our own, or pin the registry hop and disable
   the referral recursion. *Acceptance:* `tests/test_outbound_guard.py` gains the
   probe the audit ran — a `Whois Server:` line pointing at loopback must be refused,
   and the refusal must be visible as `outbound.blocked`.
7. **AUD-088 — the digest reports its window, not its backlog.** Count the rows still
   held on the pass's own predicate. *Acceptance:* the probe in the register
   (`limit=10` over thirty held incidents) answers `remaining: 20`, and a second pass
   then reaches zero.

### Pass B — a number or a reminder the operator acts on (6 findings)

1. **AUD-020, AUD-021 — quota health and the plugin boundary.** `remaining_today`
   reads the budget `reserve` enforces (the account policy, not the connector's own
   config), and the per-provider cap becomes connector configuration.
   *Acceptance:* the fake-Redis probe in the register reports 350 remaining of 500,
   and a connector that names no provider still gets the cap it declares.
2. **AUD-036 — the certificate control has no port dimension.** `kind` gains the
   port, with a backfill from the observation rows and the existing single-port
   control. This is the pass's largest change: `monitor_kind` in the router, both
   alert passes' labels and the `expiry_kind` vocabulary move with it.
   *Acceptance:* the register's two-port probe keeps two control rows, each with its
   own threshold history, and the backfill is idempotent.
3. **AUD-037 — one sighting per (identity, endpoint, source) hides a second
   subject.** Add the subject to the key or record every subject on the sighting and
   let R3 iterate them. *Acceptance:* the two-CT-subject probe yields two subjects
   and R3 evaluates both.
4. **AUD-038 — `alerted_thresholds` on the observation is always empty.** Drop the
   column, or fill it from the monitor. *Acceptance:* the API's control payload and
   the monitor cannot disagree about what has been reminded.
5. **AUD-041 — a report has no output bound.** A page or byte bound in the renderer,
   or a refusal before publication. *Acceptance:* at the documented maximum the
   renderer refuses (or truncates with a recorded reason) instead of appending
   ~250,000 rows into one in-memory document.

### Pass C — debt with a workaround (5 findings)

1. **AUD-022** — delete `connectors/dns_security/quota.py`, or name it as a
   reference rather than a budget. *Acceptance:* no second copy of the VirusTotal
   limits is left where a reader could tune it.
2. **AUD-033** — wire `score_pending` to a maintenance task or delete it and state
   that a stored score is historical. *Acceptance:* a weight change either repairs
   history or the page says it does not.
3. **AUD-057** — pin a compatible Typer/Click pair and drop AUD-054's per-option
   `flag_value` workaround. *Acceptance:* `python -m scripts.seed_data all --help`
   exits 0 and the boolean flags still arrive as `True`/`False`.
4. **AUD-060** — type the 56 untyped request helpers against the OpenAPI components,
   with a response-shape gate in the `frontend` job. *Acceptance:* the gate fails
   when a field is removed from a response model, and `tsc -b` sees the payloads.
5. **AUD-089** — the ratchet gate's own proof. Drive `main` with `_run_mypy` stubbed
   through all four outcomes: over the baseline (1), the success line (0), a count
   equal to the baseline (0), and output with no summary (2). *Acceptance:* the test
   file fails when any of the three decisions is inverted, which is the same bar
   AUD-084's gate now meets.

## Validation and Acceptance

- [x] Every one of the nineteen register rows is `fixed`, each with the test that was
      red first, and `cd backend && python -m pytest -q
      tests/test_audit_register_gate.py` stays green after every row moves.
- [x] No pass changes a documented guarantee without updating the page that states
      it (`docs/backup-restore.md`, `docs/observability.md`, `docs/security.md`,
      `docs/configuration.md` or the readiness page), and the docs gate is green.
- [x] A new skip introduced by a test that needs a service is inventoried on the
      readiness page in the same change; the skip inventory gate is the check.
      (Pass C added none.)
- [x] The full backend suite and the frontend suite are green at the end of each
      pass, not only the files the pass touched. Re-checked 2026-10-22 (frontend
      whole: 562 passed) and closed on 2026-10-23: the backend suite took 1:29:03 in
      one process for 3,539 passed and 16 skipped, after [plan 014](014-full-run-findings.md)
      repaired the seven failures the first run found — a fixture on the column
      AUD-038 dropped, the `monitor_kind` signature AUD-036 changed, two Celery guards
      that predate AUD-033's core-owned task, and the hand-written report-ceiling
      sentence AUD-041 put inside a generated table.

## Progress and Milestones

| Pass | Findings | State |
|---|---|---|
| A — evidence that is lost or misattributed | AUD-015, 016, 018, 019, 026, 030, 032, 088 | done |
| B — a number or a reminder the operator acts on | AUD-020, 021, 036, 037, 038, 041 | done |
| C — debt with a workaround | AUD-022, 033, 057, 060, 089 | done |

- **2026-10-22 — opened by 009 S28.** The nineteen rows were read together for the
  first time in the synthesis, which grouped them by what a reader loses rather than
  by the module they live in. AUD-088 and AUD-089 were filed at that step, from the
  two threads S27f carried; no step of this plan has run.
- **2026-10-22 — pass A done (8 rows).** Every row has a test that was red before its
  fix — six of them shown red in one run of the new tests alone. What changed, in the
  order the plan listed it:
  - **AUD-015** `fact_text` now separates a fact nobody reported (`None` → `N/A`)
    from one that was reported and carries nothing (`""` → `— (empty)`), the mark the
    table renderer already used.
  - **AUD-016** the compact chat line chooses its details by name
    (`TELEGRAM_DETAIL_FIELDS`) instead of by row order, so a breach line carries the
    incident date and the source's verification statement. Reading the caller was
    worth it: the compact renderer (`telegram_text`) has no production caller — the
    live channel sends `telegram_parts`, which prints every field — so the audit
    measured a second renderer that a future caller would have wired. It is correct
    now, and the row says so rather than claiming the live alert was lossy.
  - **AUD-018** the rejected-token hint is filtered to the alphabet a connector name
    is made of and cut to 40 characters, so an unauthenticated caller can no longer
    choose 5 000 characters of log line, a bidirectional override or an ANSI escape.
  - **AUD-019** `--5` is refused as an integer, `nan`/`inf` as a number, and a
    schemaless connector's string is bounded at 2 000 characters: three shapes that
    answered 500 or wrote invalid JSON are now a 400 naming the setting.
  - **AUD-026** the favicon fetch's seam is `TESTING` alone and it warns when in
    force; `APP_ENV=test` no longer removes the destination check, and the test
    asserts the resolver is consulted under that value.
  - **AUD-030** `_delete_orphans` returns `OrphanCleanup(deleted, sample)` and both
    cleanup routes put a bounded sample of ids in the audit row; the service's six
    call sites and their tests moved with it.
  - **AUD-032** the WHOIS lookup no longer calls the library's client: `lookup()`
    drives `GuardedNICClient`, which passes every hop — the registry and the
    `Whois Server:` referral it answers with — through `ensure_allowed` before a
    socket exists, and bounds the read at 256 KiB. A referral to loopback now raises
    `OutboundBlocked`, which the enrichment already answers with `refused` and an
    `outbound.blocked` line. The three tests that stubbed `whois.whois` now stub the
    service's own `lookup`, which is the seam that exists.
  - **AUD-088** the digest counts the rows still held after its commit instead of
    subtracting from the window it fetched: thirty held incidents delivered by three
    `limit=10` passes report 20, 10, 0.
  Two follow-ups the pass created and did not take, both already in the register's
  shape: the compact renderer is still dead code (a deletion with its tests is S4
  work, and `alert_message.py`'s 97% gate makes the deletions + tests one change),
  and `scripts/check_mypy_baseline.py` is still AUD-089 in pass C.
  *Verified:* the collections the change reaches (alert layer, content and delivery
  paths; connector credentials, manifest and schema; asset matching; whois
  enrichment; outbound guard; breach digest and breaches/phishing integration;
  connector runtime) — every one green, in seven runs of 27 to 112 tests; the
  connector tree 151 passed;
  `ruff check` clean on the touched files; `check_mypy_baseline.py` 0 errors; and the
  eight gates (register, map, docs consistency, docs numbers, skip inventory,
  critical coverage, GitHub claims) 100 passed. The full backend suite was not run in
  one process: it takes over an hour on this host.
- **2026-10-22 — pass B done (6 rows).** Same rule, same order:
  - **AUD-020** `remaining_today` takes the session and reads the budget the way
    `reserve` reads it — the account's approved policy layered over the connector's
    config — so the health page cannot print "0 left of 100" beside a scan admitted
    to 500. The router and the four unit tests moved with the signature.
  - **AUD-021** the provider name is gone from `provider_quota.py`. A connector
    declares `requests_per_minute_ceiling` and `certificate_requests_per_minute` in
    its own config, both validated in documented ranges; the certificate bucket is
    gated by the declared operation, charged its declared cap (default 3), and the
    three netlas seeds carry their former 60/3 limits as config so an installation
    built from this baseline keeps them.
  - **AUD-036** the expired certificate control is keyed `tls:<port>`, read from the
    probe's `metadata.port` and then its `TLS:<port>` record type. A legacy
    `kind="tls"` row is renamed in place by the first probe, keeping its threshold
    history; the inventory resolves the legacy kind until that happens. The backfill
    is a lazy rename rather than a data migration because this repository ships one
    baseline revision and no revision can run against a database already at `0001` —
    a migration would be a file no installation executes. It is idempotent and has
    its own test.
  - **AUD-037** the hostnames a certificate was reported for are accumulated in
    `signals.subjects`, exposed by the triage payload, and R3 evaluates each with its
    own baseline and its own event. The (certificate, address, port, source) key is
    unchanged, so the evidence stays one sighting; the pass B item allowed this
    shape instead of adding the subject to the key.
  - **AUD-038** the observation's `alerted_thresholds` column is gone from the model,
    the baseline, the reference schema and both upsert branches, and the inventory
    payload answers the field from the control that sends the reminder. There is one
    history, and the API cannot disagree with it.
  - **AUD-041** `ensure_renderable` refuses a document over 25,000 rows (five
    sections at the default `REPORT_MAX_ROWS`) before an FPDF object exists, and
    `enforce_output_bound` removes a written file over 64 MiB instead of publishing
    it. `generate_and_save` checks the row ceiling before it takes an executor slot.
  Method note, because the rule is "red first": the eight quota tests and the three
  render tests were run red before their code; AUD-036's two tests were shown red
  against the old single kind (`assert [('tls', 'cert-a', [30])] ==
  [('tls:8443', 'cert-a', [30])]`); AUD-037 and AUD-038 were written with the change
  in the same pass, and their reproduction is the register's Evidence cell (the
  two-subject projection probe and the always-empty column), not a second red run.
  One follow-up created and not taken: the triage payload now carries `subjects`, but
  the SPA still prints the single `subject` column — showing the rest is a UI change
  with its own test, and the rules already act on every name.
  *Verified:* the DNS/TLS collections (`dns_expiry_service`, `dns_security`,
  `dns_security_api`, `tls_identities`, `dns_tls_probe`, `dns_stale_monitor_alerts`)
  78 passed; the schema drift, schema-reference and Alembic suites 32 passed, 1
  skipped (the PostgreSQL-only case); the quota, connector and report collections 104
  passed; `test_assets_integration` 37 passed after its observation fixtures lost the
  dropped column; the seven documentation and register gates 100 passed;
  `scripts/check_docs_consistency.py` OK over 86 documents; `ruff check` clean on
  every touched file; the frontend suite whole (561 passed, 56 files) with
  `tsc -b` clean. The full backend suite was not run in one process here either.
- **2026-10-22 — pass C done (5 rows), and plan 011 with it.** Same rule, same order:
  - **AUD-022** `connectors/dns_security/quota.py` is deleted. It was a Redis guard
    nothing imported, carrying a second copy of the VirusTotal public tier
    (4/minute, 500/day); a reader could tune it and believe the budget had moved.
    The test asserts the file is absent **and** that no connector source names the
    `quota:virustotal` keyspace, so a restore of the file fails the suite.
  - **AUD-033** `score_pending` has a caller: `rescore_phishing_candidates` in the
    new `app/tasks/phishing_tasks.py`, scheduled daily at 04:45 UTC on the default
    queue, late-acknowledged because a repeat writes the same numbers, and wired
    into `beat_schedule`, `task_routes` and the Celery include list. The task
    reports `candidates_moved`, which is the one number a weight change produces.
    Deleting `score_pending` was the alternative the row allowed; it was refused
    because it would leave no repair path for history at all.
  - **AUD-057** `click` moves from 8.5.0 to 8.1.8, the version `typer==0.12.5` is
    compatible with, and `backend/requirements.txt` is regenerated by its own
    generator (which also corrected the stale header path AUD-086 had left in the
    file). With the pair compatible, Click fills `flag_value` from the default, so
    the per-option `flag_value=True` workaround is gone and `all --help` exits 0.
  - **AUD-060** all 101 request helpers name their response type; the 56 that read
    `any` now carry the interface their pages consume, with fourteen declarations
    added to `types/api.ts` (twelve payload shapes, the exposure page, and the
    `QueryParams` alias) and five `params: any` replaced. The gate is
    `backend/scripts/check_api_types.py`: rule one fails a helper with no generic,
    rule two compares each schema-backed interface with its OpenAPI model and
    fails a field the SPA reads and the model no longer sends. It runs in the
    **backend** job after the mypy ratchet rather than in `frontend`, because the
    OpenAPI document is built by importing the application; `tsc -b` in the
    `frontend` job checks the pages against the same declarations, and the two
    halves meet at `types/api.ts`. `make check-api-types` runs it locally.
    The comparison immediately found a field the SPA declared and the API never
    sent — `Job.updated_at` — which is removed with its fixture line.
  - **AUD-089** `tests/test_mypy_baseline_gate.py` drives `main` through all four
    outcomes (over baseline 1, success 0, equal 0, no summary 2) and pins that the
    gate forwards its arguments; `_run_mypy` now answers a missing interpreter with
    the gate's own exit 2 instead of raising `FileNotFoundError` out of the process.
  Method note, because the rule is "red first": the quota test was shown red
  against the file (`assert not True`), the missing-mypy test against the unhandled
  exception, and the seed `--help` test against the installed pair (exit 1,
  `TypeError: Parameter.make_metavar() missing 1 required positional argument:
  'ctx'`). The gate for AUD-060 is the deliverable itself, so its eight tests were
  written with it; the two rules were then exercised against fixtures, and the
  shipped-tree test is what proves the eight pairs agree today.
  *Verified:* the new and adjacent collections — `test_mypy_baseline_gate`,
  `test_connector_runtime::TestTheQuotaBudgetHasOneHome`, `test_phishing_rescore`,
  `test_phishing_scoring`, `test_seed_scripts`, `test_api_types_gate` — 168 passed
  across the runs; `scripts/check_api_types.py` OK over 101 helpers and 8 pairs;
  `tsc -b` clean and the frontend suite whole (561 passed, 56 files); the gates over
  the Makefile, environment template and documentation numbers 65 passed; the
  documentation consistency script over 86 pages; `ruff check` clean. The full
  backend suite was run in four shards rather than in one process, and the shard
  that holds `test_intelligence_credential.py` needs `connectors/base` on
  `PYTHONPATH` — the single-process run passes only because an earlier module puts
  it there, which is a fragility worth a test rather than a finding (nothing in the
  product changes).
