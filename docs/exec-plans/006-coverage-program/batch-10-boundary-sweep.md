# Batch 10 — The thin sweep: security boundaries

**State:** done — 70 of 73 planned statements executed, five floors new and two raised, closing run green

**Scope:** the modules batches 01–09 left with fewer than fifteen missed
statements each, taken in the order their miss could cost something rather than in
the order the gap is largest. Nine batches closed 808 of the 970 statements they
were planned from; `app/` now sits at 96.30% (529 missed) and what remains is a
long tail. A tail is not automatically worth sweeping, so this batch takes only
the ranges that name a **refusal or a boundary**: an address the platform declines
to connect to, a stored value it declines to serve, a credential it declines to
store, a refusal it still records, a module it declines to keep queued.

**Baseline** (full backend run on 2026-10-20, `coverage.json`, `app/` 96.30%):

| Module | Statements | Missed | Covered |
|---|---|---|---|
| `app/core/outbound.py` | 172 | 10 | 94.2% |
| `app/core/artifact_path.py` | 63 | 9 | 85.7% |
| `app/core/authorization_audit.py` | 47 | 8 | 83.0% |
| `app/services/source_accounts.py` | 68 | 10 | 85.3% |
| `app/services/module_registry.py` | 111 | 14 | 87.4% |
| `app/api/v1/routers/source_inventory.py` | 100 | 13 | 87.0% |
| `app/api/v1/routers/jobs.py` | 51 | 9 | 82.4% |

73 statements in seven modules, each of which already has a suite — so the work
is adding the branch to the suite that owns the behaviour, not opening a new file
per test.

**Work items**

- [x] `outbound`: a malformed `OUTBOUND_ALLOWED_HOSTS` entry is skipped rather
      than fatal or permissive; an IP literal is still classified when resolution
      returns nothing; the pinned SMTP socket closes the raw socket when the
      implicit-TLS handshake fails and tries the next validated address; a
      hostname longer than 253 characters is refused.
- [x] `artifact_path`: the 255-character bound, `.`/`..`, and a POSIX
      `C:report.pdf` (colon without a separator) are refused as "not a name"; a
      resolution that lands outside the store and one that fails are told apart
      from "the file is gone".
- [x] `authorization_audit`: the dedup window through Redis (first refusal
      recorded, second suppressed), a Redis error falling back to the in-process
      map and dropping the cached client, the map's 1024-entry bound and its
      window purge, and the account a refusal was about.
- [x] `source_accounts`: every refusal names the field — invalid identity,
      credential reference that is not an environment variable, unknown account,
      unsupported policy field, non-boolean `approved`, missing budgets, a budget
      the policy validator rejects, and an API key with characters that could
      never authenticate — plus the binding rule that a connector only receives
      its own provider's key.
- [x] `module_registry`: a label outside 1–120 characters on create and update,
      unknown module on toggle and on metadata update, a description truncated at
      2000 characters and an empty one stored as `null`, a finding kind owned by a
      differently-named row, and that disabling a module — behaviour 0.2.0 shipped
      without a test — **cancels its pending jobs** with a reason instead of
      leaving provider work queued. The batch pins that rule; it does not add it.
- [x] `source_inventory`: a scan with no ready source answers `409` rather than
      `202` with no jobs; an unknown or non-exposure observation is `404` on triage
      and on promotion; an IP subject is promoted as `ip_address`, an unpromotable
      subject is `409`, and a concurrent duplicate promotion answers
      `already_exists` instead of `500` (or, with no winner, the refusal); the
      evidence allowlist drops a nested shape rather than publishing it.
- [x] `jobs`: another account's job answers `404` (not `403`, which would confirm
      it exists), an unknown id is `404`, a job with no creator is readable by an
      analyst and reported with no email, and a relationship that cannot load does
      not turn the view into a 500.

**Plan of Work**

| File | Change |
|---|---|
| `backend/tests/test_outbound_guard.py` | four tests on the allowlist, the literal fallback and the pinned socket |
| `backend/tests/test_artifact_path.py` | three naming refusals in the existing parametrisations |
| `backend/tests/test_authorization_denials.py` | three tests with a fake Redis client and the local-map bound |
| `backend/tests/test_source_accounts_api.py` | one test walking every service refusal |
| `backend/tests/test_module_registry.py` | two tests: label/metadata bounds, and disabling cancels queued work |
| `backend/tests/test_source_inventory_api.py` | three tests: the 409, the promotion refusals, the evidence allowlist |
| `backend/tests/test_job_service_lifecycle.py` | one test class for `GET /jobs/{id}`: ownership, unknown id, system job |
| `docs/exec-plans/006-coverage-program/README.md`, `docs/exec-plans/README.md`, `CHANGELOG.md` | the batch's numbers and the floors it raises |
| `backend/scripts/check_critical_coverage.py`, `docs/production-readiness.md` | new floors for the modules this batch holds |

**What executed**

- `test_outbound_guard.py` — a malformed allowlist entry is skipped while the
  valid one beside it still works; an IP literal is classified when the resolver
  answers nothing; the pinned socket closes the raw connection when the TLS
  handshake fails; the second validated address is tried after a connect failure
  and the last real error is reported when none connects; a 254-character host is
  refused while 253 is accepted. The socket cases use a stand-in for
  `socket.create_connection`, because the branch is about what the platform does
  *after* the OS refuses — the connection itself is not the behaviour under test.
- `test_artifact_path.py` — drive-relative and dot names join the existing
  refusal table; the 255/256-character boundary is asserted from both sides; a
  resolution outside the store and one that raises are distinguished from
  "missing". The two resolution cases simulate what `realpath` returns (the
  Windows runner cannot create a symlink), while the Linux run reaches the same
  branch with a real link.
- `test_authorization_denials.py` — the window lives in Redis when the broker
  answers, and one row is written for four refusals; a broker error falls back to
  the process map and drops the cached client; the map is bounded at 1024 claims
  and purges an expired one; a refusal on a named account records `target_id`.
- `test_source_accounts_api.py` — the whole refusal table of the account service
  plus `api_key_for_connector`: unbound, wrong provider, cleared key and a row
  that no longer exists all answer "no credential here" rather than handing over
  another service's key.
- `test_module_registry.py` — label bounds on create and update, metadata update
  clipped and committed, unknown module on toggle and on metadata, a finding kind
  owned by a differently-named legacy row, and disabling a module cancelling its
  pending jobs while leaving finished work alone.
- `test_source_inventory_api.py` — `409` when a scan has no ready source, `404`
  for an unknown or foreign observation on both routes, an address promoted as
  `ip_address`, an unpromotable subject refused, the race-lost duplicate answered
  with the winner, the race-lost-with-no-winner re-raised, and the evidence
  allowlist dropping non-scalar shapes.
- `test_job_service_lifecycle.py` — `GET /jobs/{id}`: admin reads any job and the
  read is audited, another account's job is a `404` while the row still exists, a
  system job is readable with no email, an unknown id is a `404`, and a
  relationship that cannot load leaves the email empty instead of failing.

**Concrete steps**

1. Add the tests to the suites above, one module at a time.
2. Run each suite plus a targeted coverage measurement
   (`pytest tests/test_x.py --cov=app.<module> --cov-report=term-missing`) and
   confirm the named lines flip to covered.
3. Prove one test per module can fail by reverting the behaviour in memory (a
   temporary edit) and watching it fail, then restoring it.
4. Ratchet a floor for the modules now above 95% — never lower one, and only
   where the module is a boundary rather than a formatter.
5. Close with the targeted suites, then the full backend suite, then the gates
   the repository runs (`docs`, per-module coverage, mypy, version).

**Measured**

Per module, on the suite that owns it; the closing figure is the full run.

| Module | Before | After | Floor |
|---|---|---|---|
| `app/core/outbound.py` | 94.2 | **100.0** | 97 (new) |
| `app/core/artifact_path.py` | 85.7 | **95.2** | 92 (new) |
| `app/core/authorization_audit.py` | 83.0 | **100.0** | 97 (new) |
| `app/services/source_accounts.py` | 85.3 | **100.0** | 97 (raised from 80) |
| `app/services/module_registry.py` | 87.4 | **100.0** | 97 (raised from 70) |
| `app/api/v1/routers/source_inventory.py` | 87.0 | **100.0** | 97 (new) |
| `app/api/v1/routers/jobs.py` | 82.4 | **100.0** | 97 (new) |

Full closing run (2026-10-20): **3 354 passed, 16 skipped**, critical-coverage gate
OK with the new floors, mypy at 0 errors, version gate at 0.2.1. `app/` moved
from 96.30% (529 missed) to **96.79% (459 missed)**.

**Validation and acceptance**

- [x] every module named above is at or above 95% statements;
- [x] `python scripts/check_critical_coverage.py --cov-args` still names every
      gated module, and the gate passes against the closing report;
- [x] the full backend suite passes (3 354 passed, 16 skipped) and the version
      gate still reads 0.2.1;
- [x] the lines deliberately left uncovered are listed below with the reason.

**What is still uncovered here, and what is left for later**

- `app/core/artifact_path.py`, 3 lines: `95` is the absolute-path refusal, which
  the separator and colon checks above it make unreachable on every platform this
  runs on (POSIX absolutes contain `/`, Windows absolutes contain `:` or `\`);
  `168-169` is the exception arm of the containment test, which `classify_artifact`
  only reaches if `Path.resolve()` raises after `realpath` already succeeded. Both
  are defensive; neither is mocked into existence.
- The rest of the tail is not claimed as covered by this batch. The next candidates
  by evidence are `app/core/metrics.py` (13), `app/services/ingestion_events.py`
  (11), `app/api/v1/routers/reports.py` (11), `app/api/v1/routers/breaches.py`
  (11), `app/api/v1/routers/audit.py` (10), `app/services/dns_expiry_monitor_service.py`
  (10) and `app/core/audit_chain.py` (9) — plus the seven modules above fifteen
  that batches 03–08 already named in their own files. Each needs its own reading
  before a test can be written at the behaviour it owns.

**Progress log**

| Date | Change | Measured |
|---|---|---|
| 2026-10-20 | batch opened from the full-run report; seven modules, 73 missed statements | outbound 94.2, artifact 85.7, authz 83.0, accounts 85.3, registry 87.4, inventory 87.0, jobs 82.4 |
| 2026-10-20 | tests added to the seven owning suites; four behaviours reverted one at a time to watch their tests fail, then restored | modules at 100% except artifact 95.2 |
| 2026-10-20 | floors added/raised in `check_critical_coverage.py` and the readiness table; full suite run | `app/` 96.79% (459 missed) |
