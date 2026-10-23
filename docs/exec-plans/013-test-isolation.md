# Plan 013 — a test module that only collects when somebody else ran first

**State:** done — 2026-10-22

## Goal

Plan 011 closed with a note it filed as a thread rather than a finding: while the
full suite was run in shards, the shard holding `tests/test_intelligence_credential.py`
needed `connectors/base` on `PYTHONPATH`. A single-process run passed only because an
earlier module had already put it there. That is a test that proves something about
the *order* of the suite, not about the code.

The mechanism: the module loads `connectors/intelligence/providers.py` by path, and
that file imports the shared SDK by its installed name (`opendrp_connector`). Every
sibling in `backend/tests/` that does the same inserts `connectors/base` into
`sys.path` first; this one never had to, because it always ran behind one of them.
Collected alone it fails at import, with `ModuleNotFoundError: No module named
'opendrp_connector'` — verified, not inferred.

The thread said "a fragility worth a test rather than a finding (nothing in the
product changes)". This plan delivers both halves of that: the module becomes
self-sufficient, and a gate fails when a new module joins it in depending on a
neighbour's import side effects.

## Plan of Work

| File | Change |
|---|---|
| `backend/tests/test_intelligence_credential.py` | resolve `connectors/` once, insert `connectors/base` into `sys.path` before executing the provider file, with the reason written beside it |
| `backend/tests/test_connector_test_isolation.py` | new gate: find every test module that executes a connector file by path, collect each in a fresh interpreter, fail with the child's own import error |
| `docs/production-readiness.md` | one row in "What is enforced, and by which gate" |
| `docs/exec-plans/README.md` | one row for this plan |

## Concrete Steps

1. **Make the module self-sufficient.** The file follows the sibling convention
   already used by `test_intelligence_worker.py`, `test_dnstwist_cli_version.py` and
   `test_exposure_endpoints_connector.py`: one `_ROOT` covering the container path
   (`/connectors`) and the checkout path, then the SDK directory on `sys.path` when
   it is not there. *Acceptance:* `pytest -q tests/test_intelligence_credential.py`
   collects and passes with nothing imported before it.
2. **Gate the class.** The detection has to be by *what the module does*, not by a
   string in it: the SDK's name appears in the loaded file, never in the test module,
   so a `grep` for `opendrp_connector` would have missed the very file that broke.
   The gate parses each test module, follows module-level path assignments
   (`_PATH = Path("/connectors/…")`, its `__file__` fallback, and `_PATH = _ROOT /
   "…"` built from either) and treats a `spec_from_file_location` call whose target
   resolves under `connectors/` as connector code. Each such module is collected in
   a child `pytest --collect-only`, so the child has no inherited `sys.path`.
   *Acceptance:* the gate fails against the unfixed module with the child's
   `ModuleNotFoundError`, passes after the fix, and a guard test fails if the
   detection stops finding any module at all — a gate that checks nothing is a gate
   that is always green.

## Validation and Acceptance

- [x] The gate is red against `HEAD`'s version of the module (`ModuleNotFoundError:
      No module named 'opendrp_connector'` in the child's own output) and green with
      the fix.
- [x] `tests/test_intelligence_credential.py` passes when run alone (2.5 s on this
      host) and the gate itself runs in ~7 s, so it belongs to the normal suite.
- [x] The full backend suite is green over every test file. **Shards were abandoned**
      first: four concurrent `pytest` processes on this host shared one SQLite-backed
      fixture setup and ran at roughly a quarter of a single process each — about 40
      tests per shard in twelve minutes — so that attempt was stopped. One process
      finished in 1:27:49 with 7 failures that were fallout of plan 011's own fixes;
      [plan 014](014-full-run-findings.md) repaired them, and the next run was
      3,539 passed, 16 skipped, none failed in 1:29:03.
- [x] The frontend suite and `tsc -b` after plan 012's component change: 562 passed
      in 46 s on two of three whole runs, `tsc -b` clean. The first run failed one
      test while four backend shards were still being killed; the same suite passed
      twice afterwards, and the failure was not reproduced or diagnosed — it is
      recorded as a flake under load, not as a pass.

## Progress and Milestones

- **2026-10-22 — opened and closed.** The defect reproduced as described
  (`ModuleNotFoundError` at `providers.py:11`), the fix is the sibling convention,
  and the gate was shown red against `HEAD`'s file and green after it. The gate
  found one module: the one that broke. The detection is AST-based because the
  string marker missed it — the first version keyed on `opendrp_connector` and
  quietly checked nothing, which the guard test now prevents. Two detection
  refinements were needed even so: a path built from `_ROOT / "intelligence" /
  "providers.py"` was not followed until assignments were closed transitively, and
  the fixed module writes `Path("/connectors")` without a trailing slash.
  *Verified:* the gate and the module together 3 passed (7 s); `ruff check` clean on
  both files; the frontend suite whole as recorded in the checklist; `tsc -b` clean.
  The full backend suite closed the next day in one process (3,539 passed after
  [plan 014](014-full-run-findings.md) repaired what the first complete run found),
  which is the run this plan's checklist records.
