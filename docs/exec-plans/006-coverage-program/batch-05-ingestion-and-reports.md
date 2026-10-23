# Batch 05 — Ingestion and reports

**State:** done — ingestion 97.0%, report 92.3%; floors 93/89; closing run green
(2026-10-20: 3 161 passed, 14 skipped)

**Scope:** the write path a connector's findings arrive through, and the snapshot a
report is built from. A bug in the first attributes a finding to the wrong asset; a
bug in the second prints a number that disagrees with the dashboard.

**Baseline:** the `backend` job of the CI run on `main` (2026-10-19): `app/` at
90.65%, 1 337 statements missed.

| Module | Statements | Missed | Covered |
|---|---|---|---|
| `app/services/ingestion_service.py` | 432 | 55 | 87.3% |
| `app/services/report_service.py` | 453 | 61 | 86.5% |

**Measured misses**

- `ingestion_service.py`: 46-48, 52-53, 68-73, 86, 430, 539, 550-551, 828,
  888-892, 907, 925-941, 996-1040, 1069-1072, 1166-1168, 1182, 1184, 1187, 1206,
  1210
- `report_service.py`: 21, 38, 64-76, 105-106, 144, 152, 276-278, 287, 301,
  486-494, 496, 522-530, 562-570, 572, 661-663, 684-685, 689, 710-711, 716-717,
  731, 735-740

**First move**

```bash
cd backend
COVERAGE_CORE=sysmon python -m pytest -q --cov=app.services.ingestion_service --cov=app.services.report_service --cov-report=term-missing --cov-report=json:/tmp/batch05.json
```

**Work items**

- [x] The same finding submitted twice is one row, and the second submission
      reports `unchanged` rather than `updated`.
- [x] A finding whose asset cannot be matched is stored with no asset and is not
      silently dropped; the summary says how many were unmatched.
- [x] A submission that fails half-way leaves no partial batch: the savepoint
      boundaries are exercised with a failing row in the middle.
- [x] Report sections: a section with nothing to include, a section that hits its
      bound, and the `included`/`total`/`truncated` numbers that say which.
- [x] A report generated while a scan is running reads one consistent snapshot
      rather than two.

**Done when**

- both modules are at or above 92%, with floors raised to measured-minus-three;
- the ingestion, outbox and report suites plus the full backend suite are green;
- the batch file names the ranges that need a PostgreSQL-only path, if any.

**Progress log**

| Date | Change | Measured |
|---|---|---|
| 2026-10-19 | batch written from the CI baseline | 87.3%, 86.5% |
| 2026-10-20 | re-measured on the 25 suites that reference these modules (482 passed) — reproduces the baseline exactly | ingestion 87.27% (55 missed), report 86.53% (61) |
| 2026-10-20 | `test_ingestion_service_gaps.py` (11): JSON/date helpers, `_direct` refusals (no connector, unknown job, foreign spec), an RDAP arrival with no subject, a DNS batch entry that is not an observation, the per-observation path create→unchanged, and the uniqueness race that falls back to one observation at a time | these branches had no test before; the total after both ingestion additions is 97.0% |
| 2026-10-20 | `test_ingestion_service_edges.py`: an exposure finding whose scan parameters hold a value the canonicalizer refuses is still stored, because the junk value contributes nothing to the membership test | ingestion **97.0%** (13 missed) |
| 2026-10-20 | `test_report_service_gaps.py` (11): KPI caption fallback, the PDF text values each section contributes, a non-positive row limit, a 120-row report (cover + four sections, Exposure and DNS rows), a nearly empty report, collection that overruns its time limit, a renderer failure with and without a failing cleanup, a late render whose cleanup fails, and the small-file warning | report 86.5% → **92.3%** (35 missed) |
| 2026-10-20 | floors: ingestion 70→93, report new at 89 | gate and readiness page |
| 2026-10-20 | closing run: full backend suite with `--cov=app` | **3 161 passed, 14 skipped**, critical-coverage gate OK; `app/` 94%, 864 missed (−69) |

**Proven to fail:** dropping `allow_nan=False` from `_json_safe` makes
`test_json_safe_refuses_a_value_it_cannot_carry` fail with `DID NOT RAISE`; the
mutation was then reverted.

**Ranges that cannot be reached here**

- `report_service.py:152` — `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ` is
  PostgreSQL-only; SQLite takes the explicit `BEGIN` branch. Covered by the
  integration suite on PostgreSQL, not by this unit run.
- `report_service.py:486-494, 522-530, 562-570` — the explicit "start another
  page" blocks are shadowed by `set_auto_page_break(auto=True, margin=25)`: FPDF
  breaks inside `ln()` before the next iteration can see `get_y() > 270`. A
  120-row report still takes the automatic break. Removing the duplicate would be
  a code change, not a test.
- `report_service.py:105-106` — a string that fails `latin-1` after passing the
  `[^\x00-\xff]` guard would have to contain a lone surrogate, which the guard
  already rejects.
- `report_service.py:301` — the bold-font fallback depends on which fonts the
  machine has (DejaVu without its bold face, with `arialbd.ttf` beside it).
- `report_service.py:689` — `remaining_timeout <= 0` between collection and
  rendering needs the clock to advance exactly at the boundary.
- `report_service.py:710-711, 731` — a cancelled executor future and a render
  finishing in the same loop turn as its timeout; both need the event loop's
  internals, not the service's contract.
