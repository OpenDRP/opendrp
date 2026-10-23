# Batch 03 — The connector boundary

**State:** done — all three modules above 92%, floors raised, closing run green

**Scope:** what an untrusted connector may declare, what the core does with a
declaration, and the schema that refuses it. This is the boundary the platform's
architecture rests on: the core must not depend on a particular connector.

**Baseline:** the `backend` job of the CI run on `main` (2026-10-19): `app/` at
90.65%, 1 337 statements missed.

| Module | Statements | Missed | Covered |
|---|---|---|---|
| `app/services/connector_service.py` | 501 | 73 | 85.4% |
| `app/services/connector_manifest.py` | 318 | 43 | 86.5% |
| `app/schemas/connector.py` | 323 | 34 | 89.5% |

**Measured misses**

- `connector_service.py`: 72, 100, 173, 203, 232, 235, 268, 271, 273-278, 316,
  318, 324, 340-370, 401-406, 418, 420, 475-482, 508-514, 568, 585, 730, 735,
  740, 783, 851-857, 884, 905, 917, 922-923, 929, 931-937, 973, 1136
- `connector_manifest.py`: 209, 218, 238, 266-267, 281, 283, 301, 303, 310, 312,
  316-317, 321, 331, 333, 352, 364, 371, 405, 486, 599, 603, 605, 607, 609-624,
  637, 643
- `schemas/connector.py`: 57, 59-61, 66, 80, 85, 95, 105, 112, 136, 146, 149,
  153, 175, 182, 195, 230, 238, 246-247, 271, 279, 287, 358, 366, 372, 377-379,
  384, 440, 452, 460

**First move**

```bash
cd backend
COVERAGE_CORE=sysmon python -m pytest -q --cov=app.services.connector_service --cov=app.services.connector_manifest --cov=app.schemas.connector --cov-report=term-missing --cov-report=json:/tmp/batch03.json
```

**Work items**

- [x] Registration refusals: a manifest that names an unknown module, an unknown
      job type, a duplicate connector name or a capability the core does not
      declare is refused with a message that names the offending field.
- [x] Identity: a connector may act only within its own credential and its own
      jobs; a job id belonging to another connector is not found, not forbidden.
- [x] Readiness: the state a connector reports after a refused registration, a
      revoked credential and a manifest that arrives twice.
- [x] Job orchestration: the branches that decide "already claimed", "lease lost"
      and "terminal" — the same facts the job lifecycle pins, seen from the
      connector side.

**Done when**

- all three modules are at or above 92%, with floors added for the two that do not
  have one and raised for the rest;
- the connector protocol, runtime and manifest suites plus the full backend suite
  are green;
- the batch file lists the refusals that are untestable without a connector
  container, if any.

**Progress log**

| Date | Change | Measured |
|---|---|---|
| 2026-10-19 | batch written from the CI baseline | 85.4%, 86.5%, 89.5% |
| 2026-10-19 | edge suites added: `test_connector_service_edges.py` (14), `test_connector_manifest_edges.py` (24), `test_connector_schema_edges.py` (24); measured on the connector suites with `--cov=app` (316 passed) | service 85.8% (71 missed), manifest 97.2% (9 missed), schemas 94.1% (19 missed) |
| 2026-10-19 | floors ratcheted: manifest 70→94, service 70→82, schemas new at 91 | gate in `check_critical_coverage.py` |
| 2026-10-19 | admission edges: `test_connector_scan_admission_edges.py` (9) — source-account mismatch, unready credentials, unapproved account, capability refusals, a usable host and breach asset, the catalogue window, and scheduled-slot replay; connector suites (325 passed, `--cov=app`) | service 92.0% (40 missed), manifest 97.2%, schemas 94.1% |
| 2026-10-19 | service floor ratcheted 82→89 | gate and readiness page |
| 2026-10-19 | first closing run: full backend suite with `--cov=app` | 3087 passed, 14 skipped, 2 failures in doc gates — fixed below |
| 2026-10-19 | fixed the two doc-gate failures the closing run found: `docs/upgrading.md` still said 0.2.0, and the batch commands plus `coverage_gaps.py` used backslash continuations; both gates re-run | 45 passed |
| 2026-10-19 | critical-coverage gate on the full report; version gate; mypy baseline | all OK — 0 mypy errors, 0.2.1 in 7 places |
| 2026-10-20 | closing run after the doc fixes: full backend suite with `--cov=app` | **3 089 passed, 14 skipped**, critical-coverage gate OK, `app/` at 93% (1 041 missed) |

**Untestable without a connector container:** the worker-side half of a refused
registration (the connector's own retry state after the core answers 4xx) and the
readiness a live process reports after its credential is revoked. The core's
answers for both are pinned here; the container's reaction belongs to the
connector SDK suite.

**Measurement caveat:** `--cov=app.schemas.connector` on its own triggers a
bcrypt double-import error under this Windows interpreter; `--cov=app` works and
was used for the numbers above.
