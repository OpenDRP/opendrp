# Batch 06 — TLS and DNS surface

**State:** done

**Scope:** the certificate review workflow and the routes the DNS Security page
reads: which sightings are grouped, which are suppressed by scope, and what the
page is told when a provider did not answer.

**Baseline:** the `backend` job of the CI run on `main` (2026-10-19): `app/` at
90.65%, 1 337 statements missed.

| Module | Statements | Missed | Covered |
|---|---|---|---|
| `app/services/tls_identity_service.py` | 389 | 57 | 85.3% |
| `app/api/v1/routers/dns_security.py` | 228 | 53 | 76.8% |

**Measured misses**

- `tls_identity_service.py`: 132, 157, 164, 188, 193-194, 202, 224, 267, 380,
  383-384, 413-424, 468, 530, 540, 615, 621-622, 656, 659, 673, 678-679, 740-749,
  770, 780, 800-812, 830, 833-834, 840, 842, 844, 855-858, 872-880
- `dns_security.py`: 49-52, 62, 137-138, 150, 154, 178, 181, 205, 230, 249-250,
  279-285, 318-322, 339-346, 356-360, 371-381, 391-400

**First move**

```bash
cd backend
COVERAGE_CORE=sysmon python -m pytest -q --cov=app.services.tls_identity_service --cov=app.api.v1.routers.dns_security --cov-report=term-missing --cov-report=json:/tmp/batch06.json
```

**Work items**

- [x] Verdicts survive a sweep: an `expected`, `rejected` and
      `shared_infrastructure` sighting is not re-alerted by the next pass.
      `test_an_address_we_own_is_not_foreign_and_a_reviewed_sighting_stays_quiet`
      re-sweeps after `expected`; `test_a_verdict_outlives_the_alert_and_an_unknown_verdict_is_refused`
      re-sweeps after `rejected` and checks the triage view still shows the note;
      `test_a_scope_exception_and_shared_infrastructure_suppress_the_rule` leaves
      the CDN verdicts in place across a second pass.
- [x] Scope exceptions: an expired exception stops applying on its own, and one
      that names an issuer applies to that issuer's certificates only.
      `test_an_expired_exception_stops_applying_on_its_own` (lapse, renewal in
      place, re-alert on a new address) and
      `test_an_issuer_exception_applies_only_to_that_issuers_certificates`.
- [x] Grouping: several sources confirming one foreign address produce one alert;
      one certificate served from many addresses is recorded as shared
      infrastructure rather than alerted.
      `test_a_foreign_deployment_alerts_once_with_the_address_and_the_signals`
      (two providers, one message, confidence in the payload) and the CDN half of
      `test_a_scope_exception_and_shared_infrastructure_suppress_the_rule`.
- [x] Routes: an empty DNS page, a provider that did not answer, and a monitor
      that expired — each answers with a state rather than an empty list.
      `test_scan_rejects_offline_workers_without_creating_jobs` (409 with the
      sources and no `Job` rows), `test_scan_queues_online_source_and_reports_offline_source`
      (`offline_connectors` next to a queued job), and the expiry monitor payloads
      in `test_expiry_api_reports_control_and_deletion_invalidates_it` plus the
      stale-monitor suite. The empty list is the paginated envelope with
      `total: 0`, not an error, which the route tests read through
      `test_certificate_exceptions_are_admin_decisions_that_say_why`.

**Rules covered at sweep level vs. only by their own unit tests**

All four rules (R1 foreign deployment, R2 key reuse, R3 unexpected issuance,
R4 stack echo) have a sweep-level test in `tests/test_tls_identities.py`, and
`tests/test_tls_identity_service_gaps.py` adds sweep-level tests for the guards
that decide *whether* a rule may score. The branches below are reached only by a
unit-level test or the route, and are named here so a later session does not
re-measure to find out:

- `fingerprint_of`, `_sha1_of`, `_text`, `_as_list`, `_parse_moment`, `_utc`:
  their answers for junk are pinned by
  `test_the_normalisation_helpers_state_their_fallbacks`, not by a sweep that
  happens to feed them.
- `_exception_match`'s fall-through when a kind has nothing to compare (an SPKI
  exception on a certificate with no key digest): sweep-level via
  `test_an_exception_whose_kind_the_sighting_cannot_answer_does_not_apply`,
  because the alternative is constructing a provider row no producer writes.
- `add_exception`'s refusal of a kind nothing produces: the service test enables
  a `dns` connector with a provider to prove the refusal flips; the route test
  keeps the HTTP answer at 400.
- `monitor_kind` / `expiry_kind`: unit-level, because they are pure switches the
  route only calls.

**Deliberately uncovered (2 statements)**

- `tls_identity_service.py:540` — `continue` for an address-less row inside R1's
  grouping loop. The collection loop above it only admits sightings with an
  address, so this is a guard for a future change to that loop, not a behaviour a
  provider can produce.
- `tls_identity_service.py:659` — `continue` when a sighting's identity row is
  gone. The foreign key cascades, so the row cannot exist in a consistent
  database; the branch is what keeps a sweep alive on an inconsistent one.

**Done when**

- both modules are at or above 90%, with a floor added for the router and raised
  for the service — `tls_identity_service.py` 96, `dns_security.py` 97 in
  `backend/scripts/check_critical_coverage.py`, both listed in
  `docs/production-readiness.md`;
- the TLS, DNS Security and DNS expiry suites plus the full backend suite are
  green;
- the batch file states which rules are covered only by their own unit tests and
  not by a sweep-level test — above.

**Progress log**

| Date | Change | Measured |
|---|---|---|
| 2026-10-19 | batch written from the CI baseline | 85.3%, 76.8% |
| 2026-10-20 | `test_tls_identity_service_gaps.py`: projection spellings, own-address declarations, R1 guard for a provider-only certificate, SPKI/issuer/lapsed exceptions, verdict re-sweep, R2 key reuse, R4 echo | 99.0%, 79% |
| 2026-10-20 | `test_dns_certificates_api.py`: the review list with its verdict and `foreign_only` filters, `PATCH` sighting, exception create/update/list/delete with their refusals and audit | 99.0%, 97% |
| 2026-10-20 | `test_dns_security_api.py`: invalid `subject` filter, `observation_type` filter, un-promotable record member, deleting the last member of an RRset, missing observation, un-normalisable promotion target, and both sides of the duplicate-promotion race | 99.5%, 100% |
| 2026-10-20 | floors added (96/97) and the readiness table updated | 99.5%, 100% |
| 2026-10-20 | closing run: full backend suite 3 184 passed, 14 skipped; `app/` at 94.71% (14 303 statements, 756 missed); critical-coverage gate OK; mypy 0 errors; docs and body-bound gates OK; version 0.2.1 | 99.5%, 100% |

**Measurement note:** on the Windows development venv, a *module-level* dotted
`--cov=app.<module>` (the spelling this batch's "first move" uses) aborts conftest
with a PyO3 error from `bcrypt` before any test runs, while package-level
`--cov=app.core` and `--cov=app` both work — resolving a module name imports the
chain, and the second import of `bcrypt` in one process is what the extension
refuses. `--cov=app` measures the same files and is what the numbers above come
from. The CI job runs on Linux and is unaffected. [Plan 007](../README.md) step 3
moved `--cov-args` itself onto that package flag, so the gate's own spelling now
works on both platforms.
