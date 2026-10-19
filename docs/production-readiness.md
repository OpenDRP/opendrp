# Production readiness status

This page answers one question: **which production-readiness properties does this
repository enforce mechanically, and which ones must an operator verify on the
target host?** It is deliberately not a results page. Every number it reports has
been moved to [the appendix](#appendix-measurements-at-a-point-in-time), because a
measurement taken on one tree is not evidence about the tree in front of you.

## How to read this document

* A row under **What is enforced, and by which gate** names the script that holds
  it and the CI job that runs that script. A false row is a red build.
* A row under **What keeps these properties true** names the test, gate or
  documented command that keeps it true. An item with no such artifact does not
  belong in this document.
* **Known limitations and accepted risks** are decisions an operator inherits, not
  defects to be closed here. Where a limitation names a control, that control is in
  the tree; where it names a measurement, the number is in the appendix.
* The schema is one baseline revision, `0001_initial_schema`, with no parent:
  `backend/scripts/check_migrations.py` is what keeps the graph honest, and
  `alembic heads` is the command that answers the same question inside a running
  installation. A database an earlier build created is adopted by recording that
  revision as its own rather than migrated — the procedure is in
  `docs/upgrading.md`.

A statement that depends on the deployment — resources, TLS, backups, SIEM
delivery, image pinning — is verified on the host with
[docs/deployment.md](deployment.md), [configuration.md](configuration.md) and
[security.md](security.md), not from this page.

## What is enforced, and by which gate

| Property | Enforced by | Where it runs |
|---|---|---|
| Every service has a healthcheck, a bounded logging policy, resource limits, the edge/data/connector network split, an authenticated broker, and the settings the application refuses to start without | `scripts/check_compose_healthchecks.py` | `repo-hygiene`, `make check-compose` |
| Every variable a Compose file interpolates is documented in `.env.example`, every documented application setting reaches a container, and no Compose file shadows an entry with a literal | `scripts/check_env_template.py` | `repo-hygiene`, `make check-env` |
| Every documented command is pasteable as one line in bash, PowerShell and `cmd.exe` | `scripts/check_portable_commands.py` | `repo-hygiene`, `make check-commands` |
| The release version agrees across `backend/app/__init__.py`, `backend/pyproject.toml`, `CHANGELOG.md`, the connector SDK (`opendrp_connector/__init__.py`, `base.py`'s `SDK_VERSION`, `connectors/base/pyproject.toml`) and `frontend/package.json` | `scripts/check_version_consistency.py` | `repo-hygiene`, `release.yml` |
| An ignore rule cannot hide a source file from the repository | `scripts/check_tracked_sources.py` | `repo-hygiene` |
| The SPA fallback cannot redirect a client route into a real build directory | `scripts/check_frontend_spa.py` | `repo-hygiene` |
| Dependencies are declared in one place, as exact pins, with no second declaration to drift from | `scripts/check_dependency_sources.py` | `repo-hygiene` |
| Every relative link in the documentation resolves, every `#fragment` names a heading the target page has, every code fence is closed, every table row carries its header's cells, and every document under `docs/` is reachable from an index | `scripts/check_docs_consistency.py` | `repo-hygiene` |
| The readable schema snapshot `docs/db.sql` and the models the platform maps describe the same tables, columns, `NOT NULL` constraints, defaults and primary keys — in both directions | `backend/tests/test_schema_reference_gate.py` | `backend` job |
| A deployed installation refuses to start with `TESTING` set, so the flag that switches scan admission and login lockout off cannot reach production | `backend/tests/test_config.py` | `backend` job |
| Every connector worker declares its capabilities, quota buckets and credential state through one SDK shape, at start-up and after each scan, and a refused readiness post never fails a scan that produced findings | `backend/tests/test_connector_readiness_contract.py` | `backend` job |
| The connector protocol is bounded per source address, so a leaked or invented token cannot search the job queue without limit, and the bound leaves the shipped poll interval untouched | `backend/tests/test_connectors_protocol_api.py`, `backend/tests/test_security_boundaries.py` | `backend` job |
| A connector's scan summary is cut to the audit shape at the wire boundary, and a completion row carries the address and the batches of the scan it ends | `backend/tests/test_bounded_audit_lifecycle.py`, `backend/tests/test_connectors_protocol_api.py` | `backend` job |
| Every `/api/v1` route a page names is a route `docs/api.md` documents, and every declared exception still appears in the pages | `backend/tests/test_page_routes_contract.py` | `backend` job |
| Every published route carries a capability or is one of the six named public routes, the connector exemption stays under its own prefix, and every role appears in the capability table | `backend/tests/test_route_access_gate.py` | `backend` job |
| The `Access` column in `docs/api.md` states the capability the route actually requires, and no route is missing from the page | `backend/tests/test_api_docs_contract.py`, `backend/tests/route_table.py` | `backend` job |
| A refused role leaves an `authz.denied` row, at most once per account, method and route per window, and the in-process fallback still records it when Redis is down | `backend/tests/test_authorization_denials.py` | `backend` job |
| No `manage_admin` command changes a role or an active flag unless it is asked to, and every command that changes an account writes its audit row before applying | `backend/tests/test_manage_admin_cli.py` | `backend` job |
| Every `python -m scripts.<tool>` command in a fenced block is one that script's parser accepts — script, subcommand and each flag | `backend/tests/test_documented_cli_gate.py` | `backend` job |
| Every number a page promises (limits, retention, password policy, recovery codes, version) is the number the code holds, and the sentence stating it is still on the page | `backend/tests/test_docs_numbers_gate.py` | `backend` job |
| The Alembic chain has one head, intact ancestry and no silently empty `downgrade()` | `backend/scripts/check_migrations.py` | `backend` job, `make check-backend-migrations` |
| Every table and column the ORM maps is created by the revision chain, and everything the chain creates is mapped | `backend/scripts/check_schema_drift.py` | `backend` job |
| Each security-boundary module stays above its own coverage threshold | `backend/scripts/check_critical_coverage.py` | `backend` job, `make test-backend-critical-coverage` |
| The mypy error count only ratchets down | `backend/scripts/check_mypy_baseline.py` | `backend` job, `make mypy-backend` |
| The PostgreSQL/Redis integration suite actually ran, with a minimum number of passes | `backend/scripts/check_integration_ran.py` | `production-integration` job |
| A dump taken from a migrated database restores into a scratch one | `scripts/backup.sh`, `scripts/verify_restore.sh` | `production-integration` job, `make backup-verify` |
| Every image the Compose files resolve is present in the release matrix | `scripts/check_release_images.py` | `release.yml` |
| A published image has an SBOM, provenance, and no unfixed HIGH/CRITICAL finding | `trivy` step in `.github/workflows/release.yml` | `release.yml` |
| Shipped dependencies carry no known advisory, and no credential is in the history | `pip-audit` / `npm audit` / gitleaks steps | `security` and `secrets` jobs |
| Every timestamp the UI shows is the stored UTC instant, formatted without the reader's locale, and the table that shows one says so | `frontend/src/lib/timezoneContract.test.ts` | `frontend` job |
| The metrics endpoint publishes no row of data as a label, and does not exist until `METRICS_TOKEN` is set | `backend/tests/test_metrics.py` | `backend` job |
| The frontend suite enforces a coverage floor, and measures every source file rather than the ones a test happened to import | `frontend/vite.config.ts` (`npm run test:coverage`) | `frontend` job |
| The PostgreSQL-only suites actually run, and a database that is missing fails the job instead of skipping them | `backend/tests/test_postgres_only_suites_gate.py`, `backend/scripts/check_integration_ran.py` | `production-integration` job |
| Each source file the migration graph could silently lose coverage on stays above its own threshold, including the five that used to have none | `backend/scripts/check_critical_coverage.py` | `backend` job, `make test-backend-critical-coverage` |
| A migration's connection is bounded on waiting for a lock and deliberately unbounded on statement length, and both migration entry points agree | `backend/tests/test_database_limits.py`, `backend/tests/test_migrate_lock.py` | `backend` job |
| The reads that repeat on a timer have an access path, and a database adopted from an earlier build is told how to gain the two the baseline gained afterwards | `backend/tests/test_alembic_migrations.py`, `docs/upgrading.md` | `production-integration` job |
| The database connection budget a configuration implies fits the server Compose starts | `setup.py --check`, `backend/tests/test_setup_env.py` | `backend` job (the check itself runs on the host) |
| The pieces an operator assembles actually meet: a queued scan becomes a finding, the finding reaches the alert queue, and the audit trail holds the path | `scripts/e2e_smoke.py` | `e2e` job (it builds and raises the installation) |
| The same installation works in a browser: the form signs an administrator in, the session cookie is `HttpOnly`, the newest finding renders as a row with its asset, and signing out clears the cookie *and* revokes the token | `scripts/e2e_browser.py` | `e2e` job (after the smoke, on the finding it wrote) |

Every row above is mechanical, which is the point: what a red build cannot see is
the target host. TLS termination, host sizing, backup encryption, SIEM delivery and
network placement are the operator's, and they are verified as described in the
linked runbooks rather than inferred from a green CI run.

## What no gate covers

These boundaries are deliberate, and each was measured once by the audits of
2026-10-15 rather than being left to look covered. A page that reads clean is not
evidence about any of them.

* **How a browser renders the page.** The gates read the Markdown source: they know
  a fence is balanced and a table row has its cells, not how GitHub draws the
  result. A screenshot job was rejected as slow, flaky and a test of somebody
  else's renderer; the class of defect that actually strands a reader — an unclosed
  fence swallowing the rest of the page — is what rule 6 of
  `scripts/check_docs_consistency.py` closes instead.
* **What an image contains beyond the scanners' view.** Trivy, `pip-audit`, `npm
  audit` and the SBOM attestation answer for the packages they can see. A binary a
  base layer carries, a build argument that changes behaviour, and the difference
  between the image CI built and the one a registry serves are outside them.
* **What each provider can and may do.** Which endpoints a plan reaches, which
  fields a response actually carries, and what a vendor's terms permit are facts
  about an account, not about this tree. They belong to the phishing, breaches and
  DNS & TLS audits and their live spikes; the documentation remediation audit of
  2026-10-15 changed pages, not provider capability.
* **The dated measurements in this page's appendix.** Each snapshot states the tree
  it was taken on and the command that produced it, so a gate would have to freeze
  history to hold them. Reading a number here as the state of the checkout in front
  of you is the mistake the appendix exists to prevent.

## Gated security boundaries

`backend/scripts/check_critical_coverage.py` fails the build if any of these drops
below its threshold, so a strong aggregate score cannot hide a weak boundary. The
thresholds are the rule; the coverage actually measured at each dated snapshot is in
[the appendix](#appendix-measurements-at-a-point-in-time). The table below and the
gate's own map are checked against each other (`tests/test_critical_coverage_docs.py`),
so a module cannot be gated without being listed here, or listed here without being
gated, and the run measures what the gate names because CI and the Makefile print their
`--cov=` flags from the gate itself.

| Module | Threshold |
|---|---|
| `app/core/security.py` | 75% |
| `app/core/crypto.py` | 75% |
| `app/api/deps.py` | 75% |
| `app/services/connector_manifest.py` | 70% |
| `app/services/connector_service.py` | 70% |
| `app/services/ingestion_service.py` | 70% |
| `app/services/connector_credentials.py` | 80% |
| `app/services/module_registry.py` | 70% |
| `app/core/request_rate_limit.py` | 85% |
| `app/services/alert_service.py` | 70% |
| `app/services/alert_delivery_service.py` | 70% |
| `app/tasks/alert_tasks.py` | 80% |
| `app/api/v1/routers/alerts.py` | 80% |
| `app/core/health.py` | 90% |
| `app/tasks/report_tasks.py` | 80% |
| `app/services/phishing/whois_service.py` | 80% |
| `app/services/asset_matching.py` | 90% |
| `app/services/scan_admission.py` | 90% |
| `app/tasks/retention_tasks.py` | 80% |
| `app/services/provider_quota.py` | 75% |
| `app/tasks/integrity_tasks.py` | 70% |
| `app/api/v1/routers/metrics.py` | 90% |
| `app/core/metrics.py` | 85% |
| `app/services/audit_verification.py` | 90% |
| `app/services/audit_archive.py` | 75% |
| `app/services/dns_security_service.py` | 85% |
| `app/services/source_observations.py` | 90% |
| `app/services/ingestion_events.py` | 90% |
| `app/services/source_accounts.py` | 80% |
| `app/services/alert_content.py` | 80% |
| `app/services/module_aliases.py` | 90% |
| `app/services/phishing_score_service.py` | 90% |
| `app/services/alert_policy.py` | 95% |
| `app/services/breach_catalogue.py` | 90% |
| `app/services/breach_kpi.py` | 95% |
| `app/services/breach_severity.py` | 85% |
| `app/services/invitations.py` | 90% |

## Earlier remediation rounds (historical)

These rounds are recorded because the artifacts they left behind are what keep the
properties above true; the page itself is not a changelog. Each row names the code
or test that holds it.

| Item | Change |
|---|---|
| Report race | A report deleted while `report.generate` ran made the task raise `StaleDataError` and report a meaningless failure. The terminal transition is now an explicit row-count-checked `UPDATE`; a vanished report is an ordinary outcome, and the orphaned PDF is removed. Regression tests cover both the success and the failure path. |
| Dead client routes | Two frontend helpers called breach metadata and catalog routes that the backend does not expose. Removed. |
| Authenticated request limit | New `app/core/request_rate_limit.py`, wired into `get_current_user` — the one dependency every authenticated route resolves — with `AUTHENTICATED_RATE_LIMIT_PER_MINUTE` (default 600, `0` disables). The block is audited once per window, so the limiter cannot itself become the amplification it prevents. |
| Declared-module findings | Generic findings were read-only: they carried a `status` with no way to change it. `PATCH /api/v1/findings/{finding_id}` (admin/analyst) plus a status control on the module page. |
| Coverage | Added suites for WHOIS enrichment, readiness/database boundaries, alert-channel probes, alert delivery, and asset schema validation; six more modules are now gated (see above). |
| Provider-neutral breaches module | The module is named for what it stores — `Breach` / `drp_breaches`, including indexes, the check constraint, module metadata, and the reference schema; the API group is `/api/v1/breaches` and the page's calls are `scanBreaches*`. Nothing the breaches module exposes names a provider — the HIBP connector is one source that fills it, not its identity. |

## Current scan reliability hardening

Connector scans are asynchronous and recoverable: jobs carry renewable leases,
connectors heartbeat while active, expired work is retried a bounded number of
times, and provider failures are represented in job details instead of being
reported as clean empty results. The frontend waits for terminal scan state and
refreshes findings automatically. Held by `backend/tests/test_celery_boundary.py`
(the lease and retry boundaries), `backend/tests/test_connectors.py` (provider
failures represented in job details) and `frontend/src/lib/scanPolling.ts`, which
the frontend suite covers.

## What keeps these properties true

Each item is paired with the artifact that keeps it true — a test, a gate or a
documented command. An item with nothing enforcing it does not belong here.

### Operations (an installation could now survive its own success)

| Gap | Closed by |
|---|---|
| Audit history and generated reports grew without bound | The retention tables in the baseline schema, the nightly `purge_expired_data` task (`app/tasks/retention_tasks.py`) with `AUDIT_RETENTION_DAYS` / `REPORT_RETENTION_DAYS`, batched deletes, and an `audit.retention.purged` record of what it removed. Tests: `tests/test_retention_tasks.py`. |
| No backups, and no evidence a backup restores | `scripts/backup.sh` (dump + report store + read-back check), `scripts/restore.sh` (refuses without `CONFIRM_RESTORE=yes`, refuses with other clients connected, takes a safety copy), `scripts/verify_restore.sh`, the `backup` Compose profile, `make backup` / `backup-verify` / `restore`, and a CI job that dumps a migrated database and restores it into a scratch one on every push. Runbook: `docs/backup-restore.md`. |
| Container logs were unbounded | A shared `logging` policy (10 MB × 5) on every service in the Compose file set, plus `docs/observability.md` describing the SIEM path and how to switch to a log driver instead. `scripts/check_compose_healthchecks.py` fails the build if a service loses its bound. |
| Half the services had no healthcheck | Healthchecks for `celery-worker` (a broker round trip, not a process check), `celery-beat` (a liveness file the wrapper touches) and every connector image (the SDK's watchdog file), with `start_period` values that tolerate a slow first scan. Enforced by the same Compose gate. |
| An unprovisioned connector could crash-loop forever | `restart` policy and healthcheck tuning per connector; the Compose gate fails if the healthcheck disappears. |
| The API container ran as root, with the source tree writable | `backend/Dockerfile` now creates and switches to an unprivileged user, and the installation shape (`docker compose -f docker-compose.yml`, which is what `make up` runs) has no source mounts. The overlay that keeps mounts and test tooling lives in `docker-compose.dev.yml`, reachable only as `make up-tools`, so a bare `docker compose up` cannot pick it up. |
| Two API replicas raced on migrations | `backend/scripts/migrate.py` takes a PostgreSQL advisory lock around `alembic upgrade head`; the API container runs it at startup. Tests: `tests/test_migrate_lock.py`. |

### What the platform promised and did not do

| Gap | Closed by |
|---|---|
| `docs/description.md` promised audit events as JSON on stdout; INFO events were silently dropped (the audit logger inherited the stdlib root level, WARNING) | `app/core/logging_config.py` owns the logger names, the stdout handler and the level, and pins `opendrp.audit` at INFO so no `LOG_LEVEL` can silence the trail. `tests/test_logging_config.py` asserts that an audit line reaches stdout, that it carries exactly the five documented fields, and that a raised `LOG_LEVEL` does not remove it. |
| No way to correlate a user-visible failure with the record of it | `X-Request-ID` is accepted (validated), propagated through a contextvar, written into `details.request_id` of every audit row the request causes, forwarded into Celery tasks (`app/core/celery_app.py`), attached to every log line, echoed by the API and sent by the SPA (`frontend/src/lib/api.ts`). Inside `details` on purpose: a sixth top-level field would reach a SIEM index that maps the documented shape. Tests: `tests/test_request_context.py`, `frontend/src/lib/api.test.ts`. |
| Connector logs were `key=value`, not JSON | The connector SDK configures structlog JSON output and carries the same request id. |

### Security

| Gap | Closed by |
|---|---|
| No second factor | TOTP (`app/core/totp.py`, RFC 6238 — verified against the RFC's own test vectors in `tests/test_mfa.py`), enrolment and removal in `app/api/v1/routers/auth.py` (`/auth/mfa`, `/auth/mfa/setup`, `/auth/mfa/enable`, `/auth/mfa/disable`), login enforcement with replay protection and the same lockout as a wrong password, Fernet-encrypted secrets, an administrator recovery path (`POST /users/{id}/mfa/reset`, audited as `user.mfa.reset`) and a CLI path for a locked-out administrator (`manage_admin mfa-off`). The SPA asks for a code only after the API says it is required, so the endpoint is not an oracle for which accounts use MFA, and every role can enrol from **My security**. |
| Rotating a key meant losing data or signing everyone out | `ENCRYPTION_KEY` + `ENCRYPTION_PREVIOUS_KEYS` (MultiFernet: newest encrypts, all decrypt) and `JWT_SECRET_KEY` + `JWT_PREVIOUS_SECRET_KEYS` (tokens signed with a retired secret keep verifying for as long as it is listed). `python -m scripts.rotate_keys` (`generate` with `--jwt` or `--audit-chain`, then `status`, then `rewrap`) makes the rotation a verifiable three-step procedure; `docs/upgrading.md#rotating-secrets` documents it. Tests: `tests/test_key_rotation.py`. |
| Supply-chain and static analysis: dependencies audited, code never | A `bandit` gate at medium severity and confidence over `backend/app` and the `connectors/base`, `connectors/dnstwist`, `connectors/shodan` and `connectors/hibp` trees — the DNS Security, intelligence and endpoint workers are outside that scope — plus a `secrets` job that runs the gitleaks OSS binary over the **full history** (`fetch-depth: 0`) with a narrowly scoped `.gitleaks.toml`, and a CodeQL job that runs when the repository is public (`if: github.event.repository.visibility == 'public'`), because the analysis needs GitHub Advanced Security. Every action is pinned to a commit SHA, with Dependabot updating the pins. |
| Images were only ever built locally | `release.yml` builds and pushes all eight images — the backend, the frontend, and the six connector images (`dnstwist`, `shodan`, `hibp`, `dns-security`, `intelligence`, and the one shared by both endpoint workers) — to GHCR on a `v*` tag with SBOM and provenance attestations, scans each published image with Trivy and fails on an unfixed HIGH/CRITICAL finding, and verifies the tag against `app/__init__.py` before anything is published. |

### Security, second round (threat-model driven)

The round above came from a checklist. This one was chosen by asking which
*actors* the platform actually has to survive, because the checklist answers were
already in place and the interesting gaps were not on any of them. Two actors
covered almost everything:

* **The connector.** Connector code is code this platform did not write, and it
  used to share a network with the Celery broker and PostgreSQL.
* **The stolen administrator token.** Everything an administrator can reach, an
  attacker holding that token can reach — and MFA being *available* changed
  nothing about that as long as it was optional.

| Gap | Closed by |
|---|---|
| Redis was an unauthenticated broker on the application network | `--requirepass` with the password required by Compose interpolation and by a startup validator (a non-loopback `REDIS_URL` without a password is a startup error), and the stack split into three networks (`opendrp-edge`, `opendrp-net`, `opendrp-connectors`) so the connectors no longer sit on the one carrying the broker and the database. Connector egress is not assumed to be an accident: a connector that reaches PostgreSQL is a connector that has been compromised. |
| One slow query could take the whole platform down | PostgreSQL-enforced `statement_timeout` (30 s), `lock_timeout` (5 s) and `idle_in_transaction_session_timeout` (60 s) set per connection, plus an asyncpg `command_timeout` deliberately *above* the server-side bound so the server is the one that cancels. The resulting `57014` is mapped to a `503` that says the database was busy rather than a `500` that says the query was wrong. Tests: `tests/test_database_limits.py`, `tests/test_config.py`. |
| A report row was a path, and the download resolved it | `reports.file_path` holds an artifact *name*, containment is one shared implementation (`app/core/artifact_path.py`) used by the API, the sweep and the task, and a value that is not a bare name is refused and audited as `report.artifact.rejected` instead of being resolved. Tests: `tests/test_artifact_path.py`, `tests/test_reports_integration.py`. |
| An operator-supplied destination was a free SSRF primitive | `app/core/outbound.py` refuses loopback, the cloud metadata address, multicast/link-local and this deployment's own networks for every destination the platform dials — SMTP host, Telegram, WHOIS — with an allowlist (`OUTBOUND_ALLOWED_HOSTS`) for the internal relay that is the normal case in a small company, and a `OUTBOUND_BLOCKED_CIDRS` that can only add. Refusals are audited as `outbound.blocked` with the resolved address. Tests: `tests/test_outbound_guard.py`. |
| The audit trail was an ordinary table | Every entry carries an HMAC over its own five fields, the previous entry's hash and the fingerprint of the signing key, keyed from the environment (`AUDIT_CHAIN_KEYS`, never from the database it protects), with a unique monotonic `seq`. A nightly Celery task verifies incrementally and writes `audit.chain.verified` or `audit.chain.broken` into the trail itself, alerts the operator's own channels on a break, and never repairs what it finds. Retention records what it legitimately deleted, so housekeeping is distinguishable from a deletion. `GET /api/v1/audit/integrity` reports where the chain stands; `make verify-audit-chain` runs a pass now, `FULL=1` re-derives everything, `FILE=` checks an exported stream with no database at all. Tests: `tests/test_audit_chain.py`. |
| Enrolled MFA was not required MFA | `REQUIRE_MFA_FOR_ADMINS` (opt-in, default `false`) refuses an administrator with no enrolled factor, audited as `auth.mfa.required`. `/auth/mfa/*` stays reachable so the account can fix itself, and the SPA routes the operator to the onboarding page on that refusal rather than showing a permission error. Off by default because the recovery path is a person with host access, and a deployment must not be able to lock its own administrator out. The gate kept its own marker (`mfa_required`) and its own audit action deliberately — see the third and fourth rounds, which moved it to where it belongs without deleting either. Tests: `tests/test_mfa.py::TestEnforcementGate`, `tests/test_config.py::TestSecondFactorPolicy`, `tests/test_onboarding.py::TestTheDeploymentPolicyIsAStep`, `frontend/src/App.test.tsx`. |

### Security, third round: credentials somebody else chose

The first two rounds were about actors outside the platform (a stolen token, a
connector) and about the deployment (limits, chains, packaging). This one started
from a question an operator asks on the first day: *why was I not asked for my
second factor, and why is the password the wizard printed still the password?*

| Gap | Closed by |
|---|---|
| A password an administrator chose stayed valid forever | The action that assigns a password *for* someone — creating a user over the API, resetting one as an administrator, `manage_admin create`/`reset`/`--force` — now marks it temporary (`users.must_change_password`), and `POST /api/v1/auth/password` is the endpoint that lets the account holder replace it. Until that happens the account is refused everywhere except the page that completes the step. The new session is returned by the change itself (the old refresh families are revoked with reason `password_change`), because the alternative is signing the operator out for doing what was asked. Tests: `tests/test_onboarding.py`, `frontend/src/pages/OnboardingPage.test.tsx`. |
| Clearing a second factor was a permanent downgrade | `POST /users/{id}/mfa/reset` and `manage_admin mfa-off` now set `users.must_enrol_mfa`: the recovery still works immediately, and the account enrols a new factor before the rest of the platform opens. Recovery must not be the cheapest way to remove MFA. Tests: `tests/test_onboarding.py::TestEnrolmentClearsTheRequirement`, `tests/test_manage_admin_cli.py`. |
| The requirement had to be enforceable without becoming a trap | The gate lives in `get_current_user` next to the request rate limit, so a route written later inherits it (four paths stay open: `/auth/me`, `/auth/password`, `GET /auth/mfa`, and the enrolment pair once the password step is done), and the order of the steps is enforced server-side because both enrolment calls re-check the password. The refusal is a structured log event rather than an audit row — the state was audited when it was created — and `manage_admin onboarding-off` is the host-access escape hatch, with `manage_admin list` now showing the pending steps and the factor state. Tests: `tests/test_onboarding.py::TestTheGate`, `tests/test_manage_admin_cli.py`. |
| The admin UI could not clear the factor it was told to recover | The API had `POST /users/{id}/mfa/reset` since the MFA round and nothing called it. The users list now reports the factor state (`totp_enabled_at`) and the steps an account owes, and offers the recovery action for another account's factor — disabled for the caller's own, which the API refuses by design. Tests: `frontend/src/pages/UsersPage.test.tsx`. |

### Security, fourth round: the reload that never asked

The question an operator asks on the second day is not the one from the first:
*I signed in, so why does F5 put me back on the sign-in form?* The answer was a
defect that existed only in the production bundle, which is why most of this round
is about what the toolchain was allowed to hide rather than about the bug itself.

| Gap | Closed by |
|---|---|
| The SPA concluded "no session" without asking the API | Two defects met in one symptom. It asked only when a `localStorage` entry said there was a session — a record the page can write, standing in as the switch for an `HttpOnly` cookie it cannot read — and it asked from a `persist` rehydration callback, which runs *while the module graph is still being evaluated*. There, a circular import between the store and the API client (`store/auth.ts` ↔ `lib/api.ts`) handed the running code a binding that did not exist yet; the store's own `try/catch` turned the `ReferenceError` into "this browser has no session", so every reload showed the sign-in form with a valid cookie and **not one request reached the API** (0 `/auth/refresh` calls in the proxy log, against 18 successful logins). Now the question is asked once per load from `main.tsx`, nothing about the session is stored in the browser, and the two modules share an import-free registry (`lib/session-bridge.ts`) so `store → api → bridge` is the only direction. Tests: `frontend/src/main.test.tsx`, `frontend/src/store/auth.test.ts`, `frontend/src/lib/api.test.ts`. |
| A cycle between two of our own modules was invisible until a user met it | Vite keeps Rollup's `CIRCULAR_DEPENDENCY` warning on its own ignore list, and every other tool in the loop runs a real ES module graph, which evaluates a dependency before its dependant and therefore never reproduces the fault. `vite.config.ts` now fails the build on a cycle that includes `src/` (which also fails the image build, and names the modules), and `src/lib/moduleGraph.test.ts` walks the import graph in the suite itself. Cycles inside a dependency are left alone. Tests: `frontend/src/lib/moduleGraph.test.ts`. |
| Two refresh callers could race the same rotating token | A reload and a request retrying a `401` could present the same refresh token at once; rotation makes the second presentation indistinguishable from re-use, which revokes the whole family and signs the operator out of the tab that was working. Both now go through one single-flight request in `lib/api.ts`. Tests: `frontend/src/lib/api.test.ts::asks for a restored session once even when two callers overlap`. |
| The deployment's second-factor policy guarded one door | `REQUIRE_MFA_FOR_ADMINS` refused admin *routes* only, so an administrator who turned it on was asked for a factor when they happened to open an admin screen, and could browse everything else until then. It is the same obligation as a temporary password, so it is the same gate, the same page and the same moment — sign-in — with `mfa_required_by_policy` computed on the user payload (never stored, so enrolling clears it and switching the setting off releases every account at once). The marker and the audit row survive, now with `details.reason`; the policy still applies to administrators only. Tests: `tests/test_onboarding.py::TestTheDeploymentPolicyIsAStep`, `tests/test_manage_admin_cli.py`, `frontend/src/pages/OnboardingPage.test.tsx`. |
| A stale shell could keep loading a stale application | `index.html` is the one file whose name does not change between releases and the one that points at the content-hashed assets, and it was served without a `Cache-Control` header, leaving the browser free to treat it as fresh by heuristic. It is now `no-cache`: still cacheable, always revalidated (`docker/nginx/default.conf`). |

### Packaging and upgrade path

| Gap | Closed by |
|---|---|
| No contribution, conduct, changelog or issue/PR documentation | `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, `.github/ISSUE_TEMPLATE/*`, `.github/pull_request_template.md`, and a `SECURITY.md` supported-versions section that names releases rather than `main`. |
| Several copies of the version, no releases, no tags | `backend/app/__init__.py` is the single source; `scripts/check_version_consistency.py` fails the build when `backend/pyproject.toml`, `CHANGELOG.md`, the connector SDK (its `__version__`, the `SDK_VERSION` a connector registers as `api_version`, and its package metadata) or `frontend/package.json` disagrees, and it runs in CI **and** in the release workflow, which also refuses a tag that does not match the code. `OPENDRP_VERSION` pins the images Compose resolves, and the SPA's reported version is baked in at build time from that same release. |
| Nothing told an operator what upgrading would break | `docs/upgrading.md`: the procedure, the maintenance window the baseline's index families need on a populated database, the rewrite of the recorded revision that adopts a database an earlier build created, rollback in both directions, the secret-rotation procedures, and what changes when two replicas are in play. |
| Provisioning was `cp .env.example .env` and five secrets written by hand | `setup.py` is the onboarding path: a small set of deployment and security questions, then every secret generated with the operating system's CSPRNG in the exact shape the validators demand, the finished file checked against the startup rules *before* it is written, and no secret value ever printed (a fingerprint confirms the write). `--check` audits an existing `.env` without touching it and is the mechanical form of the upgrade-time template diff, `--repair` fills only the empties and placeholders, `--force` rotates while moving the replaced keys into the matching `*_PREVIOUS_*` lists so live sessions, stored ciphertext and signed audit history stay valid. It refuses to write a file git would commit. |
| `.env.example` documented settings that did nothing, and omitted settings Compose read | `scripts/check_env_template.py` (rule 1: every variable a Compose file interpolates is documented; rule 2: every entry the template defines is consumed somewhere real; rule 3: every documented application setting reaches a container; rule 4: no Compose file shadows an entry with a literal; rule 5: a setting one connector reads, and nothing else does, is namespaced after that connector, because `.env` is a single namespace shared by every service). It found seven settings that were documentation-only — including the statement timeout the template told an operator to raise for a large inventory — and nine variables Compose read that the template never mentioned; all are now wired or documented. Tests: `tests/test_env_template_gate.py`, `tests/test_setup_env.py`. |
| The quick start's administrator command could not be pasted on Windows | A command wrapped with trailing backslashes is a bash/zsh idiom — PowerShell and `cmd.exe` read the remaining lines as separate commands, so the first install on Windows ran the first line without its arguments and parsed the rest as expressions — and single quotes are not quoting to `cmd.exe`. Every documented command is one line with double-quoted values; `scripts/check_portable_commands.py` (job `repo-hygiene`, `make check-commands`) fails the build when a document, `.env.example` or an operator-facing docstring grows a shell-specific continuation. Tests: `tests/test_portable_commands_gate.py`, `tests/test_setup_env.py`. |
| A knob could only be identified as fictional by reading two files side by side | `setup.py --check` reports what an operator cannot see: a documented key their file lacks, a key their file has that the template never documents (a silent typo), a leftover placeholder, and the production rules the application itself enforces at startup. It also reports the two inconsistencies that are invisible until something fails elsewhere: a public loopback origin naming a port no binding is published on (the UI is reached through the terminator, so the browser origin and `FRONTEND_PORT` are different questions), and a pinned `OPENDRP_VERSION` that disagrees with the version this checkout declares — Settings reports the first, `/api/v1/health` the second, so the installation would display two versions of itself. |

## Known limitations and accepted risks

1. **Coverage must be measured with `COVERAGE_CORE=sysmon`.** With the default C
   tracer, frames in async request handlers are mis-attributed in this
   environment: a test that observes `201 Created` from `POST /api/v1/users` can
   leave the handler body counted as *missed*. `make test-backend*` and the CI
   coverage steps set the variable; invoking `pytest` by hand without it
   understates coverage. The gap the variable was introduced to close is recorded
   in the `Makefile`, directly above `test-backend` — roughly nine points on the
   tree it was measured from, which is the order of magnitude to expect here.
2. **The suite runs on SQLite.** PostgreSQL-specific behaviour (row locking,
   enum/UUID/JSON column semantics, NULL-unique constraints) is covered by the
   dedicated migration round-trip and the production-integration module, both of
   which require a live database and are therefore separate targets. The
   advisory-lock migration path is unit-tested for ordering, but its behaviour
   under two genuinely concurrent containers is only exercised by
   `make verify-replicas`.
3. **The two-replica proof is a local scenario, not a CI job.** CI validates the
   Compose shape (`docker compose -f docker-compose.yml -f
   docker-compose.replicas.yml config`, plus a check that `container_name` and
   the published port are still released) because running the full stack twice
   in the workflow would cost more than the assertion is worth today.
   `make verify-replicas` performs the real check — login on one replica, token
   and refresh cookie used against the other, CSRF enforced on the replica that
   never issued the cookie, and the audit row visible from both.
4. **CodeQL does not run while the repository is private** (it requires GitHub
   Advanced Security). The workflow is committed and gated on repository
   visibility, so it starts with the first push after the project is public.
   `bandit` and the full-history secret scan do run today.
5. **The frontend API client is hand-written.** Endpoint paths are string
   literals, so removing a backend route does not fail any build — that is exactly
   how the two dead helpers above survived. Generating the client from
   `/openapi.json` would remove the class of defect rather than the instance. The
   documentation half of that class is closed: `docs/api.md` is compared against
   the schema in both directions by `tests/test_api_docs_contract.py`, so a route
   added, renamed or removed without the reference moving fails the suite. The
   client's path literals are still unchecked.
6. **The authenticated rate limit fails open** when Redis is unavailable, and the
   manual-action limit behaves the same way: losing the throttle during a Redis
   outage is preferred to locking every operator out. The bound that does not
   depend on Redis ships with the platform, in the UI's nginx: the zones
   `opendrp_api`, `opendrp_auth` and `opendrp_conn` declared in
   `docker/nginx/nginx.conf` and applied in `docker/nginx/default.conf` with
   `limit_req` and `limit_conn`, with the statuses set to `429` where the zones are
   declared, keyed on the client
   address that `realip` resolves through `TRUSTED_PROXY_IPS` — an `X-Forwarded-For`
   value from a source outside that list is ignored rather than believed. What it
   does not cover: a deployment that publishes the API without the shipped frontend
   container in front of it, a flood spread across many source addresses, and the
   general truth that a rate limit bounds rate and not volume. The values and where
   to change them are in [configuration.md](configuration.md).
7. **Declared-module findings have no bulk transitions.** Status changes are
   per-finding. Native modules do not have bulk transitions either, so this is
   consistency rather than a gap, but a triage workflow over many findings would
   want them.
8. **Finding alerts are durable and asynchronous.** Ingestion writes an `alert_deliveries` queue row and never waits for SMTP or Telegram. The alert worker waits for a connector job to reach a terminal state, aggregates rows by job/module/channel/recipient, and retries only transient network/provider failures. The `alert_deliveries` queue stores delivery state independently for each channel and recipient, so an email success cannot suppress a Telegram retry. Delivery rows retain attempts, next retry time, final status, and sanitized error information. Pool exhaustion is returned as retryable `503 database_busy`, distinct from a statement timeout. The channel health response carries the queue's own counters beside the probe (`delivery` and `delivery_queue`), so a reachable provider with a stalled queue reads as `degraded` rather than green; the aggregate publishes numbers only, never a recipient, target or batch id.
9. **A disabled alert channel is never probed**, deliberately: the health
   endpoint reports `disabled` either way, so dialling it could only add latency.
   The response distinguishes *off* from *incomplete* via `configured`, and leaves
   `checked_at` null because no probe ran (`probe_state: "skipped"` says the
   same thing in one vocabulary). SMTP checks use a fixed-size worker pool and
   bounded wait; a timed-out socket operation holds its slot until it exits,
   preventing an unbounded background-thread backlog. Results are cached in Redis
   for `ALERT_HEALTH_CACHE_SECONDS`, so two operators refreshing the dashboard are
   one handshake, and a busy pool reports `probe_state: "saturated"` rather than a
   `degraded` channel.
10. **Test sends ignore the enable toggle** for email and Telegram, so an operator
   can validate credentials before switching a channel on. Real deliveries honour
   the toggle.
11. **`AUDIT_RETENTION_DAYS` defaults to one year, and the sweep deletes.**
    `0` disables it for an installation that wants an append-only archive; the
    choice is deliberate and belongs to the operator, which is why the default is
    a defensible window rather than "forever" (a volume that fills is also a
    readiness failure).
12. **Second-factor recovery is a human path.** An operator who loses their
    device needs an administrator (`POST /users/{id}/mfa/reset`) or, for the last
    administrator, host access (`python -m scripts.manage_admin mfa-off`). There
    are deliberately no single-use recovery codes: a second, printable credential
    is its own thing to leak, and the CLI keeps recovery at the same privilege
    level as the database.
13. **The audit chain detects; it cannot prevent.** An attacker with write access
    to `drp_audit_logs` *and* read access to the deployment's environment can
    rewrite history and re-sign it, and the pass will hold. What the chain makes
    expensive is the case it is meant to cover: an insider with database access
    only, a `psql` clean-up, a restore of a partial table. The independent witness
    is the SIEM's copy of the stdout stream — `verify_audit_chain --ndjson FILE=`
    checks it — which is why the two are worth keeping in different accounts.
14. **The chain key is not recoverable, and dropping it is silent.** Retiring a
    key from `AUDIT_CHAIN_PREVIOUS_KEYS` while entries it signed are still
    retained makes those entries unverifiable, which is reported as
    `unknown_key_id` — indistinguishable, to a reader, from a key that was never
    configured. The rotation procedure in `docs/upgrading.md` keeps both keys in
    place across the change for exactly this reason.
15. **A restore moves the chain backwards.** A dump taken before the last entries
    restores their absence, and a verification afterwards reports the tip as
    missing until the next entries are written. This is the expected outcome of a
    restore rather than an incident, but it is not distinguishable from a deletion
    by the pass alone; the SIEM copy is what separates the two.
16. **The chain's PostgreSQL path is not covered by the SQLite suite.** The
    position sequence (`nextval('drp_audit_logs_seq_seq')`) and the
    transaction-scoped advisory lock around appends are PostgreSQL-only and are
    therefore exercised by the migration round-trip and `make verify-replicas`,
    not by `make test-backend` (same caveat as limitation 2). The chain logic
    itself — the link, the gap detection, the retention watermark, the refusal of
    an unsigned row and key rotation — is covered by `tests/test_audit_chain.py`
    on SQLite.
17. **The backend suite is not green outside a full stack, and the count is
    recorded rather than an expectation of zero.** In the 2026-10-08 run, 18 of
    1806 tests failed: six needed the Compose network (a real Redis, a connector
    container), ten were caused by edits uncommitted at the time, and two are
    `backend/tests/test_no_legacy_surface.py` — its
    `test_there_is_exactly_one_migration_and_it_is_the_baseline` asserted that
    `backend/alembic/versions/` held exactly `0001_initial_schema.py` while the
    tree held sixteen revisions, and its vocabulary half reported hits in three
    migration files. That disagreement is closed: the history is now that one
    baseline revision, so the gate and the tree say the same thing and those two
    failures are gone from the list a later run compares against. [The appendix](#appendix-measurements-at-a-point-in-time)
    lists the run with its evidence, so a later run can be compared against a known
    list instead of rediscovered.
18. **User search is a substring scan, and the threshold for an index is
    stated rather than assumed.** `GET /api/v1/users?search=` filters on
    `email ILIKE '%…%' OR full_name ILIKE '%…%'`, and no trigram index exists:
    at the account counts an installation starts with, the planner answers that
    with a sequential scan and an index would only be maintained on every user
    change for a query it would still answer the same way. **The trigger is a
    `users` table of a few thousand rows** (RWI-12 in the user/RBAC plan). At that
    point the decision is made from a measurement, not from this paragraph:
    `EXPLAIN (ANALYZE, BUFFERS) SELECT id FROM users WHERE email ILIKE '%…%' OR
    full_name ILIKE '%…%'` on a production copy. If it reports a sequential scan
    whose buffers dominate the page, the fix is `CREATE EXTENSION pg_trgm` plus
    GIN indexes with `gin_trgm_ops` on both columns — added to the baseline and
    with an adoption note in [upgrading.md](upgrading.md), because the history is
    one revision.

## Reproducing the measurements

The commands below are how each appendix block was produced. Run the ones that
answer your question, and treat what they print as new evidence rather than as a
confirmation of the appendix.

```bash
# Backend suite and coverage (sysmon tracer — see limitation 1)
docker compose exec -T backend sh -c "COVERAGE_CORE=sysmon python -m pytest -q --cov=app --cov-report=term-missing"

# Per-module gate against that report
docker compose exec -T backend sh -c "COVERAGE_CORE=sysmon python -m pytest -q --cov=app --cov-report=json:coverage-critical.json && python scripts/check_critical_coverage.py coverage-critical.json"

# Static gates
docker compose exec -T backend sh -c "python -m ruff check app scripts tests && python -m mypy app && python scripts/check_migrations.py && python -m scripts.check_schema_drift"

# Repository gates (also run in CI's repo-hygiene, secrets and security jobs)
python scripts/check_tracked_sources.py .
python scripts/check_compose_healthchecks.py docker-compose.yml
python scripts/check_env_template.py
python scripts/check_portable_commands.py
python scripts/check_version_consistency.py
python scripts/check_docs_consistency.py
bandit --quiet --severity-level medium --confidence-level medium -r backend/app connectors/base connectors/dnstwist connectors/shodan connectors/hibp

# The audit hash chain, on a live instance (FULL=1 re-derives everything)
make verify-audit-chain

# Redis must refuse an unauthenticated client once the stack is up
docker compose exec -T redis sh -c 'redis-cli ping'   # expects NOAUTH

# The statement limits are in force on the connection the application uses
docker compose exec -T backend python - <<'PY'
import asyncio
from sqlalchemy import text
from app.core.database import AsyncSessionLocal

async def main():
    async with AsyncSessionLocal() as db:
        for setting in ("statement_timeout", "lock_timeout",
                        "idle_in_transaction_session_timeout"):
            print(setting, (await db.execute(text(f"SHOW {setting}"))).scalar())

asyncio.run(main())
PY

# The installation, then the two-replica proof (see limitation 3)
make up
ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD='...' make verify-replicas

# Frontend
cd frontend && npm run typecheck && npx vitest run && npm run build

# The build refuses a circular import between application modules, so `npm run
# build` above is also the check for that. It can be seen failing on purpose by
# importing the store from lib/session-bridge.ts, which is the cycle the reload
# fix removed; `npx vitest run src/lib/moduleGraph.test.ts` states the same rule in
# the suite, and prints the cycle when it fails.
#
# `npx vitest run src/lib/timezoneContract.test.ts` holds the other UI-wide rule:
# timestamps are rendered from @/lib/datetime (UTC, locale-independent), no
# formatter is built without a named locale, and every module that prints an
# instant also surfaces TIME_ZONE_HINT. It can be seen failing on purpose by
# rendering an expiry with `new Date(x).toLocaleString()` in any page.
```

The end-to-end smoke is the one measurement that needs a running installation,
because that is the property it checks. CI does exactly this in the `e2e` job
(`python setup.py --non-interactive`, then `docker compose up -d --build` for the
API, both workers, the scheduler and the frontend); against a stack you already
have up, the same thing is:

```bash
# 1. An administrator the run may use. `create` marks the account as owing a
#    password change of its own, which is right for a human and wrong for a run
#    with nobody watching, so the requirement is cleared explicitly.
docker compose exec -T backend python -m scripts.manage_admin create -e e2e-smoke@example.com -p 'E2eSmokePass!2345'
docker compose exec -T backend python -m scripts.manage_admin onboarding-off -e e2e-smoke@example.com

# 2. The alert dispatcher runs on the `alerts` queue, so that worker has to be up
#    for the last assertion: a stack without one queues notifications nothing
#    drains.
docker compose up -d celery-worker-alerts

# 3. The run itself. `E2E_METRICS_TOKEN` is the one the stack was raised with,
#    because the alert-queue assertion reads the queue the way an operator's
#    monitoring does, and the scrape endpoint does not exist without it.
E2E_ADMIN_EMAIL=e2e-smoke@example.com E2E_ADMIN_PASSWORD='E2eSmokePass!2345' E2E_METRICS_TOKEN="$(grep -E '^METRICS_TOKEN=' .env | cut -d= -f2-)" E2E_FRONTEND_URL=http://127.0.0.1:3000 python scripts/e2e_smoke.py
```

It writes data (an asset, a connector, a finding) and, when email alerts are not
already enabled, enables that channel against a name that does not resolve so the
alert step has a destination to reach. Nothing is sent either way: the run asserts
the queue, and an installation that already has email alerts on keeps the channel
it configured.

The browser half drives that same installation through the interface an operator
actually uses, and covers what a `urllib` request cannot reach: that the root sends
a stranger to the sign-in form, that the form's own submission creates the session,
that the refresh token is in an `HttpOnly` cookie page scripts cannot read while the
CSRF value beside it *is* readable (that is how the SPA sends it back), that no
token lands in `localStorage` or `sessionStorage`, that the newest finding the API
lists renders as a row with the asset it is attributed to, and that signing out
clears the cookie *and* leaves the token refused by the API. It needs Playwright
once per machine:

```bash
python -m pip install playwright
python -m playwright install chromium
E2E_FRONTEND_URL=http://127.0.0.1:3000 E2E_ADMIN_EMAIL=e2e-smoke@example.com E2E_ADMIN_PASSWORD='E2eSmokePass!2345' python scripts/e2e_browser.py
```

It creates nothing, so it runs after the smoke above: with no finding in the
listing it fails rather than passing on an empty table. `E2E_BROWSER_CHANNEL=msedge`
drives a browser already installed on the machine instead of Playwright's own
Chromium, `E2E_BROWSER_HEADLESS=false` opens a window you can watch, and
`E2E_ARTIFACT_DIR` writes a screenshot of the page when a step fails.

`make test-backend`, `make test-backend-fast`, `make test-backend-critical-coverage`
and `make check-backend-migrations` wrap the same commands.

### Why `alembic check` is deliberately not a gate

`alembic check` — models against a live database, indexes and constraints
included — passes only when the two agree *exactly*, and they did not on the
2026-10-08 snapshot (the measured differences are in
[the appendix](#appendix-measurements-at-a-point-in-time)). Every pair involved
enforces the same thing, so no runtime behaviour depends on the difference — but a
future `alembic revision --autogenerate` would render it as a migration that drops
and recreates those objects, which is why it is not wired in as a gate.
`backend/scripts/check_schema_drift.py` covers the part that actually stops a
deployment: a table or column the models read and the schema does not have. Closing
the gap is contained work — declare the indexes the models do not declare, and drop
the redundant constraints from the baseline revision — and it is worth doing before
anyone generates a migration from the models.

`make check-backend-migrations` runs *both* static schema gates — the revision
graph and the models-versus-schema comparison — because running half of that
check is how a green result becomes a false one. `tests/test_alembic_migrations.py`
is the PostgreSQL side of the same question: after `alembic upgrade head` it
compares `Base.metadata` with the migrated schema, and it runs the startup seeder
(`scripts/seed_defaults`) the way the API container's entrypoint does.

## Appendix: measurements at a point in time

Nothing in this appendix is a claim about the current checkout. Each block names
the date and the tree it describes. Re-run
[the commands above](#reproducing-the-measurements) before quoting any of these
numbers, and treat a stale number as a lead to re-measure rather than as evidence.

### 2026-09-12 baseline (tree `2bc8e4b`)

All measurements and counts in this block describe tree `2bc8e4b` only, before the
later hardening work.

| Area | Value |
|---|---|
| Backend test suite | **1388 passed, 2 skipped, 0 failed** (6m32s) |
| Backend coverage of `app/` | **92%** — 4954 of 5388 statements, 434 missed |
| `ruff check app scripts tests` | clean |
| `mypy app` | 0 errors, 81 source files |
| Migration gate (`backend/scripts/check_migrations.py`) | single head, intact ancestry, no no-op downgrades |
| Schema-drift gate (`backend/scripts/check_schema_drift.py`) | every mapped table and column is created by the revision chain, and everything the chain creates is mapped |
| Per-module coverage gate (`backend/scripts/check_critical_coverage.py`) | OK — all 14 modules the gate held at that date above threshold (it holds 37 today: see [Gated security boundaries](#gated-security-boundaries)) |
| Alembic head | `0001_initial_schema` at that date |
| Frontend typecheck (`tsc -b`) | clean |
| PostgreSQL migration + parity tests (`tests/test_alembic_migrations.py`, `REQUIRE_INTEGRATION=1`) | 5 passed — clean upgrade to head, downgrade round trip, `Base.metadata` versus the migrated schema, the startup seeder, and the `alembic_version` width |
| Frontend tests (vitest) | 144 passed in 31 files |
| Live stack | a single observation from that date, not a verified deployment |

Per-module coverage as measured at that baseline, for the 14 modules the gate held at
that date; the thresholds are the rule, and today's 37-row table of them lives in
[Gated security boundaries](#gated-security-boundaries):

| Module | Measured |
|---|---|
| `app/core/security.py` | 100% |
| `app/core/crypto.py` | 78.0% |
| `app/api/deps.py` | 80.4% |
| `app/services/connector_manifest.py` | 86.7% |
| `app/services/connector_service.py` | 96.7% |
| `app/services/ingestion_service.py` | 92.9% |
| `app/services/connector_credentials.py` | 97.1% |
| `app/services/module_registry.py` | 93.5% |
| `app/core/request_rate_limit.py` | 92.3% |
| `app/services/alert_service.py` | 89.6% |
| `app/api/v1/routers/alerts.py` | 98.5% |
| `app/core/health.py` | 100% |
| `app/tasks/report_tasks.py` | 90.3% |
| `app/services/phishing/whois_service.py` | 100% |

Lowest-covered modules, for orientation: `app/main.py` 76.2%,
`app/core/crypto.py` 78.0%, `app/api/deps.py` 80.4%, `app/schemas/email.py` 80.6%.
The `COVERAGE_CORE=sysmon` caveat in limitation 1 is why these are the numbers
worth comparing against; a run without it understates them.

### 2026-10-08 snapshot (tree `c63af34` plus the open work of that day)

Taken on the working tree at `c63af34` plus the asset-remediation and involvement
work planned in the internal assets-remediation record (kept in the maintainer's
checkout, deliberately not published), not on
the dated baseline above. The backend suite was executed in full — split into four
shards so that one pass fits the time budget — and each shard's exit code was
captured separately, because one combined exit code cannot say which shard
regressed.

| Area | Value |
|---|---|
| Backend suite (full, 4 shards, `-p no:randomly`) | 113 files, 1806 collected: **1784 passed, 18 failed, 6 skipped** in 26 min wall-clock |
| Migration gate (`backend/scripts/check_migrations.py`) | single head at that date; the chain has since been collapsed into one baseline revision, which is the head this page names at the top |
| Schema-drift gate (`backend/scripts/check_schema_drift.py`) | OK — every mapped table and column is created by the chain (19 tables) |
| Alembic round trip on PostgreSQL (`tests/test_alembic_migrations.py`) | 8 passed, including the expression indexes and the downgrade |
| `ruff check` on the modules this work changed | clean |
| `mypy` baseline gate | **red at that date**: `MYPY_ERROR_BASELINE` is 0 (`backend/scripts/check_mypy_baseline.py`), and that tree reported 3 errors, all in `app/services/connector_service.py` |
| Frontend tests (vitest) | **236 passed** in 37 files (`npm run test`, exit 0) |
| Frontend typecheck (`tsc -b`) | clean |

These are hand-recorded measurements of the date in the heading, and nothing
enforces them: they go stale the moment the tree moves, exactly as the 2026-09-12
block did.

#### The 18 backend failures of that run, by cause

None of them came from the code that day's remediation work touched. A run against
a full stack — and once the edits other people still had open are committed —
should have fewer:

| Cause | Count | Tests |
|---|---|---|
| Needs the Compose network | 6 | `test_source_intelligence::test_real_redis_atomic_account_and_job_limits` (`Connect call failed ('127.0.0.1', 6379)`), 3 × `test_celery_boundary` (the `SET NX` dedup and the scheduler tick with Redis unreachable), 2 × `test_manual_rate_limit` (no `429` is reached — `no_connector`, and no counter in Redis) |
| An edit that was still uncommitted | 10 | 3 × `test_alert_tasks` (a `dispatch_notification_events` call added to `app/tasks/alert_tasks.py`, which `HEAD` does not have, while the test still passes `object()` as the session), 4 × `test_connector_runtime` (`403 Active lease required for provider quota`), 2 × `test_declared_module_integration` and `test_dns_security_api` (the finding-ingest response now carries `received`/`created`/`updated`/`unchanged`/`errors`, and the tests still expect `accepted`/`rejected` alone) |
| A repository gate that no longer matched the tree | 2 | `tests/test_no_legacy_surface.py` — vocabulary hits in three migration files, plus `test_there_is_exactly_one_migration_and_it_is_the_baseline`, which asserted a single revision file while the tree held sixteen. Both closed by collapsing the history into the one baseline revision |

Two of the six service-dependent failures were deliberately not isolated further:
proving them would mean pointing a test run at the running stack's Redis, which
would write rate-limit keys into the instance an operator is using. One frontend
run under load had `SettingsPage.test.tsx` reach its timeout at line 209; the file
passes in isolation (18 tests) and the full suite passes on re-run.

### 2026-10-14 (the remediation plan of 2026-10-13, executed)

Measured on the working tree that closes the plan, in the tooling container
(`docker compose -f docker-compose.yml -f docker-compose.dev.yml run … backend`),
which is the same image and the same suite CI runs. The backend suite was executed
without the `-m "not integration"` filter, because that is what CI's `backend` job
does.

| Area | Value |
|---|---|
| Backend suite (`-p no:randomly`, `COVERAGE_CORE=sysmon`) | **2074 passed, 4 failed, 14 skipped** — the four are the ones that need a live broker, and this container had none: CI's `backend` job runs a password-less `redis:7-alpine` on `127.0.0.1:6379` for exactly them. That run is the record of what the environment looked like; the four no longer *fail* without a broker. They take the `live_redis` fixture (`backend/tests/conftest.py`), so a run that has no broker skips them with the reason — the host, never the password — while every environment that supplies one (the tooling stack, CI's `backend` job, the integration job's password-protected broker) still executes them for real, and `REQUIRE_INTEGRATION=1` turns a missing broker back into a failure. `backend/tests/test_broker_suites_gate.py` pins both halves. |
| Per-module critical coverage gate (`backend/scripts/check_critical_coverage.py`) | OK — all 21 modules above their thresholds |
| Five newly gated modules, measured before their thresholds were set | `asset_matching.py` 95.6% (floor 90), `scan_admission.py` 97.8% (90), `retention_tasks.py` 86.3% (80), `provider_quota.py` 80.3% (75), `integrity_tasks.py` 75.0% (70) |
| `app/tasks/alert_tasks.py` | 75.68% before the two uncovered task bodies gained tests, **100%** after — the gate was red on a module whose statements were never executed |
| Backend coverage of `app/` | 88.8% |
| Migration round trip and the two PostgreSQL-only suites | 28 passed against a scratch database (`test_alembic_migrations.py`, `test_asset_involvement_postgres.py`, `test_dns_expiry_postgres.py`) |
| Gates run on the host | `check_env_template`, `check_docs_consistency`, `check_portable_commands`, `check_tracked_sources`, `check_version_consistency`, `check_compose_healthchecks` — all OK; `ruff check app scripts tests ../scripts ../setup.py` clean; `mypy` baseline gate OK (0 errors) |
| Frontend suite with coverage | 38 files, **248 passed**; statements 72.93%, branches 72.91%, functions 59.38%, lines 77.8% against the floors 70/70/55/75 |
| Frontend typecheck (`tsc -b`) | clean |

Nothing enforces the numbers in this block: they are a dated reading of one tree, and
the gates are what keep the properties true.

### 2026-10-15 (the 0.2.0 tree)

Measured on the tree the 0.2.0 entry describes — `d3fe2df` plus the gate and
documentation work of that day — in a host virtual environment on Windows, with
`COVERAGE_CORE=sysmon`, no Redis service and no PostgreSQL. That is what makes the
local suite differ from the one CI runs, and the difference is named below rather
than smoothed over.

| Area | Value |
|---|---|
| Backend suite (full, one pass, `COVERAGE_CORE=sysmon`) | **2094 passed, 5 failed, 9 skipped** in 41 min |
| The five failures, by cause | four need the live broker CI's `backend` job runs: three in `tests/test_celery_boundary.py` (the `SET NX` dedup and two scheduler ticks) and `test_source_intelligence::test_real_redis_atomic_account_and_job_limits`. The fifth, `test_connector_runtime::TestDnstwistConnector::test_command_uses_bounded_defaults_and_system_dns`, resolves system DNS through `aiodns`, which cannot run on this host's event loop; CI's connector-runtime job runs it on Linux |
| Backend coverage of `app/` | **90.13%** — 9848 of 10926 statements (the 70% floor is met) |
| Per-module critical coverage gate (`backend/scripts/check_critical_coverage.py`) | OK — all **31** modules above their thresholds, and all 31 present in the report that run wrote |
| The ten newly gated modules, measured before their thresholds were set | `app/api/v1/routers/metrics.py` 100.0% (floor 90), `app/core/metrics.py` 92.3% (85), `app/services/audit_verification.py` 96.4% (90), `app/services/audit_archive.py` 82.0% (75), `app/services/dns_security_service.py` 93.2% (85), `app/services/source_observations.py` 96.1% (90), `app/services/ingestion_events.py` 97.1% (90), `app/services/source_accounts.py` 85.3% (80), `app/services/alert_content.py` 86.7% (80), `app/services/module_aliases.py` 100.0% (90) |
| `app/services/ingestion_events.py` | 37.7% before `enrich_one_event` gained a suite of its own (`backend/tests/test_ingestion_outbox_drains.py`), **97.1%** after. The lines still uncovered are the detached-session shims the real WHOIS client calls |
| Gates run on the host | `check_migrations`, `check_schema_drift` (25 tables), `check_docs_consistency` (40 documents), `check_portable_commands`, `check_withdrawn_providers`, `check_version_consistency`, `check_dependency_sources` — all OK; `ruff check app alembic scripts tests ../connectors ../scripts ../setup.py` clean; `bandit -r app ../connectors` at medium/medium exits 0; the `mypy` baseline gate is OK (0 errors); `pip-audit --strict` on the runtime lock and `npm audit --omit=dev --audit-level=high` both report no known vulnerability |
| The two gate suites this work added | `tests/test_lock_requirements_gate.py` 10 passed, `tests/test_critical_coverage_docs.py` 3 passed |
| Frontend suite with coverage | 38 files, **248 passed**; statements 72.93%, branches 72.91%, functions 59.38%, lines 77.8% against the floors 70/70/55/75 |
| Not measured here | the PostgreSQL-only suites and the Alembic round trip (`test_alembic_migrations.py`, `test_asset_involvement_postgres.py`, `test_dns_expiry_postgres.py`), the `e2e` job and the image builds: each needs the Compose stack. The dotted `--cov=` flags the gate prints cannot be exercised on this host either — resolving them makes coverage import `app/core/security.py`, and this platform's `bcrypt` extension refuses a second import in one process. CI's Linux `backend` job runs that spelling; the flags themselves were checked against the gate's map here |

Like the blocks above, nothing enforces these numbers: they are a dated reading of
one tree, and the gates are what keep the properties true.

### The `alembic check` divergence measured on 2026-10-08

On a freshly migrated PostgreSQL 17, with the working tree of that date:

* five unique constraints exist where the models declare a unique index
  (`uq_users_email` / `ix_users_email`, and the same pair for
  `drp_connectors.name`, `drp_phishing_domains.phishing_domain`,
  `drp_refresh_families.family_id` and `drp_audit_logs.seq`) — the original
  migrations created both objects, and the models only ever declared one;
* four indexes exist that no model declares:
  `uq_assets_type_normalized_value` (the partial unique index that enforces asset
  uniqueness), `ix_drp_audit_logs_user_timestamp`, `ix_reports_created_at` and
  `ix_reports_status`.

This measurement is the reason behind
[Why `alembic check` is deliberately not a gate](#why-alembic-check-is-deliberately-not-a-gate).
