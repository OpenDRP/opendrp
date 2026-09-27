# Production readiness status

This document contains a dated historical baseline and the current operational
constraints. The numeric measurements in the table below were taken on
2026-09-12 against tree `2bc8e4b`, before later hardening work; they are **not a
claim about the current checkout**. Re-run the commands in CI or the validation
section before declaring a deployment production-ready. The current migration
head is `0001_initial_schema`.

The hardening sections describe controls that are present in the source tree;
where a statement depends on the deployment (resources, TLS, backups, SIEM,
image pinning), the operator must verify it using [docs/deployment.md](deployment.md)
and the live stack rather than treating this file as evidence.

## Measured status

| Area | Value |
|---|---|
| Backend test suite | **1388 passed, 2 skipped, 0 failed** (6m32s) — run the current suite before release |
| Backend coverage of `app/` | **92%** — 4954 of 5388 statements, 434 missed (pre-hardening baseline) |
| `ruff check app scripts tests` | clean |
| `mypy app` | 0 errors, 81 source files |
| Migration gate (`scripts/check_migrations.py`) | single head, intact ancestry, no no-op downgrades |
| Schema-drift gate (`scripts/check_schema_drift.py`) | every mapped table and column is created by the revision chain, and everything the chain creates is mapped |
| Per-module coverage gate (`scripts/check_critical_coverage.py`) | OK — all 14 gated modules above threshold |
| Alembic head | `0001_initial_schema` |
| Frontend typecheck (`tsc -b`) | clean |
| PostgreSQL migration + parity tests (`tests/test_alembic_migrations.py`, `REQUIRE_INTEGRATION=1`) | 5 passed — clean upgrade to head, downgrade round trip, `Base.metadata` versus the migrated schema, the startup seeder, and the `alembic_version` width |
| Frontend tests (vitest) | 144 passed in 31 files — run the current suite before release |
| Frontend production build | succeeded for the historical baseline; run the current build before release |
| Live stack | Historical observation from 2026-09-12 only; verify the target deployment with `docker compose ps` and `/api/v1/ready` |

Lowest-covered modules, for orientation: `app/main.py` 76.2%,
`app/core/crypto.py` 78.0%, `app/api/deps.py` 80.4%, `app/schemas/email.py` 80.6%.
Every security boundary the platform depends on is at or above its gate.

## Gated modules

`scripts/check_critical_coverage.py` fails the build if any of these drops below
its threshold, so a strong aggregate score cannot hide a weak boundary:

| Module | Threshold | Measured |
|---|---|---|
| `app/core/security.py` | 75% | 100% |
| `app/core/crypto.py` | 75% | 78.0% |
| `app/api/deps.py` | 75% | 80.4% |
| `app/services/connector_manifest.py` | 70% | 86.7% |
| `app/services/connector_service.py` | 70% | 96.7% |
| `app/services/ingestion_service.py` | 70% | 92.9% |
| `app/services/connector_credentials.py` | 80% | 97.1% |
| `app/services/module_registry.py` | 70% | 93.5% |
| `app/core/request_rate_limit.py` | 85% | 92.3% |
| `app/services/alert_service.py` | 80% | 89.6% |
| `app/api/v1/routers/alerts.py` | 80% | 98.5% |
| `app/core/health.py` | 90% | 100% |
| `app/tasks/report_tasks.py` | 80% | 90.3% |
| `app/services/phishing/whois_service.py` | 80% | 100% |

## What the earlier plan changed

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
refreshes findings automatically. Development bundles use `http://localhost:3000`
as their canonical origin.

## What the hardening work closed

Each item is paired with the artifact that keeps it true — a test, a gate or a
documented command. An item with nothing enforcing it does not belong here.

### Operations (an installation could now survive its own success)

| Gap | Closed by |
|---|---|
| Audit history and generated reports grew without bound | The retention tables in the baseline schema, the nightly `purge_expired_data` task (`app/tasks/retention_tasks.py`) with `AUDIT_RETENTION_DAYS` / `REPORT_RETENTION_DAYS`, batched deletes, and an `audit.retention.purged` record of what it removed. Tests: `tests/test_retention_tasks.py`. |
| No backups, and no evidence a backup restores | `scripts/backup.sh` (dump + report store + read-back check), `scripts/restore.sh` (refuses without `CONFIRM_RESTORE=yes`, refuses with other clients connected, takes a safety copy), `scripts/verify_restore.sh`, the `backup` Compose profile, `make backup` / `backup-verify` / `restore`, and a CI job that dumps a migrated database and restores it into a scratch one on every push. Runbook: `docs/backup-restore.md`. |
| Container logs were unbounded | A shared `logging` policy (10 MB × 5) on all eight services, plus `docs/observability.md` describing the SIEM path and how to switch to a log driver instead. `scripts/check_compose_healthchecks.py` fails the build if a service loses its bound. |
| Half the services had no healthcheck | Healthchecks for `celery-worker` (a broker round trip, not a process check), `celery-beat` (a liveness file the wrapper touches) and all three connectors (the SDK's watchdog file), with `start_period` values that tolerate a slow first scan. Enforced by the same Compose gate. |
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
| Rotating a key meant losing data or signing everyone out | `ENCRYPTION_KEY` + `ENCRYPTION_PREVIOUS_KEYS` (MultiFernet: newest encrypts, all decrypt) and `JWT_SECRET_KEY` + `JWT_PREVIOUS_SECRET_KEYS` (tokens signed with a retired secret keep verifying for as long as it is listed). `scripts/rotate_keys generate|status|rewrap` makes the rotation a verifiable three-step procedure; `docs/upgrading.md#rotating-secrets` documents it. Tests: `tests/test_key_rotation.py`. |
| Supply-chain and static analysis: dependencies audited, code never | A `bandit` gate at medium severity/confidence over the backend and connectors, a `secrets` job that runs the gitleaks OSS binary over the **full history** (`fetch-depth: 0`) with a narrowly scoped `.gitleaks.toml`, and a CodeQL workflow that activates when the repository is public (it needs GitHub Advanced Security while it is private). Every action is pinned to a commit SHA, with Dependabot updating the pins. |
| Images were only ever built locally | `release.yml` builds and pushes all five images to GHCR on a `v*` tag with SBOM and provenance attestations, scans each published image with Trivy and fails on an unfixed HIGH/CRITICAL finding, and verifies the tag against `app/__init__.py` before anything is published. |

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
| Three copies of the version, no releases, no tags | `backend/app/__init__.py` is the single source; `scripts/check_version_consistency.py` fails the build when `pyproject.toml` or `CHANGELOG.md` disagrees, and it runs in CI **and** in the release workflow, which also refuses a tag that does not match the code. `OPENDRP_VERSION` pins the images Compose resolves, and the SPA's reported version is baked in at build time. |
| Nothing told an operator what upgrading would break | `docs/upgrading.md`: the procedure, the destructive migrations with what to do beforehand (`0013` discards provider keys — copy them to the connector environment first), rollback in both directions, the secret-rotation procedures, and what changes when two replicas are in play. |
| Provisioning was `cp .env.example .env` and five secrets written by hand | `setup.py` is the onboarding path: a small set of deployment and security questions, then every secret generated with the operating system's CSPRNG in the exact shape the validators demand, the finished file checked against the startup rules *before* it is written, and no secret value ever printed (a fingerprint confirms the write). `--check` audits an existing `.env` without touching it and is the mechanical form of the upgrade-time template diff, `--repair` fills only the empties and placeholders, `--force` rotates while moving the replaced keys into the matching `*_PREVIOUS_*` lists so live sessions, stored ciphertext and signed audit history stay valid. It refuses to write a file git would commit. |
| `.env.example` documented settings that did nothing, and omitted settings Compose read | `scripts/check_env_template.py` (rule 1: every variable a Compose file interpolates is documented; rule 2: every entry the template defines is consumed somewhere real; rule 3: every documented application setting reaches a container; rule 4: no Compose file shadows an entry with a literal; rule 5: a setting one connector reads, and nothing else does, is namespaced after that connector, because `.env` is a single namespace shared by every service). It found seven settings that were documentation-only — including the statement timeout the template told an operator to raise for a large inventory — and nine variables Compose read that the template never mentioned; all are now wired or documented. Tests: `tests/test_env_template_gate.py`, `tests/test_setup_env.py`. |
| The quick start's administrator command could not be pasted on Windows | A command wrapped with trailing backslashes is a bash/zsh idiom — PowerShell and `cmd.exe` read the remaining lines as separate commands, so the first install on Windows ran the first line without its arguments and parsed the rest as expressions — and single quotes are not quoting to `cmd.exe`. Every documented command is one line with double-quoted values; `scripts/check_portable_commands.py` (job `repo-hygiene`, `make check-commands`) fails the build when a document, `.env.example` or an operator-facing docstring grows a shell-specific continuation. Tests: `tests/test_portable_commands_gate.py`, `tests/test_setup_env.py`. |
| A knob could only be identified as fictional by reading two files side by side | `setup.py --check` reports what an operator cannot see: a documented key their file lacks, a key their file has that the template never documents (a silent typo), a leftover placeholder, and the production rules the application itself enforces at startup. It also reports the two inconsistencies that are invisible until something fails elsewhere: a public loopback origin naming a port no binding is published on (the UI is reached through the terminator, so the browser origin and `FRONTEND_PORT` are different questions), and a pinned `OPENDRP_VERSION` that disagrees with the version this checkout declares — Settings reports the first, `/api/v1/health` the second, so the installation would display two versions of itself. |

## Known limitations and accepted risks

1. **Coverage must be measured with `COVERAGE_CORE=sysmon`.** With the default C
   tracer, frames in async request handlers are mis-attributed in this
   environment: a test that observes `201 Created` from `POST /api/v1/users`
   can leave the handler body counted as *missed*. The same run under `sysmon`
   reports `app/api/v1/routers/users.py` at 66.7% instead of 24.0%, and the
   aggregate at 92% instead of 82%. `make test-backend*` sets the variable;
   invoking `pytest` by hand without it understates coverage by roughly nine
   points.
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
   `/openapi.json` would remove the class of defect rather than the instance.
6. **The authenticated rate limit fails open** when Redis is unavailable, and the
   manual-action limit behaves the same way. Losing the throttle during an outage
   is preferred to locking every operator out; nginx-level limits remain the
   outer bound.
7. **Declared-module findings have no bulk transitions.** Status changes are
   per-finding. Native modules do not have bulk transitions either, so this is
   consistency rather than a gap, but a triage workflow over many findings would
   want them.
8. **Finding alerts are durable and asynchronous.** Ingestion writes an `alert_deliveries` queue row and never waits for SMTP or Telegram. The alert worker waits for a connector job to reach a terminal state, aggregates rows by job/module/channel/recipient, and retries only transient network/provider failures. The `alert_deliveries` queue stores delivery state independently for each channel and recipient, so an email success cannot suppress a Telegram retry. Delivery rows retain attempts, next retry time, final status, and sanitized error information. Pool exhaustion is returned as retryable `503 database_busy`, distinct from a statement timeout.
9. **A disabled alert channel is never probed**, deliberately: the health
   endpoint reports `disabled` either way, so dialling it could only add latency
   (the SMTP probe blocks for up to `ALERT_HEALTH_CHECK_TIMEOUT_SECONDS`). The
   response still distinguishes *off* from *incomplete* via `configured`.
10. **Test sends ignore the enable toggle** for email and Telegram, so an operator
   can validate credentials before switching a channel on. Real deliveries honour
   the toggle.
11. **`AUDIT_RETENTION_DAYS` defaults to one year, and the sweep deletes.**
    `0` disables it for an installation that wants an append-only archive; the
    choice is deliberate and belongs to the operator, which is why the default is
    a defensible window rather than "forever" (a volume that fills is also a
    readiness failure).
11. **Second-factor recovery is a human path.** An operator who loses their
    device needs an administrator (`POST /users/{id}/mfa/reset`) or, for the last
    administrator, host access (`python -m scripts.manage_admin mfa-off`). There
    are deliberately no single-use recovery codes: a second, printable credential
    is its own thing to leak, and the CLI keeps recovery at the same privilege
    level as the database.
12. **The audit chain detects; it cannot prevent.** An attacker with write access
    to `drp_audit_logs` *and* read access to the deployment's environment can
    rewrite history and re-sign it, and the pass will hold. What the chain makes
    expensive is the case it is meant to cover: an insider with database access
    only, a `psql` clean-up, a restore of a partial table. The independent witness
    is the SIEM's copy of the stdout stream — `verify_audit_chain --ndjson FILE=`
    checks it — which is why the two are worth keeping in different accounts.
13. **The chain key is not recoverable, and dropping it is silent.** Retiring a
    key from `AUDIT_CHAIN_PREVIOUS_KEYS` while entries it signed are still
    retained makes those entries unverifiable, which is reported as
    `unknown_key_id` — indistinguishable, to a reader, from a key that was never
    configured. The rotation procedure in `docs/upgrading.md` keeps both keys in
    place across the change for exactly this reason.
14. **A restore moves the chain backwards.** A dump taken before the last entries
    restores their absence, and a verification afterwards reports the tip as
    missing until the next entries are written. This is the expected outcome of a
    restore rather than an incident, but it is not distinguishable from a deletion
    by the pass alone; the SIEM copy is what separates the two.
15. **The chain's PostgreSQL path is not covered by the SQLite suite.** The
    position sequence (`nextval('drp_audit_logs_seq_seq')`) and the
    transaction-scoped advisory lock around appends are PostgreSQL-only and are
    therefore exercised by the migration round-trip and `make verify-replicas`,
    not by `make test-backend` (same caveat as limitation 2). The chain logic
    itself — the link, the gap detection, the retention watermark, the refusal of
    an unsigned row and key rotation — is covered by `tests/test_audit_chain.py`
    on SQLite.

## Reproducing the numbers

```bash
# Backend suite and coverage (sysmon tracer — see limitation 1)
docker compose exec -T backend sh -c "COVERAGE_CORE=sysmon python -m pytest -q --cov=app --cov-report=term-missing"

# Per-module gate against that report
docker compose exec -T backend sh -c "COVERAGE_CORE=sysmon python -m pytest -q --cov=app --cov-report=json:coverage-critical.json && python scripts/check_critical_coverage.py coverage-critical.json"

# Static gates
docker compose exec -T backend sh -c "python -m ruff check app scripts tests && python -m mypy app && python scripts/check_migrations.py && python -m scripts.check_schema_drift"

# Repository gates (also run in CI's repo-hygiene, secrets and security jobs)
python3 scripts/check_tracked_sources.py .
python3 scripts/check_compose_healthchecks.py docker-compose.yml
python3 scripts/check_env_template.py
python3 scripts/check_portable_commands.py
python3 scripts/check_version_consistency.py
bandit --quiet --severity-level medium --confidence-level medium -r backend/app connectors/base

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
```

`make test-backend`, `make test-backend-fast`, `make test-backend-critical-coverage`
and `make check-backend-migrations` wrap the same commands.

### The one comparison that is deliberately not a gate

`alembic check` — models against a live database, indexes and constraints
included — passes only when the two agree *exactly*, and they do not. Measured on
a freshly migrated PostgreSQL 17:

* five unique constraints exist where the models declare a unique index
  (`uq_users_email` / `ix_users_email`, and the same pair for
  `drp_connectors.name`, `drp_phishing_domains.phishing_domain`,
  `drp_refresh_families.family_id` and `drp_audit_logs.seq`) — the original
  migrations created both objects, and the models only ever declared one;
* four indexes exist that no model declares:
  `uq_assets_type_normalized_value` (the partial unique index that enforces asset
  uniqueness), `ix_drp_audit_logs_user_timestamp`, `ix_reports_created_at` and
  `ix_reports_status`.

Every pair enforces the same thing, so no runtime behaviour depends on the
difference — but a future `alembic revision --autogenerate` would render it as a
migration that drops and recreates those objects. It is therefore not wired in as
a gate. `scripts/check_schema_drift.py` covers the part that actually stops a
deployment: a table or column the models read and the schema does not have.
Closing the gap is contained work — declare the four indexes in the models, and
drop the five redundant constraints from the baseline revision — and it is worth
doing before anyone generates a migration from the models.

`make check-backend-migrations` runs *both* static schema gates — the revision
graph and the models-versus-schema comparison — because running half of that
check is how a green result becomes a false one. `tests/test_alembic_migrations.py`
is the PostgreSQL side of the same question: after `alembic upgrade head` it
compares `Base.metadata` with the migrated schema, and it runs the startup seeder
(`scripts/seed_defaults`) the way the API container's entrypoint does.
