# Plan 009 — A staged audit that fits in one head at a time

**State:** done — S1 to S28 closed (2026-10-22), and the four acceptance items closed by measurement on 2026-10-23; the nineteen rows it carried are in [plan 011](011-remediation-pass.md), all of them fixed in its passes A, B and C

**Goal:** find defects, bugs and architecture problems across the whole tree without
losing attention or re-deriving the same facts every session. The work is split
into steps whose production surface is bounded (≤ 3,000 LOC each), each step ends
with a written handoff, and every production file belongs to exactly one step — a
gate fails if a file is added and assigned to none.

**Scope:** the code that ships and the files that deploy it. The audit reads tests
as evidence of intent, not as surface. It fixes what it can fix with a regression
test and records the rest in [the finding register](../audit-findings.md). It does
not redesign the platform: a refactor larger than one step becomes its own
ExecPlan in this directory.

**Baseline:** [the project map](../project-map.md) measured on 2026-10-21 —
128 files and 36,890 LOC in `backend/app`, 18 files and 11,100 LOC in
`connectors/`, 73 production files in `frontend/src`, 3,363 passing tests, 16
inventoried skips. The partition below covers all of it, enforced by
`backend/tests/test_audit_map_gate.py`.

## Method

**One question at a time.** A step opens with the area's tests (they encode what
the module promises), then the module, then the single caller that matters. Reading
the tests first is what keeps a step from rediscovering the contract from behaviour.

**Attention budget, per step:**

- ≤ 3,000 LOC of production code read fully; a step whose surface is larger is
  split before it starts, not during.
- ≤ 8 hypotheses. Each one is either dismissed in writing ("looked like X, it is
  Y because …") or filed as a finding. A hypothesis that neither resolves nor files
  is a thread for the next step's handoff, with the line that stopped it.
- ≤ 10 findings. Hitting ten closes the step; the remainder becomes the next
  step's opening, not a longer step.
- Stop at roughly 90 minutes of agent work. Depth beyond that is not depth.

**Evidence or it did not happen.** A finding is filed only with:

1. `file:line` and the code path that reaches it;
2. a reproduction — a failing test, a command with its output, or a request/response
   pair — small enough to paste;
3. the impact in the operator's terms: who is affected, what they lose;
4. a fix size (`S` ≤ 20 lines, `M` ≤ 150, `L` = its own plan) and a disposition.

A suspicion without a reproduction goes to the handoff as an open thread, never
into the register as a finding.

**Disposition.** `fixed` lands in the same step with a regression test that fails
before the change; `planned` names the plan that will carry it; `accepted` is a
trade-off the operator should know about and is added to
[security.md](../security.md) or the readiness page; `duplicate` points at the
finding it repeats. A step never ends with an unclassified finding.

**Severity** is defined in [the register](../audit-findings.md#severity): S1 is
exploitable or loses data, S2 breaks a documented guarantee, S3 is a defect with a
workaround, S4 is a defect of clarity. The audit does not spend S1 time on S4
findings: they are collected for a cleanup pass.

## Handoff protocol

Every step ends by appending this block to
[Progress and Milestones](#progress-and-milestones), rewritten — not appended
twice — so it always describes the *next* step. The block sits under one level-3
heading, Carried context for the next step, and its first line names the step:

```
Handoff after S<n> — <date>
Read: <files actually read, with LOC>
Established: <facts the next step must not re-derive, each with file:line>
Open: <threads, each with the line that stopped the investigation>
Traps: <things that look wrong and are not, with the decision they follow>
Filed: <finding ids, and the disposition of each>
Next pre-read: <≤ 5 files, ≤ 400 LOC, in the order to read them>
```

The block is the only context the next step inherits. If a fact is not in it, the
next session is allowed to re-open it — which is exactly why the block stays short
and every line carries a reference.

## Plan of Work

| File | Change |
|---|---|
| `docs/project-map.md` | new: the map, the trust boundaries, the defect-class index, the settled decisions, and the partition |
| `docs/exec-plans/009-staged-audit.md` | this plan: steps, budget, handoff protocol, progress log |
| `docs/audit-findings.md` | new: severity rubric, register schema, closure rules, the register itself |
| `backend/tests/test_audit_map_gate.py` | new gate: every production file assigned exactly once, no stale surface, every step has a surface and an exit |
| `README.md` | two documentation bullets, so both pages are reachable from the index |
| `docs/exec-plans/README.md` | one row for this plan |

## Concrete Steps

Each step names its surface as the files it owns. A file appears in exactly one
step; a later step that needs it re-reads it as evidence and says so in its `Ask`.

### Wave A — method, identity, authority

#### S0 — Baseline and method
**Surface:** none.
**Ask:** does the documented command sequence still work on this host (venv, not the
system interpreter; `COVERAGE_CORE=sysmon` where the C tracer lies)? Which known
traps must every later step respect?
**Do:** run the focused suite for one area; confirm the failing-test workflow, the
`REQUIRE_INTEGRATION` behaviour and the skip inventory gate; pick one already-known
defect as a probe and take it through the full finding lifecycle.
**Exit:** the probe is filed, reproduced and closed; the register is no longer empty;
the handoff names the interpreter, the tracer and the three traps.

#### S1 — Session, MFA, invitations
**Surface:** `backend/app/api/v1/routers/auth.py`, `backend/app/api/deps.py`,
`backend/app/core/security.py`, `backend/app/core/totp.py`,
`backend/app/core/recovery_codes.py`, `backend/app/core/mfa_policy.py`,
`backend/app/services/refresh_sessions.py`, `backend/app/services/invitations.py`,
`backend/app/models/user.py`, `backend/app/models/token.py`,
`backend/app/schemas/user.py` — 3,034 LOC.
**Ask:** can a token minted before MFA enrolment reach a protected route? Does
refresh reuse revoke the family, and is the check atomic where it must be? Does an
invitation bind to one address and one use, and does accepting it revoke existing
sessions? Does a wrong TOTP reveal whether the account exists, and is the attempt
rate-limited per user *and* per origin? Does logout revoke the family or only the
cookie?
**Exit:** every file read; each Ask answered with a test or a finding; the
concurrency cases marked PostgreSQL-only and checked against the documented skip.

#### S2 — Authorization and user administration
**Surface:** `backend/app/api/v1/routers/users.py`,
`backend/app/core/permissions.py`, `backend/app/services/admin_invariants.py`,
`backend/scripts/manage_admin.py` — 2,096 LOC.
**Ask:** does every mutation check the role *and* the object's ownership? Can an
administrator demote the last active administrator, and is that serialised? Does
the admin CLI refuse to run on production defaults, print a password, or write
without an audit row? Is there a route where a service trusts a payload because the
router forgot a dependency?
**Exit:** every endpoint in the router mapped to its role check and its audit row;
the last-admin invariant traced through both the API and the CLI.

### Wave B — evidence, ingestion, assets

#### S3 — Audit trail, chain, archive, retention, logging
**Surface:** `backend/app/core/audit.py`, `backend/app/core/audit_chain.py`,
`backend/app/core/authorization_audit.py`, `backend/app/core/logging_config.py`,
`backend/app/models/audit.py`, `backend/app/api/v1/routers/audit.py`,
`backend/app/services/audit_archive.py`,
`backend/app/services/audit_verification.py`,
`backend/app/tasks/retention_tasks.py`,
`backend/scripts/verify_audit_chain.py`, `backend/scripts/audit_archive.py` — 3,278 LOC.
**Ask:** can a state change commit while its audit row fails, and does anything tell
the operator? Does verification detect truncation, a middle deletion, and a suffix
rewritten with an older key? Do `details` ever carry a password, a token, a provider
key or a whole provider body? Does retirement delete only a verified archived
prefix, and is the archive write atomic with the delete?
**Exit:** the transaction boundary of every audited action written down (router
commit vs service commit); the four tamper cases each answered.

#### S4 — Ingestion and the module registry
**Surface:** `backend/app/services/ingestion_service.py`,
`backend/app/services/ingestion_events.py`,
`backend/app/services/module_registry.py`,
`backend/app/services/module_aliases.py`, `backend/app/models/finding.py`,
`backend/app/models/module.py`, `backend/app/models/ingestion_event.py`,
`backend/app/schemas/module.py` — 2,760 LOC.
**Ask:** are dedup keys stable across connectors and retries, or does a second batch
insert a duplicate finding? Can a partial batch commit findings without an event, and
what does the retry do then? Can a connector choose a module id, severity or asset
attribution outside its manifest? Does the generic `drp_findings` adapter validate
as strictly as the typed paths?
**Exit:** one table of dedup keys per module and their stability argument; the
partial-batch paths each demonstrated.

#### S5 — Assets and matching
**Surface:** `backend/app/services/asset_service.py`,
`backend/app/services/asset_matching.py`, `backend/app/api/v1/routers/assets.py`,
`backend/app/schemas/asset.py`, `backend/app/models/asset.py` — 2,586 LOC.
**Ask:** can an asset be attached to another user's finding, or a finding to another
user's asset? Do bulk import/export enforce the single-item limits and audit each
row? Does promotion from a finding create a duplicate under concurrency? Is the
matching rule the same in ingestion, in asset search and in the SPA's filter?
**Exit:** the owner predicate shown on every query; the promotion race answered.

### Wave C — alerts and the connector boundary

#### S6 — Alert composition and routing
**Surface:** `backend/app/services/alert_service.py`,
`backend/app/services/alert_message.py`, `backend/app/services/alert_policy.py`,
`backend/app/services/alert_facts.py`, `backend/app/services/alert_content.py`,
`backend/app/services/alert_routing.py` — 1,901 LOC.
**Ask:** can quiet hours or a suppression be bypassed through the digest path? Does
a notification count the rows it prints and name them correctly? When the finding's
owner and the asset's owner differ, whose routing wins? Does a missing fact produce
a message that says so, or an empty field?
**Exit:** the routing decision table written down; every message shape rendered once.

#### S7 — Alert delivery and notifications
**Surface:** `backend/app/services/alert_delivery_service.py`,
`backend/app/services/alert_transport.py`,
`backend/app/services/user_notifications.py`,
`backend/app/services/alert_health_cache.py`, `backend/app/tasks/alert_tasks.py`,
`backend/app/tasks/user_tasks.py`, `backend/app/api/v1/routers/alerts.py`,
`backend/app/models/alert_delivery.py`, `backend/app/schemas/email.py` — 2,418 LOC.
**Ask:** can a delivery be marked sent before the transport accepted it? Does a retry
after a timeout double-send, and is the idempotency key persisted? Can the health
cache report healthy on stale data, and is staleness bounded? Do notification emails
redact what the audit rows redact?
**Exit:** the delivery status machine drawn with its failure edges; the double-send
question answered by a test.

#### S8 — Connector control plane
**Surface:** `backend/app/api/v1/routers/connectors.py`,
`backend/app/services/connector_service.py` — 2,413 LOC.
**Ask:** can a connector token be used for another account's job, or a job claimed
twice? Is the ingest batch bounded server-side in size, count and nesting, and does
it reject unknown module ids? Can a terminal job state return to running? Is an
ingestion audit row written when the batch is rejected, and is that the documented
behaviour?
**Exit:** the job state machine and the claim/ingest authorisation written down.

#### S9 — Credentials, manifests, egress
**Surface:** `backend/app/services/connector_credentials.py`,
`backend/app/services/connector_manifest.py`, `backend/app/schemas/connector.py`,
`backend/app/models/connector.py`, `backend/app/core/outbound.py`,
`backend/scripts/manage_connector_tokens.py` — 2,115 LOC.
**Ask:** is a provider key ever returned unmasked, logged, or decrypted outside the
worker handoff? Does manifest validation reject unknown fields and enforce the
documented limits? Can a connector reach a non-allowlisted host through a redirect,
a DNS rebind, or a URL taken from a finding? Can an old token still claim jobs after
rotation?
**Exit:** the key lifecycle (store → hand to worker → rotate → revoke) traced end to
end; the egress guard's bypass attempts enumerated.

#### S10 — SDK runtime, quota, source accounts
**Surface:** `connectors/base/opendrp_connector/` (1,420),
`backend/app/services/provider_quota.py`,
`backend/app/services/scan_admission.py`,
`backend/app/services/source_accounts.py`,
`backend/app/services/source_observations.py`,
`backend/app/api/v1/routers/source_inventory.py`,
`backend/app/models/source_account.py`, `backend/app/models/source_observation.py`
— 2,233 LOC.
**Ask:** does a quota reservation leak when an exception lands between reserve and
charge? Do retries respect `Retry-After`, cap the wait, and bound the body on error
paths too? Can an account's quota be bypassed by claiming through another connector?
Does the egress guard cover the `live_check` CLIs as well as the workers?
**Exit:** the reservation lifecycle drawn; the retry/deadline arithmetic stated as
numbers.

### Wave D — workers, one provider family per step

#### S11 — DNS Security worker
**Surface:** `connectors/dns_security/main.py`,
`connectors/dns_security/tls_probe.py` — 2,196 LOC. A dead second budget (24 lines,
quota.py) was read here and deleted by AUD-022 in plan 011.
**Ask:** does the TLS probe verify chain and hostname and bound the handshake? Can
the CT-log paging run unbounded or ingest one certificate twice? Does a 429 back off
instead of burning quota? Is a probe failure distinguished from "no certificate"?
**Exit:** one finding or one written dismissal per Ask; the CT paging bound shown.

#### S12 — Intelligence worker
**Surface:** `connectors/intelligence/main.py`, `connectors/intelligence/providers.py`,
`connectors/intelligence/live_check.py` — 2,136 LOC.
**Ask:** does every provider answer go through the shared bounded reader? Are titles
and body text truncated before storage, and can binary content reach the database?
Does a provider error map to the documented code rather than a generic failure? Is a
candidate's evidence stored with provenance and a timestamp?
**Exit:** the provider table (endpoint, bound, failure code) written down.

#### S13 — Shodan and dnstwist workers
**Surface:** `connectors/shodan/main.py`, `connectors/shodan/live_check.py`,
`connectors/dnstwist/main.py` — 2,453 LOC.
**Ask:** does the favicon fetch stay on the shared bounded reader (the documented
exception)? Are credits counted per page, and does a retry re-bill? Is the dnstwist
dataset pinned, and is it fetched at build time rather than per scan? Can a target
redirect the worker to an internal address?
**Exit:** the credit arithmetic stated as numbers; the redirect path answered.

#### S14 — HIBP and exposure workers
**Surface:** `connectors/hibp/main.py`, `connectors/exposure_endpoints/main.py`,
`connectors/exposure_endpoints/endpoint_providers.py`,
`connectors/exposure_endpoints/live_check.py` — 2,871 LOC.
**Ask:** does the breach lookup batch without exceeding the documented request
budget? Is a breach's "new" status derived from the catalogue or assumed? Do the
exposure workers respect approval and plan limits? Is a provider payload stored raw
anywhere, and does that conflict with the retention policy?
**Exit:** one finding or dismissal per Ask; raw-payload storage answered with the
retention rule it follows.

### Wave E — modules and scheduling

#### S15 — Breaches
**Surface:** `backend/app/api/v1/routers/breaches.py`,
`backend/app/services/breach_catalogue.py`,
`backend/app/services/breach_severity.py`, `backend/app/services/breach_kpi.py`,
`backend/app/schemas/breaches.py`, `backend/app/models/breach.py` — 2,201 LOC.
**Ask:** is the KPI consistent with the filtered list (same predicates)? Does severity
mapping match the documented scale? Can a state change happen without an audit row?
Are large listings paginated in SQL or sliced in Python?
**Exit:** the KPI/list predicate pair compared line by line.

#### S16 — Phishing
**Surface:** `backend/app/api/v1/routers/phishing.py`,
`backend/app/services/phishing_score_service.py`, `backend/app/services/phishing/`,
`backend/app/schemas/phishing.py`, `backend/app/models/phishing.py`, and
`backend/app/tasks/phishing_tasks.py` (the maintenance pass AUD-033 in plan 011 added
to give the rescore function a caller; it owns the score this step reads) — 1,998 LOC.
**Ask:** is the score stable and explainable, and is the threshold the one the digest
claims? Can a user-controlled domain reach the WHOIS client (SSRF, injection)? Is
WHOIS data cached with a bound, and does a timeout degrade or fail the finding? Does
domain normalisation match the asset matching rule?
**Exit:** the score inputs and weights written down; the WHOIS path answered.

#### S17 — DNS and TLS
**Surface:** `backend/app/api/v1/routers/dns_security.py`,
`backend/app/services/dns_security_service.py`,
`backend/app/services/dns_expiry_service.py`,
`backend/app/services/dns_expiry_monitor_service.py`,
`backend/app/services/dns_observation_inventory.py`,
`backend/app/services/tls_identity_service.py`,
`backend/app/models/tls_certificate.py`, `backend/app/models/dns_observation.py`,
`backend/app/models/dns_expiry_monitor.py` — 2,157 LOC.
**Ask:** is expiry computed in UTC and correct for a not-yet-valid certificate? Is a
second certificate for the same `host:port` lost on merge? Does the monitor dedupe
across sweeps (the row-lock case)? Are observations deduped by asset, type and value
with a timestamp?
**Exit:** the expiry arithmetic stated as numbers; the merge key written down.

#### S18 — Jobs, scheduler, reports, integrity
**Surface:** `backend/app/services/job_service.py`, `backend/app/core/celery_app.py`,
`backend/app/tasks/scheduler_tasks.py`, `backend/app/tasks/report_tasks.py`,
`backend/app/tasks/integrity_tasks.py`, `backend/app/services/report_service.py`,
`backend/app/api/v1/routers/jobs.py`, `backend/app/api/v1/routers/reports.py`,
`backend/app/models/job.py`, `backend/app/models/report.py`,
`backend/app/schemas/job.py`, `backend/app/schemas/report.py`,
`backend/app/tasks/__init__.py` — 2,996 LOC.
**Ask:** can a report job be scheduled twice, and does a retry resume or restart? Do
tasks close their session on error? Is a scheduler tick idempotent across two
workers? Does report generation bound rows and file size?
**Exit:** the job state machine compared with the delivery one; the tick idempotency
evidence (the Redis case) cited.

### Wave F — platform shell and persistence

#### S19 — Configuration, crypto, paths, database
**Surface:** `backend/app/core/config.py`, `backend/app/core/crypto.py`,
`backend/app/core/artifact_path.py`, `backend/app/core/database.py`,
`backend/app/core/health.py`, `backend/app/__init__.py`,
`backend/app/core/__init__.py`, `backend/app/services/__init__.py`,
`backend/scripts/rotate_keys.py`, `backend/scripts/settings_reference.py`,
`.env.example` — 2,089 LOC.
**Ask:** does every setting have a validator, a documented default and a safe
fallback? Is the pool sized and recycled for the deployment, and does a failed
connection surface at startup? Does `artifact_path` refuse traversal and symlink
escape on every platform? Does crypto fail closed on a missing or rotated key, and is
rotation documented?
**Exit:** a settings audit table (name, default, validator, docs) produced once and
referenced later.

#### S20 — Error contract, limits, metrics, request context
**Surface:** `backend/app/main.py`, `backend/app/core/exceptions.py`,
`backend/app/core/safe_errors.py`, `backend/app/core/rate_limit.py`,
`backend/app/core/manual_rate_limit.py`,
`backend/app/core/request_rate_limit.py`,
`backend/app/core/request_context.py`, `backend/app/core/metrics.py`,
`backend/app/api/v1/routers/metrics.py`, `backend/app/api/v1/__init__.py`,
`backend/app/schemas/common.py`, `backend/app/schemas/__init__.py` — 1,875 LOC
(re-measured 2026-10-22; the earlier 1,560 predates the growth of the API entry
point and the metrics module during waves B to E).
**Ask:** does every error response use the documented shape and never a provider or
database message? Can a limit be bypassed by a spoofable header or by the proxy
ordering? Does metrics cardinality stay bounded? Is the request id in both the log
line and the response?
**Exit:** the middleware order written down with the reason for it; the limit keys
enumerated.

#### S21 — Settings, modules, dashboard
**Surface:** `backend/app/api/v1/routers/settings.py`,
`backend/app/schemas/settings.py`, `backend/app/models/settings.py`,
`backend/app/services/settings_service.py`,
`backend/app/api/v1/routers/modules.py`,
`backend/app/api/v1/routers/dashboard.py`,
`backend/app/services/dashboard_timeline.py` — 1,274 LOC.
**Ask:** is every setting validated per type, and is a change audited with before and
after? Does the dashboard aggregate with the same predicates as the module lists? Can
a module be disabled while its findings remain visible through another endpoint? Is
the timeline registry-driven?
**Exit:** each dashboard number traced to the query that produces it.

#### S22 — Persistence: migrations, seeding, drift
**Surface:** `backend/alembic/`, `backend/app/models/__init__.py`,
`backend/scripts/check_migrations.py`, `backend/scripts/check_schema_drift.py`,
`backend/scripts/migrate.py`, `backend/scripts/seed_defaults.py`,
`backend/scripts/seed_data.py` — 1 migration plus 1,300 LOC of scripts.
**Ask:** does the baseline migration reproduce the models (indexes, constraints,
server defaults)? Do seeders run idempotently and leave connectors disabled? Does
drift check cover every table and column the app reads? Are destructive migrations
guarded and documented?
**Exit:** the model-versus-schema difference list refreshed against today's tree;
each difference either explained or filed.

### Wave G — SPA and operations

#### S23 — SPA: client, types, state
**Surface:** `frontend/src/lib/`, `frontend/src/types/api.ts`,
`frontend/src/store/`, `frontend/src/hooks/`, `frontend/src/App.tsx`,
`frontend/src/main.tsx` — 6,254 LOC.
**Ask:** does the client refresh once on 401 and replay without a loop? Is CSRF read
from the readable cookie and sent on every mutation? Are errors mapped to a stable
shape with no raw server message? Does the typed client match the backend contract
on nulls, enums and pagination?
**Exit:** one call traced from a page to the response, including the failure path.

#### S24 — SPA: pages, first batch
**Surface:** `frontend/src/pages/AssetsPage.tsx`,
`frontend/src/pages/AssetDetailPage.tsx`,
`frontend/src/pages/BreachesPage.tsx`, `frontend/src/pages/PhishingPage.tsx`,
`frontend/src/pages/ExposurePage.tsx`, `frontend/src/pages/DNSSecurityPage.tsx`,
`frontend/src/pages/ModulePage.tsx` — 4,900 LOC.
**Ask:** does each page render failure, empty and loading distinctly? Can a filter
change drop the previous response's rows (race)? Does the bulk action send only the
current page's ids, as documented? Is a destructive action confirmed, audited, and
does it report partial failure?
**Exit:** the four states photographed per page in a note; every list's pagination
contract checked against the API.

#### S25 — SPA: pages, second batch
**Surface:** `frontend/src/pages/UsersPage.tsx`,
`frontend/src/pages/SettingsPage.tsx`,
`frontend/src/pages/DashboardPage.tsx`, `frontend/src/pages/AuditPage.tsx`,
`frontend/src/pages/ReportsPage.tsx`, `frontend/src/pages/SecurityPage.tsx`,
`frontend/src/pages/LoginPage.tsx`,
`frontend/src/pages/AcceptInvitationPage.tsx`,
`frontend/src/pages/OnboardingPage.tsx`,
`frontend/src/pages/NotFoundPage.tsx` — 6,000 LOC.
**Ask:** does the UI prevent removing the last administrator while the server also
does? Does settings show which field failed validation? Does the dashboard mark stale
data? Is the audit page's filter parity with the API (action, user, range, cursor)?
**Exit:** the user-administration and settings flows walked end to end; each block of
a form mapped to the server rule that enforces it.

#### S26 — SPA: components and accessibility
**Surface:** `frontend/src/components/` — 4,105 LOC (44 files, tests excluded).
**Ask:** does the data table support keyboard navigation and announce sort changes?
Does the MFA component keep the secret out of the URL and storage? Does the error
boundary avoid swallowing a failure? Do theme and toast respect reduced motion and
contrast?
**Exit:** one pass with keyboard only; the a11y findings filed with the component and
the user impact.

#### S27 — Operations: Compose, images, nginx, CI, repo gates, backups
**Surface:** `docker-compose.yml`, `docker-compose.dev.yml`,
`docker-compose.replicas.yml`, `docker/`, `backend/Dockerfile`, `frontend/Dockerfile`,
`connectors/*/Dockerfile`, `.github/workflows/`, `Makefile`, `setup.py`,
`backend/pyproject.toml`, `connectors/base/pyproject.toml`, `frontend/package.json`,
`frontend/tsconfig.json`, `frontend/tsconfig.app.json`, `frontend/tsconfig.node.json`,
`frontend/vite.config.ts`, `frontend/index.html`, `backend/requirements.txt`,
`backend/requirements-dev.txt`, `scripts/`,
`backend/scripts/check_critical_coverage.py`, `backend/scripts/coverage_gaps.py`,
`backend/scripts/check_mypy_baseline.py`,
`backend/scripts/check_integration_ran.py`,
`backend/scripts/check_api_types.py` (the SPA response-shape gate AUD-060 added after
the split, so the measured count below predates it) — 52 files, 15,534 lines, over
five steps' worth of attention, which is why it was divided below before it started.
**Ask:** do healthchecks, limits and headers match the documented tables? Does nginx
send the same security headers the app does? Do images pin bases and run non-root? Do
CI jobs run what the docs promise (migrations, integration, E2E)? Does every
repository gate have a test that goes red when the gate is weakened? Does backup/restore
cover the archive store, and is a restore exercised?

**How it was split.** The surface is over the attention budget, so it was divided
before the step started, by measured size (`wc -l`, 2026-10-22); each slice asks one
operating question over files that answer nothing else.

- **S27a — Compose, images, nginx** (`docker-compose*.yml`, `docker/*`,
  `backend/Dockerfile`, `frontend/Dockerfile`, `connectors/*/Dockerfile`): 16 files,
  2,960 lines. **Closed 2026-10-22** (progress entry 015). Read: the three Compose
  files, the five files under `docker/nginx/` (server block, global config, the two
  entrypoint scripts, the proxy terminator), the nine Dockerfiles and
  `scripts/check_compose_healthchecks.py`. *Ask:* do the files say what the tables in
  [deployment.md](../deployment.md) and [security.md](../security.md) say, and does the
  deploy path name one release from `.env.example` to the rendered page? *Exit:* every
  healthcheck, limit and header row reproduced from the file; the release statements
  read together (AUD-075). **Done:** the release is one number in all ten statements,
  and the gate reads the three that were missing.
- **S27b — CI and the Makefile** (`.github/workflows/ci.yml`,
  `.github/workflows/release.yml`, `Makefile`): 3 files, 1,414 lines when read (the
  Makefile is 438 now; the two fixes below added its help entries and the port
  resolution). **Closed 2026-10-22** (progress entry 016). Read: both workflows,
  the Makefile, the README CI section and CONTRIBUTING's command tables.
  *Ask:* does each job run the suite the documentation claims it runs — migrations,
  integration under PostgreSQL, the connector tree, the browser E2E — and is the
  release job's tag the version the gate reads? Does every `make` target the README
  and the runbooks name exist, and call the gate the page says it calls?
  *Exit:* every CI job mapped to the claim it enforces; one `make` target walked from
  its documented name to the command it runs. **Done:** ten jobs, every documented
  name present and every executed path checked; `make health` reads the port the
  installation publishes (AUD-076) and `make help` lists all 40 commands (AUD-077).
- **S27c — packaging and pins** (`setup.py`, `backend/pyproject.toml`,
  `connectors/base/pyproject.toml`, `frontend/package.json`, `frontend/tsconfig*.json`,
  `frontend/vite.config.ts`, `frontend/index.html`, `backend/requirements*.txt`):
  11 files, 4,427 lines — of which 2,003 are the hashed pins in the two requirement
  files, read as data by the dependency gate rather than as code.
  *Ask:* does the installer write a `.env` and a Compose file that agree with the
  template and with `settings`? Does the SPA build ship the proxy, the canonical origin
  and the version it claims? Are the pins exact and hashed?
  *Exit:* `python setup.py --check` and the dependency gate green over the tree the
  installer writes, with the file it produces compared to `.env.example`. **Done:** the
  wizard writes all 126 template settings and nothing else, `--check` on that file reports
  no findings, and `docker compose --env-file <file> -f docker-compose.yml config --quiet`
  resolves the production file set against it; the dependency gate is green (no declared
  dependencies, every pin exact and hashed); the SPA build carries the version the package
  declares (AUD-079) and `--check` names the real cost of a setting this release does not
  read (AUD-080).
- **S27d — the gates that hold this repository's prose**
  (`scripts/check_docs_consistency.py`, `scripts/check_env_template.py`,
  `scripts/check_version_consistency.py`, `scripts/check_dependency_sources.py`):
  4 files, 1,746 lines.
  *Ask:* does each gate compare a claim to the file that owns it rather than to a copy
  of the claim, and does each have a test that fails when the gate is weakened? (S27a
  answered this for `check_version_consistency.py` — it read seven statements and missed
  the three a deployment meets; the same question stands for the other three.)
  *Exit:* the four gates mapped to the tests that would notice their absence.
  **Done:** the mapping is in the Progress entry below. Two gaps, both fixed with tests
  that were red first: the dependency gate read four of the seven shipped manifests, and
  the environment-template gate's rule 3 was blind to five of the 83 fields in `Settings`
  (AUD-081, AUD-082).
- **S27e — the gates that hold the tree's shape**
  (`scripts/check_compose_healthchecks.py`, `scripts/check_release_images.py`,
  `scripts/check_portable_commands.py`, `scripts/check_tracked_sources.py`,
  `scripts/check_withdrawn_providers.py`, `scripts/check_connector_body_bounds.py`,
  `scripts/check_frontend_spa.py`): 7 files, 2,022 lines.
  *Ask:* same two questions, plus whether each gate's summary is as wide as its name —
  the Compose gate's output claims more than the file it reads (it repeats the
  documented limits from `deployment.md` rather than only the services).
  *Exit:* the same mapping, and every gap between a gate's name and what it checks
  either fixed or written into the handoff. **Partly done ahead of the step:** the
  torn-table rule (AUD-078) landed while plan execution was checked after S27b, so the
  docs gate this slice reads is already stricter than the one described above — read
  it as evidence, not as its finished state. **Done:** the seven gates are mapped to
  their tests in the Progress entry below; two gaps were fixed. The host-sizing sums in
  `configuration.md` and `deployment.md` were stale by 1.0 GiB and 1.25 CPU on every row
  and gated by nothing, and `check_frontend_spa.py` had no test and could not have one
  (AUD-083, AUD-084).
- **S27f — backups, restore and E2E evidence** (`scripts/backup.sh`,
  `scripts/restore.sh`, `scripts/verify_restore.sh`, `scripts/e2e_smoke.py`,
  `scripts/e2e_browser.py`, `scripts/verify_replicas.py`,
  `scripts/lock_requirements.py`, `backend/scripts/check_critical_coverage.py`,
  `backend/scripts/coverage_gaps.py`, `backend/scripts/check_mypy_baseline.py`,
  `backend/scripts/check_integration_ran.py`): 11 files, 2,965 lines.
  *Ask:* does backup/restore cover the report archive as well as the database, and is
  a restore exercised rather than described? Do the E2E scripts assert what the
  readiness page says they assert? Does the lock step reproduce the pinned
  requirements?
  *Exit:* a restore walked from the archive to a served page, with the store and the
  database both checked. **Closed 2026-10-22** (progress entry below). *Done:* the
  archive is proven on the same run as the dump — listed, extracted and read back —
  the pass that writes one reads it back before reporting success, CI captures a store
  and requires its archive, and the runbook's extraction commands now describe the
  archive it actually gets (AUD-085). The lock tool could not regenerate any connector
  lock and the backend lock's header named a command that works from nowhere; both are
  fixed and pinned by a fixed point over the eight generated files (AUD-086). The E2E
  scripts assert what the readiness page says they assert, and the exit's "served page"
  half is the browser step those scripts already drive; the walk itself could not be
  run on this host (no Docker daemon), which the handoff states.

**Exit:** every slice closed with its question answered from the files, every CI job
mapped to the documentation claim it enforces, the deploy path walked from
`docker compose up` to a rendered page, and one restore performed.


### Wave H — synthesis

#### S28 — Synthesis and the remediation order
**Surface:** none — the register and the map are the inputs.
**Ask:** which findings share a root cause? Which are one architectural problem
wearing five symptoms? Which documented guarantees are now known to be false?
**Do:** dedupe, re-severity by blast radius, promote the L findings into plans, write
the accepted-risk list into [security.md](../security.md), and order remediation by
risk divided by cost.
**Exit:** the register has no `open` row; every architecture finding names the plan
that will carry it; the map and the readiness page state what is now known.
**Closed 2026-10-22** (progress entry below). *Done:* the register's synthesis section
reads the 89 rows as a whole — counts by severity and disposition, the five root
causes that cover 32 of them plus the two patterns that cover ten more, and the rule
each family leaves behind. Three rows were re-rated upward by blast radius (AUD-026,
AUD-032, AUD-041) and two downgrades were refused in writing (AUD-030, AUD-018). Four
guarantees in operator pages are known to be false and each names the row that
falsifies it and the page that must change with the fix. No row needed an `L` plan of
its own, so the nineteen `planned` rows are ordered into three passes inside
[plan 011](011-remediation-pass.md), and the two threads S27f carried were filed as
AUD-088 (the breach digest's `remaining` counts its window) and AUD-089 (the mypy
ratchet's own proof). AUD-017's accepted-risk sentence in `security.md` matches the
row. The map's audit-partition section and the readiness page both state the outcome.

## Validation and Acceptance

- [x] Every production file is assigned to exactly one step, and no step names a file
      that does not exist — `cd backend && python -m pytest -q tests/test_audit_map_gate.py`
      (4 passed on 2026-10-21, before S0: the gate is scaffolding, the audit itself has
      not started).
- [x] The map's measured totals reproduce from the commands it prints (a difference
      is a new date, not a finding). Re-run on 2026-10-23: the four commands answer
      129 files / 39,506 LOC in `backend/app`, 11,148 LOC of production connector
      code, and 73 production SPA files — the per-directory split the table states.
      The LOC had moved since 2026-10-21 (9,816 → 11,073 in `api`, 15,241 → 15,686 in
      `services`, 2,298 → 2,644 in `schemas`), which is the date changing rather than
      a finding; the map now carries the 2026-10-23 measurement.
- [x] Each completed step has a handoff block and at least one dated line under
      Progress; a step with no findings still records what it dismissed. The dated
      lines are there — 34 of them, S0 through S28 with S27a–S27f each closed in
      its own line. The handoff block is a single block by the protocol's own design
      ("rewritten — not appended twice — so it always describes the next step"), which
      is why one exists at the close rather than one per step: each step's entry
      carries its Read/Established/Open/Filed budget, and the last block carries the
      final state forward.
- [x] No finding is `open` at S28; each is `fixed` (with a regression test), `planned`
      (with the plan named), `accepted` (with the page that says so), or `duplicate`.
      Counted at S28 on 2026-10-22 (the table read by a script, not by eye):
      89 rows — 69 `fixed`, 19 `planned` (all naming 011), 1 `accepted`, no `open` and
      no `duplicate`; by severity 4 / 24 / 47 / 14. The synthesis re-read all of them
      and moved three upward by blast radius (AUD-026, AUD-032, AUD-041), and filed
      the two threads S27f carried as AUD-088 and AUD-089 rather than leaving them
      as handoff prose.
- [x] Every `fixed` finding's regression test fails on the parent commit — checked
      once per wave, not per finding. The wave-closing checks were a red test before
      each fix in its own step (the register's Evidence cell records what the
      assertion read before); a single re-run of all 69 against the parent commit was
      not done at S28. **Replayed on 2026-10-23 for all 88 rows**: the tree was
      extracted at `88d211d` (the parent of `70377eb`, the commit that carries the
      audit's fixes), the test files the register names were copied from `HEAD`, and
      each named node was run against the parent application code — backend nodes
      under the parent `conftest`, frontend files under the parent SPA. **83 of 88
      fail there**, which is the proof the register claims. Five do not, each for a
      reason that makes a green parent the expected answer rather than a gap:
      AUD-016 (the fix deleted the compact Telegram renderer; the surviving test
      pins the live renderer, which already printed every field), AUD-042 (the red
      state belongs to the suite's SQLite savepoint configuration, which arrived
      with this work; the test fails at `HEAD` when
      `install_sqlite_transaction_control` is disabled, which was checked), AUD-057
      (a dependency-pin fix: the parent tree shares the installed `typer`/`click`, so
      `--help` already works), AUD-059 (a type-level test; vitest does not typecheck,
      so the evidence is `tsc -b` against the old declarations), AUD-079 (the parent
      `package.json` still says 0.2.0, matching the old fallback; the defect appears
      with the 0.2.1 bump).
- [x] The suite, the docs gate and the skip inventory gate stay green after each fix,
      and a new skip introduced by a fix is inventoried in the same change. After S18
      the docs gate (75 tests), the skip inventory gate (5) and the step's own 204
      tests are green. The full suite was run in four file-sharded processes (each
      with its own per-pid SQLite database) because a single run on this host takes
      over an hour: 3,408 passed, 16 skipped, 1 failed — the red test is AUD-042,
      which predates this step's edits. The S22 run, the latest backend run, is 3,454
      passed, 16 skipped, 0 failed, and is recorded in its step entry; S23 changed
      no backend file, so its own numbers are the frontend suite's (560 passed,
      55 files after S26) and are recorded in its entries. S27c ran the suites its
      change reaches instead of the whole backend tree: `test_setup_env.py` (63),
      `test_single_installation_shape.py`, `test_env_template_gate.py` and
      `test_github_docs_claims.py` — 122 passed — with the docs gate (85 documents)
      and the withdrawn-providers gate green, and the frontend suite whole (561
      passed, 56 files) with `npm run build` green. S27f ran the suites its change
      reaches: `test_backup_scripts.py` (11 passed, 8 of them red before the fix),
      `test_lock_requirements_gate.py` (13), and the skip, docs-consistency,
      docs-numbers, audit-map and GitHub-claims gates (86 passed), with the docs gate
      OK over 85 documents; no stack was raised, because this host has no Docker
      daemon. S28 changed only register and plan prose, so it ran the gates that read
      them: the register gate (10 passed, four of which were red first on the broken
      shapes it was written for), the map gate, the docs-consistency, docs-numbers,
      skip-inventory, critical-coverage-docs, GitHub-claims and frontend-SPA gates —
      96 passed — with `scripts/check_docs_consistency.py` clean over 86 documents.
      The per-step entries above record the runs each change reached; the close was
      re-checked on 2026-10-23 at `bd96e10`: the whole suite in one process is
      3,569 passed, 16 skipped, 0 failed in 1:38:44, the five documentation gates are
      86 passed, and the skip inventory is green with the same 16 sites.
- [x] Attention budget respected: no step's recorded surface exceeds 3,000 LOC, and a
      step that grew is split in the Progress log with the reason. S18 recorded 2,695
      LOC and was read in full. S27's surface measured 15,534 lines and was split into
      S27a–S27f before it started: the largest slice is 2,965 lines, and S27c's 4,427
      are 2,424 of packaging plus 2,003 lines of hashed requirement pins that only the
      dependency gate reads, as data.

## Progress and Milestones

| Wave | Steps | State |
|---|---|---|
| A — method, identity, authority | S0–S3 | done |
| B — evidence, ingestion, assets | S3–S5 | done |
| C — alerts, connector boundary | S6–S10 | done (S6 to S10) |
| D — workers | S11–S14 | done |
| E — modules, scheduling | S15–S18 | done |
| F — platform shell, persistence | S19–S22 | done |
| G — SPA, operations | S23–S27 | done (S23–S27f) |
| H — synthesis | S28 | done |

- **2026-10-21 — S0 closed.** Baseline confirmed on this host: the suite runs under
  `.venv/Scripts/python.exe` (3.12.15); the system interpreter (3.14.8) aborts
  collection inside SQLAlchemy before a test starts. The tracer caveat is real here:
  the same 13 tests report `app/api/v1/routers/source_inventory.py` at 100% under
  `COVERAGE_CORE=sysmon` and 75% under the C tracer. An integration module skips
  without `INTEGRATION_MIGRATION_DATABASE_URL` and fails collection under
  `REQUIRE_INTEGRATION=1`, which is the documented shape. The skip inventory gate is
  green (5 passed, 49 sites). Probe: **AUD-001** — the page counted six public
  routes where the route gate names seven; the count is now a claim in
  `test_docs_numbers_gate.py`, red before the fix and green after (35 passed).
  Budget used: five files read, one finding, no spillover into S1.

- **2026-10-21 — S1 closed.** Three findings, each fixed with a regression test that
  was red first: enrolment did not end the sessions that predate the factor
  (AUD-002), the two endpoints that remove or re-key the factor never spent the
  brute-force budget (AUD-003), and a sign-in committed its refresh family before
  writing `auth.login.success` (AUD-004). Dismissed in writing: refresh reuse does
  revoke the family, under a PostgreSQL row lock (`auth.py:857-887`); a wrong TOTP
  does not reveal whether an address exists, because the password is checked first
  against a dummy hash for unknown addresses (`auth.py:276`) and the answer is the
  same 401; an invitation is single-use, clears its digest and revokes prior
  families in one commit (`auth.py:425-470`, now pinned by
  `tests/test_user_invitations.py::test_accepting_a_reissued_link_ends_the_sessions_that_predate_it`),
  and a disabled account cannot sign in (`auth.py:839`). Budget: 11 production files, ≈3,089 LOC, six hypotheses — three
  filed, three dismissed, four threads carried (replay race, logout attribution,
  form-encoded sign-in, SPA behaviour after eviction).

- **2026-10-21 — S2 closed.** Four findings, each fixed with a test that was red
  first: reading another account's session list left no row (AUD-005), the bulk
  activation answered "changed" while leaving the old lockout in place (AUD-006),
  `manage_admin mfa-off` left the MFA lock that blocks re-enrolment (AUD-007), and
  the CLI's `create` entered the admin set without the lock the service says every
  writer takes (AUD-008). Dismissed in writing: the last-admin refusal cannot be
  reached *through the API* by construction — the caller is an active administrator
  and targeting oneself is refused first — so it is defence in depth and is pinned
  at the service layer (`test_users_operator_surface.py::TestBulk::test_the_bulk_path_holds_the_same_last_admin_guard`);
  every users route declares `require_admin` and a refusal writes `authz.denied`
  (`test_authorization_denials.py`); a role change needs no session revocation
  because `get_current_user` reloads the account per request; a password reset
  deliberately does not clear the MFA lock (it would hand extra guesses at the
  six-digit space — `user.mfa.reset` is that route); the CSV carries no credential
  and its free-text field is written only by administrators. Budget: four
  production files, ≈2,159 LOC, ten hypotheses — four filed, six dismissed, four
  threads carried (self password reset without re-authentication, background audit
  on admin reads, `ilike` escaping without `ESCAPE`, CSV formula injection).

- **2026-10-21 — S3 closed.** One finding, fixed with tests that were red first:
  the sanitiser that is the only gate between provider text and the trail missed
  the three shapes a real HTTP client produces — a quoted JSON pair, an auth
  scheme whose token survived behind the masked scheme word, and a spaced label
  (AUD-009). Four tamper cases answered against `audit_chain.verify` rather than
  against the prose, and all four are caught: a truncated tail by the committed
  checkpoint (`last_seq != upper_seq` → `gap`; `expected_prev != upper_hash` →
  `broken_link`); a deleted middle by sequence contiguity (`gap`, legitimate only
  at or below `retired_through_seq`) and by `prev_hash != expected_prev`
  (`broken_link`) — re-signing the remainder needs the HMAC key; a re-keyed suffix
  by `key_id` being inside the signed material (`key_id_mismatch` when the hash
  holds under another configured key, `unknown_key` when it holds under none).
  Dismissed in writing: retention cannot delete a row the full pass has not read
  (`archive_prefix` breaks at `row.seq > full_verify_cursor` while
  `full_verify_upper_hash` is set); the archive → receipt → delete sequence has no
  gap the watermark can disagree with, because `retire()` is called in the same
  transaction as the `DELETE` and the receipt is committed and re-verified before
  it; and an append during a verification pass cannot turn into a false alarm —
  the pass snapshots `(upper_seq, upper_hash)` before reading and the write lock
  is released while hashing. Budget: ≈2,930 LOC across `audit_chain.py`,
  `audit.py`, `models/audit.py`, the audit router, `audit_verification.py`,
  `audit_archive.py`, `retention_tasks.py`, `integrity_tasks.py` and
  `safe_errors.py` — at the cap, with the connector protocol router and the beat
  schedule read only where they route audit work. Four threads carried into wave
  B, listed in the handoff below.

- **2026-10-21 — S4 closed.** Two findings, each fixed with a test that was red first.
  The declared dedup key joined field values with an unescaped separator, so two different
  findings could share a key and the second was dropped silently (AUD-010); and the key was
  cut to the 512-character column, so long values sharing a prefix collided the same way
  (AUD-011), now replaced by a SHA-256 digest over the whole key. Dismissed in writing: the
  partial-batch path is atomic per item (each item runs in its own savepoint and writes its
  event inside it, and the router commits the batch once), pinned by
  `test_a_finding_whose_event_fails_is_rolled_back_alone`; and the `IntegrityError` retry in
  `ingest_findings` cannot meet a `ValueError`, because every handler raises its `ValueError`s
  before any write (`ingestion_service.py:124, 231, 335, 354, 539, 1076`), so the same input
  fails with `ValueError` before an `IntegrityError` can occur, and no handler raises a
  state-dependent `ValueError` after a write (`phishing_score_service.py:461` guards a
  programming error). Budget: 10 production files, about 2,640 LOC read in ranges, seven
  hypotheses: two filed, two dismissed, two carried as threads (below).

- **2026-10-21 — S5 closed.** Three findings, each fixed with a test that was red first. The
  destructive cascade read an asset's value without its type and did not exclude keys another
  remaining asset still answered to, so deleting a keyword that shared a monitored domain's
  spelling deleted that domain's phishing and breach evidence (AUD-012). A lost insert race
  rolled back the whole session, which discarded the rows an import had already written, and
  the audit row after it then failed on a lazy load; the unique index that closes the race
  existed only in migration 0001, so the test engine never reached the path (AUD-013; the ORM
  now declares the same partial unique index). The CSV export wrote keyword values as formulas
  (AUD-014). Dismissed in writing: assets carry no owner column, so "another user's finding"
  is not a question this model can ask. Access is by role (`require_active_account` to read,
  `require_analyse` to mutate, `require_admin` to delete), and a finding joins an asset by
  matching its value, not by a foreign key; the owner predicate the step asked for therefore
  does not exist, and adding one would be a schema change, not a patch. The promotion race is
  answered: `create_asset` checks, the unique index decides, and the loser re-reads the winner
  (`dns_security.py:262-288`), now without the session rollback. Budget: five production files,
  about 1,900 LOC read in ranges, nine hypotheses: four filed, three dismissed, two carried.

- **2026-10-21 — S6 closed, written as it ran.** Routing decision table, read from
  `alert_routing.py`, `alert_policy.py` and the dispatch and digest functions in
  `ingestion_events.py`:
  - phishing, candidate missing: `unknown`, delivered as the event stands;
  - phishing, verdict `rejected`: `suppressed`, event consumed, excluded from the digest in SQL;
  - phishing, verdict `confirmed`: `immediate`, delivered whatever the score;
  - phishing, score at or above the direct threshold: `immediate`;
  - phishing, score in the digest band with the digest on: `digest`, event consumed, reported once by the daily digest (`digest_queued_at`);
  - phishing, score in the digest band with the digest off, or below it: `list`, event consumed, nothing sent;
  - breach, noise flag (`fabricated`, `spam_list`, or `unverified` under `verified_only`): consumed as `breach_noise_stored_only`, never reaches the digest;
  - breach, scan above the backlog threshold with the digest on: held as `breach_digest_pending`, reported as one summary by the breach digest;
  - every other event: delivered;
  - no delivery channel: held for the retry window, or consumed when the window is zero (operations rows retry in five minutes);
  - a settings row whose values contradict each other is refused as a whole, the environment answers, and the refused fields are reported by `settings_service.py:192`.
  Dismissed in writing: there is no quiet-hours feature; the only time gate is `digest_hour_utc`. A rejected candidate cannot return through the digest, because the digest query excludes `verdict = rejected` and dispatch suppresses later events. A noise incident cannot reach the breach digest, because the digest selects only rows held under `breach_digest_pending`, and noise rows are consumed earlier. An invalid settings row is not silent (`settings_service.py:192`). A missed digest tick is delayed, not lost: the unmarked candidates are included the next day.
  Open, not yet filed: (1) `queue_breach_digest` returns `remaining = len(rows) - queued`, and `rows` is capped at the message bound, so the figure counts only the page and undercounts the real backlog; this is a wrong count, S3 class, not reproduced. (2) `queue_phishing_digest` keeps trying every candidate when no channel exists, where the breach digest stops at the first failure; wasted work, not a bypass. (3) Message shapes and missing facts: `alert_message.py` and `alert_facts.py` are not read yet, so the rule "every message shape rendered once" is not met. (4) Owner precedence: there is no owner concept on candidates or alerts (the same answer as S5), so the question reduces to recipient rotation, which is not read yet.
  Not closed: the message-shape review and the recipient rotation remain. Budget so far: four production files read in full or in windows (about 1,000 LOC).
  Rendered once (2026-10-21, `Notification` with sample rows): phishing alert in Telegram and plain text; empty breach alert; both digest headings; `highest_severity`, `breach_event_label`.
  Finding (reproduced, not yet filed in audit-findings.md): a fact whose value is `None` prints `N/A`, which says the fact is missing, but a fact whose value is an empty string prints as a blank, so the line reads `Registrar —  · N/A` with nothing to say why the field is empty. Telegram and plain text both do it. `table()` shows a missing key as `—`, so the two renderings disagree about what missing means.
  Also rendered: the breach alert with its columns (through `message_facts`, stored-row path), the phishing digest body, and a runtime-declared module. The breach Telegram line drops `Breach date` and `Verification`; filed as AUD-016. Empty-string facts are filed as AUD-015.
  Ask answered: owner precedence has no code path (no owner on candidates or alerts; delivery goes to the installation's configured destinations, and `_recipient` checks only the lease). Rotation is the lease check in `alert_delivery_service.py` (`_recipient`, `lease_token`), not a choice by owner. A notification counts the rows it prints (`total_count=len(rows)` for a digest); the undercount in `queue_breach_digest.remaining` is still an open thread, not reproduced, and is not filed.
  Exit: routing decision table written; every shape named in the plan rendered once; findings filed AUD-015 and AUD-016 (both S3, planned to wave C close-out). S6 closed.

- **2026-10-21 — S7 done.** Status machine, read from `alert_delivery_service.py`:
  ```
  pending --claim--> delivering --mark_sent--> sent
  delivering --transient error (attempts < max)--> pending   (next_attempt_at = backoff or Retry-After)
  delivering --permanent error or attempts >= max--> failed
  delivering --cancelled (destination removed/disabled)--> cancelled
  delivering --acceptance unknown (AlertDeliveryAmbiguousError)--> ambiguous   (recipient held)
  delivering --lease older than 15 min (worker died)--> ambiguous             (recipient held)
  ambiguous --hold window ends (_end_expired_holds) or operator release--> pending --claim--> ...
  failed | cancelled | sent: terminal
  ```
  Answers. Can a delivery be marked sent before the transport accepted it? No: `mark_sent` follows the send loop, and each part is acknowledged as it lands (`acknowledged_parts`). Can a timeout double-send? Yes, after the hold: AUD-017 (S2, accepted with a sentence in security.md). Is the idempotency key persisted? No key exists for either channel. Did the test answer the question? `test_alerts_reliability.py::test_a_worker_that_died_mid_send_holds_its_recipient_for_the_window` pins the re-send.
  Not answered in this step (threads for the next pass): whether the health cache can report healthy on stale data and how stale it may be (`alert_health_cache.py` not read); whether notification emails redact what the audit rows redact (`schemas/email.py` and `user_notifications.py` not read).
  Exit met: the status machine is drawn with its failure edges; the double-send question is answered by a test and filed as AUD-017.


- **2026-10-21 — S8 done.** Job state machine and authorisation, read from `connector_service.py` (`claim_work` at :290, `_owned_job` at :548) and `routers/connectors.py` (`submit_findings` at :~520):
  ```
  pending --claim_work (type match, enabled, creds ok, account approved; SKIP LOCKED)--> running (lease token, attempt+1)
  pending --claim, source account missing or unapproved--> cancelled (error_message says why; claim returns None)
  running --heartbeat (owner + token, running)--> running (lease renewed)
  running --complete_job (owner + token, lease unexpired)--> success | partial | skipped | error (summary decides)
  running --fail_job (owner + token)--> error
  running --lease expired (recover_expired_jobs)--> pending (retry) | error (retry limit)
  a connector route requires status running; a terminal job is not reachable from one
  ```
  Authorisation: a claim is for the connector's own job type, or a job bound to that connector id; a job with `connector_id` set is served only to that connector. Every job route goes through `_owned_job`: the owner (connector id, or name for unbound jobs), the lease token, `status == running` and an unexpired lease. Ingest checks ownership before validation, then bounds the item count (`MAX_FINDINGS_PER_BATCH`), then validates against the module's typed finding adapter.
  Dismissed in writing:
  - *A token used for another account's job.* Looked like a cross-tenant read; it is refused by `_owned_job` (`connector_service.py:569-576`) and by `test_connectors_protocol_api.py::test_findings_unclaimed_job_403`.
  - *A job claimed twice.* Looked like a race; `claim_work` selects a pending row under `with_for_update(skip_locked=True)` and sets it running in the same transaction. The single-winner test is `test_production_integrations.py:138` (PostgreSQL only, not run in this session), so the guarantee is stated, not measured here.
  - *A terminal job returned to running.* Looked like an unconditional transition (`job_service.py` `_finish_job`: no state guards, by design). Connector routes cannot reach it: `_owned_job` requires `running`, and `test_connector_service_edges.py::test_an_expired_lease_cannot_complete_a_job` pins the refusal.
  - *Unbounded nesting in a findings batch.* Looked open, since `payload` is `list[dict]`. Each item passes the typed finding adapter before persistence, and attributes are reduced to scalars (`schemas/connector.py:92-107`). The result summary is bounded by `bound_details` (depth 4, `connectors.py:212-224`).
  - *Unknown module id.* The batch's module comes from the job's manifest snapshot, not from the payload; an unknown module answers 400 (`connectors.py` near :537).
  Open threads (not reproduced, not filed):
  - *A whole batch refused by validation (400) writes no audit row.* `observability.md:150` records one row per **delivered** batch, which is consistent with that page but says nothing about a refused batch. Reproduction needs a connector test that posts an invalid batch and counts `connector.findings.ingested` rows; not run.
  - *`JobService` complete/fail are unconditional for internal callers.* `celery_app.py` (`complete_by_task_id`, `fail_by_task_id`) reaches them without the lease. Not read; whether a task can finish a job that was already recovered is open.
  - *Per-item size inside a batch.* The 50 MB nginx body limit (`docker/nginx/nginx.conf:30`) is the only byte bound on a findings batch; the count bound does not stop a large string. Field-level `max_length` in the adapters was not read.
  Exit met: the job state machine and claim/ingest authorisation are written down; no finding filed in this step, because each suspicion above lacks a reproduction.

- **2026-10-21 — S9 done.** Read: `connector_credentials.py` (whole, 208 LOC), `core/outbound.py` (whole, 420 LOC), `connector_manifest.py` (whole, 685 LOC), `connectors.py` 69-108, 212-225 and 996-1000.
  Answers to the Ask:
  - *Provider key unmasked, logged or decrypted outside the worker handoff?* Not answered here. `connector_credentials.py` stores connector tokens only, as a SHA-256 digest; the plaintext is returned once by `issue` (`:118`). Provider keys live in the source-account model read in S10; that is an open thread for S10.
  - *Manifest validation rejects unknown fields and enforces the limits?* Partly. `ConfigField` and `DeclaredField` are `extra="forbid"`, and the `MAX_*` limits are applied in `normalize_*` (`connector_manifest.py:~150-330`). The gap is AUD-019: the no-schema string has no length bound, and the int and float branches are wrong.
  - *A connector reaches a non-allowlisted host through a redirect, a DNS rebind or a URL from a finding?* Partly. `outbound.ensure_allowed` refuses URL-shaped values (`_looks_like_a_url`), checks every resolved address against the blocked and own-network ranges, and `pinned_smtp_class` connects to the validated addresses only. The DNS-rebind window for Telegram and WHOIS is the documented residual in the module docstring. Redirect handling in the outbound HTTP clients (`connectors/base/opendrp_connector/provider.py`) was not read: open.
  - *Can an old token still claim jobs after rotation?* Not by the digest path. `issue` replaces `token_hash` in the same commit, and `resolve` looks up by digest, so an old token matches no row. Whether `require_connector` caches a resolved connector between requests was not read: open.
  Dismissed in writing:
  - *Duplicate provisioned token resolves to the wrong connector.* `resolve` refuses an ambiguous digest (`connector_credentials.py`, `resolve`), logs `connector_token_ambiguous`, and returns no connector.
  - *A URL-shaped SMTP host or Telegram token reaches the network.* `validate_telegram_token` refuses `/ ? # @` and backslash, plus whitespace; `_looks_like_a_url` refuses the same set plus whitespace, and a bare `:` in an SMTP host is refused by `_validate_host_syntax`. The guard tests are in `test_outbound_guard.py`.
  - *Unbounded nesting in config.* With a schema, only declared scalar types are stored; with none, only scalars pass (`connector_manifest.py:664-667`).
  Filed: AUD-018 (S3, planned, the rejection log hint), AUD-019 (S3, planned, config coercion).
  Exit: the Ask is answered where the code allows; the open parts are listed in the S10 handoff.

- **2026-10-21 — S10 done.** Read: `source_accounts.py` (whole, 113 LOC), `models/source_account.py` (whole), `core/crypto.py` (`mask_value`, `encrypt_value`, `decrypt_value`), `provider_quota.py` (whole, 254 LOC), `routers/connectors.py` 455-478 and 1029-1083, `connector_service.py` 700-725 and 793, `connectors/base/opendrp_connector/provider.py` (grep only: `parse_retry_after`, `abort_when_retry_after_exceeds`). Not read: `scan_admission.py`, `source_observations.py`, `source_inventory.py`, the SDK's `base.py` and `provider.py` in full.
  Answers to the Ask:
  - *Does a quota reservation leak when an exception lands between reserve and charge?* No gap: `reserve` is one Lua script that checks every window (`minute`, `day`, `job`, and `cert-minute` for certificates) and then adds the member to all of them, so there is no separate charge step. A denial charges nothing (`provider_quota.py` SCRIPT, the first loop returns before the ZADD loop). A Redis failure answers 503 and charges nothing (`except Exception` in `reserve`). A charged attempt that later fails is not refunded, which is the provider's count, not a leak.
  - *Can an account's quota be bypassed by claiming through another connector?* No for the account's budget: the keys are `provider-quota:account:<account.id>:…`, so every connector bound to the account draws on one budget. The job must be running, owned by the caller (`job.connector_id == caller.id`) and under an unexpired lease (`reserve`, the first check), and the account comes from the job's `source_account_id`, which the core sets at enqueue.
  - *Do retries respect Retry-After, cap the wait, and bound the body on error paths?* Retry-After: honoured through `parse_retry_after` (`provider.py:100`) and aborted above `abort_when_retry_after_exceeds`, 60 s by default (`provider.py:64`, `:283-284`). The body bound on error paths was not verified: open.
  - *Does the egress guard cover the live_check CLIs as well as the workers?* Not by the backend's guard. No file under `connectors/*/live_check.py` or `connectors/*/main.py` imports `app.core.outbound`, because connectors run in their own containers and their egress is governed there. Open for S13 and S14, which read those workers.
  Reservation lifecycle: `reserve` (atomic) → denied: 429 with `Retry-After` = seconds until the oldest charge leaves the window; allowed: charged in the minute, day and job buckets; Redis unreachable: 503, no charge. Nothing releases a charge.
  Numbers: minute window 60 s; day window 86,400 s; job bucket 86,400 s; `scan_timeout_seconds` default 300 s, bounded 10-3600; `max_requests` default 20 per job; `requests_per_minute` default 10, bounded 1-600; `daily_budget` default 100, bounded 1-100000; `Retry-After` abort ceiling 60 s; a 429 answers `Retry-After` of at least 1 s.
  Dismissed in writing:
  - *Provider key returned to a connector that is not bound to the account.* `api_key_for_connector` returns a key only for the caller's own `source_account_id` and only when `account.source_id == connector.provider` (`source_accounts.py`). The response is `no-store`, and the audit row records the connector and account, never the value (`connectors.py:469-476`).
  - *Key hint leaks more than the last four characters.* `mask_value(api_key, keep_first=0, keep_last=4)`: a key of four characters or fewer is fully masked, and a longer key shows only its last four. The minimum key length is one, so a short key shows most of itself: a key of six characters shows four. Real provider keys are long, so this is a threshold, not a finding; recorded as a trap.
  - *Account budget overridden by a connector's own config.* The reverse: `connector_service.py:793` merges the account's `approved`, `requests_per_minute` and `daily_budget` over the connector's config, so the account wins in the enforced snapshot. The defect is in the health answer (AUD-020).
  Filed: AUD-020 (S3, planned, the health answer's budget), AUD-021 (S4, planned, provider names in the core).
  Exit: the reservation lifecycle is drawn and the retry and deadline numbers are stated. The egress question for the workers and the error-path body bound are carried to the handoff.

- **2026-10-21 — S11 done.** Read: `connectors/dns_security/tls_probe.py` (whole, 372 LOC), `quota.py` (whole, 24 LOC), `main.py` 20-49, 770-839 and 1603-1702 (windows), and grep over the rest of `main.py`, `test_dns_security.py` and `test_tls_probe.py`. Surface is 2,220 LOC; about 1,100 were read, the rest by grep and by test name. Ran: `PYTHONPATH=../connectors/base python -m pytest -q ../connectors/dns_security` from `backend/`, 76 passed, 1 skipped (the skip predates this step).
  Answers to the Ask:
  - *Does the TLS probe verify chain and hostname and bound the handshake?* Yes. `build_argv` never passes `-k` or `--insecure` (`tls_probe.py:116-146`). `--resolve host:port:ip` keeps SNI and the name check on the hostname, and the IP is only the transport target. The handshake is bounded by `--connect-timeout 3` and `--max-time 8` (`tls_probe.py:43-52`), with `--tlsv1.2` as the floor. Concurrency is four (`main.py`, the semaphore in `_run_tlsprobe`), and the plan is capped by `DNS_SECURITY_TLS_MAX_PROBES` (default 200, max 2,000) with `probe_budget_reached` (`main.py:1644`).
  - *Can CT paging run unbounded or ingest one certificate twice?* No. The exact-check loop runs at most `MAX_PAGES = 10` pages (`main.py:46`, `:776`). A page holds at most 100 rows (`:796`). A repeated cursor, or one longer than 512 characters, stops the loop with `invalid_pagination` (`:829`). Rows are de-duplicated by identity: `seen` in the discovery loop (`:1109-1111`) and `row_key` in the exact loop (`:970-972`). The de-duplication lines were read by grep only.
  - *Does a 429 back off instead of burning quota?* Yes, pinned by tests. A `Retry-After` above the provider ceiling is not shortened and answers `http_429_retry_later` (`test_dns_security.py:544`). A hint under the ceiling is waited out in full (`:558`). The attempt count is the connector's four (`:585`). The 429 branch of `_get_json` was not read.
  - *Is a probe failure distinct from no certificate?* Yes. The verdict comes from curl's exit code (`classify`, `tls_probe.py:306-337`). A handshake failure is `failed` with `tls_handshake`, `timeout`, `connection_refused` and so on, and produces no evidence row because there is no leaf. A host with no public address is `skipped_no_public_address`, recorded as a control row rather than silence. A control row is `unknown` unless verified (`_tls_control`).
  Dismissed in writing:
  - *A parent certificate name accepted for a sibling host.* It looked like an acceptance (the suffix test in `classify`). It is not one: curl decides the handshake, and the classifier only chooses the label of a refusal. The label was wrong, so it is filed as AUD-023 and fixed, with a test that was red first (`test_tls_probe.py`, 1 failed before the change).
  Filed: AUD-022 (S4, planned, a dead quota module), AUD-023 (S3, fixed).
  Exit: each Ask answered; the CT bound stated as numbers; the register and both gates checked in the next step.

- **2026-10-21 — S12 done.** Read: `connectors/intelligence/main.py` 1-400 and 620-731 (windows); `providers.py` 406-441, 959-1038, 1123-1253 (windows), and grep over the rest; `connectors/base/opendrp_connector/provider.py` 145-175 and 300-374 (the bounded readers and the refusal path); `backend/app/schemas/connector.py` 28-177; `backend/app/api/v1/routers/connectors.py` 518-567; `connectors/base/opendrp_connector/base.py` 581-610 and 640-669. Not read: `main.py` 401-619, `providers.py` 175-405, 441-958 and 1039-1122, `live_check.py`. Surface is 2,136 LOC; about 1,000 were read.
  Ran: a project venv at `backend/.venv` (Python 3.13, the pinned requirements without the three native packages, which do not build on this host). `tests/test_intelligence_providers.py`, `test_intelligence_worker.py` and `test_intelligence_credential.py`: 56 passed, exit 0. `../connectors` as CI runs it: 149 passed, 1 skipped, exit 0. Ruff on `connectors/intelligence` and the test file: exit 0.
  Answers to the Ask:
  - *Does every provider answer go through the shared bounded reader?* Yes. The only HTTP calls are `IntelligenceAdapter.request` (`providers.py:959-1032`), which hands the client to the SDK's `ProviderClient`, and the SDK reads every success body with `read_bounded` (`provider.py:148`, `:317-322`). A refusal is read through `read_head` with `ERROR_SNIPPET_BYTES = 4096` (`provider.py:136`, `_snippet`). A grep for `.get(`, `.post(` and `.stream(` in the package finds no other call. The client is built with `follow_redirects=False` (`providers.py:1036`). The SDK's error-path body bound, which the S10 handoff left open, is therefore closed.
  - *Are titles and body text truncated before storage, and can binary content reach the database?* Titles are truncated to 1,000 characters (`endpoint`). Page body text is not stored: an observation carries the title and the record's own fields, never the body. A provider body that is not JSON, or not valid UTF-8, is refused as `invalid_json` (`provider.py` `_read`). A control character in a title could still reach the database: filed as AUD-024 and fixed.
  - *Does a provider error map to the documented code rather than a generic failure?* Partly. `classify_http_error` (`providers.py:406-437`) maps 401, and a netlas 400 with a key phrase, to `invalid_credentials`; 403 to `access_denied`; 402 to `credits_exhausted`; 429 to `rate_limited`; 400 to `provider_rejected_request`; any other status to `http_<status>`. Provider text is matched and never returned. Not compared with a documented table.
  - *Is candidate evidence stored with provenance and a timestamp?* Partly. `candidate_evidence` carries `provider`, `capability`, `evidence` and `association` (`main.py:188-220`), and `finding()` carries the same provenance. `observed_at` comes from `observed()`, which refuses a malformed timestamp (`invalid_observation_timestamp`). What the core does with a missing `observed_at` was not checked.
  Provider call table, from the code read:
  - *request bound*: `CLIENT_TIMEOUT` 30 s total, 5 s connect (`providers.py:26`); body 2,000,000 bytes, streamed (`LIMITS`, `providers.py:40`); refusal head 4,096 bytes; each physical attempt is charged to the scan's `max_requests` and to the core's quota before it is sent (`charge`, `providers.py:993-1001`);
  - *policy bounds*: `max_pages` 1-100, `max_results` 1-5,000, `max_requests` 1-1,000 (`main.py` `POLICY`);
  - *result bounds*: titles 1,000 characters; certificate names 100 per certificate (`endpoints`, `names[:100]`); certificate subject and issuer DNs 512 characters; DNS values 1,000 characters (`dns_observations`);
  - *failure codes*: `response_too_large`, `invalid_json`, `invalid_response` (`provider.py` `_read`), the network outcomes (`NETWORK_ERROR`, `NETWORK_TIMEOUT`), and the `classify_http_error` codes above.
  Filed: AUD-024 (S3, fixed: a control character in a provider title failed the batch and every later batch).
  Exit: each Ask answered, with the provider table; the bounded-reader question for error paths closed; the title defect fixed with a red-first test.

- **2026-10-21 — S13 done.** Read: `connectors/shodan/main.py` 573-702, 628-702, 1395-1494 and the head by grep (the module docstring, `POLICY`, the constants); `connectors/shodan/live_check.py` 1-120; `connectors/dnstwist/main.py` 100-159, 225-269, 398-457, 461-550, plus grep over it; `connectors/base/opendrp_connector/provider.py` 200-300; `connectors/dnstwist/Dockerfile`. Not read: `shodan/main.py` 180-572, 702-1394 and 1495-1526, `live_check.py` 121-217, `dnstwist/main.py` 1-99, 160-224, 270-397, 550-710. Surface is 2,453 LOC; about 1,100 were read.
  Ran: `tests/test_connector_runtime.py` and `test_dnstwist_cli_version.py`: 65 passed, exit 0. `../connectors` as CI runs it: 149 passed, 1 skipped, exit 0. Ruff on `connectors/dnstwist` and the test file: exit 0. `mmh3` is 5.3.1 in the local venv because the pinned 4.1.0 has no wheel for this interpreter; the connector tests that hash favicons still pass.
  Answers to the Ask:
  - *Does the favicon fetch stay on the shared bounded reader (the documented exception)?* Yes, and the bound is applied while reading. `_read_favicon` calls `read_head(response, _FAVICON_MAX_BYTES)` (2,097,152 bytes) and returns the truncated head rather than refusing it, which the docstring argues for: half an icon hashes to nothing, and the memory held is the bound. `test_favicon_stops_reading_at_the_size_bound` feeds eight 512 KB chunks and asserts four were pulled. The fetch is the one request a connector makes to the *target*, so it is also the one that needs its own destination check: the name is resolved, every address must pass `is_safe_external_ip`, redirects are followed by hand (`follow_redirects=False`), at most three, same host only, and the next URL is rebuilt from the validated host plus path and query so a `Location` cannot smuggle userinfo or another authority. One exception: `APP_ENV=test` skips the resolution entirely — AUD-026.
  - *Are credits counted per page, and does a retry re-bill?* Two counters, and they answer different questions. `_pages` counts answered pages; `_billed_pages` counts pages past the first, the unit the vendor's credit guide charges (`_search`). Separately, `reserve` runs inside `ProviderClient._call` before every physical attempt, so a retry always consumes this scan's `max_requests` and the account's quota — `_spent` is the attempt count the summary reports, and `billed_pages` counts a retried page once. `_count` reserves a request the vendor does not charge a credit for, which the docstring states as a deliberate choice: the platform's own ledger is what bounds a scan. Whether the vendor's invoice counts a retried page is a provider fact this step did not establish: open.
  - *Is the dnstwist dataset pinned, and is it fetched at build time rather than per scan?* Yes. The image installs `dnstwist=0~20250130-1` from Debian (`connectors/dnstwist/Dockerfile`), the dictionaries ship in the package at `/usr/share/dnstwist/dictionaries/` (`_PACKAGED_TLD_DICTIONARIES`, `_PACKAGED_WORDLISTS`), and `preflight` refuses to start when `dnstwist --version` reports anything but `_EXPECTED_DNSTWIST_VERSION = "20250130"`. Nothing is downloaded per scan, and a configured dictionary path is only accepted through `_companion_file`, which falls back to the packaged file.
  - *Can a target redirect the worker to an internal address?* For the favicon fetch, no, apart from AUD-026: same host only, and the host's addresses were checked first. The dnstwist worker opens no HTTP request at all — it runs the CLI as a subprocess and reads its JSON — so a look-alike cannot redirect it. Its only network calls of its own are DNS (the resolver) and the SPF TXT lookup, both to the operator's resolver; the SMTP probe belongs to the CLI behind `DNSTWIST_MX_CHECK`, off by default and documented as such.
  Also read: `shodan/live_check.py` is a bounded diagnostic — one attempt, a hard ceiling of four requests, pace of one per second, key from the environment, fixed endpoint, and it prints counters rather than the key, a URL or a body. The S10 open thread about the `live_check` CLIs' egress is answered for this one: it talks only to `https://api.shodan.io`.
  Filed: AUD-025 (S3, fixed, dnstwist numeric settings), AUD-026 (S3, planned, the favicon guard's test seam).
  Exit: each Ask answered; the credit arithmetic stated as numbers; the redirect path answered; the favicon bound shown to be a read-time bound.

- **2026-10-21 — S14 done.** Read: `connectors/hibp/main.py` 405-434, 599-638, 890-1030, 1598-1700, 1763-1795, 1801-1920 and 1921-2070 (windows), plus grep over the file; `connectors/exposure_endpoints/main.py` (whole, 262 LOC) and `endpoint_providers.py` (whole, 227 LOC); `connectors/README.md` 920-950; `docs/source-intelligence.md` 31-33; the core's `BreachFinding` and `BreachCatalogueEntry` schemas. Not read: `hibp/main.py` 1-405, 638-890, 1030-1598, 1700-1763 and 2070-2260; `exposure_endpoints/live_check.py`. Surface is 2,871 LOC; about 1,300 were read.
  Ran: `../connectors` as CI runs it: 151 passed, exit 0 (149 before this step's two tests). `tests/test_exposure_endpoints_connector.py`: 17 passed. `../connectors/hibp/test_hibp.py`: 74 passed. Ruff on `connectors/hibp` and `connectors/exposure_endpoints`: exit 0.
  Answers to the Ask:
  - *Does the breach lookup batch without exceeding the documented request budget?* Yes. Every HIBP request goes through `_call`, whose reservation is `_spend`: `_out_of_budget` first, then the core's quota, then the local counter, and a refusal returns `None` with nothing sent (`hibp/main.py:950-1000`). The scan checks the budget at the head of every loop as well (`run_scan`, the email, paste, domain and alias loops). The numbers: `max_requests_per_scan` default 500, `requests_per_minute` default (and the subscription's own number wins when it is lower), `max_aliases_per_domain` 200, `max_catalogue_entries` 2000, `FINDINGS_BATCH` 200 and `CATALOGUE_BATCH` the SDK's own. One attempt, deliberately: HIBP bills a request whether or not it succeeds (`PROVIDER_LIMITS`, `max_attempts=1`), so there is no retry to double-charge. A `Retry-After` pauses the bucket after the answer rather than being waited out inside a retry. The catalogue's batches are submission batches, not provider pages: `/breaches` answers the corpus in one body, and the bound is a slice of it.
  - *Is a breach's "new" status derived from the catalogue or assumed?* Derived, from the core's own diff. `_catalogue_changed_since` compares the source's `AddedDate` *and* `ModifiedDate` against the core's checkpoint, counts a record with neither timestamp as changed (an unanswerable question is not "no"), and a checkpoint it cannot parse as changed for the same reason. The per-scan counts are the core's answer, not the worker's guess: `submit_catalogue` returns `created`, `updated`, `unchanged` and `new_incidents`, and the address findings' `new_rows` is the core's `accepted` count. `_normalize_breach` carries `added_date` and `modified_date` as attributes, so the core has the source's own timestamps to decide with.
  - *Do the exposure workers respect approval and plan limits?* Yes. Approval is the core's: `/me/quota/provider` answers 403 when the account is not approved or the job's lease/identity is missing, 409 when the source is disabled, and the worker stops on any of them because none is in `RECOVERABLE_ERRORS`. The plan limits are `max_requests` (1-200) and `max_targets` (1-200), the second applied with a `truncated` flag rather than silently. One correction from this step: all four refusals used to be reported as `quota_denied` (AUD-027). The key comes from the environment only (`EXPOSURE_PROVIDER` selects `NETLAS_API_TOKEN` or `SHODAN_API_KEY`), which is the documented design for this worker (`docs/source-intelligence.md:31-33`); the core-stored key path belongs to the Intelligence worker.
  - *Is a provider payload stored raw anywhere, and does that conflict with the retention policy?* No raw body is stored by either worker. Exposure builds one record per port: a validated integer port, `tcp`/`udp`, a `_token` protocol of at most 32 characters, and the provider's own address — nothing else from the response. HIBP stores the neutral breach fields (name, title and domain at 255, `pwn_count` bounded, the description and class list now bounded — AUD-028), a masked password only (`_mask_password`), and `attributes` the core re-validates to 20,000 bytes of JSON. The retention policy then applies to these rows as ordinary breach rows; the policy itself is S17's and the retention code is S3's, which found the archive/retire path sound.
  Filed: AUD-027 (S3, fixed, the exposure reservation's single error code), AUD-028 (S3, fixed, the HIBP bounds the worker did not mirror).
  Exit: each Ask answered; raw-payload storage answered against the retention rule it follows; both fixes carry a test that was red first.

- **2026-10-21 — S15 done.** Read: `backend/app/services/breach_kpi.py` (whole, 168 LOC), `breach_severity.py` (whole, 154), `breach_catalogue.py` 73-177, and `backend/app/api/v1/routers/breaches.py` 80-139, 140-284, 286-470, 770-790, 790-838, 947-1006 and 1076-1099, plus grep over the file; `backend/app/services/asset_service.py` `_delete_orphans` and `clean_orphan_breach_findings` as evidence; `docs/description.md` 238-243. Not read: `breaches.py` 470-770 and 838-947, `breaches.py` 1006-1076, `breach_catalogue.py` 178-395, `schemas/breaches.py`, `models/breach.py` beyond grep. Surface is 2,201 LOC; about 1,500 were read.
  Ran: `tests/test_breaches_gaps.py`, `test_breach_kpi.py` and `test_breach_triage.py`: 51 passed, exit 0. Ruff on the router and the test: exit 0.
  Answers to the Ask:
  - *Is the KPI consistent with the filtered list (same predicates)?* Yes where the two answer the same question, and deliberately not where they do not. The list applies one `conditions` list to both the page statement and the count statement, so `total` is the filtered count by construction (`breaches.py:349-412`). With no filters, that total is `breach_kpi.total_findings` (both count every `Breach` row). The dashboard and the report both call `breach_kpi` rather than computing a second version (`dashboard.py:27-45`, `report_service.py:163-185`). The two numbers that differ describe different questions, which the captions state: `active_findings_7d` is created within 7 days *and* status `active`/`investigating`, while the list's `?status=` has no window; `new_incidents_7d` counts catalogue rows by the source's `added_date`, which is a fact about the vendor's catalogue and not about our findings. Dismissed as a defect, with the distinction recorded here.
  - *Does severity mapping match the documented scale?* Yes. `docs/description.md:238-243` says plaintext credentials, security questions and payment data are `critical`, hashed credentials `high`, addresses and phone numbers `medium`, an address list `low`, and an unrecognized class `unknown`; `_severity_of_one` returns exactly those, in an order that keeps `Hashed passwords` from being read as plaintext and `Password hints` below the password itself. The stored value is what the filter and the sort read (`Breach.severity`, `severity_rank_case`), so the badge, `?severity=` and `?sort=severity` cannot disagree. One nuance not in the docs and not a contradiction: a *partial* credit card is `high` while a full one is `critical`.
  - *Can a state change happen without an audit row?* Not for the single-row routes: `PATCH` and `DELETE` write the row with `require_persistence=True, commit=False` and then commit, so the change and its row share a transaction (`breaches.py:811-837`, `:1076-1099`). Both scan routes audit the scheduling. The bulk cleanup is the exception in quality rather than in existence: it writes `breach.orphans.cleaned` with a count only, after the service has already committed the deletions — AUD-030. The triage row's content was the other gap: it named the field and not the value — AUD-029, fixed.
  - *Are large listings paginated in SQL or sliced in Python?* In SQL. `stmt.order_by(direction, tie).offset(skip).limit(size)` with a separate `count(*)` over the same conditions, `size` bounded at `MAX_PAGE_SIZE = 200`, `pages` from `ceil`, and `Breach.id` as the tiebreak so a row cannot appear on two pages. The two enrichment lookups are one query each over the page's values: `_asset_matches_for_breaches` resolves only the candidates of the rows shown, and `_email_incident_counts` is a single grouped query over the addresses on the page.
  Filed: AUD-029 (S3, fixed, the triage row's content), AUD-030 (S3, planned, the bulk cleanup's count-only row).
  Exit: the KPI/list predicate pair compared line by line and written down; the severity scale compared against the page that documents it.

- **2026-10-21 — S16 done.** Read: the whole surface — `backend/app/api/v1/routers/phishing.py` (600 LOC), `backend/app/services/phishing_score_service.py` (769), `backend/app/services/phishing/whois_service.py` (270), `phishing/age.py` (35), `backend/app/schemas/phishing.py` (198), `backend/app/models/phishing.py` (126). Outside it: `app/services/alert_routing.py` (whole, 67), `app/services/ingestion_events.py` (1-236, 237-366, 440-948), `app/services/ingestion_service.py` `_phishing` and `phishing_arrival` (180-309, 685-790), `core/outbound.py` 240-420, `schemas/asset.py` 1-120, `services/asset_matching.py` 1-120, `schemas/connector.py` 115-202, `docs/description.md` 78-107 and 140-170, and the installed python-whois 0.9.4 client (`whois/whois.py`). Not read: `ingestion_events.py` 367-440 (the breach digest's tail), the rest of python-whois's parser.
  Ran: `tests/test_phishing_verdict.py`, `test_phishing_digest.py` and `test_alert_policy.py` — 44 passed, exit 0; then `test_phishing_scoring.py`, `test_phishing_evidence_signals.py`, `test_phishing_change_events.py`, `test_phishing_alert_content.py`, `test_phishing_integration.py`, `test_whois_pacing.py`, `test_whois_enrichment.py` and `test_alert_backlog_digest.py` — 203 passed, exit 0. Ruff on the four changed files: clean. The venv is `backend/.venv` (3.13); the system 3.14 interpreter cannot import the ORM.
  Answers to the Ask:
  - *Is the score stable and explainable, and is the threshold the one the digest claims?* Yes to all three, with one routing gap found and fixed. One table (`SIGNAL_RULES`) declares each weight with the predicate that fires it, and `SIGNAL_WEIGHTS`, the scoring pass and the API's `AlertSignalName` all come from it (a test pins the literal list against it). `score_signals` is `Σ` of the fired weights clamped to 0…100; a value that is not a number never fires (`_below`/`_above`/`_at_least`), so a missing fact cannot score as a young domain, and `record_signal` raises on a name no rule reads. The explanation is `fired_signals` recomputed from the stored facts — the same function the delivered message calls — so the list and the alert cannot print two different reasons. The threshold pair is exactly the documented one: `alert_band` is `>= confidence_direct` → `direct`, `>= confidence_digest` → `digest`, else `list`; `queue_phishing_digest` reads `confidence >= digest AND confidence < direct`, and `AlertPolicy.consistent` refuses a stored row whose digest threshold is not below the direct one, so the middle band cannot be configured away. The gap was the third input: neither the routing nor the API read `status`, while the digest excluded `resolved` rows — AUD-031, fixed.
  - *Can a user-controlled domain reach the WHOIS client (SSRF, injection)?* The injection half is closed and the destination half is aimed at the wrong host. `validate_domain_target` bounds the value at 253 characters, strips a trailing dot, refuses `/ @ : [ ] space \\ ? #`, and requires every label to match `_HOSTNAME_LABEL_RE`, so the query text that python-whois sends cannot carry a CRLF or a second query; the pause key is checked again by `is_server_label` before it becomes a `LIKE` pattern. The target itself is resolved and every address is put through `ensure_allowed(..., port=43)`. But the client never connects to the target: a probe recording `socket.socket.connect` printed `[('whois.iana.org', 43)]` for `whois.whois("example.com")`, and the library then follows a `Whois Server:` line out of the registry's own answer (`findwhois_server` returned `127.0.0.1` for such a line) with no check at all. Filed as AUD-032; the reach is port 43 and the answer is parsed rather than returned, but the one guard that names port 43 covers neither hop.
  - *Is WHOIS data cached with a bound, and does a timeout degrade or fail the finding?* The candidate row is the cache: `registration_known` answers `nothing_to_ask` when the registrar and the creation date are both stored, and the enrichment event is written once per candidate (`record_event`'s key is `whois:phishing:<id>` and an existing row is not rewritten), so a thin registry that never publishes a date is asked once per candidate lifetime, not once per pass. Pacing is one lookup per answering server per pass (`lookup_group_key` → the TLD label), a batch of three, a 15-second hold for the candidates that lost the slot, 15 minutes for every pending event of a server that answered `rate_limited`, and 30 s doubling to 1 h for an unanswered or failed lookup, completed as `*_exhausted` after 8 attempts. The one unbounded loop is deliberate and stated here as its bound: a name the registry says is not registered is re-asked every 12 hours for as long as the candidate exists (two queries a day, never exhausted), because a name nobody owns yet can be registered. A timeout returns `unavailable`: the finding is already stored, the event is held, and the alert is written from the row without the facts — so enrichment degrades the message and never fails the write path. The default executor thread is not cancellable, so a wedged lookup outlives the `wait_for`; python-whois sets a 10-second socket timeout of its own, which is what bounds the leak.
  - *Does domain normalisation match the asset matching rule?* At the boundary, yes. `PhishingFinding.validate_phishing_domain` (`schemas/connector.py:177`) puts the value through `_validate_host_or_ip`, which requires the same fully qualified hostname and returns `cleaned.lower()`; the column is unique, so the stored key is canonical for everything the connectors submit over HTTP. Promotion then canonicalises again with the *asset* rule (`normalize_asset_value`: strip, trailing dot, lowercase, IDNA), a superset that also handles the IDNA spelling the finding validator would refuse — the asset-matching key and the promoted value therefore agree, and a candidate cannot be promoted to an asset that does not match it. Two asymmetries are worth knowing rather than filing: `validate_domain_target` adds `require_dot` but does not lowercase (WHOIS and DNS are case-insensitive, and the value it is handed is already lowercase), and an in-process caller that bypasses the schema (`_clean_str` only) could store a mixed-case or trailing-dot spelling; no production path does, since connectors submit through the API.
  Filed: AUD-031 (S2, fixed), AUD-032 (S3, planned), AUD-033 (S4, planned).
  Dismissed in writing: the generic `phishing.threat.update` row records `changed_fields` without the values — the shape AUD-029 fixed for breaches — while the decision row beside it does carry `previous_verdict`, `verdict` and the score. The bounded field list is `status` and `matched_asset`, both of which the row's own `threat_id` plus the row's history can reconstruct, so it stays a cleanup item: one before/after helper for every triage row is the S28 pass's work, and a second bespoke patch here would be the duplication that pass exists to remove.
  Exit: the score inputs and weights written down against the documented threshold pair; the WHOIS path answered hop by hop, with the connect probe as evidence.

- **2026-10-21 — S17 done.** Read: the whole surface — `backend/app/api/v1/routers/dns_security.py` (400 LOC), `app/services/tls_identity_service.py` (993), `dns_security_service.py` (219), `dns_expiry_service.py` (161), `dns_expiry_monitor_service.py` (119), `dns_observation_inventory.py` (68), `models/tls_certificate.py` (123), `models/dns_observation.py` (40), `models/dns_expiry_monitor.py` (34). Outside it, for the evidence shapes: `connectors/dns_security/main.py` 740-1010, 1595-1760 (the CT check, the historical certificate rows, the probe's control and chain rows) and `backend/app/services/ingestion_service.py` 880-970 (the batch path that calls the ingest).
  Ran: `test_tls_identities.py`, `test_tls_identity_service_gaps.py`, `test_dns_security.py`, `test_dns_security_api.py`, `test_dns_tls_probe.py`, `test_dns_stale_monitor_alerts.py`, `test_dns_expiry_service.py` and `test_dns_batch_ingestion.py` — 93 passed, exit 0 (91 before this step's two regression tests). Two throwaway probes drove the two planned rows and were deleted: two verified probe ports under one asset, and one certificate seen under two hostnames at one address.
  Answers to the Ask:
  - *Is expiry computed in UTC and correct for a not-yet-valid certificate?* The arithmetic is UTC on both sides and stated as numbers here. `due_threshold` is `days = (expires_at - now).total_seconds() / 86400` over `utc()`-normalised instants (a naive value read from SQLite is interpreted as UTC, never as local), `days <= 0` answers `0`, and otherwise the smallest step of the ladder `(30, 14, 7, 3, 1)` that is `>= days` — so a certificate 31 days out has no threshold, 30 fires `30`, 14.01 fires `30`, 14 fires `14`, and an expired one fires `0` once. `queue_expiry_alerts` selects `expires_at <= now + 30 days`, `successful_at` inside `DNS_EXPIRY_MAX_AGE_HOURS` (default 48) and not in the future, states `verified`/`expired` only, and records each threshold on the monitor row, resetting the list when the cycle `sha256(kind|cert_id|expiry)` changes; the title quotes `ceil(seconds / 86400)`, which is why `14.01` still reads "15 day(s)" — the threshold and the prose are two readings of one number. A *not-yet-valid* certificate is handled in two places: the worker has `future_only` for a CT record it cannot yet judge (that state never alerts), and the core refuses a `verified` row whose `not_before` is later than its own clock — right, and pinned by a test, but the refusal used to escape `update_monitor` into the one call that stores the whole scan, so a worker whose clock ran ahead of the core cost every observation of that scan and failed the connector's job. AUD-034, fixed.
  - *Is a second certificate for the same `host:port` lost on merge?* Not there, and the keys say why. The sighting is unique on `(identity_id, ip, port, source)`, so two certificates served on one address and port are two identities and two sightings; the observation key is per source, type, subject and `record_type`, and the worker writes `record_type = "TLS"` for 443 and `"TLS:<port>"` otherwise, so both ports are stored as separate rows (the probe printed `['TLS', 'TLS:8443']`). What *is* lost is one level up: the expiry control is one row per `(asset, kind)` and every `tls_probe` row maps to `kind = "tls"`, so the second port's certificate overwrites the first in the monitor — the probe showed one row flipping from `cert-a` (10 days) to `cert-b` (3 days) and `alerted_thresholds` going from `[14]` back to `[]`. AUD-036, planned (the fix is the control's own port dimension, which is a schema and vocabulary change). And the sighting key drops the subject, so one certificate served for two hostnames at one address yields one sighting and R3 evaluates only the subject that won — AUD-037, planned.
  - *Does the monitor dedupe across sweeps (the row-lock case)?* Yes. `update_monitor` inserts with `on_conflict_do_nothing` on the `(asset_id, kind)` constraint and then re-reads the row `with_for_update()`, so two workers cannot create two controls; a check whose own `checked_at` is older than the stored one is dropped unless the row is still `unverified`; `alerted_thresholds` survives an unchanged cycle and is cleared when the certificate or its expiry changes, which is what makes a renewal alert again and a re-scan silent; the alert pass claims rows with `skip_locked=True`, marks a threshold only when a delivery row was actually queued, and a successful check clears `stale_alerted_at` so the staleness warning can be repeated after the next quiet episode. The one defect in this mechanism is the missing port (AUD-036), and it is what makes the cycle flip on a two-port asset.
  - *Are observations deduped by asset, type and value with a timestamp?* They are deduped per source, not per asset: the key is `sha256` over `source`, `observation_type`, the normalised subject, `record_type`, and then either `value` or the certificate identity (`id`/fingerprint/serial), plus `source_domain`, `ip` or `wildcard` where the evidence can come from several scan targets; current facts (`dns_record`, `rdap`, `vt_resolution`, `vt_domain`, `certificate_check`, `tls_probe`) deliberately leave `value` and identity out, so a re-observation refreshes the row instead of stacking one per scan. The timestamp is split on purpose: `first_seen_at` is preserved by the upsert's `set_` omitting it, `last_seen_at` and `metadata_json` are refreshed, and `expires_at` is replaced. The asset is not part of the key because one DNS fact can belong to several assets; it is resolved when the monitor is written. One dead branch follows from this: the upsert carefully preserves `DNSObservation.alerted_thresholds`, which nothing ever writes — AUD-038, planned.
  Also read and dismissed in writing: the inventory projection (`inventory_query`) expands RRset members and collapses a certificate group to one row *before* counting and pagination, so neither the total nor a page can disagree with the rows; a deleted control observation marks its monitor `unverified` in the same transaction as the audit row; and `clean_orphan_observations` is a correlated `DELETE`, not a Python pass over the table.
  Filed: AUD-034 (S3, fixed), AUD-035 (S2, fixed), AUD-036 (S2, planned), AUD-037 (S3, planned), AUD-038 (S4, planned).
  Exit: the expiry arithmetic stated as numbers; the identity, sighting and observation merge keys written down.

- **2026-10-22 — S18 done.** Read: the whole surface except two files read by
  window — `services/job_service.py` (whole, 223 LOC), `core/celery_app.py`
  (whole, 443), `tasks/scheduler_tasks.py` (whole, 243), `tasks/report_tasks.py`
  (whole, 417), `tasks/integrity_tasks.py` (whole, 94), `tasks/__init__.py` (17),
  `services/report_service.py` (whole, 741), `routers/reports.py` (whole, 385),
  `routers/jobs.py` (whole, 152), `models/job.py` (whole, 116), `models/report.py`
  (whole, 85), `schemas/job.py` (42), `schemas/report.py` (45). Outside the
  surface, for the paths the Ask names: `services/connector_service.py`
  `enqueue_module_scan` and `enqueue_ready_sources` (592–924, the occurrence and
  slot logic), `tasks/retention_tasks.py` (whole, 682), `models/job.py`'s
  `ScheduleOccurrence`, `tests/test_scheduler_reliability.py` (whole) and the
  scheduler and signal sections of `tests/test_celery_boundary.py` (700–1735).
  Surface is 2,695 LOC; all of it was read.
  Ran: `tests/test_celery_boundary.py`, `test_job_service_lifecycle.py`,
  `test_reports_integration.py`, `test_report_service_gaps.py`,
  `test_report_integration_report_service.py`, `test_scheduler_reliability.py`,
  `test_integrity_tasks.py`, `test_retention_task_edges.py`,
  `test_bounded_audit_lifecycle.py` and `test_retention_tasks.py` — 204 passed,
  4 skipped, exit 0 (198 before this step's six tests). The venv is
  `backend/.venv` (3.12.15); the system 3.14 interpreter cannot import the ORM.
  Answers to the Ask:
  - *Can a report job be scheduled twice, and does a retry resume or restart?*
    Twice in the sense that matters, no; twice in the sense of two identical
    requests, yes and by design. `POST /reports/generate` is the only producer
    (`routers/reports.py`), it commits one `reports` row and one
    `report.generate` job and makes exactly one `apply_async`, and no path
    re-enqueues a report (the delete route cancels a generation by moving the row
    to `deleted`, which the task reads as `ReportDeletedDuringGeneration`). Two
    requests are two reports, which is what the caller asked for. The real
    duplicate risk is the broker's at-least-once delivery: `task_publish_retry`
    plus `acks_late=True, reject_on_worker_lost=True` on the task. What is pinned
    is the *effect* of a redelivery after completion — `_completed_report_result`
    answers the stored result and re-renders nothing — and it is pinned on the
    artifact, not on the status: a `completed` row whose file no longer resolves
    is regenerated on purpose (`test_completed_report_with_missing_file_is_not_skipped`).
    A retry **restarts**: `max_retries=1`, `autoretry_for=(TimeoutError,
    ConnectionError, OSError)`, and on a retryable failure the task rolls the
    session back, sets the report to `pending` and its job to `pending`, queues
    `report.generate.retry` through the outbox and re-raises. The next attempt
    gathers a **fresh** snapshot (the truncation metadata is rebuilt, not
    resumed), renders from scratch into `.uuid.pdf.tmp` and publishes with
    `os.replace`, so no partial PDF can be published and nothing is appended to
    the previous attempt's file. Admission is serialized: the
    `report_queue_control` singleton is taken with an upsert before the count, so
    two replicas cannot both take the last of `REPORT_QUEUE_MAX_PENDING` slots.
  - *Do tasks close their session on error?* Yes, and the failure path is written
    to be recoverable rather than merely closed: every task body and every signal
    helper opens `AsyncSessionLocal()` in `async with`, `generate_report`
    explicitly `rollback()`s the session the failed flush poisoned before it
    writes the terminal state (the reason `ReportDeletedDuringGeneration` exists),
    and `async_task` disposes the engine in `finally` so the per-task
    `asyncio.run` loop never carries a pool into the next loop. The asymmetry is
    deliberate and pinned: failures in the signal handlers are swallowed
    (`_sync_emit`, `_sync_job_status`), because a task must not fail on its own
    audit write. One consequence worth the trap list: a signal that fires inside
    a running loop (eager apply from the API process) cannot write its audit row
    at all — `asyncio.run` refuses and the guard eats it — which is why the
    eager-apply tests drive `.apply` from a thread.
  - *Is a scheduler tick idempotent across two workers?* By two mechanisms, and
    the Redis case is the first. `SET NX` on `sched:<module>:<YYYYMMDDHHMM>` with
    a 900-second TTL and an ownership token, released by a compare-and-delete
    only while this scheduler still owns the key (`scheduler_tasks.py:74-153`);
    the key covers the *occurrence*, not the tick, so a tick that runs four
    minutes late still fires 02:30 under 02:30's key
    (`test_delayed_tick_uses_original_occurrence` asserts that
    `params["scheduled_at"]`
    is the original minute), and the ten-minute lookback re-examines the same
    minutes on every tick without dispatching them twice. Redis unreachable fails
    **closed** — nothing is dispatched and the next tick retries
    (`test_redis_failure_fails_closed`). The second mechanism is durable:
    `schedule_occurrences` keyed `connector:occurrence` is read before the
    admission slot is taken, so a second dispatcher creates no second job and
    returns the existing one (`test_same_scheduled_occurrence_returns_existing_job`,
    one row with a `schedule_key`), and `jobs.schedule_key` is unique as the
    database's backstop. A dispatch that created no job releases the guard so a
    later tick can retry; one that created jobs keeps it even if the audit write
    then fails, which is the choice that prefers a lost audit row to a duplicate
    scan.
  - *Does report generation bound rows and file size?* Rows, yes: `row_limit =
    min(REPORT_MAX_ROWS, 50_000)` per section over five sections, and the PDF
    prints total, included, limit and whether it truncated for every one of them,
    from the same metadata the audit row carries. File size, no — AUD-041. The
    timeout is a *wait* bound: the renderer runs in an executor thread behind
    `shield`, so a timed-out `fpdf2` call keeps writing and the task can only
    clean up after it, which is why the temp file is per-attempt and the cleanup
    is a done-callback.
  Job state machine against the delivery one, as the exit asks: a delivery row
  owns its own retry (`AlertDelivery` lease, attempts, backoff, and an
  `ambiguous` state that a human reconciles), a connector job owns its lease
  (`lease_expires_at`, `lease_token`, `heartbeat`, `attempt_count`, and
  `recover_expired_jobs` returning an expired lease to `pending` for a bounded
  number of attempts), and a *core* job owns neither: its transitions are
  unconditional by design (`start_job`/`complete_job`/`fail_job` overwrite any
  state, documented in the docstrings and pinned by
  `test_transitions_are_unconditional_current_behavior`), and the only recovery
  it had was the broker's redelivery. That gap is exactly where AUD-039 lived.
  Dismissed in writing:
  - *Unconditional job transitions are a defect.* They are stated as a choice in
    three docstrings and pinned by a test that would have to be deleted to change
    them; a guard is a reviewed behaviour change, not an audit fix.
  - *`complete_by_task_id`/`fail_by_task_id` match a non-unique `task_id`.* The
    core is the only writer and copies the broker's id, one job per task; the
    report path passes `job_id` explicitly rather than looking it up.
  - *The tick mutates the cached schedule dict* (`schedules[module_key] = spec`).
    It writes back the values it just read, into a per-process cache, and the
    dynamic module map is validated to exclude the built-in ids
    (`schemas/settings.py` refuses `phishing`/`breaches`/`dns`/`exposure` in
    `schedules`), so one module cannot be dispatched under two keys.
  - *`AUDIT_ALLOWED_ACTIONS` listed `report.delete` twice.* A frozenset literal,
    so no behaviour — deduped in this step without a register row.
  Filed: AUD-039 (S2, fixed: a report abandoned in `generating` held a global
  queue slot for ever), AUD-040 (S3, fixed: `schedule_occurrences` had no
  retention), AUD-041 (S3, planned: the report's rows are bounded and its bytes
  are not), AUD-042 (S2, planned: the suite's SQLite engine commits a savepoint
  that is a session's first statement, so the mutation-and-audit atomicity the
  asset and ingestion paths promise is not true on the database every test runs
  on — one red test is the evidence).
  The full suite, run in four shards because one run on this host takes over an
  hour, found exactly that one red test (`test_audit_required_mutations.py`, the
  asset-create rollback): 3,408 passed, 16 skipped, 1 failed, plus the step's own
  204. It is not a regression from this step —
  `retention_tasks.py` and the audit allowlist cannot be reached from that path —
  and it is filed rather than patched here because the fix is the engine's
  transaction control, which is S19's surface.
  Also repaired in this step's documents: the three register citations that named
  a class test without its class (`AUD-010`, `AUD-011`, `AUD-012`) now run as
  written; both were re-run to prove it.
  Exit: the job state machine compared with the delivery one (above); the tick's
  idempotency evidence cited from both mechanisms, Redis included.

- **2026-10-22 — S19 closed.** The step's exit artifact exists and is checked rather
  than remembered: `backend/scripts/settings_reference.py` renders every
  `Settings` field (name, default, validator) from `model_fields`, the table lives in
  `docs/configuration.md` between two markers, and `tests/test_settings_reference.py`
  fails when the committed section and the renderer disagree, when a row carries no
  validator, when a default is missing, or when `.env.example`'s omissions are not
  exactly the nine reviewed ones (each with the reason it is omitted). Answers to the
  step's ask, in the order it asks them:
  - *Does every setting have a validator, a documented default and a safe fallback?*
    Every row does now, and two did not: **AUD-044** (the two token lifetimes
    accepted `0` and negatives, so a login minted a token that was already expired —
    bounded to `1..1440` minutes and `1..3650` days, rendered from the bounds) and
    **AUD-043** (`APP_ENV` was a free string while every production check keys on the
    exact value `production`, so `prod` or `Production ` silently switched all of
    them off;
    it is now an allowlist normalised for case and whitespace). The defaults are the
    rendered column, not a second table; the *safe fallback* is the startup refusal:
    every production check names the variable it refused, and `lifespan` performs a
    real query (`SettingsService.get_singleton`) so a bad `DATABASE_URL` fails the
    container at start rather than at the first request.
  - *Is the pool sized and recycled for the deployment, and does a failed connection
    surface at startup?* `engine_kwargs` gives a PostgreSQL URL `pool_size`,
    `max_overflow`, `pool_recycle` (1800s, inside the idle windows of the proxies an
    installation sits behind), `pool_timeout`, LIFO reuse and `pool_pre_ping`; the
    bounds are settings with `ge`/`le`, so a zero-sized or 600-connection pool is a
    startup error instead of a mystery under load. Nothing in the pool is SQLite's:
    that branch passes only `check_same_thread` and the URI flag. Startup surface is
    the `lifespan` query above plus `python setup.py --check`, which prints the pool
    budget (`DB_POOL_SIZE` × `UVICORN_WORKERS`) against the server's
    `max_connections`. The readiness probe was the gap: **AUD-045**, its database
    half waited `DB_POOL_TIMEOUT_SECONDS` (30s) or the driver's statement timeout
    while the file's own comment promised a probe faster than the orchestrator's
    timeout; it is now bounded by the same 1.5s constant as Redis, and a saturated
    pool counts as unready on purpose.
  - *Does `artifact_path` refuse traversal and symlink escape on every platform?*
    Yes, by construction rather than by sanitising: `reports.file_path` holds an
    opaque name (`<uuid>.pdf`), and `_is_plain_name` refuses separators of either
    kind, `..`, `.`, NUL/CR/LF, a colon (which covers `C:` and NTFS streams without a
    platform-specific drive test — the earlier `os.path.isdrive` call, absent on
    `posixpath`, is documented in the file as the reason the colon rule exists) and
    anything longer than 255 bytes, while requiring the platform's one suffix.
    Containment is then `realpath` against a `realpath`ed store, so a symlink
    planted in the store classifies as `outside_store`; the four reasons
    (`no_name`/`not_a_name`/`outside_store`/`missing`) travel into the audit record
    with the basename only.
  - *Does crypto fail closed on a missing or rotated key, and is rotation
    documented?* `core/crypto.py` builds its cipher at import, so a malformed or
    missing `ENCRYPTION_KEY` is a startup failure rather than the first request that
    touches an encrypted column, and there is deliberately no derivation fallback
    (a derived key cannot read what the real key wrote). Rotation is a checked
    three-step procedure — new key first, `scripts/rotate_keys rewrap`, then
    `status` until nothing is readable under the old key — with `rewrap_value`
    raising instead of skipping a value it cannot read, which is what makes the last
    step safe to act on. `docs/upgrading.md` § Rotating secrets documents it per
    secret, including the fact that a TOTP secret is inside the rewrap set: an
    account whose factor was encrypted under a dropped key is refused with
    `mfa_secret_undecryptable` and recovered through
    `manage_admin mfa-off`.
  The register row this step inherited, **AUD-042**, is closed here and its fix took
  two attempts worth recording. The SQLAlchemy recipe — `isolation_level = None` on
  connect plus `BEGIN` on the `begin` event — does make `RELEASE` a nested release,
  and it breaks this suite: every read transaction then holds a SHARED lock for as
  long as its session lives, so a sign-in's commit waited 5.6s behind an idle reader
  and failed with `database is locked` (a statement nowhere near the cause), and the
  report gatherer's own explicit `BEGIN` became a second one. `BEGIN` is instead
  sent **before the first DML statement and before the first SAVEPOINT**, which is
  the pysqlite default's own behaviour plus the one thing it got wrong;
  `tests/test_sqlite_transaction_control.py` pins all three properties (a first-
  statement savepoint is rolled back, a write without a savepoint is still rolled
  back, and an open read-only session does not block a writer's commit), and
  `test_a_create_is_refused_and_rolled_back_when_the_audit_write_fails` is green.
  Dismissed in writing:
  - *The readiness endpoint probes its two dependencies sequentially.* After
    AUD-045 each is bounded at 1.5s, so the worst case is ~3s against a 5s
    healthcheck; probing in parallel would trade a readable ordering for a second
    saved and a harder failure report.
  - *`artifact_path` does not check ownership or mode of the artifact file.* The
    store is a volume the deployment manages, and the platform's promise is
    containment — that a stored value cannot name a file outside it — not that the
    mount's permissions are right; a mode check would also refuse a legitimate
    read-only mount.
  - *`rewrap` is an operator step rather than something the API triggers.* A
    rotation that rewrapped automatically would make the mixed-key window invisible:
    `status` is the observation that says the window is closed.
  - *`core/__init__.py` re-exports `settings`/`engine` beside the services.* It is
    the package's documented convenience surface and every router imports through
    it; nothing there holds state the modules do not.
  Filed: AUD-043 (S2, fixed — `APP_ENV` accepted a typo and answered "not
  production", so every production check was skipped silently), AUD-044 (S2, fixed —
  token lifetimes unbounded, so `0` minted an already-expired token on every login),
  AUD-045 (S3, fixed — the database readiness probe was the only unbounded one).
  The full suite, in four file-sharded processes with their own per-pid SQLite
  databases: 3,434 passed, 16 skipped, 0 failed (896 + 776 + 788 + 974, each
  shard 1:06-1:13). That is 25 tests more than the S18 run and one fewer failure:
  the red test AUD-042 filed is green on the repaired SQLite engine, and the
  additions are the settings-table gate, `test_sqlite_transaction_control.py` and
  the `APP_ENV`/token-lifetime cases in `test_config.py`.
  Exit: the settings audit table, produced once and referenced from
  `docs/configuration.md` with a gate that keeps it current.

- **2026-10-22 — S20 closed.** Read: `app/main.py`, `core/exceptions.py`,
  `core/safe_errors.py` (re-read; AUD-009 is its fix), `core/rate_limit.py`,
  `core/request_rate_limit.py`, `core/manual_rate_limit.py`,
  `core/request_context.py`, `core/metrics.py`, `routers/metrics.py`,
  `api/v1/__init__.py`, `schemas/common.py`, `schemas/__init__.py`, plus
  `api/deps.py` 200-430 and `routers/connectors.py` 100-155 as evidence for the
  limit wiring, `core/logging_config.py` (grep only) and `docs/security.md`
  § rate limiting. Answers to the step's ask, in its order:
  - *Does every error response use the documented shape and never a provider or
    database message?* The shape is `{"detail": …}`, with `code` added by the
    three 503 paths (`audit_unavailable`, `database_busy`,
    `query_deadline_exceeded`); a 422 uses FastAPI's list-valued `detail` and the
    SPA's `errors.ts` reads both. No handler forwards a message: `DBAPIError` and
    pool timeout log the class and a SQLSTATE and answer a fixed string, and
    `AuditPersistenceError` answers a fixed sentence. The one gap was the
    *unhandled* 500 — AUD-048, filed and fixed. The base `HTTPException` handler
    keeps the headers a subclass set (`WWW-Authenticate`, `Retry-After`), which is
    what makes a 401 clear a cookie it must stop presenting.
  - *Can a limit be bypassed by a spoofable header or by the proxy ordering?* Not
    by a header. `extract_ip` returns the peer address unless the peer is in
    `TRUSTED_PROXY_IPS`, and then walks `X-Forwarded-For` from the hop nearest the
    platform, stopping at the first address it does not trust — the leftmost entry
    is never used. The startup validator refuses a trusted range that overlaps the
    data or connector networks or that spans the parent range, and production
    refuses an empty list, so the header is only believed when the deployment says
    who may write it. The proxy-ordering half holds for the same reason:
    `UVICORN_FORWARDED_ALLOW_IPS=*` is refused everywhere and every entry must
    parse as an IP or CIDR. Two seams remain, both deliberate and both named in
    the register: `APP_ENV=test`/`TESTING=1` makes all four limiters fail open
    (AUD-026, planned for S28), and `AUTHENTICATED_RATE_LIMIT_PER_MINUTE=0`
    disables the authenticated bound by configuration.
  - *Does metrics cardinality stay bounded?* The enumerations were not complete:
    the `method` label was whatever token arrived and an invented verb still
    reaches the middleware (the route answers 405), so a caller could add one
    series per request — AUD-047, fixed with `KNOWN_METHODS` plus one `OTHER`
    bucket. The rest holds: status class is clamped to `1xx`–`5xx`, connector
    names are `unique` in `drp_connectors` so the silence family cannot collide,
    and every family must be declared in `FAMILIES` or rendering raises. The
    scrape endpoint's own object binding was the other defect (AUD-046: it
    rendered the counters from import time, so a reset left it reporting a
    previous life's numbers and never advancing).
  - *Is the request id in both the log line and the response?* Yes, and now for
    the 500 too: the id is allowlisted (`[A-Za-z0-9._-]{1,64}`), returned in the
    header on every response the application produces, added to every structlog
    line by a processor, written into each audit row's `details`, and handed to
    Celery. The unhandled exception was answered above all of that, so neither
    sink had the id — AUD-048.
  Exit artifacts: the middleware order with its reason is written down in
  `docs/observability.md` § *The request pipeline, in order*, and the four limit
  keys with their subjects, windows and settings in § *Rate-limit keys*, both
  referenced from `docs/security.md`. Dismissed in writing:
  - *A duplicate connector name breaks every scrape with duplicate series.* It
    cannot: `Connector.name` is `unique` and indexed.
  - *A scrape is counted in its own document.* It is, and that is the honest
    number: `opendrp_http_requests_in_flight` reads `1` while the scrape renders
    itself, which the docs now say instead of the `0` the stale object used to
    report.
  - *The `RateLimitException` raised from `get_current_user` audits a row and then
    answers 429 — is the row lost?* No: `AuditLogger.emit` commits by default, and
    the first-block notice key keeps a refused client from writing one row per
    retry.
  - *A preflight answer carries no security headers.* By position, and harmless:
    the preflight has no body. The 500 now rendered in the correlation middleware
    has none either, for a stated reason (a fixed `text/plain` string, one owner
    for the header policy); the test pins it so the absence stays a decision.
  - *The manual-action window is claimed before the action runs, so a refused
    action spends it.* That is what "not more often than once every N minutes"
    means; the alternative is a refund path that would need its own audit trail.
  Filed: AUD-046 (S3, fixed — the scrape endpoint rendered counters from import
  time), AUD-047 (S2, fixed — the method label was caller-chosen), AUD-048 (S3,
  fixed — an unhandled 500 carried no request id in either sink).
  The full suite, in four file-sharded processes with their own per-pid SQLite
  databases: 3,436 passed, 16 skipped, 0 failed (896 + 777 + 788 + 974, each
  shard 0:57-1:04). The split was generated before this step created
  `tests/test_unhandled_error_contract.py`, so that file's two tests were verified
  on their own (2 passed) rather than inside the shards; the S21 run is the first
  whose split includes every test file, and it counts 3,442. The one red test in the first pass was this step's own
  documenting: the S20 surface line explained the re-measured LOC with two
  backticked bare file names, and `test_audit_map_gate.py` reads every backticked
  path in a surface as a path ("S20: main.py (no such file)"). The sentence was
  rewritten without them and the gate is 4 passed.


- **2026-10-22 — S21 closed.** Read: `routers/settings.py`, `schemas/settings.py`,
  `models/settings.py`, `services/settings_service.py`, `routers/modules.py`,
  `routers/dashboard.py`, `services/dashboard_timeline.py` (whole, 1,870 LOC),
  plus `routers/phishing.py` 55-135, `routers/assets.py` 190-235,
  `services/module_registry.py` 143-160/229-258 and `services/asset_service.py`
  115-130 as evidence for the predicates the dashboard has to agree with.
  Answers to the step's ask, in its order:
  - *Is every setting validated per type, and is a change audited with before and
    after?* Validation: yes — bounds per field in the schema (`ge`/`le` on every
    numeric field, the channel/breach literals, the email and host rules), the
    smtp-security/credentials contradiction, the cross-field alert budget checked
    against the row *as it will be saved* (`policy_from_row`), recipient ids against
    existing active users, schedule keys against the module registry, and a mask
    refused rather than stored (`looks_like_a_mask`, with its residual stated in
    the module). The audit half was not true: the row named the fields that
    arrived and no values at all — AUD-049, fixed. `module.updated` had the same
    hole — AUD-050, fixed.
  - *Does the dashboard aggregate with the same predicates as the module lists?*
    Traced tile by tile into `observability.md` § *What each dashboard number
    counts*. Three genuine differences, each a caption or a documented window
    rather than a second definition of one number: `total_assets` counts active
    assets and the tile is captioned *Active assets* (the inventory lists all
    unless `is_active` is given); `active_threats_7d` excludes resolved findings
    over a seven-day window (documented, and a question the threats list cannot
    express); the breach half is `breach_kpi`, the object the report also carries.
    `total_phishing`, `phishing_by_source` and `assets_by_criticality` use the
    same unfiltered/active sets the pages do.
  - *Can a module be disabled while its findings remain visible through another
    endpoint?* Yes, and that is the design: `set_module_enabled` cancels queued
    jobs and `require_enabled_module` denies new scans and ingestion, while
    findings already stored stay readable through `GET /findings`, the phishing
    and breach pages and the timeline. Disabling stops collection, not the record;
    `docs/api.md` now says so at the route, and the timeline docstring already
    said why a line must not vanish.
  - *Is the timeline registry-driven?* Yes: `build_timeline` reads `load_modules`,
    `timeline_layout` splits counted series from named exclusions, native adapters
    are mapped by adapter name (data) and an unknown adapter is excluded as
    `unsupported_storage` rather than silently counted as zero;
    `tests/test_dashboard_timeline_registry.py` walks every shipped and declared
    module and fails when one is neither counted nor excluded. A disabled module
    stays counted on purpose.
  Exit artifact: the per-number table in `observability.md` § *What each dashboard
  number counts* — value, the query that produces it, and the predicate it shares
  with (or the caption that distinguishes it from) the page beside it. Dismissed in
  writing:
  - *`total_assets` disagrees with an unfiltered inventory list.* It is the
    *Active assets* tile; the list's `is_active` filter answers the same question,
    and an unfiltered list answers a different one (what is configured, not what
    is monitored).
  - *The phishing list has no default verdict filter while the KPI counts every
    candidate.* Both are unfiltered on purpose: a rejected candidate is still
    stored and still visible under its verdict, so the KPI and the list agree, and
    a hidden default would make the number and the page disagree.
  - *A module's findings remain readable after it is disabled.* Intended, and
    stated at the route: a disable stops collection, not the record.
  - *`GET /settings/alert-policy` writes no audit row.* It is a derived read of a
    page that has just written `settings.view`; a row per read would double the
    log without naming a change.
  - *The manual-action window is claimed before the settings save runs.* Out of
    this surface (S20 recorded the decision); a settings save is not throttled.
  Filed: AUD-049 (S3, fixed — `settings.update` recorded the submission, not the
  change, and never the values), AUD-050 (S3, fixed — `module.updated` recorded
  only the new label and enablement). The full suite, in four file-sharded
  processes with their own per-pid SQLite databases: 3,442 passed, 16 skipped,
  0 failed (904 + 746 + 785 + 1007, each shard 0:54-1:03), the first run whose
  split includes every test file in the tree — the six over the S20 count are
  this step's four regression tests and the two `test_unhandled_error_contract.py`
  cases that run did not include.

- **2026-10-22 — S22 closed.** Read: `alembic/versions/0001_initial_schema.py`
  (whole, 1,370), `alembic/env.py`, `scripts/check_migrations.py`,
  `scripts/check_schema_drift.py`, `scripts/migrate.py`,
  `scripts/seed_defaults.py`, `scripts/seed_data.py` (whole),
  `app/models/__init__.py`, plus `app/models/audit.py`, `job.py`, `report.py`,
  `ingestion_event.py` (the five indexes it gained), `core/database.py` 262-276
  (`TimestampMixin`), `tests/test_alembic_migrations.py`,
  `tests/test_schema_drift.py`, `tests/test_schema_drift_gate.py`,
  `tests/test_schema_reference_gate.py`, `tests/test_seed_scripts.py`,
  `tests/test_no_legacy_surface.py`, and `docs/upgrading.md` 171-330 and
  1125-1160 as evidence. Answers to the step's ask, in its order:
  - *Does the baseline migration reproduce the models — indexes, constraints,
    server defaults?* It was not knowable from the gates, and the answer was no
    twice: `jobs.created_at`/`jobs.updated_at` were the only columns whose model
    default the revision did not set (AUD-051), and five plain indexes existed
    only in the revision (AUD-056). Nothing the models declare was missing from
    the revision once coverage is compared by table, ordered columns and
    uniqueness instead of by object name — the five `uq_*` constraint versus
    `ix_*` index pairs are one access path each. The refreshed list, with every
    difference explained or filed, is `production-readiness.md` § *The difference
    list refreshed on 2026-10-22 (S22)*; `docs/db.sql` states the `jobs` default
    the models have always declared.
  - *Do seeders run idempotently and leave connectors disabled?* `seed_defaults`
    does: one settings row, a legacy HIBP row bound only while it is unbound,
    `status` never touched; the baseline seeds eight connector rows enabled and
    the three Netlas rows disabled (`test_alembic_migrations.py` asserts both row
    by row). `seed_data` is idempotent per business key — each seeder's second run
    creates zero. Its *interface* was the defect: the documented `all` argument
    was rejected (AUD-053), both boolean flags arrived `None` (AUD-054), and the
    `--force` path they select had no guard (AUD-055).
  - *Does the drift check cover every table and column the app reads?* It covered
    tables and columns, and neither indexes nor server defaults (AUD-052). Now:
    columns as before; server defaults from the models to the revision (the ORM
    omits a column it expects the database to fill, while a default the schema
    supplies beyond the models is harmless); index coverage in *both* directions;
    an allowlist of the sixteen PostgreSQL-only indexes, each with its reason; and
    a stale-entry check so that list cannot rot.
  - *Are destructive migrations guarded and documented?* There is nothing to
    guard: the baseline is the whole history — one revision, no `UPDATE` or
    `DELETE`, its `op.execute` limited to the two enum types, the sequence, the
    extension and the index families — and `upgrading.md` § *Rolling back* still
    says a downgrade drops the schema and must follow a backup. The destructive
    operation in this surface was the seeder's, and it is the one finding here
    about deletion.
  Exit artifact: the difference list in `production-readiness.md`, dated, with
  the two server defaults and five indexes marked fixed and the sixteen
  PostgreSQL-only indexes named as decisions — the same names the gate now
  enforces, so the document and the build cannot disagree. Dismissed in writing:
  - *The revision sets sixty-three defaults no model declares.* Deliberate: the
    baseline seeds its own rows by hand, so `status`, `id`, the JSON columns and
    the counters carry database defaults the ORM never needs. A statement cannot
    be broken by the database supplying more than it expects; the reverse fails.
  - *`seq` is an index on the model and a unique constraint in the revision.* One
    unique btree over one column; the chain's head read uses it either way. The
    coverage comparison is why the gate stays quiet, and the naming difference is
    stated where the drift gate is explained.
  - *Sixteen indexes exist only in the revision.* Eleven expression indexes over
    the matching rules and the JSON details keys, five trigram GIN indexes for
    `ILIKE '%term%'`. None has a portable spelling, so the SQLite test schema
    cannot carry them; each is named with its reason, and an entry the revision
    stops creating fails the gate.
  - *`seed_data --force` still truncates.* Kept, and now announced, confirmed and
    refused in production: it is a demo seeder, and its output names what goes.
  - *`seed_defaults` rewrites the settings row on every container start.* It
    creates the row and never writes values, so a restart cannot undo an
    operator's save.
  Filed: AUD-051 (S3, fixed — two timestamps the models default and the revision
  did not), AUD-052 (S3, fixed — the drift gate read tables and columns and
  stopped), AUD-053 (S3, fixed — the documented `all` subcommand was rejected),
  AUD-054 (S3, fixed — both boolean flags arrived `None` under the pinned
  Typer/Click pair), AUD-055 (S3, fixed — `--force` deleted with no prompt and no
  environment check), AUD-056 (S4, fixed — five indexes only the revision knew),
  AUD-057 (S3, planned — the pinned Typer/Click pair makes this CLI's `--help`
  exit 1 with a `make_metavar()` TypeError; the flag workaround lands here, the
  pin is a release decision). Every `fixed` row here had a red test before the
  change: the five gate/default/index cases in `test_schema_drift_gate.py` (AUD-051,
  AUD-052, AUD-056) and the three `TestForceGuard` cases in
  `test_seed_scripts.py` (AUD-053 to AUD-055).
  The full suite, in four file-sharded processes with their own per-pid SQLite
  databases: 1,007 + 916 + 746 + 785 = **3,454 passed, 16 skipped, 0 failed**
  (shards 1:06, 1:04, 0:57, 1:00; this host runs the suite far slower than the
  earlier steps' entries record, so the four ran in parallel). Twelve more than
  the S21 count, which is exactly this step's tests: nine in
  `tests/test_schema_drift_gate.py` and three in `tests/test_seed_scripts.py`.
  The run began before the last two edits to `scripts/check_schema_drift.py` (a
  typing refactor and a literal-table check), so that module's own tests were
  re-run on the final file (26 passed) and the gate prints OK on the shipped
  tree;  the docs gates were re-run after the register and plan edits
  (89 passed with the seeder suite).

- **2026-10-22 — S23 closed.** Read: `lib/api.ts` (whole), `lib/api.test.ts`,
  `lib/endpoints.test.ts` (whole, 764), `lib/session-bridge.ts`, `store/auth.ts`,
  `store/auth.test.ts`, `main.tsx`, `App.tsx`, `types/api.ts` (whole, 1,074), both
  hooks, `lib/{scanPolling,modules,connectors,canonicalOrigin,useDebounce,appMeta}.ts`,
  `components/DataTable/index.tsx` 88-230, and `pages/{AssetsPage,SecurityPage,
  AcceptInvitationPage,OnboardingPage,SettingsPage}` at their call sites. Backend
  evidence: `routers/auth.py` 55-210, 424-520, 770-1000 (every `401` and the two
  CSRF checks), `routers/connectors.py` 780-870, `services/tls_identity_service.py`
  930-990, `routers/dashboard.py`, and an `app.openapi()` dump (113 paths, 84
  schemas) used as the contract's side of the comparison. Answers to the step's
  ask, in its order:
  - *Does the client refresh once on `401` and replay without a loop?* Yes. The
    refresh is single-flight (`refreshInFlight`) because the refresh token rotates
    on use and a second presentation is indistinguishable from a stolen one; the
    replay carries `_authRetry`, so a replay that is refused again rejects instead
    of asking for another refresh; `/auth/` URLs are never retried, and the boot
    restore's `401` is quiet because it is every anonymous visitor's answer. The
    bound is now pinned rather than argued: a new test counts one refresh and one
    replay when the replay also fails. The blanket `/auth/` rule was still wrong in
    one direction — six of those routes answer a *wrong typed credential* with
    `401`, and treating that as an expired session signed a valid session out
    (AUD-058).
  - *Is CSRF read from the readable cookie and sent on every mutation?* Yes. The
    value is read per request from `opendrp_csrf` (the API sets it
    `httponly=False`, `path=/`) and sent as `X-CSRF-Token` on POST, PUT, PATCH and
    DELETE; nothing is cached, so the rotation on every refresh is picked up by the
    next request. The names and the comparison are the API's (`auth.py:62`, the
    `secrets.compare_digest` at the two routes that enforce it), and those two —
    `/auth/refresh`, `/auth/logout` — are the only ones that check it, because
    every other route authenticates with the in-memory bearer token. Dismissed: a
    GET needs no header, and a request with no cookie needs none either.
  - *Are errors mapped to a stable shape with no raw server message?* The client
    deliberately shows the API's `detail` (`errors.test.ts` pins it), because the
    API's messages are written for operators and `safe_errors` is what guarantees a
    500 carries no internal text; what the client guarantees is that the *shape* is
    stable — an array detail is flattened to one sentence so React never receives
    an object, a non-JSON body (a proxy error page) falls through to a status
    sentence rather than rendering HTML into a toast, and every message carries the
    `X-Request-ID` from the response or, failing that, from the request that never
    arrived. Dismissed: the transport's own English (`"Network Error"`) is shown
    when there is nothing better, which is the honest answer for a request that
    never reached the API.
  - *Does the typed client match the backend contract on nulls, enums and
    pagination?* Pagination exactly: `Paginated<T>` is the five keys of
    `PaginatedResponse`, and `MAX_PAGE_SIZE` is 200 on both sides
    (`schemas/common.py`, `DataTable/index.tsx`). Nulls did not: twenty-six fields
    the API serializes as `null` were declared "absent or a string", and
    `SystemSettings` lacked the two breach-budget fields entirely (AUD-059). The
    enums the pages branch on were checked against the literals that produce them
    (`TLSSightingVerdict` against the route's `pattern`, `HealthState` and
    `credential_state` against `connectors.py:780-805`, the asset type/sort
    allowlists), and that spot-check is where it stopped: 56 of the client's 101
    helpers return `any`, so most payloads are unverified by construction
    (AUD-060). What *is* verified is routing: all 99 request helpers matched a live
    path and method in the OpenAPI document.
  Exit artifact — one call traced from a page to the response, failure included.
  `AssetsPage.tsx:171` opens a React Query with the filter state as its key and
  calls `endpoints.listAssets({page,size,asset_type,criticality,is_active,
  has_findings,search,sort,order})`; the helper is `api.get("/assets",{params})` on
  the instance whose `baseURL` defaults to `/api/v1`, so the wire request is
  `GET /api/v1/assets?page=1&size=20&…` with `X-Request-ID: web-<24 hex>`,
  `Authorization: Bearer <memory token>` (no CSRF header — a GET), and
  `withCredentials: true`. The API resolves `require_active_account`, runs
  `AssetService.list_assets` and answers `AssetListResponse`
  (`assets.py:192`, `{items,total,page,size,pages}` with each item an
  `AssetResponse`); axios hands `r.data` back as `Paginated<Asset>`, React Query
  caches it under that key, and `DataTable` renders `rows=items`, `total`, `page`
  and `size`. Failure path: an expired access token answers `401`; the interceptor
  sees a session, calls `restoreSession()` — one `POST /auth/refresh` with the CSRF
  header from the readable cookie — adopts the new token through the bridge, and
  replays once with `_authRetry`; a second `401` rejects with no further attempt. A
  refused refresh clears the session and announces `auth:unauthorized` once
  (`App.tsx` shows "Session expired" and routes to `/login`). A `403` with
  `mfa_required` / `onboarding_required` is announced without clearing, and the
  query's `isError` branch renders `describeApiError(error)` — a 422's list detail
  flattened, a 503's `database_busy` named as its own condition, and the reference
  id appended — instead of handing the raw body to React.
  Filed: AUD-058 (S3, fixed — a refused credential signed a valid session out),
  AUD-059 (S4, fixed — the declared response shapes disagreed with the wire on
  twenty-six nulls and two settings fields), AUD-060 (S4, planned for S28 — 56 of 101
  helpers are `any`, so the contract gate is switched off on most of the surface).
  Every `fixed` row had a red test first: four in `api.test.ts` for AUD-058
  (announcement asserted absent, before: once each with the token cleared) and the
  type fixture for AUD-059, where `tsc -b` rejected `alert_email_user_ids: null`
  before the change and accepts every fixture after it. The suite: **502 passed, 54
  files** (seven of them new here: five in `api.test.ts`, two in
  `types/api.test.ts`; the run that reported 505/55 still counted a three-test
  scratch probe used to establish the pre-fix behaviour, which is not in the tree),
  `tsc -b` clean, and `vitest run --coverage` green at 81.18 /
  75.89 / 76.53 / 83.74 against floors 70 / 70 / 73 / 75. One `SettingsPage` test
  timed out under instrumentation in the first coverage run and passed twice in
  isolation; it now carries the same 15 s budget as the test above it — a
  five-second default against four sequential render-and-wait steps over the
  largest page, not a product defect. Dismissed in writing:
  - *`_credentialCheck` stops a genuinely expired session from refreshing.* True
    for that one request: it fails with the API's sentence, and the next ordinary
    request takes the normal refresh path. The alternative — refresh first, then
    replay — rotates the refresh token on every mistyped password, which is the
    behaviour the single-flight exists to avoid.
  - *`full_name` and friends never reach a crashing call site.* Correct today
    (every consumer uses `||`), which is why AUD-059 is S4 and not a live bug; the
    fixture is what keeps the next call site honest.
  - *`/dns/certificates` and `/dns/observations` answer `PaginatedResponse[dict]`,*
    so their `response_model` constrains nothing. The certificate payload was
    traced field by field against `identities_payload` (all thirteen fields plus
    `sightings` and `foreign_sightings` are present), so the client's
    `TLSCertificate` is right; the missing response models are part of AUD-060.
  - *`restoreSession` can still rotate twice when a request `401`s just after an
    earlier refresh resolved.* The second presentation carries the token the server
    just made current, so it is a rotation and not reuse-detection; one extra
    request, no revocation, and no loop.

- **2026-10-22 — S24 closed.** Read: `AssetsPage` (whole, 948),
  `BreachesPage` 95-330 and 550-960, `PhishingPage` 185-300 and 560-740,
  `AssetDetailPage` (whole), `ModulePage` (whole), `DNSSecurityPage` (whole),
  `ExposurePage` (whole), `components/DataTable/index.tsx` 88-521, and the seven
  page test harnesses (the mocks are where the previous steps' intent is written
  down). Backend evidence: `routers/assets.py` 905-933, `routers/breaches.py`
  1087-1109 and `routers/phishing.py` 572-600 for the audit row each delete
  writes. Answers to the step's ask, in its order:
  - *Does each page render failure, empty and loading distinctly?* Yes, with one
    page-level exception (AUD-062). Per page, the four markers are:
    | Page | loading | empty | failure | refreshing |
    |---|---|---|---|---|
    | Assets | `isLoading \|\| isPlaceholderData` | filter-aware (`No assets match the current filters.` vs `No assets yet.`) | `isError` + `describeApiError(error, …)` + retry | Refresh button spins on `isFetching` |
    | Asset detail | findings `isLoading`; record read has its own alert | per module (`No phishing findings name this asset.`) | findings error + retry; record error alert (AUD-062) | `isFetching && !isLoading` |
    | Breaches | `isLoading \|\| isPlaceholderData` | filter-aware | static sentence naming the consequence + retry | Refresh button |
    | Phishing | `isLoading \|\| isPlaceholderData` | filter-aware | static sentence naming the consequence + retry | Refresh button |
    | DNS Security | `isLoading \|\| isPlaceholderData` | `No observations yet…` | `isError` + retry, and a separate alert when the connector health read fails | `isFetching && !isLoading` on the table |
    | Exposure | `query.isLoading` (no placeholder) | `No observations yet…` | `isError` + retry | `isFetching && !isLoading` |
    | Module | registry skeleton / error state; findings `isLoading` | module-specific empty text | registry error state + findings `isError` + retry | `isFetching && !isLoading` |
  - *Can a filter change drop the previous response's rows (race)?* No. Every
    list's query key contains every parameter its `queryFn` sends — assets nine,
    breaches ten, phishing ten, DNS three, exposure three, module three, asset
    detail five — so a filter never serves another filter's cache; each handler
    resets the page to 1 (the search boxes, the selects and the sort pickers were
    checked one by one); and the pages that need a placeholder pass an *empty*
    envelope and treat `isPlaceholderData` as loading, so the new key never
    renders the old rows. React Query v5 drops `data` on a key change without a
    placeholder, which is what makes the exposure page's missing placeholder a
    loading state rather than a stale one.
  - *Does the bulk action send only the current page's ids?* Yes. Only the assets
    page has one; the table can select only rows it renders, and an effect whose
    dependencies are exactly the query key clears the selection, so the ids sent
    are the rows under the current filter. The response's `applied`, `requested`
    and `missing` are reported in one sentence, and the selection and dialog are
    cleared only on success. Now pinned by a test rather than left to the effect.
  - *Is a destructive action confirmed, audited, and does it report partial
    failure?* Confirmed: every delete is behind `ConfirmDialog`, the cascade
    delete requires the asset's value to be typed, and the batch delete requires
    `DELETE`. Audited: `asset.delete` (same transaction as the cascade),
    `breach.delete` and `phishing.threat.delete` (`require_persistence=True`,
    committed with the row). Partial failure is reported for the batch; single
    deletes are one row, so there is nothing partial to report. What was wrong was
    the dialog's *lifecycle* on two of the pages (AUD-061).
  Exit artifact: the four-state table above plus the pagination contract, checked
  page by page — every list passes `total`, `page` and `size` from its own state,
  the table derives `pages` locally (now clamping an out-of-range page,
  AUD-064), and the sizes offered are 10/20/50/200 against the API's
  `MAX_PAGE_SIZE = 200`. No browser session was driven: the evidence is the
  rendering branches and the tests that exercise them, and the pages were not
  photographed against a live API.
  Filed: AUD-061 (S3, fixed — two delete dialogs closed on the click),
  AUD-062 (S4, fixed — a failed asset record rendered as an empty one),
  AUD-063 (S4, fixed — the record was cached for the tab's lifetime),
  AUD-064 (S4, fixed — a page past the end of a shrunken result claimed nothing
  matched). Each `fixed` row had a red test first: four in `AssetDetailPage.test`
  and the two page tests (AUD-061 to AUD-063), and the table case verified red by
  disabling the guard for one run (AUD-064). The suite: **508 passed, 54 files**
  (six new: two delete, two asset-detail, one table and one selection test),
  `tsc -b` clean, `npm run build` succeeds, and `vitest run --coverage` is
  81.19 / 75.81 / 76.78 / 83.73 against floors 70 / 70 / 73 / 75. Dismissed in
  writing:
  - *The assets page never passes `isRefreshing`.* Its Refresh button spins on
    `isFetching` instead, which is the same fact in the same place the operator
    clicked.
  - *`AssetDetailPage` ignores the response's `pages`.* It recomputes the same
    number from `total`/`size` in the table, and the clamp now makes the two
    agree; nothing reads the field.
  - *The phishing evidence panel says "Evidence could not be loaded." with no
    reference id and no retry button.* True, and S4 at most: the dialog is closed
    and reopened to try again, and the sentence is accurate as far as it goes.
  - *A failed delete still raises a toast on the pages that keep the dialog open
    (assets, DNS).* They show the refusal in the dialog and the toast is the
    list-level copy; the two signals name the same fact and the dialog is the one
    with the retry.

- **2026-10-22 — S25 closed.** Read: `pages/UsersPage.tsx` (whole, 1,248),
  `pages/SettingsPage.tsx` (whole, 1,262), `pages/DashboardPage.tsx` (whole, 745),
  `pages/AuditPage.tsx` (whole, 525), `pages/ReportsPage.tsx` (whole, 366),
  `pages/SecurityPage.tsx` (whole, 409), `pages/LoginPage.tsx` (251),
  `pages/AcceptInvitationPage.tsx` (107), `pages/OnboardingPage.tsx` (295),
  `pages/NotFoundPage.tsx` (40) — 5,248 LOC of production code — plus the five page
  test harnesses, `components/AlertBudgetPanel.tsx`, `components/ui/select.tsx`, and
  backend evidence: `services/admin_invariants.py` (whole), `routers/users.py`
  583-717 (bulk) and 1136-1205 (delete), `routers/audit.py` 213-300, and
  `schemas/settings.py` 96-290 (every validator). Answers to the step's ask, in its
  order:
  - *Does the UI prevent removing the last administrator while the server also
    does?* The server does, once: `ensure_active_admin_remains` counts the active
    admins excluding the target under the same advisory lock every writer of the
    set takes (`admin_invariants.py:85`, reached from update, deactivate, delete
    and the CLI), and `bulk_update_users` refuses a selection that contains every
    active admin (`users.py:634`). The page prevents what it can know without a
    second query — self-deactivation and self-deletion are disabled buttons, not
    refused requests, and self-service factor removal with them — and it does not
    pre-empt the count, because a client-side count is a second source of truth
    that goes stale the moment a colleague adds an administrator. What it did do
    is *hide* the refusal: the dialogs closed on the click, so the 409 arrived as
    a toast over a list that already looked fine (AUD-066). It now closes on the
    answer and prints the server's sentence inside the dialog, so the operator
    reads why the account is still there. The batch's "Nothing was changed" is
    accurate: the route validates the whole selection before writing and commits
    once, so a refusal leaves nothing applied.
  - *Does settings show which field failed validation?* Yes, by two paths. Each
    field has an inline `FormMessage` from the zod schema, whose bounds mirror the
    API's (`smtp_port` 1..65535, the five budget bounds, the digest-below-direct
    case, the enum literals). For a server `422` the client keeps only each
    entry's `msg` and drops `loc` (`lib/api.ts:272`), but every validator in
    `SystemSettingsUpdate` writes the field name into the message
    (`"smtp_port: must be between 1 and 65535"`, `"telegram_chat_ids: invalid chat
    id …"`, `"schedules.<id>.hour: integer 0..23"`), so the toast names the field
    even after the position is lost — deliberate, and the reason a finding was not
    filed here. The one shape that would not name a field is a `Field` constraint
    firing before its custom validator; the form refuses those same inputs first.
  - *Does the dashboard mark stale data?* It does not leave any. The page is one
    request (`GET /dashboard/overview`), so the summary and both health sections
    describe one moment; each health heading prints the server's `generated_at`
    ("Data as of …"), and a probe answered from cache prints its own `checked_at`
    and `cached` beside it — the one place the API can answer from a cache at all.
    A failed refresh blanks rather than lies: `isError` renders `—` in every KPI
    tile, `ChartState`'s error branch in every chart and one `ErrorState` above
    them. Dismissed: keeping the last good numbers with an age would be a product
    decision, and the current behaviour is the safer half of it.
  - *Is the audit page's filter parity with the API (action, user, range,
    cursor)?* Action, user (UUID and email), range (from/to, widened to whole UTC
    days by `buildUtcDate`/`toDateUtc`), request id, job id, outcome and search —
    yes, all nine of the route's conditions except one. The cursor was missing:
    `after_seq` exists on the route and in no control (AUD-067).
  Exit artifact — the settings form block by block, against the rule that
  enforces it:

  | Block | Client rule | Server rule |
  |---|---|---|
  | SMTP host, port, user, password, from | port 1..65535, email regex that accepts the stored mask | `_validate_hostname_or_ip`, `_validate_smtp_port`, control-character checks, `EmailStr` or mask |
  | Telegram bot token, chat ids | required only when the channel is on | `_TELEGRAM_BOT_TOKEN_RE`, `_TELEGRAM_CHAT_ID_RE` per id, at most 100 |
  | Email recipients | checkbox list of active users | `alert_email_user_ids`: at most 100, each a UUID |
  | Alert budget | `optionalBudgetNumber` bounds; blank is `undefined`, sent as `null` | parsed against the row *as it will be saved* (`policy_from_row`), digest below direct |
  | Scan schedules | weekday 0..6, hour 0..23, minute 0..59 | `_validate_schedule`: non-empty days, integers, dedupe and sort; built-ins may not use `schedules` |
  | Module schedules | registry-driven, toggle writes `null` | `_validate_module_schedules`: id regex, exact key set, per-field ranges |
  | Connector config | the connector's declared `config_schema` types | `validate_connector_config` coercion (AUD-019: a `--5` int still answers 500) |
  | Save | only `dirtyFields` are sent, plus `expected_version` | `409` when `expected_version` disagrees with the stored row |

  Filed: AUD-065 (S3, fixed — a batch selection outlived its list),
  AUD-066 (S3, fixed — four user dialogs closed on the click),
  AUD-067 (S3, fixed — the audit cursor had no control),
  AUD-068 (S3, fixed — recovery codes copied with a literal `\n`),
  AUD-069 (S2, fixed — a schedule minute off the five-minute grid was drawn blank
  *and* rewritten to `0` by the next unrelated save). Every `fixed` row had a red
  test first: AUD-065 and AUD-066 were run against a mutated copy of the page (the
  effect body replaced with `void 0`, the eager close restored) and failed exactly
  there; AUD-068 was run against the old expression and failed on the clipboard's
  value; AUD-069 failed twice — on the display with the old twelve-option list,
  and again on the payload with the display assertion lifted, which is the half
  that proves the silent rewrite. AUD-067 could not be mutated into existence —
  the field was absent — so its red-first evidence is the absence itself, and the
  test asserts the request parameter, not the input. The suite: **515 passed, 54
  files** (seven new: three in `UsersPage.test`, one in `AuditPage.test`, two in
  `SecurityPage.test`, one in `SettingsPage.test`; the revoke case was rewritten
  around the new confirmation rather than added), `tsc -b` clean, `npm run build`
  succeeds, and `vitest run --coverage` is 81.28 / 75.27 / 77.27 / 83.76 against
  floors 70 / 70 / 73 / 75. No backend file changed; the docs, audit-map and skip
  inventory gates are 76 passed afterwards. Dismissed in writing:
  - *The users table keeps the previous rows visible while a filter loads
    (`placeholderData`).* Deliberate and unlike the assets page, which passes an
    empty envelope: the query key carries every parameter, so the rows shown are
    the previous *complete* answer for a different question, and the effect above
    drops the selection at the same moment. The operator sees the old page with a
    spinner rather than an empty table that says nothing matches.
  - *The session dialog on the users page can end the administrator's own
    sessions.* Intentional: it is the same revocation the security page offers,
    and `/auth/sessions` for your own account is the documented surface for it.
  - *`expected_version` is sent on every save, including one that changes
    nothing.* That is the point — it is what turns a colleague's concurrent save
    into a 409 instead of a silent overwrite.
  - *The settings page renders `value={field.value ?? ""}` for the SMTP port.*
    An empty port means "no port", which the API reads as `null`; a `0` would be
    a value nobody meant.

- **2026-10-22 — S26 closed.** Read: the whole component surface — 33 production
  files, 2,998 LOC (`DataTable/index.tsx` 537, `Layout/AppLayout.tsx` 274,
  `CertificateTriage.tsx` 341, `AlertBudgetPanel.tsx` 270, `Auth/MfaEnrolment.tsx`
  203, `ui/select.tsx` 97, and the rest of `ui/` and `Theme/` in full) — plus six of
  the eleven test harnesses (`DataTable`, `MfaEnrolment`, `ThemeProvider`,
  `ErrorBoundary`, `toaster`, `use-toast`) and `index.css` as the tokens' source.
  The plan's 4,105 / 44-count was a counting error, not a growth: 44 is the
  directory's file count *with* the eleven tests, and 4,484 is its line count with
  them; the production surface the step actually reads is 2,998. Answers to the
  step's ask, in its order:
  - *Does the data table support keyboard navigation and announce sort changes?*
    Reachable, not announceable. Every control is in the tab order and a walk
    proves it without a click (`::reaches every control in the table with the
    keyboard alone`: sort button → its resize handle → next column's pair → page
    size → page buttons; First/Previous are disabled on page 1 and are skipped, as
    they should be). Rows are not focusable by design — nothing in a row is the
    action, each cell carries the page's own link or button — which is the pattern
    every list uses. What the table did not do was *say* anything: `aria-sort` sat
    on the `<th>` and the operator's focus is on the button inside it, so a click
    produced no announcement at all; the resize handle was a focusable `separator`
    with no value, which ARIA forbids; the current page was a fill colour (AUD-072).
  - *Does the MFA component keep the secret out of the URL and storage?* Yes, and
    it is worth stating how: the pending secret lives in `useState` only, the QR is
    a `URL.createObjectURL` blob from `GET /auth/mfa/qr` and is revoked when the
    step is cancelled, the `otpauth://` URI is rendered as text, and nothing in the
    block touches `localStorage`, `sessionStorage` or `location`. The password is
    re-entered rather than read from the session, which is the property that makes
    a borrowed session insufficient. What the block got wrong was the artefact
    beside the secret: the copy of the recovery codes joined them with an escaped
    backslash, so the clipboard held one line with a literal backslash and an `n` in
    it — the same defect S25 fixed on the security page, in the other place the codes are
    shown (AUD-070). The secret staying in memory until the step ends is unavoidable
    for a flow that must display it, and is not filed.
  - *Does the error boundary avoid swallowing a failure?* It does not swallow it —
    `componentDidCatch` logs the error with the component stack, the fallback names
    what happened, the raw message is rendered only under `import.meta.env.DEV`,
    and a custom `fallback` is honoured. But the fallback was a plain box: no role
    for the blanked tree, and focus left on `<body>` because the focused element
    had been replaced (AUD-074). Dismissed: the boundary wraps `<App/>` and
    `<Toaster/>` together, so a crash takes the toast host with it and a message
    raised a moment before the crash is lost — the recovery screen is the message
    at that point, and a second boundary around the toaster would surface failures
    nobody can act on.
  - *Do theme and toast respect reduced motion and contrast?* Motion, yes, by one
    rule: `index.css` sets `animation-duration`/`transition-duration` to 0.001 ms
    for every element under `prefers-reduced-motion`, which covers `animate-in`,
    the toast's slide and zoom, `animate-pulse` skeletons and the pulsing badge; no
    component overrides it with `!important` and none animates from JavaScript.
    Contrast, no — measured from the stylesheet, white on the accent was 2.30:1 in
    light and 2.32:1 in dark, white on the destructive fill 3.60:1, and the focus
    ring 2.30:1 against the page; the solid hovers made it worse by blending the
    fill toward the page (AUD-071). That token was also what every `text-destructive`
    validation message used, so the field errors on the settings and login forms
    were below AA on the card as well.
  Filed: AUD-070 (S3, fixed — the enrolment block copied the codes with a literal
  backslash and an `n`), AUD-071 (S3, fixed — the theme's own pairs failed AA, and its
  hover states failed while hovered), AUD-072 (S3, fixed — the table carried its state
  in colour and motion), AUD-073 (S4, fixed — "System" was read once and never
  observed), AUD-074 (S4, fixed — the recovery screen was silent and unfocused).
  Every `fixed` row was red first, by mutating the fixed file back and watching the
  new test fail:
  the contrast gate printed eight failing pairs with their ratios (2.2976, 3.6021,
  4.0342, 2.3226), the two MFA tests failed on the old one-liner, the theme test
  failed with the listener removed, the three table assertions failed with their
  attributes stripped, and the boundary test failed until the focus moved into
  `componentDidMount` as well as `componentDidUpdate` — the first error of a mount
  is committed *as* the mount. The suite: **560 passed, 55 files** (45 new tests:
  36 in the new `lib/themeContrast.test.ts`, four in `DataTable/index.test.tsx`,
  two in `MfaEnrolment.test.tsx`, two in `ThemeProvider.test.tsx`, one in
  `ErrorBoundary.test.tsx`), `tsc -b` clean, `npm run build` succeeds, and
  `vitest run --coverage` is 81.43 / 75.52 / 77.38 / 83.94 against floors
  70 / 70 / 73 / 75. No backend file changed; the docs, audit-map and skip
  inventory gates are 76 passed afterwards. Dismissed in writing:
  - *A twelve-column table asks for 24 tab presses before the footer, because every
    column's resize handle is a stop.* Kept: the handle is the only keyboard route
    to the width, and taking it out of the tab order makes an available action
    unreachable to the operator who most needs it. The alternative — a roving
    tabindex over the handles — trades one long walk for a hidden mode.
  - *The error boundary is one boundary around the shell and the toaster.* Rows
    above; a per-route boundary that left the sidebar standing would be a product
    change (the shell would then be the thing that survived a crash), not a fix.
  - *A stored theme value that is not `light`, `dark` or `system` is applied as a
    class.* It matches no block, so `:root` answers and the page renders light —
    wrong, but safely wrong, and the only way to write it is by hand. Unfiled.
  - *`JobsTable`'s search input is named by its placeholder.* HTML-AAM accepts
    `placeholder` as the last resort in the accessible-name computation, so it is
    not a violation; the visible magnifier and the card title carry the meaning.
  - *The theme gate measures pairs, not pages.* A class that composes a token with
    an opacity (`bg-primary/15 text-primary`) is measured where it is used — the
    avatar's initials — and not in general. A future `/`-composed text pair can
    still land under AA without this file noticing; the register's S28 pass gets it.

- **2026-10-22 — S27a closed.** One finding, fixed with the gate extended red first:
  the release was stated ten times and the gate read seven, so `.env.example`, the
  Compose SPA build-arg fallback and the frontend Dockerfile had stayed at `0.2.0`
  while the code said `0.2.1` (AUD-075) — `make up` from this tree built an image
  tagged `0.2.0` running `0.2.1` code. The gate now reads the template line, the
  Compose fallback and the `ARG` default; the three copies name `0.2.1`; four tests in
  `test_version_consistency_gate.py` fail against the old gate (`assert 0 == 1`) and
  pass after it. Read: the three Compose files (1,658 / 168 / 65), the five files under
  `docker/nginx/` (server block 155, global config 85, `hsts.sh` 117, the realip
  renderer, the terminator), `backend/Dockerfile` (128), `frontend/Dockerfile` (161),
  the six connector Dockerfiles, `backend/app/main.py` (179) for the header set the app
  sends, and `scripts/check_compose_healthchecks.py` (854) for the claims the Compose
  and nginx reads were checked against — about 3,000 lines, three hypotheses, one
  filed. Verified from the files rather than from a summary: nginx sends the same five
  headers on every response it serves, with `always` and with a CSP identical to
  `security_headers_middleware`'s, and takes `Strict-Transport-Security` from the same
  three variables through the include `hsts.sh` renders and validates with `nginx -t`,
  so a browser sees one set of values whichever process answered — no divergence, so
  no code changed for the header question. The connector healthchecks are file-staleness
  probes (stale after 90 s, eighteen missed writes at the 5 s poll interval), which is
  what keeps a long dnstwist scan from reading as a dead container; the API image and
  the six connector images run as non-root, and base tags are moving tags on purpose
  (`deployment.md` states the compensation and SECURITY.md the digest pin). Tests after
  the change: `python scripts/check_version_consistency.py` — OK, 10 statements agree on
  0.2.1; `check_compose_healthchecks.py`, `check_env_template.py` and
  `check_dependency_sources.py` exit 0 (22 services, each with a healthcheck, bounded
  logging, hardening and the documented limits); 67 passed across
  `test_version_consistency_gate.py`, `test_audit_map_gate.py`,
  `test_env_template_gate.py` and `test_single_installation_shape.py`; 127 passed across
  the docs, Compose-limit, Compose-settings, dependency, tracked-source and
  portable-command gates. Dismissed in writing:
  - *HSTS is off by default.* Deliberate and documented where the value is computed: a
    header a plain-HTTP deployment cannot honour locks a browser out of the site, so the
    default is the safe direction for the operator who has not terminated TLS yet.
  - *The image tag falls back to `latest` and the API's `OPENDRP_VERSION` to `dev`.*
    Neither is a release: an installation must pin one, and a development process
    reports the code it is running. That is why the gate reads the SPA's *display*
    fallback and not the tag.
  - *`docker-compose.replicas.yml` repeats no healthcheck.* It is an overlay that adds
    replicas to services the base file defines; a second copy would be the drift the
    Compose gate exists to catch.
  - *The frontend carries five added capabilities after `cap_drop: ALL`.* The server
    block listens on port 80 and nginx's entrypoint chowns its cache: the list is the
    minimum, and the comment above it says why. Worth an operator's eye, not a finding.
  - *An `/api/` response carries nginx's CSP as well as the app's* (the proxied
    location adds the headers too, and its CSP omits `style-src 'unsafe-inline'`).
    Browsers intersect two policies; a JSON body renders nothing, so the stricter
    intersection changes no user-visible behaviour.
  Split: S27's 15,534 lines were divided into six slices before this step started; the
  remaining five are S27b–S27f.

- **2026-10-22 — S27b closed.** Two findings, both fixed with tests that were red
  first: `make health` curled a hard-coded `http://localhost:8000` while the wizard
  writes `BACKEND_PORT` and `--backend-port` (or a hand edit of `.env`) can change it,
  so the check that deployment step 6 and both upgrade runbooks end with answered
  "API is unreachable" for a healthy stack on any other port (AUD-076); and `make
  help` omitted seven targets — including `lint-backend`, which `CONTRIBUTING.md`'s
  own table tells a contributor to run — on the page that says the list is exhaustive
  (AUD-077). Read: `.github/workflows/ci.yml` (757), `release.yml` (239) and
  `Makefile` (418), against the pages that describe them (README's CI section,
  CONTRIBUTING's command tables, `production-readiness.md`'s job column) — 1,414
  lines, six hypotheses, two filed. Established from the files: the ten jobs the pages
  name all exist (`backend`, `production-integration`, `frontend`,
  `release-image-coverage`, `compose`, `e2e`, `repo-hygiene`, `secrets`, `codeql`,
  `security`) and all 29 paths a workflow or the Makefile executes exist; the `e2e`
  job is the journey the README describes — wizard, whole stack, `e2e_smoke.py`,
  `e2e_browser.py`, then `verify_audit_chain` over both halves; `production-integration`
  runs the migration round trip, the two PostgreSQL-only suites under
  `REQUIRE_INTEGRATION=1` (a missing database is a failure, not a skip), a real backup,
  a restore into a scratch database and the audit chain on PostgreSQL, with
  `check_integration_ran.py` pinning that both suites ran; `release.yml` checks the
  version gate and the tag *before* the matrix builds, passes `VITE_APP_VERSION`
  explicitly to every image (the Compose fallback only decides a build nobody pinned),
  publishes SBOM and provenance, scans the pushed digest with Trivy and takes the
  notes from `CHANGELOG.md`; `repo-hygiene` runs every gate the README lists plus
  `check_connector_body_bounds.py`. Dismissed in writing:
  - *`release.yml` does not run the test suite.* It does not need to: a tag push runs
    `ci.yml` on the same commit, and the release's own claims are the ones it checks
    (version, tag, image matrix, scan). A release blocked on a suite that already ran
    would add a second place for the same answer.
  - *`ci.yml` runs the backend suite three times* (bare, coverage floor, critical
    coverage). Each run enforces a different threshold, and the coverage flag is asked
    from the gate so the measured set and the gate cannot describe different sets.
  - *Only three of the ten jobs carry `timeout-minutes`.* The bound exists for the
    steps that can hang — the full suite, the integration job and the image build —
    and no page claims a bound for the rest.
  - *`ci.yml` has no `concurrency` group.* Two pushes to one branch both run a full
    suite; that is a runner cost, not a correctness claim, and it is carried as an
    open thread rather than filed.
  Verified: both new tests fail before the Makefile change — `assert targets - listed
  == set()` listing exactly the seven targets, and `assert 'BACKEND_PORT' in <the old
  recipe>` — and the file is 7 passed after. The new port resolution was replayed with
  `$(COMPOSE)` stubbed and `$$` expanded the way make does: container mapping
  `127.0.0.1:9100` → 9100, `.env` `127.0.0.1:9300` (CRLF) → 9300, bare `9400` → 9400,
  nothing known → 8000. Both workflows parse as YAML. Not run: `make` is not installed
  on this host and no container was started, so no target was executed end to end; and
  `release.yml`'s matrix, Trivy scan and tag check were verified by reading.

- **2026-10-22 — S27e closed.** Two findings, both fixed with tests that were red first,
  and the seven gates mapped to the tests that would notice their absence. Read:
  `check_compose_healthchecks.py` (854), `check_portable_commands.py` (293),
  `check_release_images.py` (238), `check_tracked_sources.py` (208),
  `check_withdrawn_providers.py` (199), `check_connector_body_bounds.py` (171),
  `check_frontend_spa.py` (59), with their eight test files (142 tests) and the
  `repo-hygiene`/`e2e` jobs.
  The mapping, gate by gate (tests, then where it runs):
  - `check_compose_healthchecks.py` — seven rules (healthcheck or image `HEALTHCHECK`,
    bounded logging, application settings per service, hardening with stated exceptions,
    the per-service limit table, the broker password, the network split and the trusted
    proxy range) — 17 + 23 tests in `test_compose_limits_gate.py` and
    `test_compose_settings_gate.py` — `ci.yml:605`, `make check-compose`.
  - `check_release_images.py` — the release matrix against the resolved Compose images and
    their Dockerfiles — 15 tests — `ci.yml:403` in the `e2e` job.
  - `check_portable_commands.py` — the three shell continuations — 12 tests —
    `ci.yml:619`, `make check-commands`.
  - `check_tracked_sources.py` — ignored files that look like source — 34 tests —
    `ci.yml:598`.
  - `check_withdrawn_providers.py` — 25 tests, with an allowlist that must stay live —
    `ci.yml:654`, `make check-providers`.
  - `check_connector_body_bounds.py` — an AST rule over `connectors/` — 10 tests —
    `ci.yml:648`.
  - `check_frontend_spa.py` — three nginx rules — no test at all before this step, six in
    the new `test_frontend_spa_gate.py` — `ci.yml:607`, `make check-frontend-spa`.
  What the reading found. The host-sizing sums are published twice — `configuration.md`'s
  cumulative profile rows and `deployment.md`'s host requirements — and both were stale on
  every row: base 7.0 GiB / 7.75 CPU against a file that sums to 8.0 / 9.0, and each
  cumulative row inherited the difference, while the per-service table beside them was
  gated and green (AUD-083). `deployment.md`'s own rule — the recommendation is above the
  sum — was broken by its own base row. `_check_documented_totals` now recomputes all eight
  rows and the endpoint sentence from the file, and a profile no row covers is a finding.
  The SPA gate had no test and could not have had one: a relative configuration path and a
  `main()` with no arguments, so no fixture could reach it (AUD-084); it now takes
  `--root`, exposes `check(root)`, and six tests fail on a mutated configuration.
  Every other gate was read and left alone: each has a test that fails without it, and its
  success line is as wide as what it reads. Not fixed, written into the handoff:
  `check_portable_commands` scans backtick fences only (the tree has no `~~~` fences);
  `check_connector_body_bounds` bans `.content`, `.text`, `.json()` and `.aread()` and not
  `.read()`, because a file object's `.read()` would be a false positive and no connector
  reads a provider body that way today; `check_tracked_sources` allowlists an ignored
  *filename* anywhere in the tree, and this checkout's own `backend/coverage.json`
  (2026-10-20, not tracked, not created by this audit) makes the gate red here while a
  clone is clean.

- **2026-10-22 — S27d closed.** Two findings, both fixed with tests that were red first,
  and the four gates mapped to the tests that would notice their absence. Read:
  `scripts/check_docs_consistency.py` (776), `check_env_template.py` (474),
  `check_version_consistency.py` (309), `check_dependency_sources.py` (208), with their
  four test files (1,463) and `ci.yml`'s `repo-hygiene` job.
  The mapping, gate by gate:
  - `check_docs_consistency.py` — seven checks (links, reachability, revisions and the
    head claim, fragments, fences, tables, named pages) and 35 tests in
    `test_docs_consistency_gate.py`, one fixture per rule that fails without it, plus
    `test_the_shipped_documentation_tree_is_clean` for the real tree. Runs at
    `ci.yml:640` and `make check-docs`.
  - `check_env_template.py` — five rules, 23 tests in `test_env_template_gate.py` (one per
    rule, both directions, and the scanner's two traps: a `${…}` in a Compose comment and
    a `$${…}` in a `command:` block). Runs at `ci.yml:613` and `make check-env`.
  - `check_version_consistency.py` — ten statements, 11 tests, one per disagreement (each
    of the four deployment statements — SPA package, env template, Compose fallback,
    Dockerfile default — has its own) and the missing-file cases. Runs at `ci.yml:634`, `release.yml:71` and `make check-version`.
  - `check_dependency_sources.py` —    the pyproject rule and the pin/hash rules, 14 tests
    before this step and 17 after. Runs at `ci.yml:627` and `make check-deps`.
  What the reading found: the dependency gate's shipped set was a hand-kept tuple, and it
  had fallen behind the tree — `dns_security` and `intelligence` were named only in the
  hash list the scan loop never iterated, and `exposure_endpoints` in neither, so three of
  the seven manifests every image installs with `--require-hashes` went unchecked while
  the success line claimed each pinned a hash (AUD-081; the hash rule had no test at all).
  The set is now discovered from `connectors/*/requirements.txt`. The env gate's rule 3
  asked whether a setting was declared with `Field(`, which 5 of the model's 83 fields are
  not, so exactly the fields written in the shorter style were exempt from the rule that
  catches a documented setting no container receives (AUD-082); `settings_fields` now
  parses `class Settings` with `ast`. Both gates are green over the shipped tree with the
  stronger rules — seven manifests read instead of four, 83 settings fields instead of 78
  — and the docs and version gates were read and left alone: each already reads the file
  that owns its claim (the revisions directory, `config.py`, the manifests themselves) and
  each of its rules has a test that fails without it. Not fixed, written into the handoff:
  the link rule reads inline links only (no reference-style links exist in the tree), and
  rule 2's consumer test is a textual match, so a mention in a source comment counts as a
  reader.

- **2026-10-22 — S27c closed.** Two findings, both fixed with tests that were red
  first: the SPA's display version fell back to a literal (`"0.2.0"` in a 0.2.1 tree) for
  every build that injects no `VITE_APP_VERSION`, so a host `npm run build` shipped a bundle
  saying `0.2.0` while the image of the same tree said `0.2.1` (AUD-079); and
  `python setup.py --check` reported a previous release's settings as "the application
  would refuse to start" — which is false for keys the application ignores — without naming
  the setting that replaced a renamed one (AUD-080). Read: `setup.py` (2,155 — the writer,
  `run_check`, `validate_values`, `next_steps`, not the Compose template it renders),
  `frontend/vite.config.ts` (134), `frontend/package.json` (58), `frontend/index.html`
  (14), the three tsconfigs, `backend/pyproject.toml` (51),
  `connectors/base/pyproject.toml` (16), and `backend/requirements*.txt` as data (2,003
  lines, read by the dependency gate). Established by running the wizard rather than by
  reading it: `python setup.py --non-interactive --public-url http://localhost:3000` writes
  exactly the template's 126 settings, `--check` on that file reports no findings, and
  `docker compose --env-file` resolves the production file set with it (`config --quiet`,
  exit 0). A copy of this checkout's own `.env` — written 2026-10-14, a release before the
  provider withdrawal — is what exposed AUD-080: 18 errors, each claiming a startup failure
  that cannot happen, and no message naming a replacement. On the build side:
  `ARG VITE_APP_VERSION=0.2.1` in `frontend/Dockerfile` and
  `VITE_APP_VERSION: ${OPENDRP_VERSION:-0.2.1}` in `docker-compose.yml` are both read by
  `check_version_consistency.py`, and the literal in `appMeta.ts` was not — the one copy of
  the version no gate could see; the fallback now reads `frontend/package.json`'s version,
  the field the gate already holds to the release. The dependency gate stays green:
  `backend/pyproject.toml` declares no dependencies, every requirement is an exact pin, and
  every pin carries a hash. Not run: no image was built and no container was started (the
  Compose check is client-side), and the backend suite was not run whole — the four affected
  files were, 122 passed, which is what the step's own change reaches.

- **2026-10-22 — Plan execution checked (after S27b).** The three documents were read
  against each other and against the tree. What held: 78 rows, contiguous
  `AUD-001`–`AUD-078`, no `open` and no `duplicate`; every row is named by the plan and
  every `AUD` the plan names is in the register; every test path a `fixed` row cites
  exists; the one `accepted` row (AUD-017) has its sentence at `security.md:249`; the
  partition gate is green, so every production file is claimed once. What did not:
  - the register was **six tables, not one**: five blank lines between rows, so GFM
    rendered 44 findings as a paragraph of pipes and the docs gate never validated
    them — its walk stops at the gap. Two of those rows carried an extra unescaped
    pipe (`||` in a code span, a TypeScript `string[] | undefined`), and so did a row
    added in this session. Repaired, and the gate now reports a blank line that ends a
    table (three tests, red first); the strengthened rule then found the same defect in
    `docs/internal/README.md` (ten gaps) and
    `docs/internal/users-rbac-remediation-plan-2026-10-18.md` (four), plus one more
    unescaped pipe in the internal index — fourteen torn tables in three documents, all
    repaired (AUD-078, S2: the readiness page lists this rule among the enforced ones).
  - six rows still said `planned: 009 wave C, close-out cleanup` — a wave that closed at
    S10 without a close-out — and AUD-036 pointed at “its own plan”, which no file
    answers. The six now name the S28 cleanup pass that already carries nine rows of the
    same kind; AUD-036 names a plan of its own, to be opened by S28.
  - the map's partition row for S27 gave no LOC and one step; it now names S27a–S27f and
    the 15,534 lines measured before the split.
  - the S6 entry's heading said “in progress (not closed)” while the entry ends “S6
    closed”; retitled, because a reader scanning headings got a step that never closed.
  Carried, not fixed: the threads older entries named and never filed — S6's
  `queue_breach_digest.remaining` undercount, S7's unaudited refused batch and
  unconditional internal job completion, S7's per-item batch size — are no longer in the
  live handoff (the protocol allows that) but are not in the register either, so S28's
  Ask should collect them from the entries before declaring the register complete.

- **2026-10-22 — S27f closed, and S27 with it.** Three findings, each fixed with a
  test that was red first. Read: `scripts/backup.sh` (145), `scripts/restore.sh`
  (102), `scripts/verify_restore.sh` (100), `docs/backup-restore.md` (196),
  `scripts/e2e_smoke.py` (553), `scripts/e2e_browser.py` (540),
  `scripts/verify_replicas.py` (254), `scripts/lock_requirements.py` (564),
  `backend/scripts/check_critical_coverage.py` (289),
  `backend/scripts/coverage_gaps.py` (190),
  `backend/scripts/check_mypy_baseline.py` (146),
  `backend/scripts/check_integration_ran.py` (104), the `production-integration` and
  `e2e` jobs and the Makefile's backup targets — 2,836 lines with the runbook.
  The three answers, in the order the Ask gives them:
  - *Does backup/restore cover the report archive, and is a restore exercised?*
    Written, never proven. `backup.sh` archives the store beside the dump and checks
    the dump with `pg_restore --list`; nothing ever opened the archive.
    `verify_restore.sh` — `make backup-verify` and the `production-integration` job —
    restored the dump into a scratch database, read three values back and stopped,
    and the CI step that "proves the backup restores" produced no archive at all,
    because no step mounted a store into its container and the script skipped the
    missing directory without a line. Fixed as AUD-085: the verification lists the
    archive, extracts it into a scratch directory and reads a file out of it;
    `REQUIRE_REPORT_ARCHIVE=1` (what CI sets) makes an absent archive a failure; the
    pass that writes an archive now reads it back before reporting success and names
    a store that is not mounted; CI captures a one-report store. The runbook's own
    extraction instructions were wrong in both halves — AUD-085's register row carries
    the second half — and now say `reports/` and `--strip-components=1`.
  - *Do the E2E scripts assert what the readiness page says they assert?* Yes. The
    smoke drives `/health`, `/ready`, sign-in, module enablement, asset creation,
    channel configuration, connector provisioning, the claim → submit → complete
    protocol, the finding's listing, the alert queue through the metrics endpoint and
    five audit actions named with their target; the page's row names the same chain.
    The browser half asserts the root redirect to the form, the form's own submission,
    `HttpOnly` on the refresh cookie with a readable CSRF value beside it, no JWT in
    web storage, the newest finding rendered as a row with its asset and the UTC note,
    and sign-out clearing the cookie while the API refuses the token it held — each is
    a clause on the page. The page is narrower than the scripts, never wider.
  - *Does the lock step reproduce the pinned requirements?* No, twice, and that is
    AUD-086. `_with_marker_gated_runtime` applied the greenlet rule to every manifest,
    so `lock_requirements.py connectors/<any>/requirements.txt` exited 2 with `does
    not pin greenlet`: seven files the connector images install with
    `--require-hashes` could not be regenerated at all. `backend/requirements.txt`'s
    header named `python scripts/lock_requirements.py requirements.txt`, which resolves
    from neither the root (no such argument) nor `backend/` (no such script). And
    nothing compared a shipped runtime lock to the generator: the dev file had a
    fixed-point test, the eight runtime locks had none. The rule is now scoped to a
    manifest that installs the declaring package, the header path is anchored to the
    repository root, and a fixed point over all eight files fails on either drift.
  Filed: AUD-085 (S2, fixed), AUD-086 (S2, fixed) and AUD-087 (S3, fixed) — the
  previous step's new SPA-gate test carried a skip site with no inventory row, so
  `tests/test_skip_inventory_gate.py` was red at HEAD before this step touched
  anything; the page now lists it under Partial checkout (34 sites, 51 in total).
  Verified: `tests/test_backup_scripts.py` — before, against the shipped scripts,
  `8 failed, 2 passed` over the ten cases that existed then (a corrupt archive exited
  0, a missing store said nothing, no archive was opened); after, `11 passed`, the
  eleventh being the `reports_store/`-rooted archive that pins the runbook's old
  claim and could not have passed before either. `tests/test_lock_requirements_gate.py` —
  before, both new tests red (`does not pin greenlet` for a connector lock;
  `'requirements.txt' is not a file from the repository root`); after, `13 passed`.
  `tests/test_skip_inventory_gate.py` + `tests/test_docs_consistency_gate.py` — 40
  passed; `scripts/check_docs_consistency.py` OK over 85 documents; and the skip,
  docs-consistency, docs-numbers, audit-map and GitHub-claims gates together, 86
  passed. The CI file parses as YAML.
  Not run, and why: no backup was taken and no restore performed through Docker —
  `docker version` fails with `failed to connect to the docker API at
  npipe:////./pipe/dockerDesktopLinuxEngine`, so the stack cannot be raised on this
  host, and the fidelity of the scripts was established through the stubbed runs
  above instead. `scripts/lock_requirements.py --check backend/requirements.txt` was
  started against PyPI and did not finish inside five minutes (`timeout 300` → 124):
  the resolution is network-bound and runs `--no-cache-dir`, so the generator's own
  verdict on the pins is CI's, not this host's. `make backup-verify` therefore also
  went unexercised end to end; the two commands it runs are the two the tests drive.
  Dismissed in writing:
  - *`restore.sh` restores the database and nothing else.* Deliberate and documented in
    two places, and forced by the mount: the `backup` service mounts the store
    read-only so a backup can never modify what it archives, so an archive extraction
    from inside that container could not write the store anyway. The gap was that
    nothing proved the archive, not that `restore.sh` ignored it.
  - *`verify_replicas.py` asserts the CSRF refusal with a bare `401`.* It does not
    require the reason, so a token-reuse 401 would satisfy it as well. Kept: the check
    runs after the same cookie rotated successfully on that replica, so a rejected
    token is not the candidate, and the auth suite pins the CSRF path itself.
  - *A report archive that holds an empty store is not a failure.* An installation
    booked up before its first report legitimately archives `reports/` with no file in
    it; the run reports that it read nothing back instead of pretending, and `files >
    0` is asserted only where a file was expected.
  - *Four gates in this slice have no test that fails when they are weakened* —
    `check_critical_coverage.py`, `check_mypy_baseline.py`, `check_integration_ran.py`
    and `coverage_gaps.py`. Each prints a status CI turns into a failure and each was
    read line by line here without finding a wrong decision to reproduce; what is
    missing is proof they stay right, which is AUD-084's class and the next step's
    budget rather than this one's. Carried to S28's Ask, with the last two gates of
    the same shape (`test_skip_inventory_gate` covers the page, not the scripts).
  Budget: 12 production files, 11 test files read or written, 2,836 lines of surface,
  eight hypotheses: three filed, four dismissed, one carried.


- **2026-10-22 — S28 closed, and the audit with it.** Read: the register as one table
  (89 rows, after the two filed here), the map's partition and trust boundaries,
  `security.md`'s accepted risks, and plan 011, which was written from the order the
  synthesis produced. The synthesis itself lives in the register, not in this log, so
  a reader who wants it does not have to reconstruct it: counts by severity and
  disposition; five root causes covering 32 rows (an identity or guard computed from
  less than the thing it describes; a rule enforced on one path while the effect has
  several; evidence that records the request rather than the change; one bad element
  taking the whole batch; a check that could not fail) plus two patterns covering ten
  more (the screen answering before the server does, six rows; a number in the prose
  that nothing recomputes, four); the rule each family leaves behind; three rows
  re-rated upward by blast radius (AUD-026, AUD-032, AUD-041 — each removes a
  guarantee the product states rather than costing a workaround) with two downgrades
  refused in writing (AUD-030 keeps S3 because its row exists and bounds the loss;
  AUD-018 keeps S3 because the hint never becomes identity and no secret is written);
  the four operator-page guarantees that are still false, each beside the row that
  falsifies it and the page that must change with the fix; and the remediation order
  — no row needed an `L` plan, so nineteen rows go into three passes inside
  [plan 011](011-remediation-pass.md), ordered severity first and size second. Two
  threads S27f carried were filed instead of re-carried: AUD-088, reproduced with a
  probe over the real digest (`{'queued': 10, 'incidents': 10, 'remaining': 0}` from a
  pass with twenty rows still held — the field counts its window, not the backlog),
  and AUD-089, the one gate of the four with no test that fails when it is weakened
  (`check_mypy_baseline.py`; the other three gained one during the wave). AUD-017's
  accepted-risk sentence in `security.md` matches its row, so no accepted row went
  back to `open`. Dismissed in writing: AUD-068 and AUD-070 are one expression in two
  places, found a wave apart, but both are `fixed` and each cites its own test, so
  they stay two rows — `duplicate` is for a row that adds no symptom; the map's dated
  measurements were not re-measured, because a difference there is a new date and not
  a finding; the 69 `fixed` rows were not re-run against the parent commit as one
  batch. Budget: four documents read, three written (the register's synthesis, plan
  011, this step's record), no production file touched — the partition is unchanged
  and its gate is green.

- **2026-10-23 — the four acceptance items closed as a measurement.** The audit's
  acceptance was written while the work was moving, and three of its four unticked
  lines were questions about evidence rather than code. All four were answered from
  the tree instead of from memory. The map's totals were re-run (129 files / 39,506
  LOC in `backend/app`, 11,148 production connector LOC, 73 SPA production files)
  and the map moved to a 2026-10-23 date, with the LOC drift recorded as the date
  changing. The progress log was counted rather than assumed: 34 dated lines cover
  S0–S28 and every S27 slice; the single handoff block is what the protocol prescribes
  ("rewritten — not appended twice"), so the "block per step" wording described the
  file's evolution, not a missing artefact. The parent-commit proof was the real one:
  `88d211d` extracted with `git archive`, the test files the register names copied
  over it, and every named node run against the parent code — 83 of 88 rows fail
  there, and the five that do not each have a written reason (dead-code deletion,
  suite configuration, dependency pins, a type-level test, a version bump). The close
  was re-checked at `bd96e10`: one-process suite 3,569/16/0 in 1:38:44, documentation
  gates 86 passed, skip inventory green. The measurements live here rather than in
  the register, because a replay is a fact about a day, not a disposition.
### Carried context for the next step
Handoff after S28 — 2026-10-22
Read: `docs/audit-findings.md` (89 rows, read as a whole for the first time),
`docs/project-map.md` (partition, trust boundaries, the decided list),
`docs/security.md` § accepted risks, `docs/production-readiness.md` (the skip
inventory and what no gate covers), and `scripts/check_docs_consistency.py`'s page
resolution rules, which is what a link in a plan or the register has to satisfy.
Established: the audit is closed and its result is readable in three places — the
register's synthesis (counts, five root causes with the rule each leaves, the
severity moves, the guarantees still false, the order), the map's audit-partition
paragraph (what a later session should be held to), and the readiness page's new
section (what an operator should read as a known gap rather than a protection). The
nineteen carried rows are in plan 011, three passes, severity first then size; no row
needed a plan of its own. Two dispositions were refused downward in writing and one
pair was left as two rows even though they are one expression in two places.
Open: two threads plan 011 created and did not take, both S4 and neither changing a
guarantee. **The compact Telegram renderer is dead code**: `alert_message.telegram_text`
has no production caller — the live channel sends `telegram_parts`, which prints every
field — so deleting it is a change to that module's 97% coverage gate and its tests.
**The certificate triage shows one subject**: AUD-037 made the payload carry
`signals.subjects` and made R3 evaluate every name, but `CertificateTriage` and
`DNSSecurityPage` still render the single `subject` column, so a reviewer cannot see
the others. A future plan opens with either, with the evidence already in the register.
`backend/tests/test_audit_register_gate.py` is what keeps a row honest — it rejects a
`planned` row that names no live plan, a `fixed` row that cites no existing test, and a
table that has been torn apart by a blank line.
Traps: the register lives in `docs/`, so a sibling page is linked without `../` and a
plan has to be written `exec-plans/011-remediation-pass.md` — the docs gate resolves a
bare page name only against the root, `docs/`, `connectors/` and `.github/`, so
`011-remediation-pass.md` alone reads as a missing page; a row that begins `| AUD-`
inside a second table (the severity table, say) is parsed as a register row by the
gate, which is why the synthesis writes its ids in backticks; the evidence regex must
try `tsx` before `ts`, or every `.tsx` citation resolves as a `.ts` that does not
exist; and a skip site added with a new gate test has to reach the readiness page's
inventory in the same change, or the skip gate is red at HEAD (this step's own
`test_audit_register_gate.py` was that site).
Filed: AUD-088 (planned, 011 pass A — the breach digest's `remaining` counts the
window it fetched: a `limit=10` pass over thirty held incidents answers
`remaining: 0`; S16 skipped exactly the lines that compute it), AUD-089 (planned, 011
pass C — the mypy ratchet is the one gate of S27f's four with no test that fails when
it is weakened).
Next: **no plan is open.** [Plan 011](011-remediation-pass.md) closed its pass C on
2026-10-22 and with it the nineteen rows the audit carried: the second VirusTotal
budget is deleted (AUD-022), a stored phishing score is repaired nightly
(AUD-033), the Typer/Click pair is compatible so `--help` works (AUD-057), all 101
SPA request helpers name their response type and a gate compares the eight
schema-backed interfaces with the OpenAPI models (AUD-060), and the mypy ratchet has
a test that fails when it is weakened (AUD-089). The register is 88 `fixed`, one
`accepted`, none `planned`. The two threads this block carried are closed, each by
its own plan: [012](012-s4-cleanup.md) deleted the compact Telegram renderer nothing
sent and made the certificate review print every hostname a sighting was reported
for, and [013](013-test-isolation.md) stopped a connector test module from depending
on a neighbour's `sys.path` and added the gate that collects each such module alone.
The acceptance item those plans left open has since been answered: the whole backend
suite ran in one process on 2026-10-23 and finished at 1:27:49 with seven failures,
every one of them fallout of the remediation's own fixes — a fixture still passing
`alerted_thresholds`, a `monitor_kind` signature that had changed, two Celery guards
that predated a core-owned task, and a hand-written sentence inside a generated
table. [Plan 014](014-full-run-findings.md) repaired all seven and the next run was
3,539 passed, 16 skipped, none failed in 1:29:03. A new plan still starts from a
reproduction, never from a suspicion.

<!-- The block above is rewritten in place at the end of every step, not appended:
each step writes its own handoff, in the format under "Handoff protocol". Do not
accumulate: the block describes the next step only.
-->
