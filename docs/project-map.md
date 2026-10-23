# Project map

A map is not a description of everything: it is the shortest artefact that lets a
reader (or a later session) answer "where does this behaviour live, what may I not
break, and what has already been decided". The staged audit in
[plan 009](exec-plans/009-staged-audit.md) is partitioned from this page, and the
partition is enforced by `backend/tests/test_audit_map_gate.py`: every production
file below belongs to exactly one audit step.

Counts were measured on 2026-10-21 with the commands in
[keeping this page true](#keeping-this-page-true). They are the size of the
surface, not a claim about quality.

## Shape

```
                     browser
                        |
              frontend/ — React SPA (73 production files)
                        |  JSON over /api/v1, HttpOnly refresh cookie
                        v
  +--------------------- API process ----------------------------------------+
  | main.py: request context → metrics → CORS → security headers             |
  | api/deps.py: bearer access token → user → role → audit context           |
  | api/v1/routers/*.py (16)  ──►  services/*.py (42)  ──►  models (20)      |
  |        auth, users, assets, alerts, breaches, phishing, dns, connectors, |
  |        audit, jobs, reports, dashboard, settings, modules, metrics       |
  +------------------------------+-------------------------------------------+
                                 |  AsyncSession (pooled), Alembic schema
                                 v
                            PostgreSQL
                                 ↑
                                 |  claim → ingest → findings → modules
  +------------------ Celery workers ----------------------------------------+
  | tasks/: scheduler ticks, alert delivery, reports, retention, integrity   |
  +--------------------------------------------------------------------------+
                                 ↑
                                 |  HTTP: claim a job, POST a bounded batch
  +------------------ connector workers (7) ---------------------------------+
  | base SDK: pause, quota reservation, retries, bounded reads, egress guard  |
  | dns_security, hibp, intelligence, shodan, dnstwist, exposure_endpoints    |
  +--------------------------------------------------------------------------+
```

Two properties of the shape matter for an audit. First, the connectors are
*outside* the platform: they hold provider keys, talk to third parties and send
back findings over the same API an operator uses, so everything a connector can
do must be expressible as a scoped, revocable capability. Second, the core never
imports a connector's code; a behaviour that exists in only one worker is either a
provider quirk or a defect, and the difference is decided by the shared client in
`connectors/base/`.

## Size, measured

| Area | Files | LOC | What it is |
|---|---|---|---|
| `backend/app/api` | 18 | 9,816 | 16 routers, 129 route decorators, `deps.py` |
| `backend/app/core` | 24 | 6,079 | config, database, security, audit chain, metrics, rate limits, egress |
| `backend/app/services` | 45 | 15,241 | the behaviour: ingestion, assets, alerts, modules, connectors |
| `backend/app/tasks` | 7 | 1,654 | Celery: scheduler, delivery, reports, retention, integrity |
| `backend/app/models` | 20 | 1,609 | SQLAlchemy mappings, 1 baseline migration |
| `backend/app/schemas` | 12 | 2,298 | request/response contracts and their validators |
| `backend/scripts` | 15 | 3,933 | migrate, seed, admin, key rotation, schema/coverage gates |
| `connectors/` | 18 | 11,100 | 7 workers + the shared SDK (3,639 more LOC of worker tests) |
| `frontend/src` | 73 | 26,229 | SPA: pages, lib, components (LOC includes 53 test files) |
| `scripts/` | 19 | 5,607 | repo gates, E2E, backup/restore, release checks |
| `docs/` | 76 | 28,999 | operator pages, plans, measured status |
| `backend/tests` | 217 | 72,452 | the suite: 3,363 passing in the 2026-10-21 full run, which predates the nine tests plans 008 and 009 added |

The largest single modules are where a defect travels furthest:
`routers/auth.py` (1,260), `services/ingestion_service.py` (1,214),
`routers/connectors.py` (1,214), `services/connector_service.py` (1,199),
`routers/users.py` (1,183), `routers/breaches.py` (1,099),
`routers/assets.py` (1,012), `services/tls_identity_service.py` (993),
`services/ingestion_events.py` (948), `core/config.py` (890),
`services/alert_service.py` (775), `services/phishing_score_service.py` (769),
`services/asset_service.py` (769), `services/alert_delivery_service.py` (743).

## Layer rules

A violation is worth a finding only when it changes behaviour; the audit uses
these as hypotheses, not as style complaints.

- **Routers** validate, authorise, call one service, audit, and shape the answer.
  A router holding business rules duplicates them where the next router cannot see
  them; the two flows that already do this are `auth.py` (rotation) and
  `connectors.py` (ingestion acknowledgement).
- **Services** own transactions and invariants. A service that commits twice, or
  catches an exception to keep going, is where a half-written finding appears.
- **Models** are data only. A property that reads another table hides a query in
  a loop, and the N+1 arrives with the first report that iterates the collection.
- **The core never imports a connector**, and a connector never imports core code
  except through the SDK and the HTTP API.
- **The SPA calls the API, never the database**, and holds no secret: the refresh
  token is an `HttpOnly` cookie the scripts cannot read.

## Trust boundaries

Five boundaries carry the product's security claims; each audit step tests the
ones it touches. The claims themselves are in
[security.md](security.md), [observability.md](observability.md) and
[description.md](description.md).

| Boundary | Claim to test | Where it lives |
|---|---|---|
| Session | one active refresh family per login, rotation detects replay, and enrolment ends the sessions that predate the factor (an access token lasts out its remaining minutes, not longer) | `routers/auth.py`, `services/refresh_sessions.py`, `core/mfa_policy.py` |
| Authorisation | the role check happens on the object's owner, not only on the route; an operator sees no other tenant's row | `api/deps.py`, `core/permissions.py`, `services/admin_invariants.py` |
| Evidence | every state change writes an audit row in the same transaction, and the chain refuses an append after a detected gap | `core/audit.py`, `core/audit_chain.py` |
| Egress | a worker can reach only an allowlisted provider host, and a redirect cannot take it elsewhere | `core/outbound.py`, `connectors/base/` |
| Credentials | provider keys are encrypted at rest, returned masked, scoped to one account, and never logged | `services/connector_credentials.py`, `core/crypto.py` |

## Where a defect of each class would live

| Class | First places to look |
|---|---|
| Privilege escalation | `api/deps.py`, `core/permissions.py`, `routers/users.py`, per-object filters in `routers/assets.py` and `routers/audit.py` |
| Cross-tenant read | a `select()` without an owner predicate in `services/`; a router that takes an id straight from the path |
| Audit gap | any `commit()` in a router or a service that runs before `audit.log`, and every `except Exception` around an audit write |
| Duplicate or missing finding | `services/ingestion_service.py` dedup keys, `ingestion_events.py` idempotency, retry after a partial batch |
| Lost alert | `alert_delivery_service.py` status transitions, `alert_health_cache.py` staleness, `tasks/alert_tasks.py` retry handoff |
| Quota or cost overrun | `services/provider_quota.py` reservation window, `core/outbound.py` retries, worker retry loops |
| Injection / SSRF | `services/phishing/whois_service.py`, `connectors/*/live_check.py`, any `text()` in `services/` |
| Secret in a log | `core/logging_config.py` redaction list, `audit.py` details payloads, connector error strings |
| Migration drift | `alembic/versions/`, `check_schema_drift.py`, index and constraint declarations in `models/` |
| Broken error contract | `core/exceptions.py`, `core/safe_errors.py`, a router that raises `HTTPException` with a provider message |
| Rate limit bypass | `core/rate_limit.py` keying (user vs IP), `request_rate_limit.py` ordering behind the proxy |
| SPA auth regression | `lib/api.ts` refresh handling, `pages/LoginPage.tsx`, `components/Auth/`, `store/` |

## Already decided — do not re-flag

An audit that re-litigates these spends its budget on settled questions. Each link
states the decision and the measurement behind it.

- `alembic check` is deliberately not a gate; the measured differences are in
  [production-readiness.md](production-readiness.md#why-alembic-check-is-deliberately-not-a-gate).
- The audit chain is tamper-evidence, not write-once storage: detecting a rewrite
  of the whole database needs the tip kept elsewhere.
- SQLite is the test database; row-lock cases skip and run on PostgreSQL
  ([the skip inventory](production-readiness.md#what-a-host-run-skips-and-why)).
- Sixteen skips on a bare host are inventoried, with the cause of each.
- Connector workers duplicate provider knowledge on purpose: quotas, pacing and
  body bounds are shared through the SDK, provider semantics are not.
- `docs/db.sql` is a reference, not a deployable schema; migrations are the source
  of truth.
- The SPA keeps no token in `localStorage`/`sessionStorage`; the refresh cookie is
  `HttpOnly` and the CSRF value beside it is readable by design.
- The frontend ships as a static SPA behind nginx; there is no SSR to audit.

## Audit partition

One production file, one step. The plan is [plan 009](exec-plans/009-staged-audit.md);
the gate that keeps this partition complete is
`backend/tests/test_audit_map_gate.py`, and the findings it produces are filed in
[the register](audit-findings.md).

The audit closed on 2026-10-22: 89 findings, 69 of them fixed in the step that found
them with a regression test that was red first, 19 carried by
[plan 011](exec-plans/011-remediation-pass.md) — all nineteen since closed in its
passes A, B and C — and one accepted in
[security.md](security.md#accepted-risks-and-what-bounds-each-one). None is open and
none is `planned`.
What a later session should take from it is the closing section of the register: the
five root causes behind 32 of the rows, and beside each the rule a new change should
be held to — a key computed from everything it identifies, a rule enforced where the
effect happens, evidence that names both ends of the change, a batch that refuses per
element, and a gate that lands with a test which fails when it is weakened.

| Steps | Wave | Surface | LOC |
|---|---|---|---|
| S0 | method | none — baseline, rubric, handoff format | — |
| S1–S2 | identity and authority | session, MFA, invitations, roles, user administration, admin CLI | 5,130 |
| S3 | evidence | audit trail, chain, archive, retention, logging, verification CLIs | 3,278 |
| S4–S5 | data in | ingestion, module registry, assets and matching | 5,346 |
| S6–S7 | alerts out | composition, routing, delivery, notifications | 4,319 |
| S8–S10 | connector boundary | control plane, credentials, manifests, egress, SDK, quota, source accounts | 6,761 |
| S11–S14 | workers | one provider family per step | 9,680 |
| S15–S18 | modules and scheduling | breaches, phishing, DNS/TLS, jobs and reports | 9,352 |
| S19–S21 | platform shell | config, crypto, paths, errors, limits, metrics, settings, dashboard | 4,257 |
| S22 | persistence | migrations, seeding, schema drift, model conventions | 1 migration + 1,300 |
| S23–S26 | SPA | client and types, pages in two batches, components and a11y | 26,229 |
| S27a–S27f | operations | Compose, images, nginx; CI and the Makefile; packaging and pins; the gates that hold the prose and the tree; backups, restore and E2E | 15,534 |
| S28 | synthesis | dedupe, severity, architecture findings, roadmap | — |

## Keeping this page true

```bash
find backend/app -name '*.py' | wc -l
find backend/app -name '*.py' -exec cat {} + | wc -l
find connectors -name '*.py' ! -name 'test_*.py' -exec cat {} + | wc -l
find frontend/src \( -name '*.ts' -o -name '*.tsx' \) ! -name '*.test.*' ! -name 'test-setup.ts' | wc -l
```

The numbers above are dated measurements, like the appendix in
[production-readiness.md](production-readiness.md#appendix-measurements-at-a-point-in-time).
The audit plan's *partition* is the part that must stay true: the gate fails when
a production file is added and assigned to no step, or when a step names a file
that no longer exists. Update the step's surface in
[the plan](exec-plans/009-staged-audit.md) — not this table — when the tree moves.
