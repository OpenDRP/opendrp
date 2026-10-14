# OpenDRP — technical reference

This page is for someone changing the code: module internals, the rule that links
findings to assets, the connector protocol, the authentication and session design,
and the audit trail. [README.md](../README.md) is the platform's description —
architecture, services and Compose profiles, modules and the asset model,
configuration, operations, alerts, settings and retention, the UI and the security
model all live there — and the runbooks are in [deployment.md](deployment.md),
[upgrading.md](upgrading.md), [backup-restore.md](backup-restore.md),
[dns-security.md](dns-security.md), [source-intelligence.md](source-intelligence.md),
[observability.md](observability.md), [security.md](security.md) and
[production-readiness.md](production-readiness.md).

Each section below names the code that owns the behaviour. Where a page and the
code disagree, the code is what the platform does.

## 1. Modules and their storage

The module registry is rows in `drp_modules` (section 1.5). Four modules ship with
the platform, each with its own typed table, write adapter and endpoints; a module
an operator declares instead uses the generic `drp_findings` path.

| Module | Table | Finding kind | Asset types it consumes |
|---|---|---|---|
| `phishing` | `drp_phishing_domains` | `phishing` | `domain` |
| `breaches` | `drp_breaches` | `breach` | `email_account`, `domain` |
| `dns` | `dns_security_observations` | `dns_observation` | `domain` |
| `exposure` | `source_observations` | `exposure` | `domain`, `ip_address` |

### 1.1 Phishing

Stored in `drp_phishing_domains`. The DNSTwist connector reads active `domain`
assets, runs mutations and DNS resolution, and submits candidates with
`detection_source=dnstwist`; the Shodan connector searches its three capabilities
and submits with `detection_source` naming the capability that matched. Accepted
findings may be enriched with WHOIS data by the core (`app/services/phishing/`).

Shodan capabilities are independent and configured per connector:
`scan_ssl_text`, `scan_http_title` and `scan_favicon`. The connector registry is
the source of truth — an administrator's choice in the connector configuration
takes precedence, and the `SHODAN_SCAN_*` environment values are the fallback
until one is set. Disabling a capability stops that query; disabling all three
completes the job without an external search. Shodan receives active `domain`,
`keyword_domain` and `keyword_title` assets as targets, and active domains and IP
addresses as exclusions, so infrastructure the operator already monitors is not
reported back as a look-alike.

Status is `active`, `investigating` or `resolved`, in `drp_phishing_domains.status`.
A detection that matched a monitored keyword or domain is not a takeover: there is
no takedown workflow, and nothing in the platform requests one.

### 1.2 Breaches

Stored in `drp_breaches`. The HIBP connector reads active `email_account` assets
through breached-account lookups and active `domain` assets through breached-domain
lookups, expanding an alias domain into per-address findings; it applies its own
provider rate limit and submits normalized records. The core validates every
submission before persisting and never calls a provider itself.

Storage is provider-neutral: the core keeps what any breach source can supply
(incident name, matched value, disclosure date, affected-account count, exposed
data classes) plus an `attributes` payload for whatever else the reporting source
knows — its own classification flags, catalog timestamps, a secret sample. A
source declares its own payload shape instead of being fitted into another
vendor's fields, and the UI renders declared attributes generically.

Deduplication is per source account: the identity of a breach row is
`(source_id, breach_name, matched_email)`, with a partial unique index on
`(source_id, breach_name, matched_domain)` where `matched_email IS NULL`
(`backend/app/models/breach.py`). Two
sources reporting the same incident about the same address are therefore two rows:
the same breach seen by two providers is evidence, not a duplicate.

For display and for the cascade delete, a breach row resolves against the current
inventory in this order: an exact `email_account` asset matching `matched_email`
wins, otherwise the domain (`matched_domain`, or the domain part of a monitored
address), otherwise the provider's raw values stay visible with no asset attached.
The rule itself is section 3.

### 1.3 DNS Security

The `dns` module stores evolving, source-scoped observations in
`dns_security_observations` rather than immutable findings: a resolver RRset is
refreshed in place as it changes, and provenance is the connector and source
account that observed it. Four workers consume active `domain` assets —
`dns-rdap` (registration and expiry), `dns-resolver` (current RRsets),
`dns-ctlogs` (historical certificate evidence, including wildcards) and
`dns-virustotal` (historical passive DNS and subdomains) — and each declares its
own `dns.*` job type and holds its own core-issued credential. Their token and
provider configuration, quotas and source limits are in `dns-security.md`.

Expiry is an alertable fact only where a check establishes it. Registration-expiry
reminders need a successful, fresh RDAP check (`DNS_EXPIRY_MAX_AGE_HOURS`), and
exact-certificate expiry reminders need a separately verified, completed CT check;
both use 30/14/7/3/1-day thresholds plus one reminder after expiry. Historical CT
evidence, DNS TTLs and provider-supplied expiry metadata do not establish an
alertable expiry, and wildcard CT evidence can never establish a concrete asset or
ownership — which is why promoting an observation is an explicit, audited
operator action.

The module id is `dns`. `dns_security` is accepted as an alias wherever a module
id is read (`app/services/module_aliases.py`), which keeps a connector or a script
written against the older spelling working; the table and the settings column keep
their `dns_security_*` names. The manual scan route queues only sources with a
recent heartbeat and reports the offline ones separately rather than pretending
they ran.

### 1.4 Exposure

The `exposure` module records what a provider observes about monitored addresses
and domains in `source_observations`, through the `exposure` adapter. Two optional
workers feed it — `exposure.netlas` (profile `netlas`) and the endpoint workers
`exposure.netlas-endpoints` / `exposure.shodan-endpoints` (profiles
`netlas-endpoints` and `shodan-endpoints`) — each with its own token, and their
readiness declares the operations they can perform. A row carries the observed
subject, the service it was seen on (port, transport, protocol), the provider
observation time, first and last seen, and the triage status `observed`,
`investigating` or `resolved`. Promotion (`POST
/api/v1/exposure/observations/{observation_id}/asset`) creates a `domain` or
`ip_address` asset at `medium` criticality and records the observation, its source
and the resulting asset in the audit trail. Observing a host behind shared
infrastructure or a CDN does not establish ownership, which is why the UI says so
at the moment of promotion.

### 1.5 The module registry

`app/services/module_registry.py` reads `drp_modules`. A module declares:

| Field | Meaning |
|---|---|
| `id` | module id, and the `connector_type` its connectors register under |
| `label`, `description` | what navigation and the module page show |
| `finding_kind` | the schema submissions validate against; one kind belongs to one module |
| `asset_types` | the inventory sections its connectors receive in a scan |
| `fields` | the declared field specification findings are validated against |
| `dedup_fields` | the fields that identify a finding; together they are the dedup key |
| `title_field` | the declared field shown as the finding's title |
| `storage` | `native` (typed table and adapter) or `generic` (`drp_findings`) |

A declaration must name its fields and at least one dedup field, and the registry
refuses one that would store every submission afresh, reuses an id or a finding
kind, or names a title field it did not declare. Declared fields are immutable
once findings exist against them, because stored rows would otherwise change shape
without a migration; the label and description stay editable, and a module can be
disabled without deleting it. A disabled module's connectors are refused work.

The core owns storage, deduplication, audit and alerting for every module. That
boundary is the point of the registry: a connector submits findings and never
writes to the database.

## 2. Ingestion, validation and deduplication

`app/services/ingestion_service.py` is the only writer of findings. A submission
batch is validated against the finding kind the connector declared at registration
(the payload models are `extra="forbid"`, so an undeclared field is a rejection
rather than a silent write), then deduplicated on the module's key.

The response counts are the contract a connector author writes against:
`received`, `created`, `updated`, `unchanged`, `accepted` and `rejected`. `accepted`
counts what the submission did store — created rows and refreshed rows together —
and `rejected` counts what it did not store, which includes a duplicate as well as
a malformed entry or one whose dedup key is missing. A re-scan of an unchanged
target therefore reports `rejected` for those rows, and a connector must not treat
a non-zero `rejected` as a failed job on its own; a job fails on a rejected count
only when the core reports the batch as unusable.

Behaviour is per finding kind:

- a **phishing** row that already exists is refreshed in place — its fields are
  updated and the row reports `updated`, or `unchanged` when nothing differed —
  rather than being refused, because a look-alike that is still resolving today is
  a live detection;
- a **breach** row is deduplicated on the key in section 1.2, per source account;
- a **DNS observation** is source-scoped, so the same subject observed by two
  workers is two rows with two provenances, and a resolver RRset is refreshed
  instead of appended;
- an **exposure** observation is keyed on its subject and service identity, so a
  repeated provider answer updates `last_seen` instead of duplicating the row.

After storage the core queues alerts for what was newly stored and writes the audit
rows for the job; alert delivery itself is asynchronous (section 5).

## 3. The asset matching rule

`app/services/asset_matching.py` holds one rule, and every feature that needs to
know whether a finding concerns an asset uses it: the asset list's per-module
counters, the asset page, `?has_findings=true`, the export and the cascade delete.
One rule in one place is what stops "3 findings" on a row from disagreeing with the
two findings a delete would remove.

Matching is case-insensitive and aware of the trailing dot and of IDNA. A key set
(`key_variants`) is built per asset so that a finding written in the Unicode
spelling of a punycode host still matches: PostgreSQL cannot decode IDNA, so both
spellings are carried as literal keys instead of being left to a database-side
comparison that cannot make it. `RELATED_FINDING_MODULES` names the modules whose
rows count as "findings about this asset" — phishing, breaches, dns, exposure and
generic findings — and deleting a monitored **domain** also removes the breach
findings about mailboxes at that domain, while deleting one mailbox never touches
its domain.

The involvement read is grouped rather than per asset, and its predicates are
covered by the expression indexes the baseline creates.
Both are decisions with a measurement behind them: on 2000 assets, 100k breaches
and 50k phishing findings, evaluating the predicates once per row cost 7.6 s for a
page of 20 rows (19 s for 50) and exceeded `statement_timeout` when used as a list
filter, because the rule compares `lower(rtrim(trim(x), '.'))` — an expression a
plain column index cannot serve — and the email-to-domain branch asked for its
domains with a leading-wildcard `LIKE`. The grouped read with the expression
indexes answers the same page in about 0.1 s (0.2 s for 50 rows) and the
inventory-wide filter in about 0.8 s, with the same counts and the same set of
rows.

Assets themselves are validated per type (FQDN pattern, IPv4/IPv6, email address,
non-blank keyword) and canonicalized before storage — lowercase IDNA for domains,
case-insensitive email domains, canonical IP text — and the database enforces
uniqueness per type and canonical value. The inventory is global and single-tenant
by design: there is no owner or tenant column, so roles decide what an account may
do and never what it may see. Multi-tenancy would be a schema change plus a filter
no route may forget, which is why it is a recorded limit rather than a latent
assumption.

Sort, search and paging are declared allowlists (`sort` over
`created_at`, `updated_at`, `asset_value`, `asset_type`, `criticality`,
`is_active`, and `order`; anything else is `422`), because the value reaches
`ORDER BY` and caller input is never concatenated into a statement. Search also
accepts a subnet, which answers "which of my assets sit in this network" through
the same unique index, and refuses a subnet wider than 4096 addresses rather than
answering it in part. A page and its `total` come from one statement
(`count(*) OVER ()`), so they cannot describe two different snapshots.

## 4. Jobs and the connector protocol

### 4.1 Job types and statuses

`JobType` (`backend/app/models/job.py`) enumerates only the types the core creates
on its own behalf: `report.generate` and `system`. Every other job type belongs to
exactly one connector, which declares it at registration; a type is namespaced
(`<module>.<connector>`) and the core hands each job to the single connector that
claimed that type. `GET /api/v1/connectors/modules` reports the modules and job
types that are actually registered, which is what the module pages filter job
history with.

A job stores its creator, connector parameters, result summary, error message,
task ID and lifecycle timestamps. Its status is `pending`, `running`, `success`,
`partial`, `error`, `cancelled` or `skipped`; `partial` is what a provider that
served some capabilities and refused others produces, and it is deliberately not
reported as a clean success or as an empty result.

### 4.2 Claiming work

`GET /api/v1/connectors/me/work` claims one pending job **by job type**, taking a
row lock with `SKIP LOCKED`, so two workers polling the same connector cannot
receive the same job and a connector can never claim a sibling's or another
module's work. A lease token comes back with the job, heartbeats are expected
during long work, and an expired lease returns the job to `pending` for a bounded
number of attempts before it becomes `error` and releases its provider admission
slot. A connector can complete or fail only a job it claimed.

### 4.3 The findings submission contract

```text
POST /api/v1/connectors/me/findings/{job_id}
POST /api/v1/connectors/me/complete/{job_id}
POST /api/v1/connectors/me/heartbeat
GET  /api/v1/connectors/me/credential
GET  /api/v1/connectors/me/control
POST /api/v1/connectors/me/quota/provider
POST /api/v1/connectors/me/quota/virustotal
POST /api/v1/connectors/me/readiness
```

Submissions are counted as in section 2 and the batch is refused when it exceeds
the connector SDK's per-batch limit. `GET /me/credential` answers with the provider
key of the source account the connector is bound to — the core stores it as Fernet
ciphertext under `ENCRYPTION_KEY` and returns the plaintext only to that connector,
audited and marked `no-store`. `POST /me/quota/provider` reserves a provider
operation against the account's approved budget, and `POST /me/quota/virustotal`
answers `410` because a VirusTotal reservation is an ordinary `lookup` bucket
reservation. `POST /me/readiness` publishes what the connector can do; an idle
report cannot clear a real error. `connectors/README.md` is the full contract for
connector authors.

### 4.4 Credentials and the manifest

Registration (`POST /api/v1/connectors/register`) carries a self-declared manifest:
the module it feeds (`connector_type`, which must exist and be enabled), the single
job type it claims (`default_job_type`), the finding kind its submissions validate
as, the asset types it receives, and the operator-editable settings it exposes
(`config_schema`). The core validates the declaration — module coherent with the
finding kind, job type namespaced and unclaimed, asset types known, config keys
safe — and stores it in `drp_connectors.manifest`, so submission validation, the
configuration form and the scan payload all follow the connector's own declaration.

A credential is issued to a connector that already has a row, so provisioning —
`POST /api/v1/connectors/provision`, or `python -m scripts.manage_connector_tokens
issue` — creates the row and the token together. The row reserves a job type
(`<module>.<name>`) because a row must name the work it can be given; the connector
replaces it with the type it declares when it first registers, so a job type is
never inferred for a connector that never declared one. The plaintext is returned
exactly once and stored only as a SHA-256 digest; the registry exposes a public
prefix and issue/last-used timestamps. Rotation invalidates the previous token
immediately and revocation keeps the connector's configuration, job history and
audit trail. Requests carry the connector's own `X-Connector-Token`; the optional
`X-Connector-Name` header is checked for agreement only, and the name in an error
report is a diagnostic hint, never an identity.

### 4.5 Scheduling and provider admission

Schedules are JSON in the `system_settings` singleton: dedicated columns for
`phishing`, `breaches` and `dns`, and the generic `schedules` map that lets a
declared module have one. Days are `0=Sunday` through `6=Saturday`; the hour and
minute are UTC. Celery Beat runs the one-minute task, which examines the current
minute and the nine before it; `schedule_occurrences` records the
connector-and-UTC-minute pairs that have already run, so deduplication survives the
deletion of the job it produced, and a Redis guard with two-second connect and read
deadlines and a 900-second TTL covers a replica racing another. Downtime longer
than that window is not backfilled.

Before a job is committed, the core also takes one Redis-backed admission slot per
connector, shared by manual scans, scheduled scans, users and API replicas, so a
second simultaneous scan of the same provider answers `409` instead of spending
another provider quota. The guard fails closed with `503` when Redis cannot enforce
it, a one-hour TTL and an ownership-checked release recover from a crashed worker,
and a missing connector is reported as `no_connector` rather than being folded into
a database failure. The per-user manual throttle (`rate_limit_minutes`, 0 for
unlimited, capped at 1440) is a separate UX safeguard and does not replace this
guard.

## 5. Reports and alert delivery

A report request creates a `reports` row and a `report.generate` job. The worker
collects its snapshot in one short transaction, releases the connection, renders
the PDF, publishes it with an atomic rename into the configured report store, and
moves the row through `pending`, `generating`, `completed` or `failed`.
`REPORT_MAX_ROWS` bounds each section and the PDF states the total, the included
count, the limit and whether it truncated; `REPORT_QUEUE_MAX_PENDING` refuses
further admissions with `429`; `REPORT_GENERATION_TIMEOUT_SECONDS` bounds the whole
operation. Deletion and retention record a retryable cleanup intent before removing
the row, and files leave storage only through the configured resolver, so a worker
crash between the two cannot lose a file's only reference. The API never renders a
report in process: without Celery the job is marked failed and the request answers
`503`, which is what keeps a replica stateless. Reports are readable by any
authenticated account in the installation by design — `created_by` records
provenance, not an authorization boundary — and only administrators delete one.

Finding alerts are durable before they are announced: ingestion writes a delivery
event and moves on. `app/services/alert_delivery_service.py` and
`app/tasks/alert_tasks.py` group events by completed connector job, render one
bounded message per job, finding type and channel, and keep per-recipient state, so
a channel's failure never marks another recipient as delivered. The delivery row is
`pending`, `delivering`, `sent`, `failed` or `ambiguous`; transient failures are
retried within the attempt budget with the provider's `Retry-After` honoured, while
a configuration or authentication refusal is terminal and needs an operator.
Acceptance-unknown attempts become `ambiguous` and hold their recipient for
`ALERT_RECIPIENT_HOLD_SECONDS` rather than being replayed at once; the hold ends
with the window — the deliveries return to the queue — and an administrator can
end it early from the alerts view once the message has been reconciled with the
recipient. The platform still offers no bulk-delete for that state.

## 6. Authentication, sessions and authorization

### 6.1 Passwords and sign-in

Passwords are bcrypt hashes (`bcrypt` directly). A new password needs at least 12
characters, an uppercase letter and a digit, and no more than 72 UTF-8 bytes, which
is the hash function's input boundary. Sign-in checks the password the account
currently holds — including one an administrator assigned — and records success,
failure and lock events. Failed attempts are throttled in Redis by email and by
client address and tracked in database lockout fields, and every refusal answers
identically: an unknown address, a wrong password, a disabled account and a locked
account cannot be distinguished from the response, with the reason kept in the
audit trail.

A password assigned *for* someone sets `must_change_password`, and removing a
factor *for* someone sets `must_enrol_mfa`. While either flag is set, every
authenticated route is refused with `403` and the marker `onboarding_required`,
except `/auth/me`, `/auth/password`, `GET /auth/mfa` and — once the password step
is done — the enrolment endpoints. The check lives inside `get_current_user` so a
route added later cannot forget it. The refusal itself is not audited (the
condition was audited when it was created) and is emitted as the structured log
event `credential_onboarding_required` instead. The escape hatch for an account
that cannot complete the flow is `python -m scripts.manage_admin onboarding-off`,
run from the host.

`REQUIRE_MFA_FOR_ADMINS` is a step of the same flow rather than a filter on admin
pages: with it on, an administrator without an enrolled factor is refused by the
credential gate with the marker `mfa_required` and an `auth.mfa.required` event,
and the enrolment endpoints stay reachable so recovery is possible. User payloads
carry `mfa_required_by_policy`, computed from the setting and the account's
enrolment, so the requirement is visible at sign-in rather than discovered later.

### 6.2 Tokens and sessions

Access tokens are JWTs signed with PyJWT; the accepted algorithms are pinned to
`HS256`/`HS384`/`HS512` in configuration, so `none` or a mismatched `alg` cannot be
accepted, and the check is unconditional because a development instance issues
tokens a production instance would accept. Refresh token families live in
`drp_refresh_families`, rotate on use, and are revoked on reuse detection,
administrator reset, self-service password change, MFA recovery, deactivation and
account removal. The revocation is one shared implementation
(`app/services/refresh_sessions.py`) because the users router, the auth router and
the admin CLI all need it, and the lifecycle events record how many families were
revoked.

The session of record is the `HttpOnly` refresh cookie, not browser storage: the
access token is held in memory, so a reload drops it and every page load asks
`POST /api/v1/auth/refresh` once before the app decides what to render. Asking
rather than inferring is deliberate — a private window, cleared site data or a
denied-storage profile all make a valid server-side session look absent, and only
the API knows — and the single-flight refresh is shared with the `401` interceptor
because two overlapping presentations of a rotated token read as reuse and revoke
the family. Signing out ends the session on both sides: local state first, then
`POST /api/v1/auth/logout`, so the cookie cannot restore the session the operator
just ended. The refresh endpoint deletes the cookie when it refuses the token in
it, and every refused presentation would otherwise be retried and audited once per
page load until it expired. The nightly sweep removes revoked rows only once their
tokens can no longer be presented, because until then the row is what answers a
replayed token with `family_revoked` instead of `family_not_found`.

### 6.3 Second factor

TOTP is available to every role and enforced at sign-in for accounts that enrolled.
The secret is Fernet ciphertext under `ENCRYPTION_KEY` and is *not* rewrapped by the
key-rotation tooling, which is why an operator keeps the older key until every
factor has been re-enrolled or cleared (`manage_admin mfa-off`) — see
`upgrading.md#rotating-secrets`. The code is requested only after the password
verifies, so the endpoint cannot be used to discover which accounts have a factor;
each accepted code is single-use (the matched counter is stored in
`totp_last_used_step`, closing the replay window the ±1-step tolerance opens), and
invalid or missing codes consume their own MFA lockout budget so guessing cannot
exhaust the password budget. Enrolment is self-service and shows ten one-time
recovery codes exactly once, of which only bcrypt hashes are stored; removal needs
the password and a live code, an administrator can clear another account's factor
(`POST /api/v1/users/{user_id}/mfa/reset`, refused for the caller's own account),
and a locked-out administrator is released from the host with
`python -m scripts.manage_admin mfa-off`.

### 6.4 Roles, authorization and the administrator invariant

Authorization reads the account's current role and active flag from the database on
every authenticated request rather than trusting a claim in the token, so
deactivating an account takes effect immediately. All `/api/v1/users` management
routes require `admin`. Demoting, deactivating or deleting the last active
administrator is rejected, and on PostgreSQL the check locks the active-admin set
in a transaction-scoped advisory lock so two concurrent requests cannot both pass
it and leave the installation without an administrator. An administrator cannot
deactivate or delete their own account; self-demotion is allowed only while
another active administrator remains.

Report generation is the one deliberate exception to the viewer role: it creates an
asynchronous job owned by the requesting account and is bounded by the per-user
report throttle, while report visibility stays installation-wide.

## 7. The audit trail

### 7.1 What is recorded

Rows live in `drp_audit_logs` and the same event is emitted to stdout as one JSON
line carrying exactly five fields — `timestamp`, `user_id`, `action`,
`ip_address`, `details`. A sixth top-level field would reach a SIEM index that maps
the documented shape, which is why request correlation lives inside
`details.request_id`; `docs/observability.md` is the collector recipe and the
detections built on those events.

Reads are recorded once per result set rather than once per request: `asset.list`
is written for the first page of a listing, because the pages that continue it are
the same read, while `asset.view` records every individual lookup. Its details
record what was asked for, including `has_findings`, and `asset.findings.list`
records the counters it returned, so "who looked at this asset's involvement" is
answerable without storing the rows themselves.

State-changing account and session operations commit their audit row in the same
transaction or do not happen: if the record cannot be persisted the operation is
rolled back and the API answers `503` with `code: audit_unavailable` and
`Retry-After: 5`. Sign-out and connector heartbeats are best-effort by design, so
the guarantee is about the audited set rather than about every request. Update
details carry before/after values for changed `email`, `full_name`, `role`,
`rate_limit_minutes` and `is_active` fields, and never a password, hash, TOTP
secret or recovery code.

### 7.2 The chain

`app/core/audit_chain.py` chains each row: `entry_hash`, `prev_hash` and `key_id`
are stored (`AUDIT_CHAIN_KEYS` with `AUDIT_CHAIN_PREVIOUS_KEYS` keeping an older key
verifiable through a rotation), and a few detail keys are reserved — the chain
markers and the transport marker — so a client-supplied `details` cannot forge
them. Verification detects a deleted suffix or a deleted set of rows and refuses
subsequent appends; the scheduled pass defaults to a full sweep of the retained
chain with a persisted upper checkpoint and a fenced cursor, checks a bounded
number of entries per run and resumes after a restart. Verification never repairs
history: a chain that does not verify stays that way until an operator accounts for
it, and `GET /api/v1/audit/integrity` reports the state the check left behind.

Retention removes only a contiguous prefix that has already been archived,
verified and receipted: `python -m scripts.audit_archive` exports the prefix with
its manifest, a missing archive directory, a corrupt file, a revalidation mismatch
or `AUDIT_RETENTION_HOLD` blocks the deletion, and the database holds the receipt.
Local signatures are tamper-evidence, not write-once storage — a database rewritten
in full, or an archive deleted along with its manifest, is only detectable against
a copy kept off the host that holds the database, which is why the committed tip
belongs somewhere else.

## 8. Where the rest is written down

- the deployment shape, the service and profile inventory, and the installer
  (`setup.py`) — [README.md](../README.md#quick-start),
  [README.md](../README.md#services-and-persistence),
  [deployment.md](deployment.md);
- configuration ownership, defaults and the per-service resource table —
  [configuration.md](configuration.md), [README.md](../README.md#configuration);
- the module registry, the asset model and the identity flows as operators meet
  them — [README.md](../README.md#modules-findings-and-the-asset-model),
  [README.md](../README.md#identity-sessions-and-mfa);
- operations, alert delivery, retention and the audit chain —
  [README.md](../README.md#operations),
  [README.md](../README.md#alerts-settings-and-retention);
- upgrades, destructive revisions and secret rotation — [upgrading.md](upgrading.md);
- backups, what a dump contains and how a restore is verified —
  [backup-restore.md](backup-restore.md);
- logs, the SIEM path and the audit contract — [observability.md](observability.md);
- the security model, what the operator must verify and the accepted risks —
  [security.md](security.md);
- the measured state of the repository and its known limitations —
  [production-readiness.md](production-readiness.md);
- the route inventory (method, path, required role) — [api.md](api.md), with the
  running schema as the authority outside production;
- writing a connector — [connectors/README.md](../connectors/README.md);
- the DNS Security workers — [dns-security.md](dns-security.md);
- the optional passive-intelligence workers, accounts and quotas —
  [source-intelligence.md](source-intelligence.md).
