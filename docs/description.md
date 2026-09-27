# OpenDRP

## Dashboard and report production safeguards

Alert delivery is durable and asynchronous: finding ingestion writes a persistent
queue event and never waits for SMTP or Telegram. A worker groups events by completed
connector job, sends one bounded summary, retries only transient failures, and records
per-event retry state. `ALERT_DELIVERY_TIMEOUT_SECONDS`, `ALERT_DELIVERY_MAX_ATTEMPTS`,
`ALERT_AGGREGATION_DELAY_SECONDS`, and the message-size limits control this behavior.

Dashboard timeline data is aggregated in one database query rather than issuing
one query per day and per finding type. Empty days are filled in the API response,
so charts retain a stable 30-day shape without the N+1 database load.

Report generation is asynchronous and bounded. `REPORT_MAX_ROWS` limits the
inventory and finding rows embedded in one PDF, while
`REPORT_GENERATION_TIMEOUT_SECONDS` bounds PDF rendering. Reports are rendered
with DejaVu Sans when the runtime image provides it, preserving Unicode text
(including Cyrillic); the artifact is published atomically only after rendering
completes. Each completed report also stores truncation metadata: the UI marks
reports whose assets, phishing findings, or breaches exceeded the configured
`REPORT_MAX_ROWS` limit, and shows the included/total section counts without
changing the report's complete KPI totals.

Connector errors persisted by the core are sanitized before storage: provider
URLs, tokens, passwords, and response control characters are not copied into
`last_error`. Connector health therefore exposes a useful state without turning
provider diagnostics into a credential disclosure.

SMTP and WHOIS destination resolution is bounded by `OUTBOUND_DNS_TIMEOUT_SECONDS`.
DNS work runs outside the event loop and provider/WHOIS probes have explicit
wall-clock limits, so a broken resolver cannot exhaust API workers.

# Technical Description

## 1. Scope and purpose

OpenDRP is a self-hosted Digital Risk Protection platform. It maintains a monitored-asset inventory and detects external exposure through phishing, brand-abuse, infrastructure, and breach-data sources.

The implemented platform provides:

- asset management for domains, IP addresses, email accounts, and keyword indicators;
- phishing discovery through DNSTwist and Shodan connectors;
- HIBP breach monitoring through a connector;
- manual and scheduled scans;
- normalized finding ingestion, deduplication, and alert dispatch;
- administrator-configured email and Telegram notifications, with explicit SMTP STARTTLS, implicit TLS or trusted plain-relay mode;
- asynchronous PDF reports;
- role-based access control and refresh-token rotation;
- structured audit records and JSON audit output.

## 2. Architectural principles

### 2.1 Core and connectors

The system is split into a stateless platform core and independent connectors.

The **core** is a FastAPI application that owns:

- authentication and authorization;
- asset, finding, job, report, settings, connector, and audit state;
- validation and normalization of all API and connector input;
- deduplication and persistence;
- scan scheduling and job creation;
- alert fan-out;
- administrative connector configuration.

A **connector** is a separate container that:

1. registers itself with the core;
2. polls for work;
3. scans its external source using its own API key or toolchain;
4. submits normalized findings;
5. reports completion or failure.

The core does not give connectors database credentials. Connector-to-core requests carry that connector's own `X-Connector-Token` credential: the core issues one token per connector (shown once at issuance, stored only as a SHA-256 digest), resolves the caller from that token alone, and supports per-connector rotation and revocation. There is no platform-wide connector secret, so one leaked token cannot be replayed as another connector. The optional `X-Connector-Name` header is checked for agreement only. Provider API keys are connector-owned runtime secrets and are not present in the core settings model or API.

The core uses an async SQLAlchemy engine. PostgreSQL deployments use connection pooling configured by `DB_POOL_SIZE`, `DB_MAX_OVERFLOW`, `DB_POOL_RECYCLE_SECONDS`, `DB_POOL_TIMEOUT_SECONDS`, and `DB_POOL_USE_LIFO`.

### 2.2 Runtime topology

```text
React SPA --> Nginx --> FastAPI core --> PostgreSQL
                         |       |
                         |       +--> Redis
                         |       +--> Celery worker
                         |       +--> Celery Beat
                         |
                         +<-- connector-dnstwist
                         +<-- connector-shodan
                         +<-- connector-hibp
```

The default Compose deployment publishes the frontend on port `3000` and the backend on port `8000`. PostgreSQL and Redis use named volumes. Reports and the Celery Beat schedule use `reports_store` as local runtime storage. The API does not execute report work in-process when Celery is unavailable; it marks the job failed and returns `503`, avoiding replica-local background state. Nginx serves the React SPA with a single-file fallback (`try_files $uri /index.html`), rather than probing `$uri/`: this is important because `/assets` is both a client route and the build output directory. The fallback prevents a route-specific slash redirect to the internal port and keeps navigation on the configured browser origin.

## 3. Modules and data sources

### 3.1 Phishing module

The phishing module stores look-alike or suspicious infrastructure in `drp_phishing_domains`.

#### DNSTwist connector

- Reads active assets of type `domain`.
- Runs DNSTwist mutations and DNS resolution.
- Submits phishing candidates with `detection_source=dnstwist`.
- The core may enrich accepted findings with WHOIS data.

#### Shodan connector

The Shodan connector supports independent capabilities:

- `scan_ssl_text`: search SSL certificate text;
- `scan_http_title`: search HTTP page titles;
- `scan_favicon`: search favicon hashes.

The connector receives capability configuration from the connector registry. Environment variables are fallback values. Registry configuration takes precedence. Disabling a capability prevents that query from running; disabling all capabilities completes the job without external searches.

Shodan receives active `domain`, `keyword_domain`, and `keyword_title` targets. Active domains and IP addresses are also passed as exclusions to reduce false positives for owned infrastructure.

Phishing statuses are `active`, `investigating`, and `resolved`, stored in `drp_phishing_domains.status`. The product has no takedown workflow.

### 3.2 Breaches module

The HIBP connector reads:

- active `email_account` assets through breached-account lookups;
- active `domain` assets through breached-domain lookups, expanding aliases into per-email findings.

The connector applies its provider's request rate limit and submits normalized breach records. The core validates external data before persistence and deduplicates using breach name plus matched email or matched domain.

All provider scans are executed by connector containers. The core creates connector jobs and accepts normalized findings; it does not perform provider HTTP requests or subprocess scans.

Breach storage is provider-neutral. The core stores the fields every breach source can supply — incident name, matched asset, date, affected-account count, exposed data classes — plus an `attributes` payload for whatever the reporting source knows beyond that (its classification flags, an exposed-secret sample, its own catalog timestamps). A source therefore declares its own payload shape instead of being fitted into another vendor's field set, and the UI renders declared attributes generically (known keys with friendly labels, unknown keys humanized). Submissions that still use the pre-generalization top-level form keep working: those keys are folded into `attributes`.

For display and cleanup, breach records are resolved against the current asset inventory:

1. an exact `email_account` asset matching `matched_email` has priority — when both a
   mailbox and its parent domain are monitored, the finding is about the mailbox;
2. the domain (`matched_domain`, or the domain part of `matched_email`) is used when
   no email asset matches;
3. raw finding values remain available when no current asset resolves.

### 3.3 Module registry

The module set is **data**: it lives in `drp_modules`, not in a constant in core
code, so onboarding a data source whose findings do not fit the phishing or
breach tables is a row plus a connector registration rather than a core release,
a migration and a frontend change. A module declares:

| Field | Meaning |
|---|---|
| `id` | module id; the `connector_type` a connector registers under |
| `label`, `description` | what the UI shows in navigation and the module page |
| `finding_kind` | the schema submissions validate against; one kind identifies one module |
| `asset_types` | inventory sections its connectors receive in a scan (its "appetite") |
| `fields` | declared field specification findings are validated against |
| `dedup_fields` | fields that identify a finding; together they form the dedup key |
| `title_field` | declared field shown as the finding's title |
| `storage` | where findings land (see below) |

The core owns finding **storage, deduplication, audit and alerting** — that is what
keeps a plugin from writing to the database directly. What a module owns is the
shape of its own findings. Two storage modes exist:

- **native** — the platform's original modules (`phishing`, `breaches`) keep their
typed tables and write adapters, so existing behaviour and queries are unchanged;
- **generic** — a module an operator declares stores validated findings as JSON in
`drp_findings`, deduplicated on the key its declared `dedup_fields` produce, read
back through `GET /api/v1/findings`. The native modules keep their own richer,
module-specific endpoints and are not served by that route.

A declared module must specify its fields and at least one dedup field: the
registry rejects a declaration that would store every submission afresh, reuses
an existing id or finding kind, or names a title field it did not declare. Fields
are immutable after declaration, because findings already stored against the
previous specification would otherwise silently change shape — the label and
description remain editable, and a module can be disabled without deleting it.

Administrators manage the registry over the API (viewers may read):

```text
GET    /api/v1/modules           (viewer+)
POST   /api/v1/modules           (admin — declare a module)
PATCH  /api/v1/modules/{id}      (admin — rename, redescribe, enable/disable)
GET    /api/v1/findings          (viewer+ — generic findings, filter by ?module=)
PATCH  /api/v1/findings/{finding_id}    (analyst+ — triage a finding status)
```

## 4. Asset model and lifecycle

Each asset has:

- a UUID;
- one of `domain`, `ip_address`, `email_account`, `keyword_domain`, or `keyword_title`;
- a value up to 512 characters, unique within its asset type after canonicalization;
- criticality `low`, `medium`, `high`, or `critical`;
- an active flag;
- creation and update timestamps.

Asset input validation is type-dependent:

- domains must match the supported FQDN pattern;
- IP assets must be valid IPv4 or IPv6 values;
- email assets must be valid email addresses;
- keyword assets must not be blank.

Access rules:

- viewers can list and view assets;
- analysts and administrators can create and update assets;
- only administrators can delete assets.

### 4.1 Optional cascade deletion

Asset deletion is intentionally non-cascading by default because findings contain denormalized values and may be useful after an asset configuration change.

The administrator may explicitly request:

```text
DELETE /api/v1/assets/{asset_id}?cascade_findings=true
```

When enabled, matching phishing, breach and generic module findings are removed in the same transaction. The UI exposes this as the **Delete related findings** confirmation checkbox. The audit event includes the cascade flag and deletion counts.

### 4.2 Orphan cleanup

Orphan cleanup is separate from asset deletion and is administrator-only:

```text
POST /api/v1/phishing/threats/cleanup-orphans
POST /api/v1/breaches/cleanup-orphans
```

An orphan finding has no matching existing asset. Inactive assets still count as existing assets. Breach cleanup recognizes an exact email asset, an exact domain asset, and a domain extracted from a matched email. Each endpoint deletes only its own module's orphan findings and records the number deleted in the audit trail.

### 4.3 Integrity, search, and database behavior

Asset values are canonicalized before storage and matching: domains use lowercase IDNA form, email domains are case-insensitive, and IP addresses use canonical textual form. The database enforces uniqueness per asset type and canonical value, so a case variant cannot create a second monitoring target while a keyword and a domain may legitimately share text. Pagination is spelled `size` everywhere: there is no second spelling to keep in step.

User administration is administrator-only. The user listing endpoint (`GET /api/v1/users`) supports filtering by `role`, `is_active`, and substring `search`. Demoting, deactivating, or deleting an active administrator is rejected when it would remove the last active administrator; the check locks the active-admin set in PostgreSQL to prevent concurrent operations from bypassing the invariant. Deactivation revokes the user's refresh sessions immediately.

Asset, user, and audit searches escape wildcard characters, pagination is bounded, and listings use deterministic ordering. PostgreSQL statement and pool timeouts remain enabled; when a query exceeds the configured limit, the API returns a retryable `503` response with `code: database_busy` instead of an opaque error.

## 5. Job and connector protocol

### 5.1 Job types

Job types are **open by design**: a connector declares its own at registration
(the manifest protocol, §5.3) and the core accepts any namespaced value
(`<module>.<connector>`), handing each job to the single connector that declared
it. The core enumerates only the types it creates on its own behalf:

- `report.generate`;
- `system`.

Every other job type belongs to exactly one connector, which declares it at
registration. The first-party connectors declare `phishing.dnstwist`,
`phishing.shodan`, and `breaches.hibp`; the targeted lookups on the breach page
(`POST /breaches/scan-email`, `POST /breaches/scan-domain`) are scans of the breaches
module and therefore run as `breaches.hibp`. `GET /api/v1/connectors/modules`
reports the modules and declared job types that are actually registered, and the
module pages use it to filter job history.

Jobs have a status of `pending`, `running`, `success`, `error`, `cancelled`, or `skipped`. They store the creator, connector parameters, result summary, error message, task ID, and lifecycle timestamps.

### 5.2 Connector lifecycle

Connector-side routes are authenticated with that connector's own `X-Connector-Token` credential (issued by the admin API or the `manage_connector_tokens` CLI; there is no shared secret):

```text
POST /api/v1/connectors/register
GET  /api/v1/connectors/me/work
POST /api/v1/connectors/me/findings/{job_id}
POST /api/v1/connectors/me/complete/{job_id}
POST /api/v1/connectors/me/heartbeat
```

A findings submission returns `{"accepted": n, "rejected": m}`, where the counts
mean **newly stored** versus **not stored**. A duplicate is therefore reported as
`rejected`, not as an error: re-scanning the same target is normal and expected,
and the figure means the submission stored nothing new. Malformed entries and
payloads whose dedup key is missing are counted the same way, so a connector must
not treat a non-zero `rejected` as a failure by itself.

`GET /me/work` claims one pending job **by job type** using a row lock with
`SKIP LOCKED`. A job type is owned by exactly one connector, so a connector can
only ever claim its own work — never a sibling's, and never another module's.
The core records the claiming connector and the module in the job parameters. A
connector can complete or fail only a job claimed by itself.

Administrator and reader routes expose registry management and credential
lifecycle:

```text
GET    /api/v1/connectors
GET    /api/v1/connectors/modules      (viewer+)
GET    /api/v1/connectors/jobs
GET    /api/v1/connectors/health       (viewer+)
PATCH  /api/v1/connectors/{connector_id}/status
PATCH  /api/v1/connectors/{connector_id}/config
POST   /api/v1/connectors/provision    (creates the row and issues its token)
POST   /api/v1/connectors/{connector_id}/token   (issue or rotate)
DELETE /api/v1/connectors/{connector_id}/token   (revoke, keep the connector)
```

A connector cannot register itself into existence: a credential is issued to a
connector that already has a row, so provisioning creates both together. That
row carries a *reserved* job type (`<module>.<name>`, which this connector alone
owns) because a row must name the work it can be given; the connector replaces it
with the type it declares when it first registers, and the registration API
requires that declaration, so no job type is ever inferred for a connector that
never declared one. The plaintext is returned exactly once, stored only as a
SHA-256 digest, and the registry API exposes just a public prefix plus
issue/last-used timestamps.
Rotation invalidates the previous token immediately; revocation keeps the
connector's configuration, job history and audit trail.

Modules are **data, not a closed set** (§3.3): `connector_type` is any module id
in the registry, so a connector for a module an operator declared registers like
any other. Registration refuses an id that is unknown or disabled. Connector
statuses are `enabled` and `disabled`.

### 5.3 Connector manifest

Registration carries a self-declared manifest, which is what makes the platform
plugin-driven rather than a closed set of known connectors:

| Field | Meaning |
|---|---|
| `connector_type` | module the connector feeds (must exist and be enabled in `drp_modules`) |
| `default_job_type` | the job type this connector alone claims |
| `finding_kind` | which finding schema its submissions validate as — a native kind (`phishing`, `breach`) or the declaring module's own |
| `asset_types` | asset inventory sections it receives in a scan |
| `config_schema` | operator-editable settings (`key -> {type, label, default}`) |

The core validates the declaration (module coherent with the finding kind, job
type namespaced and unclaimed, asset types known, config keys safe) and stores
it in `drp_connectors.manifest`. Submissions are validated by the declared
finding kind, the config API is driven by the declared schema (declared defaults
materialized, declared types enforced, undeclared keys dropped), and the scan
payload carries only the declared inventory sections. Rows written before the
manifest column existed resolve to the documented defaults for their module, so
no backfill is required.

## 6. Scheduling

Schedules are stored in the singleton `system_settings` row:

```json
{"days": [1, 2, 3, 4, 5], "hour": 2, "minute": 30}
```

- `days` uses `0=Sunday` through `6=Saturday`;
- `hour` is `0..23`;
- `minute` is `0..59`;
- all times are UTC.

The default schedules are weekdays at night:

- phishing: Monday-Friday at `02:30` UTC;
- breaches: Monday-Friday at `03:30` UTC.

Celery Beat runs a one-minute task. At a matching minute, the core uses Redis `SET NX` with a short TTL to prevent duplicate dispatch and creates one pending job for every enabled connector in the module.

Manual `Rescan` uses the same connector job creation path immediately. The phishing page queues DNSTwist and Shodan independently; the breaches page queues HIBP. Rescans are asynchronous: the connector claims a job under a renewable lease, sends heartbeats during long work, and the UI polls until terminal state before refreshing findings. If a connector disappears, an expired lease returns the job to `pending` for a bounded number of attempts; after the retry limit it becomes `error` and releases its provider admission slot. Provider authentication, rate-limit, and network failures are recorded as structured job details rather than silently becoming an empty successful result.

Before a job is committed, the core also acquires one Redis-backed admission slot per connector. The slot is shared by manual scans, scheduled scans, users, and API replicas, so a second scan for the same provider returns `409` instead of spending another provider quota. The guard fails closed with `503` when Redis cannot enforce it; a one-hour TTL and ownership-checked release recover from crashed workers. The per-user manual throttle remains a separate UX safeguard and does not replace this provider-wide guard. A missing connector is reported as `no_connector`; database and unexpected enqueue failures are not rewritten as that status.

## 7. Alerts and integrations

Administrators can enable email and Telegram channels independently.

### Email alerts

Recipients can be selected from active users of any role through `alert_email_user_ids`. An optional additional address is supported by `alert_recipient_email`. Recipients are deduplicated before dispatch.

SMTP configuration includes host, port, username, password, and sender address. SMTP password and sender/recipient secret fields are Fernet-encrypted at rest. The Settings UI saves the current SMTP form before sending a test email, so a newly entered configuration is tested immediately rather than the previous persisted values. Mailtrap Sandbox commonly uses port `2525` with STARTTLS; port `465` uses implicit TLS. Use the exact hostname and credentials shown by the Mailtrap integration page.

### Telegram alerts

The settings model supports multiple `telegram_chat_ids`, one ID per entry, and that list is the only Telegram destination: the earlier single `telegram_chat_id` field was removed in v0.1.0 (a request still carrying it is rejected, not silently accepted). The Telegram bot token is encrypted at rest. `POST /api/v1/settings/validate-telegram` uses Telegram `getChat` with the stored token and returns a safe per-chat result without exposing the token. The Settings UI validates all chats before sending a test message; inaccessible chats are reported with stable reasons such as `chat_not_found`, `bot_blocked`, or `insufficient_rights`. Delivery is attempted per chat so one invalid chat does not prevent delivery to the others.

Both channels use retry logic. Finding notifications are persisted before delivery, aggregated by job and threat type, and tracked independently per channel and recipient; a successful email does not mark a failed Telegram delivery as sent. Dispatch success and failure are written to the audit trail. Telegram validation and test endpoints are available to administrators:

```text
POST /api/v1/settings/test-email
POST /api/v1/settings/validate-telegram
POST /api/v1/settings/test-telegram
```

## 8. Reports

A report request creates a `reports` row and a `report.generate` job. Celery executes the report task, writes a PDF into `REPORTS_STORE_DIR`, and updates the report status:

- `pending`;
- `generating`;
- `completed`;
- `failed`.

Authenticated users with viewer access can list and download completed reports. Only administrators can delete reports. Deleting a report also attempts to remove its file from local storage.

## 9. Identity, authorization, and security

### Roles

- `admin`: user administration, settings, connector administration, audit access, report deletion, asset deletion, and all analyst/viewer capabilities;
- `analyst`: asset creation/update, finding updates/deletion, scans, and report generation;
- `viewer`: read-only access to permitted application data.

### Authentication

- Passwords are bcrypt hashes. New passwords are at least 12 characters and no more than 72 UTF-8 bytes (the bcrypt input boundary), with an uppercase letter and a digit. Sign-in accepts any password the account may hold, including one an administrator set through the CLI, which is a stronger check than the creation policy and is applied to the *current* password rather than to the new one.
- Login uses email/password authentication and records success/failure/lock events.
- Redis rate limiting protects email and IP keys.
- Database fields track failed attempts and lock expiry.
- Access tokens are JWTs.
- **A browser session is restored from the cookie, never from the browser.** The access token is held in memory and a reload therefore drops it; the session of record is the `HttpOnly` refresh cookie. So every page load asks `POST /auth/refresh` once, from `main.tsx` and before the app decides what to render, and adopts the answer; **nothing about the session is written to browser storage at all**. It is asked rather than inferred because a client-side record cannot carry that decision: a private window, cleared site data, a denied-storage profile, or a read that fails outright all leave a valid server-side session looking absent, and the API is the only party that knows. Asking it *imperatively* rather than from a `persist` rehydration callback is not a style choice either: hydration runs while the module graph is still being evaluated, and a cycle between two modules can hand the running code a binding that does not exist yet — which, in a store that catches its own errors, is indistinguishable from "this browser has no session". `lib/session-bridge.ts` carries the full account, `lib/api.ts` reaches the session through it rather than importing the store, and both `vite.config.ts` (fails the build) and `src/lib/moduleGraph.test.ts` (walks the graph) refuse the cycle coming back. The refresh itself is single-flight, shared with the `401` interceptor: the token is rotated on use, so two overlapping presentations of it read as re-use and revoke the whole family. A refusal is handled quietly, since a browser that never signed in is not one whose session expired, and the API deletes the cookie when it refuses the token in it — the client presents that token on every load, so a dead one would otherwise be retried, and audited as `auth.refresh.failure`, once per load until it expired. Signing out ends the session on both sides for the same reason: local state first, then `POST /auth/logout`, which revokes the family. Clearing only the browser would leave the cookie valid for its whole lifetime, and the next load would restore the session the operator had just ended.
- Refresh token families are stored in `drp_refresh_families`, rotated on use, and revoked on reuse detection, password reset, password change, and account removal. The revocation itself is one shared implementation (`app/services/refresh_sessions.py`) because three callers need it — the users router, the auth router and the admin CLI — and each records how many sessions it ended (`refresh_families_revoked`) in its audit details.
- **A TOTP second factor is available for every role** and is enforced at login for accounts that enable it (`totp_enabled_at`). Invalid, missing, and recovery-code MFA attempts have a dedicated lockout budget so OTP guessing cannot bypass throttling or consume the password budget. The code is requested only after the password verifies, so the endpoint cannot be used to discover which accounts have a factor. Each accepted code is single-use — the counter it matched is stored in `totp_last_used_step`, which closes the replay window that the ±1-step clock-skew tolerance would otherwise open. A wrong code counts towards the same lockout as a wrong password; a *missing* code is refused without consuming an attempt, so a misconfigured integration cannot lock out its own operator. The secret is Fernet ciphertext under `ENCRYPTION_KEY`.
- Enrolment is self-service (`/auth/mfa/setup` requires the password again, then `/auth/mfa/enable` verifies a code); the UI offers an SVG QR code and manual URI/secret entry. Successful enrolment displays ten one-time recovery codes exactly once; only bcrypt hashes are stored, and a recovery code can replace the TOTP code at login. Removal requires both the password and a live code. Recovery is a human path: an administrator clears another user's factor through `POST /users/{id}/mfa/reset` (audited as `user.mfa.reset` and refused for the caller's own account), while a locked-out administrator uses `python -m scripts.manage_admin mfa-off`, which needs access to the deployment rather than to a browser.
- **A credential somebody else chose is treated as temporary.** `POST /auth/password` is how an account holder sets their own password — an administrator can only assign one — and it rotates the session (the response carries a new access token, every other refresh family is revoked with reason `password_change`) so the operator is not signed out by their own action. Two per-account flags drive the flow: `must_change_password`, set whenever a password is assigned *for* someone (creating a user over the API, an administrator reset, `manage_admin create`/`reset`), and `must_enrol_mfa`, set whenever a factor is removed *for* them (`POST /users/{id}/mfa/reset`, `manage_admin mfa-off`). While either is set, every authenticated route is refused with `403` and the marker `onboarding_required` — except `/auth/me`, `/auth/password`, `GET /auth/mfa` and, once the password step is done, `/auth/mfa/setup` and `/auth/mfa/enable`. The order is the server's, because both enrolment endpoints re-check the password: a factor must not be attached while a temporary password is in force, or it would be bound to a credential its owner is about to discard. It is checked inside `get_current_user` (like the request rate limit) so a route added later cannot forget it, and it is deliberately **not** audited: the state was audited when the administrator created it (`user.password_reset` / `user.mfa.reset` carry `onboarding_required` in their details), and a row per refused request would be noise — it is emitted as the structured log event `credential_onboarding_required` instead. Completing a step clears the flag by evidence only: the password endpoint, and a code verified by `/auth/mfa/enable` (which records `was_required`). The escape hatch for an account that cannot complete the flow is `python -m scripts.manage_admin onboarding-off` from the host.
- **The deployment-wide policy `REQUIRE_MFA_FOR_ADMINS` is a step of the same flow, not a filter on admin pages.** An administrator with no enrolled factor is refused by the gate above on *every* route, with the marker `mfa_required` and an audit row (`auth.mfa.required`, carrying the `reason` that produced it), because an administrator acting without a second factor is itself the signal. It is asked at sign-in rather than discovered later: every user payload carries `mfa_required_by_policy`, computed by `app/core/mfa_policy.py` from the setting and the account's enrolment — no flag is written to `users`, so enrolling one clears it and turning the setting off releases every account at once. The policy applies to administrators only, since they are the account that can create users, read the trail and change settings, and `require_admin` keeps the same check as a second line of defence. Its recovery is the setting: `manage_admin onboarding-off` releases an account's *own* steps, not this one, so an administrator who cannot enrol is released by `REQUIRE_MFA_FOR_ADMINS=false` and a recreated container. `manage_admin list` reports the state as `mfa (policy)`, which is what answers the support call when the account itself looks clean.
- The Security page provides self-service password change, one-time MFA recovery-code rotation, active-session listing/revocation, and recent security activity for the signed-in account. The session list holds only sessions that can still be used — every sign-in writes a `drp_refresh_families` row and every password change rotates the session, so an account quickly owns rows it can no longer act through, and listing them under a card titled "active sessions" made a session its owner had just closed read as an unknown device. What *ended* a session is an audit event (`auth.password.changed` counts the other sessions it signed out, `auth.session.revoked` and `auth.sessions.revoked_others` name theirs) and appears in the activity list beside it; the nightly sweep removes revoked rows once their refresh tokens can no longer be presented (`JWT_REFRESH_TOKEN_EXPIRE_DAYS`), since until then the row is what answers a replayed token with `family_revoked` instead of `family_not_found`. The last active administrator cannot be demoted, deactivated, or deleted. Each listed event is described in words ("Second factor turned on" for `auth.mfa.enrolled`), a refusal names its reason ("Sign-in attempt refused — the password did not match an active account"), and a replayed refresh token says so, with the action code kept beneath as the name the audit log and a support request use. `GET /auth/security-activity` returns codes, so the wording lives in `frontend/src/lib/audit.ts`, shared with the audit log: an event must not be described two ways depending on who is reading it. An action the UI has no sentence for is humanized together with its details rather than printed as a code, and `audit.test.ts` fails when an action the endpoint can return has no description of its own.
- `ENCRYPTION_PREVIOUS_KEYS` and `JWT_PREVIOUS_SECRET_KEYS` allow a secret to be rotated without invalidating stored ciphertext or signing every user out; `scripts/rotate_keys` generates, reports and re-encrypts. The procedure is in [`upgrading.md`](upgrading.md#rotating-secrets).

### Input and transport protection

- Pydantic validation covers user, asset, schedule, connector, HIBP, SMTP, Telegram, UUID, enum, and pagination input.
- SQLAlchemy query construction uses bound parameters.
- Connector registration accepts only allowlisted metadata fields.
- Connector configuration is validated by connector type; Shodan capability keys are explicit.
- FastAPI and Nginx set security headers.
- CORS origins are configured by environment.
- Compose requires database, JWT, Fernet, proxy, and CORS configuration values before startup; production additionally rejects placeholder-like secrets. Connector tokens are deliberately *not* interpolation-required: a missing one would otherwise make every `docker compose` command — including the one that issues tokens — fail, so a blank token instead fails closed at the connector (refuses to start) and at the core (rejects an unknown credential).
- Production deployments must set unique JWT and Fernet encryption secrets.
- `ALERT_HEALTH_CHECK_TIMEOUT_SECONDS` bounds outbound alert-channel probes and transport calls.
- `AUTHENTICATED_RATE_LIMIT_PER_MINUTE` (default 600, `0` disables) bounds authenticated requests per account. Because every read writes an audit row, an unthrottled credential could amplify load on PostgreSQL and on the audit pipeline; the block is audited once per window so the limiter does not itself become that amplifier. The check fails open when Redis is unavailable, trading strictness for availability.

## 10. Audit trail

Important authentication, administrative, scan, connector, finding-ingestion, alert, report, and read events are audited.

Each structured event contains:

```json
{
  "timestamp": "2026-09-06T00:00:00+00:00",
  "user_id": "UUID or null",
  "action": "asset.create",
  "ip_address": "client or internal service address",
  "details": {}
}
```

Rows are stored in `drp_audit_logs`. The same event is emitted as JSON to application output for log pipelines such as Elastic Security (see [`observability.md`](observability.md) for the collector recipe). The stdout line carries exactly the five fields above — a sixth would reach a SIEM index that maps the documented shape — so request correlation is recorded inside `details.request_id`. Audit access is administrator-only and supports action, user, date, email, and text filters, and audit history is swept by the nightly retention task described in [`backup-restore.md`](backup-restore.md).

## 11. API route groups

The public health and authentication routes are:

```text
GET  /api/v1/health
GET  /api/v1/ready
POST /api/v1/auth/login
GET  /api/v1/auth/me
POST /api/v1/auth/password
POST /api/v1/auth/refresh
POST /api/v1/auth/logout
GET  /api/v1/auth/mfa
POST /api/v1/auth/mfa/setup
POST /api/v1/auth/mfa/enable
POST /api/v1/auth/mfa/disable
POST /api/v1/auth/mfa/recovery-codes/rotate
GET  /api/v1/auth/sessions
DELETE /api/v1/auth/sessions/{family_id}
POST /api/v1/auth/sessions/revoke-others
GET  /api/v1/auth/security-activity
```

Core route groups:

```text
/api/v1/dashboard
/api/v1/assets
/api/v1/phishing
/api/v1/breaches
/api/v1/reports
/api/v1/jobs
/api/v1/modules
/api/v1/alerts
```

Administrator route groups:

```text
/api/v1/users
/api/v1/settings
/api/v1/audit
/api/v1/connectors
```

The exact implemented routes and role matrix are maintained in [README.md](../README.md).

## 12. Deployment and operations

The supported deployment is Docker Compose, on Linux or on Windows through
Docker Desktop with the WSL 2 backend. The development shape bind-mounts
`./backend`, `./connectors` and `./reports_store`; the production shape uses
pinned images and named volumes instead. See [`deployment.md`](deployment.md)
for the complete production procedure and resource profile.

Provisioning is one command, and it writes the secrets rather than asking the
operator to invent them:

```bash
python setup.py                 # answers -> .env, secrets from the OS CSPRNG
docker compose up -d --build
docker compose ps
curl http://localhost:8000/api/v1/health
curl http://localhost:8000/api/v1/ready
```

`setup.py` needs **Python 3.8 or newer and nothing else** — standard library
only, no `pip install`, no `cryptography` (the Fernet key is built from `secrets`
and `base64` and verified by decoding it), no network. It asks only what has no
safe default — the release to run (offered as the version this checkout
declares, because `make up` builds the images from it), the public URL the UI is
served from (with the shape of an answer printed in the prompt), the loopback
bindings this host publishes, which connectors to enable, and whether
administrator routes need a second factor. It refuses to overwrite an
`.env` that already holds secrets, and it refuses to write one that git would
commit, so the file the deployment depends on cannot reach the repository by
accident. `--check` audits an existing `.env` against the template and the
startup rules, `--repair` fills only the gaps, `--force` rotates the secrets
while keeping the replaced ones verifiable (see [upgrading.md](upgrading.md)).
Without a host Python it runs in a container:
`docker run --rm -it -v "$PWD":/work -w /work python:3.12-alpine python setup.py`.

`.env.example` is the configuration reference, and it is checked rather than
trusted: `scripts/check_env_template.py` (CI job `repo-hygiene`, `make check-env`)
fails the build when a variable a Compose file reads is undocumented, when a
setting the template documents is never passed into a container, when a Compose
file shadows one with a literal value, or when a setting that belongs to one
connector is named as if it belonged to the platform (`.env` is a single
namespace, so `SHODAN_SCAN_SSL_TEXT` rather than `SCAN_SSL_TEXT`).

`make` wraps the common operations (`up`, `down`, `restart`, `health`, `logs`,
`migrate`, `test-backend`, `typecheck-backend`, `seed-demo`, `clean`) but is
optional — `make` does not ship with Git for Windows, and [README.md](../README.md)
lists the direct `docker compose` equivalent of every target. Every command in
those instructions is a single line, so it pastes into bash, PowerShell or
`cmd.exe` unchanged: `scripts/check_portable_commands.py` (CI job `repo-hygiene`,
`make check-commands`) fails the build when one of them grows a shell-specific line
continuation or a value quoted the way only one shell reads.

Database changes are applied by Alembic; deployments run `alembic upgrade head` (the current head is the initial revision in
`backend/alembic/versions`, `0001_initial_schema`) rather than
applying [db.sql](db.sql) independently — the reference DDL is a readable
snapshot, not a migration path. The current migration head is `0001_initial_schema`; always run the migration gates rather than relying on a copied schema snapshot — `scripts/check_migrations.py` verifies the revision graph, and `scripts/check_schema_drift.py` verifies that the schema the revisions build contains exactly the tables and columns the models map (a model column no revision creates is a process that cannot start). The API container applies pending revisions itself
at startup, serialised by a PostgreSQL advisory lock (`backend/scripts/migrate.py`),
so two replicas starting together cannot race.

CI runs Python compilation, the backend suite, a coverage floor, per-module
critical-coverage gates, frontend typecheck/build, and Compose interpolation
validation on Linux. The same workflow audits the shipped dependency sets
(`pip-audit` over the backend runtime requirements, `npm audit --omit=dev` over the
frontend, plus dependency review on pull requests), fails when an ignore rule keeps
source out of the repository, and runs the PostgreSQL/Redis integration suite with
a guard that fails the job when it did not actually run. Runtime checks must still
be performed against the target deployment, including PostgreSQL migrations and
connector registration.

### Provider credentials

Provider credentials never live in the core: they are connector runtime secrets
(`SHODAN_API_KEY`, `HIBP_API_KEY` — connector environment variables in `.env`),
and the core stores none of them. `system_settings` holds only the settings the
core itself uses, which is why its encrypted columns are limited to SMTP and the
Telegram token.

### Repository hygiene

Generated PDFs, runtime databases, Celery Beat state, `.env`, dependency
directories, build output and caches are local artifacts; `.gitignore` and
`.dockerignore` keep them out of the repository and out of the build context.
Real credentials live only in `.env`, which is never committed — see
[SECURITY.md](../SECURITY.md) for how to report an exposure.
