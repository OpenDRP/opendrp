# OpenDRP

OpenDRP is a self-hosted Digital Risk Protection platform for monitoring domains, IP addresses, email accounts, and brand keywords. It detects phishing and look-alike infrastructure, searches Have I Been Pwned (HIBP) breach data, generates PDF reports, sends alerts, and records security-relevant activity in an audit trail.

The platform uses a **core + connector** architecture. The FastAPI core owns application state, authorization, validation, jobs, ingestion, deduplication, alerts, scheduling, audit logs, and the web API. External data sources run in independent connector containers and communicate with the core over HTTP.

## Architecture

```text
Browser
  |
  +-- frontend:80 (Nginx + React SPA, host port 3000 by default)
        |
        +-- /api/ --> backend:8000 (FastAPI core)
                         |
                         +-- PostgreSQL 17 (SQLAlchemy async + asyncpg pool)
                         +-- Redis 7 (Celery broker and schedule deduplication)
                         +-- Celery worker (reports, alert delivery, retention)
                         +-- Celery Beat (one-minute scan scheduler)

connector-dnstwist  --> core connector API (module: phishing)
connector-shodan    --> core connector API (module: phishing)
connector-hibp      --> core connector API (module: breaches)
```

The connectors are stateless from the platform perspective:

1. Register with the core using its own `X-Connector-Token` credential.
2. Long-poll for a pending job.
3. Run the external scan inside the connector container.
4. Submit validated, normalized findings to the core.
5. Report job completion or failure.

The core performs all database writes and applies deduplication, enrichment, alert fan-out, and audit logging. Connectors do not receive database credentials.

### First-party connectors

| Connector | Module | Source and scope | Main configuration |
|---|---|---|---|
| `dnstwist` | `phishing` | DNSTwist mutations and DNS resolution for active domain assets | `CONNECTOR_NAME=dnstwist`, `CONNECTOR_TYPE=phishing` |
| `shodan` | `phishing` | Shodan SSL text, HTTP title, and favicon searches | `SHODAN_API_KEY`, `SHODAN_SCAN_SSL_TEXT`, `SHODAN_SCAN_HTTP_TITLE`, `SHODAN_SCAN_FAVICON` |
| `hibp` | `breaches` | HIBP breached-account and breached-domain lookups | `HIBP_API_KEY` |

Two provider-side limits are worth knowing before the first scan:

- **Shodan.** The connector's `ssl:"…"` and `http.favicon.hash` searches use
  query filters that Shodan does not serve on every plan, so full coverage needs
  a key of at least the **Membership** tier. A lower-tier key is not reported as
  a clean scan: the provider's refusal appears in the job summary as a partial
  scan, and `scan_http_title` is the capability a free key can exercise.
- **HIBP.** HIBP publishes an integration key for validating an installation
  without a subscription — `HIBP_API_KEY=00000000000000000000000000000000`. With
  it, a breaches scan returns the documented fixture breaches for
  `account-exists@hibp-integration-tests.com` and for `hibp-integration-tests.com`,
  so adding those two as an `email_account` asset and a `domain` asset gives a
  new installation a working end-to-end scan. It is a test identity, not a
  secret: it only ever returns fixture data, and real results need a real key.

The connector registry is stored in `drp_connectors`. Administrators can enable or disable a registered connector and update its validated configuration from **Settings → Connectors**. For Shodan, registry settings override environment fallbacks on the next scan.

See [connectors/README.md](connectors/README.md) for the connector protocol and SDK contract.

## Features

- Asset inventory with `domain`, `ip_address`, `email_account`, `keyword_domain`, and `keyword_title` types.
- Asset criticality and active/inactive state management, with canonical per-type uniqueness and bounded search/pagination.
- DNSTwist, Shodan, and HIBP connector scans.
- Manual `Rescan` actions and configurable UTC schedules for the `phishing` and `breaches` modules.
- Matched-asset resolution for breach findings: an exact `email_account` asset wins when the breached address is monitored itself, otherwise the finding resolves through the address's domain, and raw provider values stay intact when nothing in the inventory matches.
- **Modules are data, not code.** `drp_modules` declares a module's findings kind, consumed inventory, field schema, deduplication keys and storage target, so an operator can register a new source with `POST /api/v1/modules` and its findings land in `drp_findings` without a core change. Declared findings are read through `GET /api/v1/findings` and triaged through `PATCH /api/v1/findings/{finding_id}`.
- Role-based access control: `admin`, `analyst`, and `viewer`.
- **Two-factor authentication (TOTP)** that any role can enable from **My security**: a six-digit code from an authenticator app on top of the password, single-use, counted towards the same lockout as a wrong password, with an audited administrator reset for a lost device.
- Optional cascade deletion of findings when an administrator deletes an asset.
- Separate administrator-only cleanup actions for orphan phishing and breach findings.
- Email and Telegram alerts for newly discovered findings, persisted and retried independently per channel and recipient so one destination outage does not lose another destination's delivery.
- Recipient selection by user and multiple Telegram chat IDs.
- PDF report generation through Celery.
- Structured JSON audit events on stdout (exactly `timestamp`, `user_id`, `action`, `ip_address`, `details`) plus a persistent audit record, both carrying the request's `X-Request-ID` for correlation across HTTP, Celery and the SIEM.
- Security headers, input validation, parameterized SQLAlchemy queries, refresh-token rotation, login rate limiting, and bounded outbound alert checks.
- **Data retention and backups**: a nightly sweep of audit history and generated reports, and `make backup` / `backup-verify` / `restore` — the restore path runs in CI on every push.

## Prerequisites

- **Docker.** Docker Desktop on Windows and macOS, or Docker Engine with the
  Compose v2 plugin on Linux. Every service image is a Linux image, so on
  Windows the containers run through WSL 2 and the drive holding the checkout
  must be shared with Docker Desktop.
- **Docker Compose v2.24 or newer.** There is one installation shape —
  `docker-compose.yml` — and the development overlay
  (`docker-compose.dev.yml`) is a separate file that only the test and lint
  targets layer on (`make up-tools`); the two-replica scenario uses `!reset` tags,
  which need v2.24. `docker compose version` reports what you have.
- **CPU, RAM and disk**: 4 cores, 8 GB RAM and 40 GB free space are the
  recommended floor for an installation that serves other people; 2 cores, 4 GB
  RAM and 20 GB free space is enough to try it on one machine. The space covers
  the database, generated reports, backups and the bounded container limits the
  stack applies per service; raise those limits deliberately, after measuring the
  workload. The wizard warns when the host is below the floor.
- **Optional tooling**: `make` for the shortcut targets used throughout this
  document, and **Python 3.8 or newer on the host** for the setup wizard
  (`python setup.py`), which generates the random secrets and writes `.env`.
  `make` does not ship with Git for Windows; every target has a
  [direct `docker compose` equivalent](#running-without-make).

  The wizard needs **nothing installed**: it imports only the Python standard
  library — no `pip install`, no `cryptography`, no virtualenv. It generates the
  Fernet key with `secrets` and `base64` and checks it by decoding it, which is
  the same validation the application performs. Without a host Python it runs in
  a container from the checkout:
  `docker run --rm -it -v "$PWD":/work -w /work python:3.12-alpine python setup.py`.

  (The backend's own dependencies — `cryptography`, which encrypts the settings at
  rest, among them — are installed inside the images from
  `backend/requirements.txt`, not on the host. A Compose deployment needs nothing
  on the host except Docker, and Python only for this one provisioning step.)
- **Network access** for the configured Shodan, HIBP, DNS/WHOIS, SMTP and
  Telegram integrations. Shodan needs a key of at least the Membership tier for
  the SSL-text and favicon capabilities, and HIBP has a documented integration
  key that makes a test installation work without a subscription — see
  [First-party connectors](#first-party-connectors).

## Quick start

For a complete production procedure, including TLS, pinned images, backups,
resource checks, connector provisioning and post-deployment verification, see
[docs/deployment.md](docs/deployment.md). The steps below are the shortest local
or small-installation path.

Every command below is one line, so it can be pasted as-is into bash, zsh,
PowerShell or `cmd.exe`: no line continuations, and double quotes wherever a
value is quoted - `cmd.exe` does not treat single quotes as quoting, and it
reads `<placeholder>` as input redirection.

1. Get the code and let the wizard write the configuration:

   ```bash
   git clone https://github.com/OpenDRP/opendrp.git
   cd opendrp
   python setup.py
   ```

   It asks a small set of questions — the release to run (offered as the version
   this checkout declares, so Enter accepts the one the images are built from),
   the public URL users will reach (the prompt carries an example; nothing guesses
   an origin), the loopback bindings this host publishes, the connectors to
   enable, administrator MFA and retention defaults —   then does the rest. There is no deployment profile to choose: the wizard
   writes one shape, the production one, and `make up` starts it. Every secret
   (`POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `JWT_SECRET_KEY`, `ENCRYPTION_KEY`,
   `AUDIT_CHAIN_KEYS`) is generated with the operating system's CSPRNG, so none
   is invented by hand; the comments in `.env.example` are carried into `.env`
   unchanged; the result is checked against the rules the application enforces at
   startup before the file is written; and the output ends with the exact commands
   that finish the installation on this host.

   The generated values are never printed — only a fingerprint of each, which is
   enough to confirm that a value was written. Afterwards
   `python setup.py --check` audits an existing `.env` without touching it,
   `--repair` fills only the gaps, and `--force` rotates the secrets while keeping
   the replaced ones valid (see `docs/upgrading.md`). On Windows use
   `py -3 setup.py`; the script needs Python 3.8+ and no packages at all, so
   nothing has to be installed for this step.

   To do it by hand instead, copy `.env.example` to `.env` and fill in the five
   values its header lists — the file explains each setting, and any missing
   *required* value is a startup failure rather than a silent default. Never commit
   `.env`; `.env.example` is the public template.

2. Start the stack:

   ```bash
   make up
   # equivalent without make:
   docker compose -f docker-compose.yml up -d --build
   ```

   Startup applies Alembic migrations under a PostgreSQL advisory lock (so two API
   replicas can start together), ensures the `system_settings` singleton, and starts the core, workers, and first-party connectors. It does not create an administrator account. The connector workers have no credential yet, so they exit with `Missing required environment variables: CONNECTOR_TOKEN` — expected, and fixed next.

   Nothing in the stack terminates TLS: the UI is published as plain HTTP on
   `127.0.0.1:3000`, and the proxy in front of the host is what makes it
   `https://`. `docs/deployment.md` has the procedure and
   `docker/nginx/reverse-proxy.example.conf` is a working nginx configuration for
   it, self-signed certificate included. HSTS stays off until that certificate is
   one browsers already trust — see `.env.example`, "TLS and HSTS".

3. Issue a credential per connector. Each worker authenticates with its own
   token (there is no shared connector secret), and the plaintext is printed
   once and never stored. These three commands are the whole step — each one
   prints its `CONNECTOR_TOKEN_<NAME>=…` line, which goes into `.env` as-is:

   ```bash
   docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens issue dnstwist --type phishing --env CONNECTOR_TOKEN_DNSTWIST
   docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens issue shodan --type phishing --env CONNECTOR_TOKEN_SHODAN
   docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens issue hibp --type breaches --env CONNECTOR_TOKEN_HIBP
   docker compose -f docker-compose.yml up -d connector-dnstwist connector-shodan connector-hibp
   ```

   The name is the worker's `CONNECTOR_NAME` (`dnstwist`, `shodan`, `hibp`),
   `--type` is the module that worker feeds, and `--env` is the variable it is
   printed as. `up -d` is a *recreate*, and that is the part that applies the
   value: Compose reads `.env` when a container is created, so `docker compose
   restart connector-dnstwist` would keep the placeholder and exit with the same
   error.

   Rotating a token is the same shape with `rotate`. The previous value stops
   working immediately, and the connector keeps its registry row, configuration
   and job history:

   ```bash
   docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens rotate dnstwist --env CONNECTOR_TOKEN_DNSTWIST
   docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens rotate shodan --env CONNECTOR_TOKEN_SHODAN
   docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens rotate hibp --env CONNECTOR_TOKEN_HIBP
   docker compose -f docker-compose.yml up -d connector-dnstwist connector-shodan connector-hibp
   ```

   `revoke <name>` cuts a connector off without deleting its registry row,
   configuration or job history, and `list` reports which connectors hold a
   credential:

   ```bash
   docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens revoke dnstwist
   docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens list
   ```

   On a host with `make`, the same operations also update `.env` for you —
   `connector-token-rotate` re-keys one connector in place, and
   `connector-tokens` lists who holds a credential:

   ```bash
   make connector-token NAME=dnstwist TYPE=phishing
   make connector-token NAME=shodan TYPE=phishing
   make connector-token NAME=hibp TYPE=breaches
   make connector-token-rotate NAME=hibp
   make connector-tokens
   ```

   A connector started without a token does not fail the stack: it exits with a
   clear message and the core rejects any credential it did not issue.

4. Supply the provider keys. They are connector runtime secrets rather than core
   settings: each one reaches only its own connector container, and a container
   keeps the environment it was created with, so a changed key is applied with
   `up -d --force-recreate connector-<name>`, not with `restart`.

   ```text
   SHODAN_API_KEY=your-shodan-api-key
   HIBP_API_KEY=00000000000000000000000000000000
   ```

   The wizard asked for both in step 1, so this is the same file — the point of
   writing them out is what each one has to be:

   - **Shodan** needs a key of at least the **Membership** tier for the
     `ssl:"…"` (SSL text) and `http.favicon.hash` (favicon) searches it runs. A
     lower tier is not reported as a clean empty scan: the provider's refusal
     appears in the job summary as a partial scan. `scan_http_title` is the
     capability a free key can exercise.
   - **HIBP** publishes an integration key that needs no subscription —
     `00000000000000000000000000000000`. It returns the documented fixture
     breaches for exactly two identities:
     `account-exists@hibp-integration-tests.com` and
     `hibp-integration-tests.com`. Add those as an `email_account` asset and a
     `domain` asset, and a breaches scan completes end to end on a brand-new
     installation. It is a test identity, not a credential: it only ever answers
     with fixture data, so real results need a real key.

5. Create the first administrator. Replace the quoted temporary password with
   one that meets the CLI's bootstrap minimum (8 characters, one uppercase letter
   and one digit). The user will set a new password during first sign-in; the
   regular account password policy requires at least 12 characters and no more
   than 72 UTF-8 bytes.

   ```bash
   docker compose -f docker-compose.yml exec backend python -m scripts.manage_admin create --email admin@example.com --password "ChangeMeAdminPass123!"
   ```

   The password typed here is **temporary**. Whoever runs this command knows it,
   and so does the shell history it was typed into, so the platform asks the
   account to choose its own at the first sign-in. Until that is done it refuses
   the account everywhere except the onboarding page. That page asks for whatever
   is missing, in the order the server enforces: first your own password, then a
   second factor if the deployment requires one of administrators
   (`REQUIRE_MFA_FOR_ADMINS=true`) and this account has none. Nothing is lost by
   signing in with the temporary password: the first screen is the one that
   replaces it.

   If you answered `y` to the wizard's second-factor question, this is where that
   answer lands: the administrator you are about to create is asked for an
   authenticator app at this first sign-in, and can reach nothing else until it is
   enrolled. An administrator who genuinely cannot enrol is released by turning the
   setting off — `REQUIRE_MFA_FOR_ADMINS=false` in `.env`, then recreate the
   container (`up -d`, not `restart`: the value is read when the container is
   created). `manage_admin onboarding-off` releases the account's *own* steps, such
   as a password it cannot replace, and does not apply to this one.

6. Open the UI at <http://localhost:3000>, sign in with that address and the
   temporary password, and complete the steps the page asks for.

The public `v0.1.0` branch is the reviewed source snapshot for version 0.1.0 (it is a branch, not a release tag). The initial publication does not include a `v0.1.0` tag or prebuilt GHCR images; the quick start builds images from source. For a later tagged release, `OPENDRP_VERSION` must be pinned to that release; `latest` is rejected by the setup checks and by the application.

The public health endpoint is:

```text
http://localhost:8000/api/v1/health
```

Non-production API documentation is available at `/api/docs`, `/api/redoc`, and `/api/openapi.json`. API documentation is disabled when `APP_ENV=production`.

## Services and persistence

| Service | Purpose |
|---|---|
| `frontend` | React 18.3 SPA built with Vite and served by Nginx; proxies `/api/`. |
| `backend` | FastAPI platform core and REST API. |
| `postgres` | PostgreSQL 17 application database. |
| `redis` | Celery broker and Redis-backed schedule deduplication. |
| `celery-worker` | Background report-generation task execution. |
| `celery-beat` | One-minute scheduler for database-configured scan schedules. |
| `connector-dnstwist` | Phishing connector for DNSTwist. |
| `connector-shodan` | Phishing connector for Shodan. |
| `connector-hibp` | Breaches connector for HIBP. |

The Compose deployment persists PostgreSQL and Redis in named volumes. Generated reports and the Celery Beat schedule are stored in the local `reports_store` directory, which is runtime data and must not be committed.

The backend uses an async SQLAlchemy connection pool. Defaults are `DB_POOL_SIZE=20`, `DB_MAX_OVERFLOW=10`, `DB_POOL_RECYCLE_SECONDS=1800`, `DB_POOL_TIMEOUT_SECONDS=30`, and `DB_POOL_USE_LIFO=True`. Connection-pool saturation and statement timeouts return a retryable `503 database_busy` response with `Retry-After`; monitor pool pressure rather than increasing limits without checking PostgreSQL's connection budget. The API does not run report-generation fallbacks in process: if Celery is unavailable, the job is marked failed and the request returns `503`, preserving stateless behavior.

For local-only exposure, use loopback port bindings such as `127.0.0.1:3000`, `127.0.0.1:8000`, `127.0.0.1:5432`, and `127.0.0.1:6379`. Review `.env.example` before exposing any service to a network.

## Configuration

### Environment configuration

`.env.example` is the configuration reference: every setting Compose reads is
listed there with its default and the reason it exists, including the optional
overrides most deployments never touch. `python setup.py` writes a working `.env`
from it (see [Quick start](#quick-start)).

The template is checked rather than trusted: `make check-env` fails if a variable
Compose reads is not documented, if a documented application setting is never
passed into a container (a knob that would silently do nothing), or if a Compose
file sets one to a literal value that shadows `.env`. Each of those shipped as a
real defect before the check existed.

Groups worth knowing about:

- PostgreSQL and Redis connection settings. Both datastores take a generated
  password; Redis is the Celery broker, so an unauthenticated one is a way to hand
  the worker a task it will execute with the platform's own database credentials.
- JWT and Fernet encryption secrets, and the `*_PREVIOUS_*` lists that keep a
  rotation from invalidating live sessions, stored ciphertext and signed history.
- CORS origins and published ports. A changed `FRONTEND_PORT` needs
  `CORS_ORIGINS` to follow it, or the SPA's requests are refused with an error
  that says nothing about ports. `OPENDRP_DNS_PRIMARY` and
  `OPENDRP_DNS_SECONDARY` control the resolver used by backend/worker probes;
  DNSTwist has its separate `DNS_NAMESERVERS` setting.
- Request handling and proxies: `AUTH_COOKIE_SECURE` (production requires
  `true`), `AUTHENTICATED_RATE_LIMIT_PER_MINUTE` (per-account request bound, `0`
  disables it), `TRUSTED_PROXY_IPS` with `UVICORN_FORWARDED_ALLOW_IPS` (client-IP
  resolution; `*` is rejected in production), `OPENDRP_NETWORK_SUBNET` (the
  Compose bridge subnet, kept in step with `TRUSTED_PROXY_IPS`), and
  `CONNECTOR_HEALTH_STALE_AFTER_SECONDS` (how long a connector may stay silent
  before `/connectors/health` reports it as unhealthy).
- Per-connector credentials (`CONNECTOR_TOKEN_DNSTWIST`, `CONNECTOR_TOKEN_SHODAN`, `CONNECTOR_TOKEN_HIBP`). Each connector gets its own token, issued by the core, stored only as a digest and revocable on its own; there is no platform-wide connector secret.
- `SHODAN_API_KEY` and `HIBP_API_KEY` are supplied only to their connector containers.
- `ALERT_HEALTH_CHECK_TIMEOUT_SECONDS` bounds alert-channel health checks. Finding alerts use the durable delivery queue: `ALERT_DELIVERY_TIMEOUT_SECONDS` bounds one SMTP/Telegram attempt, `ALERT_DELIVERY_MAX_ATTEMPTS` and `ALERT_DELIVERY_RETRY_BASE_SECONDS` control transient retries, and `ALERT_AGGREGATION_DELAY_SECONDS` groups findings until a connector job is terminal. `ALERT_MAX_FINDINGS_PER_MESSAGE` and `ALERT_MAX_TELEGRAM_MESSAGE_LENGTH` bound notification size.
- Shodan capability fallbacks: `SHODAN_SCAN_SSL_TEXT`, `SHODAN_SCAN_HTTP_TITLE`, and `SHODAN_SCAN_FAVICON`. These reach the connector and apply until an administrator changes the capability in its configuration form; the registry value then takes precedence for every later scan. Connector-scoped settings are namespaced after their connector, because `.env` is one namespace shared by every service (`scripts/check_env_template.py` enforces it).

The application rejects shipped or placeholder-like JWT, Fernet, database-password, and connector-token values in production. Never use development defaults in production.

### Settings UI

Administrators configure the following at `/settings`:

- **Connectors**: registered connector status and validated capability configuration.
- **Alerts**: email and Telegram toggles, selected active platform users for email alerts, an optional additional email address, explicit SMTP transport mode (`STARTTLS`, implicit TLS or trusted internal plain SMTP), and multiple Telegram chat IDs.
- **Schedules**: selected weekdays and UTC hour/minute for the phishing and breaches modules.

The **Send test email** action saves the current SMTP form values before testing them. This means a newly entered Mailtrap or SMTP configuration can be tested immediately; it does not test stale values from the previous saved configuration. SMTP password, sender address, and alert-recipient address are encrypted at rest and are never returned in plaintext.

SMTP password, SMTP sender address, alert-recipient address, and Telegram bot token are encrypted at rest using `ENCRYPTION_KEY`. Provider scan execution and provider health checks are performed by connector containers, and provider credentials are connector runtime secrets (`SHODAN_API_KEY`, `HIBP_API_KEY` — see `.env.example`). The core stores no provider credentials at all: `system_settings` holds only the settings the core itself uses.

For Mailtrap Sandbox, use the hostname and credentials shown by Mailtrap under its SMTP integration instructions. A typical setup uses `smtp.sandbox.mailtrap.io` with port `2525` (STARTTLS), the Mailtrap username/password, a valid sender address, and a test recipient. After entering these values, click **Send test email**; the UI persists the form and then performs the connection and authenticated delivery. Port `465` uses implicit TLS. Do not paste provider credentials into source files, issue trackers, or chat; rotate any credential that was exposed.

## Scan workflow

A manual scan or schedule creates jobs for enabled connectors:

1. The core snapshots active assets into job parameters.
2. An enabled connector claims its own job through the connector work-poll endpoint.
3. The connector scans its external source.
4. Findings are submitted in batches and validated by the core.
5. The core deduplicates findings, stores new records, sends enabled alerts, and writes audit events.
6. The connector reports completion and the job is finalized.

### Scan job types

Every connector **declares its own job type** at registration (see
`connectors/README.md`). The core does not carry a list of known connectors:
it accepts any namespaced type and hands each job to the one connector that
declared it, which is what keeps work isolated between connectors and modules.

| Job type | Module | Declared by | Scope |
|---|---|---|---|
| `phishing.dnstwist` | phishing | dnstwist | Active `domain` assets. |
| `phishing.shodan` | phishing | shodan | Active `domain`, `keyword_domain`, and `keyword_title` assets; active domains/IPs are exclusions. |
| `breaches.hibp` | breaches | hibp | Active `email_account` and `domain` assets, including the targeted single-email and single-domain lookups. |
| `report.generate` | reports | Celery/core | PDF report generation (core-owned). |
| `system` | system | — | Reserved system jobs. |

`GET /api/v1/connectors/modules` reports the modules and job types that are
actually registered, which is what the module pages use to filter job history.

The module-wide phishing `Rescan` queues both DNSTwist and Shodan when those connectors are enabled. The breaches `Rescan` queues the enabled HIBP connector.

Provider API keys are connector-owned runtime secrets. They are never accepted by the core settings API or stored in `system_settings`; configure them only for the matching connector container. After changing `SHODAN_API_KEY` or `HIBP_API_KEY` in `.env`, recreate the affected service; `restart` preserves the old environment:

```text
docker compose -f docker-compose.yml up -d --force-recreate connector-hibp connector-shodan
```

The UI has one address: the public URL it was built with, in `CORS_ORIGINS`. `CANONICAL_ORIGIN` is what makes the bundle send a browser that reached the SPA under some *other* origin to that one, and it is empty in a generated `.env` — an installation has a single browser origin, so there is nothing to redirect from. A Rescan is asynchronous: its job remains visible as `Pending`/`Running`, findings refresh after terminal completion, and lease recovery retries work after a connector restart. Provider errors and partial results are shown in Jobs history instead of being presented as an empty clean result.

Schedules are stored as JSON in `system_settings`:

```json
{"days": [1, 2, 3, 4, 5], "hour": 2, "minute": 30}
```

Days use cron-style numbering (`0=Sunday` through `6=Saturday`) and times are UTC. Defaults are weekdays at night: phishing at `02:30` and breaches at `03:30`. Celery Beat checks schedules every minute; Redis prevents duplicate firing within a minute.

## Findings and cleanup

### Asset deletion

Only administrators can delete assets. The API supports an explicit opt-in query parameter:

```text
DELETE /api/v1/assets/{asset_id}?cascade_findings=true
```

With `cascade_findings=false` (the default), only the asset is deleted. With `true`, matching phishing and breach findings are deleted in the same database transaction. The UI exposes this as the **Delete related findings** checkbox.

### Orphan cleanup

Administrators can independently remove findings whose monitored asset no longer exists:

```text
POST /api/v1/phishing/threats/cleanup-orphans
POST /api/v1/breaches/cleanup-orphans
```

Inactive assets still count as existing assets. Breach cleanup recognizes exact email assets, exact domain assets, and the domain portion of an email address. Each operation returns the number of deleted rows and creates an audit event.

## Web UI

Authenticated views are:

1. **Dashboard** — KPIs, timelines, source distribution, asset criticality, and administrator service health.
2. **Assets** — filters, create/edit, active/inactive toggle, canonical value normalization, and administrator deletion with optional finding cascade.
3. **Phishing** — filtered findings, status updates, source badges, `Rescan`, orphan cleanup, and module-specific jobs.
4. **Breaches** — HIBP findings, resolved matched asset and type, `Rescan`, orphan cleanup, and module-specific jobs.
5. **Modules** — one page per enabled module declared in the registry, showing the
   findings of that module with a per-row triage status. The built-in modules keep
   their dedicated pages, so this entry appears only after an operator declares a
   module.
6. **Reports** — asynchronous PDF generation, status, download, deletion for administrators, and report jobs.
7. **Users** — administrator-only account management, roles, activation, password reset, deletion, and last-active-admin protection.
8. **Audit** — administrator-only structured audit search.
9. **Settings** — administrator-only connector, alert, and schedule configuration.

All displayed timestamps use `YYYY-MM-DD HH:mm:ss` formatting in the UI.

## API overview

All application endpoints use Bearer authentication unless marked public. `viewer+` includes all three roles; `analyst+` includes `admin` and `analyst`; administrator endpoints require `admin`.

### Public and authentication

| Method | Route | Access |
|---|---|---|
| `GET` | `/api/v1/health` | Public — liveness, no dependencies |
| `GET` | `/api/v1/ready` | Public — readiness, checks PostgreSQL and Redis |
| `POST` | `/api/v1/auth/login` | Public |
| `GET` | `/api/v1/auth/me` | Authenticated |
| `POST` | `/api/v1/auth/password` | Authenticated — replace your own password (the only way an account holder sets one) |
| `POST` | `/api/v1/auth/refresh` | Refresh token |
| `POST` | `/api/v1/auth/logout` | Best-effort authenticated |
| `GET` | `/api/v1/auth/mfa` | Authenticated — MFA status |
| `POST` | `/api/v1/auth/mfa/setup` | Authenticated — generate TOTP secret |
| `POST` | `/api/v1/auth/mfa/enable` | Authenticated — verify and activate TOTP |
| `POST` | `/api/v1/auth/mfa/disable` | Authenticated — verify and deactivate TOTP |
| `POST` | `/api/v1/auth/mfa/recovery-codes/rotate` | Authenticated — replace recovery codes with password and TOTP |
| `GET` | `/api/v1/auth/sessions` | Authenticated — list own usable sessions (a signed-out one is an audit event, not a session) without token material |
| `DELETE` | `/api/v1/auth/sessions/{family_id}` | Authenticated — revoke one own session |
| `POST` | `/api/v1/auth/sessions/revoke-others` | Authenticated — revoke all other own sessions |
| `GET` | `/api/v1/auth/security-activity` | Authenticated — recent security events for own account |

### Core application routes

| Method | Route | Access |
|---|---|---|
| `GET` | `/api/v1/dashboard/stats` | viewer+ |
| `GET`, `POST` | `/api/v1/assets` | viewer+ / analyst+ |
| `GET`, `PATCH`, `DELETE` | `/api/v1/assets/{asset_id}` | viewer+ / analyst+ / admin |
| `GET` | `/api/v1/phishing/threats` | viewer+ |
| `GET` | `/api/v1/phishing/threats/{threat_id}` | viewer+ |
| `PATCH`, `DELETE` | `/api/v1/phishing/threats/{threat_id}` | analyst+ |
| `POST` | `/api/v1/phishing/threats/cleanup-orphans` | admin |
| `POST` | `/api/v1/phishing/scan/dnstwist`, `/api/v1/phishing/scan/shodan` | analyst+ |
| `GET` | `/api/v1/breaches` | viewer+ |
| `GET` | `/api/v1/breaches/{breach_id}` | viewer+ |
| `PATCH`, `DELETE` | `/api/v1/breaches/{breach_id}` | analyst+ |
| `POST` | `/api/v1/breaches/cleanup-orphans` | admin |
| `POST` | `/api/v1/breaches/scan` | analyst+ — queues the enabled breach connectors |
| `POST` | `/api/v1/breaches/scan-email`, `/api/v1/breaches/scan-domain` | analyst+ — manual single-target rescan |
| `GET` | `/api/v1/modules` | viewer+ — declared modules and their schemas |
| `POST`, `PATCH` | `/api/v1/modules`, `/api/v1/modules/{module_id}` | admin |
| `GET` | `/api/v1/findings` | viewer+ — findings of declared modules |
| `PATCH` | `/api/v1/findings/{finding_id}` | analyst+ — triage status |
| `POST` | `/api/v1/reports/generate` | viewer+ |
| `GET` | `/api/v1/reports` | viewer+ |
| `GET` | `/api/v1/reports/{report_id}/download` | viewer+ |
| `DELETE` | `/api/v1/reports/{report_id}` | admin |
| `GET` | `/api/v1/alerts/health` | viewer+ — email and Telegram channel probes |
| `GET` | `/api/v1/connectors/health`, `/api/v1/connectors/modules` | viewer+ |
| `GET` | `/api/v1/jobs` | viewer+ |
| `DELETE` | `/api/v1/jobs/{job_id}` | admin |

### Administration routes

| Method | Route | Access |
|---|---|---|
| `GET`, `PUT` | `/api/v1/settings` | admin |
| `POST` | `/api/v1/settings/test-email` | admin |
| `POST` | `/api/v1/settings/test-telegram` | admin |
| `GET`, `POST` | `/api/v1/users` | admin |
| `GET` | `/api/v1/users/brief` | admin |
| `GET`, `PUT`, `DELETE` | `/api/v1/users/{user_id}` | admin |
| `PATCH` | `/api/v1/users/{user_id}/toggle-active` | admin |
| `POST` | `/api/v1/users/{user_id}/mfa/reset` | admin — reset another user's TOTP factor |
| `GET` | `/api/v1/audit/actions` | admin |
| `GET` | `/api/v1/audit/integrity` | admin — hash-chain verification status |
| `GET` | `/api/v1/audit/logs` | admin |
| `GET` | `/api/v1/connectors` | admin |
| `GET` | `/api/v1/connectors/jobs` | admin |
| `PATCH` | `/api/v1/connectors/{connector_id}/status` | admin |
| `PATCH` | `/api/v1/connectors/{connector_id}/config` | admin |
| `POST` | `/api/v1/connectors/provision` | admin |
| `POST` | `/api/v1/connectors/{connector_id}/token` | admin |
| `DELETE` | `/api/v1/connectors/{connector_id}/token` | admin |

### Connector protocol routes

Connector routes authenticate with the connector's **own** `X-Connector-Token`
credential, never a user JWT and never a shared secret. The optional
`X-Connector-Name` header is only checked for agreement with that credential,
and it never grants access — identity is derived from the token itself:

| Method | Route | Purpose |
|---|---|---|
| `POST` | `/api/v1/connectors/register` | Register or refresh connector metadata. |
| `GET` | `/api/v1/connectors/me/work` | Atomically claim one pending job; returns `204` when empty. |
| `POST` | `/api/v1/connectors/me/findings/{job_id}` | Submit normalized finding batches. |
| `POST` | `/api/v1/connectors/me/complete/{job_id}` | Report success or failure. |
| `POST` | `/api/v1/connectors/me/heartbeat` | Update connector liveness. |

## Security and audit

- Passwords are bcrypt hashes (`bcrypt` directly; hashes written by the previous passlib-based code keep verifying).
- Access tokens are JWTs signed with PyJWT; the accepted algorithm is pinned to `HS256`/`HS384`/`HS512` in configuration, so `none` or a mismatched `alg` cannot be accepted.
- Refresh tokens use database-backed families with rotation and reuse detection.
- Failed logins are rate-limited through Redis and protected by database lockout fields. Every failure answer is identical — unknown address, wrong password, disabled account and locked account are indistinguishable, and the reason is recorded only in the audit trail.
- Client addresses are resolved by the backend from `X-Forwarded-For`, walking the chain from the right, so a client-supplied leading entry cannot forge an audit record. `TRUSTED_PROXY_IPS` must list every proxy in front of the API; Compose appends the network subnet automatically.
- Connector authentication uses one credential per connector: the core stores a SHA-256 digest of a machine-generated 256-bit token, compares it in constant time, and resolves it to exactly one connector. A token cannot be replayed as another connector, and rotation or revocation is per connector. Connector error text is exposed to admins only, because provider messages can echo API keys.
- Input is validated with FastAPI/Pydantic schemas, including asset, email, domain, schedule, Telegram, SMTP, and connector configuration fields.
- SQLAlchemy statements use bound parameters.
- Security headers and CORS are configured in FastAPI; Nginx adds headers for static and proxied responses.
- Audit records are stored in `drp_audit_logs` and emitted as one-line JSON with `timestamp`, `user_id`, `action`, `ip_address`, and `details`.
- `.env`, generated reports, databases, logs, dependency directories, caches, and local Compose overrides are excluded by `.gitignore` and `.dockerignore`.

## Dependencies and supply chain

Runtime dependencies live in `backend/requirements.txt` and are the only ones installed into the production image. Test, lint and type-check tooling lives in `backend/requirements-dev.txt`; the local Compose stack installs it via the `INSTALL_DEV_REQUIREMENTS` build argument so `make test-backend` keeps working, while a production build omits it.

CI runs a `security` job that fails on known vulnerabilities in the shipped dependency sets (`pip-audit` for the backend runtime requirements, `npm audit --omit=dev` for the frontend) and reviews newly introduced dependencies on pull requests. Dependabot keeps pip, npm, Docker and GitHub Actions pins current, grouping patch and minor updates per ecosystem and leaving major bumps for a deliberate migration — GitHub Actions majors are the exception, since an action bump is usually a one-line change and arrives in the group.

A `repo-hygiene` job runs the repository gates: `scripts/check_tracked_sources.py` fails when an ignore rule keeps source files out of the repository — an over-broad `lib/` pattern once hid `frontend/src/lib` from the published tree while every local command still passed — and `scripts/check_portable_commands.py` fails when a documented command needs a shell-specific line continuation, which is how the quick start's administrator step broke on its first Windows install.

Known deferred findings, tracked rather than ignored:

- `pytest` 8.3.2 is flagged by `pip-audit` (PYSEC-2026-1845). It is a dev-only test runner, not shipped; the fix requires moving to pytest 9 together with pytest-asyncio 1.x, which reshapes the async fixtures.
- `react-router` / `react-router-dom` 6.x carry moderate advisories that are only fixed in the 7.x major line. They are the only runtime advisories remaining and are below the gate's threshold.
- The Vite/esbuild/vitest toolchain advisories are devDependencies; every fix is a major bump. CI prints them on each run so the list stays visible.

## Development commands

```bash
make setup             # Write .env from .env.example, generating every secret
make check-env         # Fail if .env.example and the Compose files disagree
make check-commands    # Fail if a documented command is not one line for every shell
make up                # Build and start the installation (production shape)
make up-tools          # Optional: source-mounted stack with pytest/ruff/mypy
make down              # Stop services and keep volumes
make restart           # Stop and start all services
make build             # Build images only
make ps                # Show service status
make health            # Show services and API health
make logs              # Follow container logs
make migrate           # Apply Alembic migrations
make test-backend      # Run the backend test suite
make test-backend-fast # Run the backend suite without integration tests
make test-backend-integration  # Run real PostgreSQL/Redis boundary tests in Compose
make test-backend-critical-coverage  # Enforce per-module coverage thresholds
make lint-backend      # Run ruff over the backend app, scripts, and tests
make mypy-backend      # Run the mypy ratchet gate
make check-backend-migrations  # Verify the Alembic graph and that the schema it builds matches the ORM
make typecheck-backend # Compile backend app, scripts, and tests
make seed-demo         # Load demo data
make clean             # Remove local Python caches and pytest cache
make destroy           # Stop services and delete all Compose volumes
```

`make destroy` is destructive: it permanently removes PostgreSQL and Redis volumes.

Backend targets run pytest with `COVERAGE_CORE=sysmon`; running pytest by hand
without it mis-attributes coverage in async handlers and understates the result.

### Running without make

`make` is a convenience wrapper; nothing depends on it. The targets used most
often map to Compose commands directly.

In the table below, `docker compose` means
`docker compose -f docker-compose.yml` — the installation, and the only shape
there is. The test and lint targets are the exception: they exec into the tooling
container, so their equivalents start with
`docker compose -f docker-compose.yml -f docker-compose.dev.yml` and need
`make up-tools` (or that `-f` pair with `up -d`) first.

| Target | Equivalent command |
|---|---|
| `make setup` | `python setup.py` |
| `make check-env` | `python scripts/check_env_template.py` |
| `make check-commands` | `python scripts/check_portable_commands.py` |
| `make up` | `docker compose up -d --build` |
| `make down` | `docker compose down` |
| `make restart` | `docker compose down && docker compose up -d --build` |
| `make build` | `docker compose build` |
| `make ps` | `docker compose ps` |
| `make logs` | `docker compose logs -f --tail=200` |
| `make health` | `docker compose ps` then `curl -f http://localhost:8000/api/v1/health` |
| `make migrate` | `docker compose exec backend alembic upgrade head` |
| `make seed-demo` | `docker compose exec -T backend python -m scripts.seed_data all --yes` |
| `make shell-backend` | `docker compose exec backend /bin/bash` |
| `make connector-tokens` | `docker compose exec -T backend python -m scripts.manage_connector_tokens list` |
| `make up-tools` | `docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build` (tooling, not an installation) |
| `make lint-backend` | `docker compose -f docker-compose.yml -f docker-compose.dev.yml exec -T backend ruff check app scripts tests` |
| `make typecheck-backend` | `docker compose -f docker-compose.yml -f docker-compose.dev.yml exec -T backend python -m compileall -q app scripts tests` |
| `make mypy-backend` | `docker compose -f docker-compose.yml -f docker-compose.dev.yml exec -T backend python scripts/check_mypy_baseline.py` |
| `make check-backend-migrations` | `docker compose exec -T backend sh -c 'python scripts/check_migrations.py && python -m scripts.check_schema_drift'` |
| `make test-backend` | `docker compose -f docker-compose.yml -f docker-compose.dev.yml exec -T backend sh -c 'COVERAGE_CORE=sysmon python -m pytest -v tests/'` |
| `make test-backend-fast` | `docker compose -f docker-compose.yml -f docker-compose.dev.yml exec -T backend sh -c 'COVERAGE_CORE=sysmon python -m pytest -q -m "not integration" tests/'` |
| `make destroy` | `docker compose down -v` (deletes the data volumes) |
| `make backup` | `docker compose run --rm backup` |
| `make backup-verify` | `docker compose run --rm backup sh /backup-scripts/verify_restore.sh` |
| `make check-compose` | `python scripts/check_compose_healthchecks.py docker-compose.yml` |
| `make verify-replicas` | `docker compose -f docker-compose.yml -f docker-compose.replicas.yml up -d --build`, then that same file set with `--profile verify run --rm replica-check` |

The coverage and integration targets are the same commands with extra flags; read
them from the `Makefile` if you need the exact form.

### Windows notes

- **Shell.** Git Bash runs the commands in this README verbatim, including the
  single-quoted `sh -c '...'` forms. In PowerShell the differences are: `cp` is
  `Copy-Item`, a trailing `\` line continuation becomes a backtick `` ` ``, and
  environment variables are set with `$env:NAME="value"` instead of `NAME=value`.
- **Line endings.** `.gitattributes` pins the working tree to LF, because
  Dockerfiles, Compose files and Nginx configuration are consumed inside Linux
  containers and CRLF breaks their continuations. Clone after reading that file
  rather than forcing `core.autocrlf` yourself.
- **Path conversion.** Git Bash rewrites absolute-looking arguments it passes to
  containers (`/app` can arrive as `C:/Program Files/Git/app`). The commands here
  avoid it; prefix `MSYS_NO_PATHCONV=1` if you hit it with your own command.
- **Docker Desktop.** For the tooling stack (`make up-tools`), share the drive
  that holds the checkout; it bind-mounts `./backend`, `./connectors` and
  `./reports_store`. The installation uses images and named volumes. The WSL 2
  backend is the supported one.
- **Ports.** `BACKEND_PORT` and `FRONTEND_PORT` in `.env` accept `host:port`
  (defaults `127.0.0.1:8000` and `127.0.0.1:3000`, both loopback: a terminator on
  this host serves the users, and `docker/nginx/reverse-proxy.example.conf` is a
  working one). Change them if something else already occupies those ports, and
  widen the bind only deliberately.
- **`make clean`** is only a cache sweep: delete `__pycache__` directories and
  `*.pyc` files inside `backend/` and `connectors/`, or run
  `python -c "import pathlib, shutil; [shutil.rmtree(p, ignore_errors=True) for p in pathlib.Path('.').rglob('__pycache__')]"`.

## Documentation

- [docs/deployment.md](docs/deployment.md) — complete production deployment and verification runbook;
- [docs/configuration.md](docs/configuration.md) — configuration ownership, defaults and recreate requirements;
- [docs/description.md](docs/description.md) — architecture, modules, connector protocol, security model;
- [docs/production-readiness.md](docs/production-readiness.md) — measured current status, gated coverage thresholds, known limitations;
- [docs/upgrading.md](docs/upgrading.md) — upgrade and rollback procedure, destructive migrations, secret rotation, two-replica deployments;
- [docs/backup-restore.md](docs/backup-restore.md) — what is backed up, how to verify a restore, what is not in the dump;
- [docs/observability.md](docs/observability.md) — log shape, the SIEM path (Elastic/Vector/log driver), and the audit contract;
- [docs/operations.md](docs/operations.md) — backups, alert delivery, health checks, resource and disk monitoring;
- [docs/db.sql](docs/db.sql) — reference schema;
- [connectors/README.md](connectors/README.md) — writing a connector;
- [CONTRIBUTING.md](CONTRIBUTING.md) — development setup, what a change should contain, security rules;
- [CHANGELOG.md](CHANGELOG.md) — what changed in each release;
- [SECURITY.md](SECURITY.md) — vulnerability disclosure policy.

## Database

The reference schema is in [docs/db.sql](docs/db.sql). The application is migration-driven; deploy with:

```bash
alembic upgrade head
```

or use `make migrate`. Do not treat `docs/db.sql` as a replacement for Alembic migrations.

## Security

Report vulnerabilities privately through GitHub Security Advisories on
<https://github.com/OpenDRP/opendrp>; see [SECURITY.md](SECURITY.md) for the
scope, the expected response times and what to include. Do not open a public
issue for a suspected vulnerability.

## License

OpenDRP is licensed under the **GNU Affero General Public License v3.0** — see
[LICENSE](LICENSE). The AGPL's network clause applies: if you run a modified
version of this platform as a network service, you must offer its source to the
users of that service.
