# OpenDRP

OpenDRP is a self-hosted Digital Risk Protection platform for monitoring domains, IP addresses, email accounts, and brand keywords. It detects phishing and look-alike infrastructure, searches Have I Been Pwned (HIBP) breach data, monitors DNS/registration/certificate evidence through DNS Security, generates PDF reports, sends alerts, and records security-relevant activity in an audit trail.

The platform uses a **core + connector** architecture. The FastAPI core owns application state, authorization, validation, jobs, ingestion, deduplication, alerts, scheduling, audit logs, and the web API. External data sources run in independent connector containers and communicate with the core over HTTP.

## Contents

- [Architecture](#architecture)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Quick start](#quick-start)
- [Services and persistence](#services-and-persistence)
- [Configuration](#configuration)
- [Scan workflow](#scan-workflow)
- [Modules, findings and the asset model](#modules-findings-and-the-asset-model)
- [Identity, sessions and MFA](#identity-sessions-and-mfa)
- [Operations](#operations)
- [Alerts, settings and retention](#alerts-settings-and-retention)
- [Findings and cleanup](#findings-and-cleanup)
- [Web UI](#web-ui)
- [API overview](#api-overview)
- [Security and audit](#security-and-audit)
- [Dependencies and supply chain](#dependencies-and-supply-chain)
- [Development commands](#development-commands)
- [Documentation](#documentation)
- [Database](#database)
- [Security](#security)
- [License](#license)

## Architecture

```text
Browser
  |
  +-- frontend:80 (Nginx + React SPA, host port 3000 by default)
        |
        +-- /api/ --> backend:8000 (FastAPI core)
                         |
                         +-- PostgreSQL 17 (SQLAlchemy async + asyncpg pool)
                         +-- Redis 7 (Celery broker, rate-limit and admission counters)
                         +-- Celery worker (reports, enrichment, retention, schedules, integrity)
                         +-- Celery alerts worker (the delivery queue: alerts, expiry checks)
                         +-- Celery Beat (one-minute scan scheduler)

connector-phishing-dnstwist  --> core connector API (module: phishing)
connector-phishing-shodan    --> core connector API (module: phishing; profile shodan)
connector-breaches-hibp      --> core connector API (module: breaches; profile hibp)
connector-dns-rdap           --> core connector API (module: dns)
connector-dns-resolver       --> core connector API (module: dns)
connector-dns-ctlogs         --> core connector API (module: dns)
connector-dns-virustotal     --> core connector API (module: dns; profile virustotal)
connector-phishing-netlas    --> core connector API (module: phishing; profile netlas)
connector-dns-netlas         --> core connector API (module: dns; profile netlas)
connector-exposure-netlas    --> core connector API (module: exposure; profile netlas)
connector-exposure-netlas-endpoints    --> core connector API (module: exposure; profile netlas-endpoints)
connector-exposure-shodan-endpoints    --> core connector API (module: exposure; profile shodan-endpoints)
```

The connectors are stateless from the platform perspective:

1. Register with the core using its own `X-Connector-Token` credential.
2. Long-poll for a pending job.
3. Run the external scan inside the connector container.
4. Submit validated, normalized findings to the core.
5. Report job completion or failure.

The core performs all database writes and applies deduplication, enrichment, alert fan-out, and audit logging. Connectors do not receive database credentials. Each connector authenticates with its own `X-Connector-Token` credential, issued by the core, stored as a digest and revocable on its own — there is no platform-wide connector secret, and the optional `X-Connector-Name` header is checked for agreement only. A provider API key is either a connector runtime secret or, when an administrator stores one against a source account, Fernet ciphertext in the core's `source_accounts` row that only the bound connector can read through `GET /api/v1/connectors/me/credential`; the core's own settings table never holds one.

### First-party connectors

A bare `make up` starts four connector services: `connector-phishing-dnstwist`,
`connector-dns-rdap`, `connector-dns-resolver` and `connector-dns-ctlogs`. Every
other connector service is behind a Compose profile — `shodan`, `hibp`, `netlas`,
`netlas-endpoints`, `shodan-endpoints`, `virustotal`, and `backup` for the
one-shot backup runner — and `COMPOSE_PROFILES` in `.env` is what starts it with
the stack. Naming a gated service explicitly starts it for that command, but the
next `make up` leaves it down again unless its profile is listed.

| Connector | Module | Source and scope | Main configuration |
|---|---|---|---|
| `phishing-dnstwist` | `phishing` | DNSTwist mutations and DNS resolution for active domain assets | `CONNECTOR_NAME=phishing-dnstwist`, `CONNECTOR_TYPE=phishing` |
| `phishing-shodan` | `phishing` | Shodan SSL text, HTTP title, and favicon searches (profile `shodan`) | `SHODAN_API_KEY`, `SHODAN_SCAN_SSL_TEXT`, `SHODAN_SCAN_HTTP_TITLE`, `SHODAN_SCAN_FAVICON` |
| `breaches-hibp` | `breaches` | HIBP breached-account and breached-domain lookups (profile `hibp`) | `HIBP_API_KEY` |
| `dns-rdap` | `dns` | Registration/registrar/expiry via RDAP | `CONNECTOR_TOKEN_DNS_RDAP` |
| `dns-resolver` | `dns` | Current DNS RRsets for active domains | `CONNECTOR_TOKEN_DNS_RESOLVER`, `DNS_NAMESERVERS`, `DNS_SECURITY_RESOLVER_*` |
| `dns-ctlogs` | `dns` | Historical certificate/subdomain evidence | `CONNECTOR_TOKEN_DNS_CTLOGS`, optional `DNS_SECURITY_CTLOGS_API_TOKEN` |
| `dns-virustotal` | `dns` | Historical passive-DNS/subdomain intelligence (profile `virustotal`) | `CONNECTOR_TOKEN_DNS_VIRUSTOTAL`, `DNS_SECURITY_VT_API_KEY`, explicit noncommercial opt-in |

The three keyless DNS workers start with the installation, and `dns-virustotal` is
gated by the `virustotal` profile like every other keyed connector. See
[DNS Security connection guide](docs/dns-security.md#connect-the-workers)
for per-worker tokens, environment configuration, selective startup and quotas.
Settings also provides setup controls for provider-backed intelligence workers (core-token issuance, readiness, enabling and account quotas); it does not install provider API secrets or start containers. DNS Security workers use the separate manual token and Compose steps in the guide.

Provider-side limits are worth knowing before the first scan:

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

### Optional passive intelligence

Netlas is available as an opt-in connector/module combination behind the `netlas` Compose profile in the installation file itself — there is no second overlay to deploy — and migrations seed those rows disabled. The two endpoint-service workers for the exposure module are gated the same way, by `netlas-endpoints` and `shodan-endpoints`. Capabilities differ by module and are not all implemented. See [Passive source intelligence](docs/source-intelligence.md) for supported operations, account-level quotas, explicit approval and unverified provider-plan limits.

## Features

- Asset inventory with `domain`, `ip_address`, `email_account`, `keyword_domain`, and `keyword_title` types.
- Asset criticality and active/inactive state management, with canonical per-type uniqueness and bounded search/pagination.
- DNSTwist, Shodan, and HIBP connector scans.
- DNS Security: source-scoped DNS RRsets, RDAP registration expiry, historical CT/wildcard evidence and VirusTotal passive DNS; observed hosts/IPs can be promoted to assets after review.
- Manual `Rescan` actions and configurable UTC schedules for `phishing`, `breaches`, `dns`, and optional `exposure`; daily registration and exact-CT certificate expiry reminders at 30/14/7/3/1-day thresholds and once after expiry, subject to fresh successful checks.
- Matched-asset resolution for breach findings: an exact `email_account` asset wins when the breached address is monitored itself, otherwise the finding resolves through the address's domain, and raw provider values stay intact when nothing in the inventory matches.
- **Modules are data, not code.** `drp_modules` declares a module's findings kind, consumed inventory, field schema, deduplication keys and storage target, so an operator can register a new source with `POST /api/v1/modules` and its findings land in `drp_findings` without a core change. Declared findings are read through `GET /api/v1/findings` and triaged through `PATCH /api/v1/findings/{finding_id}`.
- Role-based access control: `admin`, `analyst`, and `viewer`.
- **Two-factor authentication (TOTP)** that any role can enable from **My security**: a six-digit code from an authenticator app on top of the password, single-use, counted towards the same lockout as a wrong password, with an audited administrator reset for a lost device.
- Optional cascade deletion of findings when an administrator deletes an asset.
- Separate administrator-only cleanup actions for orphan phishing/breach findings and DNS observations, preserving inactive assets and explicit DNS scan provenance.
- Email and Telegram alerts for newly discovered findings, persisted and retried independently per channel and recipient so one destination outage does not lose another destination's delivery.
- Recipient selection by user and multiple Telegram chat IDs.
- PDF report generation through Celery.
- Structured JSON audit events on stdout (exactly `timestamp`, `user_id`, `action`, `ip_address`, `details`) plus a persistent audit record, both carrying the request's `X-Request-ID` for correlation across HTTP, Celery and the SIEM.
- Security headers, input validation, parameterized SQLAlchemy queries, refresh-token rotation, login rate limiting, and bounded outbound alert checks.
- **A metrics scrape endpoint**: `GET /api/v1/metrics` publishes the platform's own health as numbers in the Prometheus text exposition format — alert-queue backlog and the age of its oldest row, recipients still held after an ambiguous delivery, connector silence, job states, and where the audit chain stands. It answers `404` — not `403` — until `METRICS_TOKEN` is set, and a refused scrape is logged rather than written into the audit chain, because a scrape every fifteen seconds would be 5 700 audit rows a day about a read of aggregate counts.
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
  [direct `docker compose` equivalent](CONTRIBUTING.md#running-the-same-things-without-make).

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
   ```Startup applies Alembic migrations under a PostgreSQL advisory lock (so two API replicas can start together), ensures the `system_settings` singleton, and starts the core, the workers and the four connectors that need no key — `connector-phishing-dnstwist`, `connector-dns-rdap`, `connector-dns-resolver` and `connector-dns-ctlogs`. Every keyed connector is behind a Compose profile (see [First-party connectors](#first-party-connectors)): step 3 starts two of them by name, and `COMPOSE_PROFILES` in `.env` is what makes a later `make up` bring them up again. It does not create an administrator account. A connector that starts without a credential exits with `Missing required environment variables: CONNECTOR_TOKEN` — expected, and fixed next.

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
   docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens issue phishing-dnstwist --type phishing --env CONNECTOR_TOKEN_DNSTWIST
   docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens issue phishing-shodan --type phishing --env CONNECTOR_TOKEN_SHODAN
   docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens issue breaches-hibp --type breaches --env CONNECTOR_TOKEN_HIBP
   docker compose -f docker-compose.yml up -d connector-phishing-dnstwist connector-phishing-shodan connector-breaches-hibp
   ```

   The name is the worker's `CONNECTOR_NAME` (`phishing-dnstwist`, `phishing-shodan`, `breaches-hibp`),
   `--type` is the module that worker feeds, and `--env` is the variable it is
   printed as. `up -d` is a *recreate*, and that is the part that applies the
   value: Compose reads `.env` when a container is created, so `docker compose
   restart connector-phishing-dnstwist` would keep the placeholder and exit with the same
   error.

   Rotating a token is the same shape with `rotate`. The previous value stops
   working immediately, and the connector keeps its registry row, configuration
   and job history:

   ```bash
   docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens rotate dnstwist --env CONNECTOR_TOKEN_DNSTWIST
   docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens rotate shodan --env CONNECTOR_TOKEN_SHODAN
   docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens rotate hibp --env CONNECTOR_TOKEN_HIBP
   docker compose -f docker-compose.yml up -d connector-phishing-dnstwist connector-phishing-shodan connector-breaches-hibp
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

This checkout declares version `0.2.0`, including DNS Security and passive source intelligence. For this local source installation, set `OPENDRP_VERSION=0.2.0` and build the images from the checkout; this version bump does not publish a GitHub release or registry images. For a published release, pin `OPENDRP_VERSION` to its released version. The setup checks and application reject the moving `latest` tag in production.

The public health endpoint is:

```text
http://localhost:8000/api/v1/health
```

Non-production API documentation is available at `/api/docs`, `/api/redoc`, and `/api/openapi.json`. API documentation is disabled when `APP_ENV=production`.

## Services and persistence

| Service | Profile | Purpose |
|---|---|---|
| `frontend` | — | React 18.3 SPA built with Vite and served by Nginx; proxies `/api/`. |
| `backend` | — | FastAPI platform core and REST API. |
| `postgres` | — | PostgreSQL 17 application database. |
| `redis` | — | Celery broker, plus the counters behind login throttling, provider admission and the short-lived scheduler guards. |
| `celery-worker` | — | Background report generation, WHOIS enrichment, retention, schedule dispatch and audit-chain verification tasks. |
| `celery-worker-alerts` | — | The durable alert-delivery queue and the daily expiry check, one delivery group at a time, with a 45-second stop grace so a send in flight finishes. |
| `celery-beat` | — | One-minute scheduler for database-configured scan schedules; it enqueues the 15-second delivery drain and the daily expiry check into the `alerts` queue. |
| `connector-phishing-dnstwist` | — | Phishing connector for DNSTwist. |
| `connector-phishing-shodan` | `shodan` | Phishing connector for Shodan. |
| `connector-breaches-hibp` | `hibp` | Breaches connector for HIBP. |
| `connector-dns-rdap`, `connector-dns-resolver`, `connector-dns-ctlogs` | — | Keyless DNS Security workers, one per source, sharing one image. |
| `connector-dns-virustotal` | `virustotal` | Keyed DNS Security worker for passive DNS and subdomains. |
| `connector-phishing-netlas`, `connector-dns-netlas`, `connector-exposure-netlas` | `netlas` | Optional Netlas workers, one per module. |
| `connector-exposure-netlas-endpoints`, `connector-exposure-shodan-endpoints` | `netlas-endpoints`, `shodan-endpoints` | Optional endpoint-service workers for the exposure module. |
| `backup` | `backup` | One-pass dump, restore and restore-verification runner; it is not part of the running stack. |

The Compose deployment persists PostgreSQL, Redis, the generated reports and the Celery Beat schedule in named volumes, `reports_store` among them. The tooling overlay (`make up-tools`) bind-mounts `./reports_store` instead, which is why a command that reads the report directory has to name the file set it runs in. All of it is runtime data and must not be committed.

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
  DNSTwist and the DNS Security resolver share the optional `DNS_NAMESERVERS` setting.
- Request handling and proxies: `AUTH_COOKIE_SECURE` (production requires
  `true`), `AUTHENTICATED_RATE_LIMIT_PER_MINUTE` (per-account request bound, `0`
  disables it), `TRUSTED_PROXY_IPS` with `UVICORN_FORWARDED_ALLOW_IPS` (client-IP
  resolution; `*` is rejected in production), `OPENDRP_NETWORK_SUBNET` (the
  Compose bridge subnet, kept in step with `TRUSTED_PROXY_IPS`), and
  `CONNECTOR_HEALTH_STALE_AFTER_SECONDS` (how long a connector may stay silent
  before `/connectors/health` reports it as unhealthy).
- Per-connector credentials (`CONNECTOR_TOKEN_DNSTWIST`, `CONNECTOR_TOKEN_SHODAN`, `CONNECTOR_TOKEN_HIBP`). Each connector gets its own token, issued by the core, stored only as a digest and revocable on its own; there is no platform-wide connector secret.
- `CONNECTOR_TOKEN_DNS_RDAP`, `CONNECTOR_TOKEN_DNS_RESOLVER`, `CONNECTOR_TOKEN_DNS_CTLOGS`, and `CONNECTOR_TOKEN_DNS_VIRUSTOTAL` are independent core-issued DNS worker credentials. They are distinct from provider API keys.
- `COMPOSE_PROFILES` is the switch for every service that does not start by default — the keyed connectors, the optional Netlas and endpoint workers, and the backup runner. It is the only place an installation decides which optional services a bare `make up` brings up, and a service started by name is not remembered by the next one.
- `SHODAN_API_KEY`, `HIBP_API_KEY`, `DNS_SECURITY_CTLOGS_API_TOKEN`, and `DNS_SECURITY_VT_API_KEY` are supplied only to their matching connector containers, and the Netlas and endpoint workers read `NETLAS_API_TOKEN` and `SHODAN_API_KEY` the same way, beside their own `CONNECTOR_TOKEN_NETLAS_*` and `CONNECTOR_TOKEN_EXPOSURE_*` credentials. A provider key can also live in the core instead of the environment: an administrator stores one per source account (`PUT /api/v1/connectors/accounts/{account_id}/api-key`), it is encrypted with `ENCRYPTION_KEY`, returned only as a masked hint, and handed to the connector bound to that account at `GET /api/v1/connectors/me/credential`. DNS resolver settings and the explicit VT noncommercial acknowledgement are documented in the [DNS environment table](docs/dns-security.md#2-configure-the-provider-environment).
- `ALERT_HEALTH_CHECK_TIMEOUT_SECONDS` bounds alert-channel health checks. Finding alerts use the durable delivery queue: `ALERT_DELIVERY_TIMEOUT_SECONDS` bounds one SMTP/Telegram attempt, `ALERT_DELIVERY_MAX_ATTEMPTS` and `ALERT_DELIVERY_RETRY_BASE_SECONDS` control transient retries, `ALERT_AGGREGATION_DELAY_SECONDS` groups findings until a connector job is terminal, and `ALERT_RECIPIENT_HOLD_SECONDS` is how long a send whose acceptance is unknown keeps its recipient out of the queue. `ALERT_MAX_FINDINGS_PER_MESSAGE` and `ALERT_MAX_TELEGRAM_MESSAGE_LENGTH` bound notification size.
- Shodan capability fallbacks: `SHODAN_SCAN_SSL_TEXT`, `SHODAN_SCAN_HTTP_TITLE`, and `SHODAN_SCAN_FAVICON`. These reach the connector and apply until an administrator changes the capability in its configuration form; the registry value then takes precedence for every later scan. Connector-scoped settings are namespaced after their connector, because `.env` is one namespace shared by every service (`scripts/check_env_template.py` enforces it).

- `METRICS_TOKEN` is what creates the scrape endpoint — with it unset, `GET /api/v1/metrics` answers `404` — and a scraper presents it as `X-Metrics-Token: …` or `Authorization: Bearer …`. `MIGRATION_LOCK_TIMEOUT_MS` bounds how long the startup migration waits behind another session's open transaction; `MIGRATION_STATEMENT_TIMEOUT_MS` stays `0` on purpose, because the baseline's index builds are legitimately the longest statement the platform runs. Thresholds and a scrape configuration are in [docs/observability.md](docs/observability.md).

The application rejects shipped or placeholder-like JWT, Fernet, database-password, and connector-token values in production. Never use development defaults in production.

### Settings UI

Administrators configure the following at `/settings`:

- **Connectors**: registered connector status and validated capability configuration.
- **Alerts**: email and Telegram toggles, selected active platform users for email alerts, an optional additional email address, explicit SMTP transport mode (`STARTTLS`, implicit TLS or trusted internal plain SMTP), and multiple Telegram chat IDs.
- **Schedules**: selected weekdays and UTC hour/minute for phishing, breaches and DNS Security; Exposure has a separate opt-in schedule (disabled by default).

The **Send test email** action saves the current SMTP form values before testing them. This means a newly entered Mailtrap or SMTP configuration can be tested immediately; it does not test stale values from the previous saved configuration. SMTP password, sender address, and alert-recipient address are encrypted at rest and are never returned in plaintext.

SMTP password, SMTP sender address, alert-recipient address, and Telegram bot token are encrypted at rest using `ENCRYPTION_KEY`. Provider scan execution and provider health checks are performed by connector containers, and provider credentials are connector runtime secrets (`SHODAN_API_KEY`, `HIBP_API_KEY`, `DNS_SECURITY_CTLOGS_API_TOKEN`, `DNS_SECURITY_VT_API_KEY` — see `.env.example`) or a key an administrator stored against a source account. `system_settings` holds only the settings the core itself uses and never holds a provider key; the `source_accounts` rows are where a key the core accepted for a connector is kept, as Fernet ciphertext whose plaintext is only ever handed to the connector that account is bound to.

For Mailtrap Sandbox, use the hostname and credentials shown by Mailtrap under its SMTP integration instructions. A typical setup uses `smtp.sandbox.mailtrap.io` with port `2525` (STARTTLS), the Mailtrap username/password, a valid sender address, and a test recipient. After entering these values, click **Send test email**; the UI persists the form and then performs the connection and authenticated delivery. Port `465` uses implicit TLS. Do not paste provider credentials into source files, issue trackers, or chat; rotate any credential that was exposed.

## Scan workflow

A manual scan or schedule creates jobs for enabled connectors:

1. The core snapshots active assets into job parameters.
2. An enabled connector claims its own job through the connector work-poll endpoint.
3. The connector scans its external source.
4. Findings are submitted in batches and validated by the core.
5. The core deduplicates findings (or refreshes source-scoped DNS observations), stores records, queues applicable alerts, and writes audit events.
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
| `dns.rdap` | dns | dns-rdap | Active domains: registration and expiry. |
| `dns.resolver` | dns | dns-resolver | Active domains: current DNS RRsets. |
| `dns.ctlogs` | dns | dns-ctlogs | Active domains: historical CT evidence. |
| `dns.virustotal` | dns | dns-virustotal | Active domains: historical passive-DNS/subdomain intelligence. |
| `phishing.netlas` | phishing | phishing-netlas | Profile `netlas`; the provider's brand capabilities are not all implemented. |
| `dns.netlas` | dns | dns-netlas | Profile `netlas`. |
| `exposure.netlas` | exposure | exposure-netlas | Profile `netlas`: host and service observations for monitored domains and addresses. |
| `exposure.netlas-endpoints` | exposure | exposure-netlas-endpoints | Profile `netlas-endpoints`. |
| `exposure.shodan-endpoints` | exposure | exposure-shodan-endpoints | Profile `shodan-endpoints`. |
| `report.generate` | reports | Celery/core | PDF report generation (core-owned). |
| `system` | system | — | Reserved system jobs. |

`GET /api/v1/connectors/modules` reports the modules and job types that are
actually registered, which is what the module pages use to filter job history.

The module-wide phishing `Rescan` queues both DNSTwist and Shodan when those connectors are enabled. The breaches `Rescan` queues the enabled HIBP connector. DNS Security's manual `Rescan` queues only enabled sources with a recent heartbeat and reports offline sources separately; it refuses to enqueue when none are online. Schedules queue enabled sources, so disable unused DNS connectors in Settings even if their containers are stopped.

Provider API keys are connector-owned runtime secrets. They are never accepted by the core settings API or stored in `system_settings`; configure them only for the matching connector container. After changing `SHODAN_API_KEY` or `HIBP_API_KEY` in `.env`, recreate the affected service; `restart` preserves the old environment:

```text
docker compose -f docker-compose.yml up -d --force-recreate connector-breaches-hibp connector-phishing-shodan
```

The UI has one address: the public URL it was built with, in `CORS_ORIGINS`. `CANONICAL_ORIGIN` is what makes the bundle send a browser that reached the SPA under some *other* origin to that one, and it is empty in a generated `.env` — an installation has a single browser origin, so there is nothing to redirect from. A Rescan is asynchronous: its job remains visible as `Pending`/`Running`, findings refresh after terminal completion, and lease recovery retries work after a connector restart. Provider errors and partial results are shown in Jobs history instead of being presented as an empty clean result.

Schedules are stored as JSON in `system_settings`:

```json
{"days": [1, 2, 3, 4, 5], "hour": 2, "minute": 30}
```

Days use cron-style numbering (`0=Sunday` through `6=Saturday`) and times are UTC. Defaults are weekdays at night: phishing at `02:30`, breaches at `03:30`, and DNS Security at `04:00` UTC. Exposure has no schedule until an administrator enables one (the UI suggests `05:00`). Celery Beat checks schedules every minute; Redis prevents duplicate firing within a minute.

## Modules, findings and the asset model

### Modules are rows, not code

`drp_modules` is the module registry, and it is data: an operator declares a
module over `POST /api/v1/modules` (admin), the declared set is read at
`GET /api/v1/modules` (viewer+), and its findings land in `drp_findings` without a
core change. A declaration names the module id (the `connector_type` its connectors
register under), its `finding_kind`, the inventory sections it consumes
(`asset_types`), its `fields`, the `dedup_fields` that identify one of its findings,
its `title_field` and its `storage`. The shipped registry holds four modules —
`phishing`, `breaches`, `dns` and `exposure` — each with its own typed table and
write adapter; a declared module stores validated findings as JSON in
`drp_findings`, deduplicated on the key its own fields produce and read back
through `GET /api/v1/findings` and `PATCH /api/v1/findings/{finding_id}`.

The core owns storage, deduplication, audit and alerting for every module, which is
what keeps a connector from writing to the database directly; a module owns only
the shape of its own findings. A declaration that would store every submission
anew is refused — at least one dedup field is required — as is an id or finding kind
another module already uses, and the declared fields are immutable once findings
exist against them, because stored rows would otherwise silently change shape. The
label and description stay editable, and a module can be disabled without deleting
it.

A connector declares itself at registration: the module it feeds, the single job
type it claims, the finding kind its submissions validate as, the asset types it
receives, and the operator-editable settings it exposes. The core validates that
manifest — module coherent with the finding kind, job type namespaced and unclaimed,
asset types known, config keys safe — and stores it, so submission validation, the
configuration form and the scan payload all follow what the connector declared
rather than a list the core carries. `connectors/README.md` is the contract for
writing one.

### The asset model

An asset is a UUID, a type (`domain`, `ip_address`, `email_account`,
`keyword_domain` or `keyword_title`), a value of at most 512 characters, a
criticality (`low`, `medium`, `high`, `critical`), an active flag and timestamps.
Values are canonicalized before they are stored and matched — domains to lowercase
IDNA form, email domains case-insensitively, IP addresses to canonical text — and
the database enforces uniqueness per type and canonical value, so a case variant
cannot become a second monitoring target. The inventory is global and single-tenant
by design: roles decide what an account may do, not what it may see.

Matching a finding to an asset is one rule (`app/services/asset_matching.py`), used
by the list, the asset page, the export and the cascade delete, so those counters
cannot disagree: an exact `email_account` asset wins when the monitored address is
the one named, otherwise the finding resolves through the address's domain, and the
provider's raw values stay intact when nothing in the inventory matches. Deactivating
an asset stops monitoring without deleting evidence; deleting one is the only
operation that removes findings, and only when an administrator asks for the cascade
(`DELETE /api/v1/assets/{asset_id}?cascade_findings=true`), which removes the
matching phishing, breach and generic-module findings in batches of 1000 in the same
transaction. Deleting a monitored domain also removes the breach findings about
mailboxes at that domain, while deleting a mailbox never touches its domain. Source
observations — what a provider saw, not what is monitored — are never removed by it;
they have their own administrator-only orphan cleanup.

## Identity, sessions and MFA

- **Roles.** `admin` (user administration, settings, connector administration, audit
  access, report and asset deletion, and everything below it), `analyst` (assets,
  findings, scans, reports) and `viewer` (read-only, with report generation as the
  one deliberate exception). Authorization reads the account's current role and
  active flag from the database on every request rather than trusting a claim in the
  token, and the last active administrator cannot be demoted, deactivated or
  deleted.
- **Passwords** are bcrypt hashes. A new one needs 12 characters, an uppercase
  letter and a digit, and no more than 72 UTF-8 bytes; a password assigned *for*
  someone — account creation, an administrator reset, `manage_admin create|reset` —
  is temporary, and the account is refused everywhere except the onboarding screens
  until its holder replaces it.
- **Failed sign-ins** are throttled in Redis and tracked in the database, and every
  refusal is identical from outside: an unknown address, a wrong password, a
  disabled account and a locked one cannot be told apart, with the reason kept in
  the audit trail.
- **A TOTP second factor** is available to every role, requested only after the
  password verifies, single-use (the matched counter is stored, closing the replay
  window the clock-skew tolerance would otherwise open) and counted against its own
  lockout budget. Enrolment is self-service from **My security** and shows ten
  recovery codes once; removal needs the password and a live code, an administrator
  can clear another account's factor, and a locked-out administrator is released
  from the host with `python -m scripts.manage_admin mfa-off`.
  `REQUIRE_MFA_FOR_ADMINS=true` makes an enrolled factor a step of the same
  onboarding flow — the account is asked for one at sign-in and can reach nothing
  else until it is enrolled — and turning the setting off is the release valve for an
  administrator who cannot enrol.
- **Sessions are cookies, not browser storage.** The access token lives in memory,
  the session of record is the `HttpOnly` refresh cookie, every page load asks
  `POST /api/v1/auth/refresh` once, and signing out ends the session on both sides.
  Refresh families rotate on use with reuse detection, and a password change, an
  administrator reset, an MFA recovery, deactivation or account removal revokes
  them. **My security** lists only the sessions that can still be used, and the
  activity list says what ended the others.
- **An operation and its audit row commit together.** If the record cannot be
  written the operation is rolled back and the API answers `503` with
  `code: audit_unavailable` and `Retry-After: 5` — the platform does not accept an
  unrecorded change to an account or a session.

## Operations

### Daily checks

```text
docker compose -f docker-compose.yml ps
docker compose -f docker-compose.yml logs --tail=200 backend celery-worker celery-worker-alerts celery-beat
```

Confirm that the backend, the workers, beat and the enabled connectors are healthy,
and read jobs and alert deliveries that failed or keep retrying in the UI. `make ps`
and `make health` are the same two checks with less typing.

### What to watch on the host

Free disk space — the Docker data root and the backup directory first — memory
pressure and OOM kills, CPU saturation during scans and PDF rendering, PostgreSQL
connection count and slow statements, Redis memory and task backlog, and repeated
container restarts. The Compose limits are conservative starting values: a limit
that is reached calls for a measured adjustment or a smaller workload, never for
removing the bound. [docs/configuration.md](docs/configuration.md) carries the
per-service table those limits are checked against.

### A service will not become healthy

`docker compose up -d` reports the healthcheck verdict, not the reason: a service
waiting on the backend prints `dependency failed to start: container
opendrp-backend is unhealthy`, which names the blocked service. The reason is one
command away, and `make up` prints exactly this when a start fails.

```text
docker compose -f docker-compose.yml logs --tail=100 backend
docker compose -f docker-compose.yml ps
docker inspect opendrp-backend --format "{{json .State.Health}}"
```

The API container's entrypoint applies migrations, ensures the `system_settings`
singleton and then starts Uvicorn under `set -e`, so the last `[OpenDRP] …` line in
its log names the step that failed and the traceback under it is the reason. Two
causes account for most of these and look identical from Compose: the container
exited (a startup step raised, which `restart: unless-stopped` turns into a loop,
so `ps` says `Restarting` rather than `Exited`), or the process is up while
`/api/v1/ready` is not 200, which means PostgreSQL or Redis is unreachable from
that container.

```text
docker compose exec backend curl -sS http://localhost:8000/api/v1/ready
```

That names the failing check; `/api/v1/health` stays dependency-free on purpose, so
it still answers when readiness cannot.

An unprovisioned connector is a different and expected state: it exits with
`Missing required environment variables: CONNECTOR_TOKEN` and gives up after ten
attempts rather than looping forever. Issue its credential with
`make connector-token NAME=<connector> TYPE=<module>`. A connector that runs but is
never admitted is polling while the core refuses its token; the core names every
refusal, so the connector to re-key is in the backend's log:

```bash
docker compose logs --tail=50 backend | grep connector_credential_rejected
```

The name in that line is read from the token and is a diagnostic hint, never an
identity: only the stored digest authorizes anything.

### Alert delivery will not go out

Finding alerts are persisted before delivery, and **the queue is drained by a
scheduled task, not by the API**: `celery-beat` enqueues
`deliver-pending-alerts-every-15-seconds` into the `alerts` queue, and
`celery-worker-alerts` is the container that executes it. A scheduler that is not
running looks exactly like a quiet installation — rows accumulate as `pending` and
nothing is delivered — and so does a delivery worker that is down while beat keeps
filling its queue. Check both:

```text
docker compose -f docker-compose.yml ps celery-beat celery-worker-alerts
docker compose -f docker-compose.yml logs --tail=50 celery-beat celery-worker-alerts
```

A scheduler that cannot start prints the `Settings` validation error that stopped
it, and no regular expression is needed to read it. Once it is healthy the backlog
is delivered as bounded aggregated messages, one per job, finding type and channel.
When a provider is unavailable: confirm the connector job and its correlation ID,
check SMTP or Telegram health in **Settings**, check the workers' health and logs,
confirm the queue moves again once the provider recovers, and do not press `Rescan`
to compensate — scans and delivery are separate durable workflows.

### Backups and audit integrity

```text
make backup
make backup-verify
```

Copy verified archives off the Docker host, protect them as sensitive data and
encrypt them at rest, and drill a restore at least quarterly or after a migration.
[docs/backup-restore.md](docs/backup-restore.md) is the full procedure, including
what a dump does not contain. Verify the tamper-evident audit chain periodically,
and ship stdout to the SIEM: database retention is not SIEM retention.

```text
make verify-audit-chain
```

### Before changing `.env`

```text
python setup.py --check
docker compose -f docker-compose.yml config --quiet
```

Then recreate the affected service — a plain `restart` keeps the environment the
container was created with. The **Applied runtime configuration** card in Settings
(`GET /api/v1/settings/runtime`) shows what the running backend actually received,
with no secret in it.

## Alerts, settings and retention

### Settings

Settings is one database row with an optimistic `version`: the UI sends only the
fields it changed plus the version it read, and `409` means reload and reconcile
rather than overwrite. Every settings or connector mutation commits together with
its audit row. Schedules are stored per module — the dedicated columns for
`phishing`, `breaches` and `dns`, and the generic `schedules` map a declared module
gets — each shaped like `{"days": [1, 2, 3, 4, 5], "hour": 2, "minute": 30}`, with
`0=Sunday` and UTC times. The scheduler examines the current minute and the nine
before it, and `schedule_occurrences` records which connector-and-minute pairs have
already run, independently of job deletion, so a job pruned by retention cannot
re-arm its own schedule. The Redis guard behind it has two-second connect and read
deadlines and a 900-second TTL; downtime longer than that window is not backfilled.

### Alert delivery

- A finding is durable before it is announced: ingestion writes a persistent
delivery event instead of waiting for SMTP or Telegram, and every channel and
recipient has its own state, so a successful email never marks a failed chat as
sent. `channel` names a concrete destination; with no channel configured nothing is
queued and `alert_delivery_no_channel` is logged, because a finding is already
stored and a row no destination can satisfy would only fail forever.
- A batch is aggregated per job, finding type and channel, and bounded by
  `ALERT_MAX_FINDINGS_PER_MESSAGE` and `ALERT_MAX_TELEGRAM_MESSAGE_LENGTH`.
  `ALERT_AGGREGATION_DELAY_SECONDS` holds findings until the connector job reaches
  a terminal state, so one scan produces one message rather than one per finding.
- Transient failures — network, timeout, HTTP 408, 429 and 5xx — are retried up to
  `ALERT_DELIVERY_MAX_ATTEMPTS` with `ALERT_DELIVERY_RETRY_BASE_SECONDS` between
  attempts, and a provider's `Retry-After` is honoured. Configuration and
  authentication failures are permanent and need an operator.
- A delivery is `pending`, `delivering`, `sent`, `failed` or `ambiguous`. An attempt
  whose acceptance is unknown becomes `ambiguous` rather than being replayed at once,
  because a timed-out send may still have arrived: the recipient is held for
  `ALERT_RECIPIENT_HOLD_SECONDS`, and an administrator can end that hold early with
  `GET /api/v1/alerts/recipients` and `POST /api/v1/alerts/recipients/{key}/release`
  once the message has been reconciled with the recipient. The hold also ends by
  itself — the deliveries go back in the queue — because by the end of the window the
  uncertain send has finished either way, and a hold that never expired would silence
  the recipient for good. There is deliberately no bulk-delete for that state.
- A message carries what the module declared: a header, the breakdown that module
  considers worth counting, and one numbered line per finding, with the email
  rendering the same material as a table plus a text alternative. Both channels link
  back to the finding only when the installation knows its own address (the first
  non-loopback `CORS_ORIGINS` entry), because a link to `localhost` points at the
  reader's own machine. A batch larger than one message is cut between findings and
  says how many it left out. Sensitive field names and credential-bearing URLs are
  redacted before rendering. SMTP uses at most four executor slots, a probe that
  cannot get one reports `degraded`, and TLS is required wherever credentials are
  presented.

### Retention

Nightly, at 04:15 UTC, one sweep removes what the retention settings allow and
records what it removed:

- audit rows older than `AUDIT_RETENTION_DAYS` (365 by default), and only as a
  contiguous prefix that has already been archived, verified and receipted — a
  retirement cannot delete an unverified chunk, and `AUDIT_RETENTION_HOLD` blocks it
  outright;
- generated reports older than `REPORT_RETENTION_DAYS` (365), the row first and then
  the artefact through the configured resolver;
- revoked refresh sessions once their tokens can no longer be presented, which is
  what keeps a replayed token answered with `family_revoked` until then;
- terminal alert deliveries and processed ingestion events older than
  `ALERT_HISTORY_RETENTION_DAYS` (90 days, `0` disables it; the setting is not in
  `.env.example`, so it is passed to the worker). Pending, delivering and ambiguous
  rows are never purged, and recipient and occurrence identities stay, so pacing and
  deduplication survive the sweep.

`RETENTION_BATCH_SIZE` and `RETENTION_MAX_BATCHES_PER_RUN` bound one sweep, and the
run reports a `truncated` marker rather than presenting an incomplete pass as a
complete one.

### The audit chain

Audit rows are hash-chained and keyed: each row carries `entry_hash`, `prev_hash`
and `key_id`, with `AUDIT_CHAIN_KEYS` as the signing key and
`AUDIT_CHAIN_PREVIOUS_KEYS` keeping an older key verifiable through a rotation. The
chain detects a deleted suffix or a deleted set of rows and refuses further appends,
the scheduled verification defaults to a full pass over the retained chain and
resumes after a restart, and it never repairs history — a broken chain stays broken
until an operator accounts for it. `GET /api/v1/audit/integrity` reports the state,
and `python -m scripts.audit_archive` exports a verified prefix with its manifest
before retirement deletes it. A complete database rewrite, or the removal of the
archive itself, is only detectable against a copy held elsewhere: local signatures
are not write-once storage, so an installation keeps the committed tip off the host
that holds the database. [docs/observability.md](docs/observability.md) is the log
shape and the SIEM path.

## Findings and cleanup

### Asset deletion

Only administrators can delete assets. The API supports an explicit opt-in query parameter:

```text
DELETE /api/v1/assets/{asset_id}?cascade_findings=true
```

With `cascade_findings=false` (the default), only the asset is deleted. With `true`, matching phishing and breach findings are deleted in the same database transaction. The UI exposes this as the **Delete related findings** checkbox, and requires the operator to type the asset's value before confirming: a cascade is the one irreversible part of that dialog. Deleting many assets at once (`POST /api/v1/assets/bulk`) is available to analysts for `activate`, `deactivate` and `criticality`, and to administrators for `delete`.

### Is an asset monitored, or only recorded?

The list answers that per row: every item of `GET /api/v1/assets` carries `findings` — the per-module counts and their total, computed from the same asset-matching rule as the cascade and the asset page — and `has_findings=true|false` limits the inventory to the assets something was reported about (the export takes the same filter). `GET /api/v1/assets/{asset_id}/findings` adds `last_seen` per module: when each module last saw a finding about that asset, so a stale involvement is as visible as a fresh one. Coverage comes from the connector registry (`GET /api/v1/connectors/modules`): a type no enabled module consumes is marked **not scanned**, and the asset page names the modules and connectors that do monitor it.

### Inventory in bulk

An inventory arrives in batches, so it can be created in one:

```text
POST /api/v1/assets/import          {"items": [...], "dry_run": false}
POST /api/v1/assets/import/csv      asset_type,asset_value,criticality  (text/csv body)
GET  /api/v1/assets/export?format=csv|json
```

Every line of a file gets its own entry in the report — `created`, `duplicate` or `invalid`, with the reason — so a failure names the row it belongs to instead of aborting the file. An import is idempotent: an existing value is reported as a duplicate and left untouched. `dry_run` answers the same question without writing anything. Limits are explicit refusals rather than silent truncation: 1000 rows and 1 MiB per import, 500 ids per bulk action, 10 000 rows per export (narrow the filter and export in parts). The whole import or bulk call is one transaction with one summary audit row; per-row failures roll back only themselves.

### Orphan cleanup

Administrators can independently remove findings whose monitored asset no longer exists:

```text
POST /api/v1/phishing/threats/cleanup-orphans
POST /api/v1/breaches/cleanup-orphans
POST /api/v1/dns/observations/cleanup-orphans
```

Inactive assets still count as existing assets. Breach cleanup recognizes exact email assets, exact domain assets, and the domain portion of an email address. DNS cleanup preserves exact subject/IP and originating-domain links; it does not infer ownership from suffixes or arbitrary DNS values. DNS observations are not removed by the asset finding-cascade checkbox: use their separate confirmed cleanup. Each operation returns the number of deleted rows and creates an audit event.

## Web UI

Authenticated views are:

1. **Dashboard** — KPIs, timelines, source distribution, asset criticality, and administrator service health.
2. **Assets** — filters, create/edit, active/inactive toggle, canonical value normalization, and administrator deletion with optional finding cascade.
3. **DNS Security** — `/dns-security`: source-filtered observations, wildcard-aware evidence, asset promotion, `Rescan`, admin orphan cleanup and per-source jobs.
4. **Exposure** — `/exposure`: provider-observed hosts and services with a triage status, asset promotion, and the module's own `Rescan`.
5. **Phishing** — filtered findings, status updates, source badges, `Rescan`, orphan cleanup, and module-specific jobs.
6. **Breaches** — HIBP findings, resolved matched asset and type, `Rescan`, orphan cleanup, and module-specific jobs.
7. **Modules** — one page per enabled module declared in the registry (`/modules/<module id>`), showing the
   findings of that module with a per-row triage status. The built-in modules keep
   their dedicated pages, so this navigation entry appears only after an operator
   declares a module.
8. **Reports** — asynchronous PDF generation, status, download, deletion for administrators, and report jobs.
9. **Users** — administrator-only account management, roles, activation, password reset, deletion, and last-active-admin protection.
10. **Audit Log** — administrator-only structured audit search, with the integrity state of the hash chain and its archive.
11. **Settings** — administrator-only connector, alert, and schedule configuration.

Every signed-in account also has **My security** — `/security`: its own password
change, second-factor enrolment with one-time recovery codes, session listing and
revocation, and its recent security activity, described in words rather than as
action codes.

Every instant the UI shows is the stored UTC instant, rendered without the reader's locale (`frontend/src/lib/datetime.ts`), and a page that displays one carries the time-zone hint; `frontend/src/lib/timezoneContract.test.ts` holds that rule for the whole UI. Schedule inputs are UTC.

## API overview

The operator-facing route inventory — every method, path and required role — is in
**[docs/api.md](docs/api.md)**. That page is the hand-maintained reference;
`GET /api/v1/openapi.json` (with its UI at `/api/docs`, served outside production)
is the generated one, and where the two disagree the schema is right.

Two things are worth knowing before you open it:

- the connector-protocol routes under `/api/v1/connectors/` authenticate with the
  connector's **own** `X-Connector-Token` credential, never a user JWT, and are
  written for connector authors in
  [connectors/README.md](connectors/README.md#the-connector-facing-api);
- requests refused by the edge rate limits are answered `429` by nginx before the
  application sees them — see
  [docs/configuration.md](docs/configuration.md#edge-rate-limits).

## Security and audit

- Passwords are bcrypt hashes, produced and verified by `bcrypt` directly, in one format (`$2b$`).
- Access tokens are JWTs signed with PyJWT; the accepted algorithm is pinned to `HS256`/`HS384`/`HS512` in configuration, so `none` or a mismatched `alg` cannot be accepted.
- Refresh tokens use database-backed families with rotation and reuse detection.
- Failed logins are rate-limited through Redis and protected by database lockout fields. Every failure answer is identical — unknown address, wrong password, disabled account and locked account are indistinguishable, and the reason is recorded only in the audit trail.
- Client addresses are resolved by the backend from `X-Forwarded-For`, walking the chain from the right, so a client-supplied leading entry cannot forge an audit record. `TRUSTED_PROXY_IPS` must list every proxy in front of the API; Compose appends the network subnet automatically.
- Connector authentication uses one credential per connector: the core stores a SHA-256 digest of a machine-generated 256-bit token, compares it in constant time, and resolves it to exactly one connector. A token cannot be replayed as another connector, and rotation or revocation is per connector. Connector error text is exposed to admins only, because provider messages can echo API keys.
- Input is validated with FastAPI/Pydantic schemas, including asset, email, domain, schedule, Telegram, SMTP, and connector configuration fields.
- SQLAlchemy statements use bound parameters.
- Security headers and CORS are configured in FastAPI; Nginx adds headers for static and proxied responses.
- Audit records are stored in `drp_audit_logs` and emitted as one-line JSON with `timestamp`, `user_id`, `action`, `ip_address`, and `details`.
- `.env`, generated reports, databases, logs, dependency directories, caches, and local Compose overrides are excluded by `.gitignore` and `.dockerignore`. Real credentials exist only in `.env`, which is never committed.
- Audit rows are hash-chained and signed (`AUDIT_CHAIN_KEYS`, with `AUDIT_CHAIN_PREVIOUS_KEYS` keeping an older key verifiable through a rotation), the nightly and on-demand verification detects a deleted suffix or a deleted set of rows and refuses further appends, and retirement removes only a verified, archived prefix. The chain is a tamper-evidence device, not write-once storage: an operator who needs to detect a rewrite of the whole database keeps the committed tip elsewhere. [docs/security.md](docs/security.md) lists what the operator still has to verify.
- A state-changing account or session operation commits with its audit row or does not happen at all, answering `503` with `code: audit_unavailable` when the audit insert fails. Sign-out and connector heartbeats are deliberately best-effort, so "every mutation is recorded" is a claim about the audited set, not about every request.
- Provider-facing error text is sanitized before it is stored: tokens, passwords, URLs and response control characters are not copied into a job's `last_error`, so a connector's error is readable without being a credential disclosure. Connector error detail is shown to administrators only.

## Dependencies and supply chain

Runtime dependencies live in `backend/requirements.txt` and are the only ones installed into the production image. Test, lint and type-check tooling lives in `backend/requirements-dev.txt`; the local Compose stack installs it via the `INSTALL_DEV_REQUIREMENTS` build argument so `make test-backend` keeps working, while a production build omits it.

CI runs a `security` job that fails on known vulnerabilities in the shipped dependency sets (`pip-audit` for the backend runtime requirements, `npm audit --omit=dev` for the frontend) and reviews newly introduced dependencies on pull requests. Dependabot keeps pip, npm, Docker and GitHub Actions pins current, grouping patch and minor updates per ecosystem and leaving major bumps for a deliberate migration — GitHub Actions majors are the exception, since an action bump is usually a one-line change and arrives in the group.

What exactly is pinned — the hash-locked Python manifests, the `npm ci` lockfile,
and the base image tags that are deliberately left floating — is written down once,
in [SECURITY.md](SECURITY.md#base-images-and-dependency-pins), with the commands
to refresh or pin the two images Compose names directly.

The `e2e` job goes further than the others: it writes an installation's configuration
with the setup wizard, builds and raises the stack, and then drives it end to end —
sign-in, a queued scan, a finding submitted by the script acting as its own
connector, then what an operator would see: the finding in the module's listing,
the alert queue grown by it and an audit entry for every step. A second half drives
the same installation through a real browser — the sign-in form, the `HttpOnly`
session cookie, the newest finding as a rendered row, and a sign-out that revokes
the token server-side (`scripts/e2e_smoke.py`, `scripts/e2e_browser.py`; thresholds
and the local procedure are in
[docs/production-readiness.md](docs/production-readiness.md#reproducing-the-measurements)).
It is the only job that builds images, so it is the slowest.

A `repo-hygiene` job runs the repository gates where the checkout is complete: `scripts/check_tracked_sources.py` fails when an ignore rule keeps source files out of the repository — an over-broad `lib/` pattern once hid `frontend/src/lib` from the published tree while every local command still passed; `scripts/check_portable_commands.py` fails when a documented command needs a shell-specific line continuation, which is how the quick start's administrator step broke on its first Windows install; `scripts/check_compose_healthchecks.py` compares the per-service limits documented in `docs/configuration.md` with the Compose file, row by row; `scripts/check_env_template.py` fails when a documented setting never reaches a container or a variable Compose reads is undocumented; `scripts/check_frontend_spa.py` fails when an SPA route can collide with a static directory; `scripts/check_dependency_sources.py` fails when a dependency declaration drifts from `requirements*.txt`; `scripts/check_version_consistency.py` fails when the platform's version statements disagree with each other; `scripts/check_docs_consistency.py` fails on a relative link that no longer resolves or a page nothing reaches; and `scripts/check_withdrawn_providers.py` fails when a provider this project removed reappears in the source or the documentation.

The rest of the workflow covers the same ground from other angles: the `frontend` job runs the SPA suite with its coverage floors and a production build; `production-integration` runs the PostgreSQL-only suites and the migration round trip against a real database; `compose` validates the two-replica file set without starting it; `release-image-coverage` resolves every Compose profile and fails if an image the stack can ask for is not one the release publishes; `secrets` scans the whole history with gitleaks (`.gitleaks.toml` allowlists test fixtures by path and nothing else); and `codeql` starts analysing the day the repository is public, because it needs GitHub Advanced Security while it is private.

Known deferred findings, tracked rather than ignored:

- The Vite/esbuild/vitest toolchain advisories are devDependencies; every fix is a major bump. CI prints them on each run so the list stays visible.
- Nothing else is deferred at the time of writing: the test runner is on pytest 9 with the pytest-asyncio 1.x line it requires, and the SPA is on react-router 7, so the two advisories this list used to carry are fixed rather than tolerated. Read the `pip-audit` and `npm audit` output of the security job before treating this list as complete — it records what CI reports, not what the pins suggest.

## Development commands

```bash
make setup        # Write .env from .env.example, generating every secret
make up           # Build and start the installation
make up-tools     # Source-mounted stack with pytest/ruff/mypy, for development
make down         # Stop services, keep the volumes
make logs         # Follow container logs
make health       # Service status and the API health endpoint
make migrate      # Apply pending Alembic migrations
make test-backend # Run the backend test suite (needs `make up-tools` first)
make check-env    # Fail if .env.example and the Compose files disagree
```

`make` with no argument prints every target. The complete list, with what each one
does and the equivalent Compose command for the ones you may want to run without
`make`, is in [CONTRIBUTING.md](CONTRIBUTING.md#make-targets).

Two of them deserve their own warning. `make destroy` permanently deletes the
PostgreSQL and Redis volumes — it is the only target that does. And the backend
test targets run pytest with `COVERAGE_CORE=sysmon`; running pytest by hand
without it mis-attributes coverage in async handlers and understates the result.

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
- **`make clean`** is a cache sweep, not a data operation: it removes
  `__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `htmlcov`,
  `*.pyc`, `*.pyo`, `.coverage`, `coverage-critical.json`, `*.tsbuildinfo` and
  stale `celerybeat-schedule*` files across the checkout, and never touches the
  database, the report store or `backups/`. Without `make`, the equivalent for
  the Python caches is
  `python -c "import pathlib, shutil; [shutil.rmtree(p, ignore_errors=True) for p in pathlib.Path('.').rglob('__pycache__')]"`.

## Documentation

Read this page first: it is the platform's description, and architecture, modules,
configuration, operations and the security model live here rather than in a page
per subject. The pages below are the specialist references and runbooks it points
to.

- [docs/deployment.md](docs/deployment.md) — complete production deployment and verification runbook;
- [docs/configuration.md](docs/configuration.md) — configuration ownership, defaults and recreate requirements;
- [docs/description.md](docs/description.md) — the implementer's reference: module internals, the matching rule and its measurements, the connector protocol, and the authentication and session design;
- [docs/production-readiness.md](docs/production-readiness.md) — measured current status, gated coverage thresholds, known limitations;
- [docs/upgrading.md](docs/upgrading.md) — upgrade and rollback procedure, destructive migrations, secret rotation, two-replica deployments;
- [docs/backup-restore.md](docs/backup-restore.md) — what is backed up, how to verify a restore, what is not in the dump;
- [docs/api.md](docs/api.md) — the route inventory: method, path and required role;
- [docs/security.md](docs/security.md) — the security model: what is enforced, what the operator must verify, and the accepted risks;
- [docs/observability.md](docs/observability.md) — log shape, the SIEM path (Elastic/Vector/log driver), and the audit contract;
- [docs/dns-security.md](docs/dns-security.md) — the optional DNS Security workers and their provider configuration;
- [docs/source-intelligence.md](docs/source-intelligence.md) — the passive-intelligence workers: setup, accounts, quotas and limits;
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

or use `make migrate`. A database an earlier build of this repository created already holds this schema: `python -m scripts.migrate` — which the API container's entrypoint runs — records the baseline revision instead of creating anything, while `alembic stamp` cannot, because stamp resolves the recorded revision before it writes. Take a verified backup first and treat that upgrade as a maintenance window; the procedure is in [docs/upgrading.md](docs/upgrading.md). Do not treat `docs/db.sql` as a replacement for Alembic migrations.

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
