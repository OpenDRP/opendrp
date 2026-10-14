# Production deployment runbook

This is the supported production procedure for a small or medium self-hosted OpenDRP installation. One file set is the installation — `docker-compose.yml`, started by `make up` — and every numbered step below addresses it, because that is what users reach. Connectors are part of that same file: keyless ones start with the installation, and keyed ones sit behind Compose profiles. See [Optional overlays and profiles](#optional-overlays-and-profiles). Two others are not installations at all: `docker-compose.dev.yml` is a test harness that mounts the source tree and installs pytest, ruff and mypy, and `docker-compose.replicas.yml` exists to be `run` once, by `make verify-replicas`, to prove the API is stateless. No step here reaches either of those.

## Requirements

- Docker Engine or Docker Desktop with Compose v2.24 or newer.
- A host sized for the set of services you actually intend to run. The figure depends on whether you enable the DNS Security profile or the passive-intelligence profile, so it is a table rather than a number: see [Host requirements](#host-requirements). The Compose file's per-service CPU, memory and PID values are *caps*, not reservations, and they are not a sizing guarantee.
- A DNS name and TLS termination in front of the frontend — the stack does not terminate TLS itself. Do not expose the application over plain HTTP: the refresh cookie is `Secure`, so no browser would send it and a session could not survive a reload. [TLS in front of the installation](#tls-in-front-of-the-installation) has the procedure and a working nginx configuration.
- Outbound access required by the enabled connectors, DNS/WHOIS, SMTP and Telegram. The backend and worker use `OPENDRP_DNS_PRIMARY` / `OPENDRP_DNS_SECONDARY`; DNSTwist and the DNS Security resolver share the optional `DNS_NAMESERVERS` setting.
- Off-host encrypted backup storage.

Check the Compose version before starting:

```text
docker compose version
```

## Optional overlays and profiles

The installation is one file; everything else is additive and explicit. Nothing
below starts unless a profile or a second `-f` names it, which is why an
unmodified checkout is the smallest supported deployment rather than a subset of
some larger template.

| File set | What it adds | How it is started |
|---|---|---|
| `docker-compose.yml` | the installation: PostgreSQL 17, Redis 7, the API, the Celery worker and beat, the frontend, and the four connectors that need no provider key — `connector-phishing-dnstwist`, `connector-dns-rdap`, `connector-dns-resolver`, `connector-dns-ctlogs` — which start with `make up` once their own connector token is issued | `make up`, or `docker compose -f docker-compose.yml up -d --build` |
| `COMPOSE_PROFILES` in `.env` (for example `netlas,shodan,hibp,virustotal`) | every keyed connector, each behind its own profile: `shodan` starts `connector-phishing-shodan`, `hibp` starts `connector-breaches-hibp`, `netlas` starts `connector-phishing-netlas`, `connector-dns-netlas` and `connector-exposure-netlas`, `netlas-endpoints` starts `connector-exposure-netlas-endpoints`, `shodan-endpoints` starts `connector-exposure-shodan-endpoints`, and `virustotal` starts `connector-dns-virustotal`. A service in a profile starts only when its profile is listed, and a missing provider key leaves that worker idle rather than failing the file | set the provider key first, then `make up` |
| `--profile backup` | one `backup` service that runs `pg_dump` plus the report-store archive, once per `make backup` or every `BACKUP_INTERVAL_SEC` in loop mode | `docker compose -f docker-compose.yml --profile backup up -d backup` |
| `docker-compose.replicas.yml` | releases the API's fixed `container_name` and published port and asks for `replicas: 2`, plus a one-shot `replica-check` service in the `verify` profile. It layers on the base file and is not deployable alone | `ADMIN_EMAIL=<addr> ADMIN_PASSWORD=<pass> make verify-replicas`, which layers both files — the `!reset` tags need Compose v2.24 or newer |
| `docker-compose.dev.yml` | source mounts and pytest/ruff/mypy inside the API container | `make up-tools` — tooling, never an installation |

[Services and persistence](../README.md#services-and-persistence) in the README
carries the same set as one flat list with each service's profile and published
port, which is the table to read when you want to know whether a container should
exist at all.

Four things about enabling one are worth knowing before you do:

* **A profile-wide `up` starts every service in that profile.** `COMPOSE_PROFILES=netlas` starts all three Netlas workers, so enable a profile only when you have set its provider key. A worker started without its key registers, reports `credentials_configured: false`, and is never admitted a scan.
* **Every profile moves the host requirement.** The Netlas profile adds three services at 512 MiB and 0.75 CPU each. [Host requirements](#host-requirements) has the sums.
* **Profiles share the one `.env`.** Provider credentials are namespaced per provider (`NETLAS_API_TOKEN`), and each worker needs its own core-issued connector token under its own `CONNECTOR_TOKEN_*` name, issued the same way as the base connectors in step 6.
* **The `backup` profile is a profile because backups belong on the operator's
  clock**, not silently attached to every `up`. `make backup` runs the same image
  once; the profile runs it as a loop with its own healthcheck. Both are described
  in [backup-restore.md](backup-restore.md).

### Prove the API is stateless under two replicas

"Stateless, so it scales horizontally" is a claim this repository demonstrates
rather than asserts, and the demonstration needs two API containers running
together. `docker-compose.replicas.yml` layers on the installation file — never
on the tooling overlay — and it is not deployable by itself:

```text
docker compose -f docker-compose.yml -f docker-compose.replicas.yml up -d
```

The overlay releases the API's fixed `container_name` and its published port,
both of which assume a single container, and asks for `replicas: 2`. Its
`replica-check` service lives in the `verify` profile, so `up -d` does not run it
by accident: it exists to be `run` once, and its exit code is the result. Both
replicas apply Alembic migrations at startup under a PostgreSQL advisory lock,
which is what makes two containers starting at the same instant safe.

The whole scenario is one make target, and it needs an existing administrator's
credentials because its last check reads the audit trail:

```text
ADMIN_EMAIL=<addr> ADMIN_PASSWORD=<pass> make verify-replicas
```

That target starts the two-replica stack, waits for both API containers to report
healthy, and runs `scripts/verify_replicas.py` inside a `python:3.12-slim`
container on the Compose network, passing the credentials in as `ADMIN_EMAIL` and
`ADMIN_PASSWORD` (the script reads those, `REPLICA_HOST` and `REPLICA_PORT` from
its environment). It checks, in order: that both replicas answer `/health` with
the same version; that an access token issued by one replica is accepted by the
other; that a refresh cookie issued by one replica can be rotated by the other;
that the second replica still refuses that refresh without the `X-CSRF-Token`
header; and that the audit row for the sign-in is readable from both, located by
the `X-Request-ID` the client sent. Each check prints `PASS` or `FAIL`, and any
failure exits non-zero.

It leaves the two replicas running on purpose, because seeing them side by side
is the point. Tear them down when you are done:

```text
docker compose -f docker-compose.yml -f docker-compose.replicas.yml down
```

## Host requirements

Each service carries a memory, CPU and PID cap. Those caps are per service, so
the numbers below are what the host must cover if everything runs at once — the
memory column is the sum of the `mem_limit` values and the CPU column the sum of
the `cpus` values in the Compose files. They are ceilings, not reservations: an
idle installation uses far less. The host also has to hold the operating system,
the Docker daemon, its image and log storage, and the page cache PostgreSQL would
like to keep — which is why the recommendation is above the sum rather than
equal to it.

| Service set | Memory (sum of caps) | CPU (sum of caps) | Recommended host |
|---|---:|---:|---|
| Installation, no profiles (`docker-compose.yml`) | 7.0 GiB | 7.75 | at least 8 GiB RAM, 8 CPU cores |
| + `backup` profile | 7.5 GiB | 8.25 | as above; the backup service is short-lived |
| + every keyed profile (`netlas`, `shodan`, `hibp`, `virustotal`) | 10.0 GiB | 12.25 | at least 12 GiB RAM, 14 CPU cores |

The two endpoint workers are outside those rows: `netlas-endpoints` and
`shodan-endpoints` add 512 MiB and 0.75 CPU each, so add 1.0 GiB and 1.5 CPU to
the row you would otherwise use. Enable a profile only after its provider key is
set; [configuration.md](configuration.md) says which variable each one reads.

Disk: at least 40 GiB free on the volume that holds the checkout and the Docker
data-root, plus room for `./backups`.

The rest of the host checklist is not optional either, and none of it is visible
in a container's status:

* **A firewall, and nothing but the terminator exposed.** Every published port in
  `docker-compose.yml` binds loopback by default (`FRONTEND_PORT=127.0.0.1:3000`
  and so on). Keep it that way unless a proxy on another host uses those bindings,
  and then expose only the port that proxy needs. PostgreSQL, Redis and the
  backend port are operator conveniences, not application endpoints.
* **NTP.** Audit timestamps, JWT `iat`/`exp` validation, TLS certificate validity
  and the backup retention window all depend on the clock being right. A drifting
  clock produces audit rows that cannot be ordered and tokens that expire early.
* **`nofile` and PID headroom.** The frontend's nginx is configured with
  `worker_rlimit_nofile 65535` and `worker_connections 4096`, and each service has
  a `pids_limit`; the host's own file-descriptor and process limits have to be at
  least as large, or the first limit is a promise the kernel does not keep.
* **Swap is disabled or negligible.** `mem_limit` is the containment: under memory
  pressure the correct outcome for a runaway scan is a killed container, not a
  host that swaps PostgreSQL onto disk and stops answering.
* **Where the Docker data-root lives.** Images, container logs and the PostgreSQL
  volume are all written there. Put it on a filesystem with room and monitoring;
  a full data-root is an audit trail that stops being written.
* **Where `./backups` lives.** It is a host directory, not a volume, precisely so
  that copying it off the host needs no Docker knowledge. Give it room for
  `BACKUP_KEEP` dump-plus-archive pairs and treat off-host replication as part of
  the installation, not an afterthought.
* **PostgreSQL connections.** Each API process owns a pool
  (`DB_POOL_SIZE` + `DB_MAX_OVERFLOW`), and so do the worker and beat processes;
  the server's `max_connections` has to exceed the sum with room for migrations,
  backups and an administrative session. The arithmetic and the current values are
  in [configuration.md](configuration.md#database-pool-budget).

The wizard reports the host-side part of this itself:

```text
python setup.py --check
```

It warns when the host has fewer than four CPU cores, less than the memory the
configured service set needs, or too little free disk on the checkout volume, and
it prints which figures belong to which service set.

## 1. Prepare the checkout and version

This checkout declares version `0.2.0`. Local installations must set `OPENDRP_VERSION=0.2.0` and build from source; this local version bump does not publish a GitHub tag, release or GHCR images. Do not pull `0.2.0` from the registry until it has actually been published. For an available production release, check out its tag and pin the same version in `.env`:

```text
git clone https://github.com/OpenDRP/opendrp.git
cd opendrp
git checkout <released-tag>
```

```dotenv
APP_ENV=production
OPENDRP_VERSION=<released-version>
```

`OPENDRP_VERSION` is required in production and must be a semantic version. The application refuses an empty value or `latest`. For a published release, `make pull-prod` pulls the matching GHCR images; source builds are available through `make up`.

One installation runs one release: this value is the image tag every service is built or pulled as, and the version the UI reports. The wizard offers the version this checkout declares (`backend/app/__init__.py`, the same string `/api/v1/health` answers) because `make up` builds the images from that tree; naming a different one is how `make pull-prod` runs a published tag instead. Keep the two equal: Settings reports `OPENDRP_VERSION` while the health endpoint reports the running code's version, so a file that disagrees has one installation displaying two versions. `python setup.py --check` reports that difference as a note.

## 2. Generate and validate configuration

Run the wizard interactively:

```text
python setup.py --public-url https://drp.example.com --version 0.2.0
```

On Windows, use `py -3 setup.py` if `python` is not the Python 3 launcher. The wizard uses only the Python standard library. It generates database, JWT, encryption and audit-chain secrets with the operating system CSPRNG, and it writes one shape of file: the production one. No flag selects another, because an installation that differs from the one users reach is not one worth checking.

`--public-url` is the origin users reach, and it is required: it becomes `CORS_ORIGINS` and the `issuer` shown in the authenticator entries. `https://` is what an installation needs; `http://localhost:<port>` is accepted so the same file can be used to check the installation on the machine that runs it (browsers treat `localhost` as a trustworthy origin, so the `Secure` cookie still works). Any other plain-HTTP origin is refused, with the reason. The prompt prints an example (`e.g. https://drp.example.com`) rather than offering a default: a guessed origin is worse than no answer, because the UI would be served from the real host and every request refused.

### The origin and the bindings

Two settings read alike and describe opposite ends of the same connection, which
is why the wizard asks for them in this order:

| Setting | What it is | What it is not |
|---|---|---|
| `CORS_ORIGINS` (the public URL) | the origin a browser uses — the TLS terminator, e.g. `https://drp.example.com` | not the port the UI is published on |
| `FRONTEND_PORT` | where the UI is published **on this host** (loopback by default: `127.0.0.1:3000`), for the terminator to forward to | not an origin a user can open by itself, unless a proxy there forwards to it |
| `BACKEND_PORT` | the API's binding on this host, which the terminator proxies `/api/` to | not an address the SPA calls: it uses its own origin, `/api/v1` |
| `POSTGRES_PORT`, `REDIS_PORT` | bindings for an operator with a client on this host | not reachable by the connector containers at all |

`docker/nginx/reverse-proxy.example.conf` is the join between the first two: it
listens on 443 and `proxy_pass`es to the `FRONTEND_PORT` binding. Change one and
you have to change the other.

That is also why `python setup.py --check` warns when a plain-HTTP loopback
origin names a port nothing in the file is published on. The common case is
`http://localhost` (port 80 is implicit) while the UI is on `127.0.0.1:3000`: the
SPA keeps working, because its requests go to its own origin through the
frontend's `/api/` proxy, where no CORS check happens — the file is simply
recording an origin nobody can open, and it would be wrong the moment anything is
cross-origin. The finding states both ways out: put the terminator on that port,
or write the origin that matches the binding.

A binding may be written as `port` or `host:port`. The wizard rewrites a bare
port to loopback (`3000` becomes `127.0.0.1:3000`) and prints the rewrite, because
Compose reads a bare port as `0.0.0.0:3000` — the checkbox for publishing an
unencrypted copy of the platform next to the encrypted one. Only an explicit host
says that on purpose.

For a non-interactive installation, the same values come from flags:

```text
python setup.py --non-interactive --public-url https://drp.example.com --version 0.2.0 --connectors dnstwist,hibp --mfa
```

`--version` may be omitted: the version this checkout declares is used, and a
value already in the file wins over it. `--public-url` may not — nothing may guess
an origin.

Review the resulting file without changing it:

```text
python setup.py --check
```

The check must report no errors. Never commit `.env`, backups or generated reports.

## 3. Validate Compose before starting

```text
docker compose --env-file .env -f docker-compose.yml config --quiet
```

Check the configured resource and security shape:

```text
python scripts/check_compose_healthchecks.py docker-compose.yml
```

The production file provides limits for memory, CPU and process count. These are guardrails, not a sizing guarantee. Monitor the host and raise limits deliberately if legitimate scans or reports are being constrained.

## 4. Create an off-host backup destination

Create or configure encrypted off-host storage for the `backups/` directory before the first production start. A local Docker volume is not a disaster recovery plan.

After the first successful startup, run and verify a backup:

```text
make backup
make backup-verify
```

Copy verified backups to storage outside the Docker host and periodically perform a restore drill.

## 5. Start the production stack

Build the images from this source checkout, then create the services:

```text
docker compose -f docker-compose.yml up -d --build
```

`make up` runs the equivalent build-and-start flow. The initial public source snapshot does not include published GHCR release images, so do not run `docker compose pull` as the first install step. The API applies Alembic migrations under a PostgreSQL advisory lock before serving requests. Do not use the tooling overlay for an installation, and do not use `docker compose restart` to apply changed environment variables: recreate the affected service with `up -d`.

Check service state and readiness:

```text
docker compose -f docker-compose.yml ps
docker compose -f docker-compose.yml exec -T backend sh -c "python scripts/check_migrations.py && python -m scripts.check_schema_drift"
```

The public frontend should be the only public application endpoint. Keep PostgreSQL, Redis and the direct backend port bound to loopback unless a deliberate network design requires otherwise.

Generated report PDFs live in the shared `reports_store` volume mounted only by
trusted backend/worker services. The production image creates
`/workspace/reports_store` with mode `0700`, owned by the unprivileged `opendrp`
user; keep the Docker host and volume administration within the trusted operator
boundary, and do not grant unrelated containers or host users write access to
that directory. Artifact path checks prevent traversal and symlink escapes, but
path validation followed by file open/unlink is not atomic against a hostile
writer that can modify the volume concurrently. This deployment does not claim
protection from a compromised service account, Docker host root, or another
principal granted write access to the volume. Development bind mounts may have
host-specific permission behavior and do not inherit the production image's
filesystem ownership guarantee.

## 6. Provision connectors

For every enabled connector, issue a core credential. The plaintext is printed once and never stored, so each command's output goes into `.env` under the variable it names:

```text
docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens issue phishing-dnstwist --type phishing --env CONNECTOR_TOKEN_DNSTWIST
docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens issue phishing-shodan --type phishing --env CONNECTOR_TOKEN_SHODAN
docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens issue breaches-hibp --type breaches --env CONNECTOR_TOKEN_HIBP
```

Paste each one-time token into the matching `.env` variable. Set provider API keys only for their connector service. Then recreate the affected services:

```text
docker compose -f docker-compose.yml up -d connector-phishing-dnstwist connector-phishing-shodan connector-breaches-hibp
```

A restart does not update a container's environment. Confirm connector registration and heartbeat in **Settings → Connectors**.

To replace a credential later, use `rotate` with the same name: the previous value stops working immediately and the connector keeps its registry row, configuration and job history. Recreate the service afterwards, because the new value is read when the container is created:

```text
docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens rotate phishing-dnstwist --env CONNECTOR_TOKEN_DNSTWIST
docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens rotate phishing-shodan --env CONNECTOR_TOKEN_SHODAN
docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens rotate breaches-hibp --env CONNECTOR_TOKEN_HIBP
docker compose -f docker-compose.yml up -d connector-phishing-dnstwist connector-phishing-shodan connector-breaches-hibp
```

`revoke <name>` cuts a connector off without deleting anything, and `list` reports which connectors hold a credential.

Provider keys are subject to provider plans. Shodan's SSL-text and favicon searches need a key of at least the **Membership** tier; on a lower tier the refusal is reported as a partial scan rather than as an empty result. HIBP publishes an integration key for a test installation (`00000000000000000000000000000000`) that returns the documented fixture breaches for `account-exists@hibp-integration-tests.com` and `hibp-integration-tests.com` — see [connectors/README.md](../connectors/README.md).

### Optional DNS Security profile

DNS Security adds four workers without changing the base installation. The setup
wizard currently offers only the three base connectors; add the missing DNS
entries from `.env.example` to your existing `.env` without overwriting secrets.
Use `--type dns` for core token issuance, which is the module's current id (`dns_security` is still accepted as a transitional alias); the keyless DNS workers start with `make up` and VirusTotal is started with `COMPOSE_PROFILES=virustotal`
for Compose startup. Provider keys are different credentials from worker tokens.

Follow the [DNS Security provisioning guide](dns-security.md#connect-the-workers)
for the token mapping and exact issuance commands. After provisioning RDAP,
resolver and CT (including an optional CT provider Bearer token), start:

```text
docker compose -f docker-compose.yml up -d --build --wait connector-dns-rdap connector-dns-resolver connector-dns-ctlogs
```

VirusTotal is separate: provision its worker token, set its provider key, verify
personal/non-commercial eligibility and explicitly set
`DNS_SECURITY_VT_PUBLIC_NONCOMMERCIAL=true` before starting its service.
Do not enable that public-tier integration for business deployments. A bare
profile-wide `up` starts all four workers; use explicit service names when only
some sources are configured. Startup may execute already-pending scans, so review
Jobs history and active assets before enabling external egress.

Check container health and a recent registry heartbeat, then rescan an active
domain from `/dns-security`. A healthy worker is not evidence that a provider
returned data: inspect the job's status and provider errors. After editing DNS
keys, recreate the matching service with the profile enabled; `restart` keeps
its old environment. Disable unused registry rows in Settings as well as stopping
their containers.

## 7. Create the first administrator

Use a temporary password that is not reused anywhere else:

```text
docker compose -f docker-compose.yml exec backend python -m scripts.manage_admin create --email admin@example.com --password "ChangeMeAdminPass123!"
```

The first sign-in requires the administrator to replace the temporary password. If `REQUIRE_MFA_FOR_ADMINS=true`, enrollment of a TOTP factor is also required before administrator routes become available.

## 8. Configure and verify the platform

1. Open `https://drp.example.com`.
2. Complete password and MFA onboarding.
3. Configure SMTP or Telegram under **Settings** and use the test action.
4. Enable only the connectors and alert channels actually used.
5. Add assets.
6. Run one manual phishing scan and one breach scan.
7. Verify that findings, job status, audit records and alert delivery are visible.
8. Generate and download a PDF report containing non-ASCII test data if applicable.
9. Open **Settings** and confirm **Applied runtime configuration** shows the pinned version and expected timeout/pool values.
10. Check `/api/v1/ready` through the reverse proxy.
11. Verify that backups and the alert delivery worker are healthy.

## TLS in front of the installation

Nothing in the Compose stack terminates TLS. The UI is served as plain HTTP on
loopback (`FRONTEND_PORT`, default `127.0.0.1:3000`) and the API on
`127.0.0.1:8000`; the terminator in front of the host is what makes them
`https://`.

`docker/nginx/reverse-proxy.example.conf` is a working nginx server block for that
role: it redirects port 80, listens on 443, sets the forwarding headers the
application needs in order to resolve and record the real client address, and
matches the application's own upload and timeout bounds. It carries the commands
for a self-signed certificate as well, which is what an installation inside the
perimeter usually wants. Copy it into `/etc/nginx`, then adjust the server name,
the certificate paths and — if the UI is published on another port —
`proxy_pass`.

Three things about the headers are not cosmetic:

* **`X-Forwarded-For`** is how the audit trail records `ip_address`. The
  application resolves the client address itself, from the right-hand end of the
  header, trusting only ranges listed in `TRUSTED_PROXY_IPS` (Compose appends this
  deployment's own network to that list). A proxy that does not set the header, or
  an installation whose `TRUSTED_PROXY_IPS` does not name the proxy, records the
  Docker bridge address in every audit row instead of the user's.
* **`X-Forwarded-Proto`** tells the application it is serving HTTPS even though the
  container it runs in is not.
* **The loopback bindings.** A proxy on another host cannot reach them at all:
  publish `FRONTEND_PORT` on the interface that proxy uses (for example
  `FRONTEND_PORT=10.0.0.10:3000`) and add the proxy's address to
  `TRUSTED_PROXY_IPS`.

Inside the frontend container, `docker/nginx/realip.sh` — copied into the image
as `/docker-entrypoint.d/41-opendrp-realip.sh` — turns `TRUSTED_PROXY_IPS` into
the nginx `set_real_ip_from` list the edge rate limits and the access log key on,
and it takes an optional output path as its only argument. An installation
reached directly needs nothing from it: with `TRUSTED_PROXY_IPS` empty it writes a
comment saying so and leaves the peer address alone.

Verify it end to end before handing the installation over: `curl -I
https://drp.example.com/` answers over TLS, a sign-in survives a page reload
(that is the `Secure` refresh cookie doing its job), and the newest audit row for
the sign-in carries the address you connected from rather than `172.x.x.x`.

### HSTS

HSTS (`Strict-Transport-Security`) is off by default (`HSTS_ENABLED=false`), and
that default is deliberate rather than merely cautious. The header is a promise
the browser keeps for `HSTS_MAX_AGE` seconds and cannot be withdrawn early:
taking it back requires an HTTPS response with `max-age=0`, which is exactly what
is unavailable while a certificate is expired or has been replaced by a
self-signed one. An internal installation replaces its certificate more often than
a year, so enabling this by default is how a deployment locks its own users out of
it.

| Setting | Default | What it does |
|---|---|---|
| `HSTS_ENABLED` | `false` | Send `Strict-Transport-Security` at all |
| `HSTS_MAX_AGE` | `31536000` | Seconds the browser remembers it. One year is what preload lists require; lower it for a pilot |
| `HSTS_INCLUDE_SUBDOMAINS` | `false` | Also applies the promise to every subdomain of the host |

Both the API and the UI read these three values, so an API response and the page
that called it cannot disagree about them. Changing them needs a recreate
(`docker compose up -d backend frontend`), not a restart: the frontend renders the
header at container start.

The renderer is `docker/nginx/hsts.sh`, which reads `HSTS_ENABLED`,
`HSTS_MAX_AGE` and `HSTS_INCLUDE_SUBDOMAINS` and writes the nginx include the
server blocks pick up. It also reports without writing, which is how to dry-run a
change before recreating anything: `docker compose exec frontend sh
/docker-entrypoint.d/40-opendrp-hsts.sh --check` answers `0` when HSTS would be
sent and `1` when it would not, and a window nginx cannot use is an input error
(`2`) rather than a header with `max-age=0`.

Turn it on when the terminator serves a certificate browsers already trust — the
case the `https://` public URL describes.

## Applying configuration changes

Environment changes require service recreation:

| Change | Required action |
|---|---|
| Application `.env` variable | `docker compose up -d <service>` |
| Connector API key or connector token | `docker compose up -d connector-<name>` |
| Image version | `docker compose pull && docker compose up -d` |
| Mounted source or test tooling (development) | `make up-tools`, which layers `docker-compose.dev.yml` on. Never the shape an installation runs |
| Database schema | Start the pinned release; the API runs the locked migration, or run the documented migration command first |

Use `--force-recreate` when Compose does not detect the changed environment. `docker compose restart` is not sufficient.

## Monitoring and minimum operational controls

- Ship container stdout/stderr to the SIEM as described in [observability.md](observability.md).
- Monitor host disk, memory, CPU, PostgreSQL connections, Redis memory and Docker restart counts.
- Alert on unhealthy backend, worker, beat or connector services.
- Check pending and failed alert deliveries after provider outages.
- Run `make backup-verify` on a schedule.
- Verify the audit chain periodically.
- Keep `OPENDRP_VERSION` pinned and review release notes before upgrading.

## Upgrade and rollback

Before every upgrade:

```text
make backup
make backup-verify
docker compose -f docker-compose.yml pull
docker compose -f docker-compose.yml up -d
```

Read [upgrading.md](upgrading.md) for destructive migrations, key rotation and rollback. Do not downgrade application images across an incompatible migration without a verified backup and a rollback plan.

## Installing without internet access

An installation whose host cannot reach the internet is supported, because the
things that need the network are the connectors, not the platform. Two halves
have to be prepared separately.

**Build where the network is, move images where it is not.** Build from the
checkout on a connected machine, then carry the images as files:

```text
docker compose -f docker-compose.yml build
docker save ghcr.io/opendrp/opendrp/backend:0.2.0 ghcr.io/opendrp/opendrp/frontend:0.2.0 > opendrp-images-0.2.0.tar
```

The release matrix builds eight images — `backend`, `frontend`,
`connector-dnstwist`, `connector-shodan`, `connector-hibp`,
`connector-dns-security`, `connector-intelligence` and
`connector-exposure-endpoints` — all tagged with `OPENDRP_VERSION` under
`OPENDRP_IMAGE_PREFIX`. Save the ones your service set uses (add the DNS,
intelligence and endpoint images if you enable those profiles), copy the
tarball, and load it on the target host:

```text
docker load < opendrp-images-0.2.0.tar
```

Then run the deployment steps as written, without `--build` and without `docker
compose pull`: Compose finds the images locally because the tag it asks for is the
same one you loaded. Dependencies are pinned exactly and hash-checked (`backend/requirements.txt`
with `pip install --require-hashes`, `frontend/package-lock.json` with `npm ci`),
so a rebuild from the same commit installs the same Python and npm tree. Base
image tags
(`python:3.12-slim`, `node:20-alpine`, `postgres:17-alpine`, `redis:7-alpine`)
are moving tags, so a rebuild can pick up a new upstream patch — deliberate, and
[SECURITY.md](../SECURITY.md#base-images-and-dependency-pins) says what
compensates for it and how to pin a digest if you need a byte-identical rebuild.
The tarball is a convenience, not the only route to a reproducible image.

**What still needs a path out of the network.** The platform itself needs none:
the wizard is standard library only, `.env` is a local file, and the API applies
its own migrations at startup under an advisory lock. What needs egress or an
internal substitute is everything that talks to the outside world — DNS and WHOIS
lookups (set `OPENDRP_DNS_PRIMARY` / `OPENDRP_DNS_SECONDARY`, and
`DNS_NAMESERVERS` for DNSTwist and the DNS Security resolver, to an internal
resolver), SMTP or a Telegram relay for alerts, and the provider APIs behind the
Shodan, HIBP, DNS Security and intelligence connectors. A deployment with no
internal resolver and no relay runs the platform and no connector; that is a
supported configuration, not a broken one, and Settings reports the connectors as
silent rather than as passing.

`make pull-prod` and `make up` from a fresh checkout both reach the network (GHCR
and the package indices respectively). Neither is part of an offline install.

## Recovering a lost host

The host is replaceable. What is not replaceable is the `.env` file, the database
and the report store — and of those three, only the `.env` cannot be regenerated
from something else. Do this in order.

1. **Prepare the replacement host** with the Docker and Compose versions in
   [Supported versions](#supported-versions) or newer, sized per [Host
   requirements](#host-requirements), with the firewall, NTP, swap and data-root
   decisions already made. Docker Engine is not the platform: install it first and
   let it come up clean.
2. **Restore the `.env`** from the out-of-band copy you keep outside this system.
   The keys in it are why this step comes before the database: `ENCRYPTION_KEY`
   decrypts the SMTP/Telegram secrets stored in PostgreSQL, `JWT_SECRET_KEY` (and
   its `*_PREVIOUS_*` lists) keeps existing sessions verifiable, and
   `AUDIT_CHAIN_KEYS` is what makes the audit chain verifiable at all. A dump
   restored under a fresh `.env` comes back with unreadable settings and a trail
   that no longer verifies. Keep `POSTGRES_USER`, `POSTGRES_DB`,
   `OPENDRP_VERSION` and the `OPENDRP_*_SUBNET` values too: the network ranges must
   stay inside `OPENDRP_NETWORK_SUBNET`, which is the parent range
   `TRUSTED_PROXY_IPS` names.
3. **Start the datastores and stop there.** `docker compose -f docker-compose.yml up -d postgres redis`, then wait for both to report healthy. Restoring into a database that is still being written to is the failure the restore script exists to refuse.
4. **Restore the newest verified dump**, from the off-host copy rather than from
   `./backups`, if the host itself was lost:
   `CONFIRM_RESTORE=yes make restore FILE=<dump>`. The script refuses without the
   confirmation, refuses while another client is connected, and takes a safety
   copy of the current database before it touches it. See
   [backup-restore.md](backup-restore.md).
5. **Re-attach the report store.** Generated PDFs live in the
   `opendrp-reports-store` volume, not in the dump; restore its archive, or point
   the volume at the copy you kept. Reports produced after the last backup are
   gone — that gap is the RPO in [backup-restore.md](backup-restore.md), not a bug.
6. **Start the platform and check it.** `docker compose -f docker-compose.yml up -d`, then `make health`. The API applies any pending migrations at startup.
7. **Prove the recovery rather than assuming it.** `make verify-audit-chain FULL=1` walks the whole chain, `make backup-verify` restores the newest dump into a throwaway database, and the hand checks from the quarterly drill in [backup-restore.md](backup-restore.md) — asset counts, the newest audit rows, one report download — are what confirm the instance is the one you meant to restore.
8. **Rotate what the incident exposed.** Key rotation (`python -m scripts.rotate_keys`),
   connector-token rotation and alert-secret replacement are described in
   [upgrading.md](upgrading.md). Rotate `JWT_SECRET_KEY` only deliberately: it
   signs every live session out.

Redis is deliberately not part of the recovery. It holds the Celery queues and the
one-minute schedule deduplication keys, both of which are rebuilt: pending jobs are
rows in PostgreSQL and are re-enqueued by the next schedule tick.

## Decommissioning

Turning the platform off is an operation with a right order, because the audit
trail is the part with lasting value and it is the part most easily destroyed by
tidying up.

1. **Export the evidence first.** Verify the chain while the installation still
   runs (`make verify-audit-chain FULL=1`) and export the trail you are required to
   keep — the audit API or the archived NDJSON stream described in
   [observability.md](observability.md). A chain that was never verified is not
   evidence, and a chain can only be verified where its keys and rows still exist.
2. **Archive the keys, deliberately.** `AUDIT_CHAIN_KEYS` is what a verifier needs
   to re-check the exported stream, so it belongs with it in the archive.
   `ENCRYPTION_KEY` is what makes any retained dump's encrypted settings readable,
   and `JWT_SECRET_KEY` is worth nothing after the fact — destroy that one rather
   than storing it. Decide, in writing, which of the two you keep and for how long.
3. **Stop the stack.** `docker compose -f docker-compose.yml down` keeps every
   volume, which is the safe first step; add `--profile backup` to address the
   services you actually started, or their containers and networks stay behind.
4. **Destroy the data only after the archive is verified.** `make destroy` (or
   `down -v`) removes the three Compose volumes — `opendrp-postgres-data`,
   `opendrp-redis-data` and `opendrp-reports-store` — and nothing brings them
   back. Container images can be deleted freely; they are rebuildable from the
   release tag.
5. **What survives you.** Off-host backups, SIEM copies and the exported trail are
   outside this host by design and are not affected by step 4. Their retention is
   a decision you still own, and an exported audit stream whose chain keys were
   destroyed is unverifiable forever.

## Supported versions

| Component | Version this release is built and tested against | Where it is fixed | How it is checked |
|---|---|---|---|
| Docker Engine + Compose | Compose v2.24 or newer (the `!reset` tags in the replicas file need it) | `docker-compose.replicas.yml`, this document | CI resolves every Compose file set and both overlay shapes |
| Python (API, worker, beat, all connectors) | 3.12 | `backend/Dockerfile`, `connectors/*/Dockerfile` | the image is the runtime; `backend/requirements.txt` is pinned exactly |
| Node.js | 20, build stage only — nothing ships a Node runtime | `frontend/Dockerfile` builder stage | the build fails without `package-lock.json`, so the tree is fixed by the lockfile |
| PostgreSQL | 17 | `docker-compose.yml` (`postgres`, and the `backup` service's client) | the backup client is deliberately the same major version so `pg_dump` refuses nothing |
| Redis | 7 | `docker-compose.yml` | the broker healthcheck authenticates and reads `PONG` |
| nginx | 1.29 | `frontend/Dockerfile` runtime stage; `docker/nginx/reverse-proxy.example.conf` for the host terminator | the image tag is pinned; the example proxy is exercised only by an operator |
| Host operating system | Linux with Docker Engine for production; Windows and macOS through Docker Desktop for local use | this document | the runbook's commands are checked for portability across bash, PowerShell and `cmd.exe` |
| Client browser | any current evergreen browser — the SPA needs `Secure` cookies, so it is reached over HTTPS | `CORS_ORIGINS`, `AUTH_COOKIE_SECURE` | production refuses a non-HTTPS origin and an insecure cookie |

Anything not in this table is not claimed to work. A newer major version of any
of these is a migration to schedule, not an upgrade to assume.
