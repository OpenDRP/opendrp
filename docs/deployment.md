# Production deployment runbook

This is the supported production procedure for a small or medium self-hosted OpenDRP installation, and it is the only one: the platform has a single deployment shape, `docker-compose.yml`, and `make up` starts it. The development overlay (`docker-compose.dev.yml`) is a test harness — it mounts the source tree and installs pytest, ruff and mypy — and no step below reaches it. Every step here assumes the installation shape, because that is what users reach.

## Requirements

- Docker Engine or Docker Desktop with Compose v2.24 or newer.
- At least 4 CPU cores, 8 GB RAM and 40 GB free disk for a small production installation. The Compose file applies conservative per-service CPU, memory and PID limits; increase them only after measuring the workload.
- A DNS name and TLS termination in front of the frontend — the stack does not terminate TLS itself. Do not expose the application over plain HTTP: the refresh cookie is `Secure`, so no browser would send it and a session could not survive a reload. [TLS in front of the installation](#tls-in-front-of-the-installation) has the procedure and a working nginx configuration.
- Outbound access required by the enabled connectors, DNS/WHOIS, SMTP and Telegram. The backend and worker use `OPENDRP_DNS_PRIMARY` / `OPENDRP_DNS_SECONDARY`; DNSTwist has its separate `DNS_NAMESERVERS` setting.
- Off-host encrypted backup storage.

Check the Compose version before starting:

```text
docker compose version
```

## 1. Prepare the checkout and version

The original release tag `v0.1.0` is preserved. A security-fixed patch candidate, `v0.1.1`, is being prepared; do not use that version until its GitHub Release and GHCR images have been published. For an available production release, check out its tag and pin the same version in `.env`:

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
python setup.py --public-url https://drp.example.com --version 0.1.1
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
python setup.py --non-interactive --public-url https://drp.example.com --version 0.1.1 --connectors dnstwist,hibp --mfa
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

## 6. Provision connectors

For every enabled connector, issue a core credential. The plaintext is printed once and never stored, so each command's output goes into `.env` under the variable it names:

```text
docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens issue dnstwist --type phishing --env CONNECTOR_TOKEN_DNSTWIST
docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens issue shodan --type phishing --env CONNECTOR_TOKEN_SHODAN
docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens issue hibp --type breaches --env CONNECTOR_TOKEN_HIBP
```

Paste each one-time token into the matching `.env` variable. Set provider API keys only for their connector service. Then recreate the affected services:

```text
docker compose -f docker-compose.yml up -d connector-dnstwist connector-shodan connector-hibp
```

A restart does not update a container's environment. Confirm connector registration and heartbeat in **Settings → Connectors**.

To replace a credential later, use `rotate` with the same name: the previous value stops working immediately and the connector keeps its registry row, configuration and job history. Recreate the service afterwards, because the new value is read when the container is created:

```text
docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens rotate dnstwist --env CONNECTOR_TOKEN_DNSTWIST
docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens rotate shodan --env CONNECTOR_TOKEN_SHODAN
docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens rotate hibp --env CONNECTOR_TOKEN_HIBP
docker compose -f docker-compose.yml up -d connector-dnstwist connector-shodan connector-hibp
```

`revoke <name>` cuts a connector off without deleting anything, and `list` reports which connectors hold a credential.

Provider keys are subject to provider plans. Shodan's SSL-text and favicon searches need a key of at least the **Membership** tier; on a lower tier the refusal is reported as a partial scan rather than as an empty result. HIBP publishes an integration key for a test installation (`00000000000000000000000000000000`) that returns the documented fixture breaches for `account-exists@hibp-integration-tests.com` and `hibp-integration-tests.com` — see [connectors/README.md](../connectors/README.md).

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
