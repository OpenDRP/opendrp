# Configuration reference

OpenDRP has three configuration layers. Keeping them separate prevents an operator from looking for a deployment setting in the web UI or expecting a `.env` edit to change a running container.

## Configuration ownership

| Layer | Examples | Where to change | Requires recreation? |
|---|---|---|---:|
| Deployment and security | `APP_ENV`, `OPENDRP_VERSION`, CORS, cookies, database pool, timeouts, resource policy | `.env` and Compose | Yes |
| Application settings | SMTP, Telegram, recipients, scan schedules, connector registry settings | **Settings** in the UI | No; persisted in PostgreSQL |
| Connector runtime | Provider API keys, connector token, DNSTwist limits, Shodan pacing | `.env` for the matching connector, or the encrypted per-account key below | Yes, for that connector |

Connector-scoped settings are namespaced after their connector (`SHODAN_*`, `DNSTWIST_*`, `HIBP_*`, `DNS_SECURITY_*`), because `.env` is one namespace shared by every service in the Compose file set: an unprefixed name would be claimed by whichever connector asked for it first. A key that several workers of the same provider share keeps one name instead (`NETLAS_API_TOKEN`). `scripts/check_env_template.py` fails a build that adds one.

### Origins and bindings

`CORS_ORIGINS` is the origin the **browser** uses, which is the TLS terminator in front of the installation. The published ports answer a different question: they bind the containers to this host (loopback by default) so that terminator can forward to them. `FRONTEND_PORT` and `docker/nginx/reverse-proxy.example.conf`'s `proxy_pass` have to be changed together; [deployment.md](deployment.md#the-origin-and-the-bindings) has the table. `python setup.py --check` warns when a plain-HTTP loopback origin names a port nothing in the file is published on.

Provider API keys reach a connector by one of two routes, and the core `system_settings` table is neither of them. The first is the connector's own environment: `.env` and Compose hand the key to the matching container, namespaced after the provider. The second is a **source account** row in the core database: the value is stored as ciphertext under `ENCRYPTION_KEY`, an administrator writes it with `PUT /api/v1/connectors/accounts/{account_id}/api-key` and clears it with `DELETE` on the same path, the API answers with a four-character hint (`mask_value(api_key, keep_first=0, keep_last=4)`, so the last four characters, which Settings renders as `API key stored (1234)`) and never with the value, and the connector bound to that account receives it when it asks `GET /api/v1/connectors/me/credential`. Alert secrets entered in Settings are encrypted at rest with `ENCRYPTION_KEY` and sender/recipient addresses are masked in API responses. SMTP security is explicit: `starttls` (recommended), `ssl` (implicit TLS), or `plain` (trusted internal relay only). It is not inferred from the port number.

## Production-required values

Production requires:

- `APP_ENV=production`;
- a pinned semantic `OPENDRP_VERSION`, never `latest`;
- unique `JWT_SECRET_KEY` and `ENCRYPTION_KEY`;
- explicit `AUDIT_CHAIN_KEYS`;
- `AUTH_COOKIE_SECURE=true`;
- `CORS_ORIGINS` naming the browser origin (the setup wizard insists on HTTPS for a public host; the startup validator parses the list rather than refusing a scheme);
- authenticated Redis and PostgreSQL URLs;
- consistent Docker network subnets.

Run the setup audit after changing `.env`:

```text
python setup.py --check
```

The administrator Settings page also exposes **Applied runtime configuration**. It shows safe values read by the running backend (version, database pool and timeout budgets), never secrets or raw connection URLs.

## Applying changes

A Docker container receives its environment when it is created. Use:

```text
docker compose -f docker-compose.yml up -d <service>
```

or, when necessary:

```text
docker compose -f docker-compose.yml up -d --force-recreate <service>
```

`docker compose restart` does not reload `.env` values.

## Resource settings

Every service in `docker-compose.yml` carries `mem_limit`, `cpus` and
`pids_limit`. The values are **ceilings, not reservations**: Docker enforces them
when a service exceeds them and reserves nothing, so what follows is a worst-case
sum, not a promise about what the stack will use.

| Service | `mem_limit` | `cpus` | `pids_limit` |
|---|---|---:|---:|
| `postgres` | `1.5g` | `1.0` | `256` |
| `redis` | `512m` | `0.5` | `128` |
| `backend` | `768m` | `1.0` | `256` |
| `celery-worker` | `1.5g` | `1.0` | `256` |
| `celery-worker-alerts` | `512m` | `0.5` | `128` |
| `celery-beat` | `256m` | `0.5` | `128` |
| `connector-phishing-dnstwist` | `768m` | `1.0` | `256` |
| `connector-phishing-shodan` | `512m` | `0.75` | `128` |
| `connector-breaches-hibp` | `512m` | `0.75` | `128` |
| `connector-dns-rdap` | `512m` | `0.75` | `128` |
| `connector-dns-resolver` | `512m` | `0.75` | `128` |
| `connector-dns-ctlogs` | `512m` | `0.75` | `128` |
| `connector-dns-virustotal` | `512m` | `0.75` | `128` |
| `connector-phishing-netlas` | `512m` | `0.75` | `128` |
| `connector-dns-netlas` | `512m` | `0.75` | `128` |
| `connector-exposure-netlas` | `512m` | `0.75` | `128` |
| `connector-exposure-netlas-endpoints` | `512m` | `0.75` | `128` |
| `connector-exposure-shodan-endpoints` | `512m` | `0.75` | `128` |
| `frontend` | `256m` | `0.5` | `128` |
| `backup` | `512m` | `0.5` | `128` |

The keyless DNS workers (`connector-dns-rdap`, `connector-dns-resolver` and
`connector-dns-ctlogs`) start with the installation. The keyed connectors and
`backup` run only when their profile is named in `COMPOSE_PROFILES` — `shodan`,
`shodan-endpoints`, `hibp`, `virustotal`, `netlas`, `netlas-endpoints` or `backup`.
`scripts/check_compose_healthchecks.py` compares every row above against
`docker-compose.yml` on each build: a limit changed in one place and not the
other fails CI instead of being discovered during an incident.

The Netlas-provider services are in `docker-compose.yml`:
`connector-phishing-netlas`, `connector-dns-netlas` and `connector-exposure-netlas`
under the `netlas` profile, and `connector-exposure-netlas-endpoints` under
`netlas-endpoints`. Each carries **512 MB RAM, 0.75 CPU and 128 PIDs**, the same
bounds as the Shodan and HIBP connectors. The Shodan endpoint worker,
`connector-exposure-shodan-endpoints`, sits under the `shodan-endpoints` profile
with those same bounds.

Sums by set. "Base" is the always-on set: the services above that are in no
profile. Each further line adds the set it names.

| Set | `mem_limit` sum | `cpus` sum |
|---|---:|---:|
| Base (always on) | 7.0 GiB | 7.75 |
| + `netlas` profile (3 workers) | 8.5 GiB | 10.0 |
| + `netlas-endpoints` and `shodan-endpoints` profiles (1 worker each) | 9.5 GiB | 11.5 |
| + `shodan`, `hibp`, `virustotal` profiles (1 worker each) | 11.0 GiB | 13.75 |
| + `backup` profile | 11.5 GiB | 14.25 |

These are floors for host sizing, not the memory the stack needs: the kernel, the
Docker daemon and page cache sit on top of every line, and enabling an overlay
raises the requirement before a single scan runs. A host that covers the base set
but not the overlay it enables will throttle or OOM-kill the container that
exceeds its own limit rather than refusing to start.
[deployment.md](deployment.md#host-requirements) turns these sums into a
recommendation, and `python setup.py --check` reports them for the checkout in
front of you.

DNSTwist and report generation are the heaviest operations. Increase a limit only
after checking host capacity and the connection budget below.

## Edge rate limits

The application limits requests per account (`AUTHENTICATED_RATE_LIMIT_PER_MINUTE`)
and failed logins per address, but those counters live in Redis and therefore fail
open when Redis is unreachable — a documented trade, see [security.md](security.md).
The nginx configuration in front of the stack is the bound that needs no
datastore:

| Zone | Applies to | Rate | Burst |
|---|---|---|---|
| `opendrp_auth` | `/api/v1/auth/` | `30r/m` per client address | 15 |
| `opendrp_api` | the rest of `/api/` | `120r/m` per client address | 60 |
| `opendrp_conn` | concurrent connections per client address | 20 on authentication, 40 elsewhere | — |

The zones are declared in `docker/nginx/nginx.conf`, applied in
`docker/nginx/default.conf`, and declared again at the terminator in
`docker/nginx/reverse-proxy.example.conf` — that proxy is the only place where the
remote address is the real client. Refusals are answered with `429`, never `503`: a
rate-limited client has not found a broken backend.

The key is the client address, taken from `X-Forwarded-For` **only** for the hops
named by `TRUSTED_PROXY_IPS`. That is the same variable the API uses for the
address it records in every audit row, rendered into the configuration at
container start by `docker/nginx/realip.sh`, so the two cannot disagree about
which hop may be believed. An installation reached directly keys on the peer
address, which is correct; an installation behind a proxy whose address is missing
from `TRUSTED_PROXY_IPS` gives every client one shared bucket.

Changing a value means changing it in the three files that carry it — the zone
declaration in `docker/nginx/nginx.conf`, the `limit_req` and `limit_conn`
application in `docker/nginx/default.conf`, and the terminator's own copies in
`docker/nginx/reverse-proxy.example.conf` — and in the table above, together.
`docker/nginx/nginx.conf` is baked into the frontend image, so that change needs a
rebuild:

```text
docker compose -f docker-compose.yml build frontend
docker compose -f docker-compose.yml up -d frontend
```

## Database pool budget

Each API process owns its own pool, and `postgres` is started with
`max_connections=200` (`docker-compose.yml`). One process can hold at most
`DB_POOL_SIZE + DB_MAX_OVERFLOW` connections, so the bound is:

```text
API workers x (DB_POOL_SIZE + DB_MAX_OVERFLOW)   = UVICORN_WORKERS x 30
+ worker pool (celery-worker)                     = 30
+ alerts pool (celery-worker-alerts)              = 30
+ beat pool (celery-beat)                         = 30
+ maintenance headroom                            = 20
```

`DB_POOL_SIZE` and `DB_MAX_OVERFLOW` are read by **every** service that opens a
pool — the API once per uvicorn worker, plus the two Celery processes and the
scheduler — because Compose gives all four the same pair. The per-service
defaults in `docker-compose.yml` (20+10 for the API, 10+5 for the workers,
5+2 for the scheduler) apply only to a service whose variable is unset, so a
`.env` written from `.env.example` — which sets `DB_POOL_SIZE=20` and
`DB_MAX_OVERFLOW=10` — leaves all four at 30. The maintenance headroom is the
clients that are not pools: the startup migration (which may hold a connection
for the length of an upgrade), a `pg_dump`, an operator's session, and the slots
PostgreSQL reserves for superusers.

With the shipped defaults (`DB_POOL_SIZE=20`, `DB_MAX_OVERFLOW=10`,
`UVICORN_WORKERS=1`) that is 140 of the 200. The two-replica shape of
[upgrading.md](upgrading.md) adds a second API process and takes the total to
170, which leaves 30 for a maintenance window. Raising `UVICORN_WORKERS` costs 30
per worker and is the change most likely to exceed the budget.

`python setup.py --check` prints the sum and warns when it does not fit the 200
`docker-compose.yml` starts PostgreSQL with, naming the variables to lower. It
reads `.env`, so it cannot see API replicas: a two-replica deployment has to add
`30` to the number itself, and the 170 above is that arithmetic already done. The
Settings page **Applied runtime configuration** shows the pool size the running
backend actually read, which is the other half of the answer — what it read, not
what the file said.
