# Configuration reference

OpenDRP has three configuration layers. Keeping them separate prevents an operator from looking for a deployment setting in the web UI or expecting a `.env` edit to change a running container.

## Configuration ownership

| Layer | Examples | Where to change | Requires recreation? |
|---|---|---|---:|
| Deployment and security | `APP_ENV`, `OPENDRP_VERSION`, CORS, cookies, database pool, timeouts, resource policy | `.env` and Compose | Yes |
| Application settings | SMTP, Telegram, recipients, scan schedules, connector registry settings | **Settings** in the UI | No; persisted in PostgreSQL |
| Connector runtime | Provider API keys, connector token, DNSTwist limits, Shodan pacing | `.env` for the matching connector | Yes, for that connector |

Connector-scoped settings are namespaced after their connector (`SHODAN_*`, `DNSTWIST_*`, `HIBP_*`), because `.env` is one namespace shared by every service in the Compose file set: an unprefixed name would be claimed by whichever connector asked for it first. `scripts/check_env_template.py` fails a build that adds one.

### Origins and bindings

`CORS_ORIGINS` is the origin the **browser** uses, which is the TLS terminator in front of the installation. The published ports answer a different question: they bind the containers to this host (loopback by default) so that terminator can forward to them. `FRONTEND_PORT` and `docker/nginx/reverse-proxy.example.conf`'s `proxy_pass` have to be changed together; [deployment.md](deployment.md#the-origin-and-the-bindings) has the table. `python setup.py --check` warns when a plain-HTTP loopback origin names a port nothing in the file is published on.

Provider API keys are never stored in the core `system_settings` table. Alert secrets entered in Settings are encrypted at rest with `ENCRYPTION_KEY` and sender/recipient addresses are masked in API responses. SMTP security is explicit: `starttls` (recommended), `ssl` (implicit TLS), or `plain` (trusted internal relay only). It is not inferred from the port number.

## Production-required values

Production requires:

- `APP_ENV=production`;
- a pinned semantic `OPENDRP_VERSION`, never `latest`;
- unique `JWT_SECRET_KEY` and `ENCRYPTION_KEY`;
- explicit `AUDIT_CHAIN_KEYS`;
- `AUTH_COOKIE_SECURE=true`;
- valid HTTPS `CORS_ORIGINS`;
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

The base Compose file applies conservative limits suitable for a small installation:

- PostgreSQL: 1 GB RAM, 1 CPU, 256 PIDs;
- Redis: 512 MB RAM, 0.5 CPU, 128 PIDs;
- backend: 768 MB RAM, 1 CPU, 256 PIDs;
- Celery worker: 1 GB RAM, 1 CPU, 256 PIDs;
- Celery Beat: 256 MB RAM, 0.5 CPU, 128 PIDs;
- DNSTwist: 768 MB RAM, 1 CPU, 256 PIDs;
- Shodan/HIBP: 512 MB RAM, 0.75 CPU, 128 PIDs;
- frontend: 256 MB RAM, 0.5 CPU, 128 PIDs.

These limits are guardrails, not a substitute for monitoring. DNSTwist and report generation are the heaviest operations. Increase limits only after checking host capacity and PostgreSQL connection usage.

## Database pool budget

Each API process owns its own pool. A rough upper bound is:

```text
API workers × (DB_POOL_SIZE + DB_MAX_OVERFLOW)
+ worker pool
+ beat pool
+ maintenance headroom
```

Keep that total below PostgreSQL `max_connections`, leaving capacity for migrations, backups and an administrative session.
