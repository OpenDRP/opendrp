# Production operations

This guide covers the checks that should continue after deployment. It is intentionally short; detailed log transport is in [observability.md](observability.md), and upgrades are in [upgrading.md](upgrading.md).

## Daily checks

```text
docker compose -f docker-compose.yml ps
docker compose -f docker-compose.yml logs --tail=200 backend celery-worker celery-beat
```

Confirm that the backend, worker, beat and enabled connectors are healthy. Review failed or repeatedly retrying alert deliveries and connector jobs in the UI.

## Resource checks

Monitor the Docker host for:

- free disk space, especially the Docker data root and backup directory;
- memory pressure and OOM kills;
- CPU saturation during scans and PDF generation;
- PostgreSQL connection count and slow statements;
- Redis memory and task backlog;
- repeated container restarts.

The Compose limits are conservative starting values. A limit breach should produce an operational adjustment or a workload reduction, not an unbounded removal of the limit.

## Alerts and queues

Finding alerts are persisted before delivery. **The queue is drained by a scheduled task, not by the API:** `deliver-pending-alerts-every-15-seconds` runs in the `celery-beat` container, so a scheduler that is not running looks exactly like a working installation with no findings — rows accumulate as `pending` and nothing is delivered. Check it first when a notification does not arrive:

```text
docker compose -f docker-compose.yml ps celery-beat
docker compose -f docker-compose.yml logs --tail=50 celery-beat
```

No regular expression is needed to read the log: a scheduler that cannot start prints the `Settings` validation error that stopped it, and `Restarting` in the `ps` output means that is what you are looking at. Once it is healthy the backlog is delivered in aggregated messages, one per job, threat type and channel.

What a delivered message contains is the module's own content, laid out by the channel: a header naming the module and the count, the breakdown of the values that module considers worth counting (for phishing, the detection source and the matched asset), and then one numbered line per finding, with the finding itself in a fixed-width face and the fields that describe it beside it. The email carries the same material as a table — one row per finding, columns named by the module's declared fields — plus a text-only alternative, and both channels link back to the finding page **only when the installation knows its own address** (the first non-loopback `CORS_ORIGINS` entry); with no such origin there is no link, because a delivered message that points at `localhost` points at the reader's own machine. A batch larger than one message is cut between findings, never inside its own markup, and the message ends by saying how many findings it left out.

A delivery can be pending, delivering, sent or failed, and the queue is independent per channel and recipient: a successful email or chat is never used to mark an unavailable destination as sent. `channel` names a concrete destination (`email` or `telegram`); an installation with no channel configured queues nothing and logs `alert_delivery_no_channel`, because the finding is already durable and a row no destination can satisfy would only fail permanently. Transient network, timeout, HTTP 408, HTTP 429 and HTTP 5xx failures are retried within the configured attempt limit. Configuration and authentication failures are permanent and require operator action.

Report generation writes to a unique temporary sibling and publishes with an atomic rename only after rendering completes. A timeout cannot publish a late PDF or delete a file while the renderer is still writing; the retention sweep also removes only old, recognized report temporary files left by a worker crash. SQLAlchemy pool exhaustion is surfaced as retryable `503 database_busy` with `Retry-After`, separately from server-side statement timeout.

When a provider is unavailable:

1. Confirm the connector/job result and correlation ID.
2. Check SMTP or Telegram health from **Settings**.
3. Check worker health and logs.
4. Confirm the queue is progressing after the provider recovers.
5. Do not repeatedly press Rescan to compensate for a delivery outage; scans and alert delivery are separate durable workflows.

## Backups

Run a backup and verify that it can be restored:

```text
make backup
make backup-verify
```

Copy verified archives off the Docker host, protect them as sensitive data and encrypt them at rest. Perform a restore drill at least quarterly or after a major migration.

## Audit integrity

Verify the tamper-evident chain periodically:

```text
make verify-audit-chain
```

Ship stdout to the SIEM. Database retention is not SIEM retention; configure the collector's retention separately.

## A service will not become healthy

`docker compose up -d` reports the *healthcheck verdict*, not the reason. A
service that waits on the backend prints `dependency failed to start: container
opendrp-backend is unhealthy`, which names the blocked service; the traceback is
one command away:

```text
docker compose -f docker-compose.yml logs --tail=100 backend
docker compose -f docker-compose.yml ps
docker inspect opendrp-backend --format "{{json .State.Health}}"
```

The API container's entrypoint applies migrations, ensures the `system_settings`
singleton and then starts Uvicorn, under `set -e`. So the last `[OpenDRP] ...`
line in its log names the step that failed, and the traceback under it is the
reason. `make up` prints that state and log tail for you when a start fails.

Two causes account for most of these, and both look identical from Compose:

* **the container exited** (`restart: unless-stopped` turns that into a loop, so
  `ps` shows `Restarting` rather than `Exited`) — a startup step raised, and the
  log tail is the error, as above;
* **the process is up but `/api/v1/ready` is not 200** — the API is running and a
  dependency it checks (PostgreSQL, Redis) is not reachable *from this
  container*. `docker compose exec backend curl -sS http://localhost:8000/api/v1/ready`
  says which check failed, and `/api/v1/health` stays dependency-free on purpose
  so it can still answer when readiness cannot.

A connector that restarts on its own is usually a different, expected state: an
unprovisioned connector exits with `Missing required environment variables:
CONNECTOR_TOKEN` and gives up after ten attempts (`restart: on-failure:10`),
rather than looping forever and filling the log. Issue its credential with
`make connector-token NAME=<connector> TYPE=<module>`.

A connector that runs but never appears to be seen is the other half of that
state: it is polling, and the core is refusing its token — for instance a value
pasted into the wrong `CONNECTOR_TOKEN_*` variable, or a `.env` kept from a
database that was recreated. The core names every refusal, so the connector to
re-key is in its own log rather than only in the connector's output:

```bash
docker compose logs --tail=50 backend | grep connector_credential_rejected
```

The reported name is read from the token itself and is a diagnostic hint, never
an identity; only the stored digest authorizes anything.

## Before changing `.env`

Run:

```text
python setup.py --check
docker compose -f docker-compose.yml config --quiet
```

After changing a value, recreate the affected service. A plain restart keeps the environment captured when the container was created. The Settings page's **Applied runtime configuration** card helps confirm what the running backend actually received.
