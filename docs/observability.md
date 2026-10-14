# Observability and SIEM integration

How OpenDRP emits telemetry, where it goes, and how to get it into a SIEM
without losing the audit trail's meaning on the way.

## Where logs go, and why there is no `/var/log/opendrp`

Every container writes to **stdout/stderr** and nothing else. There is no log
file inside the images, no `logrotate`, and no bind-mounted log directory —
because Docker (or Kubernetes, or any other runtime) already owns that job.

The only file path you will find in the repository's logging configuration is
`/tmp` for two liveness heartbeat files, and the only `/var/log` references are
in `docker/nginx/nginx.conf`, where the stock Nginx image has already symlinked
`error_log` and `access_log` to the container's stdout and stderr.

Concretely, this means:

| Producer | Sink | Shape |
|---|---|---|
| `backend` (FastAPI/uvicorn) | container stdout | one JSON object per line (structlog), except uvicorn's own access/error lines, which are plain text |
| `backend` → audit | container stdout **and** `drp_audit_logs` | JSON with exactly five fields (below) |
| `celery-worker`, `celery-worker-alerts`, `celery-beat` | container stdout | same JSON shape via structlog; Celery's own lines are plain text |
| `connector-*` | container stdout | one JSON object per line; `CONNECTOR_LOG_LEVEL` is read by the connector SDK, but neither it nor `LOG_LEVEL` is in `.env.example` or passed to a connector container by Compose, so every connector line is `INFO` until an operator sets the variable on the service itself |
| `frontend` (nginx) | container stdout | plain text, `log_format main` |

What the Docker daemon keeps on the host is
`/var/lib/docker/containers/<id>/<id>-json.log`, sized by the `x-logging` anchor
in `docker-compose.yml` (10 MB × 5 files per container). That bound is a
*debugging* convenience, not the retention policy: durable audit history belongs
in the collector and the SIEM, which is where an operator can search it, and
where it outlives the container.

Writing a file from inside the application would be worse, not better: it needs
a writable bind mount, its own rotation, and it creates a second copy of the
audit stream with different retention rules from the SIEM's — two sources of
truth for the one artefact that must have exactly one.

## The audit line contract

An audit event is emitted twice: as a row in `drp_audit_logs` and as one line of
JSON on stdout. The line has **exactly** five fields, in this shape:

```json
{"timestamp": "2026-09-13T04:15:02.418+00:00", "user_id": "8f1c…", "action": "asset.delete", "ip_address": "203.0.113.7", "details": {"asset_id": "…", "request_id": "web-9f8c1d2e3b4a"}}
```

Two properties are enforced by tests rather than by convention:

* **Exactly five fields.** `app/core/logging_config.py::_render_audit_event`
  rebuilds the event from a fixed field list immediately before rendering, so no
  future processor can widen it. Context that would otherwise be a sixth field —
  correlation, task ids, connector names — goes **inside `details`**.
* **`LOG_LEVEL` cannot silence it.** The audit logger is pinned at `INFO` while
  the rest of the platform follows `LOG_LEVEL`. Audit records are evidence; a
  level setting is a preference about noise, and it must not be able to switch
  the trail off.

`user_id` is `null` for events that are not caused by a person (scheduled scans,
background tasks), and in that case `ip_address` carries an `internal:` prefix
naming the producer (`internal:celery-beat`, `internal:celery`).

Four keys inside `details` are reserved — a caller cannot set them, and the writer
rewrites them after the entry is built. Three belong to the hash chain, and
`verify_audit_chain --ndjson` checks a stream using them:

| Key | What it is |
|---|---|
| `audit_hash` | the HMAC over this entry's five fields and `audit_prev_hash`, keyed by `AUDIT_CHAIN_KEYS` |
| `audit_prev_hash` | the hash of the previous signed entry — the link |
| `audit_key_id` | the fingerprint of the key that signed this entry, so a stream that spans a key rotation stays verifiable |

They are added *after* the entry is hashed and are excluded when the verifier
recomputes it, which is why they can live in `details` without breaking the five
fields. The database row carries the same values in columns (`entry_hash`,
`prev_hash`, `key_id`), so the two copies of one event can be compared without
guessing which key was in force at the time.

The fourth reserved key is `audit_persisted`: the transport marker that says
whether the database copy of this event was written. The stdout line always
carries it and the database row never does — it is stripped from the canonical
payload so a caller cannot forge it — so a line reading `"audit_persisted":
false` is the signature of an audit write that failed, which is exactly the case
the trail must not lose. One further key is added for the writer's own use on an
event a person caused: `actor_email` snapshots the actor's address as it stood
at the time, and the audit API reports `actor_identity_source: "snapshot"` for a
row that carries it, which is what keeps a trail readable after an account is
renamed or deleted.

## Mutations that cannot be recorded are refused

Security-critical asset and user-account mutations commit together with the audit row that records them. On the user lifecycle, the required actions are `user.created`, `user.updated`, `user.password_reset`, `user.locked`/`user.unlocked`, `user.mfa.reset`, and `user.deleted`; the account/session state and the corresponding required audit rows share a transaction. User update details record safe before/after values for changed email, full name, role, rate limit, and active status, but never the supplied password, password hash, TOTP secret, or recovery codes. Asset create/update/delete and observation promotion are also fail-closed audit writes. If a required audit row cannot be written, the mutation is rolled back and the caller is told:

```json
{"detail": "The audit trail could not record this change, so it was not applied. Retry shortly.", "code": "audit_unavailable"}
```

The response is `503` with `Retry-After: 5`, which is worth alerting on for the
same reason `audit.chain.broken` is: it means the platform refused to act rather
than acting without evidence, and a sustained run of it means the audit sink (or
the transaction) is failing. Reads are unaffected — `asset.list` and `asset.view`
stay best-effort background writes, because a read is not a change to the evidence
base. Transactional audit stdout events are emitted only after the owning transaction commits; rollback discards the pending export as well. Authentication likewise does not return an access token or set refresh/CSRF cookies unless the refresh-family row has been durably saved. Session-family persistence failure rolls back and returns a retryable `503` with `Retry-After: 5`, without creating a client-side partial session. The login-success audit event is emitted after session issuance succeeds; it is not a substitute for the durable family row.

For a user update that also resets a password, the trail contains the separate `user.password_reset` event and a `user.updated` summary; only the target identity, changed field names and safe before/after values are recorded. Password material and MFA secrets are excluded. Read events remain best-effort and do not make a read fail when audit persistence is unavailable.

## Correlation

Every HTTP request gets an `X-Request-ID`:

* **incoming** values are accepted only if they match `[A-Za-z0-9._-]{1,64}`;
  anything else is replaced by a generated `req-…` id. The value is client input
  written into two sinks, so it is allowlisted rather than escaped — a newline in
  a non-JSON sink is a forged log line.
* the value is **returned** in the same response header (also exposed to browser
  clients through CORS), so an operator's bug report can quote it;
* it is added to **every log line** emitted while handling the request;
* it is written into the **`details`** of every audit row the request produces;
* it is handed to Celery in the task headers, so a report generated by a click
  carries the same id from the HTTP request into the worker's rows and lines;
* the SPA generates one per call (`frontend/src/lib/api.ts`) and appends it to
  every error message as `(Reference: …)`.

Connectors send their own `X-Request-ID` (`conn-<name>-…`), so a job claimed by
a connector can be followed from the core's audit row into that connector's log.

A useful detection rule can therefore be written once against the id: "show every
log line and audit row for `web-9f8c1d2e3b4a`" answers *what did this request
do*, across processes and across sinks.

## Connector scans and health

Connector jobs are pull-based and carry a renewable lease. A connector sends a
heartbeat while a scan is running, so a long DNSTwist subprocess is not reported
as `degraded` merely because it has not returned yet. If the process disappears,
the core returns the expired job to `pending` up to the configured retry limit
(`CONNECTOR_JOB_MAX_ATTEMPTS`), then records an `error` terminal state.

Job summaries distinguish a valid empty provider response from `skipped`,
`partial`, and provider error details. Investigate the job's `result_summary`,
`error_message`, connector health, and correlation id together; an empty findings
table alone is not evidence that the monitored environment is clean.

## Report generation lifecycle

A report generation attempt updates the report row and its linked `report.generate`
Job together. On a retryable rendering error (`TimeoutError`, `ConnectionError`,
or `OSError`) while Celery retries remain, both return to `pending`; the worker
raises Celery's retry signal and records `report.generate.retry`. On a permanent
error or after retries are exhausted, the report becomes `failed`, the Job becomes
`error`, and `report.generate.failed` is recorded. On success, the report becomes
`completed` and its Job becomes `success` in the same database transaction.

The report outcome audit intent is committed transactionally through an outbox,
then appended to the signed audit chain. If audit persistence is temporarily
unavailable, the intent remains in the outbox with retry scheduling; the retention
worker retries delivery. Search for `report.generate.retry`,
`report.generate.completed` and `report.generate.failed` with `details.report_id`
and `details.job_id`. These lifecycle records deliberately omit user email and
PDF contents; retry events include the attempt number and error type, while
completed events include duration and bounded-row totals. This is a delivery
guarantee within the database/outbox recovery path, not a claim that Celery broker
redelivery or worker-loss behavior has been exercised in a production integration
test.

A task redelivered after completion is idempotent only when its expected artifact
exists in the configured report store; otherwise generation is attempted again.
Operators should correlate the report outcome with the Job state and artifact
availability rather than infer completion from a Celery task log alone.

The current acceptance status, including the retry-exhaustion and
worker-redelivery scenarios that remain unverified, is tracked in
[production-readiness.md](production-readiness.md).

## Shipping to a SIEM

Pick one delivery mechanism. Stacking a log driver and a file collector means
every event is indexed twice, which doubles the counters that detection rules
are thresholded on.

### Option A — collector reads the Docker log files (recommended)

Nothing changes in the application. Elastic Agent or Filebeat reads
`/var/lib/docker/containers/*/*-json.log` and attaches container metadata:

```yaml
# filebeat.yml
filebeat.inputs:
  - type: container
    paths:
      - /var/lib/docker/containers/*/*-json.log
    processors:
      # Without this, an audit line and a uvicorn access line are two
      # indistinguishable text blobs.
      - add_docker_metadata: ~
      - decode_json_fields:
          fields: ["message"]
          target: "opendrp"
          overwrite_keys: true
          when:
            has_fields: ["message"]
processors:
  - drop_fields:
      fields: ["agent", "ecs", "input", "log.offset", "stream"]
output.elasticsearch:
  hosts: ["https://elastic.example:9200"]
  index: "opendrp-%{+yyyy.MM.dd}"
```

In Elastic Security, index `message` (or `opendrp.*`) and map the five audit
fields to ECS:

| Audit field | ECS field | Note |
|---|---|---|
| `timestamp` | `@timestamp` | already ISO-8601 with UTC offset |
| `user_id` | `user.id` | UUID, or `null` for internal events |
| `action` | `event.action` | one of the values in `AUDIT_ALLOWED_ACTIONS` |
| `ip_address` | `source.ip` | `internal:*` for non-HTTP producers |
| `details` | `event.reason` / custom | keep as a nested object; includes `request_id` |
| `request_id` (in details) | `trace.id` | join key across processes |
| `logger` | `log.logger` | `opendrp` for the platform, `opendrp.audit` for records |

### Option B — logging driver

Replace the `x-logging` anchor in `docker-compose.yml`; both examples are in the
comment above it. Use this when the collector cannot read Docker's log files
(some managed platforms) but the destination speaks GELF, Fluentd or syslog:

```yaml
x-logging: &default-logging
  driver: gelf
  options:
    gelf-address: "udp://siem.example:12201"
```

### Option C — Vector

For a local forwarder that normalises before shipping, and for a quick look at
what is actually being emitted:

```toml
[sources.docker_logs]
type = "docker_logs"

[transforms.parse]
type = "remap"
inputs = ["docker_logs"]
source = '''
  parsed, err = parse_json(.message)
  if err == null { . = merge(., parsed) }
'''

[sinks.elastic]
type = "elasticsearch"
inputs = ["parse"]
endpoints = ["https://elastic.example:9200"]
```

## Retention: two policies, on purpose

| Sink | Default | Set by |
|---|---|---|
| `drp_audit_logs` (evidence in the product) | 365 days | `AUDIT_RETENTION_DAYS` (`0` = keep forever) |
| Generated PDFs in the report store | 365 days | `REPORT_RETENTION_DAYS` (`0` = keep forever) |
| Terminal alert deliveries and processed ingestion events | 90 days | `ALERT_HISTORY_RETENTION_DAYS` (`0` = keep them too). The setting is not in `.env.example`, so it is set on the process that needs it |
| `drp_refresh_families` (sessions that ended) | `JWT_REFRESH_TOKEN_EXPIRE_DAYS` after the session ended, and only after its tokens expire | `JWT_REFRESH_TOKEN_EXPIRE_DAYS` (minimum one day; a live session is never a candidate) |
| Container stdout | 10 MB × 5 per service | `x-logging` anchor in `docker-compose.yml` |
| SIEM index | your policy | your index lifecycle policy |

The nightly sweep (`purge_expired_data`, 04:15 UTC) deletes the database rows and
their PDFs in bounded batches, and removes session rows whose tokens have already
expired — a session row is what turns a replay of a signed-out refresh token into
`family_revoked` rather than a silent `family_not_found`, so it is kept exactly as
long as that distinction can be made. The same sweep purges the alert history:
deliveries that reached a terminal state (`sent`, `failed`, `cancelled`) and
ingestion events whose processing finished, each older than
`ALERT_HISTORY_RETENTION_DAYS` (90 days by default). A delivery that is still
pending, delivering or ambiguous is never a candidate, so the cleanup cannot
delete work the platform still owes, and the recipient and occurrence identities
that pace and deduplicate alerts stay behind. It records one `audit.retention.purged` row
when it removes anything, including whether it hit its batch cap and therefore had
more to do. A run that deletes nothing writes no row: an audit trail that records
daily no-ops teaches its readers to ignore it.

Note the asymmetry — the product trims its own table while the SIEM keeps
whatever you tell it to keep. That is deliberate: the SIEM copy is the one you
configure for legal hold, and the database copy exists so the product can *show*
recent history without a round trip to the SIEM.

## What is deliberately not logged

* Passwords, password hashes, access or refresh tokens, connector tokens (only
  SHA-256 digests are stored at all), CSRF values, TOTP secrets and recovery
  codes.
* Decrypted `system_settings` secrets (SMTP password, Telegram bot token).
* Request bodies. Field-level values reach the audit trail only where a decision
  needs them, and connector findings are recorded as counts (`accepted`,
  `rejected`) rather than payloads.
* **The routine refusals of the credential-onboarding gate.** An account that owes
  a password change or a new second factor is refused on every route but the ones
  that complete the step, and that refusal is a structured log event
  (`credential_onboarding_required`, carrying `details.steps` and
  `details.path`) rather than an audit row. Two reasons: the state itself was
  already audited when an administrator created it — `user.password_reset` and
  `user.mfa.reset` carry `onboarding_required` in their details — and a row per
  refused request from a client that is merely following instructions is the kind
  of noise that makes an audit table stop being read. The *completion* is audited
  (`auth.password.changed`, `auth.mfa.enrolled`), which is what a timeline of "who
  was made to do what, and when did they" needs.
* **Nothing, for the one refusal that is a security signal.** The deployment's own
  requirement (`REQUIRE_MFA_FOR_ADMINS`) is refused by the same gate but *is*
  audited — `auth.mfa.required` on each refusal, with `details.reason` naming the
  policy. There the state is not something an administrator created and already
  recorded: it is an account that can create users, read the trail and change
  settings being used without a second factor, and nobody has to have written that
  fact down anywhere else.

`SECURITY.md` treats a leak of any of the above as in scope for a report.

## Self-monitoring signals

| Signal | Meaning |
|---|---|
| `GET /api/v1/health` | the API process is up; deliberately dependency-free |
| `GET /api/v1/ready` | PostgreSQL and Redis are reachable |
| `GET /api/v1/connectors/health` | connector liveness; `CONNECTOR_HEALTH_STALE_AFTER_SECONDS` (default 120) bounds silence. The `health` and `online` fields use the same UTC heartbeat threshold; stored naive timestamps are interpreted as UTC. |
| `docker compose ps` | container healthchecks: `backend`/`frontend` by HTTP, `celery-worker` and `celery-worker-alerts` by broker round trip, `celery-beat` and the connectors by liveness file, `backup` by dump age |
| `audit.retention.purged` with `truncated: true` | the sweep is not keeping up; raise `RETENTION_MAX_BATCHES_PER_RUN` or shorten retention |
| `GET /api/v1/audit/integrity` | where the chain stands: retained vs signed rows, `last_verified_seq`, `last_verified_at`, `retired_through_seq`. Admin-only, and a *status* read: the nightly task is what performs the pass, `make verify-audit-chain` is what performs one now |
| `GET /api/v1/metrics` | the same signals as numbers a scraper can alert on, plus this replica's request counters. Off (404) until `METRICS_TOKEN` is set — see [Metrics](#metrics) |

Alert-channel health probes are on-demand connectivity/credential checks, not proof
that a user notification was delivered. Disabled channels are not contacted and
return `last_checked_at: null`. SMTP checks use a fixed pool of four workers and
bound both admission wait and probe wait. Saturated admission returns `degraded`
(busy); a synchronous socket timeout returns `failed`, and its worker slot remains
occupied until the socket call exits. This keeps repeated requests from growing an
unbounded thread backlog.

The dashboard's `active_threats_7d` KPI counts active/investigating phishing and
breach findings created within the last seven days, excluding resolved findings.
Its 30-day timeline groups by UTC calendar date and fills dates with no findings.
Connector health treats stored naive timestamps as UTC and applies the configured
staleness threshold consistently to its `health` and `online` fields.

## Metrics

`GET /api/v1/metrics` answers Prometheus text exposition format
(`text/plain; version=0.0.4`). It is the endpoint an alert is written against;
the health endpoints above answer "is it up", and these answer "is it keeping
up", which is the question that goes unanswered until a person notices.

The endpoint is **off until you turn it on**. With `METRICS_TOKEN` empty it
answers `404` rather than `403`: an installation that scrapes nothing publishes
nothing about its backlog, its connectors or how far its audit chain has been
verified, and a `403` would still confirm the route exists. Set a random token in
`.env` (32 characters or more; production refuses anything shorter) and present
it as `X-Metrics-Token`, or as `Authorization: Bearer <token>` so Prometheus's own
`authorization` block works:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: opendrp
    metrics_path: /api/v1/metrics
    scrape_interval: 30s
    static_configs:
      - targets: ["127.0.0.1:8000"]   # the API's published address
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/opendrp-metrics-token
```

By hand, and what a runbook check looks like in a terminal:

```sh
curl -fsS -H "X-Metrics-Token: $METRICS_TOKEN" http://127.0.0.1:8000/api/v1/metrics
```

### What is exported

| Metric | Type | Meaning |
|---|---|---|
| `opendrp_build_info{version,environment}` | gauge | the running build; always `1` |
| `opendrp_process_start_time_seconds`, `opendrp_process_uptime_seconds` | gauge | how long this replica has been up |
| `opendrp_http_requests_in_flight` | gauge | requests being handled right now |
| `opendrp_http_requests_total{method,status_class}` | counter | requests handled, by method and `2xx`/`5xx` class |
| `opendrp_http_request_duration_seconds_sum{status_class}`, `..._count{status_class}` | counter | total and number of timed requests; the average is the first divided by the second |
| `opendrp_alert_deliveries{status}` | gauge | delivery rows by `pending`/`delivering`/`sent`/`failed`/`ambiguous`/`cancelled` |
| `opendrp_alert_deliveries_oldest_pending_seconds` | gauge | age of the oldest delivery still waiting |
| `opendrp_alert_recipients_held`, `opendrp_alert_recipient_hold_oldest_seconds` | gauge | recipients held after a delivery whose acceptance is unknown |
| `opendrp_connectors_enabled`, `opendrp_connectors_disabled` | gauge | connector registry state |
| `opendrp_connector_silence_seconds{connector}` | gauge | seconds since that connector last reported; `-1` means it never has |
| `opendrp_jobs{status}` | gauge | jobs by `pending`/`running`/`success`/`partial`/`error`/`cancelled`/`skipped` |
| `opendrp_jobs_oldest_running_seconds` | gauge | age of the oldest running job |
| `opendrp_audit_chain_retained_rows`, `opendrp_audit_chain_committed_seq`, `opendrp_audit_chain_retired_through_seq` | gauge | how much audit history is local, and how far it has been signed and retired |
| `opendrp_audit_chain_last_verified_seq`, `opendrp_audit_chain_last_verified_timestamp_seconds` | gauge | the last verification pass; `0` seconds means never |
| `opendrp_audit_chain_verification_failure_seq` | gauge | position of the last failed verification; `0` means none recorded |
| `opendrp_audit_persistence_degraded` | gauge | `1` while this replica refuses mutating traffic because an audit write failed |

The request counters are **per replica** and reset when it restarts, which is why
they are the only families here that do; a restart reads as a counter reset on a
dashboard, and `rate()` handles that. Every other value is read from the database
on each scrape, so all replicas report the same number. Labels come from the
platform's own enumerations and from connector *names* (a registered connector is
a bounded, reviewable set); no request value — an address, a finding title, a
path — ever becomes a label.

The families that can be absent are absent deliberately:
`opendrp_jobs_oldest_running_seconds` does not exist while nothing is running, and
neither does `opendrp_alert_deliveries_oldest_pending_seconds` when the queue is
empty. A rule written as `> 300` therefore stays quiet, where a `0` would have
been indistinguishable from "just queued".

### Thresholds worth alerting on

Stated with the shipped defaults; each one names what to look at next, because an
alert that does not is an alert that gets muted.

| Alert | Expression | What it means, and what to do |
|---|---|---|
| A delivery nobody can call | `opendrp_alert_deliveries{status="ambiguous"} > 0` for 15m | A send whose acceptance is unknown is holding that recipient. Reconcile it against the provider's log, then release the recipient from the alerts view (`docs/alerts-settings-operations.md`); the hold would otherwise end by itself after `ALERT_RECIPIENT_HOLD_SECONDS` |
| The queue is not draining | `opendrp_alert_deliveries_oldest_pending_seconds > 300` | `celery-worker-alerts` or `celery-beat` is not running: the scheduler is what enqueues the drain. `docker compose ps`, then that worker's logs |
| A recipient is held | `opendrp_alert_recipients_held > 0` | Notifications are not reaching that recipient. Same reconciliation as the row above |
| A connector went quiet | `opendrp_connector_silence_seconds > 2 * CONNECTOR_HEALTH_STALE_AFTER_SECONDS` (240s at the default 120) | That container is not reporting: restarts, credential or network. It is excluded from scans while silent, so the coverage gap is real |
| A job is stuck | `opendrp_jobs_oldest_running_seconds > 2 * CONNECTOR_JOB_LEASE_SECONDS` (360s at the default 180) | The lease should have been reclaimed; check `connectors/jobs` for the job and the worker's log. `opendrp_jobs{status="error"}` climbing alongside it says the retries are being exhausted |
| Scans are failing | `increase(opendrp_jobs{status="error"}[1h]) > 0` | A provider, a credential or a network path. The job summary names the provider's own error |
| The API is failing | `rate(opendrp_http_requests_total{status_class="5xx"}[5m]) > 0` | Correlate by `X-Request-ID` with the log stream; a `database_busy` body means the statement timeout, which `DB_STATEMENT_TIMEOUT_MS` bounds |
| Verification stopped | `time() - opendrp_audit_chain_last_verified_timestamp_seconds > 50h` | The nightly integrity task is not running (it runs every 24h). Run `make verify-audit-chain` and find out why the schedule stopped |
| The chain failed verification | `opendrp_audit_chain_verification_failure_seq > 0` | Treat as a security incident, not an operations one: read `audit.chain.broken` for `first_broken_seq` and `reason`, and compare that position against this SIEM index's copy of the stream before touching the database |
| Mutations are being refused | `opendrp_audit_persistence_degraded == 1` | This replica answered `503 audit_unavailable`: audit writes are failing, so it deliberately refuses changes it cannot record. Check database connectivity and the `audit.db_error` lines |

The audit-chain rows are the ones to write first. Everything else degrades the
platform's answers; a chain that stopped being verified is the platform's answers
becoming unverifiable.

## Suggested detections

| Rule | Logic |
|---|---|
| Credential stuffing | `auth.login.failure` > N per `source.ip` in 5 min |
| Lockout wave | `auth.login.locked` grouped by `user.id` |
| Session anomaly | `auth.refresh.failure` with `details.reason == "reuse_detected"` — the whole family was revoked, which is worth a look |
| Asset tampering | `asset.delete` and `user.deleted`, always alertable: these remove the evidence base |
| Config drift | `settings.update`, `connector.config.updated`, `connector.token.rotated/revoked` |
| Exfiltration by readers | `audit.log.view` or `report.download` volume from one `user.id` |
| Trail maintenance | `audit.retention.purged` outside the nightly window, or with an unexpected `deleted_rows` |
| Audit trail rewritten | `audit.chain.broken` — the highest-severity rule in this list. The verification task runs nightly and on demand; a pass that does not hold means stored audit rows no longer hash-chain. Read `details.first_broken_seq` and `details.reason`, then compare that position against this index's copy of the stream before touching the database |
| Verification stopped running | no `audit.chain.verified` for more than 25 h: the check is only worth as much as its schedule |
| Second factor bypassed | `auth.mfa.required` — an administrator without an enrolled factor was refused a route while `REQUIRE_MFA_FOR_ADMINS=true` (`details.reason == "require_mfa_for_admins"`). Since the policy became a step of the credential gate this fires on *any* route rather than on admin routes only, so a handful of rows around one login is the normal shape of an administrator who has just signed in and is being sent to the enrolment page; a sustained run of them is a client that is not the application, or one being driven past the page. Adjacent to the login that produced it, either way, this is the shape of a stolen admin password |
| A shared credential was replaced | `auth.password.changed` from an account whose login was recently preceded by a `user.password_reset`/`user.created` for the same `user.id`: the temporary password was used as intended. The same action with `details.was_required=false` is a voluntary change, and worth a glance if it follows a `auth.login.failure` burst — someone changing the password they just guessed |
| Guessing behind a live session | `auth.password.change_failed`: a valid access token that cannot produce the current password. One is a typo; several in a row from one `user.id` is a session that is not the owner's |
| An account was released from onboarding by hand | `manage_admin onboarding-off` is the escape hatch, and the CLI writes no audit row (it has no request context — the same is true of every `manage_admin` command). The host-side view is `manage_admin list`; the detectable shape is an account that keeps working while the `user.password_reset` that preceded it is followed by no `auth.password.changed` |
| Discovery turned inward | `outbound.blocked` grouped by `details.host`: a destination the platform refused. `settings.test_email_*`/`settings.test_telegram_*` from the same operator are the benign explanation; repeated attempts at loopback or `169.254.169.254` are not |
| Artifact row rewritten | `report.artifact.rejected` — a stored `file_path` that is not an artifact name. Nothing the platform writes looks like that |
