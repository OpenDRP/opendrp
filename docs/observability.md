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

Security-critical asset and user-account mutations commit together with the audit row that records them. On the user lifecycle, the required actions are `user.created`, `user.updated`, `user.password_reset`, `user.locked`/`user.unlocked`, `user.mfa.reset`, and `user.deleted`, with one `users.bulk` row for an activation change applied to a selection (plus `user.onboarding.cleared` when the release comes from `manage_admin` on the host, where there is no request to share a transaction with); the account/session state and the corresponding required audit rows share a transaction. The owner-facing notice that follows a reset, factor removal, deactivation or deletion is scheduled after that commit and is recorded separately as `user.notification.sent`/`.failed`/`.skipped` — it is deliberately not part of the mutation's transaction, because a mail server that is down must not undo a reset. User update details record safe before/after values for changed email, full name, role, rate limit, and active status, but never the supplied password, password hash, TOTP secret, or recovery codes. Asset create/update/delete and observation promotion are also fail-closed audit writes. If a required audit row cannot be written, the mutation is rolled back and the caller is told:

```json
{"detail": "The audit trail could not record this change, so it was not applied. Retry shortly.", "code": "audit_unavailable"}
```

The response is `503` with `Retry-After: 5`, which is worth alerting on for the
same reason `audit.chain.broken` is: it means the platform refused to act rather
than acting without evidence, and a sustained run of it means the audit sink (or
the transaction) is failing. Reads are unaffected — `asset.list` and `asset.view`
stay best-effort background writes, because a read is not a change to the evidence
base. The policy is per result set, not per request: `asset.list` is written on the
list's first page only, `asset.findings.list` on the first page of each module tab,
and `asset.view` once per opening of an asset's page (the card reads `GET
/assets/{id}` once; switching tabs asks a different question and does not re-read
the record). Scrolling a list or paging through a tab therefore does not grow the
chain, while each distinct read still leaves a row. Transactional audit stdout events are emitted only after the owning transaction commits; rollback discards the pending export as well. Authentication likewise does not return an access token or set refresh/CSRF cookies unless the refresh-family row has been durably saved. Session-family persistence failure rolls back and returns a retryable `503` with `Retry-After: 5`, without creating a client-side partial session. The login-success audit event is emitted after session issuance succeeds; it is not a substitute for the durable family row.

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

The one response that used to escape this is the unhandled 500. Starlette
renders it in `ServerErrorMiddleware`, above every middleware the application
installs, so it carried no `X-Request-ID` and its log line had no id — the one
response that *is* a bug report was the one nobody could look up. It is answered
by the correlation middleware instead: same status, same opaque
`Internal Server Error` body (so nothing a client parses changes), the id on the
response, and one structured line — `unhandled_exception` with `err` (the class)
and `frame` (`file:line` that raised). The message is *not* forwarded: a route may
raise with a value the platform was trusted to hold, and this line travels the
same JSON stream as the audit rows. The exception is re-raised after the response,
so the server still writes the full traceback to its own error log. The response
has no `Content-Security-Policy`/`X-Content-Type-Options`, which is deliberate:
the body is one fixed string served as `text/plain`, and the header policy keeps
one owner.

## The request pipeline, in order

`app/main.py` registers its middleware in the order a reader should follow a
request **outwards**: the last one added is the outermost, so reading the file
bottom-up walks a response back to the client.

| Layer | Owns | Why at this position |
|---|---|---|
| `RequestContextMiddleware` | the request id, the header that returns it, and the 500 for an unhandled exception | Outermost, so every line every other layer writes carries the id — including lines written on the way out of a failure |
| `MetricsMiddleware` | the per-replica request counters | Inside the context (a counted request already has an id) and outside CORS, so a cross-origin call the CORS layer refuses is still counted: it was work this replica did, and a spike of refused calls is worth seeing |
| `CORSMiddleware` | the browser contract | Outside the response-shaping layer, so it answers preflights before anything below it runs. A preflight carries no body, which is why the missing security headers below are harmless |
| `SecurityHeadersMiddleware` | CSP, `nosniff`, frame/referrer/permissions policy, HSTS, `Server` | Innermost, so it is the last place a response the application produced can be touched — every route response and every handled error passes through it |

## Rate-limit keys

All four limits keep their state in Redis and are listed here because an
operator investigating a lockout reads the keys, not the modules.

| Key | Subject | Bound |
|---|---|---|
| `rl:fails:<subject>`, `rl:lock:<subject>` | `email:<lowercased address>` and `ip:<resolved client>`, one counter each | 5 failures in 15 minutes, then a lock for the same window; a successful sign-in clears both (only when it is not itself locked out) |
| `rl:req:<user id>:<minute>`, `rl:reqnotify:<user id>:<minute>` | an authenticated account | `AUTHENTICATED_RATE_LIMIT_PER_MINUTE` (600) per fixed wall-clock minute; the notice key is claimed once per window so a blocked client writes one audit row, not one per retry |
| `rl:req:connector-ip:<address>:<minute>` | a source address on the connector protocol, **before** the token is resolved | 600 a minute, sized against twelve workers polling every five seconds (144) |
| `rl:manual:<user id>:<scope>` | one account's manual actions, per scope: a connector name, `reports`, `assets` | `users.rate_limit_minutes` between actions, a sliding window rather than a counter |

The `ip:` bucket is keyed on `extract_ip`, which returns the peer address and
only consults `X-Forwarded-For` when that peer is in `TRUSTED_PROXY_IPS`; it then
walks the chain from the hop nearest the platform and stops at the first address
it does not trust. A client therefore cannot choose its own bucket with a header
unless the deployment trusts the peer that header came from, which the startup
validator refuses for any range covering the data or connector networks.
Every limit fails open when Redis is unavailable, which is the trade-off
[security.md](security.md#accepted-risks-and-what-bounds-each-one) records, and
the nginx edge limits are the bound that does not depend on Redis.

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

The audit volume a scan produces is decided by its batches, not by how many rows
it found: one `connector.findings.ingested` row per delivered batch, carrying the
`job_id`, the batch's `batch_size`, its place in the scan (`batch_index` and
`batch_total` when the worker submitted a complete list), and the `accepted` /
`rejected` counts; then one `connector.scan.completed` or
`connector.scan.failed` row. A scan that delivers `n` findings in batches of 500
is therefore `ceil(n / 500) + 1` rows, and the figure is predictable before the
scan runs. Every `details` value is bounded at the audit boundary — 200-character
strings, 20-item lists, nesting depth 4, 64 keys and 8,000 serialized characters
for the whole tree — with `details_truncated` set when the total cap actually
dropped something, and the same bounds apply to a connector's own `summary` on
the completion route, so a half-trusted worker cannot decide the size of an audit
row.

What is stored is sanitised before it is bounded. Provider text reaches the trail
from three directions — a connector's own `error_code`, an operator's channel test,
a delivery failure — and each passes `app/core/safe_errors.py` first. The rules are
ordered and deterministic: an absolute URL keeps its host and path while
credential-named query parameters (`key`, `token`, `secret`, `password`,
`signature`) and Telegram bot tokens are masked; well-known key prefixes (`sk-`,
`ghp_`, `AIza`, `AKIA`, `xox…`) are masked wherever they appear, including inside a
JSON body; a `Bearer`/`Basic`/`Digest` value is replaced whole rather than leaving
the token behind the scheme word; a `label<separator>value` pair is masked quoted
or not; and a spaced label (`API key …`) is masked only when its value carries a
digit, so ordinary prose survives triage. A worked example:
`HTTP 403 Forbidden; body={"error":"invalid token","token":"eyJhbGciOiJIUzI1NiJ9.abc"}`
is stored as `HTTP 403 Forbidden; body={"error":"invalid token","token":"[REDACTED]"}`
— the diagnosis survives, the credential does not. The result is then capped
(`limit`) and stripped of control characters before it lands in
`connector.last_error`, a job's `error_message`, or `details.error`, so a provider
cannot use its own error text to inflate a row or to smuggle a key into the trail.

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

A second pass at 04:45 UTC (`rescore_phishing_candidates`) is not a sweep and keeps
nothing bounded: it recomputes each phishing candidate's stored `confidence` from the
signal rows behind it, because the weights are code and a release that changes one
leaves every existing row holding a number computed under the old table. It reports
how many scores moved and writes nothing when none did, so a quiet run is visible in
the task result rather than in the trail.

The purge row is written after the deletions commit, in its own session, because a
sweep that has already removed rows must not be rolled back by a failure to
describe them — and the deletion of audit rows is itself atomic with the
`retired_through_seq` watermark, so the *chain* can never show a gap. The residual
window is narrow and stated here rather than implied: if the worker dies between
the commit and that row, the retirement is still visible from the chain watermark
and `/audit/integrity`, but the single `audit.retention.purged` line a SIEM rule
keys on is absent for that sweep, and a retry finds nothing left to delete and
therefore writes nothing either. Read the watermark, not only the purge rows, when
the question is "what did retention remove on the night of the 14th".

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
| `GET /api/v1/connectors/health` | connector liveness; `CONNECTOR_HEALTH_STALE_AFTER_SECONDS` (default 120) bounds silence. `online` and the `degraded`/`unknown` health states use the same UTC heartbeat threshold; stored naive timestamps are interpreted as UTC. The two are not synonyms: `health` is the overall verdict and reports a provider error as `failed`, while `online` stays true if that worker still checks in — which is why the DNS page gates its Rescan on `online`, and the dashboard card prints `online` beside `last_seen_at`. The same response carries what the worker last declared about its provider credentials — `credentials_configured`, `credential_state` (`valid`/`invalid`/`unsupported`/`unknown`, a closed vocabulary) and `provider_error` (a fixed list) with `checked_at` — plus `last_success_at`/`last_success_age_seconds`, when collection last completed. The derived fields are served to every role; the raw `readiness` document is administrator-only |
| `docker compose ps` | container healthchecks: `backend`/`frontend` by HTTP, `celery-worker` and `celery-worker-alerts` by broker round trip, `celery-beat` and the connectors by liveness file, `backup` by dump age |
| `audit.retention.purged` with `truncated: true` | the sweep is not keeping up; raise `RETENTION_MAX_BATCHES_PER_RUN` or shorten retention |
| `report.generate.abandoned` | a report had been `generating` for twice the generation timeout with no worker behind it, so the sweep returned it to `failed`; `details.report_ids` names the first fifty. One is a killed worker or a lost message; a row of them means the report queue or the worker pool is being lost, and until they were repaired they counted against `REPORT_QUEUE_MAX_PENDING` |
| `GET /api/v1/audit/integrity` | where the chain stands: retained vs signed rows, `last_verified_seq`, `last_verified_at`, `retired_through_seq`. Admin-only, and a *status* read: the nightly task is what performs the pass, `make verify-audit-chain` is what performs one now |
| `GET /api/v1/metrics` | the same signals as numbers a scraper can alert on, plus this replica's request counters. Off (404) until `METRICS_TOKEN` is set — see [Metrics](#metrics) |

The same signals are on the dashboard. Its **Platform status** block is computed
inside the dashboard summary — `check_database`/`check_redis` directly, not an
HTTP call to `/ready` — so the first screen shows the dependency state,
`audit_degraded`, connector enabled/disabled/silent counts with the longest
silence, the age of the oldest running job and the delivery queue's counts,
without adding a request or a second `dashboard.view` audit row. A page that
needs three requests to be told the audit trail is failing is a page that tells
an operator too late.

The page loads that summary, connector health and channel health through one
request, `GET /api/v1/dashboard/overview`. The three sections are built by the
same functions the standalone endpoints call, and the load writes one
`dashboard.view` row whose `details.sections` lists `summary`, `connectors` and
`channels`. Before this, one glance cost three requests, three transactions and
three audit rows — and because the chain lock is `pg_advisory_xact_lock` taken by
the row's transaction, three lock acquisitions as well. One row in one
transaction is one acquisition. A probe the outbound policy refuses still adds its
own `outbound.blocked` row: that is a security event, not a view, and absorbing
it into the page's single row would hide it. `/dashboard/stats`,
`/connectors/health` and `/alerts/health` keep answering for their own callers
(the DNS page reads the second) and keep their own audit actions.

### What each dashboard number counts

Every tile and series is traced to the query that produces it, because a number
nobody traced is a number that can drift from the page an operator opens next to
it. `backend/app/api/v1/routers/dashboard.py` holds the summary;
`backend/app/services/dashboard_timeline.py` the chart.

| Value | Query | Predicate, and the page it has to agree with |
|---|---|---|
| `kpi.total_assets` | `count(drp_assets.id)` | `is_active` only — the tile is captioned *Active assets*. The inventory lists every asset unless `is_active` is given, so an unfiltered list is larger by exactly the deactivated ones |
| `kpi.total_phishing` | `count(drp_phishing_domains.id)` | every candidate, whatever its verdict or status — the same set `GET /phishing/threats` returns with no filter. The verdict is a separate field an analyst filters on, never a hidden default |
| `kpi.total_breaches` | `breach_kpi(...)['total_findings']` | the rule the generated report also reads (WI-16), so the two documents publish one definition |
| `kpi.active_threats_7d` | phishing `created_at >= now-7d` and `status in (active, investigating)` plus `breach_kpi['active_findings_7d']` | the phishing half uses the same `active`/`investigating`/`resolved` vocabulary the threats list filters on; the window is the tile's own question, not the list's |
| `kpi.new_breach_incidents_7d` | `breach_kpi['new_incidents_7d']` | the sources' own incident catalogue — what arrived upstream, not what matched an address of ours |
| `timeline` rows | `build_timeline` — one `UNION ALL` of per-module daily counts over `[start, next midnight)` | a module's own table for a native adapter, `drp_findings` filtered by module id for the generic one. A module that stores current state is named in `timeline_excluded` with a reason instead of contributing a silent zero |
| `timeline_comparison` | the same series over the 30 days before the window, as one total per module | answered by a second aggregate, never by a third pass over the rows |
| `phishing_by_source` | `group by detection_source` over all candidates | a null source reads as `unknown`; the breakdown is over the same set as `total_phishing` |
| `assets_by_criticality` | `group by criticality` over active assets | null reads as `medium`; the card is captioned *Active assets*, matching the tile above |
| `platform.connectors.silent` | enabled connectors whose `last_seen_at` is older than `CONNECTOR_HEALTH_STALE_AFTER_SECONDS`, or that never checked in | the same threshold `/connectors/health` uses, read from one function |
| `platform.deliveries` | `AlertDeliveryService.channel_delivery_summary` | the function `/alerts/health` calls, so the queue counts and the stuck count cannot disagree with that page |
| `platform.oldest_running_job_seconds` | `min(jobs.created_at) where status = running` | absent (`null`) when nothing is running — not `0`, which would read as "just started" |

The connector card carries three answers that are not interchangeable.
`last_seen_at`/`online` say the worker is alive; `health` is the overall verdict,
where a prior provider error reads `failed` even while the worker is online; and
`last_success_at` says collection last completed. A worker that has never
finished a scan is therefore alive, possibly healthy, and never successful —
the card prints all three instead of letting one green badge stand for them.
Readiness is the source's own report: the state and error code are a closed
vocabulary published to every role, while the raw `readiness` document
(`capabilities`, `operations`, the provider's data-class labels) and the raw
`last_error` stay administrator-only.

Alert-channel health probes are connectivity/credential checks, not proof that a
user notification was delivered. A result is reused for
`ALERT_HEALTH_CACHE_SECONDS` (default 60; `0` disables the cache), under a Redis
key that carries a hash of that channel's settings — changing the SMTP host or the
bot token therefore asks a new question instead of reading the old answer. The
first request inside the TTL takes a `SET NX` lock and probes; the rest wait for
its result, so a burst of dashboard loads is one handshake rather than one per
operator. `checked_at` is when the probe ran (not when the response was built),
and `from_cache` says the answer came from that earlier probe. Redis being
unreachable, or an unreadable entry, falls back to probing now with
`from_cache: false`: the cache is never a new failure mode.

Disabled channels are not contacted: `checked_at` is null and `probe_state` is
`skipped`. SMTP checks use a fixed pool of four workers and bound both admission
wait and probe wait. Saturated admission reports `probe_state: "saturated"` with
`health: "unknown"`, because no observation of the channel was made; a synchronous
socket timeout reports `probe_state: "timeout"` with `health: "failed"`, and its
worker slot remains occupied until the socket call exits. This keeps repeated
requests from growing an unbounded thread backlog. The reading transaction ends
before a probe starts, so a blocked handshake does not pin a pooled database
connection.

Delivery health is reported beside the probe rather than inferred from it. Each
channel in `GET /api/v1/alerts/health` carries `delivery`: counts by status,
`retrying` (pending or failed rows waiting out a retry window), the oldest
unresolved delivery and its age, and `stuck` — ambiguous or failed deliveries
older than `ALERT_RECIPIENT_HOLD_SECONDS`. A channel with such a row
is `degraded` even when its probe is `healthy`, because the queue has stopped
being able to resolve that delivery by itself; a `failed` probe remains the more
severe answer and the queue counters are still shown. `delivery_queue` counts the
recipients whose next send is in the future — an ambiguous hold or an ordinary
retry window — once for the installation, because the hold key is a digest of
channel and target and cannot be attributed back to one channel. A live lease is
a send in progress, not a wait. The aggregate carries numbers only: no target,
batch id or recipient digest leaves the endpoint, so the same response is safe
for every role.

The dashboard's `active_threats_7d` KPI counts active/investigating phishing and
breach findings created within the last seven days, excluding resolved findings.
It answers "how much exposure do we have", and a finding can only exist for an address
or domain somebody put in the inventory. `new_breach_incidents_7d` answers the other
question — "is there new trouble out there" — from the sources' own incident catalogues
(`breach_catalogue`, synced by the breach workers): it counts the incidents a source
added to its catalogue in the same window, whether or not any monitored address is in
them, and it is why a week in which no scan met a new address no longer reads as a week
with no new incidents. Both numbers come from one rule (`app/services/breach_kpi.py`)
that the dashboard and the generated report call — which also splits the findings total by
class of exposure (`findings_by_exposure_kind`, summing to the total it splits) — and each
number travels with a caption naming what it counts; the report prints the same captions beside the same figures, so
the PDF and the page cannot explain one number two ways. An incident whose source
published no `added_date` is counted in `undated_incidents` instead of in the window,
and the report says how many of those there are whenever the number is not zero.
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
path — ever becomes a label. `method` is an enumeration too: the platform's own
verbs (`GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`) and one `OTHER`
bucket, because an HTTP method is a token the caller chooses and a request with an
invented one still passes through the middleware. `opendrp_http_requests_in_flight`
includes the scrape that is rendering it, so a single-scraper installation reads
`1`, not `0`.

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
| A delivery nobody can call | `opendrp_alert_deliveries{status="ambiguous"} > 0` for 15m | A send whose acceptance is unknown is holding that recipient. Reconcile it against the provider's log, then release the recipient with `POST /api/v1/alerts/recipients/{key}/release` ([README.md](../README.md#alerts-settings-and-retention) is the operator's view of that queue); the hold would otherwise end by itself after `ALERT_RECIPIENT_HOLD_SECONDS` |
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
| Config drift | `settings.update`, `connector.config.updated`, `connector.token.rotated/revoked`. A `settings.update` row carries `details.changes` — each field that really changed with `from` and `to` — and `updated_fields`, which is the sorted key list of that map, not the submitted form; a credential reads `set`/`unset` instead of a value. `module.updated` carries the same `changes` map for a rename, a redescription and an enable/disable |
| Exfiltration by readers | `audit.log.view` or `report.download` volume from one `user.id` |
| Trail maintenance | `audit.retention.purged` outside the nightly window, or with an unexpected `deleted_rows` |
| Audit trail rewritten | `audit.chain.broken` — the highest-severity rule in this list. The verification task runs nightly and on demand; a pass that does not hold means stored audit rows no longer hash-chain. Read `details.first_broken_seq` and `details.reason`, then compare that position against this index's copy of the stream before touching the database |
| Verification stopped running | no `audit.chain.verified` for more than 25 h: the check is only worth as much as its schedule |
| A role was asked for and refused | `authz.denied` — an authenticated account reached a route its role does not hold. `details.required` names the capability, `details.role` the account's role, `details.path`/`details.method` the route. It is written **once per account, method and route per five-minute window**, so a script looping on a `403` is one row rather than a flood: count distinct `details.path` values, not rows. A second factor refused by policy is still `auth.mfa.required` rather than this action |
| Second factor bypassed | `auth.mfa.required` — an account whose role the deployment requires a factor from was refused a route while it had none enrolled (`REQUIRE_MFA_ROLES`, or `REQUIRE_MFA_FOR_ADMINS` for administrators; `details.reason == "require_mfa"`). Since the policy became a step of the credential gate this fires on *any* route rather than on admin routes only, so a handful of rows around one login is the normal shape of an administrator who has just signed in and is being sent to the enrolment page; a sustained run of them is a client that is not the application, or one being driven past the page. Adjacent to the login that produced it, either way, this is the shape of a stolen admin password |
| A shared credential was replaced | `auth.password.changed` from an account whose login was recently preceded by a `user.password_reset`/`user.created` for the same `user.id`: the temporary password was used as intended. The same action with `details.was_required=false` is a voluntary change, and worth a glance if it follows a `auth.login.failure` burst — someone changing the password they just guessed |
| Guessing behind a live session | `auth.password.change_failed`: a valid access token that cannot produce the current password. One is a typo; several in a row from one `user.id` is a session that is not the owner's |
| The user table left the platform | `users.export` — an administrator downloaded the account list, in the format and with the filter named in `details`. The file contains roles, activity, sign-in times and onboarding state, by design no credentials; a person preparing an access review is the benign explanation, and a download outside that cycle is worth asking about |
| An administrator inspected another account | `users.view` — the actor is `user_id`, the account looked at is `details.target_user_id`, and `details.view` names which surface (`sessions` for the live-session list). One row per look, like the page view it is: the shape to read is a burst across many targets, or one outside support hours — which is an account harvest rather than a support call |
| Many accounts changed at once | `users.bulk` — one row for one decision (`details.operation`, `details.target_user_ids`, `details.changed`, `details.refresh_families_revoked`). A large `deactivate` batch is an off-boarding; the same action outside a known joiner/mover/leaver window, or followed by a new account with elevated access, is the shape worth reading |
| A session was ended by an administrator | `user.sessions.revoked` — `details.target_user_id` names the account whose sessions were signed out and `details.revoked_count` how many. Distinct from `auth.sessions.revoked_others`, which the account does to itself; this one is somebody else's decision about that account |
| The owner was not told their account changed | `user.notification.failed` or `user.notification.skipped` following `user.password_reset`, `user.mfa.reset`, `user.locked` (`is_active=false`) or `user.deleted` for the same `details.target_user_id`. `details.event` names which change (`password_reset`, `mfa_reset`, `deactivated`, `deleted`); `details.reason` is `smtp_not_configured`, `celery_unavailable`, or a sanitized transport error. `.failed` and `.skipped` are the readable half of a real risk: an administrator can change an account and the owner learns nothing, which is the same observation a person would make if their access stopped working. Group by `details.reason` to tell a deployment that has no SMTP from one whose mail server rejects the sender. The message itself never carries a password, hash, TOTP secret or recovery code; a row whose `details` does is a defect, not a configuration |
| An account was released from onboarding by hand | `user.onboarding.cleared` — `manage_admin onboarding-off` is the escape hatch, and every `manage_admin` command now writes its row. The row has `details.source == "cli"`, `details.actor` naming the operating-system user that ran it, and `details.target_user_id`/`details.target_email` naming the account; `user_id` is null because a host operator is not a platform account, so a rule that reads the trail by `user.id` will not see it — filter on the action, not on the actor column. `details.was_change_pw`/`details.was_enrol_mfa` say what was actually cleared, and a cleared password means the shared secret stays in force, so the shape to watch is this row followed by no `auth.password.changed` for the same account |
| Discovery turned inward | `outbound.blocked` grouped by `details.host`: a destination the platform refused. `settings.test_email_*`/`settings.test_telegram_*` from the same operator are the benign explanation; repeated attempts at loopback or `169.254.169.254` are not |
| Artifact row rewritten | `report.artifact.rejected` — a stored `file_path` that is not an artifact name. Nothing the platform writes looks like that |
