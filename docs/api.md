# API reference

This is the operator-facing route inventory: every endpoint the platform exposes
to a browser session, a script or an administrator. It is a reference, not a
tutorial — for how the pieces fit together, see [description.md](description.md),
and for the operator's view of them, [deployment.md](deployment.md).

All application endpoints use Bearer authentication unless marked public.
`viewer+` includes all three roles; `analyst+` includes `admin` and `analyst`;
administrator endpoints require `admin`.

The machine-readable schema is the application's own OpenAPI document, served at
`/api/openapi.json` with a browsable UI at `/api/docs`. Both are available only
outside production (`APP_ENV != production`), where the schema is switched off on
purpose: a production installation does not advertise its own surface. A
production deployment therefore reads the schema from a non-production build of
the same version, or from the source. Where this page and the running schema
disagree, the schema is authoritative: it is generated from the code, and this
page is maintained by hand.

## Public and authentication

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
| `GET` | `/api/v1/auth/mfa/qr` | Authenticated — render the pending enrolment as an SVG QR code |
| `POST` | `/api/v1/auth/mfa/enable` | Authenticated — verify and activate TOTP |
| `POST` | `/api/v1/auth/mfa/disable` | Authenticated — verify and deactivate TOTP |
| `POST` | `/api/v1/auth/mfa/recovery-codes/rotate` | Authenticated — replace recovery codes with password and TOTP |
| `GET` | `/api/v1/auth/sessions` | Authenticated — list own usable sessions (a signed-out one is an audit event, not a session) without token material |
| `DELETE` | `/api/v1/auth/sessions/{family_id}` | Authenticated — revoke one own session |
| `POST` | `/api/v1/auth/sessions/revoke-others` | Authenticated — revoke all other own sessions |
| `GET` | `/api/v1/auth/security-activity` | Authenticated — recent security events for own account |

`GET /api/v1/auth/mfa/qr` answers with an image rather than JSON, and with `409`
until an enrolment is pending: the pending `otpauth://` URI is rendered as an SVG
so that it never travels through a JSON response body, where a proxy log or a
browser extension would be more likely to keep it.

## Core application routes

| Method | Route | Access |
|---|---|---|
| `GET` | `/api/v1/dashboard/stats` | viewer+ |
| `GET`, `POST` | `/api/v1/assets` | viewer+ / analyst+ — the list carries each row's involvement (`findings`) and accepts `has_findings` |
| `GET`, `PATCH`, `DELETE` | `/api/v1/assets/{asset_id}` | viewer+ / analyst+ / admin |
| `GET` | `/api/v1/assets/{asset_id}/findings` | viewer+ — per-module counters, when each module last saw the asset, and the paged rows behind them |
| `GET` | `/api/v1/assets/export` | viewer+ — the current filter as CSV or JSON |
| `POST` | `/api/v1/assets/import`, `/api/v1/assets/import/csv` | analyst+ — per-line report, `dry_run` preview |
| `POST` | `/api/v1/assets/bulk` | analyst+ (`delete` is admin) |
| `GET` | `/api/v1/phishing/threats` | viewer+ |
| `GET` | `/api/v1/phishing/threats/{threat_id}` | viewer+ |
| `PATCH`, `DELETE` | `/api/v1/phishing/threats/{threat_id}` | analyst+ |
| `POST` | `/api/v1/phishing/threats/cleanup-orphans` | admin |
| `POST` | `/api/v1/phishing/scan/dnstwist`, `/api/v1/phishing/scan/shodan` | analyst+ |
| `GET` | `/api/v1/dns/observations` | viewer+ — paginated source observations |
| `POST` | `/api/v1/dns/scan` | analyst+ — queues online enabled DNS sources; HTTP 409 when none can start |
| `DELETE` | `/api/v1/dns/observations/{observation_id}` | analyst+ — remove an observation (resolver RRsets accept `?value=` to remove one member) |
| `POST` | `/api/v1/dns/observations/{observation_id}/asset` | analyst+ — promote a concrete observed hostname/IP |
| `POST` | `/api/v1/dns/observations/cleanup-orphans` | admin |
| `GET` | `/api/v1/breaches` | viewer+ |
| `GET` | `/api/v1/breaches/{breach_id}` | viewer+ |
| `PATCH`, `DELETE` | `/api/v1/breaches/{breach_id}` | analyst+ |
| `POST` | `/api/v1/breaches/cleanup-orphans` | admin |
| `POST` | `/api/v1/modules/{module_id}/scan` | analyst+ — independently admits ready provider sources for a module |
| `GET` | `/api/v1/exposure/observations` | viewer+ — paginated inventory |
| `PATCH` | `/api/v1/exposure/observations/{observation_id}` | analyst+ — triage status |
| `POST` | `/api/v1/exposure/observations/{observation_id}/asset` | analyst+ — promote observed hostname/IP |
| `GET` | `/api/v1/phishing/threats/{candidate_id}/evidence` | viewer+ — source evidence, max 200 rows |
| `POST` | `/api/v1/breaches/scan` | analyst+ — queues the enabled breach connectors |
| `POST` | `/api/v1/breaches/scan-email`, `/api/v1/breaches/scan-domain` | analyst+ — manual single-target rescan |
| `GET` | `/api/v1/modules` | viewer+ — declared modules and their schemas |
| `POST` | `/api/v1/modules` | admin |
| `PATCH` | `/api/v1/modules/{module_id}` | admin |
| `GET` | `/api/v1/findings` | viewer+ — findings of declared modules |
| `PATCH` | `/api/v1/findings/{finding_id}` | analyst+ — triage status |
| `POST` | `/api/v1/reports/generate` | viewer+ |
| `GET` | `/api/v1/reports` | viewer+ |
| `GET` | `/api/v1/reports/{report_id}/download` | viewer+ |
| `DELETE` | `/api/v1/reports/{report_id}` | admin |
| `GET` | `/api/v1/alerts/health` | viewer+ — email and Telegram channel probes |
| `GET` | `/api/v1/alerts/queue` | admin — alert delivery queue counters and the 50 most recent deliveries |
| `GET` | `/api/v1/alerts/recipients` | admin — recipients the queue is holding back, and the reason for each |
| `POST` | `/api/v1/alerts/recipients/{key}/release` | admin — end a recipient's hold early; the decision is audited |
| `GET` | `/api/v1/connectors/health`, `/api/v1/connectors/modules` | viewer+ |
| `GET` | `/api/v1/jobs` | viewer+ |
| `GET` | `/api/v1/jobs/{job_id}` | viewer+ — one job's outcome, capabilities and result payload |
| `DELETE` | `/api/v1/jobs/{job_id}` | admin |

The DNS Security routes moved to `/api/v1/dns` when the module was renamed from
`dns_security`. The previous prefix still answers — a connector or script written
against it keeps working — but it is kept out of the OpenAPI document, so only the
`dns` spelling is advertised and there is one route to maintain.

`GET /api/v1/alerts/queue` is the operator's view of the durable delivery queue:
per-status counters plus the 50 newest rows, each carrying its batch, job,
channel, attempt count, acknowledged parts, last error and next attempt time. It
is administrator-only: delivery rows expose how the alerting configuration
behaves, including the failure text of the last provider refusal.

`GET /api/v1/alerts/recipients` is the other half of that view: a send whose
outcome nobody knows — a worker died mid-send, or an SMTP thread timed out after
the provider may already have accepted the message — holds its recipient for
`ALERT_RECIPIENT_HOLD_SECONDS` rather than risking a duplicate, and this route
lists the recipients held for that reason separately from the ones a worker is
sending to right now. `POST /api/v1/alerts/recipients/{key}/release` ends a hold
early for an operator who has reconciled the send with the recipient; the
requeued deliveries keep their rendered parts and acknowledgement count, and the
action is written to the audit trail under `alerts.recipient.released`. A hold
needs no operator: when the window passes, the deliveries go back in the queue,
because the uncertain send has finished either way by then.

## Administration routes

| Method | Route | Access |
|---|---|---|
| `GET`, `PUT` | `/api/v1/settings` | admin |
| `GET` | `/api/v1/settings/runtime` | admin — the applied container configuration, without secrets |
| `POST` | `/api/v1/settings/validate-telegram` | admin — check a Telegram `chat_id` against the configured bot |
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
| `GET` | `/api/v1/metrics` | scrape token — `X-Metrics-Token`, and 404 when `METRICS_TOKEN` is unset |
| `GET`, `POST` | `/api/v1/connectors/accounts` | admin — list/create non-secret provider account identities |
| `PATCH` | `/api/v1/connectors/accounts/{account_id}/policy` | admin — approve and set shared budgets |
| `PUT`, `DELETE` | `/api/v1/connectors/accounts/{account_id}/api-key` | admin — store or clear the provider key bound to that account (encrypted with `ENCRYPTION_KEY`, never returned — only a masked hint) |
| `PATCH` | `/api/v1/connectors/{connector_id}/account` | admin — assign a provider connector to its account |
| `GET` | `/api/v1/connectors` | admin |
| `GET` | `/api/v1/connectors/jobs` | admin |
| `PATCH` | `/api/v1/connectors/{connector_id}/status` | admin |
| `PATCH` | `/api/v1/connectors/{connector_id}/config` | admin |
| `POST` | `/api/v1/connectors/provision` | admin |
| `POST` | `/api/v1/connectors/{connector_id}/token` | admin |
| `DELETE` | `/api/v1/connectors/{connector_id}/token` | admin |

`GET /api/v1/metrics` is the one route here that no user session reaches: it
authenticates with the shared `METRICS_TOKEN` in `X-Metrics-Token`, because a
Prometheus scraper has no session to present. It renders Prometheus text
exposition format, and it answers `404` — not `403` — while the token is unset,
so an installation that scrapes nothing does not publish its backlog sizes,
connector names or audit position at all. [observability.md](observability.md)
lists the metrics, the thresholds worth alerting on and a scrape configuration.

Two of these exist for the case where the UI is not enough: `GET
/api/v1/settings/runtime` answers "did the recreated container receive the
configuration I changed?" (it reports `APP_ENV`, the version, the database pool,
the statement/command timeouts and which file the resource limits come from —
never a secret or a raw connection URL), and `POST
/api/v1/settings/validate-telegram` checks a `chat_id` against the configured bot
before an alert depends on that recipient.

## Connector-facing routes

The connector protocol is a separate interface with its own credential: these
routes authenticate with the connector's **own** `X-Connector-Token`, never a user
JWT and never a shared secret, and the optional `X-Connector-Name` header is only
checked for agreement with that credential. They are not part of the operator
surface above, so they are documented where a connector author will look for them:
[connectors/README.md](../connectors/README.md#the-connector-facing-api).

## See also

- [configuration.md](configuration.md) — the deployment settings, resource limits
  and database connection budget behind these endpoints.
- [security.md](security.md) — authentication, auditing and the controls that
  bound each endpoint.
- [observability.md](observability.md) — what to watch while these routes run.
