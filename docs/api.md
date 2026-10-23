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

List endpoints are paginated the same way: `page` counted from 1 and `size`, which
may not exceed 200 rows. A larger `size` is refused with `422` instead of being
clamped, so a client that asks for more than the platform serves learns it from
the answer rather than from a short page that looks like the end of the list.

## Public and authentication

| Method | Route | Access |
|---|---|---|
| `GET` | `/api/v1/health` | Public — liveness, no dependencies |
| `GET` | `/api/v1/ready` | Public — readiness, checks PostgreSQL and Redis |
| `POST` | `/api/v1/auth/login` | Public |
| `POST` | `/api/v1/auth/accept-invitation` | Public — spends a single-use invitation token and sets the owner's password; unknown and expired tokens answer the same way |
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
| `GET` | `/api/v1/dashboard/stats` | viewer+ — KPI counters; the breach half travels in `kpi.breach` (findings versus incidents, the window each counts over, and the caption for each number) beside the flat keys, from the same rule the report uses. An additive `platform` block carries self-diagnostics: `database`/`redis` from the same probes `/ready` calls, `audit_degraded`, connector `enabled`/`disabled`/`silent` counts with the longest silence, `oldest_running_job_seconds`, and delivery `counts`/`stuck`/`waiting_recipients` (numbers only). It is computed inside this request, so the dashboard's Platform status block costs no extra call. The page itself reads `/dashboard/overview`; this route remains for callers that want the summary alone. `timeline` is 30 UTC-day buckets whose series come from the module registry: `timeline_series` lists every counted module (`key` — the module id and the row's field, `label`, `module_id`), `timeline_excluded` lists modules left out with a reason code (`current_state_observations` for DNS Security and Exposure, whose storage holds the present state of an asset rather than dated findings; `unsupported_storage` for an adapter this core cannot count), and `timeline_comparison` gives each counted series its totals for this window (`current`) and the 30 days before it (`previous`). Modules stored through the generic adapter are counted from `drp_findings` by module id, so declaring a module changes the row without a core or frontend release. A module is never both counted and excluded |
| `GET` | `/api/v1/dashboard/overview` | viewer+ — the whole first screen in one request and one audit row. `summary` is the `/dashboard/stats` payload (KPI with `kpi.breach`, 30-day timeline, both breakdowns and `platform`), `connectors` is the `/connectors/health` envelope and `channels` is the `/alerts/health` envelope, plus a top-level `generated_at`. The sections are produced by the same functions those endpoints call, so the three cannot publish different numbers for the same moment. The one `dashboard.view` row names them in `details.sections` (`summary`, `connectors`, `channels`); a load used to be three requests, three transactions and three rows, and since the audit chain lock is transactional, three acquisitions of it. A probe the outbound policy refuses still writes its own `outbound.blocked` row on this path — a security event is not absorbed into a view |
| `GET` | `/api/v1/assets` | viewer+ — the list carries each row's involvement (`findings`) and accepts `has_findings`; `sort` is an allowlist of six fields (`created_at`, `updated_at`, `asset_value`, `asset_type`, `criticality`, `is_active`) with `order=asc\|desc`, and a `has_findings` list is bounded by a 40-second server deadline (`503` with `code=query_deadline_exceeded` tells the caller to narrow the filter) |
| `POST` | `/api/v1/assets` | analyst+ — add one monitored asset; the audit row is `asset.create` |
| `GET` | `/api/v1/assets/{asset_id}` | viewer+ — one asset with its attributes and monitoring state |
| `PATCH` | `/api/v1/assets/{asset_id}` | analyst+ — update the asset and its monitoring fields |
| `DELETE` | `/api/v1/assets/{asset_id}` | admin — remove the asset from the inventory |
| `GET` | `/api/v1/assets/{asset_id}/findings` | viewer+ — per-module counters, when each module last saw the asset, and the paged rows behind them |
| `GET` | `/api/v1/assets/export` | viewer+ — the current filter as CSV or JSON, with the same `findings` counters and `last_seen` a list row carries; refused past 10,000 rows rather than rendered into one response |
| `POST` | `/api/v1/assets/import`, `/api/v1/assets/import/csv` | analyst+ — per-line report, `dry_run` preview |
| `POST` | `/api/v1/assets/bulk` | analyst+ (`delete` is admin) — one transaction and one summary audit row over at most 500 ids; the inventory page drives it from row selection, so activate, deactivate and criticality do not require one request per asset |
| `GET` | `/api/v1/phishing/threats` | viewer+ — each row carries the computed `domain_age_days`, the scored `confidence` with the `signals` that produced it, and the `alert_band` that score falls in (`direct`, `digest` or `list`, from the deployment's own thresholds). `sort=created_at`, `sort=age` or `sort=confidence` with `order=asc\|desc` ranks the list (an unresolved registration sorts last, never as the youngest); `?min_confidence=` keeps candidates at or above a score and `?signal=` keeps those with a fired signal of that name (a fact the platform looked at and did not match does not count) |
| `GET` | `/api/v1/phishing/threats/{threat_id}` | viewer+ |
| `PATCH`, `DELETE` | `/api/v1/phishing/threats/{threat_id}` | analyst+ — `PATCH` also records the analyst's verdict: `{"verdict": "confirmed"}` alerts on the candidate whatever it scores, `{"verdict": "rejected", "verdict_reason": "..."}` silences the channel (digest included) and **requires** the reason, and `{"verdict": null}` takes the decision back. Every decision is one audit row (`phishing.threat.verdict`) naming the verdict it replaced |
| `POST` | `/api/v1/phishing/threats/{threat_id}/asset` | analyst+ — take the candidate's own domain under monitoring; answers `already_exists` for a value already in the inventory and writes `phishing.asset.promoted` or `phishing.asset.already_exists` |
| `POST` | `/api/v1/phishing/threats/cleanup-orphans` | admin |
| `POST` | `/api/v1/phishing/scan/dnstwist`, `/api/v1/phishing/scan/shodan` | analyst+ |
| `GET` | `/api/v1/dns/observations` | viewer+ — paginated source observations |
| `POST` | `/api/v1/dns/scan` | analyst+ — queues online enabled DNS sources; HTTP 409 when none can start |
| `DELETE` | `/api/v1/dns/observations/{observation_id}` | analyst+ — remove an observation (resolver RRsets accept `?value=` to remove one member) |
| `POST` | `/api/v1/dns/observations/{observation_id}/asset` | analyst+ — promote a concrete observed hostname/IP |
| `POST` | `/api/v1/dns/observations/cleanup-orphans` | admin |
| `GET` | `/api/v1/dns/certificates` | viewer+ — certificate identities with the places each was observed (`?verdict=`, `?foreign_only=`) |
| `PATCH` | `/api/v1/dns/certificates/sightings/{sighting_id}` | analyst+ — record the review verdict for one sighting; the verdict suppresses the rule |
| `GET` | `/api/v1/dns/certificate-exceptions` | viewer+ — scope exceptions the certificate rules honour |
| `POST` | `/api/v1/dns/certificate-exceptions` | admin — allow one fingerprint, key, address, ASN or issuer out of scope |
| `DELETE` | `/api/v1/dns/certificate-exceptions/{exception_id}` | admin |
| `GET` | `/api/v1/breaches` | viewer+ — `?new_since_last_scan=true` keeps what the most recent finished breach scan turned up (the response reports the instant as `new_since`, or `null` when no scan has finished, in which case nothing is filtered out); `?exposure_kind=breach\|paste\|stealer_log` keeps one class of exposure — the closed set ingestion stores, so any other value is a `422` — and each item carries its own class; `?severity=critical\|high\|medium\|low\|unknown` filters on the severity the core derived from the exposed data classes (`unknown` means the platform does not recognize them, not that they are harmless), `?flag=verified\|spam\|fabricated\|sensitive` on the source's own flags, `?status=active\|investigating\|resolved` on the operator's triage state, `?source=` on the reporting source and `?domain=` on the vendor domain or an address at it; `?sort=created_at\|breach_date\|pwn_count\|severity` with `?order=asc\|desc` (severity is ordered by rank, loudest first) — any other value is a `422`; each item carries `severity` and, when it names an address, `email_incident_count`, how many incidents the platform holds about that address across all filters; every response also reports `unannounced`, the findings that have arrived and no alert channel has delivered yet |
| `GET` | `/api/v1/breaches/provider-readiness` | viewer+ — what the most recent finished breach scan was allowed to ask: per domain `asked` / `unscanned` (with the provider's reason) / `unknown` (the scan stopped before reaching it), the account's entitlements and pace, the scan's own `partial` verdict with its reasons, and the source's own `data_class_labels` (F-04); `connector` names the source that scan ran on, and `verifications` holds the newest verification attempt per domain — `generated` with the TXT value to publish, `verified`, `not_verified` (the record is not visible yet) or `failed` with the reason |
| `GET` | `/api/v1/breaches/{breach_id}` | viewer+ |
| `PATCH`, `DELETE` | `/api/v1/breaches/{breach_id}` | analyst+ |
| `POST` | `/api/v1/breaches/{breach_id}/asset` | analyst+ — take the exposed mailbox (or, when the source named none, the affected domain) under monitoring; answers `already_exists` for a value already in the inventory and writes `breaches.asset.promoted` or `breaches.asset.already_exists` |
| `POST` | `/api/v1/breaches/cleanup-orphans` | admin |
| `POST` | `/api/v1/modules/{module_id}/scan` | analyst+ — independently admits ready provider sources for a module |
| `GET` | `/api/v1/exposure/observations` | viewer+ — paginated inventory |
| `PATCH` | `/api/v1/exposure/observations/{observation_id}` | analyst+ — triage status |
| `POST` | `/api/v1/exposure/observations/{observation_id}/asset` | analyst+ — promote observed hostname/IP |
| `GET` | `/api/v1/phishing/threats/{candidate_id}/evidence` | viewer+ — source evidence, max 200 rows; each row carries `fields`, the allowlisted payload facts (`capability`, `verdict`, registrar/created, mail facts), beside the raw `payload` |
| `POST` | `/api/v1/breaches/scan` | analyst+ — queues the enabled breach connectors |
| `POST` | `/api/v1/breaches/scan-email`, `/api/v1/breaches/scan-domain` | analyst+ — manual single-target rescan |
| `POST` | `/api/v1/breaches/domain-verification` | analyst+ — `{"domain": "<fqdn>", "action": "generate"\|"verify", "connector": "<name>"}` (the connector is optional while one source is enabled, required when several are): queues one verification step on that source — `generate` returns the TXT value to publish, `verify` checks it — audited as `breach.domain_verification.requested` whether or not it could be queued, and reported back beside the domains in `provider-readiness.verifications` |
| `GET` | `/api/v1/modules` | viewer+ — declared modules and their schemas |
| `POST` | `/api/v1/modules` | admin |
| `PATCH` | `/api/v1/modules/{module_id}` | admin — rename, redescribe or enable/disable. Disabling cancels queued jobs and denies new scans; findings already stored stay readable through `/findings` and the dashboard timeline, because a disable stops collection, not the record. The `module.updated` row carries `changes` with both ends of each transition |
| `GET` | `/api/v1/findings` | viewer+ — findings of declared modules, including modules since disabled |
| `PATCH` | `/api/v1/findings/{finding_id}` | analyst+ — triage status |
| `POST` | `/api/v1/reports/generate` | viewer+ |
| `GET` | `/api/v1/reports` | viewer+ |
| `GET` | `/api/v1/reports/{report_id}/download` | viewer+ |
| `DELETE` | `/api/v1/reports/{report_id}` | admin |
| `GET` | `/api/v1/alerts/health` | viewer+ — email and Telegram channel probes; each channel carries `enabled`, `configured`, the probe's `health`/`message`/`latency_ms`, `probe_state` (`ok`, `saturated`, `timeout` or `skipped`) and `checked_at`/`from_cache` — when the probe ran and whether this answer is a cached one (`ALERT_HEALTH_CACHE_SECONDS`). The response carries `generated_at`, when it was assembled, which differs from `checked_at` when the answer came from the cache. Each channel also carries `delivery`: counts by status (`pending`, `delivering`, `sent`, `failed`, `cancelled`, `ambiguous`), `retrying` (pending or failed rows whose retry window is still in the future), `oldest_unresolved_at`/`oldest_unresolved_age_seconds`, and `stuck`/`degraded_reason` — `delivery_stuck` when an `ambiguous` or `failed` delivery is older than `ALERT_RECIPIENT_HOLD_SECONDS`, in which case the channel is `degraded` even if its probe succeeded. The response adds `delivery_queue.waiting_recipients`, the recipients inside a hold or a retry window. These are numbers only: no target, batch id or recipient digest is published. The dashboard prints `configured` beside the badge (it is what explains `not_configured`), the probe state and time, the queue counters, and `generated_at` as `Data as of`, so no field of this response is invisible to its only reader |
| `GET` | `/api/v1/alerts/queue` | admin — alert delivery queue counters and the 50 most recent deliveries |
| `GET` | `/api/v1/alerts/recipients` | admin — recipients the queue is holding back, and the reason for each |
| `POST` | `/api/v1/alerts/recipients/{key}/release` | admin — end a recipient's hold early; the decision is audited |
| `GET` | `/api/v1/connectors/health`, `/api/v1/connectors/modules` | viewer+ — connector liveness (`health`, the raw heartbeat timestamp and `online`, which DNS Security reads) and the module registry; the raw `last_error`, `blocked_reason` (why the core would refuse the next scan) and the `quota_*` fields are administrator-only and `null` for every other role. `online` is liveness alone — a worker whose last scan failed is still `online` — so the dashboard prints it beside `last_seen_at` rather than deriving it from `health`, and prints `generated_at` as `Data as of`. Every role also receives the readiness the source declared about its provider credentials, reduced to a closed vocabulary: `credentials_configured`, `credential_state` (`valid`, `invalid`, `unsupported`, `unknown`), `provider_error` (a fixed list — `invalid_credentials`, `ip_restricted`, `access_denied`, `credits_exhausted`, `rate_limited`, `provider_application_error`, `provider_rejected_request`, `network_or_invalid_response`, `http_NNN`) and `checked_at`, the time of that declaration. `last_success_at` and `last_success_age_seconds` say when collection last completed, which is a different fact from the heartbeat. The raw `readiness` document (capabilities, operations, the provider's data-class labels) is administrator-only, like `last_error` |
| `GET` | `/api/v1/jobs` | viewer+ |
| `GET` | `/api/v1/jobs/{job_id}` | viewer+ — one job's outcome, capabilities and result payload |
| `DELETE` | `/api/v1/jobs/{job_id}` | admin |

The DNS Security routes moved to `/api/v1/dns` when the module was renamed from
`dns_security`. The previous prefix still answers — a connector or script written
against it keeps working — but it is kept out of the OpenAPI document, so only the
`dns` spelling is advertised and there is one route to maintain. The deprecated
spelling requires exactly what its `/api/v1/dns` counterpart does, for all ten
paths: `GET /api/v1/dns-security/observations`,
`POST /api/v1/dns-security/scan`,
`DELETE /api/v1/dns-security/observations/{observation_id}`,
`POST /api/v1/dns-security/observations/{observation_id}/asset`,
`POST /api/v1/dns-security/observations/cleanup-orphans`,
`GET /api/v1/dns-security/certificates`,
`PATCH /api/v1/dns-security/certificates/sightings/{sighting_id}`,
`GET` and `POST /api/v1/dns-security/certificate-exceptions`, and
`DELETE /api/v1/dns-security/certificate-exceptions/{exception_id}`.

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
| `GET` | `/api/v1/settings/alert-policy` | admin — the alert budget in force: the saved values where stated, the deployment's `ALERT_*` environment for the rest, plus which row fields were refused |
| `POST` | `/api/v1/settings/validate-telegram` | admin — check a Telegram `chat_id` against the configured bot |
| `POST` | `/api/v1/settings/test-email` | admin |
| `POST` | `/api/v1/settings/test-telegram` | admin |
| `GET`, `POST` | `/api/v1/users` | admin — each row carries `last_login_at` (`null` when the account never completed a sign-in), and `GET` accepts `signed_in=true\|false` for the access-review question ("has signed in" / "never signed in") |
| `GET` | `/api/v1/users/brief` | admin |
| `GET`, `PUT`, `DELETE` | `/api/v1/users/{user_id}` | admin — `PUT` is the only route that changes activation (`is_active`), so one operation has one audit shape |
| `POST` | `/api/v1/users/{user_id}/unlock` | admin — release a brute-force login lockout; clears `failed_login_attempts` and `locked_until` only, and audits `user.unlocked` with `method=brute_force_unlock` |
| `POST` | `/api/v1/users/{user_id}/mfa/reset` | admin — reset another user's TOTP factor |
| `GET` | `/api/v1/users/export` | admin — the list behind the same filters as `GET /users`, as CSV or JSON; review columns only (role, activity, factor enrolment, last sign-in, onboarding), never a hash, TOTP secret or recovery code; capped at 10 000 rows |
| `GET`, `DELETE` | `/api/v1/users/{user_id}/sessions` | admin — list the account's usable sessions (ids and times, never tokens) or end all of them; `DELETE` is refused for the caller's own account |
| `POST` | `/api/v1/users/bulk` | admin — `activate`/`deactivate` a selection in one transaction and one `users.bulk` row; the caller's own account and a selection leaving no active administrator are refused |
| `POST` | `/api/v1/users/invite` | admin — create an account whose password only its owner sets; returns the single-use link token once (digest stored), and mails it when SMTP and a public origin are configured |
| `POST` | `/api/v1/users/{user_id}/invitation` | admin — replace a lost or expired invitation; the previous link stops working |
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
