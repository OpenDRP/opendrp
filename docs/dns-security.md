# DNS Security module

The DNS Security module stores observations as evolving, source-scoped facts in
`dns_security_observations`; it does not treat an observation as an immutable
finding. Repeated current resolver and RDAP results refresh the source's own row,
while an observation from another source remains independent. Resolver rows
store a whole RRset (bounded member list in `metadata.record_values`) per
hostname/record type, so multiple A/AAAA answers do not overwrite one another.
Passive-DNS resolution history retains the originating domain, hostname and
resolution timestamp; certificate identity includes certificate ID and wildcard
scope. A source failure
never deletes other sources' data.

## Sources

| Source | Evidence | Important caveat |
|---|---|---|
| RDAP | Registration events, registrar, registration and expiry timestamps | A missing expiry event is not evidence that a domain does not expire. |
| Resolver | Current A, AAAA and CNAME records; optionally NS, MX and CAA | DNS TTL is cache lifetime, not asset-registration expiry. |
| CT Logs | Certificate/issuer history and SAN metadata | Historical certificate appearance alone proves neither current DNS nor ownership. |
| VirusTotal | Passive-DNS/resolution and subdomain intelligence | Public-tier use is permitted only for personal, non-commercial use. |
| Netlas (optional) | Passive DNS history and certificate-collection evidence | Runs behind the `netlas` profile with the approved provider-account quota; not a current resolver/RDAP source. |

Netlas is the only optional provider in this module. Censys, FOFA and Criminal IP
are not shipped: the baseline seeds no registry row for them and their provider
code is not in the repository. Observations already recorded for them stay
readable as evidence. See [source intelligence](source-intelligence.md).

All results are bounded and independently retried; connector credentials are
per-worker and supplied at runtime, never in source, repository examples or
provider payload logs. The keyless DNS workers (RDAP, resolver, CT Logs) start
with the installation; only `dns-virustotal` is gated by the `virustotal` Compose
profile. Provision the desired worker tokens with module type `dns`
(`dns_security` is still accepted as a transitional alias, so a connector or
script that predates the rename keeps working); then start the corresponding
source containers. Credentials for VirusTotal are optional and its worker refuses to
send requests unless the API key and explicit noncommercial acknowledgement are
both present. CT authentication uses the optional
`DNS_SECURITY_CTLOGS_API_TOKEN` environment variable as `Authorization: Bearer`;
it is separate from the worker's `CONNECTOR_TOKEN_DNS_CTLOGS` credential. No
provider secrets belong in committed files.

CT wildcard matches are shown as `*.hostname`; they remain certificate evidence
and cannot be promoted as concrete host assets. VirusTotal observations are
marked historical, with bounded DNS/certificate metadata retained. Response
bodies are streamed with a 2 MB decoded-byte cap; pagination is bounded and
VirusTotal next links must retain the original HTTPS host and endpoint. An
all-error source scan reports `error`, not a successful empty scan; core ingestion
rejections fail the job rather than being silently counted as persisted results.
RDAP bootstrap redirects use bounded HTTPS hops with public-address validation
and IP pinning (TLS SNI and Host retain the registry name).

## Connect the workers

Run commands from the repository root with a healthy backend. The setup wizard
currently provisions only DNSTwist/Shodan/HIBP; DNS Security is a separate,
optional post-installation step. Do not recreate an existing `.env` with the
wizard just to add this module: copy only missing DNS variables from
[`.env.example`](../.env.example), retaining existing values and credentials.

### 1. Issue one core credential per desired worker

| Worker identity | Compose service | `.env` credential | Job type |
|---|---|---|---|
| `dns-rdap` | `connector-dns-rdap` | `CONNECTOR_TOKEN_DNS_RDAP` | `dns.rdap` |
| `dns-resolver` | `connector-dns-resolver` | `CONNECTOR_TOKEN_DNS_RESOLVER` | `dns.resolver` |
| `dns-ctlogs` | `connector-dns-ctlogs` | `CONNECTOR_TOKEN_DNS_CTLOGS` | `dns.ctlogs` |
| `dns-virustotal` | `connector-dns-virustotal` | `CONNECTOR_TOKEN_DNS_VIRUSTOTAL` | `dns.virustotal` |

Issue only the sources you intend to run. Each command prints a one-time
`VARIABLE=token` line: save it to the matching local `.env` entry, not to Git or
shared logs. The core stores only its digest. If a credential already exists,
use `rotate`, not `issue`.

```bash
docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens issue dns-rdap --type dns --env CONNECTOR_TOKEN_DNS_RDAP
docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens issue dns-resolver --type dns --env CONNECTOR_TOKEN_DNS_RESOLVER
docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens issue dns-ctlogs --type dns --env CONNECTOR_TOKEN_DNS_CTLOGS
```

For an eligible personal/non-commercial VirusTotal installation, additionally:

```bash
docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens issue dns-virustotal --type dns --env CONNECTOR_TOKEN_DNS_VIRUSTOTAL
```

### 2. Configure the provider environment

| Variable | Default | Meaning |
|---|---|---|
| `CONNECTOR_TOKEN_DNS_RDAP`, `CONNECTOR_TOKEN_DNS_RESOLVER`, `CONNECTOR_TOKEN_DNS_CTLOGS`, `CONNECTOR_TOKEN_DNS_VIRUSTOTAL` | Empty/unconfigured | Separate core-issued worker credentials; not provider keys. |
| `DNS_SECURITY_RESOLVER_TIMEOUT_SECONDS` | `3` | Resolver query timeout; clamped to 0.5–5 seconds. |
| `DNS_SECURITY_RESOLVER_EXTENDED` | `false` | Add NS/MX/CAA to A/AAAA/CNAME queries. |
| `DNS_NAMESERVERS` | Empty | Shared DNSTwist/DNS-resolver override; at most 8 comma-separated IP addresses. Empty uses the system/Docker resolver. |
| `DNS_SECURITY_CTLOGS_API_BASE` | `https://api.ctlogs.dev` | Only this HTTPS provider host is accepted, not an arbitrary proxy URL. |
| `DNS_SECURITY_CTLOGS_API_TOKEN` | Empty | Optional CT provider Bearer credential; anonymous mode remains available with conservative limits. |
| `DNS_SECURITY_VT_API_KEY` | Empty | VirusTotal provider API key, sent as `x-apikey`. |
| `DNS_SECURITY_VT_PUBLIC_NONCOMMERCIAL` | `false` | Explicit eligibility acknowledgement, not permission to use a public key commercially. |

Set provider secrets only in the local `.env` or deployment secret manager.
The core settings API does not accept or store them. Leaving the VirusTotal
acknowledgement false is intentional until the operator confirms eligibility.

### 3. Start only configured services

RDAP, resolver and CT Logs are keyless and start with the installation; this command makes sure they are up:

```bash
docker compose -f docker-compose.yml up -d --build --wait connector-dns-rdap connector-dns-resolver connector-dns-ctlogs
```

Only after configuring both VT variables and confirming eligibility:

```bash
docker compose --profile virustotal -f docker-compose.yml up -d --build --wait connector-dns-virustotal
```

VirusTotal is keyed, and the `virustotal` profile gates its container: without the
profile the service is not created, and with it the worker starts, registers and
reports `credentials_configured: false` until both the key and the
non-commercial acknowledgement are present — its scans then fail with
`api_key_not_configured` rather than report a clean empty result. The Compose
profile name is distinct from the `dns` module id used for tokens and API filters. `restart` does not apply `.env` edits; `up -d` recreates services
whose environment changed. A newly started worker can immediately claim old
pending jobs and perform external requests against their frozen asset snapshots.

### 4. Verify and scan

```bash
docker compose -f docker-compose.yml ps
docker compose -f docker-compose.yml logs --tail=50 connector-dns-rdap connector-dns-resolver connector-dns-ctlogs
docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens list
```

In **Settings → Connectors**, check enabled status and a recent heartbeat (also
available through authenticated `GET /api/v1/connectors/health`). Add an active
`domain` asset, open `/dns-security`, and use **Rescan**. These workers consume
active domains, not the keyword/email/IP inventory. Follow pending/running and
terminal results in Jobs history; a healthy container does not prove a provider
scan succeeded. Review `provider_errors`, `observations`, and the terminal job
status. Missing tokens cause authentication/startup failure; missing VT keys or
acknowledgement cause an error scan, not a clean empty result.

### Rotate or stop a source

```bash
docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens rotate dns-ctlogs --env CONNECTOR_TOKEN_DNS_CTLOGS
docker compose -f docker-compose.yml up -d --wait connector-dns-ctlogs
docker compose -f docker-compose.yml stop connector-dns-ctlogs
```

After `rotate`, save the new one-time output to `.env` **before** `up`.
`revoke dns-ctlogs` cuts off that credential without deleting history. Disable
unused sources in **Settings → Connectors** as well as stopping their containers,
so schedules do not queue work for stopped but enabled sources. Do not remove
PostgreSQL volumes or downgrade migrations to disconnect a source.

## API and permissions

| Method | Route | Permission / response |
|---|---|---|
| `GET` | `/api/v1/dns/observations` | Viewer+; paginated `items`, `total`, `page`, `size`, `pages`; filters `subject`, `source`, `observation_type`. |
| `POST` | `/api/v1/dns/scan` | Analyst+; HTTP 202 with `status`, `job_ids`, `offline_connectors`; HTTP 409 if no job can be queued (including when no enabled worker is online). |
| `POST` | `/api/v1/dns/observations/{observation_id}/asset` | Analyst+; optional JSON `target` selects the subject or a concrete resolver value; HTTP 201 with `already_exists` and `asset`; unrelated targets and wildcard evidence are refused with HTTP 409. |
| `DELETE` | `/api/v1/dns/observations/{observation_id}` | Analyst+; HTTP 204; optional `value` selects one RRset member. CT deletes all certificate evidence grouped by source, hostname and wildcard scope; audited. |
| `POST` | `/api/v1/dns/observations/cleanup-orphans` | Admin; `status` and `deleted`; destructive, audited cleanup. |

## Queued scans and orphan cleanup

**Rescan** creates pending jobs asynchronously, not scan results. DNS workers
claim jobs over the connector protocol; the Celery worker does not execute them.
Manual rescans enqueue only enabled workers with a recent heartbeat. Offline
sources are reported separately; if none are online the API refuses the request
without creating jobs. The page displays connector availability and disables
Rescan when no workers are available. Existing pending jobs are retained and
will wait for the corresponding worker to start.

Administrators can use **Clean orphans** after confirmation. Cleanup
removes observations only when neither their exact hostname/IP nor their
originating scan domain (CT certificate value or passive-DNS `source_domain`)
is a configured domain/IP asset. Inactive assets still count. It does not infer
ownership from suffixes, DNS record values, or keywords. Cleanup is audited and
never runs automatically on a provider failure.

## Limits and schedules

The anonymous CT Logs API documents 100 requests per hour, sequentially, with up
to 10 pages per domain. CT requests are paced at one every 36 seconds, retries
included, and capped at 100 per scan. VirusTotal's *published* public-tier limits
are 4 requests per minute and 500 per day; what the platform enforces is the
approved per-account policy — the `requests_per_minute` and `daily_budget` an
operator approved for that source account — in shared Redis windows, so two
workers of the same account cannot each spend the whole budget. The worker adds a
ceiling of its own: at most 500 reserved requests per scan. A quota slot is
reserved before every actual HTTP attempt, including retries, and every attempt
counts against the account; a quota-service failure denies the request.

The module's rescan schedule is configurable in **Settings → Scan
schedules**. Expiry reminders are queued daily for active domain assets at 30, 14, 7, 3 and 1 day thresholds, plus once after expiry. Registration (RDAP) and observed certificate (completed exact CT lookup) controls have separate durable cycles. Historical certificate expiry dates from CT subdomain discovery or Netlas do not by themselves establish an alertable monitoring check.
Checks older than `DNS_EXPIRY_MAX_AGE_HOURS` (default 48) or failed/incomplete
checks cannot queue new expiry alerts. The sweep reads the database only; it does
not make provider requests. Configure a scan schedule to keep evidence fresh. A reminder threshold is only marked after a delivery
row was enqueued. The schedule is stored in `system_settings.schedule_dns_security`
(not an environment variable); days are cron-style 0=Sunday through 6=Saturday
and hour/minute are UTC. Resolver TTL is excluded from expiry alerts. CT messages explicitly describe
passive observations, not certificates confirmed to be deployed on a service.
Only a completed `/v1/domain/{hostname}` check can establish CT monitoring;
subdomain discovery alone cannot. The newest already-issued exact certificate is
selected by `not_before` and certificate ID; future certificates and wildcard
names do not suppress expiry alerts for the selected exact certificate.

### Expiry control stateThe baseline creates `dns_expiry_monitors`. Monitor state is read from the
observations already recorded and from the checks that follow them; a fresh
installation has nothing to derive it from, and a database adopted at the baseline
already holds it. Nothing here deletes observations. Historical CT remains
unverified until a new exact check.
 Active domain assets
and an enabled DNS Security module are required for alerting. Renewal or a new
selected certificate starts a new cycle; a skipped sweep queues only the nearest
due threshold, not every missed threshold. No configured destination means no
threshold is consumed. Queue events and threshold markers share a transaction;
row locks prevent duplicate events from parallel sweep workers.

The observations API adds `expiry_kind` and `expiry_monitor` (kind, state,
checked_at, successful_at, expires_at, certificate_id, not_before,
remaining_seconds, alerted_thresholds). States distinguish verified, stale,
unverified, failed, incomplete, no_certificate, future_only and unknown. Exact
checks are visible as `certificate_check` rows, including empty/failure outcomes.
The Validity / Expiry column labels registration, passive certificate and DNS
cache dates separately. Expiry alert monitoring is narrower than the inventory:
RDAP registration and exact CT certificate checks can create monitors; ordinary
DNS TTL, discovery certificates and passive-source expiry metadata cannot. Deleting control evidence invalidates monitoring until
a new successful check; deleting its asset cascades its control state.

Exact CT lookups are performed before subdomain discovery and share the existing
100-request scan budget, sequential pacing, retry, 10-page and 500-result limits.
Large/partial exact searches are incomplete, not clean results. No active TLS/SNI
probe is performed.

## Inventory display and deletion

The observations API expands each resolver RRset into one row per record value
and groups certificate evidence by source, hostname and wildcard scope. Grouping
happens in SQL before counts and pagination; raw certificate evidence and complete
RRsets remain stored without a data migration. The page also includes source-scoped
observations produced by the optional Netlas DNS worker (`dns-netlas`) when its
capability is enabled; these are historical/provider evidence, not live DNS
resolution. `evidence_count` shows the number
of retained certificates, and the latest observation represents the group.
Asset controls sit next to the subject or resolver value. `In Assets` is disabled
for existing assets, including inactive assets; promotion refreshes these flags.

Deleting a resolver row with its `value` removes only that member; deleting a CT
row removes its entire displayed evidence group after explicit confirmation.
Other sources and assets are untouched. Future scans can rediscover deleted data.

## Asset promotion

Analysts can promote an observed hostname or IP to the monitored asset inventory.
Normalization and the database uniqueness rule prevent duplicates. Promotion
adds exactly the observed subject or the explicitly selected resolver address/hostname; it does not infer a registrable domain from a
public suffix, and it does not establish ownership. Review CT-only or otherwise
historical evidence before adding it as a monitored asset.

The UI asks before promoting: the confirmation names the asset type and
criticality that will be created (`domain`, or `ip_address` when the value parses
as an address; criticality `medium`) and says which observation it came from. The
resulting asset carries **no model-level link** back to that observation — there
is no foreign key from `assets` to the observation tables, because findings and
observations outlive asset configuration — so the trace is the audit trail: the
`dns_security.asset.promoted` (or `exposure.asset.promoted`) entry records the
originating observation, its source, its type and the created asset, including
its `criticality`. A value that was already monitored is recorded as
`dns_security.asset.already_exists` (or `exposure.asset.already_exists`) and
answers `already_exists` instead of creating a second asset.
