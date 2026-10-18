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
| Shodan (optional) | What each of our own addresses serves as an independent index saw it — certificate fingerprint, organisation, ASN, JARM, page title, favicon hash — and where else a certificate of ours is being served | Runs behind the `shodan` profile with the approved provider account. Reading one of our own addresses is free; the reverse search spends one query credit per request and is capped per scan. |
| TLS probe | The certificate each active domain asset serves right now, with its chain, validity, serial, SPKI hash and SAN names, read from a verified handshake | One bounded handshake per host and port against our own asset only; a failed or refused handshake is evidence about the probe, never about the certificate. |

Netlas and Shodan are the optional sources in this module (`netlas` and `shodan`
profiles). Censys, FOFA and Criminal IP
are not shipped: the baseline seeds no registry row for them and their provider
code is not in the repository. Observations already recorded for them stay
readable as evidence. See [source intelligence](source-intelligence.md).

All results are bounded and independently retried; connector credentials are
per-worker and supplied at runtime, never in source, repository examples or
provider payload logs. The keyless DNS workers (RDAP, resolver, CT Logs and the
TLS probe) start
with the installation; `dns-virustotal` is gated by the `virustotal` Compose
profile and the keyed `dns-shodan` worker by `shodan`, the profile that also
gates the phishing Shodan worker. Provision the desired worker tokens with module type `dns`
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

### Provider fields, as a live call confirmed them

The provider shapes this module reads were confirmed by one bounded call each on
2026-10-15 (never by assumption, and never by CI: a live call spends a real account).
For Shodan they are:

* `GET /shodan/host/{ip}` answers with one entry per open service under `data[]`, and a
  service carries `ssl.cert.fingerprint.sha256`, `ssl.cert.fingerprint.sha1`,
  `ssl.cert.serial` (decimal), `ssl.cert.issued`/`expires` (`YYYYMMDDhhmmssZ`),
  `ssl.cert.subject`/`issuer` (`{C, CN, O}`), `ssl.cert.extensions` (a list, where
  `subjectAltName` holds the names), `ssl.jarm`, `http.title` and `http.favicon.hash`.
  `org`, `asn`, `ports`, `hostnames` and `last_update` are on the document itself.
* `GET /shodan/host/search` matches on `ssl.cert.fingerprint:"<SHA-1>"` and on
  `ssl.cert.serial:"<decimal>"`. The plausible-looking
  `ssl.cert.fingerprint.sha256:"<SHA-256>"` filter is **accepted and matches nothing** —
  it returns `200` with `total: 0`, which in a worker would read as "this certificate
  is served nowhere". The SHA-1 is therefore what is searched and the SHA-256 stays the
  certificate identity; `connectors/dns_security/test_shodan_dns.py` pins the query so
  the trap cannot be re-entered.

The spike spent three query credits (two searches that answered, one that matched
nothing) of the account's monthly allowance — the only provider traffic in these
sources that is not free, and the reason `max_searches` exists.

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
| `dns-tlsprobe` | `connector-dns-tlsprobe` | `CONNECTOR_TOKEN_DNS_TLSPROBE` | `dns.tlsprobe` |
| `dns-shodan` | `connector-dns-shodan` | `CONNECTOR_TOKEN_DNS_SHODAN` | `dns.shodan` |

Issue only the sources you intend to run. Each command prints a one-time
`VARIABLE=token` line: save it to the matching local `.env` entry, not to Git or
shared logs. The core stores only its digest. If a credential already exists,
use `rotate`, not `issue`.

```bash
docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens issue dns-rdap --type dns --env CONNECTOR_TOKEN_DNS_RDAP
docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens issue dns-resolver --type dns --env CONNECTOR_TOKEN_DNS_RESOLVER
docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens issue dns-ctlogs --type dns --env CONNECTOR_TOKEN_DNS_CTLOGS
docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens issue dns-tlsprobe --type dns --env CONNECTOR_TOKEN_DNS_TLSPROBE
```

For an eligible personal/non-commercial VirusTotal installation, additionally:

```bash
docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens issue dns-virustotal --type dns --env CONNECTOR_TOKEN_DNS_VIRUSTOTAL
```

For the certificate review's provider confirmation (Shodan):

```bash
docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens issue dns-shodan --type dns --env CONNECTOR_TOKEN_DNS_SHODAN
```

### 2. Configure the provider environment

| Variable | Default | Meaning |
|---|---|---|
| `CONNECTOR_TOKEN_DNS_RDAP`, `CONNECTOR_TOKEN_DNS_RESOLVER`, `CONNECTOR_TOKEN_DNS_CTLOGS`, `CONNECTOR_TOKEN_DNS_TLSPROBE`, `CONNECTOR_TOKEN_DNS_VIRUSTOTAL`, `CONNECTOR_TOKEN_DNS_SHODAN` | Empty/unconfigured | Separate core-issued worker credentials; not provider keys. |
| `DNS_SECURITY_RESOLVER_TIMEOUT_SECONDS` | `3` | Resolver query timeout; clamped to 0.5–5 seconds. |
| `DNS_SECURITY_RESOLVER_EXTENDED` | `false` | Add NS/MX/CAA to A/AAAA/CNAME queries. |
| `DNS_NAMESERVERS` | Empty | Shared DNSTwist/DNS-resolver override; at most 8 comma-separated IP addresses. Empty uses the system/Docker resolver. |
| `DNS_SECURITY_CTLOGS_API_BASE` | `https://api.ctlogs.dev` | Only this HTTPS provider host is accepted, not an arbitrary proxy URL. |
| `DNS_SECURITY_CTLOGS_API_TOKEN` | Empty | Paid-tier CT provider Bearer credential; distinct from the core worker token. |
| `DNS_SECURITY_CTLOGS_PUBLIC_NONCOMMERCIAL` | `false` | Eligibility acknowledgement for the provider's keyless tier. Without a token the worker sends no request until this is true. |
| `DNS_SECURITY_CTLOGS_MAX_REQUESTS_PER_SCAN` | `100` | Bounded 1–10000. The default is what the keyless tier's hourly cap affords. |
| `DNS_SECURITY_CTLOGS_MIN_REQUEST_INTERVAL_SECONDS` | `36` | Bounded 0–3600, retries included. The default keeps one request in flight on the keyless tier. |
| `DNS_SECURITY_VT_API_KEY` | Empty | VirusTotal provider API key, sent as `x-apikey`. |
| `DNS_SECURITY_VT_PUBLIC_NONCOMMERCIAL` | `false` | Explicit eligibility acknowledgement, not permission to use a public key commercially. |
| `DNS_SECURITY_TLS_PORTS` | `443` | Allowlist of ports the active probe handshakes, at most three, comma-separated. A malformed entry is dropped and reported. |
| `DNS_SECURITY_TLS_PATH` | `/` | The request path the probe asks for; 1–200 printable characters starting with `/`. |
| `DNS_SECURITY_TLS_MAX_PROBES` | `200` | Handshake budget for one scan, bounded 1–2000. Beyond it the scan reports `probe_budget_reached`. |
| `SHODAN_API_KEY` | Empty | Shodan provider key for this worker, shared with the phishing Shodan worker. A key stored on the approved source account wins over it. |
| `SHODAN_MIN_REQUEST_INTERVAL_SECONDS` | `1` | Bounded 0–3600 seconds between sequential provider requests. Shodan's free tier answers about one request per second. |
| `SHODAN_REQUEST_TIMEOUT_SECONDS` | `30` | Bounded 5–120 seconds per provider request. |

Set provider secrets only in the local `.env` or deployment secret manager.
The core settings API does not accept or store them. Leaving the VirusTotal
acknowledgement false is intentional until the operator confirms eligibility.
The CT Logs acknowledgement works the same way and is a separate statement about a
separate provider: its terms restrict keyless use to non-commercial purposes, so
without a paid-tier token the worker performs no request at all until
`DNS_SECURITY_CTLOGS_PUBLIC_NONCOMMERCIAL=true`. A configured token is that
statement and needs no flag.

### 3. Start only configured services

RDAP, resolver, CT Logs and the TLS probe are keyless and start with the installation; this command makes sure they are up:

```bash
docker compose -f docker-compose.yml up -d --build --wait connector-dns-rdap connector-dns-resolver connector-dns-ctlogs connector-dns-tlsprobe
```

Only after configuring both VT variables and confirming eligibility:

```bash
docker compose --profile virustotal -f docker-compose.yml up -d --build --wait connector-dns-virustotal
```

For the certificate review's provider confirmation, after the Shodan account is approved
and its key is stored (Settings → Provider accounts):

```bash
docker compose --profile shodan -f docker-compose.yml up -d --build --wait connector-dns-shodan
```

The `shodan` profile also starts the phishing Shodan worker, so an installation that
already runs that profile brings this worker up on the same `up -d`. Its per-scan
budgets are connector settings rather than environment variables: `max_host_lookups`
(default 25, bounded 0–500) bounds the free lookups of our own addresses, and
`max_searches` (default 1, bounded 0–20) bounds the credit-spending reverse searches —
setting it to 0 keeps the free confirmation and spends nothing. Every request is
reserved against the approved account's quota before it is sent, and the job summary
reports `host_lookups`, `search_requests` and `search_candidates` so an operator can
read what a scan spent without opening the provider's console.

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
docker compose -f docker-compose.yml logs --tail=50 connector-dns-rdap connector-dns-resolver connector-dns-ctlogs connector-dns-tlsprobe connector-dns-shodan
docker compose -f docker-compose.yml exec -T backend python -m scripts.manage_connector_tokens list
```

In **Settings → Connectors**, check enabled status and a recent heartbeat (also
available through authenticated `GET /api/v1/connectors/health`). Add an active
`domain` asset, open `/dns-security`, and use **Rescan**. These workers consume
active domains, not the keyword/email inventory; `dns-shodan` is the one worker
that also consumes active `ip_address` assets, because it asks the index about our
own addresses as well as their names. Follow pending/running and
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
included, and capped at 100 per scan. Both numbers are settings
(`DNS_SECURITY_CTLOGS_MIN_REQUEST_INTERVAL_SECONDS`,
`DNS_SECURITY_CTLOGS_MAX_REQUESTS_PER_SCAN`) because a keyed plan raises the
provider's ceiling; an unusable value falls back to the default rather than
removing the bound. A budget smaller than the inventory cannot cover every domain,
so exact checks begin where the previous scan stopped and the tail is reached over
successive scans instead of never. VirusTotal's *published* public-tier limits
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

### Served-certificate control (`kind="tls"`)

The probe feeds its own monitor kind, which is what makes a reminder actionable:
`verified` means the handshake succeeded and the leaf parsed, `expired` means the
served certificate is already past its `notAfter` (alerted at threshold 0
immediately), and `failed`/`incomplete`/`skipped_no_public_address` never alert and
preserve the previous evidence and cycle. A renewal therefore starts a new
countdown because the served fingerprint changed - not because a log recorded an
issuance. Reminders of this kind say `Live TLS certificate` and
`Active TLS probe of the service (verified handshake)` and name the probed address
and port, while CT-derived reminders keep the passive wording, so the two can no
longer be confused.

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
scan budget, sequential pacing, retry, 10-page and 500-result limits. Large/partial
exact searches are incomplete, not clean results, and so are two cases the control
row now names: a domain whose request the per-scan budget refused (our budget is
not a provider failure), and an empty result returned by an index that reports it
searched only part of the domain's history. The provider's own coverage statement -
`history_window_days` and `history_truncated` - is stored with the control row, so
an empty page from a truncated window is `incomplete` rather than the
`no_certificate` a reader would take for calm.

The active probe is what removes the gap CT leaves: it resolves each active domain
asset, refuses every non-public address (`skipped_no_public_address`, also not an
alert base), and performs one `curl` handshake per address and port with
`--resolve`, so the URL, the SNI and the name check stay on the monitored hostname.
It never uses `-k`/`--insecure` for the authoritative pass: a verification failure
is split into expired, name mismatch and untrusted-or-self-signed from curl's own
exit code and the leaf it still delivered. Connect and total timeouts are 3 s and 8 s,
at most four handshakes run at a time, and a build whose curl predates 7.88 (no
`%{certs}`) probes nothing and reports `curl_certs_unsupported`. The fingerprint,
validity, serial, SPKI hash and SAN names of the served certificate are recorded
per host and port, with the chain as its own evidence row keyed by fingerprint.

## Certificate deployment review

The finding this module is built to produce is a copied service: a VM, disk image or
container carrying a web server *and its private key*, redeployed somewhere else. The
evidence is that a certificate of ours is served from an address that is not ours.
The platform answers that question about the *certificate* rather than about any one
observation, because the same certificate is legitimately seen by our own probe, by
Certificate Transparency and by a provider, on our addresses and on someone else's.

The certificate step of the daily 05:30 UTC sweep (after both default scan slots)
first projects the raw evidence in `dns_security_observations` into identities
(`tls_certificate_identities`, one row per fingerprint — the same fingerprint is never
two certificates) and sightings (`tls_certificate_sightings`, one row per certificate,
address, port and observing source, so re-observing a fact refreshes it instead of
stacking a duplicate), then scores the projection:

| Rule | Alert | Fires when |
| --- | --- | --- |
| R1 | `tls.certificate.foreign` | A certificate of ours is observed on an address that is not ours |
| R2 | `tls.key.reuse` | One Subject Public Key Info digest appears in two different certificates |
| R3 | `tls.certificate.unexpected` | A certificate covers our name but was not deployed by us |
| R4 | none — raises confidence and marks the sighting `needs_review` | A service stack echoes ours (a JARM and a title or favicon match, with no certificate match) |

R4 is deliberately not an alert: matching a JARM and a title is strong evidence of a
clone and weak evidence of *which* clone, so it becomes a candidate a human confirms.

`is_ours` is the platform's own answer and never a source's opinion. An address is ours
when our own handshake verified our certificate on it, when an operator registered it as
an `ip_address` asset, when our own resolver answers with it for a monitored name (a CDN
edge of ours is nobody's copy), or when the row is a provider's record of an address this
platform named — which is the only kind of address the Shodan worker asks about.
Sightings are grouped by certificate and address before queueing, so several sources
confirming one foreign address produce one alert naming the address, the sources, the
organisation, the ASN and the rule that fired, rather than one alert per source.
**No traffic is sent to third-party infrastructure:** every provider read is a search
over data the vendor already collected, and the only active traffic is our own probe
against our own assets. An alert never invites an operator to probe the foreign host.

R1 is suppressed when the evidence looks like shared infrastructure — several foreign
addresses serving one certificate from a hosting, CDN or cloud organisation — and the
sighting's verdict is set to `shared_infrastructure` so the decision is visible rather
than silent.

Two provider paths feed these rules, and the module's Shodan worker (`dns-shodan`) runs
both from one scan, in that order:

* **Confirmation, free.** `GET /shodan/host/{ip}` for the addresses this platform names —
  the `ip_address` assets of the inventory and the addresses its monitored domains
  resolve to right now. The answer names the certificate that address serves, so a
  certificate of ours is a fact an independent index agrees with, and it carries the
  organisation, ASN, JARM, page title and favicon hash the echo rule and the
  shared-infrastructure suppression score on. These rows are `host_lookup` observations,
  and the platform reads them as evidence about our own service. A host the provider
  indexes with no certificate is recorded as exactly that, never guessed at.
* **The reverse question, at a price.** `GET /shodan/host/search` with the SHA-1
  fingerprint of a certificate this scan just found, which answers *where else* it is
  being served — the foreign address R1 alerts on. Each request is one query credit
  (100 per month on a free plan), so it is capped per scan by `max_searches`, reserved
  against the approved account before it is sent, and switched off entirely at 0. A scan
  that found more certificates than its budget covered says so in `provider_errors`
  (`search_budget_reached`) and its job status is `partial`, rather than presenting a
  partial sweep as a clean one. The serial is the fallback filter for a certificate the
  fingerprint index has not caught up with, and it draws on the same budget.

A row that arrived from either path carries `host_lookup_confirmed`, which is what gives
R1 its confidence bonus: the address was named by an index that also stated the
certificate it serves. Reporting an address without that statement does not earn it, so
confidence still counts *confirmations* rather than sources.

### Verdicts and scope exceptions

The review workflow is what keeps this usable in an estate with CDNs and partner
appliances. Only sightings a rule left as `candidate` are queued for, so any judgement
survives every later sweep:

* `GET /api/v1/dns/certificates` lists certificates with their sightings
  (`foreign_only`, `verdict`, `page`, `size`).
* `PATCH /api/v1/dns/certificates/sightings/{id}` records a verdict — `candidate`,
  `expected`, `shared_infrastructure`, `confirmed_foreign` or `rejected` — and is
  written to the audit trail as `tls.sighting.<verdict>`.
* `GET|POST /api/v1/dns/certificate-exceptions` and
  `DELETE /api/v1/dns/certificate-exceptions/{id}` manage the identities a rule must
  not alert on, matched by `fingerprint`, `spki`, `ip`, `asn` or `issuer`, with a reason
  and an optional end date. An expired exception stops applying on its own rather than
  needing somebody to remember it. Adding and removing one is administrator-only and
  recorded as `tls.exception.added` / `tls.exception.removed`.

The DNS Security page shows the certificate list above the job table, with the address,
the organisation and the signals behind the score on the row, and names what a verdict
means before it is recorded. The unverified case is shown as it is: a certificate
someone else indexed is evidence that the certificate exists, not that it is deployed.

Retention is `TLS_CERTIFICATE_RETENTION_DAYS` (default 365). An identity outlives the
sightings that reference it only while one of them remains, and a sighting row
cascades with its identity; the raw provider evidence in
`dns_security_observations` is governed by the DNS retention window instead, so
triaging a certificate never depends on keeping the observations that produced it.

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
