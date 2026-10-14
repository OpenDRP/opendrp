# OpenDRP Connectors

OpenDRP uses a **core + connector** architecture (inspired by OpenCTI
import connectors): the platform core (FastAPI backend) owns all data,
while *connectors* are independent containers that fetch data from external
sources and submit normalized findings back to the core.

```
┌───────────────── Core (backend) ─────────────────┐
│ API, assets, jobs, dedup, alerts, audit, UI data │
└───────▲──────────────────▲───────────────▲───────┘
        │ register/poll/submit (HTTPS)      │
┌───────┴──────┐   ┌───────┴──────┐  ┌───────┴──────┐
│ (any source) │   │ (any source) │  │ (any source) │
│ type:        │   │ type:        │  │ type:        │
│ phishing     │   │ phishing     │  │ breaches     │
└──────────────┘   └──────────────┘  └──────────────┘
```

## How a connector works

Every connector runs the shared SDK (`connectors/base`) loop:

1. **Register** itself with the core (`POST /api/v1/connectors/register`)
   using its own `CONNECTOR_TOKEN` credential. The connector is provisioned on
   the core first (row + token together), because the credential *is* its
   identity — see "Credentials" below.
2. **Poll for work** (`GET /api/v1/connectors/me/work`) — the core
   atomically hands out one pending scan job (204 when the queue is empty).
3. **Scan** its external data source (dnstwist binary / Shodan API / HIBP API).
4. **Submit findings** in batches (`POST /api/v1/connectors/me/findings/{job}`)
   — the core validates, dedups, enriches, and fans out alerts.
5. **Report completion** with a JSON summary (`POST /api/v1/connectors/me/complete/{job}`).

A connector is **stateless**: it holds no DB credentials and cannot write to
the database directly. Disable it in the UI and it simply stops receiving work.

## The connector-facing API

Everything the SDK calls lives under `/api/v1/connectors/` and is authenticated
with this connector's own token (`X-Connector-Token`, plus the optional
`X-Connector-Name`, which only has to agree with the credential — see
[Credentials](#credentials)). There is deliberately **no** "who am I" endpoint:
the credential *is* the identity, so a `GET /connectors/me` would only be a
second place for it to be misread. `GET /connectors/me/control` is what a worker
asks when it needs to know whether it should be working.

These routes are the SDK's contract rather than the operator API, so they are
kept out of the platform's route overview on purpose: an operator reads
*connectors and modules*, not the wire protocol one worker speaks. The
operator-side equivalents are JWT-authenticated and documented in the
[main README](../README.md) — `POST /connectors/provision`,
`POST|DELETE /connectors/{id}/token`, `GET /connectors/health` and
`GET /connectors/modules` among them.

| Method | Path | Called by the SDK as |
|---|---|---|
| `POST` | `/connectors/register` | `register()` — at start-up |
| `GET` | `/connectors/me/work` | `poll_work()` — claims one job, `204` when idle |
| `POST` | `/connectors/me/findings/{job_id}` | `submit_findings()` |
| `POST` | `/connectors/me/complete/{job_id}` | `complete()` / `report_failure()` |
| `POST` | `/connectors/me/heartbeat` | `heartbeat()` and the job-lease loop |
| `POST` | `/connectors/me/quota/provider` | `reserve_provider_request(bucket)` |
| `POST` | `/connectors/me/quota/virustotal` | retired — answers `410 Gone`; reserve `lookup` on the route above |
| `POST` | `/connectors/me/readiness` | credential and capability state |
| `GET` | `/connectors/me/control` | `enabled` and the operator's config |
| `GET` | `/connectors/me/credential` | the provider key bound to this connector's account |

### `POST /connectors/register`

The payload is the connector describing itself, and identity still comes from
the credential: a name that is neither the credential's own name nor one of its
aliases is refused with `403` rather than creating or rewriting another
connector's row (registration upserts by name).

```json
{
  "name": "phishing-dnstwist",
  "connector_type": "phishing",
  "api_version": "1.2.0",
  "protocol_version": 2,
  "info": {"version": "1.2.0", "python": "3.12.11", "hostname": "…", "platform": "linux"},
  "default_job_type": "phishing.dnstwist",
  "finding_kind": "phishing",
  "asset_types": ["domain"],
  "config_schema": {"scan_certificates": {"type": "bool", "label": "…", "default": true}}
}
```

The response is the connector's registry row — including `token_prefix`, the
public prefix of the credential in use, and never its digest. Registering again
with the same declaration is how a worker heals itself after the core's data was
reset, which is why the SDK registers on every start-up and not once per
lifetime.

### `GET /connectors/me/work`

`204` means nothing is queued; the SDK then sleeps `POLL_INTERVAL_SEC` (default
`5`) instead of spinning. A claim answers with the job and, crucially, its lease:

```json
{
  "job_id": "…",
  "lease_token": "…",
  "lease_seconds": 180,
  "protocol_version": 2,
  "job_type": "phishing.dnstwist",
  "connector": "phishing-dnstwist",
  "module": "phishing",
  "config": {},
  "params": {"config_snapshot": {}, "manifest_snapshot": {}},
  "created_at": "2026-10-11T09:00:00Z"
}
```

Work is claimed for the connector the credential identifies and one job per
poll, so a leaked token cannot drain another connector's queue and two workers of
the same connector never receive the same job. A response without `lease_token`
is refused by the SDK rather than run: acting on a job it could not have claimed
is the one thing a worker must never do.

### `POST /connectors/me/findings/{job_id}`

Header `X-Connector-Lease: <lease_token>`, body a JSON **array** of findings.
The batch is bounded at 500 items (a longer array is `400`), and every item is
validated against the finding kind the connector's own manifest declares before
anything is persisted — a payload outside that schema is refused, never reshaped.
Ingestion is idempotent core-side (the dedup key is unique, `phishing_domain` for
phishing and the breach plus matched email/domain for breaches), which is what
makes it safe for the SDK to retry a batch whose response was lost: it retries
transport failures (network, `408`, `425`, `429`, `5xx`) and never authentication
or validation errors.

The response carries the `accepted` and `rejected` counters and a bounded
per-item `errors` list whose entries name the index, a code and whether a retry
could help:

```json
{"accepted": 40, "rejected": 1, "errors": [{"index": 7, "code": "invalid_observation", "retryable": false}]}
```

The SDK treats `rejected > 0` or `accepted != <batch length>` as a protocol error
and fails the job, so a silent partial write cannot be reported as a clean scan.

### `POST /connectors/me/complete/{job_id}`

```json
{"ok": true, "summary": {"new_discovered": 12}, "lease_token": "…"}
```

`ok: false` with an `error` string (at most 4000 characters, control characters
refused) marks the job failed; what the job history shows is this `summary`. The
lease token is mandatory on both paths: only the claim that is still current may
close a job, so a worker whose lease expired cannot finish — or reopen — work
that has moved on.

### `POST /connectors/me/heartbeat`

An idle heartbeat is `{}` and only refreshes `last_seen_at`; the SDK sends at
most one every 30 seconds. A heartbeat that names a job carries
`{"job_id": …, "lease_token": …}` and renews **that job's** lease — the core
requires the token before it moves the expiry, and keeping the lease fresh is
what stops a long scan (a DNSTwist sweep, a wide Shodan search) from being
reclaimed while it is still running. The SDK's job loop renews every
`JOB_HEARTBEAT_INTERVAL_SEC` (default `15`, clamped to `5`–`30`) and cancels the
scan if the lease is lost. Response: `{"status": "ok", "server_time": "…"}`.

### `POST /connectors/me/quota/provider`

A reservation, not a report. Query parameters are `job_id` (the claimed job) and
`bucket` (the operation being charged — a provider connector may charge only one
of the operations it declared at readiness, which for the shipped workers are
`search`, `lookup` and `certificate`; `reserve_virustotal_request()` uses
`lookup`), plus the `X-Connector-Lease` header.
One call checks and charges the per-minute, daily and per-job windows in a single
atomic operation against the **account's** budget, so two replicas of the same
source account cannot each spend the same quota.

```json
{"reserved": true, "account": "…", "billing_credits": "unknown", "request_budget": 100}
```

A refusal is explicit rather than a silent overspend: `429` with `Retry-After`
when a window is exhausted, `403` when the job lease is not active, the account
is not operator-approved or the connector has no provider identity, `409` when
the source is disabled or the scan's deadline has passed, `400` for a bucket the
provider's declared operations do not include, and `503` when the quota backend
is unreachable. Treating any of them as "carry on" is spending a budget nobody
agreed to.

### `POST /connectors/me/quota/virustotal`

Retired, and answers `410 Gone`. It is kept only so that a connector built
against an older SDK fails loudly instead of silently bypassing the shared
budget: the lease-bound `/connectors/me/quota/provider` above replaces it.

### `POST /connectors/me/readiness`

The connector reports what it observed about its own provider credentials, so the
UI can tell "nothing found" apart from "the key is wrong":

```json
{"credentials_configured": true, "credential_state": "valid", "provider_error": null,
 "capabilities": ["ssl", "http_title"], "operations": ["search"]}
```

`credential_state` is one of `unknown`, `valid`, `invalid` or `unsupported`, and
`provider_error` is a coarse enumeration (`invalid_credentials`, `ip_restricted`,
`access_denied`, `credits_exhausted`, `rate_limited`, …) rather than the
provider's raw text, which routinely carries the key. Capability and operation
names are namespaced lowercase identifiers and are deduplicated core-side. A
later readiness signal does **not** erase a recent actionable error unless the
connector reports `credential_state: "valid"`, so an idle report cannot quietly
clear a real failure. Response: `{"status": "ok", "enabled": true}`.

### `GET /connectors/me/control`

What a worker asks before doing provider work, and what it can re-read to pick up
an operator's change without being restarted:

```json
{"enabled": true, "config": {"scan_certificates": true}}
```

`enabled` is the conjunction of the connector's own switch and its module's, so
disabling a module in Settings stops every worker feeding it rather than only the
one that was clicked. `config` is the per-connector settings object the registry
holds — the same one the manifest's `config_schema` renders as a form — which is
the reason a connector reads its operator-editable settings from the core instead
of from its own environment.

### `GET /connectors/me/credential`

Where a passive-intelligence worker gets its provider key. The key is stored
once, per source account, encrypted with the core's `ENCRYPTION_KEY` — this route
is what lets a connector read it without the key being repeated in every
container's environment. Only the connector bound to the account can ask for it,
and the answer is never cacheable:

```json
{"configured": true, "api_key": "..."}
```

`{"configured": false}` means no key is stored for the account; a worker reports
that as `credentials_configured: false` rather than treating a missing key as an
empty result. Each disclosure is audited by connector and account and never by
value. The SDK does not call this automatically — `connectors/intelligence` asks
for it on start-up and after a credential rejection, and falls back to the
provider variable in its own environment when the core holds no key.

None of these routes paginates: work is one job per poll, a finding batch is
bounded at 500 items and a quota reservation is a single unit. That is the whole
contract a connector author has to satisfy — one job, one bounded batch, one
reservation, each proved by the lease it was issued.

## Self-declared manifest

A connector announces what it is at registration, so the core never carries a
list of known connectors. The SDK sends this declaration from environment
variables:

| Variable | Meaning |
|---|---|
| `CONNECTOR_TYPE` | module the connector feeds — must exist and be enabled in the core's module registry (`drp_modules`); the core refuses an unknown id and lists the ones it has |
| `CONNECTOR_JOB_TYPE` | **required.** The scan job type this connector **alone** claims, e.g. `phishing.dnstwist`. A connector that declares none could claim no work, so the SDK refuses to start without it |
| `CONNECTOR_FINDING_KIND` | which core finding schema its submissions validate as (defaults to the module's kind) |
| `CONNECTOR_ASSET_TYPES` | comma-separated inventory sections to receive, e.g. `domain,email_account` |
| `CONNECTOR_CONFIG_SCHEMA` | JSON of operator-editable settings: `{"scan_certificates": {"type": "bool", "label": "…", "default": true}}` |

A module the platform ships with (`exposure`, `phishing`, `breaches`, `dns`) writes to its own typed
tables. A module an **operator declares** at runtime stores findings in generic
JSON storage (`drp_findings`), deduplicated on the fields its declaration names —
so a new source can be onboarded without a core release, a migration or a
frontend change. Either way the connector's declaration is the only thing it
needs to supply; the module record supplies the rest.

The core stores the manifest and uses it as the source of truth:

* **work isolation** — a job is claimed by unique job type, so a connector can
  never pick up another connector's (or another module's) scan;
* **validation** — submissions are validated against the declared finding kind,
  and the declared config schema drives the config API (declared defaults are
  materialized, unknown keys are dropped, declared types are enforced);
* **UI** — `GET /connectors/modules` reports the modules and job types that are
  actually registered, and Settings renders the connector's config form from the
  declared schema, so a new connector appears in job history and becomes
  configurable without a frontend change.

## Credentials

Every connector authenticates with a credential of its own — there is no
platform-wide connector secret. A single shared value could be replayed as any
connector and could not be revoked for one of them alone, so the core issues a
token per connector and keeps only its SHA-256 digest.

Provisioning creates the registry row *and* the token together (a connector
cannot register itself before one exists), and it happens against a running
core:

```bash
docker compose exec -T backend python -m scripts.manage_connector_tokens issue phishing-dnstwist --type phishing --env CONNECTOR_TOKEN_DNSTWIST
docker compose exec -T backend python -m scripts.manage_connector_tokens issue phishing-shodan --type phishing --env CONNECTOR_TOKEN_SHODAN
docker compose exec -T backend python -m scripts.manage_connector_tokens issue breaches-hibp --type breaches --env CONNECTOR_TOKEN_HIBP
```

A bundled connector is named `<module>-<provider>` — `phishing-dnstwist`,
`breaches-hibp`, `dns-rdap` — with a `-<task>` suffix when one provider exposes
more than one worker (`exposure-netlas-endpoints`). A connector that predates the
scheme keeps its former label as an alias, so the registry identity it already has
and the token already issued for it keep working.

A connector of your own follows the same shape: the name is the value you set as
`CONNECTOR_NAME`, and `--type` must be a module the core already knows.

```bash
docker compose exec -T backend python -m scripts.manage_connector_tokens issue <name> --type <module> --env CONNECTOR_TOKEN_<NAME>
```

The CLI prints `<VAR>=<token>`; paste that into the worker's `CONNECTOR_TOKEN`
and recreate the container — `docker compose up -d connector-<name>`. A plain
restart is not enough, because a container keeps the environment it was created
with. On a host with `make`,
`make connector-token NAME=<name> TYPE=<module>` does the issuing *and* updates
`.env`, so a fresh checkout is one command per worker. The plaintext is shown
once and cannot be retrieved — only rotated:

```bash
make connector-token-rotate NAME=<name>          # or the CLI 'rotate'
docker compose exec -T backend python -m scripts.manage_connector_tokens revoke <name>
docker compose exec -T backend python -m scripts.manage_connector_tokens list
```

A worker whose `CONNECTOR_TOKEN` is empty or still the `.env.example`
placeholder does not break the stack: it exits at startup with
`Missing required environment variables: CONNECTOR_TOKEN`, and the core rejects
any token it never issued. Compose deliberately does not interpolate-require the
value, because that would make every `docker compose` command fail — including
the `exec` that issues tokens — on an unprovisioned checkout.

`revoke` cuts a connector off without deleting its registry row, configuration or
job history. The same operations are available to admins over the API
(`POST /connectors/provision`, `POST|DELETE /connectors/{id}/token`) and from
**Settings → Connectors** in the UI.

Identity comes from the token, so the SDK treats a `401`/`403` as fatal: it logs
the exact recovery command and exits instead of retrying, since only an operator
can issue a replacement token. The optional `X-Connector-Name` header is only
checked for agreement with the credential.

The core names the refusal on its own side too. A stale token is logged as
`connector_credential_rejected` with the connector name the token carries, the
path it was presented on and the caller's address — once per connector per
minute, so polling cannot flood the log:

```bash
docker compose logs --tail=50 backend | grep connector_credential_rejected
```

That line is the fastest way to answer "which key stopped working", because the
label it reads is what an operator typed wrong, not what a connector claimed.

## Enabling connectors

Connectors are enabled by defining their container in `docker-compose.yml`
(twelve connector services ship pre-configured) and controlled at runtime from
the **Settings → Connectors** panel. Four of them are part of the installation,
because they need no provider credential: `connector-phishing-dnstwist`,
`connector-dns-rdap`, `connector-dns-resolver` and `connector-dns-ctlogs`. The
other eight are gated by a Compose profile, so a keyed worker is never created
until the operator asks for it: `connector-phishing-shodan` by `shodan`,
`connector-breaches-hibp` by `hibp`, `connector-phishing-netlas`,
`connector-dns-netlas` and `connector-exposure-netlas` by `netlas`,
`connector-exposure-netlas-endpoints` by `netlas-endpoints`,
`connector-exposure-shodan-endpoints` by `shodan-endpoints` and
`connector-dns-virustotal` by `virustotal`.

Connector-specific secrets are passed via `.env` (never hardcoded):

| Variable | Used by | Purpose |
|---|---|---|
| `CONNECTOR_TOKEN` | all | this connector's own credential (issued by the core for it, per connector) |
| `SHODAN_API_KEY` | phishing-shodan | Shodan API key |
| `HIBP_API_KEY` | breaches-hibp | HaveIBeenPwned API key |
| `SHODAN_SCAN_SSL_TEXT` | phishing-shodan | fallback default for the `scan_ssl_text` capability |
| `SHODAN_SCAN_HTTP_TITLE` | phishing-shodan | fallback default for the `scan_http_title` capability |
| `SHODAN_SCAN_FAVICON` | phishing-shodan | fallback default for the `scan_favicon` capability |
| `SHODAN_MIN_REQUEST_INTERVAL_SECONDS` | phishing-shodan | minimum delay between sequential provider requests (default `1`; increase for a stricter plan/quota) |
| `SHODAN_REQUEST_TIMEOUT_SECONDS` | phishing-shodan | per-request provider timeout (default `30`, bounded to `5..120`) |
| `DNS_NAMESERVERS` | phishing-dnstwist, dns-resolver | optional comma-separated resolver IPs; empty uses the Docker/system resolver; DNS Security allows at most 8 |
| `DNSTWIST_FUZZERS` | phishing-dnstwist | bounded comma-separated fuzzer list; the expensive full set is opt-in |
| `DNSTWIST_TLD_DICTIONARY` | phishing-dnstwist | optional TLD dictionary path; disabled by default because it greatly expands DNS work |
| `DNSTWIST_THREADS` | phishing-dnstwist | subprocess concurrency, clamped to 1-32 (default 8) |
| `DNSTWIST_TIMEOUT_SECONDS` | phishing-dnstwist | per-scan subprocess timeout in seconds (default `120`) |
| `INTELLIGENCE_PROVIDER` | phishing-netlas, dns-netlas, exposure-netlas | selects the passive-intelligence provider (`netlas`); any other value refuses to start |
| `EXPOSURE_PROVIDER` | exposure-netlas-endpoints, exposure-shodan-endpoints | selects the endpoint-lookup provider (`netlas` or `shodan`); any other value refuses to start |
| `NETLAS_API_TOKEN` | phishing-netlas, dns-netlas, exposure-netlas, exposure-netlas-endpoints | Netlas API token, read by the workers that speak to Netlas |
| `CONNECTOR_TOKEN_NETLAS_PHISHING`, `CONNECTOR_TOKEN_NETLAS_DNS_SECURITY`, `CONNECTOR_TOKEN_NETLAS_EXPOSURE`, `CONNECTOR_TOKEN_EXPOSURE_NETLAS_ENDPOINTS`, `CONNECTOR_TOKEN_EXPOSURE_SHODAN_ENDPOINTS` | the matching Netlas or endpoint worker | that worker's own core credential (see the tables below) |

A connector-scoped setting is namespaced after its connector (`SHODAN_*`,
`DNSTWIST_*`, `HIBP_*`). `.env` is one namespace shared by every service in the
Compose file set, so an unprefixed name would be claimed by whichever connector
asked for it first, and the collision would be invisible until then.
`scripts/check_env_template.py` fails the build on one: the single exemption, with
its reason, is `DNS_NAMESERVERS`.

### DNS Security workers

The module id is `dns` (the earlier `dns_security` stays a recognized alias), and
all four services share the DNS Security image: RDAP, resolver and CT Logs start
with the installation, VirusTotal is gated by the `virustotal` profile. They consume active `domain` assets
and submit `dns_observation` payloads, not phishing threats or generic findings.

| Identity | Service | Core token variable |
|---|---|---|
| `dns-rdap` | `connector-dns-rdap` | `CONNECTOR_TOKEN_DNS_RDAP` |
| `dns-resolver` | `connector-dns-resolver` | `CONNECTOR_TOKEN_DNS_RESOLVER` |
| `dns-ctlogs` | `connector-dns-ctlogs` | `CONNECTOR_TOKEN_DNS_CTLOGS` |
| `dns-virustotal` | `connector-dns-virustotal` | `CONNECTOR_TOKEN_DNS_VIRUSTOTAL` |

For each desired source, issue a credential with `--type dns`, save its
one-time output in the corresponding local `.env` entry, configure provider
variables, then recreate **only configured services** (enabling a profile where
one gates the worker). Do not pass a Compose profile name as a token module type:
the module is `dns`. The setup wizard does not yet
select these optional workers.

```bash
docker compose exec -T backend python -m scripts.manage_connector_tokens issue dns-ctlogs --type dns --env CONNECTOR_TOKEN_DNS_CTLOGS
docker compose up -d --build --wait connector-dns-ctlogs                            # no profile: keyless, part of the installation
```

CT's optional `DNS_SECURITY_CTLOGS_API_TOKEN` is a **provider** Bearer token,
not the core worker token above. VirusTotal requires `DNS_SECURITY_VT_API_KEY`
and the explicit `DNS_SECURITY_VT_PUBLIC_NONCOMMERCIAL=true` acknowledgement;
its public tier cannot be used for business purposes. Both provider credentials
stay in the matching worker, never the core settings. Resolver knobs are
`DNS_SECURITY_RESOLVER_TIMEOUT_SECONDS` and `DNS_SECURITY_RESOLVER_EXTENDED`.

[Full DNS setup, rotation, verification and API guide](../docs/dns-security.md)
includes all four issuance commands, the complete environment table, quota
limits and pending-job troubleshooting. A running worker can claim previously
queued work immediately. Disable unused sources in Settings to stop schedules
from queueing them; stopping a container does not disable its registry row.
See also the [worker implementation notes](dns_security/README.md).

### Exposure endpoint workers

The `connectors/exposure_endpoints` image serves two providers, one per service,
and asks them which services a target exposes — one observation per distinct
port, submitted as `exposure` findings. `EXPOSURE_PROVIDER` selects the lookup
client and refuses any value other than `netlas` or `shodan`; the worker reads
`NETLAS_API_TOKEN` or `SHODAN_API_KEY` accordingly. Ownership is decided by where
the endpoint came from: an IP target is exact, and a domain target is associated
with the address its name resolved to, so a shared address alone never proves
that the domain owns it.

| Identity | Service | Profile | Provider | Core token variable | Job type |
|---|---|---|---|---|---|
| `exposure-netlas-endpoints` | `connector-exposure-netlas-endpoints` | `netlas-endpoints` | `netlas` | `CONNECTOR_TOKEN_EXPOSURE_NETLAS_ENDPOINTS` | `exposure.netlas-endpoints` |
| `exposure-shodan-endpoints` | `connector-exposure-shodan-endpoints` | `shodan-endpoints` | `shodan` | `CONNECTOR_TOKEN_EXPOSURE_SHODAN_ENDPOINTS` | `exposure.shodan-endpoints` |

Both declare the `endpoint_lookup` capability, charge the `lookup` quota bucket
before every request, and carry a bounded per-scan policy: `max_requests` and
`max_targets` are integers between `1` and `200`, defaulting to `20`, and a
reservation the core refuses stops the scan instead of letting a request past the
budget. `live_check.py` in that directory is an operator-run check that spends
real quota: it reads the key from the environment only, makes at most five
requests (retries included) and prints counts and ports — never the key, the
request URL or a response body.

### Provider plans and test data

**Shodan.** The `ssl:"…"` and `http.favicon.hash` searches use query filters
that Shodan does not serve on every plan, so the `scan_ssl_text` and
`scan_favicon` capabilities need a key of at least the **Membership** tier to
return results. A lower-tier key is handled honestly rather than silently: the
provider's refusal is retried for transient codes and otherwise reported in the
job summary as a partial scan, and `scan_http_title` is the capability a free
key can exercise. `SHODAN_MIN_REQUEST_INTERVAL_SECONDS` exists because a stricter
tier enforces its own rate limit — raise it rather than discovering the limit as
`429`s.

**HIBP.** For validating an installation without a subscription, HIBP publishes
an integration key that only ever returns fixture data:

```text
HIBP_API_KEY=00000000000000000000000000000000
```

With it, add `account-exists@hibp-integration-tests.com` as an `email_account`
asset and `hibp-integration-tests.com` as a `domain` asset, then run a breaches
scan: the email lookup returns the fixture breaches for that address and the
domain lookup returns the fixtures for that domain. Both are the addresses HIBP
documents for its integration tests, and the key is a test identity rather than
a secret — real results need a real key from the HIBP account page.

### Shodan capabilities

The Shodan connector supports three individually togglable capabilities.
The **registry config** (editable in Settings → Connectors) takes precedence
over the env-var fallbacks:

```json
{ "scan_ssl_text": true, "scan_http_title": true, "scan_favicon": true }
```

With `scan_ssl_text=false` the connector skips all `ssl:"…"` searches
(no wasted API credits); disabling all three completes the scan immediately
with a `no_capabilities_enabled` summary. Shodan requests are serialized and
paced by default, and transient `429`/`5xx` responses are retried with bounded
backoff honoring `Retry-After`. A final quota, provider, or timeout error is
reported in the job summary as a partial scan rather than being mistaken for
zero findings. The connector never retries invalid credentials.

Every capability also reports its own outcome in the job summary under
`capability_results`, so a scan that returns fewer findings than expected can be
read from the job that produced it instead of re-run by hand:

```json
"capability_results": {
  "ssl":     {"queries": 2, "matches": 21, "candidates": 10, "stored": 10, "skipped": null},
  "title":   {"queries": 1, "matches": 1,  "candidates": 1,  "stored": 0,  "skipped": null},
  "favicon": {"queries": 0, "matches": 0,  "candidates": 0,  "stored": 0,  "skipped": "favicon_unavailable"}
}
```

`matches` is what the provider returned, `candidates` the findings built from
them, `stored` the ones the core kept, and `skipped` names a capability that
could not run at all (`no_domain_assets` when there is no `domain` asset to hash,
`favicon_unavailable` when the domain served no icon). **`matches` above `stored` is the count of
findings whose dedup key the core already had**: `phishing_domain` is unique in
the core, so a host the platform already records refreshes its existing row —
reported as `updated`, or as `unchanged` when nothing changed — instead of
appearing as a second finding. The title row above is a real example, where the
single `http.title:"HIBP"` host in Shodan's index was already stored from the
certificate search. DNSTwist reports the same
split for a scan that discovered nothing: `candidates` generated, `resolved` to a
public address, `new_discovered` stored.

The core submission path also retries only transient transport failures. Finding
batches are idempotent in the core, so a response lost after a successful commit
cannot create duplicate findings; authentication and validation errors are never
retried.

## Writing a new connector

1. Create `connectors/<name>/main.py`:

```python
from opendrp_connector import ConnectorBase

class MyConnector(ConnectorBase):
    async def run_scan(self, work: dict):
        # work = {"job_id", "job_type", "connector", "config", "params"}
        findings = [
            {"phishing_domain": "example-login.com",  # for type=phishing
             "matched_asset": "example.com",
             "ip_address": "1.2.3.4",
             "detection_source": "my_connector"},
        ]
        await self.submit_findings(work["job_id"], findings)
        return [], {"new_discovered": len(findings)}

if __name__ == "__main__":
    MyConnector().main()
```

2. Add a Dockerfile copying `connectors/base` (see existing connectors).
3. Add a compose service with `CONNECTOR_NAME=<name>`, the matching
   `CONNECTOR_TYPE`, and the manifest variables above (`CONNECTOR_JOB_TYPE`,
   `CONNECTOR_FINDING_KIND`, `CONNECTOR_ASSET_TYPES`, `CONNECTOR_CONFIG_SCHEMA`).
4. Start it: `docker compose up -d connector-<name>` — it appears in the
   Connectors panel and starts receiving work when enabled.

No core, HTTP-schema or frontend change is required: the connector declares its
job type, its finding kind, the inventory it consumes and its settings, and the
platform adapts.

## Finding schemas

**Phishing** (`connector_type=phishing`):
`phishing_domain` (required) and `matched_asset` (required), plus `ip_address`,
`web_ports`, `original_domain`, `observed_at`, `detection_source` (defaults to
the connector name) and `metadata`.

**Breaches** (`connector_type=breaches`): provider-neutral fields plus
`matched_email` and/or `matched_domain` (at least one required).
Core fields: `breach_name` (required), `title`, `domain`, `breach_date`,
`pwn_count`, `description`, `data_classes`.

**DNS observations** (`connector_type=dns`): `observation_type` (required, one of
`dns_record`, `rdap`, `certificate`, `certificate_check`, `vt_subdomain`,
`vt_resolution`, `hostname`, `passive_dns`) and `subject` (required, a hostname or
an IP address), plus `record_type` (`A`, `AAAA`, `CNAME`, `NS`, `MX`, `CAA`, `SOA`,
`RDAP` or `TXT`), `value`, `expires_at`, `status` (`current` by default, or
`historical`, `expired`, `unknown`) and `metadata` (at most 10 000 bytes once
serialized).

**Exposure** (`connector_type=exposure`): `subject` and `matched_asset` (both
required), `hostname`, `port` (1–65535, required), `transport` (`tcp` by default,
or `udp`), `protocol` (`unknown` by default), `observed_at` and `metadata`.

Anything your source knows beyond that goes in the payload's free-form field —
`metadata` for phishing, `attributes` for breaches — a flat payload of scalars or
string lists, e.g.
`{"is_verified": true, "masked_password": "ab****cd", "source_id": "FEED-9"}`.
The core does not model any vendor's field set, so you declare your own; keys
must be lowercase identifiers (`^[a-z][a-z0-9_]{0,63}$`), at most 32 keys, and
control characters are rejected. Attribute values are stored and returned
verbatim (booleans, numbers, strings, lists of strings), and the UI renders
declared attributes with friendly labels for the well-known ones and humanized
labels for the rest. Every payload model refuses fields it does not declare and
refuses unrecognized values rather than reshaping them, so a phishing batch that
spells its extra values `attributes`, or a breach batch that spells them
`metadata`, is rejected instead of silently losing them.

Dedup is enforced core-side: a phishing domain already in the DB refreshes its
existing row (`updated`, or `unchanged` when the scan supplied nothing new)
rather than creating a second one; breach rows are unique per source account,
breach name and matched email, and a domain-only finding — one with a matched
domain and no matched email — is unique per breach name and matched domain.
