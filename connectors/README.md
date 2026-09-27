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

## Self-declared manifest

A connector announces what it is at registration, so the core never carries a
list of known connectors. The SDK sends this declaration from environment
variables:

| Variable | Meaning |
|---|---|
| `CONNECTOR_TYPE` | module the connector feeds — must exist and be enabled in the core's module registry (`drp_modules`); the core refuses an unknown id and lists the ones it has |
| `CONNECTOR_JOB_TYPE` | **required.** The scan job type this connector **alone** claims, e.g. `phishing.lookalike`. A connector that declares none could claim no work, so the SDK refuses to start without it |
| `CONNECTOR_FINDING_KIND` | which core finding schema its submissions validate as (defaults to the module's kind) |
| `CONNECTOR_ASSET_TYPES` | comma-separated inventory sections to receive, e.g. `domain,email_account` |
| `CONNECTOR_CONFIG_SCHEMA` | JSON of operator-editable settings: `{"scan_certificates": {"type": "bool", "label": "…", "default": true}}` |

A module the platform ships with (`phishing`, `breaches`) writes to its own typed
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
docker compose exec -T backend python -m scripts.manage_connector_tokens issue dnstwist --type phishing --env CONNECTOR_TOKEN_DNSTWIST
docker compose exec -T backend python -m scripts.manage_connector_tokens issue shodan --type phishing --env CONNECTOR_TOKEN_SHODAN
docker compose exec -T backend python -m scripts.manage_connector_tokens issue hibp --type breaches --env CONNECTOR_TOKEN_HIBP
```

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
(all three first-party connectors ship pre-configured in the compose file)
and controlled at runtime from the **Settings → Connectors** panel.

Connector-specific secrets are passed via `.env` (never hardcoded):

| Variable | Used by | Purpose |
|---|---|---|
| `CONNECTOR_TOKEN` | all | this connector's own credential (issued by the core for it, per connector) |
| `SHODAN_API_KEY` | shodan | Shodan API key |
| `HIBP_API_KEY` | hibp | HaveIBeenPwned API key |
| `SHODAN_SCAN_SSL_TEXT` | shodan | fallback default for the `scan_ssl_text` capability |
| `SHODAN_SCAN_HTTP_TITLE` | shodan | fallback default for the `scan_http_title` capability |
| `SHODAN_SCAN_FAVICON` | shodan | fallback default for the `scan_favicon` capability |
| `SHODAN_MIN_REQUEST_INTERVAL_SECONDS` | shodan | minimum delay between sequential provider requests (default `1`; increase for a stricter plan/quota) |
| `SHODAN_REQUEST_TIMEOUT_SECONDS` | shodan | per-request provider timeout (default `30`, bounded to `5..120`) |
| `DNS_NAMESERVERS` | dnstwist | optional comma-separated resolvers; empty uses the Docker/system resolver |
| `DNSTWIST_FUZZERS` | dnstwist | bounded comma-separated fuzzer list; the expensive full set is opt-in |
| `DNSTWIST_TLD_DICTIONARY` | dnstwist | optional TLD dictionary path; disabled by default because it greatly expands DNS work |
| `DNSTWIST_THREADS` | dnstwist | subprocess concurrency, clamped to 1-32 (default 8) |

A connector-scoped setting is namespaced after its connector (`SHODAN_*`,
`DNSTWIST_*`, `HIBP_*`). `.env` is one namespace shared by every service in the
Compose file set, so an unprefixed name would be claimed by whichever connector
asked for it first, and the collision would be invisible until then.
`scripts/check_env_template.py` fails the build on one: the single exemption, with
its reason, is `DNS_NAMESERVERS`.

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
`favicon_unavailable` when the domain served no icon). **`matches` above `stored`
is deduplication, not loss**: `phishing_domain` is unique in the core, so a host
the platform already records is rejected rather than updated — the title row
above is a real example, where the single `http.title:"HIBP"` host in Shodan's
index was already stored from the certificate search. DNSTwist reports the same
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
`phishing_domain` (required), `matched_asset`, `ip_address`, `web_ports`,
`original_domain`, `detection_source` (defaults to the connector name).

**Breaches** (`connector_type=breaches`): provider-neutral fields plus
`matched_email` and/or `matched_domain` (at least one required).
Core fields: `breach_name` (required), `title`, `domain`, `breach_date`,
`pwn_count`, `description`, `data_classes`.

Anything your source knows beyond that goes in `attributes` — a flat payload of
scalars or string lists, e.g.
`{"is_verified": true, "masked_password": "ab****cd", "source_id": "FEED-9"}`.
The core does not model any vendor's field set, so you declare your own; keys
must be lowercase identifiers (`^[a-z][a-z0-9_]{0,63}$`), at most 32 keys, and
control characters are rejected. Attribute values are stored and returned
verbatim (booleans, numbers, strings, lists of strings), and the UI renders
declared attributes with friendly labels for the well-known ones and humanized
labels for the rest. Anything outside `attributes` is not part of the protocol:
a payload that puts a provider field next to `breach_name` is rejected rather
than reshaped, so what a connector sent is always what the core stored.

Dedup is enforced core-side: a phishing domain already in the DB is
silently dropped; breach rows are unique per (breach, matched email/domain).
