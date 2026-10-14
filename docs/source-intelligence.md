# Passive source intelligence

Netlas is the only optional passive intelligence provider. Its three workers — `phishing-netlas`, `dns-netlas` and `exposure-netlas`, one per module `phishing`, `dns` and `exposure` — use the core's pull/lease protocol and are defined in [docker-compose.yml](../docker-compose.yml) behind the `netlas` profile. A second, separate family of optional workers asks a provider which services a host exposes: `exposure-netlas-endpoints` and `exposure-shodan-endpoints`, behind the `netlas-endpoints` and `shodan-endpoints` profiles. Censys, FOFA and Criminal IP are not shipped: the baseline seeds no registry row for them and their provider code is not in the repository. Source observations already recorded for them are kept as evidence.

## Opt-in setup

1. Upgrade the core with the normal migration procedure and take a verified backup first. Nothing is enabled automatically.
2. Set the provider key in `.env` (or in your secret manager): `NETLAS_API_TOKEN`. Never place credentials in connector config, API responses or the browser.
3. Issue a core credential for each Netlas worker you intend to run:

   ```bash
   docker compose exec -T backend python -m scripts.manage_connector_tokens issue exposure-netlas --type exposure --env CONNECTOR_TOKEN_NETLAS_EXPOSURE
   ```

   Repeat for `phishing-netlas` (`--type phishing`, `CONNECTOR_TOKEN_NETLAS_PHISHING`) and `dns-netlas` (`--type dns`, `CONNECTOR_TOKEN_NETLAS_DNS_SECURITY`). The endpoint workers issue the same way with `--type exposure` and their own variables, `CONNECTOR_TOKEN_EXPOSURE_NETLAS_ENDPOINTS` and `CONNECTOR_TOKEN_EXPOSURE_SHODAN_ENDPOINTS`. The `--type` is the module id; the `--env` name is listed in `.env.example`.
4. Enable the profile and start the workers:

   ```bash
   COMPOSE_PROFILES=netlas make up
   ```

   The `netlas` profile starts all three workers together. A worker started without its provider key still registers: its capability list comes from the provider adapter rather than the key, so it reports `credentials_configured: false` and is never admitted a scan.
5. In Settings, check credential readiness, capabilities and last success. Explicitly approve the request/minute and daily budgets for the shared quota account, and enable the registry rows you want. Registration and heartbeat do not validate the provider key; `valid` is reported only after a successful provider request.
6. Add active domain/IP assets and use Exposure Rescan. Exposure schedules start disabled; enable one explicitly if you need it.

Provider credentials reach the worker from its own environment or from the core. A key stored once per source account is encrypted with `ENCRYPTION_KEY` and read only by the connector bound to that account, through `GET /api/v1/connectors/me/credential`, which is never cacheable and is audited by connector and account without the value. `credential_ref` only names an environment variable.

## Endpoint lookups

`connectors/exposure_endpoints` is a second optional image behind the
`netlas-endpoints` and `shodan-endpoints` profiles. `EXPOSURE_PROVIDER` selects the
provider and refuses any value other than `netlas` or `shodan`; the worker reads
`NETLAS_API_TOKEN` or `SHODAN_API_KEY` for that provider and charges the `lookup`
quota bucket before every request. Each scan is bounded by its own policy
(`max_requests` and `max_targets`, each 1–200, default 20): an IP target is an
exact match, and a domain target is associated with the address its name resolved
to, so a shared address alone never establishes ownership. `live_check.py` in that
directory is an operator-run check that spends real quota — at most five requests,
retries included — and prints counts and ports, never a key, a request URL or a
response body.

## Provider accounts

Settings → Connectors → Provider accounts holds the metadata-only quota policy for each upstream account. The migrated `default` Netlas account is used by unassigned Netlas workers once its budgets are approved. Unapproved or missing accounts are blocked fail-closed. Adding a second account does not switch credentials: the matching worker must also receive that key. Scan jobs freeze account policy and connector config when queued; later edits apply to new scans only.

## Ingestion, provenance and labels

Connector ingestion reports `received`, `created`, `updated`, `unchanged`, `accepted`, `rejected` and bounded per-item `errors`. Replays are `unchanged`, not rejected. Findings, evidence and notification outbox events commit together. Notification delivery is at-least-once across the database-to-channel boundary.

Provenance comes only from the authenticated connector identity and its bound account, never from a field in the finding. Connector rows use `<module>-<source>[-<task>]` labels — `phishing-netlas`, `dns-netlas`, `exposure-netlas-endpoints` — and each seeded row also carries its earlier spelling as an alias, which is what keeps authentication and tooling on the same identity.

## Account API

- `GET/POST /api/v1/connectors/accounts` lists or creates non-secret account identities.
- `PATCH /api/v1/connectors/accounts/{account_id}/policy` takes an explicit approval boolean and integer minute/day budgets.
- `PATCH /api/v1/connectors/{connector_id}/account?account_id=...` binds a module connector to a matching account.
- `GET /api/v1/connectors` includes each connector's UUID, `source_account_id` and display label.

## Safety and result semantics

Each provider request needs a live job lease, an enabled module, account minute/day capacity, a per-job request slot and an unexpired deadline. Redis failure denies requests. Response bytes, pages, targets, findings and HTTP timeouts are bounded. Transient network errors, HTTP 429 and 5xx get at most two retries, with capped backoff and a `Retry-After` wait of up to five seconds. Every physical attempt consumes quota. No provider redirect is followed. Provider errors map to safe codes; raw response bodies are not logged or stored.

Disabling a source cancels pending jobs; re-enabling does not resurrect them. A phishing match is a candidate, not a malicious verdict. Exposure is provider-observed inventory, not verified vulnerability or exploitation. Exposure association requires exact IP or hostname matching; a shared IP, CDN or certificate SAN alone does not establish ownership. Failed or truncated scans never resolve historical evidence.

## Netlas contract

- Bearer authentication against the documented `/responses/` search, `/host/{host}/` summary, `/domains/` collection (passive A/AAAA/NS) and `/certs/` collection (certificate names and fingerprints).
- Responses and domains share the 60/min general account budget; certificate collection has its own 3/min bucket plus the shared account, day and job budgets.
- The DNS Security worker uses the Domains and Certificates collections. Host summary and certificate SAN names are not ownership assertions.
- Malformed records are isolated from valid siblings; a scan with malformed records reports `partial`, not a clean result.

Readiness uses a small safe error set (`invalid_credentials`, `credits_exhausted`, `rate_limited`, `provider_rejected_request`, `network_or_invalid_response`, or an HTTP status class).

## Interfaces

- `POST /api/v1/modules/{module}/scan`: per-source admission.
- `GET /api/v1/exposure/observations`: paginated inventory with optional source filter.
- `GET /api/v1/phishing/threats/{id}/evidence`: source evidence (up to 200 records).
- The Exposure UI at `/exposure` lets analysts triage observations and promote a concrete hostname or IP into Assets after a confirmation that names the asset type and criticality.
- PDF reports include bounded Exposure and DNS observation sections with truncation metadata.

## Verification boundaries

Provider tests use mocked HTTP transports. They cover parsing, bounds, retries, quota reservations and error handling, but do not prove live credentials, plan entitlement or provider availability. Before relying on live results, run a bounded, budgeted validation against your Netlas account.

## Limitations

- Netlas capabilities depend on the account plan and the operator's configuration.
- Provider contracts and plans can change; re-check the [Netlas API reference](https://docs.netlas.io/api-reference/) before enabling a source in production.
