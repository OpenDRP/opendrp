# ExecPlan 004 — Connectors: the two provider runtimes plan 003 did not reach

## Goal

Plan [003](003-connector-provider-runtime.md) put pacing, quota reservation, the
retry loop, `Retry-After` parsing and a bounded body read into one SDK client and
migrated the three connectors that talk to metered third-party APIs by name:
`shodan`, `hibp`, `dns_security`. Two workers were left out of that inventory
because they reach the same providers through their own adapters:

- `connectors/intelligence/providers.py` — `Adapter.request` (L923) with
  `retry_delay` (L399) and `classify_http_error` (L365);
- `connectors/exposure_endpoints/endpoint_providers.py` — `EndpointClient._get`
  (L96) with `_retry_wait` (L75).

They carry the fourth and fifth copy of the same mechanisms, and one of them
carries a defect of the kind plan 003 closed: `exposure_endpoints` reads the whole
body into memory with `client.get(...)` and only then compares
`len(response.content) > MAX_BODY_BYTES` (L142) — the bound is consulted after the
buffering it exists to prevent.

The architectural rule is the project's own: the core must not depend on
particular connectors, and a connector must not reinvent the contract. After this
plan, every worker that spends a provider's quota makes its calls through one
client.

**This plan changes no code by itself.** It exists so the migration can be sliced
per worker and verified worker by worker.

## Inventory — what is duplicated, and what is not

| Mechanism | `connectors/intelligence/` | `connectors/exposure_endpoints/` | Shared client today |
|---|---|---|---|
| Retry attempts | `for attempt in range(3)` (L932) | `MAX_ATTEMPTS = 3` (L25) | `ProviderLimits.max_attempts` |
| Local backoff | `0.25 * 2**attempt` (L990) | `0.25 * 2**attempt` (L124) | `2**attempt`, clamped |
| `Retry-After` | `retry_delay` (L399): seconds **and** HTTP-date, capped 24 h | `_retry_wait` (L75): seconds only, capped 5 s | `parse_retry_after`: both forms |
| Long-hint behaviour | wait out the capped hint, then retry | wait out the capped hint, then retry | `abort_when_retry_after_exceeds` |
| Response size bound | streamed, 2 MB (L977) | **buffered first**, then compared (L142) | streamed, `max_response_bytes` |
| Quota reservation | `self.reserve(bucket)` before each attempt (L937), local budget first (L934) | same shape (L116, L115) | `reserve` hook |
| Failure vocabulary | `invalid_credentials`, `access_denied`, `credits_exhausted`, `rate_limited`, `provider_rejected_request`, `http_<status>`, `network_or_invalid_response`, `invalid_response`, `response_too_large` | `network_or_invalid_response`, `rate_limited`, `provider_rejected_request`, `response_too_large`, `invalid_response` | `http_<status>`, `http_<status>_retry_later`, `response_too_large`, `invalid_json`, `invalid_response`, `network_error`, `network_timeout`, `retry_exhausted` |

Two things the table says that the previous plan's table did not have to face:

1. **In these two workers the error code is a decision, not a label.**
   `exposure_endpoints.RECOVERABLE_ERRORS` (main.py L31-40) decides whether the
   scan moves to the next target, and it is a set of *those* strings. Renaming
   `network_or_invalid_response` to the shared `network_timeout` would silently
   turn "try the next target" into "stop the scan". So this migration keeps the
   connector's vocabulary at the boundary and maps the shared names onto it,
   explicitly, in one table per worker — the opposite of what plan 003 did for
   `dns_security`, where the shared name was adopted because the string reached
   only the job summary.
2. **The two backoffs differ from the shared one.** Both workers wait
   `0.25 * 2**attempt`; the shared client waits `2**attempt`. Plan 003 did not
   need to notice because its three connectors all used the plain form. Sending
   these two through the shared client without a factor would multiply their
   first retry wait by four.

## Plan of Work

### One SDK addition: a backoff factor

`ProviderLimits` gains `backoff_factor: float = 1.0`, and the local wait becomes
`backoff_factor * 2 ** attempt`, still clamped by `max_retry_delay`. The default
keeps every existing caller bit-for-bit: `shodan`, `hibp` and `dns_security` pass
nothing and wait what they waited. The two workers here pass `0.25`.

Nothing else in the shared client changes. The hint still wins over the local
backoff, and `max_retry_delay` still clamps both.

### What deliberately stays in each worker

| Stays | Why |
|---|---|
| The failure vocabulary and its mapping from the shared outcomes | the code is the worker's own decision about what to do next |
| `classify_http_error` for Netlas (`api key not found` in a 400 body) | provider-specific rejection, exactly what `classify_error` is for |
| Buckets (`search`, `lookup`, `dns`, …) and who is charged | the core's quota model |
| Endpoint paths, expressions, field mapping, catalogue submission | module semantics |
| `credentials_unconfigured` check before the loop | a key that is absent is not a provider answer |
| `EndpointClient.requests` / `Adapter.requests` counters | the per-scan budget the hook enforces |

### Migration order

1. **`exposure_endpoints`** first: 227 lines, one `_get`, its own test module and
   the real defect — the buffered body. Small enough that the diff can be read
   against the acceptance criteria in one sitting.
2. **`intelligence`**: 1220 lines, one `request` method called by every lookup,
   with a classification table that already has the shape of `classify_error`.

Each worker is one commit with its existing tests unchanged and green.

## Concrete Steps

1. Add `backoff_factor` to `ProviderLimits` + unit test in
   `backend/tests/test_connector_provider_client.py` (the SDK contract tests live
   there because `connectors/base/` has no test tree of its own).
2. Migrate `EndpointClient._get` onto `ProviderClient`, keeping `MAX_ATTEMPTS`,
   `MAX_BODY_BYTES`, the 404-means-not-indexed answer and the error table. Run
   `backend/tests/test_exposure_endpoints_connector.py`.
3. Add the one test the defect deserves: a streamed body larger than the bound is
   refused mid-read, and the transport is not asked for the rest.
4. Migrate `Adapter.request` onto `ProviderClient` with
   `classify_error=classify_http_error` wired through, `retry_delay` deleted, and
   the shared outcomes mapped back onto this worker's codes. Run
   `backend/tests/test_intelligence_providers.py` and
   `backend/tests/test_intelligence_worker.py`.
5. Re-run the connector contract suites and the full backend fast suite.

## Validation and Acceptance

| Check | Command / file |
|---|---|
| SDK unit tests | `backend/tests/test_connector_provider_client.py` |
| Exposure endpoints | `backend/tests/test_exposure_endpoints_connector.py` |
| Intelligence providers and worker | `backend/tests/test_intelligence_providers.py`, `backend/tests/test_intelligence_worker.py` |
| Connector runtime + protocol contract | `backend/tests/test_connector_runtime.py`, `backend/tests/test_connectors_protocol_api.py` |
| Readiness contract | `backend/tests/test_connector_readiness_contract.py` |
| Lint / types / docs | `ruff check app ../connectors`, `python -m mypy app`, `scripts/check_docs_consistency.py` |

Acceptance criteria, stated so the migration cannot drift:

- for the same provider responses, both workers record the same error codes they
  record today — `RECOVERABLE_ERRORS` and the intelligence error list are the
  contract, and a code that changes name changes behaviour;
- the same number of wire attempts for the same response sequence, and the same
  wall-clock wait (`0.25 * 2**attempt`, hint-capped at 5 s);
- a request that the per-scan budget refuses is not sent, not counted and not
  retried;
- no response body larger than the bound is ever buffered, let alone decoded —
  this is the defect, and it is closed for `exposure_endpoints` by the read the
  shared client performs;
- the core-facing API (`ConnectorBase`, readiness, quota) is untouched.

## Risks

| Risk | Mitigation |
|---|---|
| The error vocabulary is load-bearing in `exposure_endpoints` (control flow) | map shared outcomes to the worker's codes in one explicit table, with a test per code |
| Intelligence's Netlas 400-body classifier reads 8 KB today, 4 KB in the shared client | 4 KB is where the shared snippet stops; assert the known phrases classify at the boundary rather than assuming them early in the body |
| Both workers create their own `httpx.AsyncClient` per call, and tests replace the transport | keep the client creation where it is; the shared client takes the client it is given |
| Retry timing is asserted in tests through a patched `asyncio.sleep` | the patch is on the module attribute, so the shared client's sleep is patched too; assert the waits, do not delete the assertions |
| A worker's `transport=` test seam | pass the transport through unchanged — the shared client never builds a transport |

## Progress and Milestones

- [x] Inventory (this document).
- [x] `backoff_factor` in `ProviderLimits` + SDK test (`47282d7`).
- [x] `exposure_endpoints` migrated; the buffered read closed with a test.
      `EndpointClient._get` is an adapter over `ProviderClient.get_json`, and the
      per-scan budget plus the core reservation became the client's `reserve`
      hook, so a refused attempt is still sent nowhere. The statuses moved into
      `EndpointClient._error_code`, which the shared client calls; the outcomes a
      status cannot express are one explicit table,
      because `RECOVERABLE_ERRORS` is written in this worker's words and a shared
      name arriving unrenamed would stop a scan that should have continued. One
      case is deliberately left unnamed: a Shodan 404 returns `None` from the
      classifier so the `http_404` stays the client's, and `_get` reads it as
      "not indexed" rather than as a failure.
      The defect is closed by the read the shared client performs: the bound was
      consulted after the whole answer had been buffered, and is now enforced
      mid-read (ten chunks sent, five read). A long `Retry-After` is still capped
      at five seconds rather than abandoning the call, which is why
      `abort_when_retry_after_exceeds=None` is stated rather than inherited.
- [x] `intelligence` migrated: `Adapter.request` is an adapter over
      `ProviderClient`, with `self.requests`/`self.max_requests` and the core
      reservation kept as one `charge` hook in their original order. The statuses
      are `classify_http_error`'s, handed to the client as its classifier; the
      outcomes a status cannot express are the `OUTCOME_CODES` table; and the
      provider's own `Retry-After` is still attached to `ProviderError`, read from
      the response that carried it, because this worker reports the pause to the
      core rather than only waiting on it. `retry_delay` stayed as the wrapper
      that caps what is reported to one day — the shared parser reads both forms,
      and the cap is this worker's decision. The signature did not change: the
      client is still built by this worker and passed in, so the transport seam is
      intact.
      Two harness changes, neither an assertion: the test module puts
      `connectors/base` on `sys.path` so the SDK is importable the way the image
      makes it importable, and the two `asyncio.sleep` patches now patch the
      module instead of a local import, because the wait happens inside the shared
      client. A new test pins the 4 KB snippet against a refusal body that nearly
      fills it, and another pins the long-hint policy: a `Retry-After: 3600` is
      waited out for five seconds and the call is retried, not abandoned.
- [x] Contract suites, lint, types and docs gate green locally: 247 passed over
      `test_connector_runtime.py`, `test_connector_provider_client.py`,
      `test_connector_readiness_contract.py`, `test_connector_sdk_contract.py`,
      `test_connectors_protocol_api.py`, `test_intelligence_worker.py`,
      `test_exposure_endpoints_connector.py`, `test_no_legacy_surface.py`, plus
      `test_intelligence_providers.py` (41) and `test_intelligence_credential.py`;
      `ruff check app ../connectors` clean, `mypy app` clean, docs gate OK.
