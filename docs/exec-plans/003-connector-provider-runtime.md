# ExecPlan 003 — Connectors: one provider HTTP runtime

## Goal

Three connectors that talk to metered third-party APIs each carry their own
version of the same four mechanisms — pacing, quota reservation, retry policy and
Retry-After parsing — while `ConnectorBase` already owns the core-facing side
(`_request`, `_request_with_retry`, `_client_session`, `reserve_provider_request`).
This plan puts those four mechanisms in **one** place in the SDK, leaves every
provider's endpoint/parameter/error vocabulary in its own connector, and fixes one
security gap that the duplication hid.

The architectural rule behind it is the one the project states for the platform:
the core must not depend on particular connectors, and connectors must not each
reinvent the contract. A new provider should cost an endpoint map and a field
mapping, not a third copy of a retry loop.

**This plan changes no code.** It exists so the migration can be sliced and
verified provider by provider.

## Inventory — what is actually duplicated

| Mechanism | `connectors/hibp/main.py` | `connectors/dns_security/main.py` | `connectors/shodan/main.py` |
|---|---|---|---|
| Retry-After parsing | `_retry_after_seconds` (L253) — numeric only | `_retry_after` (L203) | `_retry_after` (L482) — numeric **and** HTTP-date |
| Retry loop | none (single attempt, returns `None`) | `MAX_RETRIES = 3` (L48), exponential `2**attempt` | `_SHODAN_MAX_RETRIES = 2` (L81), cap `30.0` (L89) |
| Response size bound | **none** — `client.get(...)` then `.json()` | `MAX_RESPONSE_BYTES = 2_000_000` (L47), streamed `bytearray` | **none** — `response.json()` |
| Quota reservation | `_reserve(bucket)` + `_limiter.acquire()` | `before_request` hook → `reserve_provider_request` | `_reserve("search")` + `_pace_provider_request()` |
| Pace control | `self._limiter` (`RateLimiter`) | caller-supplied reservation | `_min_request_interval` + `_last_provider_request` |
| Credential state | 401 → `invalid` / 200 → `valid` (L957–961) | reported elsewhere in the scan | `_error_code` maps 403+credit → `quota_exhausted` |
| Named failure vocabulary | `"network_error"` | `"response_too_large"`, `"invalid_json"`, `"invalid_response"`, `"retry_exhausted"`, `"http_<code>"` | same plus `"network_timeout"`, `"quota_exhausted"` |

Two consequences worth stating plainly:

1. **A real defect, not just duplication.** `hibp` and `shodan` decode an
   unbounded response body from a third party into memory. `dns_security`
   already refuses anything over 2 MB. A provider (or a MITM on a pinned
   connection) can hand `hibp` a 500 MB body today and the worker will try to
   parse it. This must be fixed as its own commit with its own test, *not*
   folded into the refactor, because it is a behaviour change.
2. **Three retry vocabularies.** The same failure gets three names depending on
   the connector, so the core's readiness/error reporting cannot compare them.

## Plan of Work

### New: `connectors/base/opendrp_connector/provider.py`

One class, one responsibility: "make one provider HTTP call under the account's
budget and the provider's pace, and classify the outcome".

```python
@dataclass(frozen=True)
class ProviderLimits:
    max_attempts: int = 3
    max_retry_delay: float = 30.0
    max_response_bytes: int = 2_000_000
    timeout: float = 30.0


class ProviderClient:
    """Paced, budgeted, size-bounded HTTP for a metered provider.

    The connector supplies what only the provider knows: the base URL, auth
    headers, the reservation hook, and the error-code mapping. Everything that
    must be true for *every* provider call lives here, once.
    """

    def __init__(self, *, http, reserve, pace=None, limits=ProviderLimits(),
                 credential_state=None, provider_errors=None): ...

    async def get_json(self, url, *, params=None, headers=None,
                       free=False) -> ProviderResult: ...
    async def post_json(self, url, *, json=None, headers=None,
                        free=False) -> ProviderResult: ...
```

`ProviderResult` carries `payload`, `status`, `outcome` (`None` on success) and the
bounded `response` — the same triple `dns_security._get_json` already returns, so
its call sites migrate mechanically.

Rules the class enforces (moved, not invented):

- reservation **before** every wire attempt, including retries;
- pace acquisition before the request, optionally two limiters (the HIBP
  per-route allowance is exactly this case);
- streamed read with `max_response_bytes`, decoding only after the bound passes;
- `Retry-After` in both formats (seconds and HTTP-date), clamped to
  `max_retry_delay`, with the provider's own hint winning over local backoff;
- one outcome vocabulary shared by all connectors;
- credential state callback so a 401 still updates readiness exactly once.

### What deliberately stays provider-specific

| Stays in the connector | Why |
|---|---|
| URLs, query parameters, `minify`, API key placement | provider vocabulary |
| `_error_code` text sniffing (Shodan's 403 + "credit") | provider-specific rejection |
| `free=True` calls (IP lookup, `_count`) | a billing fact only the provider documents |
| Field mapping, catalogue submission, capability declaration | module semantics |
| HIBP's per-domain limiter and stealer-log interval policy | provider plan shape |

### Migration order

1. **Pilot: `shodan`** (smallest of the three, `_get` is one method, tests live in
   `backend/tests/test_connector_runtime.py`). `_get` becomes a thin adapter over
   `ProviderClient.get_json`.
2. **`dns_security`** — `_get_json` already has the target shape; replace its body
   with the shared client and delete `MAX_RESPONSE_BYTES`/`_retry_after` locals
   only after the shared defaults are proven equal.
3. **`hibp`** — `_get`/`_post` collapse into one call shape; the per-route limiter
   becomes the optional second limiter.
4. **Separately, as a defect fix:** give `hibp` and `shodan` the response-size
   bound with a test per connector. Not in the refactor commits.

## Concrete Steps

1. Add `provider.py` + unit tests in `backend/tests/test_connector_provider_client.py`
   (the SDK contract tests already live in `backend/tests/` and import
   `opendrp_connector` directly; `connectors/base/` has no test tree of its own).
   No provider involved: fake transport, fake reservation, fake clock.
2. Migrate `shodan._get`; keep `_reserve`, `_pace_provider_request`,
   `_error_code` where they are. Run `backend/tests/test_connector_runtime.py`
   and `connectors/dns_security/test_shodan_dns.py`.
3. Migrate `dns_security._get_json`; run its test module.
4. Migrate `hibp._get`/`_post`; run `connectors/hibp/test_hibp.py`.
5. Fix the unbounded-body defect in `hibp` and `shodan` with one test each.
6. Re-run the connector contract suites (below) and the full backend fast suite.

## Validation and Acceptance

| Check | Command / file |
|---|---|
| SDK unit tests | `backend/tests/test_connector_provider_client.py` (new), `backend/tests/test_connector_sdk_contract.py` (907) |
| Connector runtime + protocol contract | `backend/tests/test_connector_runtime.py` (1616 lines), `backend/tests/test_connectors_protocol_api.py` (1340) |
| HIBP behaviour | `connectors/hibp/test_hibp.py` (2140) |
| DNS Security / TLS | `connectors/dns_security/test_*.py` |
| Readiness contract | `backend/tests/test_connector_readiness_contract.py` |
| Lint / types | `ruff check app ../connectors`, `python -m mypy app` |

Acceptance criteria, stated so the migration cannot drift:

- each migrated connector's public methods return the same values for the same
  provider responses (existing tests unchanged and green);
- the same provider failure yields the same `outcome` string it yields today
  (a rename is a behaviour change and needs its own decision);
- `ProviderLimits` defaults are equal to today's per-connector constants, and any
  difference is called out in the commit message;
- no response body larger than `max_response_bytes` is ever decoded;
- `ConnectorBase`'s core-facing API is untouched — this plan adds a collaborator,
  it does not change the protocol.

## Risks

| Risk | Mitigation |
|---|---|
| Pacing semantics differ subtly (HIBP pauses its limiter on 429; Shodan sleeps) | keep the pause as a provider callback; do not move `RateLimiter.pause` into the SDK |
| A shared default changes a provider's retry count | pass today's constants explicitly at each call site first, then converge in a separate commit |
| `dns_security` streams and pins IPs for RDAP; a naive client would follow redirects | keep `follow_redirects=False` and the pinned-URL call in the connector; the shared client takes the URL it is given |
| Large diff in 2200-line files | one connector per commit, pilot first, tests unchanged |

## Progress and Milestones

- [x] Duplication inventory (this document).
- [x] `provider.py` + SDK unit tests. While the pilot migrated, the "provider
      names its own rejection" hook the sketch called `provider_errors` became
      `classify_error`: Shodan answers a drained account with a 403 whose body
      says so, and a streamed response cannot be re-read after it is closed, so
      the class reads a bounded snippet and hands it to the connector's table.
      A classifier never renames a decision the client already made
      (`http_429_retry_later` stays as it is).
- [x] Pilot migration: `shodan`. `_get` is now an adapter over
      `ProviderClient.get_json`; `_retry_after` and its imports are gone,
      `_reserve`, `_pace_provider_request` and the 403+credit table stay where
      they were. `ProviderLimits` carries today's constants explicitly
      (`max_attempts=3`, `max_retry_delay=30`), and
      `abort_when_retry_after_exceeds=None` keeps the old answer to a long hint —
      waiting it out at the ceiling and retrying, rather than abandoning the call.
      The 2 MB body bound arrived with the shared client and is asserted per
      connector here, so step 5's Shodan half is closed: the defect cannot be
      folded out of a refactor that replaces the read it lived in.
- [ ] `dns_security`.
- [ ] `hibp` (still decodes an unbounded body — the remaining half of step 5).
- [ ] Full backend fast suite green on CI (the pilot is green in
      `test_connector_runtime.py`, `test_connector_provider_client.py` and
      `connectors/dns_security/test_shodan_dns.py`).
