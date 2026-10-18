# ExecPlan 005 — Connectors: the last unbounded body, and the gate that keeps it the last

## Goal

Plans [003](003-connector-provider-runtime.md) and
[004](004-remaining-provider-runtimes.md) closed four places where a worker read a
third party's body without a limit, and moved every provider call onto one client
that reads under a bound. One place was left, found while writing 004's report and
not part of either plan:

`ShodanConnector._fetch_favicon` — the connector's only request to a **target**
rather than to its provider — used `client.get(...)` and then sliced the result
(`r.content[:_FAVICON_MAX_BYTES]`). The limit existed; it was applied to a body
that was already complete, which is the buffering a limit exists to prevent. The
bytes come from a host the inventory names, so they are as untrusted as the URL.

Closing it is one commit. Making sure a fifth instance cannot appear is the rest of
this plan: a **source-level gate** over the connector tree, so a new worker that
reaches for `response.json()` fails on CI instead of passing review.

Both halves are written: the defect is fixed in this plan's first commit and the
gate is in the second, wired into CI. What remains open is the one decision the
gate's evidence was meant to settle — whether the SDK should also read the
*platform's* own answers under a bound — and that is recorded in Progress rather
than left to a reader.

## Inventory — every remaining body read in the connector tree

| Where | What it reads | Allowed? |
|---|---|---|
| `connectors/base/opendrp_connector/base.py` L411, L523-525, L576, L606, L629 | the **core's** own API (`_request`, `_request_with_retry`, the session helper) | yes — but see below |
| `connectors/dns_security/main.py` L1197 | core: `GET /me/credential` | yes, same reason |
| `connectors/hibp/main.py` L753 | core: the connector's credential read | yes |
| `connectors/intelligence/main.py` L276, L348 | core: credential read, quota reservation | yes |
| `connectors/shodan/main.py` L558 | core: quota reservation answer | yes |
| `connectors/shodan/live_check.py` L106 | a **provider** body, in the operator-run diagnostic CLI | no — should use the shared reader |
| `connectors/**/main.py`, `providers.py`, `endpoint_providers.py` | provider bodies | already bounded: every call goes through `ProviderClient` |
| `connectors/shodan/main.py` `_read_favicon` | a **target's** body | bounded as of this plan's first commit |

Two things this table says:

1. **Most remaining reads are the platform's own API.** They are not the same risk
   as a third party's, and a gate that ignored the difference would either be
   useless or would force five rewrites that change nothing. The core's own
   responses are still worth a bound — a misconfigured base URL or a compromised
   core is not a trusted peer — but that belongs in the SDK, once, not per caller.
2. **One diagnostic tool reads a provider body unbounded.** `live_check.py` is run
   by an operator with a real key, not by the platform, so it is a lower risk; it
   is in the table so that "everything is bounded" is true rather than nearly true.

## Plan of Work

### Step 1 — the last defect (done)

`_fetch_favicon` streams with `client.stream(...)` and reads through a new
`_read_favicon`, which stops at `_FAVICON_MAX_BYTES`. What it returns is the same
truncated slice as before — an icon that is too large is a fact about the target,
and half an icon hashes to something that is not an icon — so the observable
behaviour is unchanged and only the memory held changes. A test sends eight
half-megabyte chunks and asserts four are read.

### Step 2 — the gate: a rule this tree can actually check

The rule, stated so it can be enforced by reading the source:

> No module under `connectors/` outside the SDK reads a response body through
> `.content`, `.text` or `.json()` unless the response came from
> `self._request(...)` — that is, from the platform's own API. A body from
> anywhere else is read by a bounded reader.

Implementable in `scripts/check_connector_body_bounds.py` with `ast`, because the
core case is syntactically visible: the receiver is either a name assigned from
`await self._request(...)` or the call itself inlined. No dataflow beyond one
local assignment is needed, and there is no file-level allowlist — an allowlist is
where a gate goes to die.

The gate needs three things the repo already asks of its gates:

- it runs in CI (`.github/workflows/ci.yml`, next to the docs and version gates);
- it has its own test, like `test_docs_consistency_gate.py` has, that feeds it a
  file with an unbounded read and a file with an allowed one;
- it prints the file and line of every violation, because a gate whose failure
  message is one line long gets disabled.

### Step 3 — the SDK reads the core's answer under a bound (only if the gate needs it)

If the gate cannot express the core exception cleanly, the alternative is to
remove the exception: the SDK gains one bounded reader, and the five core call
sites use it. That is the better end state — one reader for every body the
platform consumes — and it is deliberately a separate commit from the gate, so a
gate that turns out to be wrong does not drag the SDK with it.

### Deliberately not in this plan

- **The `Retry-After` policy.** Five workers answer "how long may a scan stall?"
  five different ways (`hibp` never retries, `exposure` and `intelligence` cap at
  5 s, `dns_security` abandons above 60 s, `shodan` waits to its ceiling). Each is
  defensible; converging them is a product decision about a scan's deadline, not a
  deduplication, and it deserves its own plan. What did happen here is that the
  numbers stopped being implicit:
  `backend/tests/test_connector_provider_limits.py` pins all five workers' limits
  in one table, with the reason for each row beside it, so the policy change will
  arrive as a visible diff instead of a surprise — and so the divergence itself is
  documented somewhere a reader can find it.
- **The release.** `dev` is 30+ commits ahead of `main`; shipping is a separate
  decision from this refactoring.
- **`dns_security`'s four clients and three timeouts.** Same reason: changing them
  changes how long a source may take.

## Concrete Steps

1. `_fetch_favicon` streams under the bound, `_read_favicon` added, the two
   transport fakes in `backend/tests/test_connector_runtime.py` learned to stream,
   and a new test asserts the read stops at the bound. **Done in this plan's first
   commit; existing assertions unchanged.**
2. Write `scripts/check_connector_body_bounds.py` and its test.
3. Wire it into CI next to the docs gate; run it on this tree and fix what it
   reports (expected: `shodan/live_check.py`, and nothing else outside `base/`).
4. Decide step 3 (SDK-wide bounded core read) on the evidence from step 3's run.

## Validation and Acceptance

| Check | Command / file |
|---|---|
| The defect | `backend/tests/test_connector_runtime.py -k favicon` |
| The gate | `python scripts/check_connector_body_bounds.py` on this tree |
| The gate's own test | `backend/tests/test_connector_body_bounds_gate.py` (new) |
| Connector contracts | `backend/tests/test_connector_runtime.py`, `test_connectors_protocol_api.py`, `test_connector_provider_client.py` |
| Lint / types / docs | `ruff check app ../connectors`, `python -m mypy app`, `scripts/check_docs_consistency.py` |

Acceptance criteria:

- the favicon read never holds more than the bound in memory, and returns the same
  truncated slice as before for the same body;
- the gate fails on a module that reads a provider body directly, and passes on a
  module that reads `self._request(...)`'s answer — both asserted by its test;
- the gate reports every violation with its file and line;
- no connector's existing test changes an assertion to satisfy the gate.

## Risks

| Risk | Mitigation |
|---|---|
| A static rule cannot see a body read that goes through a helper | the gate is a floor, not a proof: it catches the shape every defect in this repo actually had (a direct attribute read) |
| The gate's core exception is too clever to read | fall back to step 3 — one bounded reader in the SDK, no exception at all |
| `live_check.py` is hard to migrate without network | it is a CLI; the migration is mechanical and its test, if any, drives a fake transport |
| A gate in CI slows the job | it parses a few dozen small files; it belongs next to the other cheap gates, not in the backend suite |

## Progress and Milestones

- [x] `_fetch_favicon` bounded read + test (`_read_favicon`): eight chunks sent,
      four read, the same truncated slice returned.
- [x] `scripts/check_connector_body_bounds.py`, with its own test
      (`backend/tests/test_connector_body_bounds_gate.py`, 9 cases) that builds a
      tree demonstrating each violation the rule names, and asserts the shipped
      tree is clean — which is what keeps the gate from being a rule nobody
      satisfies.
- [x] CI wiring: the step sits in `repo-hygiene` next to the documentation gate,
      because it parses source and needs no environment.
- [x] `connectors/shodan/live_check.py` reads its provider body through the shared
      client, which was the gate's first and only finding. One attempt is stated
      explicitly: the tool's ceiling counts physical requests, and a retry would
      spend a second one on a question already answered.
- [x] **Step 3 was not taken, on the gate's evidence.** The rule as written
      expressed the core exception structurally — a name bound from
      `self._request(...)` — and every core read in the tree is exactly that shape,
      five of them, so the SDK-wide bounded reader would have added a dependency
      for no behavioural gain. Recording it here so the next session does not
      re-open it as a missing step. If the core ever answers with something the
      platform cannot bound, the SDK is where that bound goes — it owns the only
      reader that is allowed to touch a body unboundedly, because it *is* the
      reader.
