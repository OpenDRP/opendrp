# Plan 020 — the diagnostics payload an operator reads

**State:** done — 2026-10-23: `GET /settings/runtime` declares a model, the inventory is 22

## Goal

`GET /settings/runtime` answers the self-host question the Settings page exists to
settle: *did the recreated container receive my setting?* The handler builds a dict of
five keys, two of them nested objects of three numbers each, and the SPA types it as
`RuntimeConfiguration`:

```
{app_env, version, database_pool: {size, max_overflow, pool_timeout_seconds},
 timeouts: {statement_ms, command_seconds, outbound_dns_seconds}, resource_limits_source}
```

Nothing about the route is wrong. What is missing is the declaration that makes the
client's copy checkable: the numbers come from `core_settings`, and a setting renamed
or dropped in `app/core/config.py` changes this payload with only the page noticing.
That is the same class the plan 015 rule closes for paths and rule 2 closes for
modelled routes, and this route is the last settings payload in the inventory.

It is also the easiest remaining entry, which is why it is next rather than the
composed ones: the payload has no variants, no unions and no ORM objects, and both
nested objects are plain scalars. Modelling it is two small classes and one wrapper,
and the bytes cannot move because every key is already present.

## Plan of Work

| File | Change |
|---|---|
| `backend/app/schemas/settings.py` | `DatabasePoolSettings`, `RuntimeTimeouts`, `RuntimeConfigurationResponse` |
| `backend/app/api/v1/routers/settings.py` | `response_model=RuntimeConfigurationResponse` on `/runtime` |
| `backend/scripts/check_api_types.py` | the `RuntimeConfiguration` pair, its `UNMODELLED` entry deleted, the count 23 → 22 |
| `docs/production-readiness.md` | the limitation says 22 |
| `docs/exec-plans/README.md` | one row for this plan |

## Concrete Steps

1. **Red first.** Declare the pair and delete the inventory entry before the model
   exists: the gate reports a model the OpenAPI document does not have and a read of a
   route that declares none.
2. **The three models.** The two nested objects get their own classes so their field
   names are in the document rather than in a nested dict schema, and the wrapper names
   the five top-level keys. Types mirror the settings they read: the pool size, the
   overflow and both integer timeouts are `int`; `DB_COMMAND_TIMEOUT_SECONDS` and
   `OUTBOUND_DNS_TIMEOUT_SECONDS` are `float` in `core/config.py` and stay `float` here,
   so `3.0` is serialized as `3.0` exactly as it is today.
3. **The route.** `response_model=RuntimeConfigurationResponse`, with the handler's
   docstring untouched — it is the operator-facing explanation of why secrets are
   absent, and this plan does not change what is exposed.
   *Acceptance:* the gate is green, the entry is gone, and the endpoint answers the
   same JSON — the settings reliability suite reads `app_env`, the pool and the
   timeouts from it.

## Validation and Acceptance

- [x] Red before the model, green after: `13 interfaces`, `22 routes`.
- [x] The payload is unchanged, including the two floats: the model's own round-trip
      over the handler's dict is equal to it, and
      `tests/test_settings_reliability.py` (which asserts the documented sections) is
      green.
- [x] `tests/test_api_types_gate.py`'s inventory test passes, so the deletion is
      justified by a route that declares a model.
- [x] `ruff` clean; the mypy ratchet reports its baseline; `tsc -b` is unaffected
      because the client's interface did not change.
- [x] The documentation gates that read the edited pages stay green.

## Progress and Milestones

- **2026-10-23 — opened.** Last settings entry, smallest remaining shape: five keys,
  two of them objects of scalars.
- **2026-10-23 — closed.** The settings router now has no unmodelled response at all;
  the remaining 22 are the dashboard, audit, connector, asset and scan payloads, each
  of which needs its own decision about what it promises.
