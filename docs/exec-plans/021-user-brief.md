# Plan 021 — the route that declared itself a dict

**State:** done — 2026-10-23: `GET /users/brief` declares `UserBriefResponse`, the
inventory is 21

## Goal

`GET /users/brief` did not merely answer a dict — it said so in the decorator:
`response_model=list[dict]`. That is an explicit statement that the payload is
whatever the handler returns, in an endpoint whose whole purpose is the four fields
three checkboxes need (`id`, `email`, `role`, `is_active`). The SPA declares exactly
those four as `UserBrief`, and nothing compared them.

Measuring the same shape across the tree found **eleven routes that declare
themselves unmodelled**:

| Router | Routes |
|---|---|
| `connectors.py` | `GET /me/credential`, `POST /me/quota/virustotal`, `POST /me/complete/{job_id}`, `POST /me/heartbeat`, `GET /health`, `GET /modules` |
| `phishing.py` | `POST /scan/dnstwist`, `POST /scan/shodan` |
| `dns_security.py` | `GET /certificate-exceptions` |
| `reports.py` | `POST /generate` |
| `users.py` | `GET /brief` |

Four of those are the connector protocol (`/me/credential`, `/me/quota/virustotal`,
`/me/complete/{job_id}`, `/me/heartbeat`) — connector-facing, documented where a
connector author looks, and not read by the SPA at all. The other seven are read by
the browser and six of them are in the inventory already. This plan takes the
smallest, so the eleven become ten and the pattern for the rest is written down.

## Plan of Work

| File | Change |
|---|---|
| `backend/app/schemas/user.py` | `UserBriefResponse` — the four fields, with the same enum coercion `UserBase` uses |
| `backend/app/api/v1/routers/users.py` | `response_model=list[UserBriefResponse]` replaces `list[dict]` |
| `backend/scripts/check_api_types.py` | the `UserBrief` pair, its `UNMODELLED` entry deleted, the count 22 → 21 |
| `docs/production-readiness.md` | the limitation says 21 |
| `docs/exec-plans/README.md` | one row for this plan |

## Concrete Steps

1. **Red first.** Declare the pair and delete the inventory entry before the model
   exists: the gate reports the missing model and the read of a route that declares no
   model — and the route *could not* be rescued by adding an entry back, because its
   `response_model` is what has to change.
2. **The model.** `UserBriefResponse` in `schemas/user.py` beside `UserResponse`, using
   the same `EmailAddress` and `UserRole` types and the same
   `use_enum_values=True`, so `role` serializes as `"admin"` rather than
   `UserRole.ADMIN`. It is deliberately not `UserBase`: that model carries
   `full_name` and `rate_limit_minutes`, and adding them to this payload is a change
   nothing asked for.
3. **The route.** Replace `list[dict]` with `list[UserBriefResponse]`; the handler's
   `str(r.id)` becomes redundant against a `uuid.UUID` field but stays harmless, and
   the test that asserts the payload is what proves it.
   *Acceptance:* the gate is green, the entry is gone, and the endpoint answers the
   same four keys.

## Validation and Acceptance

- [x] Red before the model, green after: `14 interfaces`, `21 routes`.
- [x] The payload is unchanged: the four keys and their JSON types are what the
      handler built (`id` as a string, `role` as a string, `is_active` as a boolean),
      and the settings and users suites that read this endpoint are green.
- [x] `tests/test_api_types_gate.py`'s inventory test passes, so the deletion is
      justified by a route that declares a model.
- [x] `ruff` clean; the mypy ratchet reports its baseline; `tsc -b` is unaffected
      because the client's interface did not change.
- [x] The documentation gates that read the edited pages stay green.

## Progress and Milestones

- **2026-10-23 — opened.** The eleven explicit `response_model=dict` declarations are
  the measurement; six are the connector protocol and are not the SPA's contract, and
  the five browser-facing ones were already in the inventory.
- **2026-10-23 — closed.** Ten routes still declare themselves unmodelled: four are
  the connector protocol, and six are browser reads (`/connectors/health`,
  `/connectors/modules`, `/dns/certificate-exceptions`, both phishing scan routes and
  `/reports/generate`). Those six, then the composed payloads (`DashboardOverview`,
  `AuditIntegrity`) whose models are contracts of their own.
