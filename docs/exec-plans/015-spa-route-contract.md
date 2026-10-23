# Plan 015 — the paths the SPA calls, against the routes the API serves

**State:** done — 2026-10-23: 109 calls checked, and a renamed route fails the gate at the helper that calls it

## Goal

The audit closed with one sentence in [the readiness page](../production-readiness.md)
that it could not make false at the time: *"Endpoint paths are string literals, so removing a backend
route does not fail any build."* It is limitation 5 there, and the same fact is the
evidence line of AUD-060 in [the register](../audit-findings.md):

> the paths and verbs are right (all 99 calls match a live route)

That number was true on the day it was measured and nothing recomputes it. It is the
audit's own fifth root cause — *a number in the prose that nothing recomputes* —
sitting in the register's evidence column, and it is the last unchecked link in the
chain that connects the browser to a handler:

| Edge | Checked by |
|---|---|
| page → `endpoints` helper | `tsc -b`, and `frontend/src/lib/endpoints.test.ts` pins method, path, query and body |
| helper → response shape | `backend/scripts/check_api_types.py` rule 2, against the OpenAPI models |
| helper → **route** | nothing |
| route → `docs/api.md` | `tests/test_api_docs_contract.py` (both directions) |
| route → capability | `tests/test_route_access_gate.py` |

A route renamed in `app/api/v1/routers/` is therefore invisible to the client: the
helper keeps its literal, the TypeScript compiler sees a string, the backend suite sees
no caller, and the page fails in the browser with a 404 the build called success. The
readiness page already names the remedy for the *class* — generate the client from
`/openapi.json` — and this plan does not attempt that, because it would replace 109
hand-written calls with a generator that has its own surface. It closes the half that
can be closed today: the paths the client writes are compared with the route table the
application publishes.

## Plan of Work

| File | Change |
|---|---|
| `backend/scripts/check_api_types.py` | a third rule: every call in `frontend/src` names a path (and verb) the OpenAPI document serves; the extracted call count has a floor so a parser that stops matching cannot pass |
| `backend/tests/test_api_types_gate.py` | the new rule's proof — literal extraction through generics and chained calls, template parameters, verb mismatch, a non-literal argument, a pre-prefixed path, the floor, and the real tree |
| `docs/production-readiness.md` | the "what is enforced" row for `check_api_types.py` grows the path check; limitation 5 narrows to what is actually still open |
| `Makefile` | the `help` line for `check-api-types` names what it now compares |
| `docs/exec-plans/README.md` | one row for this plan; and 007's row stops saying a run is outstanding that ran on 2026-10-21 and again on 2026-10-23 |

## Concrete Steps

1. **The rule, and the reproduction first.** Before the rule exists, the tree passes
   `python scripts/check_api_types.py` with a route renamed: the gate reads response
   *fields*, and a path is not a field. Reproduce it on a scratch copy of the router
   (rename `DELETE /users/{user_id}` to `/users/{user_id}/purge`), show
   `check_api_types.py` still prints OK, then restore. That is the instance; the rule
   is the class.
2. **Extraction.** One scanner over every `.ts`/`.tsx` file under `frontend/src`
   (tests excluded) finds `api.<verb>` — including the chained `api` newline `.post`
   shape the file uses — skips a generic argument that may contain braces, brackets or
   an arrow function, and reads the first argument when it is a string or template
   literal. A template interpolation (`${id}`) is a path parameter by any name. A call
   whose first argument is a variable, or whose path already carries `/api/v1`, is
   reported rather than skipped: the gate's silence has to mean "checked".
3. **Comparison.** Paths are normalised on both sides (any `{...}` or `${...}` is the
   same slot) and compared with `app.openapi()["paths"]`, verb against verb. The prefix
   is the client's own default, `/api/v1`, which every shipped build sets and
   `frontend/src/lib/api.ts` falls back to.
4. **The floor.** The gate refuses a corpus smaller than `MINIMUM_CALLS`, so a change
   of call style that hides calls is a failure and not a quieter run.
   *Acceptance:* the rule reports the renamed route from step 1 with its file and line,
   and the real tree passes with the count printed.

## Validation and Acceptance

- [x] Each new test was red before the rule existed and is green after it: nine
      failed on `AttributeError: module 'scripts.check_api_types' has no attribute
      'calls_in'` (and the three existing tests stayed green), then `17 passed`.
- [x] `python scripts/check_api_types.py` passes on the tree and prints how many calls
      it checked: **109** (101 in `lib/api.ts`, 8 in `JobsTable.tsx`, `lib/connectors.ts`,
      `lib/findings.ts` and `lib/modules.ts`).
- [x] Renaming one route makes the same command fail, naming the helper's file, line,
      verb and path — run against the finished gate:
      `lib/api.ts:599: DELETE /api/v1/users/${id} — /api/v1/users/{user_id} serves
      GET, PUT` (exit 1; the router was restored immediately after).
- [x] `make check-api-types` and the `backend` job are unchanged (same script, same
      invocation), and the gates that read the edited pages stay green: 125 passed
      across the documentation consistency, documentation numbers, page-routes,
      audit-register, skip-inventory, audit-map and documented-CLI suites.
- [x] The readiness page no longer claims the path literals are unchecked, and
      limitation 5 names only the part that remains (the client is still hand-written;
      a route *added* without a caller is not a defect this gate looks for).
- [x] `ruff` clean on the two changed Python files, and the mypy ratchet reports
      `0 errors (baseline 0)` — `app` is the only target, and no application file
      changed.

## Progress and Milestones

- **2026-10-23 — opened.** Reproduced with a throwaway scanner over the shipped client:
  101 `api.<verb>` calls in `frontend/src/lib/api.ts` and 8 in
  `components/JobsTable.tsx`, `lib/connectors.ts`, `lib/findings.ts` and `lib/modules.ts`,
  compared with `app.openapi()["paths"]` — all 109 agree today, which is what makes the
  gate worth writing rather than a list of repairs. The scanner also found the shapes
  the rule has to read: chained calls (`api` then `.post<T>(`), generics carrying braces
  (`<{ codes: string[] }>`) and parameters spelled `${encodeURIComponent(id)}`.
  Before writing the rule, the reproduction: with `DELETE /users/{user_id}` renamed to
  `/users/{user_id}/purge` on a scratch copy, `scripts/check_api_types.py` still printed
  OK, exit 0.
- **2026-10-23 — closed.** The rule reads the calls, the tests drive every decision,
  and the reproduction is the same rename run against the finished gate: it printed
  `lib/api.ts:599: DELETE /api/v1/users/${id} — /api/v1/users/{user_id} serves GET, PUT`
  and exited 1, which is the answer a reader needs at the moment the build goes red.
  The scanner needed three readings the first attempt did not have — the chained `api`
  newline `.post` form (16 of the 101 calls in `lib/api.ts` are written that way),
  generics carrying braces or arrays, and the line of the *path* rather than of `api` —
  and each is now a test.
