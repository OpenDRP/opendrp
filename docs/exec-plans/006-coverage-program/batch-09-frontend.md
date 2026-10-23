# Batch 09 — The SPA

**State:** done — functions 76.53%, floor raised 55 → 73, closing run green

**Scope:** the frontend suite's own floors, measured over every source file rather
than the files a test happened to import (`frontend/vite.config.ts`).

**Baseline:** the `frontend` job of the CI run on `main` (2026-10-19): 38 files,
248 tests, statements 72.93%, branches 72.91%, functions 59.38%, lines 77.8%,
against floors 70/70/55/75.

Functions were the outlier: four points above the floor while every other axis had
twenty points of margin. That gap was ordinary — a component's handlers are not
called by a render test — which is why this batch started there.

**First move**

```bash
cd frontend
npm run test:coverage
```

Then read the coverage table it prints, and pick the files whose uncovered
functions change what an operator sees: the alert budget form, the asset detail
page's per-module counts, and the DNS & TLS review page.

The suite had already grown to 52 files and 477 tests by the time this batch was
executed, so the three named files were read against their current numbers rather
than the baseline's: `AlertBudgetPanel.tsx` was already at 100% of its ten
functions, `AssetDetailPage.tsx` at 82.35% and `DNSSecurityPage.tsx` at 76.74%.

**Work items**

- [x] One test per interactive branch that changes a request: submit, cancel,
      refuse-on-validation, and retry after a `503 database_busy`.
- [x] The currency of a rendered fact: a timestamp shows the stored UTC instant, a
      count that is zero renders zero rather than a blank, and a truncated section
      says so.
- [x] Raise the functions floor to the measured value minus three points, and leave
      the other three floors untouched.

**What executed, and why each test is a behaviour rather than a line**

- `AssetsPage.test.tsx` — a refused read (`503 database_busy`) shows the sentence
  that names the condition and offers a retry that asks again; the import report
  says when it is showing the first 100 of 150 lines and where the rest is. Both
  are operator-facing answers that a client rewrite can silently lose.
- `AssetDetailPage.test.tsx` — a failed findings read is retried and the rows
  replace the error; `Refresh` re-reads the module the operator has open (not the
  first tab) at the current page.
- `DNSSecurityPage.test.tsx` — a refused promotion, deletion and orphan cleanup
  each report the server's own sentence instead of failing silently, and a refused
  deletion leaves the row on screen. The evidence badge is asserted for the three
  shapes the row can carry (provider-scored `Suspicious · 9` with its tooltip,
  clean `Reputation`, `Served certificate · 3 records`), because the count is what
  triage compares between rows.
- `components/Auth/MfaEnrolment.test.tsx` — the second-factor flow had no test of
  its own: a session alone cannot start enrolment (the password is required
  first), a wrong password and a wrong code both keep the form and the secret on
  screen, cancel enables nothing, and the recovery codes are shown once and only
  left behind after the operator confirms they saved them. This is the gap among
  the numbers that costs a credential rather than a pixel, so it was closed here
  even though it was not one of the three files the batch named.
- `pages/UsersPage.test.tsx` — an administrator's password reset is sent as
  `new_password` (the camelCase field would be dropped by the API and the reset
  would quietly not happen), a checked box with no value is refused before the
  request, and cancelling the edit dialog sends nothing. A reset is a credential
  change, so a form that looks like it worked is the worst outcome here.
- `pages/SecurityPage.test.tsx` — a password change whose two fields disagree is
  refused before anything is sent, a successful one adopts the session the API
  returned (the change revoked the old refresh family) and clears the fields, and
  `Sign out other sessions` reports what it ended. The first two are the failure
  modes that lock an account holder out of their own account.
- `lib/endpoints.test.ts`, `lib/registryHelpers.test.ts`, `lib/errors.test.ts`,
  `components/ui/toaster.test.tsx` — the request each endpoint builder sends, the
  registry and finding helpers the connector pages call (a mistyped route there
  hands an operator a token they can never use), the two `503` codes and the
  correlation id an error line quotes, and the toast host that renders a raised
  message with its title and description — every page's failure line goes through
  it, and the page tests mock `toast` itself, so nothing else asserts that host
  exists.

**Measured**

Run on the closing tree: 53 files, 495 tests, all passing.

| Axis | Baseline | After | Floor |
|---|---|---|---|
| statements | 72.93 | 81.17 | 70 (unchanged) |
| branches | 72.91 | 75.87 | 70 (unchanged) |
| functions | 59.38 | 76.53 | **73** (was 55) |
| lines | 77.8 | 83.71 | 75 (unchanged) |

The floor is the measured value minus three points and rounded down: 76.53 − 3 =
73.53 → 73. The other three axes were left alone deliberately — they already carry
five to ten points of margin, and raising a floor that no ordinary change threatens
only moves the tripwire into the way of valid work.

**Done when**

- [x] functions coverage is at or above 65% and the floor is raised (76.53%, floor 73);
- [x] `npm run test:coverage` and the production build are green;
- [x] the batch file records which uncovered functions are unreachable by design.

**Functions that remain uncovered, and why**

- `src/components/ui/dropdown-menu.tsx` — 0%. The whole file is Radix re-exports
  wrapped in `forwardRef`; every remaining function body only runs inside a
  pointer-driven portal that jsdom cannot open. Covered instead at the contract the
  application uses (`ThemeProvider.test.tsx` replaces the menu with the `onClick`
  contract `ThemeToggle` relies on), which is why this file is measured by the
  denominator but not by a test.
- `src/lib/audit.ts` (39.65% of functions) — the page that renders it is covered;
  what is not are the formatters for `details` shapes no fixture produces yet
  (per-provider catalogue diffs, archive verifications). This is a candidate for
  the sweep after this program rather than a deliberate miss.
- `src/pages/SecurityPage.tsx` moved from 46.66% to 73.33% of functions with the
  change-password and revoke-others tests; what is left is the recovery-code
  rotate handler and the copy button, whose server-side counterparts are pinned
  in `backend/tests/test_mfa.py`.
- `src/pages/UsersPage.tsx` moved from 54.54% to 60.9% with the password-reset
  test; what is left is the invitation and bulk-action wiring inside the same
  dialog, which the invitation and bulk suites reach through their own mocks.
- `src/pages/PhishingPage.tsx` (55.4%) — per-row action handlers behind a
  selection that the existing tests do not build; the report, verdict and evidence
  suites drive the same page through its filters and dialogs, so what is left is
  the row-level closures rather than the transport.
- `src/components/ui/*` (`avatar.tsx`, `form.tsx`, `select.tsx`, `table.tsx`,
  `separator.tsx`) — single branch bodies for a className or an empty state; a
  test would assert Tailwind strings.

**Progress log**

| Date | Change | Measured (stmt / branch / func / line) |
|---|---|---|
| 2026-10-19 | batch written from the CI baseline | 72.93 / 72.91 / 59.38 / 77.8 |
| 2026-10-20 | `endpoints`, `registryHelpers`, error mapping, toaster, asset list refusal and truncation, asset detail retry/refresh, DNS refusals and evidence badges, MFA enrolment | 79.86 / 75.07 / 75.17 / 82.51 |
| 2026-10-20 | MFA enrolment suite added (7 tests); change-password and revoke-others tests (3) | 80.69 / 75.36 / 76.08 / 83.18 |
| 2026-10-20 | administrator password-reset and edit-dialog cancel tests (2) | 81.17 / 75.87 / 76.53 / 83.71 |
| 2026-10-20 | floor raised to 73; `npm run test:coverage` and `npm run build` green | 81.17 / 75.87 / 76.53 / 83.71 |
