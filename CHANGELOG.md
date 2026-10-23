# Changelog

All notable changes to OpenDRP are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The version in `backend/app/__init__.py` is the single source of truth;
`scripts/check_version_consistency.py` fails the build if this file disagrees
with it.

## [Unreleased]

### Added

- Accounts can be created by invitation, so the first password is one only its
owner has ever seen: `POST /api/v1/users/invite` creates the account and
`POST /api/v1/users/{user_id}/invitation` replaces a lost link, both returning
the single-use token once while the database keeps only its digest and a
seven-day expiry. The owner opens `/accept-invitation`, chooses a password, and
`POST /api/v1/auth/accept-invitation` spends the link in one transaction — new
hash, cleared invitation, revoked refresh families and an
`auth.invitation.accepted` row. Unknown and expired links answer identically, and
the invitation is mailed over the alert transport when SMTP and a non-loopback
origin are configured (the administrator can still copy the link themselves).
The user table gains an `Invite user` action and a `Resend invitation` action for
a pending or expired link.
- The inventory page now drives the batch endpoint from row selection: activate,
  deactivate and one criticality change travel as a single request, and a batch
  delete stays administrator-only and requires typing `DELETE`. Selection is
  limited to the current page by design.
- A breach or phishing finding can be taken under monitoring from its row: the
  value the module already matched becomes an asset through the same per-user
  throttle and audit trail as the DNS and exposure promotions, with
  `<module>.asset.promoted` / `<module>.asset.already_exists` events.
- The dashboard loads as one request: `GET /api/v1/dashboard/overview`
  returns its summary, connector health and channel health together, produced by
  the same functions the standalone endpoints call. A page load is now one HTTP
  request, one transaction and one `dashboard.view` audit row instead of three of
  each — the audit chain lock is taken by the row's transaction, so the old page
  also paid three acquisitions of it per load. `/dashboard/stats`,
  `/connectors/health` and `/alerts/health` keep their own contracts, and a
  probe the outbound policy refuses still records `outbound.blocked`.
- The dashboard timeline is built from the module registry instead of a
  hardcoded pair of tables: `timeline_series` names every counted module with the
  label the registry gives it, `timeline_excluded` names the modules left out and
  why (`current_state_observations` for DNS Security and Exposure), and
  `timeline_comparison` carries each series' total for the 30 days before the
  window. A module stored through the generic adapter is counted from
  `drp_findings` by module id, so a newly declared module appears in the chart —
  lines, legend, caption and empty state — without a core or frontend release.
- `GET /connectors/health` reports a core-computed `blocked_reason`
  (`provider_account_missing`, `account_policy_unapproved`, or `null`), so an
  operator can see why a provider connector cannot scan without reading the
  worker's readiness report.
- GIN trigram indexes cover the phishing candidate's domain, matched asset and
  IP address, so the substring search no longer scans the table. Adopted
  databases take the idempotent `CREATE INDEX` statements from
  [docs/upgrading.md](docs/upgrading.md).
- `POST /api/v1/users/{user_id}/unlock`, with an `Unlock` action next to the
  locked badge, releases a brute-force sign-in lockout without touching the
  password, role, active flag or second factor. It writes one `user.unlocked` row
  with `method=brute_force_unlock`; the factor's own counter stays where it was,
  because releasing it would hand extra guesses at the code to whoever already
  has the password.
- The user payload carries `last_login_at` (`null` means "never signed in"), the
  admin table shows it as `Last sign-in` with an explicit `never`, and
  `GET /users?signed_in=false` answers the access-review question from the
  database rather than from the current page.
- An administrator's reset of a password, clear of a second factor, deactivation
  or deletion now tells the account holder by email, scheduled after the mutation
  commits and delivered over the alert transport. The outcome is recorded as
  `user.notification.sent` / `.failed` / `.skipped`; a missing or broken SMTP
  server leaves the mutation successful, and the message never contains the
  password, a hash, a TOTP secret or a recovery code.
- `GET /api/v1/users/export` writes the user list behind the same filters as the
  table, as CSV or JSON, for access review: role, activity, factor enrolment,
  last sign-in and the onboarding step still owed, capped at 10 000 rows. It
  names its columns explicitly, so a hash, TOTP secret or recovery code cannot
  arrive in the file, and records `users.export` with the filter and row count.
- Administrators can read another account's sessions (`GET
  /api/v1/users/{id}/sessions` — ids and times, never tokens) and end all of
  them (`DELETE`), recorded once as `user.sessions.revoked`. The account's own
  sessions stay on the self-service page, which keeps the current browser.
- The user list has the three support slices as filters — owes onboarding, no
  second factor, locked out — and answers them in SQL; an expired lockout is not
  reported as locked, because the column keeps its old deadline.
- Activation changes can be applied to a selection: `POST /api/v1/users/bulk`
  activates or deactivates up to 100 accounts in one transaction with one
  `users.bulk` row, revokes the sessions of the deactivated accounts, and refuses
  the batch (rather than applying part of it) for the caller's own account, an
  unknown id, or a selection that would leave no active administrator.
- The dashboard opens with a **Platform status** block: database and Redis from
  the same probes `/ready` calls, `audit_degraded` (the condition `/ready`
  answers 503 on), connector enabled/disabled/silent counts with the longest
  silence, the age of the oldest running job, and the delivery queue's pending,
  ambiguous, failed, stuck and waiting counts. It is an additive `platform`
  field of `dashboard/stats`, computed inside that request, so the page makes no
  fourth HTTP call and writes no additional `dashboard.view` row.
- The dashboard's three charts have states instead of a guess: a skeleton while
  the query is in flight, the failure in place of the chart, and "no findings"
  only when the series' own total is zero. The timeline's empty state was
  previously unreachable — the server always returns 30 calendar days, and each
  card tested the *length* of the array, so the first paint of the most-opened
  page asserted "No findings recorded in the last 30 days" before the answer
  arrived. Each chart now carries `role="img"` naming the series and window it
  draws, plus a visible total, so the numbers are not available only to sighted
  users.
- The readiness page's skip count is an inventory a check enforces: every place in
  `backend/tests` that can turn a test into a skip is listed there with the cause
  it belongs to, and `tests/test_skip_inventory_gate.py` fails when the tree and
  the page disagree in either direction — an unlisted skip site, a row for a site
  that no longer exists, a cause count that no longer matches, or a `tests/...`
  reference that does not resolve. Sites are named `file::function` rather than
  `file:line`, so an insertion above one no longer rots it, and the application
  tree is asserted to contain no skip call at all.
- A staged audit has a map and a partition it cannot silently lose: `docs/project-map.md`
  records the layers, the trust boundaries, the measured size of every area and the
  settled decisions an audit must not re-litigate, and `docs/exec-plans/009-staged-audit.md`
  splits the whole tree into 29 steps of at most 3,000 lines each, every step ending
  with a written handoff. `tests/test_audit_map_gate.py` fails when a production file
  belongs to no step or to two, when a step names a path that has moved, or when a
  step stops stating its surface, questions and exit.

### Changed

- The certificate review names every hostname a sighting was reported for. One
  certificate served for several names at one address is one sighting, and the
  issuance rules already judged each of those names; the row printed only the one
  that created it, so a reviewer of a shared address could not see the neighbour the
  rules had acted on.
- The interface's accent and destructive colours are darker, because the ones they
  replaced could not carry their own labels. Measured from `index.css`: white on the
  accent was 2.30:1 in light mode and 2.32:1 in dark, white on the destructive fill
  3.60:1, and the focus ring 2.30:1 against the page — under the 4.5:1 and 3:1 WCAG
  floors on every primary button, default badge, tooltip, field message and the one
  toast variant that says a request was refused. The accent is 30% lightness in
  light mode, the dark theme keeps its hue with an ink foreground (8.6:1), the
  destructive fill is 45%, and the hover fills are their own darker tokens instead
  of `bg-primary/90`, which blended toward the page and made a hovered button less
  readable than a resting one. `src/lib/themeContrast.test.ts` computes both themes
  from the stylesheet and fails with the ratio in the message.

- The connector documentation states how long a provider call may take: the four
  questions every worker answers (attempts, the longest single wait, the body
  bound, and whether a longer `Retry-After` abandons the call), the answer each
  worker gives, and why they differ — HIBP bills every request, Shodan bills a
  credit per page, DNS Security's CT phase has a hundred-request scan budget to
  protect, and the per-target workers cap one wait so a slow answer cannot eat a
  twenty-request budget. The numbers are unchanged; the table on the page is
  checked against the code table, so a value that changes without the page
  changing fails CI.
- The connector SDK owns the one bounded reader: `read_bounded` refuses the chunk
  that crosses a limit and `read_head` keeps at most the limit and stops reading.
  Every provider body goes through them, and so does the one body a worker reads
  from a *target* rather than a provider (Shodan's icon fetch), which had grown
  its own copy of the same loop. A body that crosses the bound raises the reader's
  own `BodyTooLarge` and is reported differently from a failed connection, because
  "the sender offered too much" and "the connection broke" are different facts.
  The CI gate that bans direct body reads in connectors now covers `.aread()` as
  well as `.content`, `.text` and `.json()`.
- A new CI gate reads the connector tree for the defect class the last four
  fixes belonged to: five separate times a worker took a third party's body in
  full and considered its size afterwards, or had no bound at all. The rule is
  now checked by machine — a body from anywhere but this platform's own API is
  read through a bounded reader, never through `.content`, `.text` or `.json()` —
  and its one exception (an answer from `self._request`) is syntactic, so there is
  no allowlist by file. The Shodan diagnostic CLI was the gate's first finding and
  now reads its provider answer through the shared client, one attempt per
  question.
- The Shodan worker's favicon fetch reads the icon under its size bound instead of
  after the fact: the request is the only one a connector makes to a *target*
  rather than to its provider, and it buffered whatever that host sent before
  slicing the first 2 MB. Eight half-megabyte chunks now yield four read and the
  same truncated slice as before — what changes is how much is ever held in
  memory.
- The intelligence worker makes its Netlas calls through the connector SDK's
  shared client, which is the last of the five copies of a pace, a quota
  reservation, a retry loop and a `Retry-After` parser. Its own numbers are stated
  rather than inherited — three attempts, a five second cap on one wait, a body
  bound of 2 MB, and a long hint waited out at that cap instead of abandoning the
  call. Its failure vocabulary is unchanged, because the codes are the module's
  decisions: the statuses stay `classify_http_error`'s (wired to the client as its
  classifier), a body that would not parse, one refused for its size and a failed
  transport come back through one explicit table, and the provider's own
  `Retry-After` is still reported to the core on the error it produced. A Netlas
  400 whose text says the key is unknown is still `invalid_credentials`. The
  provider's refusal text is still bounded, now at the 4 KB the shared client
  reads for classification instead of 8 KB.
- The exposure-endpoint worker makes its Netlas and Shodan lookups through the
  connector SDK's shared client, and the bound on what a provider may return is
  now enforced while the answer is being read instead of after: `client.get(...)`
  buffered the whole body and compared its length to 2 MB afterwards, so a
  provider-controlled 500 MB response was already in memory when the check ran.
  The numbers that were this worker's decision are stated rather than inherited —
  three attempts, a five second cap on one wait, and a `Retry-After` that is
  waited out at that cap instead of abandoning the call. The failure vocabulary
  is deliberately unchanged, because it is control flow here:
  `RECOVERABLE_ERRORS` decides whether the next target is attempted, so the
  shared client's names are mapped back onto the codes this worker already had.
  A Shodan 404 keeps meaning "not indexed".
- DNS Security makes every provider call through the connector SDK's shared
  client, which closes the third and last copy of a pace, a quota reservation, a
  retry loop and a `Retry-After` parser. Four of its own numbers are stated
  rather than inherited, because the shared defaults are a different product
  decision: four attempts instead of three, a sixty second ceiling on a single
  wait (a legitimate `Retry-After: 20` was being shortened to eight), the same
  sixty abandoning a call as `http_<status>_retry_later` rather than stalling a
  scan, and the timeout still taken from the client each source built — this one
  worker runs clients at 15, 25 seconds and Shodan's operator setting, and one
  shared number would have changed two of them. The RDAP bootstrap keeps its
  address pinning and TLS SNI name: the shared client carries the connection
  detail it is given (`extensions`) instead of resolving or pinning anything
  itself. A scan that has spent its own request budget still reports
  `request_budget_reached` with no request sent and nothing retried. One failure
  name changes: a timeout is now `network_timeout` rather than `network_error`,
  the vocabulary the other metered connectors already report.
- The HIBP worker's two ways of calling the provider — the path form and the body
  form — are now one, and the JSON body it returns is bounded at 2 MB: it used to
  decode whatever a provider sent back, which is the defect DNS Security never
  had and Shodan no longer does. What stays this provider's own is stated rather
  than inherited: one attempt, because HIBP bills a request whether or not it
  succeeds, and a `Retry-After` that pauses the bucket for the next call instead
  of driving a retry loop. A refusal still names the key as invalid in the
  readiness row, and an oversized or unparseable answer now reports
  `response_too_large` / `invalid_json` instead of looking like an empty result.
- The Shodan worker makes every provider call through the connector SDK's shared
  client, so its pace, quota reservation, retry loop and failure vocabulary are
  the mechanisms the other metered connectors use instead of a fourth copy of
  them. What was deliberate is unchanged: three attempts, a 30 second ceiling on
  any single wait, a `Retry-After` read in seconds or as an HTTP date, and a 403
  whose text names credits reported as `quota_exhausted` rather than as a
  permissions problem. One thing does change: an answer larger than 2 MB is
  refused as it is read instead of being decoded into memory — the bound DNS
  Security already had, with HIBP next to get it.
- Alert-channel health no longer dials SMTP and Telegram on every page load: a
  probe's result is reused for `ALERT_HEALTH_CACHE_SECONDS` (60 by default, `0`
  disables the cache), in Redis under a key hashed from that channel's settings,
  so editing the SMTP host or the bot token asks again and a burst of requests
  performs one handshake instead of one per operator. `last_checked_at` carried
  the response time and therefore always read "just checked"; it is replaced by
  `checked_at` (when the probe ran) and `from_cache`, and `probe_state` separates
  a probe that could not run (`saturated`, `timeout`) from a channel that is
  degraded, so a busy pool no longer reports the channel as `degraded`. The
  reading transaction ends before any probe starts, and a Redis that cannot be
  reached falls back to probing rather than failing the health page.
- Connector health publishes the readiness the source declared, so a refused
  scan no longer looks like a healthy worker: `credentials_configured`,
  `credential_state` (`valid`, `invalid`, `unsupported`, `unknown`) and
  `provider_error` from a fixed list, with `checked_at`, reach every role, and
  the raw `readiness` document stays administrator-only like `last_error`.
  `last_success_at` and `last_success_age_seconds` state when collection last
  completed, which the card prints beside the heartbeat: alive, healthy and
  "never completed a scan" are three different answers, and one green badge no
  longer has to stand for all of them. A stored readiness row whose values are
  outside those vocabularies is reduced to `unknown`/`null` on the way out.
- The alert-channel health card reports the delivery queue beside the probe:
  counts by status, the oldest unresolved delivery and its age, and
  `delivery_queue.waiting_recipients` — recipients inside a hold or an ordinary
  retry window. A channel with an `ambiguous` or `failed` delivery older than
  `ALERT_RECIPIENT_HOLD_SECONDS` is `degraded` even when its probe succeeded, so
  a green badge is no longer read as a delivery guarantee; a probe that failed
  stays the more severe answer and the counters are still shown. The aggregate is
  numbers only — no recipient, target or batch id — and is served to every role.
- The dashboard's connector and channel cards print the fields the API already
  returned and nobody read: `online` beside the heartbeat that decides it
  (`health` is the overall verdict, so a worker whose last scan failed is still
  online), `configured` beside the channel badge (`false` is what explains a
  `not_configured` badge), `generated_at` as `Data as of`, and, for an
  administrator, the `blocked_reason` and `quota_*` that say why a provider scan
  is refused and how much of the day's budget is left.
- The timeline is named for what it draws — phishing findings and breach matches
  per day over 30 days — and states that DNS and exposure findings are not in the
  series; the KPI over `count(assets) where is_active` is `Active assets` rather
  than "Monitored assets", which promised coverage it did not measure. The
  README's Dashboard entry no longer calls the health cards administrator-only:
  every signed-in account sees them, and only the raw error text, the refusal
  reason and the provider quota do not.
- `manage_admin reset` and `unlock` no longer make the account an administrator
  and no longer reactivate it: a support reset used to be a silent grant of
  administration over users, audit and settings, and `unlock` undid a deliberate
  deactivation. `--role`, `--ensure-admin` and `--activate` ask for those changes
  explicitly, `create --force` leaves activity alone, and the command prints every
  field it changed. The CLI now validates a password with the API's own policy
  instead of accepting 8 characters where the API required 12.
- Every `manage_admin` command writes its audit row — `user.created`,
  `user.password_reset`, `user.unlocked`, `user.mfa.reset`,
  `user.onboarding.cleared`, and `users.list` for the read — with
  `details.source = "cli"`, the operating-system user in `details.actor` and
  `user_id` null. A mutating command whose row cannot be written fails instead of
  applying without a trail.
- A refused authorization is now an event: `authz.denied` records the path,
  method, role and required capability, once per account, method and route per
  five-minute window, with an in-process fallback when Redis is unavailable.
- Routes declare a capability from `app/core/permissions.py` rather than a list
  of roles, and `backend/tests/test_route_access_gate.py` fails a route that
  carries neither a capability nor a named public reason. The `Access` column in
  [docs/api.md](docs/api.md) is compared with the same table in both directions.

- Password hashing and verification no longer run on the event loop. Five sign-ins
  used to block it for 1.16 s (measured here); the same five now leave the loop
  answering within 16 ms, and five *concurrent* hashes finish in 0.28 s instead of
  1.17 s, because `bcrypt` releases the GIL. The dummy hash that keeps an unknown
  address as expensive as a wrong password is now built once at import rather than
  inside the first request that misses.
- Second-factor recovery codes are stored as HMAC-SHA256 digests keyed from
  `ENCRYPTION_KEY` (and its rotation-era predecessors) instead of bcrypt. A bcrypt
  digest from an earlier release still verifies and is spent on use, so no printed
  list stopped working; new sets are entirely HMAC.
- `drp_refresh_families.user_id` carries a foreign key with `ON DELETE CASCADE`, so
  a session cannot outlive its account even when the account is removed by SQL that
  never passed through the API. An adopted database adds it with an orphan cleanup
  and `ADD CONSTRAINT … NOT VALID` / `VALIDATE CONSTRAINT`; the steps are in
  [docs/upgrading.md](docs/upgrading.md).
- `User.reports` is mapped with `passive_deletes`, so the schema's
  `ON DELETE SET NULL` decides what survives a deleted account. The ORM cascade
  used to delete the reports, and the router avoided it with a hand-written
  `DELETE` — the correct behaviour depended on one code path remembering.

### Removed

- The compact Telegram renderer nothing sent. `alert_message.telegram_text` — with
  `telegram_finding_line`, `TELEGRAM_DETAIL_FIELDS`, `TELEGRAM_DETAIL_LIMIT`,
  `escaped` and `OMISSION_NOTE_RESERVE` — had no production caller: the delivery
  path has always sent `alert_content.telegram_parts`, which prints every field of
  every finding across as many messages as the budget needs. A second format no
  channel produces is a format a reader has to rule out, and the test that pinned
  its breach line went with it; the live channel's date and verification statement
  are pinned on the path that actually sends.
- `PATCH /api/v1/users/{user_id}/toggle-active`. Activation is changed through
  `PUT /api/v1/users/{user_id}` with `is_active`, which already audits the change
  as `user.updated`; the second route for the same field was a second audit shape
  to keep in step.

### Fixed

- A backup proves both halves, and says when it only has one. `scripts/backup.sh`
  writes a report-store archive beside the dump, and `scripts/verify_restore.sh` —
  which `make backup-verify` and the `production-integration` job run — restored the
  dump and never opened the archive, so an empty, truncated or wrongly-rooted
  `reports-*.tgz` passed every gate while the restored instance listed reports it
  could not download. A pass now reads its own archive back before reporting success
  and names a store that is not mounted instead of ending with a bare `done`; the
  verification lists the archive, extracts it into a scratch directory and reads a
  file out of it, and `REQUIRE_REPORT_ARCHIVE=1` (what CI sets) makes a missing
  archive a failure. `docs/backup-restore.md` also states the archive's real
  top-level entry — `reports/`, because `REPORTS_DIR` is `/reports` on both Compose
  file sets — and gives extraction commands that put the PDFs where the platform
  looks for them.
- `scripts/lock_requirements.py` can regenerate the connector locks again. The
  marker-gated rule that keeps `greenlet` in the runtime lock was applied to every
  manifest, and none of the seven connector locks installs SQLAlchemy, so each one
  was refused with "does not pin greenlet" — which is why their headers had never
  been regenerated. The rule is now scoped to a manifest that installs the package
  declaring the dependency. `backend/requirements.txt` also carried a header naming
  `python scripts/lock_requirements.py requirements.txt`, a command that works from
  no directory (the script is at the repository root, the argument at `backend/`);
  the header path is anchored to the repository root, and a test pins every shipped
  runtime lock to what the generator writes.
- The host requirements an operator sizes a machine from are recomputed instead of
  copied. `docs/configuration.md` and `docs/deployment.md` both published sums of the
  Compose file's `mem_limit` and `cpus` values, and both had drifted by 1.0 GiB and 1.25
  CPU on every row — base 7.0 GiB / 7.75 CPU against 8.0 / 9.0 — while the per-service
  table between them was gated and green. `deployment.md` recommended 8 GiB of RAM for a
  sum of 8.0 GiB, contradicting its own rule that the recommendation sits above the sum.
  The numbers are corrected and `scripts/check_compose_healthchecks.py` recomputes all
  eight rows and the endpoint sentence from the file; a profile that no published row
  covers is a finding.
- The frontend SPA gate can be tested, and is. `scripts/check_frontend_spa.py` shipped
  without a test and with a relative configuration path, so no fixture could reach it and
  nothing failed if a rule was deleted: the `/assets` collision and the
  port-in-redirect leak it exists to prevent could both return silently. It now takes
  `--root`, exposes `check(root)`, and `backend/tests/test_frontend_spa_gate.py` drives
  each rule against a mutated configuration.
- The dependency gate reads every manifest the tree ships. `scripts/check_dependency_sources.py`
  walked a hand-kept tuple of four manifests while seven ship: `connectors/dns_security`
  and `connectors/intelligence` were named only in the hash list its scan loop never
  iterated, and `connectors/exposure_endpoints` — whose Dockerfile installs it with
  `--require-hashes` — was in neither. Three of the seven files every connector image
  installs with `--require-hashes` were therefore unchecked for exact pins and hashes,
  while the gate's success line said each of them pinned a hash. The shipped set is now
  discovered from `connectors/*/requirements.txt`, the development manifest stays
  pinned-only and unhashed, and three tests cover the scan and the hash rule the second
  list had no test for.
- The environment-template gate asks the model rather than the spelling. Its rule that a
  documented setting must be passed into a container recognised a `Settings` field only
  when it was declared with `Field(`, so the five fields written with a plain default —
  `AUDIT_ARCHIVE_DIR`, `AUDIT_RETENTION_HOLD`, `ALERT_PHISHING_DIGEST_ENABLED`,
  `ALERT_CANDIDATE_CHANGE_NOTIFICATIONS`, `ALERT_BREACH_NOISE_POLICY` — were exempt from
  it, 78 of the model's 83 fields being seen. `settings_fields` now parses `class Settings`
  with `ast`, so the next setting written in the shorter style is covered too.
- `setup.py --check` states what a setting it does not recognise actually costs. An
  `.env` from an earlier release keeps lines this one does not read — a withdrawn
  provider's key, a connector token for a service the release no longer ships, a renamed
  setting — and every one of them was reported with the summary "the application would
  refuse to start". It does not: unknown keys are ignored and the stack starts. A name one
  or two characters from a documented setting is now answered with `did you mean X?` (an
  edit budget, not a similarity score, so another connector's token is never offered as
  the correction), any other unknown name is reported as a setting this release does not
  read that configures nothing on its own and should be deleted, and the summary no longer
  promises a startup failure that cannot happen.
- The SPA displays the release it was built from. `frontend/src/lib/appMeta.ts` fell back
  to the literal `"0.2.0"` when no build injected `VITE_APP_VERSION` — which is every
  host `npm run dev` and `npm run build` — so a bundle built from this 0.2.1 tree named the
  previous release while the image named 0.2.1, and no gate read the copy because the
  version check only saw `frontend/package.json` and the Dockerfile's build argument. The
  fallback is now the package's own version, the field the version gate already holds to
  the release.
- The documentation gate sees a table torn by a blank line. `check_tables` stopped at
  the first gap, so `docs/audit-findings.md` had been rendering forty-four findings as
  a paragraph of pipes — with two malformed rows among them — while the gate reported
  the page clean and `production-readiness.md` listed that rule as enforced. A blank
  line after a table now reports the rows it orphans, unless a new header and separator
  follow it; the rule found fourteen such tables in three documents plus four unescaped
  pipes, all repaired.
- `make health` checks the port the installation actually publishes. The target curled
`http://localhost:8000` outright, while the wizard writes `BACKEND_PORT` (and
`--backend-port`, or a hand edit of `.env`, can move it): on any other port the one
post-start check the deployment and upgrade runbooks end with reported "API is
unreachable" for a healthy stack. It now asks the running container
(`docker compose port backend 8000`), falls back to `BACKEND_PORT` in `.env` and only
then to 8000, and names the port it used.
- `make help` lists every target. Seven existed and were documented elsewhere but
  absent from the list `CONTRIBUTING.md` calls exhaustive — `lint-backend` (which the
  page's own table tells a contributor to run), `test-backend-fast`, `tools-check`,
  `pull-prod` and the three connector-credential targets — so the documented way to
  issue or rotate a connector token was invisible to anyone who asked for help.
- The release version is one number in every file a deployment is made of.
`scripts/check_version_consistency.py` compared seven statements and none of the
three an operator meets first: the `OPENDRP_VERSION` line a new installation copies
from `.env.example`, and the `VITE_APP_VERSION` build-argument fallbacks in
`docker-compose.yml` and `frontend/Dockerfile`. A release bump therefore left all
three at the previous version, so `make up` from this tree built an image tagged
`0.2.0` running `0.2.1` code, with Settings and `/api/v1/health` reporting different
versions. The gate now reads ten statements, the three copies name `0.2.1`, and four
tests in `backend/tests/test_version_consistency_gate.py` fail against the old gate
and pass after it.
- The recovery codes are copied one per line from the enrolment block too. The
security page's copy was fixed and this one — the same list, shown by the flow a
new account is sent through — kept joining it with an escaped backslash, so the
clipboard received a single line with a literal backslash and an `n` between the
codes, and a refused clipboard reported nothing. Both places now write a real
newline through the same try/catch and say when the write was refused.
- The data table tells a screen reader what it just did. A sortable header named the
  column but never the direction, `aria-sort` sat on the header cell rather than on
  the button the operator is focused on, the column handle was a focusable
  `separator` with no value — so the arrow keys resized a column silently, and the
  drag had no upper bound at all — and the current page was only a fill colour. The
  button now names the direction it is showing, the applied order is announced
  through a status line, the handle carries its value and bounds (and clamps), and
  the current page is marked.
- A console left open follows the system appearance. "System" was read once, when
  the theme was chosen and never again, so a window opened in the morning stayed
  light after the desktop switched at dusk; `color-scheme` was never set either, so
  the browser's own controls — the date inputs on the audit page, a dialog's
  scrollbar — stayed light inside a dark page. The scheme is followed while
  selected, painted for the browser too, and the listener is removed when a fixed
  theme is chosen.
- A render error announces itself. The boundary never swallowed the failure — it
  logged it and drew a screen — but the screen was a plain box with no role, and
  focus was left on `<body>` because the element that had it had been replaced, so
  a screen reader heard nothing and a keyboard user tabbed from the top to find the
  explanation. The recovery screen is a `role="alert"` and takes focus, including on
  the first error of a page's life.

- A batch action on the users page no longer reaches accounts the operator has
  filtered away. The selection survived a filter, a page-size change or a page
  change, so "N selected" counted rows the table no longer showed while the batch
  route applied every id it was given; the selection is now dropped whenever the
  question the list is answering changes, and kept when the same view is refreshed.
- Destructive user actions stay in front of the operator until the API answers.
  Deactivating, deleting, clearing a second factor and a batch
  activation/deactivation closed their dialog on the click, so the pending state
  was never visible and the server's refusal — the last active administrator, your
  own account, an account that is no longer locked — arrived as a toast over a list
  that still showed the account. The four dialogs now close on success, refuse to
  be dismissed while the request is in flight, and print the API's reason inside
  themselves.
- The audit log can be opened at a known sequence. `GET /audit/logs` has always
  accepted `after_seq` and the page offered no field for it, so an investigator
  told where a verification stopped had to page back from the newest row twenty at
  a time; the filter row now takes a cursor, and the view starts there, oldest
  first.
- Recovery codes are copied one per line. The copy button joined them with an
  escaped backslash, so every code after the first arrived on the same line with a
  literal `\n` between them — discovered exactly when the codes are the only way
  back into an account. It also reports a refused clipboard instead of silently
  doing nothing.
- A saved schedule minute is no longer rewritten by an unrelated save. The minute
  control offered only a five-minute grid while the API accepts 0..59; a stored
  `17` could not be displayed, and the select library answers a value it cannot
  resolve with an empty one, which the form stored as `0` and marked dirty — so
  saving any other setting moved the scan from `:17` to `:00` and reported
  "Settings saved". The control offers the whole range now, and `17` renders as
  `17`.
- Revoking a connector credential asks first. The button sits beside "Rotate
  credential" and its effect is a worker that can no longer claim work until a new
  token is issued and its container recreated; the confirmation says so before it
  sends anything.
- A refused delete stays in front of the operator. Deleting a breach match or a
  phishing look-alike closed the dialog as soon as it was confirmed, so a slow
  delete showed no progress anywhere, and a refusal arrived as a toast over a list
  that still showed the row — with no dialog left to retry from. Both dialogs stay
  open with the confirm button pending and print the API's reason inside them, the
  behaviour the inventory and DNS pages already had.
- An asset's own page no longer answers from a snapshot taken earlier in the
  session. Its record — criticality, both dates, what monitors the asset type — was
  read once per tab and never invalidated, so an edit made on the inventory page
  appeared there and not on the asset's page; it is read once per visit now. When
  that read fails the page says so and offers a retry, instead of rendering an
  asset with no criticality and no dates as though nobody had filled it in.
- A list no longer claims nothing matches when the page it is showing outlived its
  result. Deleting the last row on the last page left the table asking for a page
  the server no longer had: an empty table, "No assets match the current filters"
  about rows that still matched, and a range that ran backwards ("16–15 of 15").
  It now moves to the last page that exists.
- A mistyped password no longer signs an operator out. The API answers a wrong
  current password, a wrong authenticator code and a lapsed invitation token with
  `401` — the same status an expired access token gets — and the SPA treated every
  `/auth/` `401` as an expired session: it cleared a valid session, showed
  "Session expired", and navigated away from the form, losing the enrolment secret
  an administrator was about to confirm and sending an invitee with a bad link to
  the sign-in page instead of the page that explains the invitation. Those six
  requests — and a sign-out whose refresh cookie had already lapsed, which is the
  outcome the operator asked for — are marked as credential checks now, so the
  refusal reaches the form that asked, with the API's own sentence; a genuinely
  expired session is still refreshed once and replayed, and a second refusal still
  ends it.
- Certificate Transparency evidence reaches the certificate tables again. The
  projector that turns stored observations into identities and sightings read
  `fingerprint_sha256`, `certificate_fingerprint_sha256`, `certificate_id` and
  `fingerprint` — but not `id`, which is the only spelling the CT worker's
  historical rows carry and the one the storage key already uses. Every one of
  those rows was skipped, so the review list and the key-reuse and unexpected-
  issuance rules only ever saw the single newest certificate per domain. `id` is
  now accepted, still gated on being a 64-character hex digest.
- One unusable control row no longer costs a DNS scan. The expiry monitor refuses
  a `verified` record whose `not_before` is later than the core's clock, and that
  refusal used to escape the observation ingest, rolling back the whole batch and
  failing the connector's job — so a worker running minutes ahead of the platform
  destroyed its own evidence. The refused control is now logged as
  `dns_control_refused` and skipped: the observations are stored, the other
  controls advance, and only that control keeps its previous state.

- Closing a phishing candidate now silences the channel, not only the digest. An
  operator's `resolved` status was read by the daily digest, which skipped those
  rows, while the delivery path routed the same candidate by its score alone — so a
  resolved look-alike at 95 was announced immediately, and the same shape at 40 had
  its event consumed as "digest pending" and then filtered out of the digest, which
  reported the arrival nowhere at all. The routing now reads the status after the
  analyst's verdict and consumes the event with `phishing_status_resolved`, which
  makes the set of candidates the digest skips identical to the set the channel
  does not reach; a confirmed candidate still alerts, because confirmation asks to
  be told about exactly these changes.
- Provider errors are redacted in the shapes they actually arrive in. The
  sanitiser that every stored provider string passes through masked URLs and
  `token=…`-style pairs, but not a quoted JSON pair (`"token":"…"`), not an auth
  scheme — `Authorization: Bearer …` masked the word `Bearer` and left the token
  behind it — and not a spaced label such as `API key sk-…`. A connector, a
  channel test or a delivery failure could therefore persist its own provider key
  in `connector.last_error`, a job's `error_message` or `details.error`, where
  operators read it and the SIEM keeps it for the retention period. Vendor key
  prefixes (`sk-`, `ghp_`, `AIza`, `AKIA`, `xox…`) are now masked wherever they
  appear, credentials behind an auth scheme are masked whole, quoted pairs keep
  their label and quoting, and a spaced label is masked only when its value
  carries a digit so ordinary prose survives triage.
- An administrator reading another account's sessions is now recorded. The list of
  a user's live sessions — which devices can still be used, and when each last
  refreshed — answered with no audit row at all, while `GET /users/{id}` next door
  wrote `users.view`. The read now writes the same action with
  `details.view = "sessions"` and the number of sessions, so "who looked at whose
  sessions" is answerable from the trail.
- Reactivating accounts through the bulk endpoint clears the lockout again.
  `PUT /users/{id}` had always cleared `failed_login_attempts` and `locked_until`
  when an account came back, because a revived account must not inherit the
  counters it collected while it was off; the batch set `is_active` and answered
  `changed: 1` with the old lock still in place, so the person was refused at the
  next sign-in.
- `manage_admin mfa-off` clears the factor's attempt counter and lock. Clearing a
  lost authenticator left `mfa_locked_until` behind, and both enrolment routes
  refuse while it is in force: the recovered account could sign in but could not
  enrol a new factor for another fifteen minutes, with nothing saying why. The
  audit row carries `mfa_lockout_cleared` so the release is visible.
- `manage_admin create` takes the active-administrator lock before inserting. The
  invariant's own documentation says every writer of that set holds it, and the
  API's create and invite paths do; the one path with no authenticated caller did
  not, so the serialisation argument was true for every writer but this one.
- Turning on a second factor now ends every other session, in the same transaction
  as the enrolment. The sessions that predate it were exactly the ones a factor is
  meant to stop: their refresh tokens kept minting access tokens without ever being
  asked for a code, so an account holder who enabled MFA after a password leak
  stayed signed in wherever the leak had already been used. The browser that
  performs the enrolment keeps its own session, and the audit row now carries
  `refresh_families_revoked`. An access token minted before enrolment still lives
  out its remaining minutes; the indefinite path is the one that is closed.
- Disabling the second factor and replacing its recovery codes spend the same
  per-account attempt budget as signing in. Both endpoints checked the lockout but
  never incremented the counter, so a correct password bought an unthrottled
  six-digit guess — the one operation that removes the factor for good. Five wrong
  codes now lock the account for fifteen minutes on all three paths.
- A successful sign-in is no longer a session without its sign-in row. The route
  used to commit the refresh family first and write `auth.login.success`
  afterwards, so a failing audit write left a usable session that the trail could
  not explain — the event a SIEM correlates every later action with. The family,
  the `last_login_at` update and the audit row now share one commit: if the trail
  cannot be written, the answer is 503 and no session exists.
- The readiness page and the route gate agree on the size of the unauthenticated
  surface. The page said six routes need no capability while
  `tests/test_route_access_gate.py` names seven — `/ready` had joined the gate's map
  without the sentence moving — so a reviewer auditing the public surface from the
  page came one route short. The count is now a claim in
  `backend/tests/test_docs_numbers_gate.py`, read from the gate's own map, so the
  page cannot state a different number without failing the build.
- A phishing digest calls its candidates candidates. The subject already said
  "candidates below the alert threshold", while the counted line under it — in the
  email body, in the Telegram header and in both of Telegram's layouts — still said
  "N new findings", so a summary of four parked look-alikes read as four findings.
  The count is now stated once, where the wording lives, and the channels print it:
  an alert counts "new findings", a phishing digest "candidates below the alert
  threshold", a breach digest "new incidents from one scan". A digest also counts
  only its own rows, so a summary no longer reports the alerts that were already
  sent in the same channel as if they were part of it.
- The audit trail's last-resort stdout line publishes exactly the five documented
  fields. `_publish_audit_event` falls back to `print()` when the structured
  renderer refuses a record, and it used to serialize the event as it stood: the
  five fields a SIEM index maps, plus anything a caller had put beside them. It
  now takes the five by name, the same way the renderer it falls back from does,
  so a safety net cannot become a second stream with a shape nobody documented.
- The `has_findings` filter answers in the database instead of loading the
  inventory: on the plan's dataset (50 002 assets, 1 000 001 findings) it used to
  fail outright with `asyncpg`'s 32767-parameter limit, because one bind
  parameter was sent per involved asset. It is now a correlated `EXISTS` over the
  indexed key columns, evaluated inside the page statement (960 ms vs. an error;
  an unfiltered page is 55 ms), and the statement count no longer depends on
  inventory size.
- The asset table shows its skeleton while the first request is unanswered
  instead of claiming the inventory is empty; the same placeholder/loading pair
  was corrected on the audit, breach, DNS, phishing, report and job lists.
- Clicking an asset header now orders the server's result set and records
  `sort`/`order` in the URL; the previous order was whatever page had been
  fetched.
- The asset card reads `GET /assets/{id}` once per opening, shows criticality and
  both dates, and no longer writes `asset.findings.list` for every page of a tab.
- `lastSeenAt` compares parsed instants instead of ISO strings, so a date and a
  timestamp are ordered by the moment they mean and a malformed value is ignored.
- Orphaned breach findings are cleaned with an indexed email-domain predicate
  instead of a correlated `LIKE` that could not use the index.
- Asset list and export answer with one bounded refusal
  (`code=query_deadline_exceeded`) when a `has_findings` read or an export
  exceeds its 40-second budget, and the export carries the same involvement
  counters and last-seen value as a list row.

## [0.2.1] - 2026-10-20

### Added

- Coverage work now has a plan of record and a way to choose the next hour by
evidence instead of by memory. `docs/exec-plans/006-coverage-program/` splits the
remaining uncovered branches into nine batches — authentication, accounts and
settings, the connector boundary, alerts, ingestion and reports, TLS and DNS,
the data lifecycle, the long tail, and the SPA — and each batch keeps its own
state file: the measurement it was planned from, the work items, the floors it
raised and a dated progress log, so a later session resumes from the document
rather than from a fresh full-suite run. `backend/scripts/coverage_gaps.py` ranks
the modules a run left behind by statements missed rather than by percentage (a
module at 60% of twelve statements is not the same debt as one at 88% of nine
hundred), prints a table a batch file can take unchanged, and is covered by
`tests/test_coverage_gaps.py`. The baseline the program starts from is the
`backend` job of the 2026-10-19 CI run on `main`: 2 918 passed, 8 skipped, and
90.65% of `app/` (14 300 statements, 1 337 missed).

- The first batch of that program closes the request boundary's unnamed branches.
`tests/test_deps_boundaries.py` executes the address parsing a proxy actually
produces (quoted values, `host:port`, bracketed IPv6, and the malformed forms that
must be refused rather than recorded as a fragment), a `TRUSTED_PROXY_IPS` value
with a typo in it, a configuration that cannot be read, a peer whose socket is
already gone, a failed audit write during a refusal, and the deployment's
second-factor policy refusing an administrator. `tests/test_mfa.py` gains the
edges of an enrolment a client can reach by mistake: enabling twice, confirming
without a code, a wrong password at the second step, a pending secret that is no
longer there, and recovery-code rotation without a factor, with a wrong password,
replaying the code that enrolled it, and succeeding while recording its count.
The batch's closing measurement executes 81 of the 109 baseline misses: `auth.py`
lands at 94.9% and `deps.py` at 99.5%, and the per-module gate now holds both —
`auth.py` enters at 91%, `deps.py` rises from 75% to 96%, each three points below
its measured value, and the full backend run closed the batch.

- The session and durability refusals on the same router are pinned too:
`tests/test_auth_edges.py` covers the lockout predicates on the naive timestamps
SQLite returns, a Redis outage in both best-effort login counters, the
access-token fallback that identifies a browser, an undecryptable pending factor
secret, a sign-in with no credentials, a locked second factor answering before
the code is read, `revoke-others` without an identifiable session, a cookie logout
without the CSRF header, a refresh token without a family, the lock refusals of
setup, enable and disable, a QR request for a secret no key can read, revoking one
session with its audit row, a logout whose token cannot be parsed, and a refresh
whose rotation cannot be committed — which answers `503` rather than returning a
token storage never accepted. The same suite changes a password and replays the
refresh token issued before it, which the change must revoke; the test fails if
the revocation is removed.

- The second batch covers the account and settings surface. `tests/
test_settings_contract.py` walks every validator branch — the module reaches
100%, including the empty-value and named-field refusals — and `tests/
test_users_edges.py` adds the role/activation filters, the duplicate-address
answers on create and invite, invitation reissue, a bulk no-op, rate-limit
updates, a naive lockout release, unknown-account 404s on the per-account
routes, MFA reset, and the storage-conflict translations. The duplicate-create
test exposed that SQLite names the unique rule `users.email` while the router
recognised only PostgreSQL's `users_email_key`, so a taken address answered the
generic constraint message; one shared predicate now answers "already exists"
on both. `users.py` is gated at 91% and `schemas/settings.py` at 97%.

- The rest of that program's backend batches close on the same rule — a test where
a range names a behaviour, a deliberate miss recorded where it does not. The
connector boundary adds the manifest's schema refusals and the service's
credential, provisioning and rotation edges (`connector_manifest.py` 97.2%,
`schemas/connector.py` 94.1%, `connector_service.py` 92.0%); alerts and delivery
add the queue's ambiguity and lease paths, the message layer's redaction and
clipping, and the health cache's stale window (`alert_message.py` 100%,
`alert_health_cache.py` 99.1%, `alert_delivery_service.py` 97.6%,
`alert_service.py` 97.2%); ingestion and reports add the write path's duplicate
and out-of-order answers and the report assembly's empty and truncated sections
(`ingestion_service.py` 97.0%, `report_service.py` 92.3%); TLS and DNS add the
certificate identity rules and the router's refusal edges
(`tls_identity_service.py` 99.5%, `routers/dns_security.py` 100%); the lifecycle
batch adds retention's per-table bounds, the audit archive's verification before
deletion, the per-account quota and the configuration's own refusals
(`retention_tasks.py` 99.3%, `config.py` 96.6%, `audit_archive.py` 95.7%,
`provider_quota.py` 99.0%); and the long tail adds the remaining routers and both
scheduled task bodies (`routers/connectors.py` 99.6%, `routers/phishing.py` 100%,
`routers/assets.py` 99.6%, `settings_service.py` 98.7%,
`user_notifications.py` 100%, `tasks/user_tasks.py` 100%,
`tasks/integrity_tasks.py` 100%). Floors are new or raised for every one of them,
never lowered, and `docs/production-readiness.md` carries the same map the gate
holds. `app/` closes at **96.30% (529 missed)** from 90.65% (1 337 missed).

- The SPA's coverage floor is no longer four points below its own functions
number. `npm run test:coverage` measured 59.4% of functions against a 55% floor
while every other axis had twenty points of margin, so the batch that closed that
gap added the interactions an operator actually performs: a refused
`database_busy` read on the inventory that explains itself and retries, an asset
detail page whose failed findings read is retried and whose `Refresh` re-reads
the open module, a DNS review page that reports a refused promotion, deletion and
orphan cleanup with the server's own sentence and keeps the row on screen after a
refused delete, the evidence badge that puts a provider's malicious count on the
row, and the second-factor enrolment flow — password required before a secret is
generated, a wrong code keeping the secret on screen, and recovery codes shown
once and only left behind after the operator confirms they saved them. The
password-change and revoke-others actions on the security page are pinned too:
a mismatch is refused before anything is sent, and a successful change adopts the
session the API returned because the change revoked the old refresh family. An
administrator's password reset is asserted to travel as `new_password` — the
camelCase name would be dropped by the API and a form that looked successful
would leave the old password in place — and a checked reset with no value is
refused before the request. The suite moves from 72.93/72.91/59.38/77.8 to
**81.17/75.87/76.53/83.71** over 53 files and 495 tests, and the functions floor
rises 55 → 73 (the other three are left where they were). The functions still uncovered are named in
`docs/exec-plans/006-coverage-program/batch-09-frontend.md`: the audit `details`
formatters no fixture produces yet, and the Radix wrappers that only run inside a
pointer-driven portal jsdom cannot open.

- The coverage program's backend tail is swept where a missing branch is a
refusal rather than a formatter. Seven modules under fifteen missed statements each
were taken in the order their miss could cost something: the destination policy
(the allowlist entry that is a typo, an IP literal classified when DNS answers
nothing, the pinned SMTP socket that closes the raw connection when the handshake
fails and tries the next validated address), the artifact store (a drive-relative
name, the 255-character bound, and a resolution that lands outside the store told
apart from a resolution that fails), the refusal camera (its window in Redis, its
fall-back map when the broker is down, the map's bound, and the account a refusal
was about), the provider-account service (every refusal names its field, and a
connector only ever receives its own provider's key), the module registry (label
bounds, metadata truncation, a finding kind owned by a differently-named row, and
the queue-cancelling a disabled module has done since 0.2.0 — **disabling a module
cancels the work it had queued**, rather than leaving a provider scan behind for a
module an administrator switched off — which until this batch had no test standing
behind it), the source-inventory
routes (`409` when a scan has nothing to queue, `404` for an observation another
module owns, an address promoted as `ip_address`, and a promotion that loses a
race answered with the winner rather than a `500`) and `GET /jobs/{id}` (another
account's job is a `404` that does not confirm it exists, a system job is readable
with no email). Floors are new for five of them and raised for two — the registry
from 70 to 97 and the provider-account service from 80 to 97 — and
`docs/production-readiness.md` carries the same map. `app/`
closes at **96.79% (459 missed)** from 96.30%, with 3 354 tests passing.

## [0.2.0] - 2026-10-19

### Added

- Report generation now captures KPI counts and bounded sections from one database snapshot, uses dashboard-compatible active-threat definitions, and makes every section's included/total/limit/truncated counts visible in the PDF and API metadata. Queue admission is globally bounded; generation/retries have an end-to-end budget, durable outcome audits, and recoverable artifact cleanup/retention intents.

- Durable asset-scoped DNS expiry monitoring for registration and exact passive CT certificates, with 30/14/7/3/1-day and expired notifications, freshness enforcement, renewal cycles and transactionally deduplicated queueing. Exact CT checks precede subdomain discovery; the UI distinguishes registration/certificate expiry from DNS TTL and reports check state.
- The certificate review workflow answers the question the DNS & TLS module exists for — is a certificate of ours served somewhere that is not ours — about the *certificate* instead of about any one observation: the daily sweep projects the CT, provider and probe evidence already stored into fingerprint identities (`tls_certificate_identities`) and sightings (`tls_certificate_sightings`, one row per certificate/address/port/source), then scores four rules over the difference. R1 (`tls.certificate.foreign`) is a certificate of ours on a foreign address, R2 (`tls.key.reuse`) is one SPKI digest inside two different certificates, R3 (`tls.certificate.unexpected`) is a certificate for our name we did not deploy, and the stack-echo rule (a JARM plus a title or favicon match with no certificate match) raises confidence and marks the sighting for review instead of alerting. Sightings are grouped by certificate and address before queueing, so several sources confirming one foreign address produce one alert naming the address, the organisation, the ASN and the sources, and a hosting/CDN organisation serving one certificate from many addresses is recorded as `shared_infrastructure` rather than alerted. A verdict (`expected`, `shared_infrastructure`, `confirmed_foreign`, `rejected`) is written to the audit trail and survives every later sweep, so a judged sighting is never re-alerted; an administrator can take a fingerprint, SPKI, address, ASN or issuer out of the rules' scope with a reason and an optional end date that expires on its own. No traffic is sent to third-party infrastructure: every provider read is a search over data the vendor already collected, and the only active traffic remains our own probe against our own assets. The DNS Security page exposes the list and the decisions, and `TLS_CERTIFICATE_RETENTION_DAYS` (default 365) bounds what is kept.
- Transactional ingestion outbox with per-finding savepoints, explicit created/updated/unchanged outcomes and persisted evidence refreshes; notification and WHOIS work is dispatched asynchronously.
- Operator-managed provider accounts and explicit shared quota approval, stable UUID routing/provenance, and connector names in `<module>-<source>[-<task>]` form with the registry accepting the earlier spellings as aliases. See the upgrade notes and `docs/upgrading.md` before adopting a database an earlier build created.
- `GET /api/v1/assets/{asset_id}/findings` and an asset detail page that answer "what is this asset involved in": per-module counts (phishing, breaches, DNS Security, exposure, generic findings) plus the paged rows behind each count. The predicates come from the same asset-matching rule the cascade uses, so the view and the deletion can never disagree.
- Promotions from DNS Security and Exposure observations record the originating observation, its provider source and the resulting asset in the audit trail; the UI names the source in the confirmation and toast instead of producing an untraceable asset.

- `GET /api/v1/assets` now says how much the platform holds about each row: every item carries `findings` — the per-module counts (phishing, breaches, DNS Security, exposure, generic findings) and their total, computed by the same matching rule as the asset page and the cascade — and `GET /api/v1/assets/{asset_id}/findings` adds `last_seen` per module, the moment each module last saw a finding about that asset (published as ISO text, so a breach disclosure date and a scan timestamp are never compared). A list row can no longer look like a monitored asset when nothing was ever reported about it.
- Bulk inventory endpoints: `POST /api/v1/assets/import` (JSON) and `POST /api/v1/assets/import/csv` create a batch with a per-line `created`/`duplicate`/`invalid` report, `dry_run` previews it without writing anything, `GET /api/v1/assets/export` renders the current filter as CSV or JSON using the same matching and ordering as the list, and `POST /api/v1/assets/bulk` applies `activate`/`deactivate`/`criticality` (analyst) or `delete` (administrator) to up to 500 named assets with one summary audit row. Limits are refusals, not truncations: 1000 rows and 1 MiB per import, 500 ids per bulk action, 10 000 rows per export.

- The alert budget is an installation's own decision, not only the deployment's. The six values that decide how loudly a scored phishing candidate is reported — the thresholds that separate "announced now", "in the daily digest" and "in the list only", whether that digest runs and at which UTC hour, how long a finding no configured channel can receive is held, and whether a revised candidate is announced again — can be restated on the Settings page's **Alert budget** section, which writes `system_settings`. A field left blank is not zero: it is "not decided here", and the deployment's `ALERT_*` environment keeps answering that one, which is why the page prints the values in force beside the fields that override them and the six columns are nullable with no default. The row is read where the value is used — the delivery route, the digest's tick, the outbox's deferral window and ingest's revision rule — so a save takes effect on the next scan rather than on the next container restart. The digest runs from an hourly tick that decides from the saved hour, because a beat schedule is built when the worker starts and an hour held there could only ever be the value its container was created with. A stored row that contradicts itself (a digest threshold at or above the direct one) is refused *as a whole* — by the save that would create it, with a `400` naming the fields, and by every reader that meets one, which then answers from the environment instead of half-applying it. `GET /api/v1/settings/alert-policy` reports the values in force, whether each came from the row or the environment, and what was refused. An adopted database needs the six `ADD COLUMN IF NOT EXISTS` statements in [docs/upgrading.md](docs/upgrading.md); nothing routes differently until somebody saves the page.

- The credential-breach module now reports and rates what it stores, instead of dumping whatever the provider returned. A leak alert is built from a **declared** column set — incident, account, vendor domain, date, affected-account count, data classes, the source's own verified/spam marker when it made one, and the change class in the first column — and from the **stored row** at send time, so values that are not declarations (`id`, `created_at`, `status`, `source`, a truncated `description`, the `data_classes` JSON and the whole `attributes` blob) cannot appear in a message at all; a 50-finding scan renders in at most six Telegram parts and one email stays under the limit, measured rather than hoped for. The worker no longer invents metadata: an unavailable `/breach/{name}` answer used to be submitted as a stub `{Name, Title, Domain: ""}` that the core stored as a finding with no date and no vendor, and the core now refuses a finding with no usable date instead of writing `1970-01-01` — the only path that stores a date-less row is a reporter that says so itself (`attributes.metadata_incomplete`), and the API and the page then say the metadata is incomplete rather than presenting the observation day as the incident's. The worker also paces itself by the subscription rather than by a guessed constant: a token bucket over a worker-declared `requests_per_minute` (default 10, the conservative reading of the lowest paid tier), `Retry-After` obeyed on a 429, one `/breach/{name}` lookup per incident per scan, and declared bounds on the aliases one domain scan expands and the requests it may spend — the ~2000-request single scan the audit measured is unreachable, and a scan that hits its budget says so in its summary instead of discovering the cost by paying it.
- A breach scan that finds a hundred new incidents is a backlog, not a report, and the channel treats it as one: past `ALERT_BREACH_DIGEST_THRESHOLD` (default 20, restatable in Settings → Alert budget beside the phishing budget) one scan's notifications wait for the daily digest — the same hour as the phishing digest — and leave as a single summary; an incident the source itself labels spam or fabricated is stored, visible and not announced under the default `ALERT_BREACH_NOISE_POLICY=store_only_spam`, with the operator's answer (`verified_only`, `all`) one setting away. A re-report is only news when something moved: `reappeared` (the incident came back after an analyst resolved it, and the resolution stands), `new_data_class`, `incident_grew` (past `ALERT_BREACH_GROWTH_FLOOR`, which keeps a source's bookkeeping out of the channel), `now_verified` and `date_corrected` are each delivered **once**, keyed by the change rather than by the row, while a scan that rediscovers identical facts writes no event at all and only moves `last_seen_at`. The list reports `unannounced` — findings no channel has delivered yet — so the silence around an installation that ran its first scan before configuring an alert channel is visible and countable rather than invisible, and `?new_since_last_scan=true` answers "what did the last scan turn up?" from the completion of the most recent finished scan.

- A breach of a domain being monitored is now visible **before** anybody has added an address of that domain to the inventory. Findings can only exist for what the inventory holds, so the breach module gained the other half of the picture: a connector reads its source's own incident *catalogue* (`POST /api/v1/connectors/me/catalogue/{job_id}`, bounded at 500 entries a batch, and a `/breaches` sweep the worker bounds with `max_catalogue_entries`), and the core — which is what holds the inventory — computes the diff, because the provider has no "added since" question to ask. One row per `(source, breach_name)` in the new `breach_catalogue` table keeps the source's own `added_date`/`modified_date` beside the platform's `created_at`/`last_synced_at`, so a corrected date cannot make an old incident look new and "new" is a claim about this installation's own history. An incident the platform has never stored whose vendor domain is an **active** monitored asset queues exactly one `new_incident` notification, matched by the platform's own asset rule (case, trailing dot and IDNA included) and reported with the same declared columns as any other breach event; a repeated sweep of the same catalogue announces nothing, an incident at a domain nobody watches is stored and not announced, and a sweep that was cut short says so instead of passing off a short catalogue as a complete one. Between sweeps a scan pays one cheap request: the job's params carry the checkpoint under `params.catalogue`, and a source this installation has never synced answers `last_synced_at: null`, which is what makes the first scan read the whole catalogue. An empty answer is reported as empty (`empty: true`) rather than as a clean domain, and an unanswered one leaves the phase `failed`, so "nothing in the catalogue" and "nobody asked the provider" never read the same way. An adopted database needs the `CREATE TABLE` from [docs/upgrading.md](docs/upgrading.md)'s *incident catalogue* section; until a worker that knows the route is deployed, the table stays empty and nothing is announced on the strength of a catalogue nobody read.

- The credential-breach module can say *which* exposure it found, instead of calling every row a breach. A compromised account, a name that appeared in a paste and a site found in a stealer log are three findings about the same address with three different responses, and the module could only represent the first. `drp_breaches.exposure_kind` now carries the class (`breach`, `paste`, `stealer_log`), declared per finding by the source and validated against that closed set at both the wire schema and the ingestion service — a class outside it is refused by name rather than stored under a heading nobody chose. The module's identities do not move for it: a paste or a stealer log carries its own identifier inside `breach_name` (`paste:<id>`, `stealerlog:<site>`), so the existing unique pairs and indexes keep working and an installation that adopts the column rebuilds no row, re-identifies nothing, and reads every row it already holds as a breach because that is what the module could represent then. `GET /api/v1/breaches?exposure_kind=…` filters the list (any other value is a `422`, because the filter cannot offer a class the core refuses to store), the class is shown per row, and the page's class picker, the audit row of a list read and the PDF/API row shape all carry it. The breach KPI splits its findings total by the same classes — `findings_by_exposure_kind`, summing to the total it splits — so "how exposed are we" and "exposed how" are answered from one computation, printed in the report's summary and on the dashboard card that carries the total. A correction is followed: a source that re-reports the same identifier under a different class updates the row rather than adding a second one, while a re-report that declares nothing leaves the stored class alone — absence is not a claim.

- The exposure the module finds is now exposure it can look for without the address leaving the platform. A subscription that includes HIBP's k-anonymity search no longer needs the address in the request: the worker hashes it and sends the first six characters (`/breachedaccount/range/{prefix}`), matches the answer back on the remaining suffix — a prefix is shared by every account in its bucket, so only our own suffix is about us — and then reads each named incident from the catalogue, which is the path a domain alias already took. Both forms are asserted to produce identical rows, so not sending the address is not a quiet change of coverage, and the summary reports the form used with whose decision it was (`disabled_by_operator`, `not_in_subscription`, `subscription_unknown`) plus what the bucket did (`matched`, `unmatched`, `case_retries`, `metadata_missing`). The provider does not document how it normalizes an address before hashing, so a mixed-case address whose lowercased digest matches nothing is confirmed once with the raw-case digest: one extra request, only when it could matter, instead of a silent "not breached". A refused range answer is never downgraded to the address form — the count is `emails_unavailable` and the job is `partial` — and because `/pasteAccount/{email}` has no hash equivalent, the route that still names an address is listed in the summary (`email_lookup.address_routes`) and can be switched off with `pastes_enabled: false`, which is what makes "no address leaves in a URL" an achievable state rather than a claim.

- The classes the module could already *store* are now classes it can *find*, from HIBP: a monitored address's pastes (`/pasteAccount/{email}`, one row per paste with the paste's own date and its source, id, title and address count in `attributes`, `paste_without_id` counted rather than stored when an entry has no id) and, for addresses and monitored domains, the websites named in stealer logs (`stealerLogsByEmail`, `stealerLogsByEmailDomain`, one row per site as `stealerlog:<site>`). The stealer-log pass spends a separately priced allowance, so it is off unless the operator turns `stealer_logs_enabled` on, and it still asks nothing unless `/subscription/status` explicitly says `IncludesStealerLogs: true` — a plan that does not state it, or an account question that was not answered, is reported as `not_in_subscription` / `subscription_unknown` rather than spent discovering a `403`. Inside `stealer_logs_interval_hours` (default 168) the scan says `not_due` and asks nothing: the last sighting travels to the worker in the job's `params.stealer_logs.last_seen_at`, read from the rows the core holds, so a restarted worker does not repeat the week; the domain route waits on a second, lower bucket (`stealer_logs_domain_requests_per_minute`, default 3) on top of the key's pace, and `max_stealer_log_sites_per_asset` (default 50) bounds what one identifier contributes, with the rest counted as `sites_over_limit`. The two routes answer with names and nothing else — no incident, date, count or data classes — so those findings declare `metadata_incomplete` and the core records the first sighting instead of inventing facts, and a re-read of the same undated row no longer moves its date: the stored observation instant is written once, so the change classifier cannot report a `date_corrected` every week about the platform's own clock. A job that could not ask reports it (`pastes.unavailable`, `stealer_logs.unavailable`) and is `partial`; the message prints `Exposure: Paste` or `Exposure: Stealer log` beside the account, and dates an undated row as `not stated (observed …)` instead of presenting the observation day as the incident's. `/stealerLogsByWebsiteDomain` is deliberately not called: it would import third-party account addresses of a monitored site in bulk, which is an operator's privacy decision and not a default.

- "How much credential exposure do we have" and "is there new trouble out there" were being answered by the same figure, and neither answer was true. The report counted breach *rows* created in the last seven days, which conflates a new incident with a newly scanned address: a scan that traverses an address somebody just added produces findings about incidents that are years old, while a breach of a vendor whose addresses nobody has added yet produced nothing at all. `new_breach_incidents_7d` now answers the second question from the sources' own incident catalogues — the incidents a source added in the window, whether or not any monitored address is in them — and the first keeps answering the first, from stored findings. Both come from one rule (`app/services/breach_kpi.py`) that the dashboard and the report call, so the PDF and the page are the same computation rather than two definitions that had already drifted apart once: `active_threats_7d` keeps the meaning the dashboard and the reports audit agreed on (active/investigating findings created in the window), and every breach figure travels with a caption naming what it counts — printed beside the number on the dashboard card, in the PDF's summary line and on the title page, from one string the rule wrote. An incident a source published no date for is counted in `undated_incidents` instead of in the window, and the report says how many there are whenever that number is not zero, because "nothing was added" and "half this catalogue cannot be dated" are different answers. The dashboard's `kpi.breach` object and the report's `kpi.breach_kpi` are the same payload, asserted equal over one seeded installation.

- A breach list that is empty and a breach list nobody was allowed to fill no longer look the same. Whether the source *agreed* to be asked existed only inside the scan's job summary, so the page showed a short list and left the operator to guess. `GET /api/v1/breaches/provider-readiness` now reports the most recent finished scan's own account of itself, and asks the provider nothing to do it: per domain it says `asked` (the source was put the question, so "no findings" is an answer *about the domain*), `unscanned` with the provider's reason (`domain_not_verified`, `domain_outside_allowance`, `domain_access_denied`), or `unknown` when the scan spent its request budget before reaching it — only the first of the three means nothing was found. Beside the domains it reports what the account may do (subscription name, the rate the plan states, stealer logs, k-anonymity ranges, verified domains), the pace the scan actually ran at after the plan's own number was applied as a ceiling on the operator's, the `partial` verdict carrying the same reason keys Jobs shows, and the source's own names for the classes of data it publishes. Because both surfaces read one run they cannot disagree about it, and a source that is not the shipped worker fills the same shape. A connector may now publish `data_class_labels` in its readiness row — bounded, merged across a module's enabled sources and ignored when a source publishes none — so the page renders a stored class through the provider's vocabulary (`Passwords` as the source words it) instead of a label this platform invented, and falls back to the stored name when there is nothing to render. The page carries the whole verdict above the list it explains, and a breach worker re-reads `/dataClasses/descriptions` once per process rather than once per scan, so the labels reach a scan that ran before any existed.

- The verdict "not verified" now has a remedy beside it. A domain a source refuses to search because the account has not enrolled it can be enrolled from the Breaches page: `POST /api/v1/breaches/domain-verification` queues one step of the flow on **one** source — `generate` returns the TXT value to publish, `verify` checks it — and the outcome is read back per domain in `provider-readiness.verifications` (`generated` with the record exactly as the source stated it, `verified`, `not_verified` while DNS propagates, or `failed` with a reason from the worker's own vocabulary). The request names the source it should ask: with one enabled breaches connector it is implied, with several it is required and the refusal lists them, because a verification enrols the domain in one account's dashboard rather than in every source's. The step is audited as `breach.domain_verification.requested` whether or not it could be queued — "nobody asked" and "nobody could ask" are different answers on the page — and it is queued **outside** the connector's scan admission slot, since an operator waiting for a domain to become scannable is exactly when a scheduled scan is running. A verification stores no finding and its job is not read as "the last scan": the readiness card keeps the scan's own domains, pace and entitlements, and reports the attempts beside them, including an attempt whose domain the last scan never named. The page offers both steps per refused domain, prints the record to publish, and follows the queued job to its answer instead of leaving it at "requested".

- The breach list now answers "what do I handle first" instead of only "what is stored". Severity is derived from the classes of data an incident exposed — plaintext credentials, security questions and payment data are `critical`, hashed credentials `high`, addresses and phone numbers `medium`, an address list `low` — and is written to the row by one rule (`app/services/breach_severity.py`) when the row is written, so the page's badge, the `?severity=` filter and the `?sort=severity` ordering read the same value; a class the rule has never seen leaves the row `unknown` (shown as *Unclassified*) rather than quietly ranked as harmless. The list also filters by the operator's `status`, by the source's own flag (`verified`, `spam`, `fabricated`, `sensitive`, asked of the stored payload), by reporting source and by domain (the matched domain or an address at it), orders by finding date, incident date, size or severity rank (loudest first, not alphabetically), and every row names how many incidents the platform already holds about that address across all filters — an account seen four times is one account to handle, not four rows to triage as new. The PDF's breach section uses the same order and the same severity column, so the report and the page cannot rank the same incident differently. New gated boundaries: `breach_severity.py` (91% measured, 85% required), `breach_catalogue.py` (98%, 90%) and `breach_kpi.py` (100%, 95%).

- The Netlas spike can now answer the page-body question. `live_check.py --question body` asks `/responses_count/` and one page of `/responses/` with `http.body:"<identifier>"` and prints both counters, so the broad expression the phishing worker pages through is confirmed against the account before a scan relies on it. The same run fixed a real defect in the script: it normalised *every* value as a host, so the documented brand example `"ACME Corp."` was refused as `invalid_endpoint` before a request left the machine; only `own_hashes`, `whois` and `mx` name an endpoint and are normalised now, while brands, counts and body expressions stay the phrases the query builder quotes. Confirmed against a live Netlas account on 2026-10-17: `http.body:"OpenDRP"` returned `count=8 rows=8`, `whois` and `mx` parsed, while `/certs/` with a `certificate.*` expression timed out at 30 seconds — recorded in `docs/source-intelligence.md` as an account/plan property that keeps the brand-certificate capability unverified rather than pretending it answered.

- A provider capability an operator switched on is now also a capability their plan has to permit. The Shodan worker refuses the five questions added with the budget wave — page body, certificate subject, HTML hash, organisation/network pivots and the free host lookup — until `provider_terms_acknowledged` is true in its registry config (or `SHODAN_TERMS_ACKNOWLEDGED=true` in its environment), and the Netlas phishing worker refuses `http.body` searches until `http_body_acknowledged` / `INTELLIGENCE_HTTP_BODY_ACKNOWLEDGED` says so. A refusal is named in the job summary as `licence_acknowledgement_required` and sends nothing to the provider, so a capability that looks enabled cannot spend credits silently. The three historical Shodan questions keep running: they were already being asked when the gate arrived, and stopping them would be a change nobody chose. `.env.example`, Compose and `connectors/README.md` document the two statements and why the toggle and the acknowledgement are separate.

- Alert delivery is a durable per-Job/type/channel/recipient queue: a per-recipient lease and interval serialize batches that would otherwise overlap, one retry budget is shared with permanent provider rejections, and `Retry-After` is persisted instead of clamped to 300 seconds. Telegram sends every safe fact as numbered persisted parts, and an acknowledged part is never sent twice. A delivery whose acceptance is unknown becomes `ambiguous`: the recipient stays blocked with no expiry until an operator reconciles it against provider logs, because a timed-out SMTP thread may still have sent.
- Settings is a database singleton with an optimistic `version` — a concurrent save is refused with `409` instead of overwriting the other operator — and the scheduler records each persisted occurrence (`schedule_occurrences`) independently of Job deletion. Audit retirement can only delete a contiguous prefix after the signed NDJSON archive and its manifest verify, and `AUDIT_ARCHIVE_DIR` has no report-store fallback, so a missing or unwritable archive blocks deletion. The baseline creates all of it.
- The Audit page exposes raw `details`, event and actor identifiers, sequence and hash, snapshot versus legacy current-user identity, and exact `request_id`/`job_id`/outcome filters; `GET /api/v1/alerts/queue` reports delivery backlog and recent redacted diagnostics to administrators.

- Provider API keys can be stored per source account from Settings. Keys are encrypted with the core Fernet key (`ENCRYPTION_KEY`), shown only as a masked hint, and released only to the connector bound to that account and provider. The baseline creates the columns; an environment variable named by the credential reference remains the fallback.

- The DNS module is `dns` and every bundled connector is named `<module>-<provider>` (`phishing-dnstwist`, `breaches-hibp`, `dns-rdap`, …), so a Compose service name, its `CONNECTOR_NAME` and its job type read as one scheme. The baseline seeds that scheme, and every row also carries its earlier label as an alias, so a connector image that registers under the name it was built with keeps authenticating and a source keeps the observations it already reported. The `dns_security_observations` table and the `schedule_dns_security` column keep their names, and the previous `dns_security` module id is still accepted as a transitional alias.

- `GET /api/v1/metrics` publishes the platform's health as numbers a scraper can alert on: alert-queue backlog and the age of its oldest row, recipients held after an ambiguous delivery, connector silence per connector, job states and the age of the oldest running job, and where the audit chain stands (retained rows, committed, retired and last-verified positions, and whether a verification has failed). Durable gauges are read from the database on every scrape, so every replica reports the same value and a restart does not look like a drop in traffic; this replica's request counters are labelled as such. The endpoint answers `404` — not `403` — until `METRICS_TOKEN` is set, and a refused scrape is logged with the caller's address instead of being written into the audit chain, because a scrape every fifteen seconds is 5 700 audit rows a day describing a read of aggregate counts. No value taken from a request can become a label: labels come from the platform's own enumerations and from connector names, which is what keeps the endpoint from becoming a second copy of the records the audit trail exists for. Thresholds, the metric list and the scrape configuration are in `docs/observability.md`.

- The journey from a queued scan to a queued alert is exercised against a real installation before a release, by `scripts/e2e_smoke.py` in the new CI job `e2e`: the job writes an installation's configuration with the setup wizard, builds and raises the stack (API, both workers, the scheduler and the frontend), and the smoke signs in as an administrator, registers the asset, provisions a connector over the documented bootstrap, queues a module scan, claims the work as that connector, submits one finding, completes the job, and then asserts what an operator would see — the finding in the module's listing, the alert queue grown by it (read back through the metrics endpoint), and an audit entry for every step. The connector in that run is the script itself, so the journey is provider-independent, and the alert sink is a name that does not resolve, because the property under test is that a finding becomes a queue entry without anyone clicking: SMTP delivery, retries and recipient holds are covered by the alert suite and by the operator's own channel test.


- The other half of that journey runs in a browser, because a served shell that answers with an API that answers does not add up to a usable product: `scripts/e2e_browser.py` drives the same installation with Playwright in the same CI job. The root sends a stranger to the sign-in form and the form's own submission creates the session, which is then asserted where the design puts it -- the refresh token in an `HttpOnly` cookie that `document.cookie` cannot see, the CSRF value beside it readable by page scripts (that is how the SPA sends it back), and no access token anywhere in `localStorage` or `sessionStorage`, so one injected script cannot lift a long-lived credential out of the browser. It then asserts that what the platform stored is what the operator sees: the newest finding the API lists renders as a row together with the asset it is attributed to, on a table that states its timestamps are UTC, and it finds the account it signed in as in the shell's own menu. Signing out ends the session on both sides -- the cookie is cleared from the jar *and* the value it held is refused with a 401 -- because a copy taken before the sign-out must not still mint sessions. It renders a finding the smoke has just written, so against an installation with none it fails instead of passing on an empty table; a failing step reports the page's own text and the browser's console, and `E2E_ARTIFACT_DIR` writes screenshots for a person.

- The two PostgreSQL-only suites are run by CI, and a database that is missing fails the job instead of skipping it. `tests/test_asset_involvement_postgres.py` and `tests/test_dns_expiry_postgres.py` each skipped themselves when `INTEGRATION_MIGRATION_DATABASE_URL` was unset — and no job ever set it — so the properties only a real database can host (the row lock that makes two concurrent DNS expiry sweeps queue one alert, and the correlated `EXISTS` behind `has_findings`) had no gate anywhere. The `production-integration` job runs both against the database its own migration step leaves behind, with `REQUIRE_INTEGRATION=1` and a separate assertion on the report that nothing was skipped; `backend/tests/test_postgres_only_suites_gate.py` pins that wiring, including that the assertion would reject a skipped run.

- The per-module coverage gate holds five more modules, all of them places where a regression costs data or quota rather than a wrong pixel: `app/services/asset_matching.py` (95.6% measured, 90% required), `app/services/scan_admission.py` (97.8%, 90%), `app/tasks/retention_tasks.py` (86.3%, 80%), `app/services/provider_quota.py` (80.3%, 75%) and `app/tasks/integrity_tasks.py` (75.0%, 70%). They sat outside every per-module gate while the aggregate floor hid them, which is the same loophole the gate exists to close.
- The per-module coverage gate holds the ten boundaries this release adds, each measured before its threshold was set: `app/api/v1/routers/metrics.py` (100.0% measured, 90% required) is the scrape token gate and `app/core/metrics.py` (92.3%, 85%) is the label shaping that keeps a request value out of a metric; `app/services/audit_verification.py` (96.4%, 90%) reads the audit chain and `app/services/audit_archive.py` (82.0%, 75%) is the only code that deletes audit history, which it does after the archive verifies; `app/services/dns_security_service.py` (93.2%, 85%) validates what a provider claims a name resolves to, and `app/services/source_observations.py` (96.1%, 90%) is the write path a declared module's findings arrive through; `app/services/ingestion_events.py` (97.1%, 90%) settles an outbox claim across a network call, and its `enrich_one_event` had been executed by no test at all — the task that calls it is covered with the import stubbed out — so the drain now has its own suite (`tests/test_ingestion_outbox_drains.py`) for the claim it takes, the lock it releases before its WHOIS call, the fence that discards a stale result, the bounded retry a failure records, and the two outbox rows a deployment with no delivery channel treats differently; `app/services/source_accounts.py` (85.3%, 80%) issues and releases a connector's provider credential; `app/services/alert_content.py` (86.7%, 80%) is the redaction every outbound message passes; and `app/services/module_aliases.py` (100.0%, 90%) decides which stored identity a module or connector name resolves to. `docs/production-readiness.md` carries the same map, and `backend/tests/test_critical_coverage_docs.py` now fails the build when the page and the gate disagree in either direction — the drift that let a release ship a table the gate did not hold.

- `npm run test:coverage` enforces thresholds instead of only measuring, and measures every source file instead of the ones a test happened to import: statements 70%, branches 70%, functions 55%, lines 75%, set just under the 72.9/72.9/59.4/77.8 the suite measured. A page rewritten with its tests deleted, or a helper no test imports, now fails the `frontend` job rather than lowering a number nobody read.

- The two reads that repeat on a timer have their own indexes: `ix_jobs_status_created` (`status='pending'` ordered by `created_at` — the claim every connector makes on every poll, the most frequent read the table has) and `ix_ingestion_events_due` (`kind`, `processed_at`, due `next_attempt_at` — the outbox dispatcher, every fifteen seconds, over the rows retention keeps). The revision creates both and drops them with their tables; an adopted database is the case they cannot cover, so `docs/upgrading.md` carries the two `CREATE INDEX IF NOT EXISTS` statements for it (adoption records a revision and creates nothing, by design).

- A schema migration is bounded where a bound helps, and explicitly unbounded where it does not. `MIGRATION_LOCK_TIMEOUT_MS` (30 s) is applied to the connection the revision runs on, so an `ALTER TABLE` waiting behind another session's open transaction fails with PostgreSQL's own `lock_timeout` error — the failure that used to read as an API container that was simply "unhealthy" while the startup migration blocked, with nothing naming the wait. `MIGRATION_STATEMENT_TIMEOUT_MS` defaults to `0` on purpose: the baseline's index builds are legitimately the longest statement this platform runs. The advisory-lock connection in `scripts/migrate.py` keeps waiting, deliberately — a second replica must queue and then find nothing to do, which is what `tests/test_migrate_lock.py` pins — so it carries the statement bound and not the lock one.

- Opt-in passive intelligence checkpoint: disabled provider/module registry entries, lease-bound account quotas, phishing source evidence, Exposure inventory/UI/schedule and bounded DNS/Exposure PDF sections. See `docs/source-intelligence.md` for remaining acceptance gaps; Criminal IP domain/brand search is not implemented.
- Native DNS Security module with source-scoped observations, source filtering, analyst asset promotion, admin-only confirmed orphan cleanup, UTC scan scheduling and RDAP expiry reminders at 30/14/7/3/1-day thresholds.
- Six optional DNS workers (`dns-rdap`, `dns-resolver`, `dns-ctlogs`, `dns-tlsprobe`, `dns-virustotal`, `dns-shodan`): `dns-rdap`, `dns-resolver`, `dns-ctlogs` and `dns-tlsprobe` start from `docker compose up -d`, while `dns-virustotal` sits behind the `virustotal` profile and `dns-shodan` behind `shodan`. Each has an independent core credential and a connector-owned provider key. The baseline creates the observation table, schedule field and registry rows.
- `dns-tlsprobe` reads the certificate a host and port serve right now from one bounded handshake per address against our own assets, so a validity reminder can rest on what the service serves rather than only on what a log recorded.
- `dns-shodan` confirms what our own addresses serve as an independent index saw it (certificate fingerprint, organisation, ASN, JARM, title, favicon hash) and searches, under a per-scan credit cap, where else a certificate of ours is being served. Provider data only; the free lookup is bounded separately from the credit-spending search, and the SHA-1 fingerprint is the search key because Shodan accepts the SHA-256 spelling and matches nothing.
- DNS connector provisioning, environment, verification, rotation, quota and upgrade instructions; optional CT Bearer authentication and explicit VirusTotal public-tier noncommercial acknowledgement.

- The DNSTwist worker now chooses techniques by class instead of by raw fuzzer list: `DNSTWIST_FUZZER_CLASSES` (`typo`, `idn`, `bitsquatting`, `plural`, `subdomain`, `dictionary`, `various`, `tld`) brings each technique *with* the dictionary the CLI demands beside its fuzzer, so the previous knob can no longer build an invocation the binary rejects; `typo` is the default and the expensive classes stay opt-in. A per-domain candidate cap (`DNSTWIST_MAX_CANDIDATES`, default 250) is applied before resolution, where a permutation costs no DNS request, and a shortened set is reported (`domains_truncated`) instead of looking like a domain with fewer look-alikes. Two new options default off because they widen the scan's network footprint rather than a bill: the CLI's MX check plus one free SPF TXT question, which makes `mx_without_spf` an answered fact rather than an inferred one, and page similarity (`--lsh tlsh`), reported as unavailable when the TLSh module is absent — `--phash` and screenshots are deliberately never used. The resolver is built on first use and falls back to the event loop's own resolver where `aiodns` cannot run, so a host with no permutations no longer fails a scan, and the connector refuses to start on a fuzzer class it does not know.

- The Shodan worker spends query credits by policy instead of by constant, and asks five questions it did not before. `GET /shodan/host/count` runs before a broad expression is paged, so a result set an operator cannot read to the end is refused by name and an empty one costs no search request at all; `max_pages` is an operator setting, replacing the connector's hardcoded three-page ceiling; the owned hosts that used to be filtered only after they were paid for are now `-domain:`/`-hostname:` negatives inside the query (capped, with the rest still filtered locally and counted). Five new capabilities ship off until an operator turns them on: page-body search counted before it is paged, the certificate name of a *confirmed* candidate (`ssl.cert.subject.cn`), the HTML-hash pivot read from a free lookup because only Shodan computes that hash, `org:`/`net:` pivots capped per scan, and the free `/shodan/host/{ip}` enrichment whose facts (ASN, organisation, title, icon hash, JARM, certificate names) arrive as candidate evidence instead of new discoveries. Scans report `spent`, `budget_left`, `daily_budget`, `daily_budget_left`, `retry_after_seconds`, `pages`, `billed_pages` and `free_lookups`, and a budget refusal stops the scan with a named reason rather than failing it as a provider error. Provider-reported facts now score: a candidate found by a title search, a body search or a perceptual icon match carries `title_match`, `brand_in_body` or `favicon_perceptual_match`, derived from the stored evidence and retracted when that evidence is gone. `connectors/shodan/live_check.py` is the operator-run spike that confirms the new field names against the paying account, bounded to four requests that print counters only.

- The Netlas phishing worker asks the questions a brand protection module actually needs: the certificate collection queried from *our brand* (`certificate.subject.organization:"…" OR certificate.names:*…*`) instead of only from our own domain, page text and page titles for the brand, our own favicon in the provider's index (byte-for-byte by SHA-256, and one edit away by the provider's perceptual hash), and — for the candidates an analyst has **confirmed** — the registration record and the mail facts behind each name. A brand and a confirmed candidate are now each enough for a scan to be worth queueing. The two broad expressions are counted before they are paged, and a result set an operator cannot read to the end is skipped by name; the certificate questions are paid for from the certificate bucket the provider limits to three per minute. Scans report what they could not do (`skipped` reasons, including a budget refusal or a disabled source, which stop a scan instead of failing it as a provider error) and what the allowed work cost (`spent`, `budget_left`, `daily_budget`, `daily_budget_left`), and the candidate evidence endpoint returns the allowlisted facts behind each row so a certificate claiming the brand is distinguishable from a registration record about a known candidate. Provider questions are confirmed by `connectors/intelligence/live_check.py`, an operator-run spike bounded to six requests that prints counts only.

- The phishing module answers *why* a look-alike is worth a morning from data rather than from the build that happened to run. Every accepted candidate is scored from the facts the platform observed — a young registration, a brand in the title or in the page body, a favicon matched byte-for-byte or perceptually, a certificate of ours on a foreign host, a parked name, an aged domain, corroboration by two independent sources — and the score is stored on the row with the signal rows behind it, so the list, the `?signal=` filter, the alert and the daily digest all read one number. The score decides how loudly the candidate is reported (`alert_band`: announced, digested, list-only), and an analyst's **verdict** outranks it in both directions: a confirmed candidate is announced however low it scores and re-announced when the thing changes, while a rejected one is silent in every later scan and in the digest without leaving the list an operator works from. Every decision and un-decision is one audit row naming the verdict it replaced and the score it overrode. The candidate list carries the computed age of the registration, the signals that fired with their points, and — new here — the sources behind each candidate. Alerts are assembled from the stored row at send time, so a registrar or an abuse contact resolved *after* the finding was reported still reaches the message as one follow-up rather than a second finding, and a revision of an already reported candidate names what moved (the fields that changed, with their before and after values).

- A candidate says who reported it, not only who found it. `GET /api/v1/phishing/threats` (and the single-candidate reads) now carry `sources` — the distinct source identities recorded as evidence for that candidate, sorted — and `source_count`, and the alert message prints the same fact as `Sources`. The column is read from the evidence rows rather than stored on the candidate, so it cannot drift from what the score counted: two names mean two providers agreeing, which is what the corroboration signal pays for, and a candidate with no evidence rows says so instead of reprinting the single connector that *found* it (`detection_source`). The candidate list shows the count and the names in one column and reads `not recorded` when there is nothing to show.

### Changed

- The registration enrichment pass paces itself the way registries require, and a governor that has had enough of us is no longer answered with a retry per candidate. The pass (`enrich_pending_events`, run by `process_enrichment_events` on its unchanged fifteen-second tick) claims a small batch of events instead of one, asks each *answering server* — the registry behind a name's top-level domain — at most once per pass so a scan's worth of look-alikes arrives as a trickle rather than a burst, and completes a candidate whose row already carries its registrar and registration date without a query at all: the row is the cache. A refusal (`whois_rate_limited`) holds the event *and* every other pending event of that registry for a pause measured in minutes, because that answer was about our address rather than about the name; a name nobody has registered is re-asked twice a day rather than never, because a name nobody owns can be registered; a lookup that did not answer is retried thirty seconds doubling to an hour and completed once its eight attempts are spent, so a registry nobody can reach cannot leave a pending queue every later pass re-walks; and our own destination policy refusing a target is terminal. What became of each event is written on the outbox row itself (`whois_facts_known`, `whois_pacing`, `whois_no_record`, `whois_rate_limited`, `whois_unavailable`, `whois_target_refused`, `*_exhausted`), and the task answers with a count per outcome instead of a boolean — so a quiet day and a refused registry are no longer the same result. `enrich_one_event` remains as the single-event form of the same pass.

- The provider-licence boundaries an installation works inside are now stated where an operator and a connector author each look for them. `README.md` and `connectors/README.md` say what Shodan (API integration with attribution; reproduction, resale and redistribution reserved for a separate agreement; redistribution of the database is the Enterprise Data License) and Netlas (commercial client services and derived findings on a paid plan; resale and white-label use reserved for an Enterprise add-on; use that builds a competing product forbidden; credentials not shareable) permit, what follows from it — findings are bounded facts about the operator's own assets rather than raw responses or a mirrored dataset, one credential per provider account released only to the connector bound to it, provider quotas charged before a request — and that neither vendor publishes a customer-side retention limit, which is why how long a fact is kept is this platform's own `*_RETENTION_DAYS` setting. Confirm a capability's entitlement in the vendor's console before enabling it.

- The migration history is one file: `backend/alembic/versions/` holds only `0001_initial_schema.py`, which creates the whole schema in one step and seeds the built-in modules, the connectors this release ships and their source accounts. A fresh installation applies it once. A database created by an earlier build of this repository already holds that schema and is adopted by recording `0001_initial_schema` as its revision, which `python -m scripts.migrate` does itself when it finds a recorded revision this release no longer ships; nothing is created or dropped by that write. `alembic stamp` cannot make it: stamp resolves the recorded revision before it writes, so it stops on the id the adoption exists to replace. Take a verified backup before it and treat the upgrade as a maintenance window on a populated database, where the baseline builds the matching and expression indexes in one transaction. Procedure: `docs/upgrading.md`.

- The API route reference is checked against the application instead of being trusted. `docs/api.md` listed 96 of the 106 operations the schema publishes, and nothing could tell: a reader who found seven routes in a section concluded the eighth did not exist. `backend/tests/test_api_docs_contract.py` now compares the page's route tables against the OpenAPI schema in both directions — an undocumented route, a route the application no longer serves, or an exclusion whose connector-facing route was renamed all fail the suite. It found three defects on the first run: the undocumented `GET /api/v1/jobs/{job_id}`, a `modules` row whose method/route combinations claimed two endpoints that do not exist, and a link into `connectors/README.md` whose fragment matched no heading.
- The pinning policy has one home. `SECURITY.md`, "Base images and dependency pins", states what is pinned and verified (the hash-locked Python manifests installed with `--require-hashes`, the `npm ci` lockfile) and which base image tags are deliberately left floating, with the commands to refresh or pin them. The policy was previously asserted only in passing: `dependabot.yml` cited that section before it existed, and `docs/deployment.md` claimed a rebuild pins "every base image tag" exactly, which a moving `-slim` tag does not.
- Creating or importing an asset goes through the per-user manual throttle under its own `assets` scope, so an account cannot multiply scan cost without limit while importing an inventory still leaves the window for the scan that monitors it.
- The asset detail page, the export and the import all read the inventory the same way the list does; the asset create/edit dialog validates values before sending them (`frontend/src/lib/assetValidation.ts`) and shows a `422` next to the field it names rather than as one flattened sentence.
- The delete dialog now stays open until the deletion settles, reports a failure where the decision was made, and requires the asset's value to be typed before a cascade deletes findings. `ConfirmDialog` gained `confirmDisabled` for that gate.
- `GET /api/v1/assets` sorts on the server: `sort` accepts `created_at`, `updated_at`, `asset_value`, `asset_type`, `criticality` or `is_active` and `order` accepts `asc`/`desc`, both as declared allowlists rather than strings reaching `ORDER BY`; `id` breaks ties so a row cannot appear on two pages of one listing. `search` also accepts a subnet (`10.0.0.0/24`, `2001:db8::/120`) and answers which assets sit in it; a subnet wider than 4096 addresses is refused with an explanation instead of being answered in part. The page and its `total` now come from one statement, so they cannot describe different snapshots while an operator scrolls.
- The involvement counters and the `has_findings` filter read the matching rule as a handful of grouped, index-driven lookups instead of one correlated test per asset: the rule compares `lower(rtrim(trim(x), '.'))`, which no index on the bare column can serve, and its email-to-domain branch asked with a leading-wildcard `LIKE`. Measured on 2000 assets, 100k breaches and 50k phishing findings, the per-asset form cost 7.6 s for a page of 20 rows (19 s for 50) and hit `statement_timeout` as a filter; the grouped form answers the same page in ~0.1 s (0.2 s for 50) and the inventory-wide filter in ~0.8 s. The baseline creates the expression indexes that make those predicates indexable, and the email-to-domain rule is now an equality on an address's domain part rather than a pattern match, which the cascade, orphan cleanup, breach resolution and the counters all share.
- `GET /api/v1/assets` accepts `has_findings=true|false` — the export filter takes it too — to read the inventory as "which of these are involved in something", answered under the display policy so an inactive asset keeps the findings recorded about it. The inventory and the asset page also show coverage: `GET /api/v1/connectors/modules` declares which modules and connectors consume each asset type, a type no enabled module consumes is marked **not scanned**, and the asset page names what does monitor it.
- `asset.list` is audited once per result set rather than once per request: paging through one listing no longer extends the audit chain per page (`asset.view` still records every individual asset lookup). The audit details also carry the `sort`/`order` used.
- `ruff` and `bandit` now read the whole shipped tree instead of `app` alone: `ruff check app alembic scripts tests ../connectors ../scripts ../setup.py` and `bandit -r app ../connectors`, in CI and in the Makefile. The connector tree carries its own credentials and parses provider responses, and the migration tree builds the schema a deployment starts from, so a lint scope that stopped at `app` could not see the code most exposed to the outside. The widened scope found one unused import — `backend/alembic/env.py` carried `import os` — which is removed.

### Fixed

- **The reference schema was four tables and eighteen columns behind the platform.** `docs/db.sql` is the file an operator reads to see what the platform stores without starting it, and it described 26 of the 30 tables the models map: the whole TLS certificate review workflow (`tls_certificate_identities`, `tls_certificate_sightings`, `certificate_scope_exceptions`) and the phishing signal trail (`phishing_candidate_signals`) were invisible in it, and later waves' `last_seen_at`/`verified_at` on breaches, the candidate score and verdict columns, the alert-budget columns on `system_settings` and `dns_expiry_monitors.stale_alerted_at` were missing from tables it did name. An audit two days earlier had compared the file by hand and found no difference, which is the point: nothing repeated the comparison. `backend/tests/test_schema_reference_gate.py` now compares every table, column, nullability, primary key and server default in both directions on every run, and names the two defaults the revision creates and the models deliberately leave to the writer.

- **The Breaches page told operators that HIBP domain verification had no product flow, after the flow shipped.** The README paragraph on `/breacheddomain/{domain}` still said the platform "has no flow for it and cannot tell you that a domain is unverified", while `POST /api/v1/breaches/domain-verification` issues the TXT record and checks it and `GET /api/v1/breaches/provider-readiness` reports, per domain, whether it was asked, refused and for which reason, with the newest attempt in `verifications`. The paragraph now names the route, the two steps and the readiness fields, so a refused domain has a remedy beside the empty list instead of a dashboard trip the page did not mention.

- **A test that needs a broker failed instead of skipping, so a run without one looked like a regression.** Three scheduler tests in `tests/test_celery_boundary.py` and the quota-script test in `tests/test_source_intelligence.py` open a real Redis client and exercise behaviour only a broker has — `SET NX` once per minute, the dispatch guard that blocks a second tick, the Lua script that charges a provider account atomically. They reached for `settings.REDIS_URL` (one of them for a hard-coded `localhost:6379`) and *failed* when nothing listened there, so any run outside the tooling stack — a developer's bare virtualenv, for instance — reported four red tests whose cause had nothing to do with the change under test, while the PostgreSQL suites beside them had always skipped by convention (`INTEGRATION_*` plus `REQUIRE_INTEGRATION=1`). They now take a `live_redis` fixture in `tests/conftest.py` that probes the platform's own broker URL once per session: unreachable is a skip naming the host — never the password, because `REDIS_URL` carries a deployment secret and the reason is written into a CI log and a JUnit report — and `REQUIRE_INTEGRATION=1`, which CI's integration job sets, turns the same condition into an error so a job that was given a broker and lost it cannot pass on tests that never ran. Reachability rather than an opt-in variable is deliberate: the tooling stack and CI's `backend` job supply the broker through `REDIS_URL`, so a gate on a separate `INTEGRATION_REDIS_URL` would have dropped these tests exactly where they must run. `tests/test_broker_suites_gate.py` pins every half of it — that each test file opening a real client is declared, that every test reaching one takes the fixture (including through `_run_sync(_clear_dispatch_guard, ...)`, which reaches the client without calling it), that the fixture refuses a silent skip under `REQUIRE_INTEGRATION=1`, that the skip message cannot carry the broker's password, and that both CI jobs still have a broker to provide — the environment names the URL, and the service container that answers on its port is read as well, because a `REDIS_URL` pointing at a port nothing listens on skips the same tests just as silently.

- **A UUID column could corrupt its own value, and the failure landed in whatever test read it.** Every primary key and every UUID foreign key was declared as `sqlalchemy.UUID`, which writes the literal type name `UUID` into the DDL of *every* backend. PostgreSQL has that type; SQLite, where the whole unit suite runs, does not — and SQLite's answer to a type name it does not know is affinity. `UUID` matches none of its rules, so the column was given NUMERIC affinity, which SQLite then applies to the value on insert: a 32-character hex string made only of decimal digits is a number to it, and too large for its 64-bit integer, so the row stored a REAL. Reading that row ran `uuid.UUID(1e+32)` inside the type's own result processor and raised `AttributeError: 'float' object has no attribute 'replace'`. `uuid4` draws such a hex about once in three million, so the suite met it rarely and at random: the one full run that hit it went red in `tests/test_dns_security.py`, on a read of that module's own observations, while the same test passed on its own and in every smaller selection made to reproduce it. All 48 UUID columns now declare `sqlalchemy.Uuid` — `CHAR(32)` where the backend has no native UUID (TEXT affinity, so the hex is stored verbatim) and the native `UUID` column on PostgreSQL, which is what a deployment already stores, so no data changes and no migration is needed. `Base` maps `uuid.UUID` to the same type, so a column declared by annotation alone cannot choose a different one, and the baseline revision uses it as well, so a database built by the migrations has the same shape as one built by `create_all`. `backend/tests/test_uuid_columns.py` fails a build that reintroduces the shape on either side — a column that renders anything but `CHAR(32)` on SQLite or `UUID` on PostgreSQL — and round-trips a UUID whose hex is a number to SQLite, reproducing the original traceback exactly when the type is wrong.

- **The version statements outside the core disagreed with the release.** The connector runtime announced `1.2.0` as its `api_version` and its package metadata and `__version__` said `1.0.0`, while the SPA's `package.json` said `1.0.0` — one tree built and tagged as `0.2.0`, three other numbers an operator or a bug report could read instead. Connector images are built and tagged with the platform's version and the core stores `api_version` on the connector row as the version of the build that last registered, so all of them now say `0.2.0`. `scripts/check_version_consistency.py` compares seven statements rather than three — the three it already read plus the connector SDK's `__version__`, the connector `SDK_VERSION` it registers with, the connector SDK's package metadata and `frontend/package.json` — and `backend/tests/test_version_consistency_gate.py` pins both the disagreement and the shipped tree. The wire-protocol revision stays its own integer and is deliberately not compared.
- Every timestamp the UI shows is the stored UTC instant, rendered without the reader's locale, and the table that shows one says so. The DNS Security validity column was the exception: certificate and registration expiry, and the last successful check, went through `Date.prototype.toLocaleString`, so the date on screen depended on the browser's zone and settings — a row that disagreed with the audit trail, the UTC scan schedule and the expiry thresholds an operator compares it against. Numbers are formatted with a named locale too (`Intl.NumberFormat('en-US')`), so the same count renders the same way in a screenshot, a report and a support thread, and the pages that display instants (DNS Security, Exposure, Security, Settings) now surface the time-zone hint the others already did. `frontend/src/lib/timezoneContract.test.ts` holds the rule for the whole UI — no locale-dependent formatter outside `lib/datetime.ts`, no `.toLocale*` conversion, and a time-zone hint wherever a timestamp is printed — and a failed list or card now announces itself with `role="alert"` rather than replacing the data in silence.
- The DNSTwist connector refuses to run against a CLI it was not written for, and the CLI is pinned to the release the code expects. The `dnstwist` package used to arrive from the distribution with nothing pinning it, while the connector parses its JSON, uses its fuzzer vocabulary and depends on its resolved-address dictionary — so a base-image rebase could change what a scan finds without a line changing here, and no gate or diff would say so. `connectors/dnstwist/Dockerfile` and `backend/Dockerfile` now pin `dnstwist=0~20250130-1`, and the connector verifies `dnstwist --version` before it registers: a different release exits the container non-zero with both versions and the fix in the log, instead of reporting a stream of quiet `partial` scans. Pinned by `tests/test_dnstwist_cli_version.py`, which also checks that the image pin and `_EXPECTED_DNSTWIST_VERSION` are the same release.
- The `repo-hygiene` source gate no longer fails on a developer's own virtual environment. It recognised `.venv` and `.venv313` but not a name with letters after the prefix (`.venv-alerts`, `.venv-audit`), so a local environment was reported as source hidden from the repository and the job went red for a reason unrelated to the change under test. The root `.gitignore` now covers the whole `**/.venv*/` family and the gate decides by shape instead of by a list of names, with `backend/tests/test_tracked_sources_gate.py` pinning both that false positive and the over-broad-rule case the gate exists for.
- **`requirements-dev.txt` could not be installed with hash checking at all.** `pytest` carried a hash while `iniconfig`, `pluggy`, `coverage` and `mypy_extensions` — which `pytest`, `pytest-cov` and `mypy` need — were pinned in neither manifest. `pip` turns hash checking on for the whole run as soon as one requirement carries a hash and refuses the file before collecting anything, so both the development and the CI installs stood one regeneration away from a resolution error nothing in the repository could see. The four pins are added, and `backend/tests/test_lock_requirements_gate.py` now walks the declared closure of both manifests against the metadata of the packages they installed — no network call — and fails on a package the resolution leaves undeclared, on a `MARKER_GATED_RUNTIME` dependency the source does not pin (pip does not evaluate `platform_machine` for a target it is only told about, so the generator can only keep `greenlet` by hand), and on a `requirements-dev.txt` line without a hash of its own or repeating a pin the file it includes already makes. The generator's target platforms now name `manylinux_2_28` as well: `pillow` 12.3.0 publishes no `manylinux2014` wheel and the image's glibc accepts the newer tag, so the platform list was the thing that had gone stale, not the pin.
- Dashboard `active_threats_7d` now counts only active/investigating phishing and breach findings created in the last seven days; its 30-day timeline groups by UTC date with dialect-correct SQLite/PostgreSQL expressions and zero-fills missing days. Connector health interprets naive stored heartbeats as UTC and keeps `health` and `online` thresholds aligned. SMTP alert probes are capped at four concurrent workers; timed-out workers retain capacity until their socket call exits, saturated probes report `degraded`, and disabled probes have `last_checked_at: null`.
- Metadata-only asset PATCHes no longer silently canonicalize legacy `asset_value` or populate a null `normalized_value`; explicit identity edits remain validated, canonicalized, and visible in before/after audit details.
- The dead `PaginationParams` (`skip`/`limit <= 500`) model — a second spelling of pagination with a third limit, contradicting §4.3 — is removed, and the single-tenant scope of the inventory (no owner column; roles decide what an account may do, not what it may see) is now documented as a deliberate limit rather than left implicit.
- DNS Security inventory expands resolver RRsets into individual rows and groups CT evidence by source, hostname and wildcard scope before pagination without discarding certificate history. Inline asset controls reflect existing/inactive assets; analyst deletion is confirmed, source-scoped and audited. Module action bars stay together and use the shorter Clean orphans label.
- Asset mutations and their audit rows commit in one transaction: when the audit write fails the change is refused with `503 audit_unavailable` instead of leaving an asset created, edited or deleted without a trail. `asset.update` records only the fields that really changed, with their before/after values, a type change without the value for the new type is rejected rather than silently retyped, and every asset action writes plain type names (`domain`) instead of enum reprs.
- The list `size` bound lives in one place (`MAX_PAGE_SIZE`): every list endpoint declares it, the table UI no longer offers `10000` that the API answered with `422`, and `GET /api/v1/findings` rejects an over-limit `size` instead of silently clamping it.
- One asset-matching rule (`app/services/asset_matching.py`) replaces the separate implementations in breach resolution, cascade deletion, orphan cleanup, the DNS observation inventory, expiry monitors and the connector inventory snapshot: case, trailing dot, IDNA/punycode and canonical address forms resolve identically everywhere, deleting a monitored domain also removes the breach findings about mailboxes at that domain, deleting one mailbox never touches its domain, and `casefold()` no longer diverges between the Python and SQL paths.
- Administrator orphan cleanup uses a SQL anti-join in batches instead of loading the finding tables into memory, and cascade deletion deletes linked findings in batches of 1000 ids, so neither depends on table size. Source observations are never deleted by either operation: they record what a provider saw, not what is monitored.
- `keyword_domain`/`keyword_title` values may no longer contain quotes, backslashes, control characters, or exceed 200 characters, and the Shodan connector builds provider query phrases only for values it can quote safely, reporting `skipped_keywords` in the job result instead of interpolating operator input into the query language.
- Asset matching, the asset list order and substring search are backed by indexes the baseline creates: every asset-scoped read filters on the module's denormalized `matched_asset` column and every list page ordered by `created_at, id`, both previously sequential scans. Substring search gains a `pg_trgm` GIN index, so the upgrade installs that extension and needs a maintenance window — see `docs/upgrading.md`.
- Asset deactivation, reactivation and promotion are confirmed with their consequences stated: deactivating stops scanning and matching while keeping every finding and source observation, the delete dialog reports how many findings the asset is involved in, and a promotion names the asset type and criticality it will create — with an explicit warning, for exposure observations, that a shared IP or CDN name does not prove ownership.
- Alert messages are rendered from one timestamped safe snapshot: every field the module declares is included, sensitive field names and credential-bearing URLs are redacted, and WHOIS enrichment that arrives later is not promised in an earlier message. SMTP and Telegram I/O runs after the settings transaction is committed and its objects detached, and SMTP requires TLS whenever credentials are sent — it connects to a validated numeric address while verifying the configured hostname.
- Audit retention never deletes a suffix or an unverified chunk: the expired prefix is archived, signed and verified first, revalidated in a short transaction, and `AUDIT_RETENTION_HOLD` blocks deletion outright. Scheduled verification defaults to a bounded full retained-chain pass with a persisted upper checkpoint and a fenced cursor, so a worker restart resumes instead of restarting; a truncated pass reports that it is incomplete rather than verified.
- Terminal sent/failed/cancelled deliveries and processed ingestion events expire after `ALERT_HISTORY_RETENTION_DAYS` (default 90; `0` disables cleanup). Pending, delivering and ambiguous deliveries never enter that purge, so a cleanup cannot delete work that is still owed or unresolved.

- Authentication mutations and their audit row now share one transaction: changing a password, rotating a refresh token, revoking a session (one or all others), rotating recovery codes, starting/confirming/removing a second factor and admitting a manual module or DNS Security scan all commit together with the event that records them, so an unavailable audit refuses the change with `503` instead of applying it unrecorded. Sign-out stays deliberately best-effort: clearing the browser's cookies and revoking its family must not depend on the audit store, or a brief audit outage would leave a usable refresh token on a device the user asked to sign out of.
- A DNS Security worker that is still named `dns-<source>` resolves to the historical `<source>` observation identity, exactly as it does once that label survives as an alias after a display rename — the same provider can no longer hold two identities depending on whether a rename had happened.

- **The critical-coverage gate could not pass: two scheduled tasks had no test that ran them.** `app/tasks/alert_tasks.py` measures 37 statements, and `process_enrichment_events` and `check_dns_expiry_alerts` — the WHOIS enrichment drain and the registration/certificate expiry check the scheduler calls every day — were executed by no test, so the module sat at 75.68% against its 80% floor and the `backend` job's `Validate per-module critical coverage thresholds` step failed. Both bodies own the session and the shape of what the schedule reports, which is exactly what a wrapper can get wrong while the schedule stays live, so the fix is four tests in `tests/test_alert_tasks.py` (the module is at 100% from that file alone) rather than a lower threshold.

- **Three test fixtures let the machine decide whether the code passed.** `tests/test_config.py`, `tests/test_key_rotation.py` and `tests/test_setup_env.py` build a production `Settings` without pinning `REDIS_URL`, and production refuses a broker URL with no password unless its host is loopback — so the same tests passed in CI (`redis://127.0.0.1:6379/0`) and failed on any host whose value was `redis://redis:6379/0`, for a reason unrelated to what they assert. Each fixture now pins the loopback URL, the way the positive test in `test_setup_env.py` already did.
- **The pages a reader meets first were describing a stack one release behind.** `README.md` did not name `celery-worker-alerts` at all — the worker that drains the `alerts` queue `celery-beat` fills every fifteen seconds — and explained the delivery drain as running in the scheduler, so an operator watching the wrong container would see a quiet installation; it also still said the DNS page rendered timestamps in the browser's zone after the UI moved to stored UTC instants, omitted the metrics scrape endpoint and `METRICS_TOKEN`, described the `repo-hygiene` job as two gates when it runs ten, and pointed an adopted database at `alembic upgrade head` alone. `SECURITY.md` claimed `requirements-dev.txt` carried no digests while every pin in it carries one, and the pull-request template asked for a changelog section the changelog no longer has; the two pages that list log producers and container healthchecks (`docs/observability.md`, `docs/security.md`) still named one worker. The claims are checked now rather than trusted: `backend/tests/test_github_docs_claims.py` fails when a page names a make target, a Compose service or a CI job that does not exist, and it parses the setup wizard's two promises — Python 3.8 syntax, standard library only — instead of repeating them.

- **The connection-budget warning described a configuration nobody could have.** `python setup.py --check` summed `CELERY_DB_POOL_SIZE` and `CELERY_DB_MAX_OVERFLOW` — names that appear in no `Settings` field, in no `.env.example` entry and in no Compose file — and compared the result against an unrelated constant, so the number it printed was about a deployment that cannot exist. It now computes `(UVICORN_WORKERS + the three Celery processes) x (DB_POOL_SIZE + DB_MAX_OVERFLOW) + 20` of maintenance headroom and warns against the `max_connections=200` Compose starts PostgreSQL with, naming the variables to lower. `docs/configuration.md`'s pool budget described the same sum with per-service numbers Compose does not configure (one shared pair leaves all four services at 30), so the page and the check now agree.

- DNS RRsets retain multiple addresses; CT evidence preserves wildcard scope and certificate/hostname identity; passive-DNS history retains origin and resolution time. Bounded streaming, validated pagination, safe RDAP bootstrap redirects and honest failure statuses prevent incomplete scans from appearing clean.
- DNS Rescan reports queued work and unavailable sources instead of claiming offline workers started; consistent green Rescan buttons and DNS Security navigation above Phishing.
- **A runbook pointed an operator at a page that had stopped existing.** `docs/observability.md` told whoever was on call to release a held alert recipient "from the alerts view (`docs/alerts-settings-operations.md`)" — a page that stopped existing when the alerts and settings material moved into `README.md`. The name was in backticks rather than in a link, so the link rule in `scripts/check_docs_consistency.py` could not see it and nothing else looked; that is what makes a written-out page name worth gating, because it is an instruction whether or not it is clickable. The row now names the release route and links the section that documents it, and the gate grew a fourth rule: every `*.md` name a tracked page writes has to be a file this repository has, resolved beside the page that names it and at the repository root, the two ways a reader would look. `docs/internal/` and `CHANGELOG.md` are exempt by name and say so in the module docstring — both record what a past tree contained, and an entry naming the page it deleted is the entry doing its job. Seven tests in `tests/test_docs_consistency_gate.py` hold the rule, including the defect in the words it shipped in.
- **The front page was silent about the prerequisite of an HIBP domain lookup.** HIBP answers `GET /breacheddomain/{domain}` only for a domain that is verified with HIBP and inside the subscription's domain allowance, and refuses an unverified one with `403`; the platform has no verification flow and cannot tell an operator that a domain is unverified. The connector records that refusal as a provider error on a `partial` scan, so an empty Breaches page for a monitored domain means nothing until the job has been read in Jobs history — a scan that found nothing and a scan the provider refused look the same on that page. `README.md` states the prerequisite where the provider limits are read before a first scan, and the paragraph that lists the `repo-hygiene` steps now names the tenth one (`python -m compileall -q setup.py`) it was leaving out.

### Security

- The `security` job's `pip-audit --strict` step was failing this release rather than warning about it: the lock carried `pillow` 12.2.0 and `PyJWT` 2.14.0, both with published advisories. They move to 12.3.0 and 2.15.0 with every hash regenerated by `scripts/lock_requirements.py`, and the audit reports no known vulnerability in the runtime set again.

### Removed

- Censys Platform v3, FOFA and Criminal IP connectors, provider code, Compose services, settings, tests and seeded source rows. Netlas is the only remaining optional passive-intelligence provider.

## [0.1.2] - 2026-09-29

### Security

- Make `requirements*.txt` the single source of truth for Python dependencies: the Poetry dependency tables in `backend/pyproject.toml` resolved a different tree than the image ships (fastapi `^0.115` pulled an old Starlette while `requirements.txt` pinned 1.6.x), so every Dependabot alert described packages the production image never contained. A new `repo-hygiene` gate (`scripts/check_dependency_sources.py`) fails the build if the declarations drift apart again or a pin stops being exact.
- Close every open critical/high/medium dependency finding: `pycares` 4.5.0 → 4.9.0 in the DNSTwist connector (GHSA-5qpg-rh4j-qp35), dev-only `anyio` → 4.14.2 (GHSA-82r6-8w77-94w6, TLS hostname spoofing), `react-router` 6.30 → 7.18 (GHSA-wrjc-x8rr-h8h6, GHSA-337j-9hxr-rhxg), the `vite`/`esbuild` toolchain → vite 7.3.6 + esbuild 0.28 (dev-server advisories with no 5.x backport), `vitest` → 4.1.11 (GHSA-5xrq-8626-4rwp), and `pytest` → 9.0.3 with `pytest-asyncio` 1.x (GHSA-6w46-j5rx-g56g). `pip-audit` and `npm audit` now report zero known vulnerabilities for runtime and development sets alike.
- Stabilise the frontend build chain: `tailwindcss`/`@tailwindcss/vite` leave the `4.0.0-beta` line for stable 4.3.

### Changed

- Remove the unused `pytest-httpx` dev dependency instead of forcing a runtime `httpx` bump: the suite mocks HTTP through `httpx.MockTransport` and `ASGITransport` directly.

## [0.1.1] - 2026-09-27

### Security

- Upgrade backend `msgpack` to a fixed version and pin fixed `setuptools`, resolving GHSA-6v7p-g79w-8964 and CVE-2025-47273. Remove pip's stale bundled SBOM from the runtime image so image scans report the installed package versions.
- Move the frontend runtime to a current Nginx image based on Alpine 3.23, bringing its bundled system libraries up to patched versions and addressing the HIGH/CRITICAL findings from the 0.1.0 image scan.

## [0.1.0] - 2026-09-27

First release. A self-hosted Digital Risk Protection platform: a stateless FastAPI core
that owns asset inventory, threat findings, jobs, alerting, reporting and an audit trail,
plus independent connector containers (DNSTwist, Shodan, HIBP) communicating over a unified protocol.

### Platform Core

- **Asset inventory** across 5 asset types (`domain`, `ip_address`, `email_account`, `keyword_domain`, `keyword_title`) with canonical normalization and uniqueness.
- **Dynamic Module Registry & Generic Findings** (`drp_modules`, `drp_findings`): onboard external threat intelligence sources as data without code modifications.
- **Unified Connector Protocol**: pull-based task claims (`FOR UPDATE SKIP LOCKED`), renewable job leases, heartbeat tracking, and distributed Redis admission control to protect provider quotas.
- **Alert Delivery Queue**: durable, asynchronous finding notifications via SMTP (STARTTLS / SSL / plain) and Telegram with independent per-channel and per-recipient retry states.
- **Reporting Engine**: bounded, asynchronous PDF reports with DejaVu Unicode support and row truncation tracking.
- **RBAC & User Administration**: roles `admin`, `analyst`, `viewer` with protection against removing the last active administrator.
- **Audit Trail & Integrity**: structured JSON audit logs (Elastic Security ready) with cryptographic HMAC hash-chaining (`seq`, `entry_hash`, `prev_hash`, `drp_audit_chain`).
- **Database Architecture**: PostgreSQL connection pooling with statement timeouts and graceful 503 `database_busy` degradation.

### Security

- **Multi-Factor Authentication (TOTP, RFC 6238)**: enrollment with SVG QR codes, single-use step tracking, dedicated brute-force throttling, and hashed recovery codes.
- **Enforced Admin MFA Policy** (`REQUIRE_MFA_FOR_ADMINS`): credential onboarding gate requiring second-factor setup before platform access.
- **Credential Onboarding**: temporary administrator-assigned passwords (`must_change_password`), immediate session revocation on password/status changes, and single-flight token refresh cookies (`HttpOnly`).
- **SSRF Protection & Safe Egress**: connector network guards rejecting private/internal IP ranges and cloud metadata endpoints.
- **Secret Encryption at Rest**: Fernet encryption for provider and alert secrets with key rotation support (`rotate_keys`). An undecryptable value raises instead of falling back to the stored bytes: a development fallback that returned the input would hand ciphertext back as if it were the secret.

### Changed

- **One installation shape, and it is production.** The setup wizard no longer asks which deployment this is, and it takes no flag that could select one: `--profile` is not accepted (argparse refuses it, exit code 2), and the `make up-prod` alias is gone with it. It writes `APP_ENV=production`, `AUTH_COOKIE_SECURE=true`, a pinned `OPENDRP_VERSION` and a `CORS_ORIGINS` derived from a required public URL. There is no second file to drift: `make up` starts the installation, and the source-mounted stack with pytest, ruff and mypy is named for what it is (`make up-tools`), which is what the test and lint targets use.
- **A generated `.env` can no longer send users to their own machine.** `CANONICAL_ORIGIN` is written empty. The development build used to compile `http://localhost:3000` into the frontend bundle, and `main.tsx` redirects any browser whose origin differs from it — so every visitor to a real installation was sent to their own `localhost:3000`. A re-run of the wizard (`--repair`) rewrites `APP_ENV`, `AUTH_COOKIE_SECURE` and `CANONICAL_ORIGIN` even in an existing file, because those describe the installation rather than a choice.
- **The UI is published on loopback by default** (`FRONTEND_PORT=127.0.0.1:3000`, like `BACKEND_PORT`), and the wizard warns about any bare port that would publish a service on every interface. The stack terminates no TLS: an installation is reached through the proxy in front of it, and `docker/nginx/reverse-proxy.example.conf` is a working nginx configuration for that role, self-signed certificate included.
- **HSTS is a deployment setting, off by default.** `HSTS_ENABLED`, `HSTS_MAX_AGE` and `HSTS_INCLUDE_SUBDOMAINS` replace the header that the API (`app.main`) and the frontend's nginx each hard-coded unconditionally. Both read the same three values, so they cannot disagree: `docker/nginx/hsts.sh` renders the nginx include at container start and validates it with `nginx -t`, and `app.core.config.hsts_header_value` builds the API's copy. The default is `false` because the header is a promise a browser keeps for `HSTS_MAX_AGE` seconds and cannot withdraw early — an internal installation with a self-signed certificate would otherwise lock its own users out for a year.
- **The setup wizard offers the release this checkout declares, and shows the shape of the answers that have no default.** `OPENDRP_VERSION` is the image tag every service is built or pulled as, and `make up` builds those images from this tree — so the version in `backend/app/__init__.py` (what `/api/v1/health` reports, and what `scripts/check_version_consistency.py` already treats as the single source of truth) is what the prompt offers, and `--version` stops being a required flag. A value already in the file still wins over it, so a re-run does not move an installation to another release. The public-URL prompt prints an example (`e.g. https://drp.example.com`) instead of producing it only after a refused answer, and keeps having no default: a guessed origin is a UI that refuses every request.
- **The binding questions say what they are.** The prompt asked whether to "keep the default loopback ports" next to a public URL that also takes a port, which reads as one question about one number. They are the two ends of a single connection: `CORS_ORIGINS` is the origin a browser uses (the TLS terminator), while `BACKEND_PORT`, `FRONTEND_PORT`, `POSTGRES_PORT` and `REDIS_PORT` are where the containers are published **on this host** for that terminator to forward to (`docker/nginx/reverse-proxy.example.conf` proxies `/` to the `FRONTEND_PORT` binding and `/api/` to `BACKEND_PORT`). The prompt now says so, names the loopback form, and rewrites a bare port into it — Compose reads `3000` as `0.0.0.0:3000`, which publishes an unencrypted copy of the platform next to the encrypted one.
- **`TEMPLATE` is not a section of a `.env`.** The template began with a `[TEMPLATE]` line that nothing read — not the template gate, not the wizard's own parser, not Compose — and because the wizard rewrites the template's lines in place it travelled, unread, into every file it wrote. It is gone, and so is the repair step that used to look for it: 0.1.0 is the first release, so there is no file in the wild that carries one.
- **The Shodan capability fallbacks are namespaced like every other connector setting.** `SCAN_SSL_TEXT`, `SCAN_HTTP_TITLE` and `SCAN_FAVICON` are `SHODAN_SCAN_SSL_TEXT`, `SHODAN_SCAN_HTTP_TITLE` and `SHODAN_SCAN_FAVICON`, beside `SHODAN_API_KEY` and `SHODAN_MIN_REQUEST_INTERVAL_SECONDS`. `.env` is one namespace shared by every service in the Compose file set, so an unprefixed connector setting is a collision waiting for the second connector that wants the same word — and it read like a platform-wide knob. No alias is kept: an old name is simply not read, and `python setup.py --check` reports it as *not documented in .env.example*.
- **The `CORS_ORIGINS` comment no longer describes the development shape.** It instructed an operator to change the CORS port whenever `FRONTEND_PORT` changed, which is true only when the UI is opened directly on its published port and wrong for an installation behind a terminator.

### Removed

- **No backward compatibility, by policy.** 0.1.0 is the first release, so nothing has to understand an earlier format: the platform has exactly one connector protocol, one finding shape and one installation shape, and `tests/test_no_legacy_surface.py` fails a change that reintroduces a compatibility branch.
- **An `ENCRYPTION_KEY` that is not a valid Fernet key is a startup error in every environment.** A development build used to derive a 32-byte key from whatever was in the setting — a passphrase, or the placeholder the template ships — so a development database written that way kept opening. The derived key cannot read what the real key wrote, and nothing outside production refused the value: the setting is validated in every environment now, and the failure names `ENCRYPTION_KEY` instead of surfacing later as a stored secret that cannot be decrypted. Pinned by `tests/test_crypto.py`.
- **The connector protocol has one shape.** Registration requires `default_job_type` and `api_version`; the SDK refuses to start without `CONNECTOR_JOB_TYPE`; a job is finalized only with the lease token its claim returned (the lease-less path and the `params["claimed_by"]` marker are gone); and the shared `connector.scan` job type is gone, so every job type is declared by the connector that owns it. Provisioning, the one path that creates a row *before* a connector can declare anything, reserves `<module>.<name>` explicitly and the connector re-declares its own type on first registration; nothing infers a job type from a name.
- **Breach submissions take provider fields only inside `attributes`.** The top-level vendor fields (`is_verified`, `masked_password`, …) were folded into `attributes` for connectors built before the payload became provider-neutral; a payload that puts them next to `breach_name` is now refused instead.
- **The audit trail has no unverifiable prefix.** `drp_audit_logs.entry_hash` is NOT NULL and the single writer signs in the inserting transaction, so the verifier no longer tolerates unsigned rows: one is a break, not history.
- **The alert queue has no `aggregate` channel, and the per-finding delivery path is gone.** `AlertDelivery.channel` names a concrete destination (`email` or `telegram`); an installation with no channel configured queues nothing instead of storing a row that no destination can satisfy. `app/services/event_hooks.py` and `AlertService.send_alert_notification` — dead since every finding started going through the queue — are deleted, together with the two templates only they rendered.
- **The Celery task header is read under one name.** A task's request id travels in `X-Request-ID` and nowhere else. The second spelling the signal handler accepted is gone: `request_id_header()` is the only producer, so a header under another name is not this platform's id, and adopting it joined one request's log lines to another's task.
- **`takedown_status` is renamed to `status`.** The column was named after a workflow the product does not have.
- **The breach API group is `/api/v1/breaches`, not `/api/v1/hibp`.** The routes kept the first source's name "for deployed clients", which a first release does not have: `app/api/v1/routers/breaches.py`, `app/schemas/breaches.py` and the SPA's `scanBreaches*` calls now name the module, and the page fetches `/breaches`, `/breaches/{id}` and `/breaches/scan*`. The HIBP connector remains what it always was — one source that fills the module.
- **The first-party connectors' job types name the module, not the workflow.** `hibp.scan` is `breaches.hibp`, which is what the manifest reservation reserves for that connector anyway, so a job type now reads the same way in the registry, in the job list and in the shipped `.env.example`/Compose files as it does in the rule that produced it (`<module>.<connector>`).
- **Pagination is spelled `size` only.** `GET /assets` accepted a bounded `limit` alias for early clients; an unknown parameter can no longer change how many rows come back.
- **The SPA keeps nothing about the session in browser storage, and no longer cleans up after a build that did.** A startup step removed a `localStorage` key written by an earlier development build; nothing predates this release, so the bootstrap only asks the API (`POST /auth/refresh`) whether the browser has a session. Covered by `frontend/src/main.test.tsx`.
- **`docs/refactoring-baseline.md` is deleted.** An internal pre-refactoring measurement of module paths that no longer exist; `docs/production-readiness.md` carries the current status. `tests/test_no_legacy_surface.py` now fails a build that cites a revision, an endpoint or a vocabulary the release does not have.
- **The worker no longer listens on queues nothing publishes to.** `celery-worker` consumed `default,phishing,hibp,reports,alerts` while `task_routes` publishes only to `default`, `reports` and `alerts`; the two extra names were module and provider vocabulary in a core configuration file, and connector work never travelled through Celery at all. A `phishing` or `hibp` queue is now as impossible to configure as it always was to reach.
- **Ingestion no longer dispatches alerts itself.** Every finding is handed to the durable alert queue (`AlertDeliveryService`), which a worker drains, so an SMTP or Telegram outage cannot delay, fail or roll back a finding that is already stored.
- **A delivered alert says the shape of what it found, not just how much.** The message opened with one aggregate number followed by one undifferentiated line per finding, which is the same reading whatever the batch contains. It now leads with the count, breaks it down by the values the module considers worth counting (source and matched asset for phishing, the breach and its domain for a breach), and then lists each finding as a numbered monospace line with the fields that describe it. The email carries the same content as a table — one row per finding, columns from the module's own declared fields — with the plain-text alternative spelling out the same facts, and a button back to the finding page. Values are clipped before they are escaped (one 4 KB "domain" from a source can no longer push every other finding out of the message), and the counted values are capped with a `+N` tail rather than listed in full. A message links back to the finding page only when the installation knows its own address: the link comes from the first non-loopback `CORS_ORIGINS` entry, and the template's default is no link at all. It used to default to `http://localhost:3000`, which in a delivered message is a link to the reader's own computer.
- **An alert uses the platform's own email layout.** `emails/finding_summary.html` extends `emails/base.html` — the layout the platform already ships for its operational mail, dark header and all — instead of bypassing it with a standalone document, so an alert no longer looks less like this product than the warning next to it.

### Added

- **The scheduled jobs are checked against the tasks the application registers.** A `beat_schedule` entry is only a string until a worker resolves it, so a renamed or misspelled task stops its work with the scheduler still reporting healthy. `tests/test_celery_wiring.py` now fails a build in which any scheduled entry names a task nothing registers.
- **A public origin that no binding serves is reported.** A plain-HTTP loopback origin (`http://localhost`, port 80 implied) while the UI is published on `127.0.0.1:3000` is the mistake the two prompts invite: nothing serves that port, the SPA keeps working (its requests go to its own origin through the frontend's `/api/` proxy, where no CORS check happens), and the file ends up recording an origin nobody can open. `python setup.py --check` reports it as a warning — a proxy on that port is a legitimate reading — and names both ways out.
- **A version that disagrees with the checkout is reported.** Settings reports `OPENDRP_VERSION` while `/api/v1/health` reports the running code's version, so a file pinning anything else has one installation displaying two versions. A note rather than a warning: `make pull-prod` pulls a release tag deliberately, and that is the one case where the two differ on purpose.
- **`scripts/check_env_template.py` gained rule 5: a connector-scoped setting has to be namespaced.** An entry the template documents that a connector reads and the platform does not must start with that connector's name, or be listed in `CONNECTOR_SHARED_VARS` with a reason (`DNS_NAMESERVERS` is the single exemption). The rule was written for the `SCAN_*` defect above, and it fails the build on the next one.

### Fixed

- **A model column that no revision created stopped a fresh deployment from starting.** `SystemSettings` mapped `telegram_chat_id` while the consolidated baseline created only `telegram_chat_ids`, so the startup seeder — the first ORM read in the entrypoint, and the same select the application lifespan performs — raised `UndefinedColumnError`, `set -e` ended the container, and Compose reported only `dependency failed to start: container opendrp-backend is unhealthy`. No test could see it: the unit suite builds its schema from the same metadata under test, and the migration test asserted a hand-written subset of columns. `scripts/check_schema_drift.py` (database-free, run in CI and by `make check-backend-migrations`) and the PostgreSQL parity test in `tests/test_alembic_migrations.py` now fail a build that reintroduces this shape, and the same suite runs the startup seeder against a freshly migrated database.
- **The seeded module registry now matches the application's own definitions** — label, description, `asset_types`, `fields`, `dedup_fields` and `storage`. The baseline had seeded `storage.adapter = "breaches"` where `ingestion_service` dispatches on `"breach"`, which would have sent every breach finding down the generic path into `drp_findings` instead of the breach table, without raising anything.
- **A secret containing `*` or `•` can be stored.** The masked-value guard refuses a value that *is* the UI placeholder (a run of mask characters) rather than any value containing an asterisk, which had made a legitimate password impossible to save.
- **The WHOIS enrichment suite depended on a real resolver.** `WhoisService.enrich` runs the outbound destination guard before every lookup, and that guard resolves the domain — inside the same budget the lookup itself is given. The tests let the guard resolve `evil.example` for real, so a resolver that hung for the budget expired it first and left the finding untouched: an intermittent failure, which showed up as one failing test in a full run under coverage instrumentation. The suite now inlines the guard, which is hermetic and quicker; the destination policy itself is still pinned in `tests/test_outbound_guard.py`.
- **The critical-coverage gate could not pass.** `scripts/check_critical_coverage.py` requires `app/services/alert_delivery_service.py` and `app/tasks/alert_tasks.py` to be measured, while the pytest runs in CI and in `make test-backend-critical-coverage` passed `--cov` only for the modules next to them — so the report had no entry for either file and the job failed on a missing module rather than on coverage. Both runs now measure every module the gate names.
- **`celery-beat` started, but not with the environment the application requires, so the whole schedule was dead.** Its `environment` block did not pass `AUDIT_CHAIN_KEYS` — `backend` and `celery-worker` both got it — and in production `Settings` refuses to load without it, so the scheduler exited on import and `restart: unless-stopped` restarted it forever. The only trigger for alert delivery is a beat-scheduled task (`deliver-pending-alerts-every-15-seconds`), so the visible symptom was that findings were stored, the queue filled with `pending` rows, and no email or Telegram notification was ever sent, while every health endpoint reported healthy. Three other scheduled jobs had silently stopped with it: the retention sweep, the scan-schedule refresh and the nightly audit-chain verification. `scripts/check_compose_healthchecks.py` now fails a build in which a service that carries `APP_ENV` — the three that run the application — is missing any setting production startup requires, with the requirement list itself pinned against the real `Settings` model by `tests/test_compose_settings_gate.py`.
- **A scan that found fewer results than expected could not be explained by the job that produced it.** The Shodan connector reported the capabilities that *ran* (`capabilities_run`) next to a single aggregate count, so the three reasons a capability can come back empty — it matched hosts the platform already stores, it had nothing to search with, it is broken — were indistinguishable in the job history, and the only way to tell them apart was to re-run the scan by hand. Each capability now reports its own `queries`, `matches`, `candidates`, `stored` and `skipped` under `capability_results`, and the count that used to read as a loss is now legible: `matches` above `stored` is deduplication (`phishing_domain` is unique in the core, so a re-found host refreshes the row it already has instead of adding a second one). DNSTwist reports the same three steps — `candidates` generated, `resolved` to a public address, `new_discovered` stored — so a scan that discovered nothing says which of the three produced the zero. `tests/test_connector_runtime.py` pins both summaries, and the job list renders grouped counters as `ssl (matches=21, stored=10)` instead of truncating them as JSON.
- **My security listed sessions that had already been signed out, as if they were devices still holding the account.** Every sign-in writes a `drp_refresh_families` row and every password change rotates the session, so an account collects rows it can no longer act through — and `GET /auth/sessions` returned them with a `revoked` flag under a card titled *Active sessions*. On the live installation that made the two sessions the administrator had already closed (each one replaced by the next password change) read as two unknown devices, which is exactly what that card is for. The endpoint now answers with sessions that can still be used, the `revoked` field is gone because it could never be anything but false, and the component's branch that rendered "(revoked)" is gone with it: what ended a session is the audit event `auth.password.changed`, `auth.session.revoked` or `auth.sessions.revoked_others`, shown in prose in the activity list on the same page. The card also states that this browser is the only session, and its "sign out other sessions" button reports how many that would be and is inert at zero. Revoking one refreshes the activity list as well, so the session that was listed a moment ago appears in it immediately — the two cards now answer the same question from either end. Tests: `tests/test_auth_integration.py` (a signed-out session is not returned; the ended one is still on record in the activity list) and `frontend/src/pages/SecurityPage.test.tsx`.
- **Session rows accumulated forever.** Nothing removed a `drp_refresh_families` row — not even after the refresh token it described had expired, which is when the row stops being a security control (it is what turns a replayed token into `family_revoked` rather than `family_not_found`) and becomes a row nobody reads. `run_retention_sweep` now deletes revoked families once `JWT_REFRESH_TOKEN_EXPIRE_DAYS` have passed since they were revoked, bounded by the same batch settings as the other sweeps; a live session has no `revoked_at` and can never be selected, which is what the new tests in `tests/test_retention_tasks.py` pin.
- **My security listed raw audit codes, so the account holder could not tell what had happened.** The page rendered `auth.mfa.enrolled`, `auth.password.changed` and the rest verbatim: the names are the audit trail's filter vocabulary, and the reader there is the person the event is *about*. Every event now reads as a sentence — "Second factor turned on", "Password changed — 3 other sessions signed out", "Sign-in attempt refused — the password did not match an active account" — with the action code kept underneath as the name the audit log and a support request use. Refusals and replayed refresh tokens are emphasised (`authTone`), so "did somebody else try" is visible without reading the whole list, and an empty list says so instead of showing nothing. The wording lives in `frontend/src/lib/audit.ts`, shared with the audit log, which had its own summary function duplicating half the vocabulary; a description is built from the entry's own `details`, and an action with no sentence of its own is humanized with its details rather than printed as a code. `frontend/src/lib/audit.test.ts` fails when an action `GET /auth/security-activity` can return has no description.
- **An alert arrived as one solid line.** The aggregated summary was built with the newline escape double-escaped in the literal (`f"...SUMMARY</b>\\n\\n"` instead of `\n`), so the delivered text carried a backslash and an `n` where a line break belonged: Telegram rendered the bold header correctly and then every finding on one unbroken line, and the `text/plain` alternative of the email did the same. Exactly one code path was affected — the queued per-job summary — which is why every other message the platform sends (the Settings test message, the operator warnings) was fine. `tests/test_alert_message_format.py` renders the ten findings the live phishing job produced and fails a build whose delivered text contains a literal `\n` or no real line breaks.
- **A long alert could be cut inside its own markup.** The Telegram summary was truncated with a plain slice, so on a batch large enough to hit the length limit the slice could land between `<code>` and `</code>` or inside an entity; Telegram answers that with `400 can't parse entities`, which the delivery queue records as a *permanent* failure — an alert lost to a length check rather than to an outage. The finding list is now dropped line by line against a budget that reserves the footer and the note saying how many findings were left out, so the message always says what it left behind instead of quietly ending mid-finding. Pinned by the long-batch case in the same suite.
- **The email summary of an aggregated alert was a JSON dump in a table cell.** `emails/generic_finding_alert.html` rendered whatever it was given as one row per top-level field, so the aggregated path — which passed `json.dumps(rows)` under the key `Findings` — produced an inbox message whose entire content was an escaped JSON array, under a footer claiming the fields were "its own declared finding fields". That template is gone: `emails/finding_summary.html` renders a real findings table (one row per finding, columns taken from the fields the module declared), the batch's counts, and the link back to the platform.
- **The favicon capability could never follow a redirect, so a domain whose `/favicon.ico` had moved was searched for nothing at all.** The redirect branch validated that the target stayed on the domain whose addresses had just been resolved and then returned `None` anyway — dead code that turned a common shape (`/favicon.ico` → `/static/icon.png`, or an http → https hop) into a silent zero findings, while `capabilities_run` still claimed the capability had run. Same-host redirects are now followed up to three hops, each one rebuilt from the already-validated host so a `Location` header cannot smuggle userinfo or another authority into the request; an off-host redirect still ends the lookup, and both are covered by tests.

- **A refused connector credential left no trace on the platform's side.** The core answered a bare `401` to whatever presented a stale token and said nothing else, so replacing a key was guesswork: the value lives in `.env` and the core stores only its digest, which means "which connector's token went stale" had to be read out of the connector's own output — output a bounded restart loop (`restart: on-failure:10`) scrolls away, while the registry merely showed nothing had been seen from it. Every refusal is now logged as `connector_credential_rejected` with the name the token *carries*, the path it was presented on and the caller's address, throttled to one line per connector per minute so a connector polling every five seconds does not become the log. The name is read from the token's own label and is a hint for that line only — never an identity, since a caller chooses it, and authorization still comes solely from a digest that resolves. Pinned by `tests/test_connectors_protocol_api.py` (the label is reported, a valid connector's name in the header cannot hide it, a credential that carries no label is still reported, polling does not flood, an accepted credential writes nothing) and by the label reader's own tests in `tests/test_connector_credentials.py`.

### Documentation

- **Quick start carries the whole connector-credential procedure.** Step 3 has the complete issue, rotate, revoke and list commands for all three first-party connectors (`dnstwist`, `shodan`, `hibp`) as single lines that paste into bash, PowerShell or `cmd.exe`, together with the `make` equivalents and the reason a recreate — not a restart — is what applies a new value.
- **Provider plan limits are stated rather than discovered.** Shodan's SSL-text and favicon searches need a key of at least the **Membership** tier, and a lower tier reports a partial scan instead of a clean empty one; HIBP's integration key (`00000000000000000000000000000000`) with its two fixture assets is documented in the README, `connectors/README.md` and `.env.example`, so a new installation can complete an end-to-end breach scan before anyone buys a subscription.
- **`docs/deployment.md` has a section on the origin and the bindings.** What each of the five settings is, what it is not, and which one has to change with which — the question two similarly-named prompts used to leave open.
