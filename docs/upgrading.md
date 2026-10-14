# Upgrading OpenDRP

This document is the operator's checklist for moving a running installation to a
newer release, and for getting back to the previous one. It describes the
supported procedure, not every possible one.

The short version:

```bash
make backup                     # 1. an upgrade you cannot undo is a migration
# 2. set OPENDRP_VERSION to the release you are moving to, in .env
make up                         # 3. build and start; the API migrates itself
make health                     # 4. confirm the instance and the API answer
```

The API container applies pending migrations at startup, serialised by a
PostgreSQL advisory lock (`backend/scripts/migrate.py`), so two replicas starting
together cannot race. Moving the schema *before* the API starts is still useful
for a large migration, and is described in step 4 below.

## Versioning and where a version lives

Releases are Git tags of the form `vX.Y.Z`, published as multi-arch images at
`ghcr.io/<owner>/opendrp/<image>:X.Y.Z`, with an SBOM and build provenance
attached (see `.github/workflows/release.yml`).

The platform version is declared once, in `backend/app/__init__.py`, and
`GET /api/v1/health` reports it — that endpoint is the authoritative answer for
"what am I running". `scripts/check_version_consistency.py` fails the build if
that value, `backend/pyproject.toml` and the newest `CHANGELOG.md` entry
disagree, and the release workflow refuses to publish a tag that does not match
the code, so a tag cannot name a version the images do not report.

An installation pins the release through `OPENDRP_VERSION` in `.env`:

```dotenv
OPENDRP_VERSION=0.2.0
```

Left unset, Compose resolves every `opendrp` image to `:latest`. The wizard always
writes a pinned version, and the application refuses to start without one when
`APP_ENV=production`, so an unset value survives only in a checkout you are
building locally. `latest` is a moving target, and "the same version" stops being a
statement anyone can check. Pin the version.

## Before you upgrade

**Take a backup, and know that it restores.** An upgrade is the one operation
where the previous state is not recoverable from the repository, because the
schema moves with the images.

```bash
make backup          # pg_dump + report store into ./backups, then verified as readable
make backup-verify   # restores the newest dump into a throwaway database and checks it
```

`docs/backup-restore.md` covers off-host copies, retention and what is *not* in
the dump.

**Read `CHANGELOG.md` for the releases you are crossing**, not just the target
one. Configuration keys, migration steps and log shapes change there, and the
entry is curated for exactly this purpose. Entries that need operator action
carry an explicit warning.

**Check `.env.example` for new keys.** A release that adds a setting ships its
default in `.env.example`; compare it with your `.env`. In production a missing
*required* value is a startup failure rather than a silent fallback — that is
intentional, and it is why this step is early in the list.

The mechanical form of this step reads the diff for you, without writing
anything:

```bash
python setup.py --check
```

It reports settings the template defines and your file does not mention (each
with a default), keys your file has that the template never documents (a typo is
silent otherwise), any value still holding a placeholder, and the production
rules the application enforces at startup — the Fernet key's shape, the audit
chain key, the cookie flag, the subnet nesting. `--repair` then fills exactly the
empties and placeholders, leaving every value that already works alone.

## The upgrade

### 1. Stop the writers

```bash
docker compose down
```

Not strictly required for every release, but it removes the window in which an
old worker writes rows that a new schema cannot represent. For a small
installation the downtime is seconds; for a two-replica deployment this is the
step that makes the migration a single, unambiguous event.

### 2. Set the target version

```dotenv
OPENDRP_VERSION=0.2.0
```

### 3. Start the new images

An installation that runs published images moves to them first:

```bash
docker compose -f docker-compose.yml pull
```

A source installation builds the images from the tree instead. This checkout is
one: 0.2.0 declares its version but publishes no registry images, so a `pull` has
nothing to fetch and `make up` is what builds and starts the stack.

```bash
docker compose -f docker-compose.yml build
```

Then start the stack, either way:

```bash
docker compose -f docker-compose.yml up -d
```

The API container runs `python -m scripts.migrate` before it serves a request:
that script takes a PostgreSQL advisory lock, runs `alembic upgrade head`, and
releases it, so two replicas starting at the same instant serialise instead of
both deciding the same migration is pending. Nothing else is needed for an
ordinary upgrade.

### 4. Moving the schema ahead of the API (optional, for large migrations)

For a migration that rewrites a lot of rows it is worth applying it while the old
API is still running and the new one is not yet started, so the window in which
the API is unavailable is not sized by the migration. After the pull or the build
above and before `up`:

```bash
docker compose -f docker-compose.yml run --rm backend python -m scripts.migrate
```

Then confirm and start:

```bash
docker compose -f docker-compose.yml run --rm backend alembic current   # the new head
make up
make health                                                             # API + container status
```

If a migration fails, stop here and restore rather than improvising:
`CONFIRM_RESTORE=yes make restore FILE=backups/<dump>`. A partially applied
migration is a state neither release supports.

### 5. Verify the instance

- `GET /api/v1/health` reports the version you intended (`jq .version`).
- Sign in, open **Dashboard**, and confirm one connector reports a recent
  heartbeat (**Settings → Connectors**).
- The audit page shows new records — which also confirms the audit writer, the
  most load-bearing table in the schema, survived the upgrade.

## The schema and its single revision

`backend/alembic/versions/` holds one revision, `0001_initial_schema`, and it has
no parent. It creates the whole schema in one step — identity, assets, phishing,
breaches, DNS Security observations, exposure inventory, modules, findings, jobs,
connectors, source accounts, settings, the audit trail with its archive, the alert
queue and the report lifecycle — and seeds the built-in modules, the connectors
this release ships and the source accounts they draw on. A fresh installation
applies it once through the normal `alembic upgrade head` startup path, and
`docker compose exec backend alembic heads` confirms it inside a running
installation: there is no intermediate state left to rehearse and no
revision-by-revision checklist to read, because the schema a deployment runs is
the schema this release describes.

Nothing in the baseline deletes anything. The providers this platform does not
ship (Censys, FOFA, Criminal IP) are simply not seeded, and their provider code is
not in the repository; observations already recorded for them stay readable as
evidence.

The two index families described below are the only part of the baseline that
behaves differently on a populated database than on an empty one, so a populated
database still moves in a maintenance window — the collapse changed the shape of
that window, not whether one is needed.

### A database created by an earlier build

A database an earlier build of this repository created already holds this schema.
Alembic cannot move it on its own, because the revision id recorded in
`alembic_version` names a file this release no longer ships, and `alembic upgrade
head` refuses to start rather than guess what that file would have done. Adopting
it means recording the revision the database is already at:

```bash
make backup                       # the dump is what makes this reversible
docker compose exec backend python -m scripts.migrate
```

`scripts/migrate.py` recognises a recorded revision outside the script directory,
logs `migration_adopted` and records `0001_initial_schema`: nothing is created and
nothing is dropped. A revision it cannot place is refused rather than guessed at,
which is the case of a database this project did not create.

When the API container is not running, the same step by hand is the row itself —
`alembic stamp` cannot do it, because stamp reads the recorded revision before it
writes and stops on the id this one command exists to replace:

```bash
docker compose exec postgres psql -U opendrp -d opendrp -c "UPDATE alembic_version SET version_num = '0001_initial_schema'"
```

Recording the revision states a decision; it does not check one, so confirm the
equality first.
`make check-backend-migrations` runs both halves of that check inside the running
backend container — the ORM models against the schema the revision builds, and
`Base.metadata` against a database migrated from scratch — and
`tests/test_alembic_migrations.py` does the same round trip in a disposable
database. If`make backup` or `make backup-verify` did not succeed, stop here rather than recording the revision: restoring that dump is the only path back.

Then add only the integration variables `.env.example` has gained; existing
provider and worker secrets must be preserved. Two of them are new and optional —
Compose's defaults apply when the file omits them: `MIGRATION_LOCK_TIMEOUT_MS`
bounds how long the upgrade waits for a lock before failing with PostgreSQL's own
`lock_timeout` error (the alternative is a container that is merely "unhealthy"
while the startup migration blocks, with nothing naming the wait), and
`MIGRATION_STATEMENT_TIMEOUT_MS` is `0` on purpose, because the index builds below
are legitimately the longest statement this platform runs. Configure DNS sources
through the [DNS connection guide](dns-security.md#connect-the-workers) and paid
passive providers through the
[source intelligence guide](source-intelligence.md#opt-in-setup).
Schedules dispatch ready sources independently, but disabled or unconfigured
entries stay blocked, and provider workers still need explicit enablement and an
approved source-account budget. The base Compose startup does not enable optional
worker profiles.

### An index the baseline gained after your build was created

Adoption records a revision and creates nothing — that is what makes it safe on a
database with data — so an index the baseline has gained *since* the build that
created your database is not there afterwards, and nothing says so: the queries it
exists for keep working, only slowly. Two were added after the collapse, both for
work that repeats on a timer:

```bash
docker compose exec postgres psql -U opendrp -d opendrp -c "CREATE INDEX IF NOT EXISTS ix_jobs_status_created ON jobs (status, created_at)"
docker compose exec postgres psql -U opendrp -d opendrp -c "CREATE INDEX IF NOT EXISTS ix_ingestion_events_due ON ingestion_events (kind, processed_at, next_attempt_at)"
```

`ix_jobs_status_created` serves the claim every connector makes on every poll
(`status='pending'`, ordered by `created_at`), and `ix_ingestion_events_due`
serves the outbox dispatcher, which selects the unprocessed, due rows every
fifteen seconds. Both are plain `CREATE INDEX` — not `CONCURRENTLY`, which cannot
run inside a transaction and so cannot run inside a revision either — so they
belong in the same maintenance window as the upgrade. Run them after the upgrade,
not before: the revision creates them itself, and `CREATE INDEX IF NOT EXISTS` on a
database that already has them is a no-op. A database this release created has
them already, and `\di ix_jobs_status_created` is what tells the two cases apart.

### The baseline's index families take a write lock

Building an index is not a lock-free operation: `CREATE INDEX` holds a lock that
blocks writes to the table for the duration of the build, and Alembic runs the
whole revision in one transaction. The baseline creates the indexes behind asset
matching, the asset list order and substring search, and — over expressions rather
than columns — the ones the matching rule itself compares. On an installation with
a large `drp_findings`, `drp_phishing_domains` or `source_observations` table those
builds are the longest part of the upgrade, so run it in a maintenance window
rather than during peak ingestion; a fresh database builds them in milliseconds.
`CREATE INDEX CONCURRENTLY` is not an option here: it cannot run inside a
transaction, and therefore not inside an Alembic revision.

The baseline also installs the `pg_trgm` extension, which its substring-search
indexes use, and `uuid-ossp` for the UUID defaults. The role that runs migrations
must therefore be allowed to create extensions in the database — which is the case
in the shipped Compose deployment, where the application role owns the database.
`downgrade()` drops the indexes and deliberately leaves both extensions installed:
an extension is database-wide, and another index or an operator's own query may be
using it.

The expression indexes exist because the matching rule never compares a stored
column: it compares `lower(rtrim(trim(x), '.'))`, and an index on the bare column
cannot serve that predicate. Without them the involvement counters on the asset
list and the `has_findings` filter fall back to scanning the module tables —
measurably (2000 assets, 100k breaches: 7.6 s for a page of 20
rows, and a `statement_timeout` refusal when the same rule was used as a filter).
The expression has to stay character-for-character equal to the one
`app/services/asset_matching.py` renders; a test compares the stored definition
so a refactor of the helper cannot silently orphan the indexes.

### Values worth checking by hand

**A setting that moves keeps neither an alias nor a fallback, by design.** The old
name is simply not read, and `python setup.py --check` reports it as *not
documented in .env.example* — which is the intended instruction rather than a
silent default. Recreate the container that reads it afterwards
(`docker compose up -d <service>` — a plain `restart` keeps the environment the
container was created with).

**The seeded rows are part of the schema.** `ingestion_service` selects the write
path from `drp_modules.storage->>'adapter'`, and an adapter it does not recognise
sends every finding of that module to the generic table instead of its own — no
error, just the wrong table. Two gates make that class of drift impossible to ship
unnoticed: `python -m scripts.check_schema_drift` compares the ORM models with the
schema the revisions build (no database needed), and the PostgreSQL migration test
suite compares `Base.metadata` with a migrated database *and runs the startup
seeder against it*. Both run in CI. `make check-backend-migrations` runs them on demand, inside the
running backend container, so it needs the installation up (`make up`) rather than
just checked out.

`scripts/check_migrations.py` enforces that every revision has a `downgrade()`
and that a deliberately empty one says so, so a release cannot ship a migration
that has no way back. A downgrade is still a schema change: it is only safe
together with the images that match it, which is what the next section is about.

### Source accounts and uniform connector labels

The labels are one scheme, and the baseline seeds exactly it. Every bundled
connector is named `<module>-<provider>` — `phishing-dnstwist`, `phishing-shodan`,
`phishing-netlas`, `breaches-hibp`, `dns-rdap`, `dns-resolver`, `dns-ctlogs`,
`dns-virustotal`, `dns-netlas` — with a `-<task>` suffix where one provider serves
several sources, as in `exposure-netlas-endpoints`, and the module id is the word
the job type uses (`dns.rdap`, not `dns_security.rdap`). Compose service names
follow the label (`connector-phishing-dnstwist`, `connector-dns-rdap`).

Each seeded row also carries its earlier label as an alias, and the first alias is
what the source identity is derived from: a connector image that registers under
the name it was built with still authenticates, still owns its job type, and still
attaches its observations to the same provider, so an upgrade does not fork a
source's history. The same holds for `CONNECTOR_NAME` values and issued-token
labels. `dns_security` remains accepted as an alias for the module id and for a
connector's type, and the `schedule_dns_security` column keeps its name. Provision
new connectors with the current label rather than an earlier one, which would be a
second identity for the same source.

A provider account is separate from an individual module worker. Existing
account groups are created with `approved: false`, so explicitly review Settings
→ Connectors → Provider accounts and set a conservative requests/minute and
daily budget before enabling a provider worker. Credentials stay in each
worker's environment/secret manager; `credential_ref` stores only the variable
name. Jobs freeze account limits, connector config, manifest and target assets
when queued, so editing a policy affects future jobs only.

Breach identity is per source account: `(source_id, breach_name, matched_email)`,
with the partial-index domain fallback where a provider reports no address. Two
providers reporting the same incident are two rows, which is the point — the same
breach seen twice is evidence, not a duplicate. Run
`python -m scripts.check_schema_drift` before the deployment and perform the
PostgreSQL migration round-trip in a disposable test database before rollout.

## The broker password and the network split

Two properties of the stack an operator has to know about, both about the same
boundary: the containers that hold a credential.

**Redis is the Celery broker, and it requires a password.** Not a cache that can
be thrown away: anything able to open a socket to it can push a task the worker
executes with the platform's own database credentials, read the payloads of every
other participant, and clear the rate-limit counters. Compose requires the value,
so the stack will not come up without it:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Put the result in `.env` as `REDIS_PASSWORD`; Compose builds `REDIS_URL` from it
(`redis://:${REDIS_PASSWORD}@redis:6379/0`). The application refuses to start with
a non-loopback `REDIS_URL` that carries no password, so a deployment that is not
run through Compose is covered by the same rule. Rotating it later is two moves:
change the value, then `docker compose up -d --force-recreate redis backend
celery-worker celery-beat` — the broker and its clients must agree, so recreate
them together rather than one at a time.

**The stack is three networks, not one.** `opendrp-edge` carries the frontend and
the API; `opendrp-net` carries the API, the workers, PostgreSQL and Redis;
`opendrp-connectors` carries the API and the connector containers. A connector is
code this platform did not write, and it does not sit on the network that holds
the broker and the database — it has the token it was issued and the API, and
nothing else.

The subnets are `OPENDRP_EDGE_SUBNET` / `OPENDRP_DATA_SUBNET` /
`OPENDRP_CONNECTOR_SUBNET`, carved out of `OPENDRP_NETWORK_SUBNET` (the parent
range named by `TRUSTED_PROXY_IPS`). If your host already uses `172.18.0.0/16`,
set all four variables to a free range before the first start. The application
validates the relationship at startup: a sub-app outside the parent is a startup
error rather than an audit trail that quietly records nginx's address instead of
the client's.

## The audit chain key

The audit trail is hash-chained: every entry carries an HMAC over its own
fields and the previous entry's hash, so an edit, a deletion or an insertion
anywhere in the stored history is detectable by recomputing the chain. The key is
the whole point — without it, anyone who can write to the audit table can also
recompute what they changed — so in production it comes from the environment and
is required at startup.

It is deliberately *not* `ENCRYPTION_KEY`. Reusing one secret for two purposes
makes rotating either one a change of both, and the chain has to outlive a
Fernet rotation to be worth anything: an audit reader verifies a year of history
with the key that was in force when it was written.

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Put the result in `.env` as `AUDIT_CHAIN_KEYS`. A non-production deployment that
leaves it empty derives one from `ENCRYPTION_KEY` so that the code path is
exercised everywhere; production refuses to start without an explicit value,
because a derived key silently stops verifying the moment `ENCRYPTION_KEY` is
rotated.

Every audit row is signed by the writer that created it, so the verifier has
nothing to excuse: an unsigned row is a break. Run the check once after
upgrading, and nightly from then on (`verify_audit_chain` is on the beat
schedule):

```bash
make verify-audit-chain
```

The same result is available over the API to an administrator
(`GET /api/v1/audit/integrity`), and both write `audit.chain.verified` or
`audit.chain.broken` into the trail itself.

Two consequences worth knowing before you enable it:

- **Retention still deletes, and the chain records that it did.** When the sweep
  removes history it records the position and hash it removed up to, so the
  deletion is a signed fact rather than a hole. Deleting rows by hand — `psql`,
  a restore of a partial table, a manual clean-up — is the thing the chain
  reports as broken, because nothing recorded it.
- **Restoring an old backup rewinds the chain.** A dump taken before the last
  entries restores their absence, and the verifier will report the tip as
  missing. Verify after a restore (`make backup-verify` does not cover this:
  run `make verify-audit-chain` on the restored instance) and treat a mismatch as the
  expected outcome of the restore rather than as an incident.

## Optional: requiring a second factor for administrators

MFA is available to every account out of the box, but enrolled is not the same
as required: with the default, a stolen administrator password is still enough
for every admin route. Set this in `.env` to make the second factor a condition
of using an administrator account:

```bash
REQUIRE_MFA_FOR_ADMINS=true
```

What it does and does not do:

- An administrator with no enrolled authenticator is refused **every route except
  the ones that enrol one**, with `403` and `mfa_required` in the detail, and each
  refusal is audited as `auth.mfa.required` (with `reason: require_mfa_for_admins`
  — the marker and the action are shared with the account-level gate, and this is
  what tells a reader which of the two refused).
- **It is asked at sign-in.** The sign-in response reports
  `mfa_required_by_policy`, so the frontend goes straight to the onboarding page
  and asks for the factor there, instead of the operator reaching the dashboard and
  meeting a refusal on the first page that happens to be protected.
- `/auth/mfa/*` stays reachable, so the account can enrol itself.
- An analyst or viewer is unaffected. The gate is about the role that can change
  the platform's configuration, not about the second factor being mandatory for
  everyone.
- **The recovery path is the setting.** There is no self-service reset, by design
  — a self-service reset is a bypass of the second factor — and
  `manage_admin onboarding-off` does not release this requirement, because it is
  not a flag on the account. An administrator who cannot enrol is released by
  setting `REQUIRE_MFA_FOR_ADMINS=false` in `.env` and then recreating the
  containers that read it:

  ```bash
docker compose up -d --force-recreate backend celery-worker celery-beat
  ```

  A *recreate* rather than a `restart`, the same as for every other setting:
  Compose fixes a container's environment when it is created. Separately,
  `python -m scripts.manage_admin mfa-off -e <email>` remains the recovery for a
  *lost device*: it clears the factor, and the account enrols a new one.

The default is `false`: turning it on is a decision, not a side effect of
deploying. An administrator meets it at sign-in, and then everywhere — not on
admin routes only.

## A password an administrator sets is temporary

This is not a setting: it is what the platform does with a credential that one
account chose for another, and it is the first thing an operator meets after an
administrator creates their account.

**A password typed for somebody else would otherwise stay in force forever.**
`manage_admin create`, `manage_admin reset`, creating a user over the API and
resetting a password as an administrator would all leave that password valid
indefinitely. Whoever typed the command would keep a working credential for an
account they do not own — in their shell history, their chat message, the runbook
that quotes the example password.

**So those actions mark the password as temporary**
(`users.must_change_password`), and clearing another account's second factor marks
the factor as owed again (`users.must_enrol_mfa`). Until the account completes the
step, the API answers `403` with `onboarding_required` for every authenticated
route except `/auth/me`, `/auth/password`, `GET /auth/mfa` and — once the password
step is done — the two enrolment endpoints. Sign-in itself keeps working, and the
frontend sends the operator straight to the page that completes the step:

- **Password first, then factor.** The enrolment endpoints re-check the password,
  so a factor cannot be attached while a temporary password is in force. The order
  is enforced by the server, not by the screen.
- **The installation's policy is a third reason to land on this page.** With
  `REQUIRE_MFA_FOR_ADMINS=true` an administrator who has no factor is asked at
  sign-in and reaches nothing else until one is enrolled — the same gate with one
  more reason. See "Optional: requiring a second factor for administrators" above.
- **Changing the password ends the account's other sessions** (refresh families
  revoked with reason `password_change`) and returns a fresh access token, so the
  operator is not signed out by the action that was asked of them.
- **A signed-in session is frozen, not just warned.** An account whose password is
  reset while a tab is open is refused from that moment, because the flags are read
  from the database on every request rather than carried in the token.
- **The one case the page cannot finish by itself:** a session that was already
  open when the password was reset does not know the temporary password. The page
  says so and offers sign-out: sign in again with the temporary value the
  administrator gave you, and the same page completes the change.
- **Audit trail.** The change is audited as `auth.password.changed` (`was_required`
  says whether it was demanded or voluntary, `refresh_families_revoked` how many
  sessions ended), a refused change as `auth.password.change_failed`, and the
  creation/reset/factor-clear events carry `onboarding_required` in their details.
  The routine 403 refusals are structured log events (`credential_onboarding_required`),
  not audit rows: the state they report was audited when it was created.

**Releasing an account that cannot complete the flow** — a temporary password
applied faster than it could be changed, a deployment with no authenticator app
ready yet, an account that has to be used before its owner reaches it:

```bash
docker compose exec backend python -m scripts.manage_admin onboarding-off --email user@example.com
```

`manage_admin list` shows what each account owes before you do that, so the state
is visible without a browser session. Clearing the flags does not weaken anything
by itself — the flags grant no privilege — but it does leave the administrator's
password in force, which is exactly the situation the flags exist to make visible.

**Nothing happens to an account until an administrator acts on it.** Nothing sets
these flags by running the platform; the next administrator action on an account
is what starts the flow for it.

## Rolling back

Rolling back is two moves — the images, then the schema — in that order.

```bash
docker compose down
# set OPENDRP_VERSION back to the previous release in .env
docker compose up -d
docker compose exec backend alembic downgrade <target-revision>
```

Notes:

- The target is the revision the previous release ends at. With a single baseline
  revision there is nothing between `head` and `base` to step back to, so the
  schema route and the data route are the same decision: if you are unsure,
  restore the backup from the first step instead. That is the only path guaranteed
  to reproduce the previous state exactly, including the data written since the
  upgrade.
- A downgrade can be destructive for exactly the same reasons the upgrade was: a
  revision that adds a column usually drops it in `downgrade()`, and the data it
  held goes with it. Check the revision's `downgrade()` before relying on it.
- `0001_initial_schema` is the floor: downgrading below it drops the whole
  schema. From 0.1.0 the supported way back to an earlier release is the backup.
- Never run a matching downgrade while workers are writing. Stop the stack first,
  as above.

## Rotating secrets

A secret that leaked is only a problem for as long as it is still accepted. That
makes rotation an operational capability, not a fire drill, and the platform is
built so that each of these can be done without losing stored data or signing
everyone out.

The sections below are the per-secret procedures, with the verification each one
needs. `python setup.py --force` does the mechanical part of all three at once —
it generates the new values and moves each replaced one into the matching
`*_PREVIOUS_*` list, so nothing they signed or encrypted stops verifying — and it
writes a timestamped backup of the file first. What it cannot do is the part that
depends on the running installation: `rewrap` and `status` after an
`ENCRYPTION_KEY` change, and an `ALTER ROLE` after a `POSTGRES_PASSWORD` change,
because the database volume keeps the password it was initialised with. It says
so when you run it.

### `ENCRYPTION_KEY` — the Fernet key for secrets at rest

It encrypts `system_settings.smtp_password`, `smtp_from_email`,
`alert_recipient_email` and `telegram_bot_token`, every provider key stored on a
source account (`source_accounts.api_key_encrypted`) and the TOTP secret of every
enrolled account (`users.totp_secret`). Two keys can be configured at once:
`ENCRYPTION_KEY` encrypts, and `ENCRYPTION_PREVIOUS_KEYS` (comma-separated) is
used only to decrypt.

**An enrolled authenticator is inside the procedure, not beside it.** A TOTP
secret is encrypted with the same key when the account enrols
(`users.totp_secret`), so `rewrap` re-encrypts it and `status` counts it alongside
the settings columns and the source-account keys. That is what makes the four
steps below sufficient: while a key that wrote a live factor is still listed in
`ENCRYPTION_PREVIOUS_KEYS`, `status` reports that value as readable under a key
other than the first, and the rotation is not finished until it does not. Drop the
key anyway and the factor is unreadable: that account is refused at its
second-factor step with `mfa_secret_undecryptable` in the log, because an
unreadable secret cannot answer "can this account prove possession". The way back
is `python -m scripts.manage_admin mfa-off -e <email>`, after which the account
enrols a new factor under the current key.

```bash
# 1. Generate the new key and the .env lines to paste.
docker compose exec backend python -m scripts.rotate_keys generate

# 2. Put the new key in ENCRYPTION_KEY and the old one in
#    ENCRYPTION_PREVIOUS_KEYS, then recreate the API containers so the new
#    key is loaded (`make restart` is down + up, which recreates them).
make restart

# 3. Re-encrypt what the old key wrote, then check nothing still depends on it.
docker compose exec backend python -m scripts.rotate_keys rewrap
docker compose exec backend python -m scripts.rotate_keys status

# 4. `status` says every value it counts is readable with key [0]: drop
#    ENCRYPTION_PREVIOUS_KEYS, recreate again, done. That count includes the
#    TOTP secret of every enrolled account (see above).
```

Two properties are worth knowing before you start. `rewrap` **aborts** if it
meets a value no configured key can read — it will not skip it, because the next
step deletes a key. And a key listed in `ENCRYPTION_PREVIOUS_KEYS` must still be a
valid Fernet key: a typo is reported rather than worked around.

### `JWT_SECRET_KEY` — the signing secret

Rotating this would normally sign every user out, refresh tokens included — that
is what makes it get deferred. Listing the old secret in
`JWT_PREVIOUS_SECRET_KEYS` keeps verification working against both:

```bash
docker compose exec backend python -m scripts.rotate_keys generate --jwt
# paste both lines, then recreate the API containers so they reload them
make restart
```

Existing sessions keep working. Withdraw the old secret after
`JWT_REFRESH_TOKEN_EXPIRE_DAYS` (3 by default) — removing it from the list is what
invalidates the tokens signed with it, and until then it is still a live
credential, so a rotation triggered by exposure needs it removed sooner at the
cost of those sessions.

### `AUDIT_CHAIN_KEYS` — the key that signs the audit trail

Rotating this one is different from the two above, and the difference is the
point of the chain: an entry can only be verified with the key that signed it,
so the old key has to stay in `AUDIT_CHAIN_PREVIOUS_KEYS` for at least as long as
the history you intend to be able to verify survives retention.

```bash
docker compose exec backend python -m scripts.rotate_keys generate --audit-chain
# put the new key first in AUDIT_CHAIN_KEYS and move the old one to
# AUDIT_CHAIN_PREVIOUS_KEYS, then recreate the writers
make restart
make verify-audit-chain
```

New entries are signed with the first key; the rest only verify. While both are
configured the chain verifies end to end, which is the state you want to check
with the command above *before* deciding to drop the old key — dropping it early
makes every entry it signed unverifiable, which is indistinguishable from
somebody having rewritten them.

The order matters in one more way: this key cannot be recovered. A deployment
that loses it and has no previous key keeps the history but can no longer prove
anything about it, so keep it in whatever secret store holds `POSTGRES_PASSWORD`
rather than only in `.env` on the host.

### Connector credentials and provider API keys

- **Connector tokens** are per connector, stored only as a SHA-256 digest, and
  rotated one at a time: `make connector-token-rotate NAME=phishing-dnstwist` (the
  Makefile writes the new value into the connector's `.env` variable), then
  recreate that connector:
  `docker compose up -d connector-phishing-dnstwist`. No other connector is affected,
  and no core secret is involved.
- **Provider keys** (`SHODAN_API_KEY`, `HIBP_API_KEY`, `DNS_SECURITY_CTLOGS_API_TOKEN`, `DNS_SECURITY_VT_API_KEY`) live either in a connector
  container's environment or on the source account that owns the credential
  (`PUT /api/v1/connectors/accounts/{account_id}/api-key`), where the ciphertext is
  covered by the `rewrap` above. Rotate them at the provider, update whichever of
  the two holds the key, and recreate the affected connector:
  `docker compose up -d connector-phishing-shodan`.

Both cases need a *recreate*, not a restart: Compose fixes a container's
environment when it creates it, so `docker compose restart` keeps the value the
container started with (the same reason the Compose file's own comments give
`up -d` rather than `restart`). For a provider-key change in the tooling
stack, use `docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --force-recreate connector-breaches-hibp connector-phishing-shodan`.

Connector scan jobs use a lease and active heartbeat. Upgrading or restarting a
connector can therefore recover an interrupted job automatically. The job is
retried only up to `CONNECTOR_JOB_MAX_ATTEMPTS`; after that it is marked `error`
so an operator does not get an infinite retry loop.

### PostgreSQL password

`POSTGRES_PASSWORD` in `.env` is only read when the database container is
*created*; changing it alone does nothing on an existing volume. The role's
password has to be changed inside PostgreSQL as well:

```bash
# Substituting these with $VAR only works in bash: cmd.exe and PowerShell pass the
# literal text. Use the POSTGRES_USER and POSTGRES_DB values from .env (both are
# `opendrp` in the template).
docker compose exec postgres psql -U opendrp -d opendrp -c "ALTER ROLE opendrp WITH PASSWORD 'the-new-password'"
# then set POSTGRES_PASSWORD in .env and recreate the API containers
make restart
```

`POSTGRES_PASSWORD` is also not stored encrypted anywhere: it is read from the
environment by every process that connects.

### If a credential was exposed, rotate in this order

1. `JWT_SECRET_KEY` — the exposed value may be a signing secret; sessions are the
   widest blast radius.
2. `ENCRYPTION_KEY` — every stored alert secret, provider key and enrolled
   authenticator secret is readable with it.
3. `AUDIT_CHAIN_KEYS` — an attacker holding it can rewrite history and make it
   verify, which is the one property the trail is supposed to have; rotate it
   before deciding the incident is over.
4. Connector tokens, one at a time.
5. Provider API keys, at the provider.
6. `POSTGRES_PASSWORD`, last: it is the one that requires recreating the
   writers, and doing it last means the value that leaked is already inert.

The GitHub secret-scanning gate (`.github/workflows/ci.yml`, the `secrets` job)
catches a committed credential, but nothing catches a leaked one, which is why
this list exists.

## Two API replicas

The API is stateless: sessions are JWTs, refresh-token families live in
PostgreSQL, and Celery jobs are in Redis, so replicas behind a load balancer
share everything that matters. The upgrade procedure above still applies, with
two additions:

- Migrations are safe to leave to the containers: `scripts/migrate.py` holds a
  database-level advisory lock across `alembic upgrade head`, so the second
  replica waits and then finds nothing to apply. Before that wrapper existed,
  two containers starting together *was* a race — the kind that only appears when
  someone scales the API out, which is why `make verify-replicas` starts two of
  them and checks a session across both.
- Connectors long-poll the core, so a rolling restart briefly returns 503 to a
  connector mid-poll. The SDK treats that as retryable; if yours does not, stop
  the connectors first.

`make verify-replicas` starts exactly this shape (`docker-compose.replicas.yml`)
and proves the properties above rather than assuming them: it signs in against one
replica, presents that access token and refresh cookie to the other, checks that
CSRF is enforced on the replica that never issued the cookie, and confirms both
replicas can read the audit row the login produced — located by the
`X-Request-ID` the client sent. Run it once before you put two replicas behind a
load balancer:

```bash
ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD='...' make verify-replicas
```

The target layers `docker-compose.replicas.yml` on the installation file itself
and leaves the two replicas running so you can look at them; tear them down when
you are done:

```bash
docker compose -f docker-compose.yml -f docker-compose.replicas.yml down
```
