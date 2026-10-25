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
"what am I running". The connector images are built and tagged from that same
release, and each connector registers that version as its `api_version`, so a
connector's row in **Settings → Connectors** names the release it came from.
`scripts/check_version_consistency.py` fails the build when that value,
`backend/pyproject.toml`, the newest `CHANGELOG.md` entry, the connector SDK
(its `__version__`, the `SDK_VERSION` it registers with, and
`connectors/base/pyproject.toml`) or `frontend/package.json` disagree, and the
release workflow refuses to publish a tag that does not match the code, so a tag
cannot name a version the images do not report.

The connector protocol revision is a different number: `protocol_version` is an
integer describing the shape of the connector protocol and is deliberately not
compared with the release.

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
one: 0.2.2 declares its version, and the images a `pull` would fetch for it come
from the release run on tag `v0.2.2`, so `make up` is what builds and starts the
stack here.

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

Three more indexes belong to the same class, added for the candidate list's
substring search (AST-47): the list asks `ILIKE '%term%'` of `phishing_domain`,
`matched_asset` and `ip_address`, and a btree cannot answer a leading wildcard,
so every search read the whole table. They use the `pg_trgm` extension the
baseline installs, and follow the same rule — plain `CREATE INDEX`, run after the
upgrade, in the maintenance window:

```bash
docker compose exec postgres psql -U opendrp -d opendrp -c "CREATE INDEX IF NOT EXISTS ix_drp_phishing_domains_phishing_domain_trgm ON drp_phishing_domains USING gin (phishing_domain gin_trgm_ops)"
docker compose exec postgres psql -U opendrp -d opendrp -c "CREATE INDEX IF NOT EXISTS ix_drp_phishing_domains_matched_asset_trgm ON drp_phishing_domains USING gin (matched_asset gin_trgm_ops)"
docker compose exec postgres psql -U opendrp -d opendrp -c "CREATE INDEX IF NOT EXISTS ix_drp_phishing_domains_ip_address_trgm ON drp_phishing_domains USING gin (ip_address gin_trgm_ops)"
```

On an installation with many candidates these are the longest part of that
window, and `\di ix_drp_phishing_domains_phishing_domain_trgm` tells whether they
are already there.

### A column default the baseline gained after your build was created

Adoption records a revision and creates nothing, so a default the baseline has
gained *since* the build that created your database is not there either.
`jobs.created_at` and `jobs.updated_at` are that case: every other table in the
baseline is created with `DEFAULT now()` through `TimestampMixin`, and `jobs` was
the one that was not. The platform's own writers are ORM statements that supply
both values, so nothing fails on the older database — but a hand-written `INSERT`
that omits them is refused `NOT NULL` there and accepted on a database this release
created, which is the kind of difference that only shows up in a maintenance
window. Two statements close it:

```bash
docker compose exec postgres psql -U opendrp -d opendrp -c "ALTER TABLE jobs ALTER COLUMN created_at SET DEFAULT now()"
docker compose exec postgres psql -U opendrp -d opendrp -c "ALTER TABLE jobs ALTER COLUMN updated_at SET DEFAULT now()"
```

`make check-backend-migrations` compares the models against the schema the
revision builds, and its output names this default when a checkout expects it; a
database this release created has it already, and `\d jobs` is what tells the two
cases apart.

### A table the baseline gained after your build was created

Adoption creates nothing, so the same applies to a whole table: a database created
by a build that predates the certificate review workflow has no
`tls_certificate_identities`, `tls_certificate_sightings` or
`certificate_scope_exceptions`, and the DNS Security page's certificate list stays
empty rather than reporting a schema error. `make check-backend-migrations` is what
tells the two cases apart inside a running installation — it compares the ORM
models against the schema the revision builds *and* reflects the live database —
and a database this release created has them already.

The three tables are new in this release and nothing else references them, so they
can be created in a running installation after the upgrade:

```sql
CREATE TABLE IF NOT EXISTS tls_certificate_identities (
  id uuid NOT NULL,
  fingerprint_sha256 varchar(64) NOT NULL,
  fingerprint_sha1 varchar(40),
  spki_sha256 varchar(64),
  serial_hex varchar(128),
  subject_dn varchar(1000),
  issuer_dn varchar(1000),
  not_before timestamptz,
  not_after timestamptz,
  san_dns json NOT NULL DEFAULT '[]'::json,
  key_algo varchar(64),
  origin varchar(32) NOT NULL,
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT tls_certificate_identities_pkey PRIMARY KEY (id),
  CONSTRAINT uq_tls_identity_fingerprint_sha256 UNIQUE (fingerprint_sha256)
);
CREATE INDEX IF NOT EXISTS ix_tls_identity_spki ON tls_certificate_identities (spki_sha256);
CREATE INDEX IF NOT EXISTS ix_tls_identity_serial ON tls_certificate_identities (serial_hex);

CREATE TABLE IF NOT EXISTS tls_certificate_sightings (
  id uuid NOT NULL,
  identity_id uuid NOT NULL,
  subject varchar(253),
  ip varchar(64),
  port integer,
  source varchar(32) NOT NULL,
  observed_at timestamptz NOT NULL,
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  is_ours boolean NOT NULL DEFAULT false,
  confidence smallint NOT NULL DEFAULT 0,
  signals json NOT NULL DEFAULT '{}'::json,
  verdict varchar(32) NOT NULL DEFAULT 'candidate',
  reviewed_by uuid,
  reviewed_at timestamptz,
  review_note varchar(2000),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT tls_certificate_sightings_pkey PRIMARY KEY (id),
  CONSTRAINT uq_tls_sighting_identity_endpoint_source UNIQUE (identity_id, ip, port, source),
  CONSTRAINT tls_certificate_sightings_identity_id_fkey FOREIGN KEY (identity_id)
    REFERENCES tls_certificate_identities (id) ON DELETE CASCADE,
  CONSTRAINT tls_certificate_sightings_reviewed_by_fkey FOREIGN KEY (reviewed_by)
    REFERENCES users (id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS ix_tls_sighting_identity ON tls_certificate_sightings (identity_id);
CREATE INDEX IF NOT EXISTS ix_tls_sighting_verdict ON tls_certificate_sightings (verdict);
CREATE INDEX IF NOT EXISTS ix_tls_sighting_ip ON tls_certificate_sightings (ip);

CREATE TABLE IF NOT EXISTS certificate_scope_exceptions (
  id uuid NOT NULL,
  match_kind varchar(16) NOT NULL,
  match_value varchar(255) NOT NULL,
  reason varchar(1000),
  created_by uuid,
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT certificate_scope_exceptions_pkey PRIMARY KEY (id),
  CONSTRAINT uq_certificate_scope_exception UNIQUE (match_kind, match_value),
  CONSTRAINT certificate_scope_exceptions_created_by_fkey FOREIGN KEY (created_by)
    REFERENCES users (id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS ix_tls_exception_kind_value ON certificate_scope_exceptions (match_kind, match_value);
```

The statements are the ones the revision runs, with `IF NOT EXISTS` added so a
database that already has them is left alone. They are plain DDL — a new table and
its indexes — so they belong in the same maintenance window as the upgrade, and the
matching `DROP TABLE` statements are in the revision's `downgrade()`. Nothing
reads these tables until the daily certificate sweep has run once, so an installation
that adopts them mid-week reports nothing foreign until the next 05:30 UTC pass,
which is the honest answer rather than an all-clear.

### The refresh-family foreign key

`drp_refresh_families.user_id` was an unconstrained `uuid`, so a family could
outlive its account. That is not untidy, it is a session nobody can revoke: the
refresh path resolves the account before it looks at the family, so the row can
never be presented again — and the retention sweep deletes by `revoked_at`, which
an orphan never has, so no sweep ever selected it either. The baseline now declares
`fk_drp_refresh_families_user_id_users … ON DELETE CASCADE`, which makes "the
account is gone" and "its sessions are gone" one fact at the schema level rather
than a hand-written `DELETE` in the user router.

A database this release created has the constraint. An adopted one does not —
adoption creates nothing — so add it in this order, in a maintenance window:

```sql
-- 1. What the constraint would refuse: families whose account is gone.
SELECT count(*) FROM drp_refresh_families f
LEFT JOIN users u ON u.id = f.user_id
WHERE u.id IS NULL;

-- 2. Remove those rows. `users.id` is the primary key, so NOT IN has no NULL
--    to swallow the answer.
DELETE FROM drp_refresh_families
WHERE user_id NOT IN (SELECT id FROM users);

-- 3. Add the rule without holding every writer behind a full check, then
--    validate the history once. `NOT VALID` checks new writes immediately.
ALTER TABLE drp_refresh_families
  ADD CONSTRAINT fk_drp_refresh_families_user_id_users
  FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE NOT VALID;
ALTER TABLE drp_refresh_families
  VALIDATE CONSTRAINT fk_drp_refresh_families_user_id_users;
```

Re-running step 1 after the validation answers `0`; that is also what
`tests/test_users_rbac_postgres.py` asserts on a migrated database, together with
the cascade itself (a raw `DELETE FROM users` leaves no family behind) and the
delete rule the constraint carries.

### The connector this release binds to a source account

`breaches-hibp` is provider-backed in this release: the baseline seeds it with
`provider: hibp`, a `quota_group` and a `source_account_id`. That is what makes a
scan wait for a readiness row and an approved budget instead of returning a short
list that reads like "no breaches". Adoption creates nothing, so a database an
earlier build created keeps the row it was seeded with — a connector with no
provider, gated on nothing and spending requests no account records.

`backend/scripts/seed_defaults.py` runs on every backend start and closes exactly
that gap: it creates the `hibp/default` account (unapproved, like every other
seeded account) and binds `breaches-hibp` to it while the row is still unbound, so
an operator's reassignment is never overwritten. There is no manual step to add
the binding; the scan stays refused until a person approves the account:

1. **Settings → Sources** — confirm the `hibp` account named `default` exists.
2. Approve its policy and set at least `requests_per_minute` and `daily_budget`.
   Without an account the refusal is reported as `provider_account_missing`;
   with an unapproved one as `account_policy_unapproved`. Both are named in the
   source list and on a job that was queued before the row disappeared, so an
   operator never has to read an empty scan as "nothing found".
3. Keep the worker's `CONNECTOR_TOKEN_HIBP` as it is — the connector credential
   is unchanged. The provider key may live in the account (rotatable without a
   container restart) or stay in `HIBP_API_KEY` for an installation that has not
   adopted accounts yet; an account key takes precedence.

A scan requested before the account exists is refused, not queued: the response
names `provider_account_missing` and the job history stays empty rather than
recording work that could never spend.

### The phishing candidates this release starts scoring

Candidate scoring adds three columns to `drp_phishing_domains` and one child table, and
the manual verdict (WI-12) adds four more: `verdict`, `verdict_reason`, `verdict_by`
and `verdict_at`.
Adoption creates nothing, so a database created by a build that predates scoring has
no `confidence`, no `signals`, no `digest_queued_at` and no
`phishing_candidate_signals`: the phishing list then shows every candidate with a
confidence of `0` and no signals, which is not an error but is not the scored view
this release describes either. `make check-backend-migrations` tells the two cases
apart inside a running installation — it compares the ORM models against the schema
the revision builds *and* reflects the live database — and a database this release
created has them already.

The columns carry defaults and the table is new and referenced by nothing else, so
both can be added to a running installation after the upgrade:

```sql
ALTER TABLE drp_phishing_domains ADD COLUMN IF NOT EXISTS confidence smallint NOT NULL DEFAULT 0;
ALTER TABLE drp_phishing_domains ADD COLUMN IF NOT EXISTS signals json NOT NULL DEFAULT '{}'::json;
ALTER TABLE drp_phishing_domains ADD COLUMN IF NOT EXISTS digest_queued_at timestamptz;
ALTER TABLE drp_phishing_domains ADD COLUMN IF NOT EXISTS verdict varchar(32);
ALTER TABLE drp_phishing_domains ADD COLUMN IF NOT EXISTS verdict_reason varchar(2000);
ALTER TABLE drp_phishing_domains ADD COLUMN IF NOT EXISTS verdict_by uuid;
ALTER TABLE drp_phishing_domains ADD COLUMN IF NOT EXISTS verdict_at timestamptz;
ALTER TABLE drp_phishing_domains
  ADD CONSTRAINT drp_phishing_domains_verdict_by_fkey FOREIGN KEY (verdict_by)
  REFERENCES users (id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS ix_phishing_confidence ON drp_phishing_domains (confidence);
CREATE INDEX IF NOT EXISTS ix_phishing_domains_confidence_status ON drp_phishing_domains (confidence, status);

CREATE TABLE IF NOT EXISTS phishing_candidate_signals (
  id uuid NOT NULL,
  candidate_id uuid NOT NULL,
  name varchar(64) NOT NULL,
  value json NOT NULL,
  confidence smallint NOT NULL DEFAULT 0,
  observed_at timestamptz,
  source varchar(100),
  CONSTRAINT phishing_candidate_signals_pkey PRIMARY KEY (id),
  CONSTRAINT phishing_candidate_signals_candidate_id_fkey FOREIGN KEY (candidate_id)
    REFERENCES drp_phishing_domains (id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_phishing_candidate_signals_candidate ON phishing_candidate_signals (candidate_id);
```

Each statement is the one the revision runs, with `IF NOT EXISTS` added so a
database that already has it is left alone. `ADD COLUMN` with a constant default is
metadata-only on PostgreSQL 11 and later, so the three scoring columns do not rewrite
the table; the four verdict columns are nullable with no default, which is the same
kind of change. `ADD CONSTRAINT` in the block above is *not* idle on a second run —
unlike the columns it has no `IF NOT EXISTS` spelling, so a database that already has
the verdict columns and their constraint should run only the statements it is missing,
or accept the error for that one line. The two indexes and the new table do hold a
write lock while they build, which is why they belong in the same maintenance window
as the upgrade. The matching `DROP TABLE` is in the revision's `downgrade()`.

Until the columns exist, nothing routes on a verdict (`verdict` reads as `NULL`, which
is the untouched state) and the phishing list shows no decision — the score alone
decides, exactly as before the upgrade.

The one thing adoption does not do is score what is already there. The columns
arrive with `0` and `{}`, and `0` is a real score — nothing fired — rather than a
marker for "unknown", so a candidate only carries a confidence once a scan has run
over it. An installation that wants its current inventory scored should run a scan
from the module page rather than assume the empty column means the candidate was
weighed and dismissed.

### The alert budget's operator values

Six columns on `system_settings` are this release's second half of the alert budget:
`alert_confidence_direct`, `alert_confidence_digest`,
`alert_phishing_digest_enabled`, `alert_phishing_digest_hour_utc`,
`alert_no_channel_retry_hours` and `alert_candidate_change_notifications`. They are all
nullable and all default to `NULL`, which is what makes the migration safe on a live
installation: `NULL` means *this one has not been decided here*, and the deployment's
own `ALERT_*` environment values answer it — the behaviour an installation had before
the upgrade, byte for byte. Nothing routes differently until somebody saves the
Settings page.

Adoption creates nothing, so a database created by a build that predates these columns
has no place to store an operator's choice, and the Settings page's alert budget form
would fail on save against it. `make check-backend-migrations` tells the two cases
apart. Adding the six columns to a running installation after the upgrade is
metadata-only — each is nullable with no default, so no table rewrite:

```sql
ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS alert_confidence_direct smallint;
ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS alert_confidence_digest smallint;
ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS alert_phishing_digest_enabled boolean;
ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS alert_phishing_digest_hour_utc smallint;
ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS alert_no_channel_retry_hours smallint;
ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS alert_candidate_change_notifications boolean;
```

A row can also state a threshold pair that does not hold together when the two are
written a field at a time (the digest threshold must stay below the direct one).
Nothing breaks if it happens: the row is refused *as a whole* and the environment
answers instead, which is why `invalid` is reported on the resolved policy rather than
guessed at from the database. A save that would leave the row in that state is refused
before it is stored: the API evaluates the pair as the row will hold it after the
update, so stating one of the two against a stored other is caught, and the operator is
told which fields they are.

### The credential-breach columns

The breach wave adds four columns, all nullable and all safe on a live installation for
the same reason as the budget's own: they are either an operator's unanswered question or
a fact the platform has simply not recorded yet.

`drp_breaches.last_seen_at` is when the source last reported the incident, and
`drp_breaches.verified_at` is when it first confirmed it. Both are distinct from
`updated_at`, which moves whenever a scan rewrites anything on the row — including a scan
that found exactly the same facts again — so "is this incident still arriving?" and "did
it change?" were the same question before these columns existed. `last_seen_at` is filled
by the next scan of an existing row; a row adopted from an older build keeps `NULL` until
one arrives, which reads as "not seen since the upgrade" rather than as a date the
platform made up.

`system_settings.alert_breach_noise_policy` and
`system_settings.alert_breach_digest_threshold` are the breach module's half of the alert
budget, editable in Settings → Alert budget under the same rule as the rest: `NULL` is
"not decided here" and `ALERT_BREACH_NOISE_POLICY` /
`ALERT_BREACH_DIGEST_THRESHOLD` answer it. `ALERT_BREACH_GROWTH_FLOOR` stays an
environment value and needs no column.

Adding them to a running installation after the upgrade is metadata-only — each is
nullable with no default, so no table rewrite:

```sql
ALTER TABLE drp_breaches ADD COLUMN IF NOT EXISTS last_seen_at timestamptz;
ALTER TABLE drp_breaches ADD COLUMN IF NOT EXISTS verified_at timestamptz;
ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS alert_breach_noise_policy varchar(32);
ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS alert_breach_digest_threshold smallint;
```

One behaviour change is *not* additive and is worth reading before upgrading: a breach
finding with no usable `breach_date` is now **refused** instead of being stored with
`1970-01-01`. That date was the platform's own invention — it appeared on the page, in
reports and in alerts as though it were the day of the incident — and a row that already
carries it is left alone by the upgrade but is not reproduced by any new scan. A
reporter whose data genuinely has no date states `attributes.metadata_incomplete`, which
is the only path that stores a row without one; the API and the page then say the
metadata is incomplete rather than showing that day as a fact.

### The classes of exposure

The module stores one kind of exposure per row — an account compromised, a name that
appeared in a paste, or a site found in a stealer log — in `drp_breaches.exposure_kind`
(default `breach`, which is what every row the platform already holds means). The column
is *not* part of any unique key: a paste or a stealer log carries its own identifier
inside `breach_name` (`paste:<id>`, `stealerlog:<site>`), so the module's existing unique
pairs and indexes keep working and no row is rebuilt or re-identified by the upgrade. A
row stored before the column existed is a breach of an account because that is all the
module could represent then.

It is metadata-only and safe to apply more than once:

```sql
ALTER TABLE drp_breaches ADD COLUMN IF NOT EXISTS exposure_kind varchar(32) DEFAULT 'breach' NOT NULL;
CREATE INDEX IF NOT EXISTS ix_drp_breaches_exposure_kind ON drp_breaches (exposure_kind);
```

Until a worker that declares the class is deployed, every new finding is stored as
`breach`, and `GET /api/v1/breaches?exposure_kind=paste` answers with an empty list rather
than an error — an installation with only breach sources has nothing of the other kinds to
show, and the page says so rather than hiding the filter.

### The severity of a finding

The triage wave adds one column, `drp_breaches.severity` (default `unknown`), which holds
how loud a finding is as derived from the classes of data it exposed — plaintext
credentials, security questions and payment data are `critical`, hashed credentials
`high`, addresses and phone numbers `medium`, an address list `low`. It is written by the
core when the row is written, from one rule (`app/services/breach_severity.py`), because
the list's badge, its `?severity=` filter and its `?sort=severity` ordering have to read
the same value; a value computed per query would be a second rule beside the one the PDF
uses.

It is metadata-only and safe to apply more than once:

```sql
ALTER TABLE drp_breaches ADD COLUMN IF NOT EXISTS severity varchar(16) DEFAULT 'unknown' NOT NULL;
CREATE INDEX IF NOT EXISTS ix_drp_breaches_severity ON drp_breaches (severity);
```

Rows an installation already holds keep `unknown` — shown as *Unclassified* and sorted
below `low` — until a scan re-reports them and the core writes the derived value. That is
deliberate: the alternative is a second implementation of the rule in adoption SQL, and
the two would eventually disagree about the same row. `unknown` is a statement that this
build has not classified the row, not a statement that the row is harmless.

### The incident catalogue

The breach wave adds one table and one index, and no existing row moves. `breach_catalogue`
holds what a source knows about incidents at large — one row per `(source, breach_name)`,
with the source's own `added_date`/`modified_date` beside the platform's own
`created_at`/`last_synced_at` — so a breach of a domain being monitored is visible before
anybody has added an address of that domain to the inventory (F-09, WI-13).

A new installation gets it from the baseline revision. A running installation adopts it
with the DDL below, which is the table the revision creates and is safe to apply more
than once (the table and the index are the only objects, and neither carries data):

```sql
CREATE TABLE IF NOT EXISTS breach_catalogue (
    id uuid DEFAULT uuid_generate_v4() NOT NULL,
    source character varying(100) NOT NULL,
    breach_name character varying(255) NOT NULL,
    title character varying(255) DEFAULT ''::character varying NOT NULL,
    domain character varying(255) DEFAULT ''::character varying NOT NULL,
    breach_date date,
    added_date timestamp with time zone,
    modified_date timestamp with time zone,
    pwn_count integer DEFAULT 0 NOT NULL,
    data_classes json DEFAULT '[]'::json NOT NULL,
    attributes json DEFAULT '{}'::json NOT NULL,
    last_synced_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT pk_breach_catalogue PRIMARY KEY (id),
    CONSTRAINT uq_breach_catalogue_incident UNIQUE (source, breach_name)
);
CREATE INDEX IF NOT EXISTS ix_breach_catalogue_source_domain
    ON breach_catalogue (source, domain);
```

Then verify the schema matches the release before deploying it, which is the same check
every other upgrade runs:

```bash
python -m scripts.check_schema_drift
```

Two things change for a connector, both additive. The protocol gains
`POST /api/v1/connectors/me/catalogue/{job_id}`, and a breach scan's job params carry the
checkpoint to sweep against under `params.catalogue` (`{"source": …, "incidents": 0,
"last_synced_at": null, "stale": false}`) — `last_synced_at: null` is a source this
installation has never synced, so the first scan of it reads the whole catalogue. A
worker built before this release ignores both, which is why the table starts empty and
stays empty until a worker that knows the route is deployed: nothing announces an
incident on the strength of a catalogue nobody read.

### The phishing worker's breadth questions

The brand wave adopts nothing: no column, no index, no registry row. Four things change
for an installation that runs a Netlas worker, and three of them are additive.

The seeded `phishing-netlas` service now declares `keyword_domain` in
`CONNECTOR_ASSET_TYPES` (it was `domain,keyword_title`), because a brand asset is what
the certificate and page-text questions are asked *from*. `docker compose up -d`
recreates that container from the updated file. A worker started from a copy of the old
environment keeps scanning exactly as it did before, with the domain and title questions
only — which is also why this is not a failure mode: the connector advertises what it can
ask, and the scan summary names the questions it did not ask.

A queued phishing job now carries `candidates`: the candidates an analyst **confirmed**,
each with the asset it was matched to, bounded to twenty. The worker asks the provider
what those names serve, when they were registered and whether they receive mail — facts
about a name the platform already found, stored as evidence against it, never as new
candidates. A connector that ignores the key is unaffected.

Job summaries gain `skipped`, `spent`, `budget_left`, `daily_budget`,
`daily_budget_left` and `retry_after_seconds`. `skipped` is the one worth reading: it
counts the reasons a scan did not ask (`expression_too_broad`, `favicon_hash_unavailable`,
`whois_unavailable`, `provider_quota_exhausted`, `source_disabled`,
`provider_access_denied`), so a scan that found nothing can be told apart from one that
was not allowed to look. A budget or kill-switch refusal now ends a scan with that name
instead of failing the job as a provider error.

The provider quota response gains `remaining_today`, the account's remaining requests for
the day. A connector built against the older response ignores it, and the core reports
`null` rather than a number when the quota backend does not answer with one, so an
upgraded core with an un-upgraded worker (or the reverse) is not a failure either way.

Two policy keys bound what the breadth questions cost, both editable per connector in
Settings: `max_broad_results` (default 1000 — a brand or page-text expression with a
larger result set is counted and then skipped, not paged) and the existing
`max_reverse_lookups`. Certificate queries, the brand one included, are reserved from the
certificate bucket that the provider's three-per-minute limit applies to, so an
installation with a tight certificate budget sees the brand questions throttled before
anything else.

### The Shodan worker spends by policy, the DNSTwist worker scans by class

Still nothing to adopt: no column, no index, no registry row. What changes is what two
connectors ask for, and three of those changes are visible to an operator who reads a job
summary.

The Shodan worker's five new questions (`scan_http_body`, `scan_cert_subject`,
`scan_html_hash`, `scan_pivots`, `scan_host_lookup`) all default to **off**, so an
upgraded installation keeps asking exactly the questions it asked before until somebody
turns one on in the connector's configuration. Its page ceiling, once the hardcoded
constant `3`, is now the connector's own `max_pages` registry setting; an installation
that never opens the form gets the same three pages as before. Its readiness row
declares one more capability (`body`), which is what the core now accepts as a scan
reason beside `certificate`, `title` and `favicon`.

Job summaries from a provider worker gain `pages`, `billed_pages` (pages past the first,
the unit Shodan's credit guide bills) and `free_lookups`, and their `skipped` field
changes shape: it is now a mapping of reason to count (`{"expression_too_broad": 1}`)
instead of a bare string. That is the shape the Netlas worker has reported since the
previous wave, and anything that reads a summary should expect the mapping.

On the DNSTwist side, `DNSTWIST_FUZZERS` is **replaced** by
`DNSTWIST_FUZZER_CLASSES`. An installation whose `.env` still sets the old name gets the
default class (`typo`); for the set this project shipped as its default the two are the
equivalent, since `typo` is exactly those eight fuzzers. The classes also fix an
invocation the old knob could build and the CLI would refuse: `--tld` and
`--dictionary` are only accepted beside their own fuzzer, which the class carries.
`DNSTWIST_DICTIONARY`, `DNSTWIST_MAX_CANDIDATES`, `DNSTWIST_MX_CHECK` and
`DNSTWIST_CONTENT_INSPECTION` are new and default to the previous behaviour (packaged
files, 250 candidates, no mail check, no page similarity). The connector now refuses to
start on a class name it does not know, rather than scanning with fewer techniques than
the operator asked for, and a domain with no permutations no longer needs a DNS client
at all — which is what made a Windows host fail a scan whose look-alikes were simply not
registered.

One consequence is worth stating plainly: the facts a provider or the CLI already
reported now **score**. A candidate found by a title search, a page-body search or an
icon match carries `title_match` (20), `brand_in_body` (15) or
`favicon_perceptual_match` (20), and a candidate that accepts mail without publishing an
SPF policy carries `mx_without_spf` (15). Those signals are derived from the evidence at
ingestion, so an existing candidate picks them up the next time a scan observes it; the
weights themselves are unchanged, and nothing rescored history in this release.

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
`dns-tlsprobe`, `dns-virustotal`, `dns-shodan`, `dns-netlas` — with a `-<task>` suffix where one provider serves
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

The breach worker is one of them. `breaches-hibp` used to sit outside this
mechanism: its row declared no provider, so a revoked key produced a short list
that read like "no breaches" and its requests were not drawn from any account.
On the first start after the upgrade the startup seeder creates the `hibp`
account with `approved: false` and binds the connector to it, for an adopted
database as well as a fresh one. Until you open Settings → Connectors → Provider
accounts and approve that policy, a breach scan is refused as
`account_policy_unapproved` — a named reason in the Jobs page rather than an
empty result. Approve it with a requests/minute you are willing to spend (10 is
the worker's own default and matches the conservative reading of the lowest paid
HIBP tier); `HIBP_API_KEY` in the worker's environment remains the credential,
and a key stored on the account takes precedence over it.

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

## Optional: requiring a second factor by role

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
  refusal is audited as `auth.mfa.required` (with `reason: require_mfa` — the
  marker and the action are shared with the account-level gate, and this is what
  tells a reader which of the two refused).
- **It is asked at sign-in.** The sign-in response reports
  `mfa_required_by_policy`, so the frontend goes straight to the onboarding page
  and asks for the factor there, instead of the operator reaching the dashboard and
  meeting a refusal on the first page that happens to be protected.
- `/auth/mfa/*` stays reachable, so the account can enrol itself.
- **Analysts can be covered too, with `REQUIRE_MFA_ROLES=admin,analyst`.** The
  flag above adds `admin` to whatever that list names, so the two are read
  together rather than one replacing the other. An installation that wants the
  factor from everyone names all three roles; a viewer without a factor would then
  be held at the onboarding step, which is a deliberate choice rather than a
  side effect.
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
  more reason. See "Optional: requiring a second factor by role" above.
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

## A recovery no longer grants administration

`manage_admin reset` used to end with two side effects nobody asked for: the
account became an `admin`, and it became active. A support reset on a viewer was
therefore a grant of administration over users, audit and settings, and a
`reset` or `unlock` switched a deliberately deactivated account back on. Neither
happens now. Roles and activity change only when a flag asks for it, and the
command prints every field it changed:

```bash
# change the password only — role and active flag are left as they are
docker compose exec backend python -m scripts.manage_admin reset --email user@example.com --password "NewStrongPass456!"

# say so when the change is wanted
docker compose exec backend python -m scripts.manage_admin reset --email user@example.com --password "NewStrongPass456!" --role analyst
docker compose exec backend python -m scripts.manage_admin reset --email user@example.com --password "NewStrongPass456!" --ensure-admin
docker compose exec backend python -m scripts.manage_admin reset --email user@example.com --password "NewStrongPass456!" --activate
docker compose exec backend python -m scripts.manage_admin unlock --email user@example.com --activate
```

If a runbook step relied on `reset` or `unlock` reactivating an account, add
`--activate` to it: the command now reports the account as still deactivated
rather than quietly fixing it. `create --force` overwrites the password and
likewise leaves the account's activity alone.

Two more differences worth knowing before the first upgrade:

- **The CLI uses the API's password policy.** It accepted 8 characters while the
  API required 12, so an installation could be bootstrapped with a password its
  own API would have refused. `create` and `reset` now validate with the same
  `validate_password_strength`, which means a short password in an old runbook is
  refused instead of accepted.
- **Every command writes an audit row.** `create`, `reset`, `unlock`, `mfa-off`
  and `onboarding-off` write `user.created`, `user.password_reset`,
  `user.unlocked`, `user.mfa.reset` and `user.onboarding.cleared`; `list` writes
  the same `users.list` read event the API writes. The row carries
  `details.source = "cli"`, `details.actor` naming the operating-system user, the
  target account in `details.target_user_id`/`details.target_email`, and
  `user_id = null` — a host operator is not a platform account, so a SIEM rule
  that selects on `user_id` will not see these rows. A mutating command whose row
  cannot be written fails rather than applying without a trail, which is why the
  backend container needs the same database access it already has.

The user API changed with it: the `toggle-active` operation on a user
(`PATCH …/users/{user_id}/toggle-active`) is gone. Activation is changed through
`PUT /api/v1/users/{user_id}` with
`{"is_active": false}`, the one operation that already audits the change as
`user.updated` — a script still calling the old route gets a `404`.

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

**A second-factor recovery code is derived from this key too.** Since the
user/RBAC round the digests in `users.mfa_recovery_codes` are HMAC-SHA256 keyed
from `ENCRYPTION_KEY` under a label of its own, so they are *not* re-encrypted by
`rewrap` (there is nothing to rewrap: the stored value is already a digest) and
they are **not** counted by `status`. What keeps a printed list working during a
rotation is `ENCRYPTION_PREVIOUS_KEYS`: every configured key verifies, the first
one signs. Dropping the previous key therefore retires the codes that were issued
under it — the account still signs in with its password and a live TOTP code, and
`POST /api/v1/auth/mfa/recovery-codes/rotate` issues a fresh list under the
current key. An installation that drops a previous key without rotating the codes
leaves those accounts without a recovery path until they do, which is the same
class of exposure as dropping a key a TOTP secret was written with, only with a
working way back.

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

### Confirming a provider plan before a capability spends

Two workers now treat the plan entitlement as an operator statement rather than as
something implied by a switch. This is a behaviour change on upgrade, and it is
deliberate: a capability that is on but not permitted would spend an account's credits
and break the vendor's terms at the same time.

* **Shodan.** The five capabilities added with the budget wave — page body, certificate
  subject, HTML hash, organisation/network pivots and the free host lookup — no longer
  run on their toggle alone. Set `provider_terms_acknowledged: true` in the connector's
  configuration form, or `SHODAN_TERMS_ACKNOWLEDGED=true` in the service environment.
  The three historical questions (`ssl`, page title, favicon) keep running unchanged:
  they were already being asked when this gate arrived.
* **Netlas.** An `http.body` search runs only when `http_body_acknowledged: true`
  (registry config) or `INTELLIGENCE_HTTP_BODY_ACKNOWLEDGED=true` (environment). On an
  installation that relied on the previous default, the body question stops until the
  statement is made; certificate, title, favicon, WHOIS and MX questions are unaffected,
  and a scan with a brand but no acknowledgement reports
  `licence_acknowledgement_required` in its summary (`partial` when the other questions
  still produced findings, `skipped` when they produced none).

Both refusals send nothing to the provider, so an upgrade cannot spend a credit before
the operator has confirmed the plan. Nothing in the database changes and no SQL is
needed.
