# Backup and restore

OpenDRP holds an asset inventory, findings that took API quota to collect, and
an audit trail that is meant to be trustworthy. None of it is reproducible from
anything else, so a backup is not optional — and a backup that has never been
restored is a belief, not a plan.

## What is backed up

| Artefact | Where it lives | Included |
|---|---|---|
| PostgreSQL (assets, findings, jobs, audit, settings, connectors) | `postgres_data` volume | yes, `pg_dump --format=custom` |
| Generated PDF reports | report store (`reports_store` volume in production, `./reports_store` in development) | yes, `tar.gz` alongside the dump |
| Celery Beat schedule file | report store | via the same archive; harmless to lose, beat recreates it |
| `.env` (secrets) | your host | **no** — deliberately. Back it up out of band: a dump plus an `.env` is a complete copy of the platform's authority, and the two should not travel in the same file |
| Container images | registry | no — rebuild from the version tag |

## Taking a backup

```bash
make backup
```

That runs `scripts/backup.sh` inside a `postgres:17-alpine` container, which is
the point: the `pg_dump` client always matches the server's major version, and
the host needs no PostgreSQL client tools at all. Output lands in `./backups`:

```
backups/opendrp-20260913T041500Z.dump        # the database
backups/reports-20260913T041500Z.tgz         # the report store
backups/latest.dump                          # the newest dump: a hard link where the filesystem allows one, a copy otherwise
```

Every dump is checked with `pg_restore --list` before it is trusted, and the
script keeps the newest `BACKUP_KEEP` (default 14) plus their archives. What it
prunes is exactly what it writes: `opendrp-*.dump` and the `reports-*.tgz` beside
each one. The `pre-restore-*.dump` safety copies a restore writes are not in that
set, so they stay in `./backups` until you delete them — do that once the restore
is settled, rather than letting the directory grow one full copy of the database
per restore.

**A backup follows the file set you address.** The installation mounts a named
volume for the report store; the tooling overlay (`make up-tools`) replaces it
with the `./reports_store` directory in the checkout. The backup service archives
whichever one its own file set mounts, and `make backup` uses the installation file
set — the same one `make up` starts — so the dump and the report archive come from
the stack you are actually running. Taking a backup of the tooling stack without
naming it would produce a correct dump and a faithfully empty archive.

### Running it on a schedule

```bash
# The file set must match the stack that is running; this is the installation's.
docker compose -f docker-compose.yml --profile backup up -d backup
```

The same image loops every `BACKUP_INTERVAL_SEC` (default 86400) instead of
exiting after one pass, and carries a healthcheck that fails when no dump was
written within `BACKUP_MAX_AGE_MIN` (default 1560). A backup container that
quietly stopped running is the classic way a recovery fails, and Docker would
otherwise report it as healthy.

A failed pass in loop mode does not kill the container — the next attempt
matters more than the exit code, and `docker compose logs backup` has the
failure. `make backup` (single pass) does report a status, so it is what CI and
cron should call.

### Getting the dumps off the machine

`./backups` is a host directory precisely so this step is somebody else's
problem, solved with their favourite tool. Two examples:

```bash
# Any S3-compatible object store
rclone copy ./backups remote:opendrp-backups --include '*.dump' --include '*.tgz'

# A second host you already trust
rsync -a --delete ./backups/ backup-host:/srv/opendrp-backups/
```

The dumps are **not encrypted by the platform**. They contain the asset
inventory, findings and the audit trail in the clear — the same content as the
database, minus the disk encryption. Encrypt them at rest yourself
(`gpg --encrypt`, an encrypted bucket, or an encrypted volume) and treat them
with the same care as `.env`.

## Proving a backup restores

```bash
make backup-verify
```

This restores the newest dump into a throwaway database
(`opendrp_restore_check`), checks that the schema, the module registry and the
Alembic revision row all came back, and then drops the scratch database. A dump
that fails this is not a backup, and finding that out now is the entire point.

The report archive beside the dump is proven on the same run: it is listed,
extracted into a scratch directory and a file is read back out of it, because an
archive that cannot be listed or extracted is a store that will not come back. A
dump with no archive beside it restores as a database-only backup and says so;
set `REQUIRE_REPORT_ARCHIVE=1` to make a missing archive a failure, which is what
CI does — a job that quietly stopped capturing the store should not stay green.

It runs in CI against a freshly seeded database and a one-report store on every
push, so both halves of the backup path are exercised continuously rather than
remembered during an incident.

## Restoring over the live database

Restoring is destructive and the script behaves accordingly: it refuses without
explicit confirmation, refuses while another client is connected, and takes a
safety copy of the current database before touching it.

```bash
# 1. Stop every writer.
docker compose -f docker-compose.yml stop backend celery-worker celery-beat connector-phishing-dnstwist connector-phishing-shodan connector-breaches-hibp

# 2. Restore. The script asks for CONFIRM_RESTORE=yes.
CONFIRM_RESTORE=yes make restore FILE=backups/opendrp-20260913T041500Z.dump

# 3. Bring the platform back and check it.
docker compose -f docker-compose.yml up -d
make health
make backup-verify
```

`CONFIRM_RESTORE=yes` is read by the script, which runs inside the container, so
the Makefile passes the value through to it — the confirmation is a deliberate
friction point, not a variable that quietly goes missing.

The database is not the only thing a dump describes: the report store is
restored separately, below, because `scripts/restore.sh` restores the database
and nothing else.

Notes:

* `RESTORE_SKIP_SAFETY_COPY=1` skips the pre-restore dump. Only use it when the
  database is already known to be worthless — the safety copy is what makes
  "wrong dump" recoverable.
* If the restore fails halfway, the database is in a partial state. The message
  the script prints tells you exactly what to do: restore the
  `pre-restore-*.dump` file the same way.
* Redis is **not** restored. It holds the Celery broker queues and the
  short-lived schedule and rate-limit guards, all of which are rebuilt: pending
  jobs, and the schedule occurrences that stop one from being queued twice, are
  rows in PostgreSQL, and work is re-enqueued on the next schedule tick by design.

### Restoring the report archive

`scripts/restore.sh` restores the database and nothing else, so an instance
restored from a dump has report rows whose PDFs are not on disk. The archive is
`reports-<stamp>.tgz` beside the dump, written by the same pass.

The archive holds exactly one top-level entry, `reports/`: it is made with
`tar -C "$(dirname "$REPORTS_DIR")" "$(basename "$REPORTS_DIR")"`, and both
Compose file sets point `REPORTS_DIR` at `/reports` inside the container — the
development overlay changes which host directory is mounted there, not the path.
Extracting it into the store's *parent* therefore leaves the PDFs one directory
away from where the platform looks for them, so extract its contents into the
store itself:

```bash
# Development stack: the store is ./reports_store in the checkout.
tar -xzf backups/reports-20260913T041500Z.tgz -C ./reports_store --strip-components=1
```

On an installation the store is the `reports_store` named volume, whose full name
carries the Compose project prefix (`docker volume ls` shows it). The `backup`
service mounts it read-only on purpose — a backup can never modify the store it
archives — so use a throwaway container that mounts it read-write:

```bash
docker run --rm -v opendrp_reports_store:/store -v "$PWD/backups:/backups:ro" alpine:3 sh -c 'tar -xzf /backups/reports-20260913T041500Z.tgz -C /store --strip-components=1'
```

Either way, check afterwards that a report downloads. A restore that stops at the
database leaves the inventory and the UI consistent and only the downloads
missing, which reads like a permissions problem rather than an unfinished
restore.

## Recovery objectives

| | Target | Why |
|---|---|---|
| RPO | your `BACKUP_INTERVAL_SEC`, default 24 h | backups are periodic, not continuous. Change the interval if that is too much to lose |
| RTO | minutes for a small installation | restoring is a `pg_restore` plus a stack restart, and the verify target keeps it that way |

Log the real numbers from your own drill in this table rather than inheriting
someone else's estimate.

## Quarterly drill

Do this on a calendar, not when you need it. The run takes about ten minutes.

1. `make backup` on the production host.
2. Copy `latest.dump` and the `reports-<stamp>.tgz` that goes with it to a
   machine that is *not* the production host.
3. There, start a throwaway stack with an empty database:
   `docker compose -f docker-compose.yml up -d postgres` and nothing else.
4. `CONFIRM_RESTORE=yes make restore FILE=<the copied dump>` — against the
   throwaway stack — then extract the report archive into the report store, or
   step 5 cannot download a PDF (`tar -xzf backups/reports-<stamp>.tgz -C
   ./reports_store --strip-components=1` on a development stack, whose store is
   `./reports_store`; the archive's one top-level entry is `reports/`, so
   `--strip-components=1` is what puts the files where the platform looks).
5. `docker compose up -d`, sign in, and check three things by hand: the asset
   count on the dashboard, the newest audit rows, and that a generated report
   downloads.
6. Confirm that the offsite copy is actually offsite — open the object store and
   look, rather than trusting the job's exit code.
7. Record the wall-clock time it took and put that number in the table above.

If step 5 fails, the drill has done its job: a backup that does not restore is a
discovery worth making quarterly rather than during an outage.
