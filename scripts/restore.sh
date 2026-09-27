#!/bin/sh
# Restore a dump over the live database.
#
# This is the one script in the repository that destroys data on purpose, so it
# has three deliberate friction points:
#
#   1. it refuses to run without CONFIRM_RESTORE=yes;
#   2. it refuses to run while it can see another client connected, and tells you
#      what to stop — restoring underneath a running API produces a database that
#      is half old and half new and cannot be reasoned about;
#   3. it takes its own safety copy of the current database first, unless told not
#      to. Restoring the wrong dump is a mistake that is recoverable; overwriting
#      the only copy of what you had is not.
#
# Typical use, in this order:
#
#   docker compose stop backend celery-worker celery-beat connector-dnstwist \
#                        connector-shodan connector-hibp
#   make restore FILE=backups/opendrp-20260913T041500Z.dump
#   docker compose up -d
#
# See docs/backup-restore.md.
set -eu

PGHOST="${PGHOST:-postgres}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:?PGUSER must be set}"
PGDATABASE="${PGDATABASE:?PGDATABASE must be set}"
: "${PGPASSWORD:?PGPASSWORD must be set}"
BACKUP_DIR="${BACKUP_DIR:-/backups}"

export PGPASSWORD

log() {
    echo "[restore] $*"
}

fail() {
    echo "[restore] FAILED: $*" >&2
    exit 1
}

if [ "${CONFIRM_RESTORE:-}" != "yes" ]; then
    fail "refusing to overwrite '${PGDATABASE}' without CONFIRM_RESTORE=yes.
       This deletes every asset, finding and audit row currently in the database.
       Re-run as:  CONFIRM_RESTORE=yes make restore FILE=<dump>"
fi

dump="${1:-$BACKUP_DIR/latest.dump}"
if [ ! -f "$dump" ]; then
    fail "no dump at ${dump}"
fi
if ! pg_restore --list "$dump" >/dev/null 2>&1; then
    fail "${dump} is not a readable archive; nothing was changed"
fi

# Refuse while the platform is still connected. `pg_stat_activity` sees the API
# and worker pools, so this is a real check rather than a reminder.
others="$(psql --host="$PGHOST" --port="$PGPORT" --username="$PGUSER" \
    --dbname="$PGDATABASE" --no-psqlrc --tuples-only --no-align --command="
        SELECT count(*) FROM pg_stat_activity
         WHERE datname = current_database()
           AND pid <> pg_backend_pid()
           AND backend_type = 'client backend';
    " 2>/dev/null || echo 0)"

if [ "${others:-0}" -gt 0 ]; then
    fail "${others} other client connection(s) to '${PGDATABASE}'.
       Stop the services that hold them first, then restore:
         docker compose stop backend celery-worker celery-beat \\
                              connector-dnstwist connector-shodan connector-hibp"
fi

if [ "${RESTORE_SKIP_SAFETY_COPY:-0}" != "1" ]; then
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    safety="$BACKUP_DIR/pre-restore-${stamp}.dump"
    log "taking a safety copy of the current database first: ${safety}"
    # Not `--no-owner` semantics to worry about here: this copy exists only to be
    # restored by this same instance in the next few minutes.
    pg_dump --format=custom --no-owner --file="$safety" "$PGDATABASE" \
        || fail "could not take the safety copy; refusing to proceed (set RESTORE_SKIP_SAFETY_COPY=1 to override)"
    log "safety copy written (${safety})"
fi

log "dropping and recreating '${PGDATABASE}'"
# FORCE for the same reason as in verify_restore.sh: a lingering connection must
# not be able to block a restore the operator has explicitly confirmed.
psql --host="$PGHOST" --port="$PGPORT" --username="$PGUSER" \
    --dbname=postgres --no-psqlrc --quiet \
    --command="DROP DATABASE IF EXISTS ${PGDATABASE} WITH (FORCE)" >/dev/null
psql --host="$PGHOST" --port="$PGPORT" --username="$PGUSER" \
    --dbname=postgres --no-psqlrc --quiet \
    --command="CREATE DATABASE ${PGDATABASE}" >/dev/null

log "restoring ${dump}"
pg_restore --host="$PGHOST" --port="$PGPORT" --username="$PGUSER" \
    --dbname="$PGDATABASE" --no-owner --exit-on-error "$dump" \
    || fail "pg_restore reported an error; the database is in a partial state.
       The safety copy can be restored with RESTORE_SKIP_SAFETY_COPY=1 make restore FILE=<pre-restore dump>"

log "restored. Start the platform again: docker compose up -d"
log "Then confirm: make health && make backup-verify"
