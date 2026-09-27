#!/bin/sh
# Prove that the newest backup can actually be restored.
#
# `pg_restore --list` (run during every backup) only shows that the archive is
# readable. It cannot tell you that the dump restores into a working schema, that
# the objects it depends on exist on the target, or that the data it carries is
# the data you expect. The only honest check is a real restore, into a database
# nobody is using, followed by reading something back.
#
# This runs from the same container as the backup itself:
#
#   make backup-verify
#
# It is deliberately part of CI as well. A backup path that is never exercised is
# a belief, and beliefs about backups are what turn a recoverable incident into an
# unrecoverable one.
set -eu

PGHOST="${PGHOST:-postgres}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:?PGUSER must be set}"
: "${PGPASSWORD:?PGPASSWORD must be set}"
BACKUP_DIR="${BACKUP_DIR:-/backups}"
SCRATCH_DB="${SCRATCH_DB:-opendrp_restore_check}"

export PGPASSWORD

log() {
    echo "[verify-restore] $*"
}

# `psql -d postgres` because the scratch database cannot be dropped from a
# connection to itself, and the maintenance database always exists.
psql_admin() {
    psql --host="$PGHOST" --port="$PGPORT" --username="$PGUSER" \
        --dbname=postgres --no-psqlrc --quiet --command="$1"
}

dump="${1:-$BACKUP_DIR/latest.dump}"
if [ ! -f "$dump" ]; then
    log "FAILED: no dump at ${dump}. Take one first: make backup"
    exit 1
fi

log "restoring ${dump} into scratch database '${SCRATCH_DB}'"
# FORCE terminates any leftover connection to the scratch database, so a previous
# failed run cannot block this one.
psql_admin "DROP DATABASE IF EXISTS ${SCRATCH_DB} WITH (FORCE)"
psql_admin "CREATE DATABASE ${SCRATCH_DB}"

cleanup() {
    psql_admin "DROP DATABASE IF EXISTS ${SCRATCH_DB} WITH (FORCE)" || true
}

# --no-owner: the dump was taken with --no-owner, so ownership must not be
# applied on the way back in.
if ! pg_restore --host="$PGHOST" --port="$PGPORT" --username="$PGUSER" \
    --dbname="$SCRATCH_DB" --no-owner --exit-on-error "$dump"; then
    log "FAILED: pg_restore reported an error; the dump is not restorable as-is"
    cleanup
    exit 1
fi

# Read something back. The point is not these three values specifically: it is
# that a query against the restored schema succeeds and returns the content the
# platform cannot function without.
checks="$(psql --host="$PGHOST" --port="$PGPORT" --username="$PGUSER" \
    --dbname="$SCRATCH_DB" --no-psqlrc --tuples-only --no-align --command="
        SELECT
            (SELECT count(*) FROM information_schema.tables
              WHERE table_schema = 'public'),
            (SELECT count(*) FROM drp_modules),
            (SELECT count(*) FROM alembic_version);
    ")" || checks=""

if [ -z "$checks" ]; then
    log "FAILED: the restored database could not be queried; schema is incomplete"
    cleanup
    exit 1
fi

tables="$(printf '%s' "$checks" | cut -d'|' -f1)"
modules="$(printf '%s' "$checks" | cut -d'|' -f2)"
revisions="$(printf '%s' "$checks" | cut -d'|' -f3)"

# Two built-in modules exist in every installation. Zero means the restore
# produced an empty platform that would accept no connector and store no finding.
if [ "${modules:-0}" -lt 2 ]; then
    log "FAILED: restored database has ${modules} module(s); expected at least 2"
    cleanup
    exit 1
fi
if [ "${revisions:-0}" -lt 1 ]; then
    log "FAILED: restored database records no Alembic revision"
    cleanup
    exit 1
fi

cleanup
log "OK — ${dump} restored: ${tables} tables, ${modules} modules, ${revisions} revision row(s)"
