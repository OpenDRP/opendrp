#!/bin/sh
# PostgreSQL + report-store backup.
#
# Runs inside a `postgres:17-alpine` container, not on the host, for two reasons:
# the client version then matches the server exactly (pg_dump refuses to dump a
# newer server, and a silently older client produces a dump that cannot be
# restored), and a self-hosted operator does not need to install a PostgreSQL
# client to be able to take a backup.
#
# Two ways to run it, one implementation:
#
#   make backup                    # one pass, then exit (BACKUP_ONCE=1)
#   docker compose --profile backup up -d backup
#                                  # same image, loops every BACKUP_INTERVAL_SEC
#
# Environment (all supplied by docker-compose.yml):
#   PGHOST PGPORT PGUSER PGDATABASE PGPASSWORD   connection (password is read by
#                                                pg_dump from the environment)
#   BACKUP_DIR          where dumps are written (a host directory or a volume)
#   BACKUP_KEEP         how many dumps to keep (default 14)
#   BACKUP_REPORTS      archive the report store too (default 1)
#   REPORTS_DIR         report store inside this container (default /reports)
#   BACKUP_ONCE         "1" = run a single pass and exit with its status
#   BACKUP_INTERVAL_SEC seconds between passes in loop mode (default 86400)
#
# A backup that has never been restored is a guess, so every dump is checked for
# readability before it is trusted, and `make backup-verify` restores the newest
# one into a throwaway database. See docs/backup-restore.md.
set -eu

BACKUP_DIR="${BACKUP_DIR:-/backups}"
BACKUP_KEEP="${BACKUP_KEEP:-14}"
BACKUP_REPORTS="${BACKUP_REPORTS:-1}"
REPORTS_DIR="${REPORTS_DIR:-/reports}"
BACKUP_INTERVAL_SEC="${BACKUP_INTERVAL_SEC:-86400}"

PGHOST="${PGHOST:-postgres}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:?PGUSER must be set}"
PGDATABASE="${PGDATABASE:?PGDATABASE must be set}"
: "${PGPASSWORD:?PGPASSWORD must be set}"
# pg_dump reads the password from the environment; keep it out of argv so it can
# never appear in `ps` output or in a container's command line.
export PGPASSWORD

log() {
    echo "[backup] $*"
}

run_once() {
    mkdir -p "$BACKUP_DIR"
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    dump="$BACKUP_DIR/opendrp-${stamp}.dump"

    log "dumping database '${PGDATABASE}' from ${PGHOST}:${PGPORT} to ${dump}"
    # --format=custom keeps compression and allows a selective restore;
    # --no-owner because the restoring instance may use different role names.
    if ! pg_dump --format=custom --no-owner --file="$dump" "$PGDATABASE"; then
        log "FAILED: pg_dump exited non-zero; removing the partial file ${dump}"
        rm -f "$dump"
        return 1
    fi

    # The whole point of a backup is the restore. A file that pg_restore cannot
    # even read its table of contents from is not a backup, and finding that out
    # during an incident is the worst possible time.
    if ! pg_restore --list "$dump" >/dev/null 2>&1; then
        log "FAILED: ${dump} is not a readable archive; left in place for inspection"
        return 1
    fi

    if [ "$BACKUP_REPORTS" = "1" ] && [ -d "$REPORTS_DIR" ]; then
        reports_archive="$BACKUP_DIR/reports-${stamp}.tgz"
        # `-C` + a relative name keeps the archive free of the source path, so it
        # can be extracted anywhere.
        if tar -czf "$reports_archive" -C "$(dirname "$REPORTS_DIR")" "$(basename "$REPORTS_DIR")" 2>/dev/null; then
            log "archived the report store to ${reports_archive}"
        else
            rm -f "$reports_archive"
            log "WARNING: could not archive ${REPORTS_DIR}; the database dump is unaffected"
        fi
    fi

    # `latest.dump` is a convenience for restore, not an extra copy: it is a
    # hard link when the filesystem allows one and a copy otherwise.
    rm -f "$BACKUP_DIR/latest.dump"
    ln "$dump" "$BACKUP_DIR/latest.dump" 2>/dev/null || cp "$dump" "$BACKUP_DIR/latest.dump"

    rotate
    log "done: ${dump}"
    return 0
}

rotate() {
    # Keep the newest BACKUP_KEEP dumps (and their report archives). Sorted by
    # name: the timestamp format sorts lexicographically in time order. Word
    # splitting over `ls` is safe here because this script generates every
    # filename and none of them contains whitespace.
    kept=0
    for file in $(ls -1r "$BACKUP_DIR"/opendrp-*.dump 2>/dev/null); do
        kept=$((kept + 1))
        if [ "$kept" -gt "$BACKUP_KEEP" ]; then
            log "pruning ${file}"
            rm -f "$file"
            stamp="${file##*/opendrp-}"
            rm -f "$BACKUP_DIR/reports-${stamp%.dump}.tgz"
        fi
    done
}

if [ "${BACKUP_ONCE:-0}" = "1" ]; then
    run_once
    exit $?
fi

log "loop mode: a backup every ${BACKUP_INTERVAL_SEC}s, keeping ${BACKUP_KEEP}"
while :; do
    # A failed pass in loop mode must not kill the container: the operator needs
    # the next attempt to happen, and `docker compose logs backup` already shows
    # the failure. `make backup` (once mode) is the one that reports a status.
    run_once || log "pass failed; retrying in ${BACKUP_INTERVAL_SEC}s"
    sleep "$BACKUP_INTERVAL_SEC" || exit 0
done
