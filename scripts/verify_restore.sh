#!/bin/sh
# Prove that the newest backup can actually be restored.
#
# `pg_restore --list` (run during every backup) only shows that the archive is
# readable. It cannot tell you that the dump restores into a working schema, that
# the objects it depends on exist on the target, or that the data it carries is
# the data you expect. The only honest check is a real restore, into a database
# nobody is using, followed by reading something back.
#
# The dump is half of a backup. The other half is `reports-<stamp>.tgz`, written
# beside it by the same pass, and this script used to restore the database and
# never open it — so an empty, truncated or wrongly-rooted archive passed every
# gate the repository has, and the first person to find out was an operator whose
# restored instance listed reports it could not download. The archive is now
# listed, extracted into a scratch directory and read back the same way, on the
# same run. `REQUIRE_REPORT_ARCHIVE=1` turns "there was no archive beside this
# dump" into a failure, which is what CI sets: a job that silently stopped
# capturing the store would otherwise stay green.
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
# The store's path inside this container, which is what the archive's top-level
# entry is named after: `/reports`, so the archive holds `reports/…`.
REPORTS_DIR="${REPORTS_DIR:-/reports}"
REQUIRE_REPORT_ARCHIVE="${REQUIRE_REPORT_ARCHIVE:-0}"

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

# The archive a pass writes beside its dump: `opendrp-<stamp>.dump` and
# `reports-<stamp>.tgz` share the stamp. `latest.dump` carries no stamp of its
# own, so the newest archive beside it is the one the last pass wrote — the same
# assumption `backup.sh` relies on when it prunes.
report_archive() {
    case "${dump##*/}" in
        opendrp-*.dump)
            stamp="${dump##*/opendrp-}"
            printf '%s/reports-%s.tgz\n' "$(dirname "$dump")" "${stamp%.dump}"
            ;;
        *)
            ls -1 "$(dirname "$dump")"/reports-*.tgz 2>/dev/null | tail -n 1
            ;;
    esac
}

# Prove the other half of the backup: list the archive, extract it into a
# scratch directory nobody is using, and read a file back out of it.
check_report_archive() {
    archive="$(report_archive)"
    if [ -z "$archive" ] || [ ! -f "$archive" ]; then
        if [ "$REQUIRE_REPORT_ARCHIVE" = "1" ]; then
            log "FAILED: REQUIRE_REPORT_ARCHIVE=1 but there is no report archive beside ${dump}"
            return 1
        fi
        log "note: no report archive beside ${dump}; this backup carries the database only, and the report store was not part of it"
        return 0
    fi

    if ! listing="$(tar -tzf "$archive" 2>/dev/null)"; then
        log "FAILED: ${archive} is not a readable archive; the report store cannot be restored from it"
        return 1
    fi

    # The archive is made with `tar -C <parent> <basename>`, so it holds exactly
    # one top-level entry, named after the store. Extracting an archive rooted
    # somewhere else would write beside the store rather than into it, which is
    # the restore that leaves the downloads missing.
    store_name="$(basename "$REPORTS_DIR")"
    tops="$(printf '%s\n' "$listing" | cut -d/ -f1 | sort -u | sed '/^$/d' | tr '\n' ' ')"
    tops="$(printf '%s' "$tops" | sed 's/ $//')"
    if [ "$tops" != "$store_name" ]; then
        log "FAILED: ${archive} holds '${tops}' at the top level, not '${store_name}'; extracting it would not restore the store"
        return 1
    fi

    scratch="$(mktemp -d)"
    if ! tar -xzf "$archive" -C "$scratch" 2>/dev/null; then
        rm -rf "$scratch"
        log "FAILED: ${archive} cannot be extracted, so the store it holds cannot be restored"
        return 1
    fi
    files="$(find "$scratch" -type f | wc -l | tr -d ' ')"
    if [ "${files:-0}" -lt 1 ]; then
        # Not a failure: a store that held no report is archived faithfully, and
        # a backup taken before the first report legitimately looks like this.
        rm -rf "$scratch"
        log "note: ${archive} archived an empty report store; there was no report to read back"
        return 0
    fi
    sample="$(find "$scratch/$store_name" -type f | head -n 1)"
    if [ ! -s "$sample" ]; then
        rm -rf "$scratch"
        log "FAILED: ${archive} restored ${files} file(s), and the first (${sample##*/}) is empty; the store it holds is not usable"
        return 1
    fi
    rm -rf "$scratch"
    log "OK — ${archive} restored: the report store ('${store_name}/', ${files} file(s)), the first file read back non-empty"
    return 0
}

check_report_archive || exit 1

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
