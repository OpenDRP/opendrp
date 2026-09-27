#!/bin/sh
# Run Celery Beat under a liveness heartbeat.
#
# Why a wrapper instead of a plain `celery beat` command: every other service in
# the stack has something a healthcheck can ask — an HTTP endpoint, a broker
# round trip. Beat has neither. It owns no queue, answers no probe, and its only
# externally visible artefact is the schedule it is supposed to be advancing, so
# a container that starts, logs "beat: Starting..." and then wedges looks
# identical to a healthy one from the outside.
#
# So the process itself is not the thing to check. This script starts beat in the
# background, touches BEAT_LIVENESS_FILE every few seconds for as long as the
# beat process is still alive, and forwards the container's stop signal to it.
# The healthcheck (compose) reads that file's mtime; a stale file means the
# scheduler stopped, and scans silently stop being dispatched.
#
# Invoked as `sh /app/scripts/beat_wrapper.sh` rather than by path, so a Windows
# checkout that cannot carry the executable bit still runs it.
set -eu

BEAT_LIVENESS_FILE="${BEAT_LIVENESS_FILE:-/tmp/opendrp-beat-alive}"
BEAT_HEARTBEAT_INTERVAL_SEC="${BEAT_HEARTBEAT_INTERVAL_SEC:-5}"

# Fail loudly instead of starting silently without a heartbeat: a wrapper whose
# liveness file is missing would leave the container permanently unhealthy, and
# an operator would go looking for a scheduler fault rather than a typo.
mkdir -p "$(dirname "$BEAT_LIVENESS_FILE")" 2>/dev/null || true
if ! date +%s >"$BEAT_LIVENESS_FILE" 2>/dev/null; then
    echo "[beat_wrapper] cannot write BEAT_LIVENESS_FILE=$BEAT_LIVENESS_FILE" >&2
    exit 1
fi

celery -A app.core.celery_app beat \
    --loglevel="${CELERY_LOGLEVEL:-info}" \
    --scheduler celery.beat.PersistentScheduler \
    --schedule="${CELERYBEAT_SCHEDULE:-/workspace/reports_store/celerybeat-schedule.db}" &
beat_pid=$!

# Forward the stop signal: beat has to shut down gracefully so it persists the
# schedule state and does not re-fire a slot on the next start.
shutdown() {
    kill -TERM "$beat_pid" 2>/dev/null || true
}

trap shutdown TERM INT

while kill -0 "$beat_pid" 2>/dev/null; do
    date +%s >"$BEAT_LIVENESS_FILE" 2>/dev/null || true
    sleep "$BEAT_HEARTBEAT_INTERVAL_SEC"
done

wait "$beat_pid"
