#!/bin/sh
# ------------------------------------------------------------------------------
# OpenDRP frontend — render /etc/nginx/hsts.inc from the deployment's settings
# ------------------------------------------------------------------------------
# Nginx cannot read an environment variable, and `add_header` is not conditional
# on anything: a directive is either in the configuration or absent. So the three
# settings an operator actually reasons about (is HSTS on, for how long, and for
# subdomains too) are turned into one directive here, at container start, and the
# server blocks `include` the result.
#
# Why not the nginx image's `envsubst` template mechanism: `default.conf` is full
# of nginx's own variables ($host, $remote_addr, $proxy_add_x_forwarded_for ...),
# and substituting into it means every one of them has to be kept out of the
# environment. Rendering one small file keeps the server configuration literal and
# the substitution surface to three names.
#
# Copied into the image as /docker-entrypoint.d/40-opendrp-hsts.sh, so the nginx
# entrypoint runs it before the server starts and `nginx -t` can refuse a value
# nginx cannot parse - a container that says why, instead of one that comes up and
# quietly serves without the header.
#
# HSTS is a promise a browser keeps for HSTS_MAX_AGE seconds, and it cannot be
# withdrawn early: the browser has to be reached over HTTPS with `max-age=0`,
# which is exactly what is unavailable when a certificate has expired or been
# replaced by a self-signed one. That is why `HSTS_ENABLED=false` is the default —
# see .env.example.
#
# Usage:  hsts.sh [--check] [OUTPUT]
#   OUTPUT  include to write (default: /etc/nginx/hsts.inc)
#   --check  report whether HSTS would be enabled (exit 0 = yes, 1 = no), write
#            nothing - this is what `make evidence`-style diagnostics and the
#            test suite use.
#
# Exit codes: 0 written (or: HSTS enabled, with --check), 1 misconfigured (or:
# HSTS disabled, with --check), 2 unusable arguments.
# ------------------------------------------------------------------------------
set -eu

CHECK_ONLY=0
OUTPUT="/etc/nginx/hsts.inc"
for argument in "$@"; do
    case "$argument" in
        --check) CHECK_ONLY=1 ;;
        -*) echo "hsts.sh: unknown option '$argument'" >&2; exit 2 ;;
        *) OUTPUT="$argument" ;;
    esac
done

HSTS_ENABLED="${HSTS_ENABLED:-false}"
HSTS_MAX_AGE="${HSTS_MAX_AGE:-31536000}"
HSTS_INCLUDE_SUBDOMAINS="${HSTS_INCLUDE_SUBDOMAINS:-false}"

# The same truthiness the application accepts (`app.core.config.as_bool` in
# effect): anything else - including a typo like `ture` - is off, because the safe
# direction for a header that cannot be withdrawn is "not sent".
is_true() {
    case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
        1|true|yes|on) return 0 ;;
        *) return 1 ;;
    esac
}

if ! is_true "$HSTS_ENABLED"; then
    if [ "$CHECK_ONLY" = "1" ]; then
        exit 1
    fi
    {
        echo "# HSTS disabled: HSTS_ENABLED is not true (docker/nginx/hsts.sh)."
        echo "# Set HSTS_ENABLED=true in .env, then recreate this container, once the"
        echo "# certificate in front of this host is one browsers already trust."
    } >"$OUTPUT"
    echo "[OpenDRP] HSTS disabled; no Strict-Transport-Security header will be sent."
    exit 0
fi

case "$HSTS_MAX_AGE" in
    ''|*[!0-9]*)
        echo "hsts.sh: HSTS_MAX_AGE must be a whole number of seconds, got '$HSTS_MAX_AGE'" >&2
        exit 2
        ;;
esac
if [ "$HSTS_MAX_AGE" -le 0 ]; then
    # max-age=0 is how a server tells a browser to *forget* HSTS, which is the
    # opposite of what this file is asked to do. Refused rather than clamped: the
    # operator meant one of the two, and guessing which is how a security setting
    # ends up doing the reverse of what its name says.
    echo "hsts.sh: HSTS_MAX_AGE must be greater than 0 when HSTS_ENABLED is true (max-age=0 means 'forget HSTS'); set HSTS_ENABLED=false to send no header" >&2
    exit 2
fi

VALUE="max-age=$HSTS_MAX_AGE"
if is_true "$HSTS_INCLUDE_SUBDOMAINS"; then
    VALUE="$VALUE; includeSubDomains"
fi

if [ "$CHECK_ONLY" = "1" ]; then
    exit 0
fi

echo "add_header Strict-Transport-Security \"$VALUE\" always;" >"$OUTPUT"
echo "[OpenDRP] HSTS enabled: Strict-Transport-Security: $VALUE"

if command -v nginx >/dev/null 2>&1; then
    # Fail here, with the message nginx gives for the file it cannot parse, rather
    # than in a server that refuses to start after the include is read.
    nginx -t >/dev/null
fi
