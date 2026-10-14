#!/bin/sh
# ------------------------------------------------------------------------------
# OpenDRP frontend — render the trusted-proxy list nginx's realip module needs
# ------------------------------------------------------------------------------
# The edge rate limits are keyed on `$binary_remote_addr`. Without the realip
# module that address is the peer, and behind a TLS terminator the peer is the
# proxy — so every client would share one bucket, and a single busy browser
# would rate-limit everybody else. `real_ip_header X-Forwarded-For` replaces the
# address with the client's, but only for requests whose peer is named by
# `set_real_ip_from`. That restriction is the whole point: a client that invents
# its own `X-Forwarded-For` entry is not on the list, so the header is ignored
# and the peer address still counts against it.
#
# The list comes from `TRUSTED_PROXY_IPS`, the same variable the API uses to
# resolve the address it records in every audit row (`app/core/config.py`,
# `app/api/deps.py`). One value, two consumers: they cannot disagree about which
# hop may be believed. Accepted forms are exactly the ones the application's
# validator accepts — comma-separated IP addresses or CIDRs, no wildcard.
#
# Why a rendered file rather than a literal in `nginx.conf`: the trusted range is
# a deployment fact (it is the proxy's address), `nginx` cannot read an
# environment variable, and the container's default set of proxies is worth
# nothing to an operator. Rendering one small file keeps the server
# configuration literal and the substitution surface to one variable.
#
# Copied into the image as /docker-entrypoint.d/41-opendrp-realip.sh, so the
# nginx entrypoint runs it before the server starts — after the HSTS fragment,
# for no better reason than a stable order.
#
# Usage:  realip.sh [OUTPUT]
#   OUTPUT  include to write (default: /tmp/opendrp/realip/realip.inc)
#
# Exit codes: 0 written, 2 misconfigured or unusable arguments.
# ------------------------------------------------------------------------------
set -eu

OUTPUT="/tmp/opendrp/realip/realip.inc"
for argument in "$@"; do
    case "$argument" in
        -*) echo "realip.sh: unknown option '$argument'" >&2; exit 2 ;;
        *) OUTPUT="$argument" ;;
    esac
done

TRUSTED_PROXY_IPS="${TRUSTED_PROXY_IPS:-}"

# Created here rather than baked into the image: docker-compose.yml mounts a
# tmpfs over /tmp and the root filesystem is read-only, so anything the image
# placed here would be hidden anyway.
mkdir -p "$(dirname "$OUTPUT")"

if [ -z "$TRUSTED_PROXY_IPS" ]; then
    {
        echo "# No trusted proxy is configured: TRUSTED_PROXY_IPS is empty."
        echo "# nginx therefore leaves \$binary_remote_addr as the peer address,"
        echo "# which is right for an installation reached directly. Behind a"
        echo "# terminator it means every client shares one rate-limit bucket."
    } >"$OUTPUT"
    echo "[OpenDRP] no trusted proxy configured; edge limits key on the peer address."
    exit 0
fi

# The entries become lines of nginx configuration, so they are validated before
# they are rendered rather than trusted: anything that is not an address
# character sequence would be a way to inject a directive.
valid_entry() {
    case "$1" in
        *[!0-9A-Fa-f:./]*) return 1 ;;
        *[0-9]*) return 0 ;;
        *) return 1 ;;
    esac
}

rendered=""
for entry in $(printf '%s' "$TRUSTED_PROXY_IPS" | tr ',' ' '); do
    [ -n "$entry" ] || continue
    if [ "$entry" = "*" ]; then
        echo "realip.sh: TRUSTED_PROXY_IPS must list addresses, not '*': every client could then choose its own source address" >&2
        exit 2
    fi
    if ! valid_entry "$entry"; then
        echo "realip.sh: TRUSTED_PROXY_IPS contains '$entry', which is not an IP address or CIDR" >&2
        exit 2
    fi
    rendered="$rendered$entry
"
done

if [ -z "$rendered" ]; then
    echo "# TRUSTED_PROXY_IPS held no usable entry; no proxy is trusted." >"$OUTPUT"
    echo "[OpenDRP] TRUSTED_PROXY_IPS held no usable entry; no proxy is trusted."
    exit 0
fi

{
    echo "# Rendered by docker/nginx/realip.sh from TRUSTED_PROXY_IPS."
    printf 'set_real_ip_from %s;\n' $rendered
    echo "real_ip_header X-Forwarded-For;"
    echo "real_ip_recursive on;"
} >"$OUTPUT"

# One line per entry: the container log is the only record of which hops this
# nginx believes, and a concatenated list would read as one malformed address.
echo "[OpenDRP] trusting X-Forwarded-For from:"
printf '  %s' $rendered
printf '\n'

if command -v nginx >/dev/null 2>&1; then
    # Fail here, with the message nginx gives, rather than in a server that
    # refuses to start once the include is read. `/etc/nginx/hsts.inc` is
    # included as a glob, so an unrendered HSTS include is not an error.
    nginx -t >/dev/null
fi
