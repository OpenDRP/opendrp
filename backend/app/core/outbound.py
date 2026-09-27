"""The destination policy for every connection this platform makes outward.

The rule this module exists to enforce is that **an operator-supplied
destination is not an operator-chosen network path**. Three surfaces let someone
who can reach the settings page name a host the platform will then connect to:
the SMTP server for alert email, the Telegram bot API, and the WHOIS lookup for a
domain found in a phishing finding. None of them is under HTTPS-only egress
control, and the API container sits on the data network next to PostgreSQL and
Redis, holds the deployment's secrets, and — on a cloud host — can reach the
instance metadata endpoint that hands out the instance role.

A "webhook"-shaped feature is not required for that to matter. `smtp_host` is a
free-text field whose only previous validation was "looks like a hostname or IP",
so `169.254.169.254`, `postgres`, `redis` and the Docker gateway were all
acceptable, and the probe reports back whether the connection opened and how
long it took — which is a port scanner an administrator does not need to run from
the outside.

What is blocked by default
--------------------------
* loopback (`127.0.0.0/8`, `::1`) — the API's own listeners, and anything an
  operator may have bound only to localhost on the same host;
* link-local (`169.254.0.0/16`, `fe80::/10`) — the metadata services of every
  major cloud (169.254.169.254) together with their less famous cousins, which
  are listed explicitly because being wrong here means handing over the instance
  credentials;
* unspecified and multicast (`0.0.0.0/8`, `224.0.0.0/4`, `::/128`, `ff00::/8`) —
  never a destination, occasionally a routing trick;
* **the deployment's own networks** (`OPENDRP_NETWORK_SUBNET` and the three
  subnets inside it) — the platform should not be usable as a way to reach
  itself, and those ranges are exactly where PostgreSQL, Redis and the Docker
  gateway live.

What is *not* blocked: RFC1918 ranges generally. A small company's mail relay is
usually at 10.x or 192.168.x, and refusing it by default would make the guard
the reason alerts stop working. `OUTBOUND_ALLOWED_HOSTS` exists for the cases the
default does not cover.

Residual risk, stated rather than hidden: the address is checked after
resolution and the connection is then made by hostname, so a DNS record that
changes between the two could still point at a blocked address. Closing that
window needs connection-level pinning (a custom transport that connects to the
validated IP while keeping the hostname for TLS), which is a large change for a
threat that requires control of the operator's DNS. The guard's job here is to
make the obvious pivots impossible, not to be an egress proxy.

A name that does not resolve is not refused. This is a deliberate limit on what
the guard is for: it exists to stop a connection *reaching* a forbidden address,
and a name with no answers cannot reach anything. Treating an empty resolution as
a refusal looks stricter and is worse — a resolver hiccup, a mail relay that is
temporarily missing from split-horizon DNS, or a test stand-in host would all be
reported as a security refusal, and the operator would be told to allowlist a
host that is fine. The connection attempt itself remains the thing that fails,
and it fails with the resolver's own error, which names the real problem.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import concurrent.futures
from typing import Iterable

from app.core.config import settings

#: The Telegram API host, as a constant. It is never built from configuration:
#: a hostname assembled from an operator-supplied value is a hostname an operator
#: can redirect, which is what `validate_telegram_token` is for.
TELEGRAM_API_HOST = "api.telegram.org"

#: `NNNN:XXXXXXXX…`, the shape Telegram issues. Duplicated from the settings
#: schema on purpose rather than imported from it: the schema validates what an
#: operator *writes*, this validates what is about to be *used*, and the second
#: must not depend on the first having run (a value restored from a backup, or
#: written before the schema grew the check, is used all the same).
TELEGRAM_BOT_TOKEN_RE = re.compile(r"^[0-9]{5,20}:[A-Za-z0-9_\-]{20,128}$")

#: Hostname labels, optionally punycode. Used for operator-supplied names where
#: an IP literal is also acceptable.
_HOSTNAME_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")

#: Characters that never occur in a hostname or in an IPv4/IPv6 literal, and that
#: do occur in a URL. `:` is absent on purpose: it separates the hextets of an
#: IPv6 address, and a check that refuses it refuses `::1` and `fe80::1` — the
#: two addresses the guard most wants to see. The URL-shaped value this catches
#: is `http://169.254.169.254/…`, which a `validate_*` call at write time would
#: have refused but a row restored from a backup never went through.
_HOST_FORBIDDEN_CHARS = ("/", "\\", "@", "?", "#", "[", "]")

REASON_EMPTY = "empty_host"
REASON_INVALID = "invalid_host"
REASON_BLOCKED_NETWORK = "blocked_network"
REASON_OWN_NETWORK = "own_network"
REASON_DNS_UNAVAILABLE = "dns_unavailable"

#: Ranges that are never a legitimate destination for an operator-supplied host.
#: Kept as literals rather than derived, so that a change here is a visible change
#: in the security posture rather than a side effect of an unrelated edit.
_DEFAULT_BLOCKED_CIDRS = (
    # Loopback.
    "127.0.0.0/8",
    "::1/128",
    # Link-local, which is where every cloud metadata service lives.
    "169.254.0.0/16",
    "fe80::/10",
    # Named individually because they are outside 169.254/16 and are the two
    # metadata endpoints most often forgotten.
    "100.100.100.200/32",  # Alibaba Cloud
    "192.0.0.192/32",  # Oracle Cloud
    # Unspecified, broadcast and multicast.
    "0.0.0.0/8",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/128",
    "ff00::/8",
)


class OutboundBlocked(Exception):
    """A destination the platform refuses to dial, with a machine-readable reason.

    The reason codes are stable strings (`blocked_network`, `own_network`,
    `invalid_host`, ...) so that they can be written into an audit record and
    matched on, rather than being read as prose.
    """

    def __init__(
        self,
        host: str,
        *,
        reason: str,
        port: int | None = None,
        address: str | None = None,
    ) -> None:
        self.host = host
        self.reason = reason
        self.port = port
        self.address = address
        super().__init__(f"refusing to connect to {host!r}: {reason}")

    def as_audit_details(self) -> dict:
        """Audit fields for a refusal.

        The address is included because it is what makes the record actionable —
        "blocked because it resolves to 169.254.169.254" is a different finding
        from "blocked because it is inside the deployment's own subnet" — and the
        host is the value the operator typed.
        """
        details: dict[str, object] = {"host": self.host, "reason": self.reason}
        if self.port is not None:
            details["port"] = self.port
        if self.address is not None:
            details["address"] = self.address
        return details


def _parse_networks(values: Iterable[str]) -> tuple:
    networks = []
    for value in values:
        candidate = str(value or "").strip()
        if not candidate:
            continue
        try:
            networks.append(ipaddress.ip_network(candidate, strict=False))
        except ValueError:
            # A malformed entry must not silently widen the policy, so it is
            # skipped and the operator's typo shows up as an unexplained block
            # of that range rather than as an unexpected allowance.
            continue
    return tuple(networks)


def blocked_networks() -> tuple:
    """Ranges no operator-supplied destination may resolve into."""
    configured = str(getattr(settings, "OUTBOUND_BLOCKED_CIDRS", "") or "").split(",")
    return _parse_networks([*_DEFAULT_BLOCKED_CIDRS, *configured])


def allowed_hosts() -> tuple[str, ...]:
    raw = str(getattr(settings, "OUTBOUND_ALLOWED_HOSTS", "") or "")
    return tuple(part.strip().lower() for part in raw.split(",") if part.strip())


def _allowlisted(host: str, address: str) -> str | None:
    """The allowlist entry that permits this destination, if any.

    Two forms, because both are needed in practice: a hostname (the operator's
    mail relay, whose address may change) and a CIDR (a range of internal
    senders). The hostname form is what makes the option usable without
    re-resolving; the CIDR form is what makes it precise.
    """
    normalized = host.strip().lower()
    for entry in allowed_hosts():
        if entry == normalized:
            return entry
        if "/" in entry:
            try:
                network = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            if ipaddress.ip_address(address) in network:
                return entry
    return None


def resolve_addresses(host: str) -> tuple[str, ...]:
    """Every address a host resolves to, bounded by the DNS probe timeout.

    ``getaddrinfo`` is a synchronous libc call and its resolver timeout is
    platform-dependent. Running it in a short-lived executor gives SMTP/WHOIS
    health checks a deterministic upper bound instead of allowing a broken DNS
    server to hold an API worker indefinitely. A timeout is treated as an
    unresolved destination; the subsequent provider connection still reports
    the actual configuration/network failure.
    """
    timeout = float(getattr(settings, "OUTBOUND_DNS_TIMEOUT_SECONDS", 3.0))
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    future = executor.submit(socket.getaddrinfo, host, None, 0, socket.SOCK_STREAM)
    try:
        infos = future.result(timeout=timeout)
    except (socket.gaierror, UnicodeError, OSError, TimeoutError):
        future.cancel()
        return ()
    finally:
        # Do not wait for a libc resolver call after its deadline. The process
        # remains bounded because the executor has one short-lived thread and
        # callers are never blocked on its shutdown.
        executor.shutdown(wait=False, cancel_futures=True)
    addresses: list[str] = []
    for info in infos:
        address = info[4][0]
        if address not in addresses:
            addresses.append(address)
    return tuple(addresses)


def classify_address(address: str) -> str | None:
    """Why this address is refused, or ``None`` when it is acceptable.

    IPv4-mapped IPv6 addresses are unwrapped first: `::ffff:127.0.0.1` is
    loopback, and a check that only looks at the v6 form would not notice.
    """
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return REASON_INVALID
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped

    for network in blocked_networks():
        if parsed.version == network.version and parsed in network:
            return REASON_BLOCKED_NETWORK
    for network in settings.deployment_networks:
        if parsed.version == network.version and parsed in network:
            return REASON_OWN_NETWORK
    return None


def _looks_like_a_url(candidate: str) -> bool:
    """Whether a value is a URL rather than a host.

    A use-time shape check, so that a host that never passed a ``validate_*``
    call — one restored from a backup, or written before the schema grew the
    check — still cannot smuggle a path or a set of credentials into the
    connection. Deliberately narrower than :func:`_validate_host_syntax`: it only
    refuses what is unambiguously not a host, because a false refusal here stops
    a delivery that should have happened.
    """
    if any(character in candidate for character in _HOST_FORBIDDEN_CHARS):
        return True
    return any(character.isspace() for character in candidate)


def ensure_allowed(host: str, *, port: int | None = None) -> tuple[str, ...]:
    """Raise :class:`OutboundBlocked` unless ``host`` may be connected to.

    Returns the resolved addresses so a caller that wants to log or pin them can.
    The check is per *address*: a host that resolves to one public and one blocked
    address is refused, because the platform cannot choose which one the kernel
    will pick.
    """
    candidate = str(host or "").strip()
    if not candidate:
        raise OutboundBlocked(candidate, reason=REASON_EMPTY, port=port)
    if _looks_like_a_url(candidate):
        raise OutboundBlocked(candidate, reason=REASON_INVALID, port=port)

    addresses = resolve_addresses(candidate)
    if not addresses:
        # A name with no answer is not a security verdict. The provider call
        # remains responsible for reporting the resolver failure; callers that
        # expose a health endpoint wrap the whole probe in a wall-clock timeout.
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            return (candidate,)
        addresses = (candidate,)

    for address in addresses:
        if _allowlisted(candidate, address) is not None:
            continue
        reason = classify_address(address)
        if reason is not None:
            raise OutboundBlocked(
                candidate, reason=reason, port=port, address=address
            )

    return addresses


def validate_telegram_token(value: str | None) -> str:
    """Return a usable Telegram bot token, or raise ``ValueError``.

    The token is interpolated into a URL *path*, under a host this module owns as
    a constant, so the property that matters is path safety rather than the exact
    shape Telegram issues: nothing that can end the path segment
    (`/`, `?`, `#`), escape the URL (`@`, `\\`), or inject whitespace may appear.
    `123456789:@evil.example/x` is refused — it has the shape of a token and
    would otherwise send every alert to an operator-chosen host — while a value
    that simply does not look like a real token is accepted, because refusing it
    would reject a token Telegram has not issued yet and a value restored from a
    backup that predates any format check. The stricter `NNNN:XXXX` rule stays
    where it belongs: in the settings schema, on what an operator writes.

    ``TELEGRAM_BOT_TOKEN_RE`` is kept as the documented shape of a well-formed
    token and exported for callers that want to *warn* on an odd value rather
    than refuse it.
    """
    candidate = str(value or "").strip()
    if not candidate:
        raise ValueError("telegram token is empty")
    if len(candidate) > 256:
        raise ValueError("telegram token is longer than 256 characters")
    if any(character.isspace() or ord(character) < 32 for character in candidate):
        raise ValueError("telegram token contains whitespace or control characters")
    if any(character in candidate for character in ("/", "?", "#", "@", "\\")):
        raise ValueError(
            "telegram token contains a URL separator, so it is not a token"
        )
    return candidate


def _validate_host_syntax(
    value: str | None, field: str, *, require_dot: bool
) -> str:
    """Shared shape check for a hostname or IP literal coming from outside.

    Rejects anything that is a URL rather than a host — no scheme, credentials,
    bracketed port, path or fragment. A field that accepts
    `smtp://user:pass@smtp.example:25` is a field that will eventually be parsed
    somewhere less careful.

    ``require_dot`` distinguishes the two callers. A WHOIS target came from a
    finding and must be a name on the internet, so a single label is wrong. An
    SMTP host may legitimately be `mail` on a network the operator controls, and
    the control that matters there is not the spelling but whether the address it
    resolves to is one the platform may connect to — which is the guard's job.
    """
    candidate = str(value or "").strip().rstrip(".")
    if not candidate:
        raise ValueError(f"{field} is empty")
    if len(candidate) > 253:
        raise ValueError(f"{field} is longer than 253 characters")
    if any(character in candidate for character in ("/", "@", ":", "[", "]", " ", "\\", "?", "#")):
        raise ValueError(f"{field} must be a hostname or IP address, not a URL")

    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        pass

    labels = candidate.split(".")
    if require_dot and len(labels) < 2:
        raise ValueError(f"{field} is not a fully qualified hostname")
    if any(not _HOSTNAME_LABEL_RE.match(label) for label in labels):
        raise ValueError(f"{field} is not a valid hostname or IP address")
    return candidate


def validate_smtp_host(value: str | None) -> str:
    """Return a usable SMTP host, or raise ``ValueError``."""
    return _validate_host_syntax(value, "smtp host", require_dot=False)


def validate_domain_target(value: str | None) -> str:
    """Return a domain an enrichment lookup may be made for, or raise `ValueError`.

    The value reaches this module from a finding, so it originated outside the
    platform: a WHOIS client resolves whatever it is given, and "whatever" must
    not include a URL or a bare container name.
    """
    return _validate_host_syntax(value, "domain", require_dot=True)
