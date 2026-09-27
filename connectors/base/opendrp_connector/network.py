"""Connector-side egress guard for provider and DNS-derived targets."""

from __future__ import annotations

import ipaddress
import os
import socket
from concurrent.futures import ThreadPoolExecutor


_BLOCKED = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
)


def is_safe_external_ip(value: str) -> bool:
    """Return whether a connector may open a socket to this address.

    Test fixtures use RFC 5737 documentation ranges to avoid real network
    access. They are allowed only when the process explicitly runs in TESTING;
    production connector containers never set that flag.
    """
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    if os.environ.get("TESTING") == "1" or os.environ.get("APP_ENV") == "test":
        documentation = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
        if any(address in ipaddress.ip_network(cidr) for cidr in documentation):
            return True
    return not any(address.version == network.version and address in network for network in _BLOCKED)


def resolve_public_ips(host: str, *, timeout: float = 3.0) -> tuple[str, ...]:
    """Resolve and validate every A/AAAA answer with a bounded DNS call."""
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(socket.getaddrinfo, host, None, 0, socket.SOCK_STREAM)
    try:
        infos = future.result(timeout=timeout)
    except (OSError, socket.gaierror, UnicodeError, TimeoutError):
        future.cancel()
        return ()
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
    addresses = []
    for info in infos:
        address = info[4][0]
        if address not in addresses:
            addresses.append(address)
    if not addresses or any(not is_safe_external_ip(address) for address in addresses):
        return ()
    return tuple(addresses)


def require_safe_external_ip(value: str) -> str:
    if not is_safe_external_ip(value):
        raise ValueError(f"refusing connector network access to non-public address {value!r}")
    return str(value).strip()
