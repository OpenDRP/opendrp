"""Endpoint lookups for the exposure connectors: Netlas and Shodan host data only.

Each function answers one question: which services a single IP or domain exposes.
Nothing here starts a scan, submits a target to a provider or follows a redirect.
Every physical HTTP attempt is charged to the per-scan budget and to the core's
shared provider quota before it is sent, so retries are never free.
"""

import asyncio
import ipaddress
import re
from urllib.parse import quote

import httpx

BASES = {
    "netlas": "https://app.netlas.io/api",
    "shodan": "https://api.shodan.io",
}
KEY_ENV = {
    "netlas": "NETLAS_API_TOKEN",
    "shodan": "SHODAN_API_KEY",
}
MAX_BODY_BYTES = 2_000_000
MAX_ATTEMPTS = 3


class ProviderError(RuntimeError):
    """Safe codes only: never a URL, response body or credential."""

    def __init__(self, code, retry_after=None):
        super().__init__(code)
        self.retry_after = retry_after


def host(value):
    """Normalize a domain (not an IP) for lookup; reject anything else."""
    if not isinstance(value, str) or len(value) > 253:
        raise ProviderError("invalid_endpoint")
    value = value.rstrip(".").lower()
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ProviderError("invalid_endpoint") from exc
    if not re.fullmatch(
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
        value,
    ):
        raise ProviderError("invalid_endpoint")
    return value


def _ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except (TypeError, ValueError):
        return None


def _port(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, str) and value.isdecimal():
        value = int(value)
    if isinstance(value, int) and 1 <= value <= 65535:
        return value
    return None


def _token(value, default="unknown"):
    text = re.sub(r"[^a-z0-9._+-]", "-", str(value or "").lower()).strip("-")
    return text[:32] or default


def _retry_wait(value):
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    return min(5.0, max(0.0, seconds))


class EndpointClient:
    """One provider, one scan. ``reserve(bucket)`` is awaited before every attempt."""

    def __init__(self, provider, api_key, reserve, *, max_requests, transport=None):
        if provider not in BASES:
            raise ValueError("unsupported provider")
        self.provider = provider
        self.api_key = (api_key or "").strip()
        self.reserve = reserve
        self.max_requests = max_requests
        self.requests = 0
        self._transport = transport

    async def _get(self, path, params=None, *, bucket="lookup"):
        """Return the decoded JSON object, or ``None`` for a Shodan 404 (not indexed)."""
        if not self.api_key or len(self.api_key) > 512 or any(ord(c) < 33 for c in self.api_key):
            raise ProviderError("credentials_unconfigured")
        headers = {"Accept": "application/json"}
        query = dict(params or {})
        if self.provider == "netlas":
            headers["Authorization"] = "Bearer " + self.api_key
        else:
            # Shodan authenticates with a query parameter only; the URL is never logged.
            query["key"] = self.api_key

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(30, connect=5),
            follow_redirects=False,
            transport=self._transport,
        ) as client:
            for attempt in range(MAX_ATTEMPTS):
                if self.requests >= self.max_requests:
                    raise ProviderError("scan_request_budget_exhausted")
                await self.reserve(bucket)
                self.requests += 1
                last = attempt == MAX_ATTEMPTS - 1
                try:
                    response = await client.get(BASES[self.provider] + path, params=query, headers=headers)
                except httpx.HTTPError as exc:
                    if last or self.requests >= self.max_requests:
                        raise ProviderError("network_or_invalid_response") from exc
                    await asyncio.sleep(0.25 * (2**attempt))
                    continue

                status = response.status_code
                if status == 404 and self.provider == "shodan":
                    return None
                if status == 401:
                    raise ProviderError("invalid_credentials")
                if status == 403:
                    raise ProviderError("access_denied")
                if status == 429 or 500 <= status <= 599:
                    if last or self.requests >= self.max_requests:
                        raise ProviderError("rate_limited" if status == 429 else "network_or_invalid_response")
                    wait = _retry_wait(response.headers.get("Retry-After"))
                    await asyncio.sleep(wait if wait is not None else 0.25 * (2**attempt))
                    continue
                if status != 200:
                    raise ProviderError("provider_rejected_request")
                if len(response.content) > MAX_BODY_BYTES:
                    raise ProviderError("response_too_large")
                try:
                    data = response.json()
                except ValueError as exc:
                    raise ProviderError("network_or_invalid_response") from exc
                if not isinstance(data, dict):
                    raise ProviderError("invalid_response")
                return data
        raise ProviderError("network_or_invalid_response")

    async def host_ports(self, target):
        """Services exposed by one IP or domain, as normalized endpoint records."""
        if self.provider == "netlas":
            value = str(target) if _ip(target) else host(target)
            data = await self._get("/host/" + quote(value, safe="") + "/")
            return _netlas_records(data)
        data = await self._get("/shodan/host/" + str(ipaddress.ip_address(target)))
        if data is None:
            return []
        return _shodan_records(data)

    async def resolve(self, domains):
        """Shodan only: resolve a batch of domains in one request (``None`` if unresolved)."""
        if self.provider != "shodan":
            raise ProviderError("unsupported_capability")
        names = [host(name) for name in domains]
        if not names:
            return {}
        data = await self._get("/dns/resolve", {"hostnames": ",".join(names)})
        resolved = {}
        for name in names:
            resolved[name] = _ip((data or {}).get(name))
        return resolved


def _netlas_records(data):
    if not isinstance(data, dict):
        raise ProviderError("invalid_response")
    ports = data.get("ports", [])
    if not isinstance(ports, list):
        raise ProviderError("invalid_response")
    ip = _ip(data.get("ip"))
    records = []
    for item in ports:
        if not isinstance(item, dict):
            continue
        port = _port(item.get("port"))
        if port is None:
            continue
        transport = str(item.get("prot4") or "tcp").lower()
        records.append(
            {
                "ip": ip,
                "port": port,
                "transport": transport if transport in {"tcp", "udp"} else "tcp",
                "protocol": _token(item.get("prot7") or item.get("protocol")),
            }
        )
    return records


def _shodan_records(data):
    ip = _ip(data.get("ip_str") or data.get("ip"))
    seen = {}
    for item in data.get("data") or []:
        if not isinstance(item, dict):
            continue
        port = _port(item.get("port"))
        if port is None:
            continue
        transport = str(item.get("transport") or "tcp").lower()
        seen[(port, transport)] = _token(item.get("product"))
    for port in data.get("ports") or []:
        number = _port(port)
        if number is not None:
            seen.setdefault((number, "tcp"), "unknown")
    return [
        {
            "ip": ip,
            "port": port,
            "transport": transport if transport in {"tcp", "udp"} else "tcp",
            "protocol": protocol,
        }
        for (port, transport), protocol in sorted(seen.items())
    ]
