"""Endpoint lookups for the exposure connectors: Netlas and Shodan host data only.

Each function answers one question: which services a single IP or domain exposes.
Nothing here starts a scan, submits a target to a provider or follows a redirect.
Every physical HTTP attempt is charged to the per-scan budget and to the core's
shared provider quota before it is sent, so retries are never free.
"""

import ipaddress
import re
from urllib.parse import quote

import httpx

from opendrp_connector.provider import ProviderClient, ProviderLimits

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
#: The ceiling this worker runs its client under, named once because the shared
#: client is given it explicitly: its own limit is a single number, and passing
#: that instead would drop the separate connect bound.
CLIENT_TIMEOUT = httpx.Timeout(30, connect=5)

#: This worker's numbers for one provider call, stated rather than inherited.
#: Every one of them is what `_get` did before the shared client existed: three
#: attempts, a local backoff of `0.25 * 2 ** attempt`, a `Retry-After` capped at
#: five seconds, and a two megabyte body.
#:
#: Two of them would change behaviour if left to the shared defaults.
#: `backoff_factor` is a quarter of the shared exponent, and
#: `abort_when_retry_after_exceeds=None` is this worker's answer to a long hint:
#: the hint is already capped at five seconds by `max_retry_delay`, so there is
#: nothing to abandon - and the shared default of sixty would turn a provider
#: asking for a longer pause into a `http_<status>_retry_later` failure this
#: worker's vocabulary has no name for.
LIMITS = ProviderLimits(
    max_attempts=MAX_ATTEMPTS,
    max_retry_delay=5.0,
    max_response_bytes=MAX_BODY_BYTES,
    backoff_factor=0.25,
    abort_when_retry_after_exceeds=None,
)

#: The shared client's names, said in this worker's own vocabulary.
#:
#: `RECOVERABLE_ERRORS` in `main.py` is a set of *these* strings and it decides
#: whether the next target is worth asking about, so a shared name cannot simply
#: pass through: `network_timeout` would turn "try the next target" into "stop the
#: scan" without a single test changing. The statuses already have a home - the
#: classifier below, which the shared client calls - so this table is only what a
#: status cannot express: a body it refused to read, and a transport that failed.
OUTCOME_CODES = {
    "network_error": "network_or_invalid_response",
    "network_timeout": "network_or_invalid_response",
    "retry_exhausted": "network_or_invalid_response",
    "invalid_json": "network_or_invalid_response",
    "response_too_large": "response_too_large",
    "invalid_response": "invalid_response",
}


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

    def _error_code(self, status, _body):
        """What this worker calls each refusal, from the status alone.

        The shared client hands every plain ``http_<status>`` to this table, which
        is why the numbers live here rather than in the SDK: which of them mean
        "the account cannot scan" and which mean "this target failed" is this
        worker's decision, and ``RECOVERABLE_ERRORS`` is written in its words.

        A Shodan 404 is the one answer that is not a failure at all - the address
        simply is not in the index - so it is left under the client's own name,
        which :meth:`_get` reads as "nothing to report".
        """
        if status == 404 and self.provider == "shodan":
            return None
        if status == 401:
            return "invalid_credentials"
        if status == 403:
            return "access_denied"
        if status == 429:
            return "rate_limited"
        if 500 <= status <= 599:
            return "network_or_invalid_response"
        return "provider_rejected_request"

    async def _get(self, path, params=None, *, bucket="lookup"):
        """Return the decoded JSON object, or ``None`` for a Shodan 404 (not indexed).

        One provider call, made through the shared client: the pace, the retries,
        the ``Retry-After`` ceiling and the body bound are its mechanisms, and each
        physical attempt is charged to this scan's budget and to the core's shared
        quota by the hook below, so a retry is never free.

        The body bound is also the fix this migration carries: the attempt used to
        read the whole answer into memory and compare its length afterwards, which
        is the buffering the bound exists to prevent. It is now refused while it is
        being read.
        """
        if not self.api_key or len(self.api_key) > 512 or any(ord(c) < 33 for c in self.api_key):
            raise ProviderError("credentials_unconfigured")
        headers = {"Accept": "application/json"}
        query = dict(params or {})
        if self.provider == "netlas":
            headers["Authorization"] = "Bearer " + self.api_key
        else:
            # Shodan authenticates with a query parameter only; the URL is never logged.
            query["key"] = self.api_key

        async def charge():
            if self.requests >= self.max_requests:
                raise ProviderError("scan_request_budget_exhausted")
            await self.reserve(bucket)
            self.requests += 1

        async with httpx.AsyncClient(
            timeout=CLIENT_TIMEOUT,
            follow_redirects=False,
            transport=self._transport,
        ) as client:
            provider = ProviderClient(
                http=client,
                limits=LIMITS,
                reserve=charge,
                classify_error=self._error_code,
            )
            result = await provider.get_json(
                BASES[self.provider] + path,
                params=query,
                headers=headers,
                timeout=CLIENT_TIMEOUT,
            )

        if result.outcome is None:
            payload = result.payload
            if not isinstance(payload, dict):
                # A JSON array or scalar is a valid body and the wrong answer.
                raise ProviderError("invalid_response")
            return payload
        if result.outcome == "http_404" and self.provider == "shodan":
            # The provider's documented way of saying "not indexed", not a failure.
            return None
        raise ProviderError(OUTCOME_CODES.get(result.outcome, result.outcome))

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
