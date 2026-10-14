"""Passive provider contracts (Netlas only); never submit targets or request live scans."""

import asyncio
import ipaddress
import json
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import quote, urlsplit

import httpx

BASES = {
    "netlas": "https://app.netlas.io/api",
}
KEYS = {
    "netlas": "NETLAS_API_TOKEN",
}


def core_credential(payload):
    """The provider key the core returned for this connector, or ``None``.

    Anything other than an explicit ``configured: true`` with a non-empty string
    is treated as no key, so a malformed response can never produce one.
    """
    if not isinstance(payload, dict) or payload.get("configured") is not True:
        return None
    key = payload.get("api_key")
    return key if isinstance(key, str) and key else None


CAPABILITIES = {
    "netlas": (
        "hostname",
        "ip",
        "certificate",
        "title",
        "body",
        "lookup",
        "passive_dns",
    ),
}


class ProviderError(RuntimeError):
    """Safe codes only, never raw URLs, response bodies or credentials."""

    def __init__(self, code, retry_after=None):
        super().__init__(code)
        self.retry_after = retry_after


def quoted(value):
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or any(ord(c) < 32 for c in value)
    ):
        raise ProviderError("invalid_search_value")
    # Escape search grammar metacharacters before adding the phrase delimiter.
    return '"' + re.sub(r'([\\"*?:(){}\[\]])', r"\\\1", value) + '"'


def query(provider, capability, value):
    fields = {
        "netlas": {
            "certificate": "certificate.names",
            "title": "http.title",
            "body": "http.body",
            "hostname": "host",
            "ip": "ip",
        },
    }
    field = fields.get(provider, {}).get(capability)
    if field is None:
        raise ProviderError("unsupported_capability")
    return field + ":" + quoted(value)


def host(value):
    if not isinstance(value, str) or len(value) > 253:
        raise ProviderError("invalid_endpoint")
    value = value.rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
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


def classify_http_error(provider, status_code, body):
    """Return a small safe error code; provider response text is never exposed."""
    text = body.decode("utf-8", errors="ignore").lower()[:8192]
    try:
        payload = json.loads(text)
    except (ValueError, TypeError):
        payload = None
    if isinstance(payload, dict):
        fragments = [
            str(value)
            for key, value in payload.items()
            if key.lower() in {"detail", "message", "errmsg", "error", "reason"}
            and isinstance(value, (str, int, float))
        ]
        text = " ".join(fragments).lower()[:8192] or text

    if status_code in {401} or (
        provider == "netlas"
        and status_code == 400
        and any(
            phrase in text
            for phrase in ("api key not found", "invalid api key", "api key is invalid")
        )
    ):
        return "invalid_credentials"
    if status_code == 403:
        return "access_denied"
    if status_code == 402:
        return "credits_exhausted"
    if status_code == 429:
        return "rate_limited"
    return f"http_{status_code}" if status_code != 400 else "provider_rejected_request"


def retry_delay(value):
    """Parse Retry-After delta-seconds or HTTP-date, capped to one day."""
    try:
        if value.strip().isdigit():
            seconds = int(value.strip())
        else:
            deadline = parsedate_to_datetime(value)
            if deadline.tzinfo is None:
                deadline = deadline.replace(tzinfo=timezone.utc)
            seconds = int((deadline - datetime.now(timezone.utc)).total_seconds())
        return min(86400, max(0, seconds))
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None


def observed(value):
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            date = datetime.fromtimestamp(
                value / 1000 if value > 10**11 else value, timezone.utc
            )
        else:
            date = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return (
            date.replace(tzinfo=timezone.utc).isoformat()
            if date.tzinfo is None
            else date.astimezone(timezone.utc).isoformat()
        )
    except (ValueError, OverflowError, OSError):
        raise ProviderError("invalid_observation_timestamp") from None


class Adapter:
    def __init__(self, provider, env, reserve, *, transport=None):
        if provider not in BASES:
            raise ProviderError("unsupported_provider")
        self.provider, self.env, self.reserve = provider, env, reserve
        self.transport = transport
        self.requests = 0
        self.max_requests = 20
        self.truncated = False
        self.record_errors = 0
        self.record_error_codes = []

    def record_error(self, code="invalid_record"):
        self.record_errors += 1
        if len(self.record_error_codes) < 20:
            self.record_error_codes.append(code)

    def _validated_result_batch(self, items, *, limit):
        if not isinstance(items, list):
            raise ProviderError("invalid_response")
        batch = []
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("data"), dict):
                self.record_error()
                continue
            batch.append(item["data"])
        if len(batch) > limit:
            self.truncated = True
        return batch[:limit]

    async def search_certificates(self, value, *, max_pages=3, max_results=100):
        """Search Netlas' documented certificate collection, with its own quota."""
        if self.provider != "netlas":
            raise ProviderError("unsupported_capability")
        target = host(value)
        if max_pages < 1 or max_results < 1:
            raise ProviderError("invalid_search_limit")
        certificates, start = [], 0
        async with self.client() as client:
            for _ in range(max_pages):
                response = await self.request(
                    client,
                    "GET",
                    "/certs/",
                    params={
                        "q": f'certificate.names.keyword:"{target}"',
                        "fields": "names,fingerprint_sha256,subject_dn,issuer_dn,validity,extensions.subject_alt_name.dns_names",
                        "start": start,
                    },
                    bucket="certificate",
                )
                items = response.get("items")
                if not isinstance(items, list):
                    raise ProviderError("invalid_response")
                batch = self._validated_result_batch(items, limit=max_results)
                for document in batch:
                    fingerprint = document.get("fingerprint_sha256")
                    if (
                        not isinstance(document.get("names"), list)
                        or not isinstance(fingerprint, str)
                        or not re.fullmatch(r"[0-9a-fA-F]{64}", fingerprint)
                    ):
                        self.record_error("invalid_certificate_record")
                        continue
                    certificates.append(document)
                more = len(items) == 20
                if len(certificates) >= max_results:
                    self.truncated = (
                        self.truncated or more or len(certificates) > max_results
                    )
                    return certificates[:max_results]
                if not more:
                    return certificates
                start += 20
            self.truncated = True
        return certificates

    async def search_domains(self, value, *, max_pages=3, max_results=100):
        """Query Netlas' documented passive DNS Domains collection only."""
        if self.provider != "netlas":
            raise ProviderError("unsupported_capability")
        target = host(value)
        if max_pages < 1 or max_results < 1:
            raise ProviderError("invalid_search_limit")
        rows, start = [], 0
        async with self.client() as client:
            for _ in range(max_pages):
                response = await self.request(
                    client,
                    "GET",
                    "/domains/",
                    params={
                        # Netlas documents this wildcard query for passive DNS
                        # discovery; keep the wildcard syntax generated, never user-supplied.
                        "q": f"domain:*.{target}",
                        "fields": "domain,a,aaaa,ns,last_updated",
                        "start": start,
                    },
                    bucket="search",
                )
                batch = self._validated_result_batch(
                    response.get("items"), limit=max_results
                )
                rows.extend(batch)
                more = len(response["items"]) == 20
                if len(rows) >= max_results:
                    self.truncated = self.truncated or more or len(rows) > max_results
                    return rows[:max_results]
                if not more:
                    return rows
                start += 20
            self.truncated = True
        return rows

    def dns_observations(self, target, rows):
        """Normalize DNS RRsets without treating provider data as ownership."""
        target = host(target)
        observations = []
        for row in rows:
            raw_domain = row.get("domain")
            try:
                domain = host(raw_domain)
            except ProviderError:
                self.record_error()
                continue
            if domain != target and not domain.endswith("." + target):
                self.record_error()
                continue
            try:
                timestamp = observed(row.get("last_updated") or row.get("@timestamp"))
            except ProviderError as exc:
                self.record_error(str(exc))
                timestamp = None
            for record_type, key, version in (
                ("A", "a", 4),
                ("AAAA", "aaaa", 6),
                ("NS", "ns", None),
            ):
                values = row.get(key, [])
                if values is None:
                    values = []
                if not isinstance(values, list):
                    self.record_error()
                    continue
                valid = []
                for value in values[:20]:
                    if version is not None:
                        try:
                            address = ipaddress.ip_address(value)
                        except (ValueError, TypeError):
                            self.record_error()
                            continue
                        if address.version != version:
                            self.record_error()
                            continue
                        valid.append(str(address))
                    else:
                        try:
                            valid.append(host(value))
                        except ProviderError:
                            self.record_error()
                if not valid:
                    continue
                normalized_values = sorted(set(valid))
                observations.append(
                    {
                        "observation_type": "passive_dns",
                        "subject": domain,
                        "record_type": record_type,
                        "value": "; ".join(normalized_values)[:1000],
                        "status": "historical",
                        "metadata": {
                            "evidence": "netlas_passive_dns_dataset",
                            "source_domain": target,
                            "provider_observed_at": timestamp or "unknown",
                            "record_values": normalized_values,
                        },
                    }
                )
        return observations

    @property
    def configured(self):
        return bool(self.env.get(KEYS[self.provider], "").strip())

    async def request(
        self, client, method, path, *, params=None, body=None, bucket="search"
    ):
        key = self.env.get(KEYS[self.provider], "").strip()
        if not key or len(key) > 512 or any(ord(c) < 33 for c in key):
            raise ProviderError("credentials_unconfigured")
        headers = {"Accept": "application/json", "Authorization": "Bearer " + key}
        params = dict(params or {})

        for attempt in range(3):
            if self.requests >= self.max_requests:
                raise ProviderError("scan_request_budget_exhausted")
            # Charge each physical attempt against both the shared provider
            # quota and per-job request budget; retries are never free.
            await self.reserve(bucket)
            self.requests += 1
            try:
                retry_wait = None
                async with client.stream(
                    method,
                    BASES[self.provider] + path,
                    params=params,
                    json=body,
                    headers=headers,
                ) as response:
                    if response.status_code != 200:
                        chunks = bytearray()
                        async for chunk in response.aiter_bytes():
                            chunks.extend(chunk[: 8192 - len(chunks)])
                            if len(chunks) >= 8192:
                                break
                        code = classify_http_error(
                            self.provider, response.status_code, bytes(chunks)
                        )
                        retry_after = retry_delay(
                            response.headers.get("Retry-After", "")
                        )
                        error = ProviderError(code, retry_after)
                        if (
                            response.status_code != 429
                            and not 500 <= response.status_code <= 599
                        ):
                            raise error
                        if attempt == 2 or self.requests >= self.max_requests:
                            raise error
                        retry_wait = min(
                            5,
                            retry_after
                            if retry_after is not None
                            else 0.25 * (2**attempt),
                        )
                    else:
                        data = bytearray()
                        async for chunk in response.aiter_bytes():
                            if len(data) + len(chunk) > 2_000_000:
                                raise ProviderError("response_too_large")
                            data.extend(chunk)
                        result = json.loads(data)
                if retry_wait is not None:
                    await asyncio.sleep(retry_wait)
                    continue
                break
            except ProviderError:
                raise
            except httpx.HTTPError as exc:
                if attempt == 2 or self.requests >= self.max_requests:
                    raise ProviderError("network_or_invalid_response") from exc
                await asyncio.sleep(0.25 * (2**attempt))
            except (ValueError, UnicodeError) as exc:
                raise ProviderError("network_or_invalid_response") from exc
        else:
            raise ProviderError("network_or_invalid_response")

        if not isinstance(result, dict):
            raise ProviderError("invalid_response")
        if result.get("error"):
            raise ProviderError("provider_application_error")
        return result

    def client(self):
        return httpx.AsyncClient(
            timeout=httpx.Timeout(30, connect=5),
            follow_redirects=False,
            transport=self.transport,
        )

    async def search(self, capability, value, *, max_pages=3, max_results=100):
        if self.provider == "netlas" and capability == "certificate":
            return await self.search_certificates(
                value, max_pages=max_pages, max_results=max_results
            )
        expression = query(self.provider, capability, value)
        rows = []
        async with self.client() as client:
            for page in range(max_pages):
                response = await self.request(
                    client,
                    "GET",
                    "/responses/",
                    params={"q": expression, "start": page * 20},
                    bucket="search",
                )
                items = response.get("items")
                if not isinstance(items, list):
                    raise ProviderError("invalid_response")
                batch = self._validated_result_batch(items, limit=max_results)
                more = len(items) == 20
                rows.extend(batch)
                if len(rows) >= max_results:
                    self.truncated = more or len(rows) > max_results
                    return rows[:max_results]
                if not more:
                    return rows
            self.truncated = True
        return rows

    async def lookup_host(self, value, *, max_results=100):
        target = host(value)
        async with self.client() as client:
            response = await self.request(
                client, "GET", "/host/" + quote(target, safe="") + "/", bucket="lookup"
            )
        ports = response.get("ports", [])
        if not isinstance(ports, list):
            raise ProviderError("invalid_response")
        ip = response.get("ip")
        if ip is not None:
            try:
                ip = str(ipaddress.ip_address(ip))
            except ValueError:
                raise ProviderError("invalid_endpoint_ip") from None
        whois = response.get("whois") if isinstance(response.get("whois"), dict) else {}
        timestamp = whois.get("@timestamp") or response.get("@timestamp")
        rows = []
        for item in ports[:max_results]:
            if not isinstance(item, dict):
                self.record_error()
                continue
            protocol = item.get("prot7") or item.get("protocol") or "unknown"
            transport = item.get("prot4") or "tcp"
            rows.append(
                {
                    "host": target,
                    "ip": ip,
                    "port": item.get("port"),
                    "protocol": protocol,
                    "transport_protocol": transport,
                    "last_updated": timestamp,
                }
            )
        self.truncated = len(ports) > max_results
        return rows


def endpoints(row, adapter=None):
    """Actual host/web records only: a SAN never proves endpoint ownership."""
    if not isinstance(row, dict):
        raise ProviderError("invalid_record")
    if "names" in row and ("fingerprint_sha256" in row or "subject_dn" in row):
        names = row.get("names")
        if not isinstance(names, list):
            if adapter:
                adapter.record_error()
                return []
            raise ProviderError("invalid_certificate_names")
        validity = row.get("validity")
        validity = validity if isinstance(validity, dict) else {}
        certificate = {}
        fingerprint = row.get("fingerprint_sha256")
        if isinstance(fingerprint, str) and re.fullmatch(
            r"[0-9a-fA-F]{64}", fingerprint
        ):
            certificate["sha256"] = fingerprint.lower()
        elif fingerprint is not None and adapter:
            adapter.record_error()
        for source_key, target_key in (("start", "valid_from"), ("end", "valid_to")):
            if validity.get(source_key):
                try:
                    certificate[target_key] = observed(validity[source_key])
                except ProviderError as exc:
                    if adapter:
                        adapter.record_error(str(exc))
        for key in ("subject_dn", "issuer_dn"):
            value = row.get(key)
            if isinstance(value, str) and not any(ord(char) < 32 for char in value):
                certificate[key] = value[:512]
        records = []
        for name in names[:100]:
            if not isinstance(name, str) or name.startswith("*."):
                continue
            try:
                subject = host(name)
            except ProviderError:
                if adapter:
                    adapter.record_error()
                continue
            records.append(
                {
                    "subject": subject,
                    "ip": None,
                    "port": None,
                    "transport": "tcp",
                    "protocol": "tls-certificate",
                    "observed_at": certificate.get("valid_from"),
                    "title": "TLS certificate",
                    "certificate": certificate,
                }
            )
        return records
    try:
        record = endpoint(row)
        return [record] if record else []
    except ProviderError as exc:
        if not adapter:
            raise
        adapter.record_error(str(exc))
        return []


#: Keys a provider row can name its subject under, in the order ``endpoint`` reads
#: them. Used to tell "this row names nothing" from "everything on this row was
#: filtered out", which are different outcomes for the caller: the first is a
#: partial scan, the second is a row that simply produced no observation.
SUBJECT_KEYS = ("hostname", "domain", "host", "ip", "ip_address", "uri")


def has_subject(row) -> bool:
    """Whether a provider row names anything this connector could attribute."""
    return isinstance(row, dict) and any(row.get(key) for key in SUBJECT_KEYS)


def endpoint(row):
    ip = row.get("ip") or row.get("ip_address")
    if ip:
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            raise ProviderError("invalid_endpoint_ip") from None
    subject = row.get("hostname") or row.get("domain") or row.get("host") or ip
    uri = row.get("uri") or row.get("host")
    port = row.get("port")
    if isinstance(uri, str) and uri:
        # Providers may emit both URLs and bare hostname:port / [IPv6]:port.
        try:
            ipaddress.ip_address(uri)
        except ValueError:
            parsed = urlsplit(uri if "://" in uri else "//" + uri)
            if parsed.username or parsed.password:
                raise ProviderError("invalid_endpoint")
            if parsed.hostname:
                subject = parsed.hostname
                try:
                    port = port or parsed.port
                except ValueError:
                    raise ProviderError("invalid_endpoint_port") from None
    if not subject:
        return None
    if isinstance(port, str) and port.isdecimal():
        port = int(port)
    if port is not None and (
        isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
    ):
        raise ProviderError("invalid_endpoint_port")
    protocol = row.get("protocol") or "unknown"
    if not isinstance(protocol, str) or len(protocol) > 32:
        raise ProviderError("invalid_endpoint_protocol")
    transport = str(
        row.get("transport_protocol") or row.get("transport") or "tcp"
    ).lower()
    if transport not in {"tcp", "udp"}:
        raise ProviderError("invalid_endpoint_transport")
    return {
        "subject": host(subject),
        "ip": ip,
        "port": port,
        "transport": transport,
        "protocol": protocol.lower(),
        "observed_at": observed(
            row.get("last_updated")
            or row.get("lastupdatetime")
            or row.get("scan_time")
            or row.get("@timestamp")
        ),
        "title": str(row.get("title") or "")[:1000],
    }
