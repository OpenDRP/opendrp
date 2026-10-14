"""DNS Security source connectors (RDAP, DNS resolver, CT Logs, VirusTotal).

No provider secrets are embedded in code or the core registry. Each connector is
identified by its own manifest and posts bounded normalized observations to the
core's native, source-keyed DNS inventory. Provider errors never erase another
source's observations.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import re
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

import dns.resolver
import httpx
import structlog

from opendrp_connector import ConnectorBase
from opendrp_connector.network import resolve_public_ips
log = structlog.get_logger()

MAX_DOMAINS = 1000
MAX_OBSERVATIONS = 500
MAX_PAGES = 10
MAX_RESPONSE_BYTES = 2_000_000
MAX_RETRIES = 3
MAX_CTLOGS_REQUESTS_PER_SCAN = 100
CTLOGS_MIN_REQUEST_INTERVAL_SECONDS = 36.0


class _RequestBudgetReached(Exception):
    pass
def _text(raw: object, limit: int) -> str:
    if not isinstance(raw, str):
        return ""
    return re.sub(r"[\x00\r\n]", "", raw).strip()[:limit]


def _date(raw: object) -> str | None:
    if not isinstance(raw, str) or len(raw) > 64:
        return None
    try:
        value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return (value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value).isoformat()
    except ValueError:
        return None


def _in_domain(host: str | None, domain: str) -> bool:
    return host is not None and (host == domain or host.endswith("." + domain))


def _domain(raw: object) -> str | None:
    if not isinstance(raw, str):
        return None
    value = raw.strip().rstrip(".")
    if not value or len(value) > 253 or "://" in value or "/" in value or "@" in value:
        return None
    try:
        address = ipaddress.ip_address(value)
        return str(address)
    except ValueError:
        pass
    try:
        normalized = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    labels = normalized.split(".")
    if len(normalized) > 253 or len(labels) < 2 or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels):
        return None
    if not all(re.fullmatch(r"[a-z0-9-]+", label) for label in labels):
        return None
    return normalized


def _retry_after(response: httpx.Response) -> float | None:
    value = response.headers.get("Retry-After")
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        try:
            target = parsedate_to_datetime(value)
            if target.tzinfo is None:
                target = target.replace(tzinfo=timezone.utc)
            return max(0.0, (target - datetime.now(timezone.utc)).total_seconds())
        except (TypeError, ValueError, OverflowError):
            return None


class DNSConnector(ConnectorBase):
    SOURCE = ""
    BASE_URL = ""
    JOB_TYPE = ""
    NAME = ""

    def __init__(self):
        super().__init__()
        self._errors: list[str] = []
        self._client_timeout = httpx.Timeout(15.0, connect=5.0)

    async def register(self):
        await super().register()
        if self.SOURCE == "virustotal":
            await self._request("POST", "/api/v1/connectors/me/readiness", json={
                "credentials_configured": bool(self.env.get("DNS_SECURITY_VT_API_KEY", "").strip()),
                "credential_state": "unknown", "capabilities": ["hostname", "lookup"], "operations": ["lookup"]})

    def _domains(self, work: dict) -> list[str]:
        raw = (work.get("params") or {}).get("domains") or []
        values = []
        for item in raw[:MAX_DOMAINS] if isinstance(raw, list) else []:
            candidate = _domain(item)
            if candidate and candidate not in values:
                try:
                    ipaddress.ip_address(candidate)
                except ValueError:
                    values.append(candidate)
        return values

    async def _get_json(
        self,
        client: httpx.AsyncClient,
        url: str,
        *,
        headers: dict | None = None,
        before_request=None,
        extensions: dict | None = None,
    ) -> tuple[dict | list | None, str | None, httpx.Response | None]:
        """Fetch bounded JSON, invoking the reservation hook before every wire attempt."""
        for attempt in range(MAX_RETRIES + 1):
            try:
                if before_request is not None:
                    await before_request()
                options = {"extensions": extensions} if extensions else {}
                async with client.stream("GET", url, headers=headers, **options) as response:
                    if response.status_code == 200:
                        content = bytearray()
                        async for chunk in response.aiter_bytes():
                            if len(content) + len(chunk) > MAX_RESPONSE_BYTES:
                                return None, "response_too_large", response
                            content.extend(chunk)
                        try:
                            payload = json.loads(content)
                        except (ValueError, UnicodeError):
                            return None, "invalid_json", response
                        if not isinstance(payload, (dict, list)):
                            return None, "invalid_response", response
                        return payload, None, response
            except _RequestBudgetReached:
                return None, "request_budget_reached", None
            except (httpx.TimeoutException, httpx.HTTPError):
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(min(8, 2 ** attempt))
                    continue
                return None, "network_error", None
            if response.status_code == 429 or response.status_code >= 500:
                if attempt < MAX_RETRIES:
                    delay = _retry_after(response)
                    if delay is not None and delay > 60:
                        return None, f"http_{response.status_code}_retry_later", response
                    await asyncio.sleep(delay if delay is not None else 2 ** attempt)
                    continue
            if response.status_code != 200:
                return None, f"http_{response.status_code}", response

        return None, "retry_exhausted", None

    async def _rdap_lookup(self, client: httpx.AsyncClient, domain: str):
        """Follow bounded HTTPS bootstrap redirects with public-IP pinning.

        rdap.org normally redirects to the registry. Disabling all redirects
        made that normal response a failed scan; blindly following is an SSRF.
        No provider authentication is forwarded to registry destinations.
        """
        url = f"https://rdap.org/domain/{quote(domain, safe='.-')}"
        visited: set[str] = set()
        for _ in range(6):
            try:
                parsed = urlsplit(url)
                host = _domain(parsed.hostname)
                safe = (parsed.scheme == "https" and host and parsed.port in (None, 443)
                        and parsed.username is None and parsed.password is None and not parsed.fragment)
            except ValueError:
                safe = False
            if not safe or url in visited:
                return None, "unsafe_rdap_redirect", None
            visited.add(url)
            addresses = await asyncio.to_thread(resolve_public_ips, host)
            if not addresses:
                return None, "rdap_destination_blocked", None
            address = addresses[0]
            authority = f"[{address}]" if ":" in address else address
            pinned_url = urlunsplit(("https", authority, parsed.path, parsed.query, ""))
            payload, error, response = await self._get_json(
                client, pinned_url,
                headers={"Host": host, "Accept": "application/rdap+json, application/json"},
                extensions={"sni_hostname": host},
            )
            if response is None or response.status_code not in {301, 302, 303, 307, 308}:
                return payload, error, response
            location = response.headers.get("location", "")
            if not location or len(location) > 2048:
                return None, "invalid_rdap_redirect", response
            url = urljoin(url, location)
        return None, "rdap_redirect_limit", None

    async def _run_rdap(self, domains: list[str]) -> list[dict]:
        observations: list[dict] = []
        async with httpx.AsyncClient(timeout=self._client_timeout, follow_redirects=False) as client:
            for domain in domains:
                urls = [f"https://rdap.org/domain/{quote(domain, safe='.-')}"]
                for url in urls:
                    payload, error, _ = await self._rdap_lookup(client, domain)
                    if error or not isinstance(payload, dict):
                        self._errors.append(error or "invalid_response")
                        observations.append({"observation_type": "rdap", "subject": domain, "record_type": "RDAP", "value": domain, "status": "unknown", "metadata": {"provider": "rdap", "check_state": "failed"}})
                        continue
                    metadata = {"provider": "rdap"}
                    expires_at = None
                    events = payload.get("events")
                    if isinstance(events, list):
                        for event in events[:20]:
                            if isinstance(event, dict) and event.get("eventAction") in {"registration", "expiration", "last changed"}:
                                date_value = event.get("eventDate")
                                if isinstance(date_value, str) and len(date_value) <= 64:
                                    key = {"registration": "created", "expiration": "expires", "last changed": "updated"}[event["eventAction"]]
                                    metadata[key] = _text(date_value, 64)
                                    if key == "expires":
                                        try:
                                            parsed_expiry = datetime.fromisoformat(date_value.replace("Z", "+00:00"))
                                            if parsed_expiry.tzinfo is None:
                                                parsed_expiry = parsed_expiry.replace(tzinfo=timezone.utc)
                                            expires_at = parsed_expiry.astimezone(timezone.utc).isoformat()
                                        except ValueError:
                                            self._errors.append("invalid_expiry_date")
                    registrar = None
                    entities = payload.get("entities")
                    if isinstance(entities, list):
                        for entity in entities[:50]:
                            if isinstance(entity, dict) and isinstance(entity.get("roles"), list) and "registrar" in entity["roles"]:
                                vcard = entity.get("vcardArray")
                                if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
                                    registrar = next((_text(entry[3], 200) for entry in vcard[1][:100] if isinstance(entry, list) and len(entry) > 3 and entry[0] == "fn"), None)
                                    break
                    if registrar:
                        metadata["registrar"] = registrar
                    observations.append({"observation_type": "rdap", "subject": domain, "record_type": "RDAP", "value": domain, "expires_at": expires_at, "metadata": metadata})
                    if len(observations) >= MAX_OBSERVATIONS:
                        self._errors.append("observation_limit_reached")
                        return observations
                    break
        return observations

    async def _run_resolver(self, domains: list[str]) -> list[dict]:
        observations: list[dict] = []
        resolver = dns.resolver.Resolver(configure=True)
        nameservers = [
            item.strip()
            for item in self.env.get("DNS_NAMESERVERS", "").split(",")
            if item.strip()
        ]
        if nameservers:
            if len(nameservers) > 8:
                self._errors.append("too_many_resolvers")
                return observations
            try:
                resolver.nameservers = [str(ipaddress.ip_address(item)) for item in nameservers]
            except ValueError:
                self._errors.append("invalid_resolver_address")
                return observations
        try:
            resolver_timeout = float(self.env.get("DNS_SECURITY_RESOLVER_TIMEOUT_SECONDS", "3"))
        except ValueError:
            resolver_timeout = 3.0
        resolver.timeout = min(5.0, max(0.5, resolver_timeout))
        resolver.lifetime = resolver.timeout
        record_types = ["A", "AAAA", "CNAME"]
        if self.env.get("DNS_SECURITY_RESOLVER_EXTENDED", "false").lower() in {"1", "true", "yes"}:
            record_types.extend(["NS", "MX", "CAA"])
        for domain in domains:
            for record_type in record_types:
                try:
                    answer = await asyncio.to_thread(resolver.resolve, domain, record_type, raise_on_no_answer=False)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    continue
                except (dns.exception.Timeout, dns.resolver.NoNameservers, OSError):
                    self._errors.append("resolver_error")
                    continue
                ttl = int(getattr(answer.rrset, "ttl", 0) or 0) if answer.rrset else 0
                expiry = datetime.fromtimestamp(time.time() + max(0, min(ttl, 31_536_000)), timezone.utc).isoformat() if ttl else None
                # The storage identity is subject+record_type: submit one whole
                # RRset, not individual members that overwrite each other.
                values = sorted({_text(str(record), 255) for record in list(answer)[:20]})
                if values:
                    observations.append({"observation_type": "dns_record", "subject": domain, "record_type": record_type, "value": "; ".join(values)[:1000], "expires_at": expiry, "metadata": {"ttl": ttl, "record_values": values, "source_domain": domain}})
                    if len(answer) > 20:
                        self._errors.append("rrset_truncated")
                    if len(observations) >= MAX_OBSERVATIONS:
                        self._errors.append("observation_limit_reached")
                        return observations
        return observations

    async def _ct_exact_check(self, client, base, domain, headers, reserve):
        """Select the newest already-issued exact certificate, never a wildcard.

        A completed bounded query is required for an alertable result. Failed or
        truncated searches carry an explicit control record, not an empty success.
        """
        now = datetime.now(timezone.utc)
        candidates = []
        cursor = None
        cursors = set()
        state = "incomplete"
        future = False
        for _ in range(MAX_PAGES):
            url = f"{base}/v1/domain/{quote(domain, safe='.-')}"
            if cursor:
                url += f"?after={quote(cursor, safe='')}"
            payload, error, _response = await self._get_json(client, url, headers=headers, before_request=reserve)
            if error:
                self._errors.append(error)
                state = "failed"
                break
            rows = payload.get("rows") if isinstance(payload, dict) else None
            if not isinstance(rows, list) or len(rows) > 100:
                self._errors.append("invalid_response")
                state = "failed"
                break
            valid = True
            for item in rows:
                if not isinstance(item, dict) or _domain(item.get("match")) != domain or str(item.get("match", "")).startswith("*."):
                    valid = False
                    continue
                issued, expiry = _date(item.get("not_before")), _date(item.get("not_after"))
                identity = _text(item.get("id"), 128)
                if not issued or not expiry or not identity or datetime.fromisoformat(expiry) <= datetime.fromisoformat(issued):
                    valid = False
                    continue
                if datetime.fromisoformat(issued) > now:
                    future = True
                else:
                    candidates.append((datetime.fromisoformat(issued), identity, expiry, item))
            if not valid:
                self._errors.append("invalid_certificate_record")
                state = "incomplete"
                break
            if payload.get("has_next") is False:
                state = "verified" if candidates else "future_only" if future else "no_certificate"
                break
            next_cursor = payload.get("next_cursor")
            if payload.get("has_next") is not True or not isinstance(next_cursor, str) or not next_cursor or len(next_cursor) > 512 or next_cursor in cursors:
                self._errors.append("invalid_pagination")
                break
            cursors.add(next_cursor)
            cursor = next_cursor
        else:
            self._errors.append("page_limit_reached")
        selected = max(candidates, key=lambda item: (item[0], item[1])) if candidates and state == "verified" else None
        metadata = {"check_state": state, "source_domain": domain, "lookup": "exact", "checked_at": now.isoformat()}
        check = {"observation_type": "certificate_check", "subject": domain, "status": "unknown", "metadata": metadata}
        evidence = None
        if selected:
            issued, identity, expiry, item = selected
            metadata.update({"certificate_id": identity, "not_before": issued.isoformat()})
            check["expires_at"] = expiry
            evidence = {"observation_type": "certificate", "subject": domain, "value": domain, "expires_at": expiry, "status": "historical", "metadata": {"id": identity, "not_before": issued.isoformat(), "source_domain": domain, "wildcard": False, "certificate_match": domain, "lookup": "exact", "issuer": _text(item.get("issuer"), 200), "evidence": "certificate_transparency_historical_not_dns_proof"}}
        return check, evidence

    async def _run_ctlogs(self, domains: list[str]) -> list[dict]:
        observations: list[dict] = []
        base = self.env.get("DNS_SECURITY_CTLOGS_API_BASE", "https://api.ctlogs.dev").rstrip("/")
        try:
            parsed_base = urlsplit(base)
            safe_base = (
                parsed_base.scheme == "https"
                and parsed_base.hostname == "api.ctlogs.dev"
                and parsed_base.port in (None, 443)
                and parsed_base.username is None
                and parsed_base.password is None
                and parsed_base.path in ("", "/")
                and not parsed_base.query
                and not parsed_base.fragment
            )
        except ValueError:
            safe_base = False
        if not safe_base:
            self._errors.append("invalid_provider_url")
            return observations
        headers = {"Accept": "application/json"}
        token = self.env.get("DNS_SECURITY_CTLOGS_API_TOKEN", "").strip()
        if token:
            if len(token) > 512 or any(ord(char) < 33 or ord(char) > 126 for char in token):
                self._errors.append("invalid_api_token")
                return observations
            headers["Authorization"] = f"Bearer {token}"
        request_count = 0

        async def reserve_ctlogs_request() -> None:
            nonlocal request_count
            if request_count >= MAX_CTLOGS_REQUESTS_PER_SCAN:
                raise _RequestBudgetReached
            last_request = getattr(self, "_ctlogs_last_request_at", None)
            if last_request is not None:
                elapsed = time.monotonic() - last_request
                delay = CTLOGS_MIN_REQUEST_INTERVAL_SECONDS - elapsed
                if delay > 0:
                    await asyncio.sleep(delay)
            self._ctlogs_last_request_at = time.monotonic()
            request_count += 1

        async with httpx.AsyncClient(timeout=httpx.Timeout(25.0, connect=5.0), follow_redirects=False) as client:
            # Exact control checks have priority over potentially huge discovery.
            exact_evidence: set[tuple] = set()
            for domain in domains:
                if len(observations) >= MAX_OBSERVATIONS - 2:
                    self._errors.append("observation_limit_reached")
                    break
                check, evidence = await self._ct_exact_check(client, base, domain, headers, reserve_ctlogs_request)
                observations.append(check)
                if evidence:
                    observations.append(evidence)
                    exact_evidence.add((evidence["metadata"]["id"], domain, False))
            for domain in domains:
                if len(observations) >= MAX_OBSERVATIONS:
                    self._errors.append("observation_limit_reached")
                    break
                url = f"{base}/v1/subdomains/{quote(domain, safe='.-')}"
                cursor = None
                seen: set[tuple] = set(exact_evidence)
                cursors: set[str] = set()
                for _page in range(MAX_PAGES):
                    page_url = url if not cursor else f"{url}?after={quote(cursor, safe='')}"
                    payload, error, _ = await self._get_json(
                        client,
                        page_url,
                        headers=headers,
                        before_request=reserve_ctlogs_request,
                    )
                    if error == "request_budget_reached":
                        self._errors.append(error)
                        return observations[:MAX_OBSERVATIONS]
                    if error:
                        self._errors.append(error)
                        break
                    rows = payload.get("rows") if isinstance(payload, dict) else None
                    if not isinstance(rows, list):
                        self._errors.append("invalid_response")
                        break
                    for row in rows[:MAX_OBSERVATIONS]:
                        if not isinstance(row, dict):
                            continue
                        match = _text(row.get("match"), 255)
                        wildcard = match.startswith("*.")
                        host = _domain(match[2:] if wildcard else match)
                        if not _in_domain(host, domain):
                            self._errors.append("invalid_ct_hostname")
                            continue
                        cert_id = _text(row.get("id") or row.get("serial_hex"), 128)
                        identity = cert_id or hashlib.sha256(json.dumps(row, sort_keys=True, default=str).encode()).hexdigest()[:32]
                        row_key = (identity, host, wildcard)
                        if row_key in seen:
                            continue
                        seen.add(row_key)
                        raw_san_count = row.get("san_count")
                        san_count = int(raw_san_count) if isinstance(raw_san_count, int) or (isinstance(raw_san_count, str) and len(raw_san_count) <= 10 and raw_san_count.isdigit()) else 0
                        metadata = {"id": identity, "serial_hex": _text(row.get("serial_hex"), 128), "issuer": _text(row.get("issuer"), 200), "not_before": _text(row.get("not_before"), 64), "key_algo": _text(row.get("key_algo"), 64), "san_count": max(0, min(san_count, 10000)), "evidence": "certificate_transparency_historical_not_dns_proof", "source_domain": domain, "certificate_match": match, "wildcard": wildcard}
                        expires = _date(row.get("not_after"))
                        if row.get("not_after") and expires is None:
                            self._errors.append("invalid_expiry_date")
                        observations.append({"observation_type": "certificate", "subject": host, "record_type": None, "value": domain, "expires_at": expires, "status": "historical", "metadata": metadata})
                        if len(observations) >= MAX_OBSERVATIONS:
                            break
                    if len(observations) >= MAX_OBSERVATIONS:
                        self._errors.append("observation_limit_reached")
                        break
                    next_cursor = payload.get("next_cursor") if isinstance(payload, dict) else None
                    if not payload.get("has_next"):
                        break
                    if not isinstance(next_cursor, str) or not next_cursor:
                        self._errors.append("invalid_pagination")
                        break
                    if len(next_cursor) > 512 or next_cursor in cursors:
                        self._errors.append("invalid_pagination")
                        break
                    cursors.add(next_cursor)
                    cursor = next_cursor
                else:
                    self._errors.append("page_limit_reached")
                if len(observations) >= MAX_OBSERVATIONS:
                    break
        return observations[:MAX_OBSERVATIONS]

    async def _run_virustotal(self, domains: list[str]) -> list[dict]:
        key = self.env.get("DNS_SECURITY_VT_API_KEY", "").strip()
        if not key:
            self._errors.append("api_key_not_configured")
            return []
        if len(key) > 512 or any(ord(char) < 33 or ord(char) > 126 for char in key):
            self._errors.append("invalid_api_key")
            return []
        if self.env.get("DNS_SECURITY_VT_PUBLIC_NONCOMMERCIAL", "false").strip().lower() not in {"1", "true", "yes"}:
            self._errors.append("public_tier_noncommercial_ack_required")
            return []
        base = "https://www.virustotal.com/api/v3"
        observations: list[dict] = []
        seen: set[tuple] = set()
        request_count = 0

        async def reserve_virustotal_request() -> None:
            nonlocal request_count
            if request_count >= 500:
                raise _RequestBudgetReached
            await self.reserve_virustotal_request()
            request_count += 1

        async with httpx.AsyncClient(timeout=self._client_timeout, follow_redirects=False) as client:
            for domain in domains:
                endpoints = [
                    (f"/domains/{quote(domain, safe='.-')}/subdomains", "vt_subdomain"),
                    (f"/domains/{quote(domain, safe='.-')}/resolutions", "vt_resolution"),
                ]
                for path, kind in endpoints:
                    next_url = f"{base}{path}?limit=10"
                    visited: set[str] = set()
                    for _ in range(MAX_PAGES):
                        if next_url in visited:
                            self._errors.append("invalid_pagination")
                            break
                        visited.add(next_url)
                        payload, error, _ = await self._get_json(
                            client,
                            next_url,
                            headers={"x-apikey": key, "Accept": "application/json"},
                            before_request=reserve_virustotal_request,
                        )
                        if error == "request_budget_reached":
                            self._errors.append(error)
                            return observations[:MAX_OBSERVATIONS]
                        if error:
                            self._errors.append(error)
                            break
                        data = payload.get("data") if isinstance(payload, dict) else None
                        if not isinstance(data, list):
                            self._errors.append("invalid_response")
                            break
                        for item in data[:100]:
                            if not isinstance(item, dict):
                                continue
                            attributes = item.get("attributes") if isinstance(item.get("attributes"), dict) else {}
                            subject = _domain(item.get("id") if kind == "vt_subdomain" else attributes.get("ip_address"))
                            if kind == "vt_subdomain":
                                valid = item.get("type") == "domain" and _in_domain(subject, domain)
                            else:
                                try:
                                    ipaddress.ip_address(subject or "")
                                    valid = item.get("type") == "resolution" and _in_domain(_domain(attributes.get("host_name")), domain)
                                except ValueError:
                                    valid = False
                            if not valid:
                                self._errors.append("invalid_vt_record")
                                continue
                            identity = (kind, subject, domain, attributes.get("host_name") if kind == "vt_resolution" else None, str(attributes.get("date") or "") if kind == "vt_resolution" else None)
                            if identity in seen:
                                continue
                            seen.add(identity)
                            metadata = {
                                "evidence": "virustotal_passive_dns_or_enumeration",
                                "source_domain": domain,
                                "last_analysis_date": _text(str(attributes.get("last_analysis_date") or ""), 32),
                            }
                            if kind == "vt_resolution":
                                metadata.update({"host_name": _domain(attributes.get("host_name")), "resolution_date": _text(str(attributes.get("date") or ""), 32), "resolver": _text(attributes.get("resolver"), 100)})
                            else:
                                records = attributes.get("last_dns_records")
                                if isinstance(records, list):
                                    metadata["last_dns_records"] = [
                                        f"{_text(record.get('type'), 16)} {_text(record.get('value'), 200)}"
                                        for record in records[:20] if isinstance(record, dict)
                                    ]
                                certificate = attributes.get("last_https_certificate")
                                if isinstance(certificate, dict):
                                    validity = certificate.get("validity")
                                    if isinstance(validity, dict):
                                        metadata["certificate_not_after"] = _date(validity.get("not_after"))
                            observations.append({
                                "observation_type": kind,
                                "subject": subject,
                                "record_type": None,
                                "value": domain,
                                "status": "historical",
                                "metadata": metadata,
                            })
                            if len(observations) >= MAX_OBSERVATIONS:
                                break
                        links = payload.get("links") if isinstance(payload, dict) else None
                        next_page = links.get("next") if isinstance(links, dict) else None
                        if len(observations) >= MAX_OBSERVATIONS:
                            self._errors.append("observation_limit_reached")
                            break
                        if not next_page:
                            break
                        if not isinstance(next_page, str) or len(next_page) > 2048:
                            self._errors.append("invalid_pagination")
                            break
                        try:
                            parsed = urlsplit(next_page)
                            safe_next = (parsed.scheme == "https" and parsed.hostname == "www.virustotal.com"
                                         and parsed.port in (None, 443) and parsed.username is None and parsed.password is None
                                         and parsed.path == f"/api/v3{path}" and not parsed.fragment)
                        except ValueError:
                            safe_next = False
                        if not safe_next:
                            self._errors.append("invalid_pagination")
                            break
                        next_url = next_page
                    else:
                        self._errors.append("page_limit_reached")
                    if len(observations) >= MAX_OBSERVATIONS:
                        return observations[:MAX_OBSERVATIONS]
        return observations[:MAX_OBSERVATIONS]

    async def run_scan(self, work: dict) -> tuple[list[dict], dict]:
        self._errors = []
        domains = self._domains(work)
        if not domains:
            return [], {"status": "skipped", "reason": "no_valid_domain_assets", "source": self.SOURCE}
        try:
            if self.SOURCE == "rdap":
                observations = await self._run_rdap(domains)
            elif self.SOURCE == "resolver":
                observations = await self._run_resolver(domains)
            elif self.SOURCE == "ctlogs":
                observations = await self._run_ctlogs(domains)
            elif self.SOURCE == "virustotal":
                observations = await self._run_virustotal(domains)
            else:
                observations = []
        except Exception as exc:
            # Source failure stays local. It cannot turn another provider's
            # previous data into a deletion or fail sibling jobs.
            self._errors.append(type(exc).__name__)
            observations = []
            log.warning("dns_source_scan_failed", source=self.SOURCE, error=type(exc).__name__)
        if observations:
            await self.submit_observations(work["job_id"], observations)
        status = ("partial" if observations else "error") if self._errors else "success"
        return [], {"source": self.SOURCE, "domains_scanned": len(domains), "observations": len(observations), "provider_errors": sorted(set(self._errors)), "error_code": self._errors[0] if status == "error" else None, "status": status}

    async def submit_observations(self, job_id: str, observations: list[dict]) -> None:
        for start in range(0, len(observations), 50):
            batch = observations[start:start + 50]
            result = await self.submit_findings(job_id, batch)
            if result.get("rejected", 0) or result.get("accepted") != len(batch):
                raise RuntimeError("core_rejected_dns_observations")


class RDAPConnector(DNSConnector):
    SOURCE, NAME, JOB_TYPE = "rdap", "dns-rdap", "dns.rdap"


class ResolverConnector(DNSConnector):
    SOURCE, NAME, JOB_TYPE = "resolver", "dns-resolver", "dns.resolver"


class CTLogsConnector(DNSConnector):
    SOURCE, NAME, JOB_TYPE = "ctlogs", "dns-ctlogs", "dns.ctlogs"


class VirusTotalConnector(DNSConnector):
    SOURCE, NAME, JOB_TYPE = "virustotal", "dns-virustotal", "dns.virustotal"


def main() -> None:
    name = os.environ.get("CONNECTOR_NAME", "dns-rdap")
    connectors = {"dns-rdap": RDAPConnector, "dns-resolver": ResolverConnector, "dns-ctlogs": CTLogsConnector, "dns-virustotal": VirusTotalConnector}
    # Transitional: workers started with the pre-rename name keep working until their env is updated.
    connectors.update({f"{cls.SOURCE}-dns-security-default": cls for cls in (RDAPConnector, ResolverConnector, CTLogsConnector, VirusTotalConnector)})
    cls = connectors.get(name)
    if cls is None:
        raise RuntimeError("CONNECTOR_NAME must be one of the DNS Security worker names")
    cls().main()


if __name__ == "__main__":
    main()
