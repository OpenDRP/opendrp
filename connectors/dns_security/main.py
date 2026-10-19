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
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

import dns.resolver
import httpx
import structlog

from opendrp_connector import ConnectorBase
from opendrp_connector.base import ConnectorAPIError
from opendrp_connector.network import resolve_public_ips
from opendrp_connector.provider import ProviderClient, ProviderLimits
from tls_probe import (
    CONCURRENCY as TLS_PROBE_CONCURRENCY,
    DEFAULT_MAX_PROBES as DEFAULT_TLS_MAX_PROBES,
    MAX_MAX_PROBES as MAX_TLS_MAX_PROBES,
    build_argv,
    classify as classify_tls_probe,
    curl_version,
    parse_output as parse_curl_output,
    parse_path as parse_tls_path,
    parse_ports as parse_tls_ports,
    read_chain,
    run_curl,
    version_is_sufficient,
)
log = structlog.get_logger()

MAX_DOMAINS = 1000
MAX_OBSERVATIONS = 500
MAX_PAGES = 10
MAX_RESPONSE_BYTES = 2_000_000
MAX_RETRIES = 3
#: The keyless tier of ``api.ctlogs.dev`` allows 100 requests per hour with one
#: request in flight, which is where the default pacing comes from. A keyed plan
#: raises that ceiling, so both numbers are operator settings: a worker paced
#: slower than its tier allows spends the whole scan budget on the first domains
#: of the inventory and leaves the tail unverified (F-02 in the DNS & TLS audit).
DEFAULT_CTLOGS_MAX_REQUESTS_PER_SCAN = 100
DEFAULT_CTLOGS_MIN_REQUEST_INTERVAL_SECONDS = 36.0
MAX_CTLOGS_MAX_REQUESTS_PER_SCAN = 10_000


class _RequestBudgetReached(Exception):
    pass
def _text(raw: object, limit: int) -> str:
    if not isinstance(raw, str):
        return ""
    return re.sub(r"[\x00\r\n]", "", raw).strip()[:limit]


#: RDAP reports EPP statuses as prose (``client transfer prohibited``) while some
#: registries answer in camel case (``clientTransferProhibited``). Only the punctuation
#: and case differ, so one canonical token is stored and the core's registration rule
#: compares values instead of spellings.
_EPP_STATUS_STRIP = re.compile(r"[^a-z0-9]")
MAX_EPP_STATUSES = 20


def _vt_reputation(attributes: dict) -> dict:
    """The reputation facts VirusTotal reports for a domain or a discovered host.

    These were read for the discovery passes only as far as the certificate's expiry,
    so a subdomain the provider *itself* scores malicious was stored as an ordinary
    discovery row (F-09 in the DNS & TLS audit). Statistics, reputation, vendor
    categories and the served certificate's fingerprint all belong in the evidence,
    and a row the provider flags carries `suspicious` so a reader of the row does not
    have to re-query the provider to notice.
    """
    metadata: dict = {}
    stats = attributes.get("last_analysis_stats")
    if isinstance(stats, dict):
        for key in ("malicious", "suspicious", "harmless", "undetected", "timeout"):
            value = stats.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 10_000_000:
                metadata[f"analysis_{key}"] = value
    reputation = attributes.get("reputation")
    if isinstance(reputation, int) and not isinstance(reputation, bool) and -10_000_000 <= reputation <= 10_000_000:
        metadata["reputation"] = reputation
    categories = attributes.get("categories")
    if isinstance(categories, dict):
        flattened = sorted(
            f"{_text(vendor, 32)}: {_text(category, 64)}"
            for vendor, category in list(categories.items())[:50]
            if isinstance(vendor, str) and isinstance(category, str)
        )
        if flattened:
            metadata["categories"] = [item for item in flattened if item != ": "][:50]
    certificate = attributes.get("last_https_certificate")
    if isinstance(certificate, dict):
        fingerprint = certificate.get("fingerprint")
        if isinstance(fingerprint, dict) and _text(fingerprint.get("sha256"), 128):
            metadata["certificate_fingerprint_sha256"] = _text(fingerprint["sha256"], 128).lower()
        validity = certificate.get("validity")
        if isinstance(validity, dict):
            if _date(validity.get("not_before")):
                metadata["certificate_not_before"] = _date(validity["not_before"])
            if _date(validity.get("not_after")):
                metadata["certificate_not_after"] = _date(validity["not_after"])
    if metadata.get("analysis_malicious") or metadata.get("analysis_suspicious"):
        metadata["suspicious"] = True
    return metadata


def _epp_statuses(raw: object) -> list[str] | None:
    """The registration's EPP statuses as canonical tokens, or None if not answered.

    ``None`` and ``[]`` are deliberately different: an answer that carried no
    ``status`` member says nothing about the registration, while an empty list is a
    registry stating the domain holds no status at all - and losing a lock the domain
    previously had is exactly the transition worth reporting.
    """
    if not isinstance(raw, list):
        return None
    tokens = {_EPP_STATUS_STRIP.sub("", _text(item, 64).lower()) for item in raw[:50] if isinstance(item, str)}
    return sorted(token for token in tokens if token)[:MAX_EPP_STATUSES]


def _date(raw: object) -> str | None:
    if not isinstance(raw, str) or len(raw) > 64:
        return None
    try:
        value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return (value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value).isoformat()
    except ValueError:
        return None


def _env_int(env: dict, name: str, default: int, low: int, high: int) -> int:
    """A bounded integer setting; an unusable value falls back to the default."""
    try:
        value = int(str(env.get(name, "")).strip())
    except (TypeError, ValueError):
        return default
    return value if low <= value <= high else default


def _env_float(env: dict, name: str, default: float, low: float, high: float) -> float:
    """The same for a duration in seconds."""
    try:
        value = float(str(env.get(name, "")).strip())
    except (TypeError, ValueError):
        return default
    return value if low <= value <= high else default


def _ct_history_window(payload: dict) -> tuple[int | None, bool]:
    """What the certificate provider says about the history it searched.

    ``api.ctlogs.dev`` reports the window it covers and whether that window is
    the domain's whole history. Without both facts an empty result cannot be told
    apart from "this domain has no certificate", which is how a truncated window
    became a clean result an operator would trust (F-03 in the audit).
    """
    days = payload.get("history_window_days")
    if isinstance(days, bool) or not isinstance(days, int) or not 0 <= days <= 36_500:
        days = None
    return days, payload.get("history_truncated") is True


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


#: Shodan's two answers, and why this worker prices them differently.
#:
#: The host lookup (``/shodan/host/{ip}``) is free and rate limited to about one request
#: per second, and the host search spends one *query credit* per request (100 per month
#: on a free plan). A live spike on 2026-10-15 confirmed both shapes and one trap: a
#: lookup document carries its services under ``data[]`` with
#: ``ssl.cert.fingerprint.sha256``/``sha1``, ``ssl.jarm``, ``http.title`` and
#: ``http.favicon.hash``, the search filter that matches is ``ssl.cert.fingerprint``
#: with the *SHA-1* value, and the plausible-looking ``ssl.cert.fingerprint.sha256``
#: filter is accepted by the API and matches nothing. The SHA-1 is therefore what is
#: searched and the SHA-256 stays the certificate identity.
SHODAN_API_BASE = "https://api.shodan.io"
#: Addresses one scan asks about. A larger inventory reports ``address_limit_reached``
#: instead of quietly checking the head of the list.
MAX_SHODAN_ADDRESSES = 200
#: Service banners read from one host document, and matches kept from one search page.
MAX_SHODAN_SERVICES = 20
MAX_SHODAN_MATCHES = 100
#: Shodan's useful limit is query credits, not HTTP requests, and the free tier answers
#: roughly one request per second.
DEFAULT_SHODAN_MIN_REQUEST_INTERVAL_SECONDS = 1.1
MAX_SHODAN_SEARCH_VALUE = 80

#: Per-scan capabilities and their bounds, in the shape the registry renders as the
#: connector's configuration form. The defaults are a deliberate arithmetic: one search
#: request per scan is one query credit, which keeps a weekly schedule at roughly four
#: credits a month against a free plan's hundred, and 25 host lookups is what a small
#: inventory of domains resolves to. Setting ``max_searches`` to zero switches the
#: credit-spending half off without giving up the free confirmation.
SHODAN_POLICY = {
    "max_host_lookups": (0, 500, 25),
    "max_searches": (0, 20, 1),
}


def _shodan_when(value: object) -> str | None:
    """Shodan's certificate timestamps (``20260918200229Z``) as an ISO instant."""
    if not isinstance(value, str) or len(value) != 15 or not value.endswith("Z"):
        return None
    try:
        moment = datetime.strptime(value, "%Y%m%d%H%M%SZ")
    except ValueError:
        return None
    return moment.replace(tzinfo=timezone.utc).isoformat()


def _shodan_dn(value: object) -> str | None:
    """Shodan's ``{C: US, CN: ...}`` name as the single string the core stores."""
    if not isinstance(value, dict):
        return None
    rendered = [
        f"{key}={_text(item, 200)}"
        for key, item in sorted(value.items())
        if isinstance(key, str) and isinstance(item, str) and _text(item, 200)
    ]
    return ", ".join(rendered)[:1000] or None


def _shodan_asn(value: object) -> int | None:
    """``AS15169``, ``15169`` or an integer as the number, or nothing at all."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        digits = value.strip().upper().removeprefix("AS")
        if not digits.isdecimal():
            return None
        number = int(digits)
    else:
        return None
    return number if 0 <= number <= 4_294_967_295 else None


def _shodan_hex(value: object, length: int) -> str | None:
    """A certificate fingerprint as lowercase hex of the expected width, or nothing."""
    if not isinstance(value, str):
        return None
    candidate = value.strip().lower()
    return candidate if re.fullmatch(rf"[0-9a-f]{{{length}}}", candidate) else None


def _shodan_serial(value: object) -> tuple[str | None, str | None]:
    """The certificate serial as ``(hex, decimal)``, as far as it converts.

    Shodan reports the serial in decimal and its ``ssl.cert.serial`` filter takes that
    spelling, while the core's identity facts are hex. Both spellings are kept for that
    reason, and a value that is not a plain bounded integer is dropped rather than
    stored as if it were a number.
    """
    if not isinstance(value, str):
        return None, None
    digits = value.strip()
    if not digits.isdecimal() or len(digits) > MAX_SHODAN_SEARCH_VALUE:
        return None, None
    return format(int(digits), "x")[:128], digits


def _shodan_san_names(certificate: dict) -> list[str]:
    """The names in the certificate's subjectAltName extension, if it lists any.

    Shodan reports extensions as ``[{"name": ..., "data": ...}]`` and nowhere else,
    so an extension list without that entry is the same answer as no list at all: no
    SAN names known, never a guessed one.
    """
    extensions = certificate.get("extensions")
    if not isinstance(extensions, list):
        return []
    for entry in extensions[:50]:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("name") or "").strip().lower() not in {"subjectaltname", "subject alternative name"}:
            continue
        data = _text(entry.get("data"), 4000)
        if not data:
            continue
        names: list[str] = []
        for item in data.split(",")[:100]:
            candidate = item.strip()
            if not candidate.upper().startswith("DNS:"):
                continue
            name = _domain(candidate.split(":", 1)[1].strip().removeprefix("*."))
            if name and name not in names:
                names.append(name)
        return names
    return []


def _shodan_services(document: dict) -> list[dict]:
    """The service banners of a host document, bounded, and one row per port.

    A host lookup answers with one entry per open service under ``data[]``, while a
    search match *is* such an entry. Both shapes are read the same way, so one
    normalization serves the free answer and the credit-spending one.
    """
    entries = document.get("data")
    services = [entry for entry in entries if isinstance(entry, dict)] if isinstance(entries, list) else []
    if not services and (isinstance(document.get("ssl"), dict) or isinstance(document.get("http"), dict)):
        services = [document]
    bounded: list[dict] = []
    seen: set[int] = set()
    for entry in services:
        port = entry.get("port")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            port = 0
        if port in seen:
            continue
        seen.add(port)
        bounded.append(entry)
        if len(bounded) >= MAX_SHODAN_SERVICES:
            break
    return bounded


def _shodan_signals(*documents: dict) -> dict:
    """The facts the scoring rules read, from the first document that carries each.

    ``title``/``http_title`` and ``favicon_hash``/``http_favicon_hash`` are written as
    one value under both spellings on purpose: R4 compares the *same* key on both sides
    of the echo, and the source that reports the other side uses whichever spelling its
    provider does, so a single spelling would leave half the comparisons empty.
    """
    signals: dict = {}
    for document in documents:
        if not isinstance(document, dict):
            continue
        org = _text(document.get("org"), 200)
        if org and "org" not in signals:
            signals["org"] = org
        asn = _shodan_asn(document.get("asn"))
        if asn is not None and "asn" not in signals:
            signals["asn"] = asn
    for document in documents:
        if not isinstance(document, dict):
            continue
        ssl = document.get("ssl") if isinstance(document.get("ssl"), dict) else {}
        jarm = _text(ssl.get("jarm"), 120) if ssl else None
        if jarm and "jarm" not in signals:
            signals["jarm"] = jarm
        http = document.get("http") if isinstance(document.get("http"), dict) else {}
        title = _text(http.get("title"), 200) if http else None
        if title and "title" not in signals:
            signals["title"] = title
            signals["http_title"] = title
        favicon = http.get("favicon") if http else None
        hash_value = favicon.get("hash") if isinstance(favicon, dict) else None
        if isinstance(hash_value, int) and not isinstance(hash_value, bool) and "favicon_hash" not in signals:
            signals["favicon_hash"] = hash_value
            signals["http_favicon_hash"] = hash_value
    return signals


def _shodan_certificate_facts(document: dict) -> dict:
    """The certificate facts an identity is built from, or an empty mapping.

    An empty mapping is the honest answer for a host that serves no certificate the
    provider indexed: without a fingerprint there is no identity to attach, and a
    half-filled identity would be worse than none.
    """
    ssl = document.get("ssl") if isinstance(document.get("ssl"), dict) else None
    certificate = ssl.get("cert") if isinstance(ssl, dict) and isinstance(ssl.get("cert"), dict) else None
    if not isinstance(certificate, dict):
        return {}
    fingerprint = certificate.get("fingerprint") if isinstance(certificate.get("fingerprint"), dict) else {}
    facts: dict = {}
    sha256 = _shodan_hex(fingerprint.get("sha256"), 64)
    if sha256:
        facts["fingerprint_sha256"] = sha256
        facts["id"] = sha256
    sha1 = _shodan_hex(fingerprint.get("sha1"), 40)
    if sha1:
        facts["fingerprint_sha1"] = sha1
    serial_hex, serial_decimal = _shodan_serial(certificate.get("serial"))
    if serial_hex:
        facts["serial_hex"] = serial_hex
    if serial_decimal:
        facts["serial_decimal"] = serial_decimal
    subject_dn = _shodan_dn(certificate.get("subject"))
    if subject_dn:
        facts["subject_dn"] = subject_dn
    issuer_dn = _shodan_dn(certificate.get("issuer"))
    if issuer_dn:
        facts["issuer_dn"] = issuer_dn
    not_before = _shodan_when(certificate.get("issued"))
    if not_before:
        facts["not_before"] = not_before
    not_after = _shodan_when(certificate.get("expires"))
    if not_after:
        facts["not_after"] = not_after
    san_dns = _shodan_san_names(certificate)
    if san_dns:
        facts["san_dns"] = san_dns
    return facts


#: Findings are submitted while the scan progresses, so an operator watching a
#: long sweep sees it move; 50 is deliberately below the SDK default of 500 and
#: buys nothing else. See connectors/README.md.
SUBMIT_BATCH = 50


class DNSConnector(ConnectorBase):
    SOURCE = ""
    BASE_URL = ""
    JOB_TYPE = ""
    NAME = ""
    #: Whether this worker's target list may come from monitored ``ip_address`` assets
    #: as well as from domains. The core queues both sections to every job; a worker
    #: that only understands domains must not treat an address-only inventory as work
    #: it can do.
    TARGETS_ADDRESSES = False
    #: Declared per source in the readiness overrides below: the two provider-backed
    #: sources advertise different things, so a single class-level tuple would have to
    #: lie about one of them.
    CAPABILITIES = ()
    OPERATIONS = ()

    def __init__(self):
        super().__init__()
        self._errors: list[str] = []
        self._client_timeout = httpx.Timeout(15.0, connect=5.0)
        #: Counters a source adds to the job summary beyond the shared ones.
        self._scan_facts: dict = {}

    async def register(self):
        await super().register()
        # The payload is the SDK's: one shape for every worker, built from the
        # overrides below rather than spelled out again here. Every source declares,
        # including the compute-only ones, so "no key needed" and "key missing" are
        # not the same sentence in the row.
        await self.report_readiness()

    def readiness_capabilities(self) -> list[str]:
        """What this source can be asked about, in the core's vocabulary.

        ``ip`` and ``hostname`` are both declared because admission needs one
        capability per asset type the worker accepts.
        """
        if self.SOURCE == "shodan":
            return ["certificate", "hostname", "ip", "title", "favicon", "lookup"]
        if self.SOURCE == "virustotal":
            return ["hostname", "lookup"]
        # Resolver, CT and TLS-probe scans read public data: no provider key, no
        # paid lookup capability to promise.
        return ["hostname"]

    def readiness_operations(self) -> list[str]:
        """The provider quota buckets this source may reserve against.

        Only the metered sources declare one; a compute-only scan that named a bucket
        would claim a budget it never spends.
        """
        if self.SOURCE == "shodan":
            return ["lookup", "search"]
        if self.SOURCE == "virustotal":
            return ["lookup"]
        return []

    def credentials_configured(self) -> bool:
        """Whether this worker has a provider key from its environment.

        A key stored in the core is fetched at scan time and is not visible here, so an
        absent variable is not proof that no key exists; the readiness row is refreshed
        after every credential read for exactly that reason.
        """
        name = {"virustotal": "DNS_SECURITY_VT_API_KEY", "shodan": "SHODAN_API_KEY"}.get(self.SOURCE, "")
        return bool(name and self.env.get(name, "").strip())

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

    def _addresses(self, work: dict) -> list[str]:
        """The addresses the core queues alongside the domains, or nothing.

        The core sends the monitored ``ip_address`` assets as ``ips`` to every job, so a
        worker that can answer about an address is not told which ones to use. A value
        that is not an address never becomes a provider request: the platform has to
        recognise a target itself before this worker asks a third party about it.
        """
        raw = (work.get("params") or {}).get("ips") or []
        values: list[str] = []
        for item in raw[:MAX_SHODAN_ADDRESSES] if isinstance(raw, list) else []:
            try:
                candidate = str(ipaddress.ip_address(str(item).strip()))
            except ValueError:
                continue
            if candidate not in values:
                values.append(candidate)
        return values

    def _provider_limits(self) -> ProviderLimits:
        """This worker's numbers for one provider call, stated rather than inherited.

        They are the constants this connector retried with before the shared client
        existed: ``MAX_RETRIES`` + 1 attempts, a local backoff of ``2 ** attempt``,
        and a ``Retry-After`` above sixty seconds abandoned as
        ``http_<status>_retry_later`` rather than waited out inside a scan.

        The retry ceiling is sixty because that is the *hint* ceiling: a provider
        asking for twenty seconds is waited out for twenty, exactly as before. The
        local backoff never reaches it (``2 ** 3`` is eight), so one constant keeps
        both halves of the old behaviour and the shared default of thirty would
        have quietly shortened a legitimate hint.

        The body bound is read here, at call time, rather than baked into a
        class attribute: it is the number under test, and a test lowering
        ``MAX_RESPONSE_BYTES`` is asserting the bound rather than the value.
        """
        return ProviderLimits(
            max_attempts=MAX_RETRIES + 1,
            max_retry_delay=60.0,
            max_response_bytes=MAX_RESPONSE_BYTES,
            abort_when_retry_after_exceeds=60.0,
        )

    async def _get_json(
        self,
        client: httpx.AsyncClient,
        url: str,
        *,
        headers: dict | None = None,
        params: dict | None = None,
        before_request=None,
        extensions: dict | None = None,
    ) -> tuple[dict | list | None, str | None, httpx.Response | None]:
        """Fetch bounded JSON, invoking the reservation hook before every wire attempt.

        The pace, the reservation, the retry loop, ``Retry-After`` and the body bound
        are :class:`ProviderClient`'s; what stays here is the shape every call site in
        this worker reads — the payload, the name of the failure, and the response,
        which the RDAP bootstrap needs for its ``Location`` header.

        ``before_request`` becomes the client's reservation, so a hook that raises
        (this scan's own request budget) arrives as "no call was made" instead of a
        provider failure: nothing is sent, nothing is retried, and the check reports
        ``request_budget_reached``. The ceiling stays the caller's: it is read off the
        client it built, because this one worker runs clients with three different
        timeouts (15s for RDAP and VirusTotal, 25s for CT logs, and Shodan's own
        operator setting), and one shared number would change two of them.

        ``extensions`` carries what only this connection knows (the SNI name for an
        address-pinned RDAP request) to the shared client rather than around it.
        """
        provider = ProviderClient(
            http=client,
            limits=self._provider_limits(),
            reserve=before_request,
        )
        try:
            result = await provider.get_json(
                url,
                headers=headers,
                params=params,
                timeout=getattr(client, "timeout", None),
                extensions=extensions,
            )
        except _RequestBudgetReached:
            return None, "request_budget_reached", None
        return result.payload, result.outcome, result.response

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
                # rdap.org is the only bootstrap this worker uses; the registry host
                # it redirects to is resolved and pinned inside the lookup.
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
                statuses = _epp_statuses(payload.get("status"))
                if statuses is not None:
                    metadata["epp_status"] = statuses
                secure_dns = payload.get("secureDNS")
                if isinstance(secure_dns, dict) and isinstance(secure_dns.get("delegationSigned"), bool):
                    metadata["secure_dns"] = secure_dns["delegationSigned"]
                observations.append({"observation_type": "rdap", "subject": domain, "record_type": "RDAP", "value": domain, "expires_at": expires_at, "metadata": metadata})
                if len(observations) >= MAX_OBSERVATIONS:
                    self._errors.append("observation_limit_reached")
                    return observations
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
        extended = self.env.get("DNS_SECURITY_RESOLVER_EXTENDED", "false").lower() in {"1", "true", "yes"}
        if extended:
            record_types.extend(["NS", "MX", "CAA", "TXT"])
        for domain in domains:
            targets = [(domain, record_type) for record_type in record_types]
            if extended:
                # Mail authorization lives in TXT: the domain's own record carries SPF,
                # and the policy for it is published at `_dmarc.<domain>` (F-08 in the
                # DNS & TLS audit). Both are stored as ordinary RRsets under the name
                # that holds them, so a change is the R4 event like any other record,
                # and `source_domain` keeps the row linked to the asset we were asked
                # to scan rather than to the underscore-prefixed name.
                targets.append((f"_dmarc.{domain}", "TXT"))
            for name, record_type in targets:
                try:
                    answer = await asyncio.to_thread(resolver.resolve, name, record_type, raise_on_no_answer=False)
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
                    observations.append({"observation_type": "dns_record", "subject": name, "record_type": record_type, "value": "; ".join(values)[:1000], "expires_at": expiry, "metadata": {"ttl": ttl, "record_values": values, "source_domain": domain}})
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
        window_days: int | None = None
        truncated = False
        for _ in range(MAX_PAGES):
            url = f"{base}/v1/domain/{quote(domain, safe='.-')}"
            if cursor:
                url += f"?after={quote(cursor, safe='')}"
            payload, error, _response = await self._get_json(client, url, headers=headers, before_request=reserve)
            if error:
                self._errors.append(error)
                # Our own per-scan budget is not a provider failure: the check never
                # ran, so the honest state is "incomplete" and the monitor keeps the
                # evidence it already had instead of recording a failure (F-02).
                state = "incomplete" if error == "request_budget_reached" else "failed"
                break
            rows = payload.get("rows") if isinstance(payload, dict) else None
            if not isinstance(rows, list) or len(rows) > 100:
                self._errors.append("invalid_response")
                state = "failed"
                break
            reported_days, reported_truncated = _ct_history_window(payload)
            window_days = reported_days if reported_days is not None else window_days
            truncated = truncated or reported_truncated
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
                if candidates:
                    state = "verified"
                elif future:
                    state = "future_only"
                elif truncated:
                    # The provider searched only part of this domain's history, so an
                    # empty page is an admission of blindness rather than a clean
                    # result: "incomplete" is the state that never alerts (F-03).
                    self._errors.append("history_window_truncated")
                    state = "incomplete"
                else:
                    state = "no_certificate"
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
        metadata = {"check_state": state, "source_domain": domain, "lookup": "exact", "checked_at": now.isoformat(), "history_truncated": truncated}
        if window_days is not None:
            metadata["history_window_days"] = window_days
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
        if not token and self.env.get("DNS_SECURITY_CTLOGS_PUBLIC_NONCOMMERCIAL", "false").strip().lower() not in {"1", "true", "yes"}:
            # This provider restricts keyless and free use to non-commercial
            # purposes; the paid plan is what the token means. Until the operator
            # says which one they are on, the worker does not call the API - the
            # same acknowledgement the VirusTotal worker already requires (F-06).
            self._errors.append("public_tier_noncommercial_ack_required")
            return observations
        if token:
            if len(token) > 512 or any(ord(char) < 33 or ord(char) > 126 for char in token):
                self._errors.append("invalid_api_token")
                return observations
            headers["Authorization"] = f"Bearer {token}"
        max_requests = _env_int(
            self.env, "DNS_SECURITY_CTLOGS_MAX_REQUESTS_PER_SCAN",
            DEFAULT_CTLOGS_MAX_REQUESTS_PER_SCAN, 1, MAX_CTLOGS_MAX_REQUESTS_PER_SCAN,
        )
        min_interval = _env_float(
            self.env, "DNS_SECURITY_CTLOGS_MIN_REQUEST_INTERVAL_SECONDS",
            DEFAULT_CTLOGS_MIN_REQUEST_INTERVAL_SECONDS, 0.0, 3600.0,
        )
        request_count = 0

        async def reserve_ctlogs_request() -> None:
            nonlocal request_count
            if request_count >= max_requests:
                raise _RequestBudgetReached
            last_request = getattr(self, "_ctlogs_last_request_at", None)
            if last_request is not None:
                elapsed = time.monotonic() - last_request
                delay = min_interval - elapsed
                if delay > 0:
                    await asyncio.sleep(delay)
            self._ctlogs_last_request_at = time.monotonic()
            request_count += 1

        async with httpx.AsyncClient(timeout=httpx.Timeout(25.0, connect=5.0), follow_redirects=False) as client:
            # Exact control checks have priority over potentially huge discovery.
            exact_evidence: set[tuple] = set()
            # The budget buys fewer exact checks than a large inventory has domains,
            # so each scan starts where the previous one stopped. Without this the
            # same head of the list consumes every scan and the tail's monitors age
            # out in silence (F-02). The cursor is process-local on purpose: it is a
            # fairness device, not state any other worker could be handed.
            start = int(getattr(self, "_ctlogs_exact_start", 0) or 0) % len(domains)
            covered = 0
            for offset in range(len(domains)):
                if len(observations) >= MAX_OBSERVATIONS - 2:
                    self._errors.append("observation_limit_reached")
                    break
                domain = domains[(start + offset) % len(domains)]
                spent_before = request_count
                check, evidence = await self._ct_exact_check(client, base, domain, headers, reserve_ctlogs_request)
                if request_count > spent_before:
                    covered += 1
                observations.append(check)
                if evidence:
                    observations.append(evidence)
                    exact_evidence.add((evidence["metadata"]["id"], domain, False))
            # Next scan picks up where this one really stopped, not at the top of the
            # list: a domain whose request the budget refused was not checked.
            self._ctlogs_exact_start = (start + covered) % len(domains)
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
                # The domain's own record first: one request, no pagination, and it is the
                # only place the provider's reputation, its vendor categories and the
                # certificate it currently serves are reported for the monitored name
                # (F-09 in the DNS & TLS audit).
                domain_payload, domain_error, _ = await self._get_json(
                    client,
                    f"{base}/domains/{quote(domain, safe='.-')}",
                    headers={"x-apikey": key, "Accept": "application/json"},
                    before_request=reserve_virustotal_request,
                )
                if domain_error == "request_budget_reached":
                    self._errors.append(domain_error)
                    return observations[:MAX_OBSERVATIONS]
                if domain_error:
                    self._errors.append(domain_error)
                else:
                    domain_data = domain_payload.get("data") if isinstance(domain_payload, dict) else None
                    domain_attributes = domain_data.get("attributes") if isinstance(domain_data, dict) else None
                    if not isinstance(domain_data, dict) or domain_data.get("type") != "domain" or not isinstance(domain_attributes, dict):
                        self._errors.append("invalid_vt_record")
                    else:
                        observations.append({
                            "observation_type": "vt_domain",
                            "subject": domain,
                            "record_type": None,
                            "value": domain,
                            "status": "current",
                            "metadata": {
                                "evidence": "virustotal_domain_reputation",
                                "source_domain": domain,
                                "last_analysis_date": _text(str(domain_attributes.get("last_analysis_date") or ""), 32),
                                **_vt_reputation(domain_attributes),
                            },
                        })
                        if len(observations) >= MAX_OBSERVATIONS:
                            self._errors.append("observation_limit_reached")
                            return observations[:MAX_OBSERVATIONS]
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
                                # A discovered subdomain the provider scores malicious is
                                # evidence about our own name space, not a footnote.
                                **_vt_reputation(attributes),
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

    # ------------------------------------------------------------------
    # Shodan: our own addresses for free, a found certificate once
    # ------------------------------------------------------------------

    def _shodan_policy(self, work: dict) -> dict | None:
        """The bounded per-scan capabilities, or ``None`` after recording why not.

        The registry's saved configuration wins over the defaults, exactly like every
        other capability switch: a value outside its declared range is refused rather
        than clamped, because a scan that silently spends more than its operator asked
        for is the failure this budget exists to prevent.
        """
        config = work.get("config") if isinstance(work.get("config"), dict) else {}
        policy: dict = {}
        for key, (low, high, default) in SHODAN_POLICY.items():
            value = config.get(key, default)
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                self._errors.append("invalid_scan_policy")
                return None
            policy[key] = value
        return policy

    async def _shodan_api_key(self) -> str:
        """This account's Shodan key: the core's copy first, the environment second.

        The key an operator stored for the source account is the one the quota is drawn
        from, so it wins over a value left in the worker's environment. The read is
        audited by the core (``connector.credential.read``) and never logged here. A key
        that is absent, oversized or not printable is refused instead of sent.
        """
        try:
            payload = (await self._request("GET", "/api/v1/connectors/me/credential")).json()
        except (ConnectorAPIError, ValueError):
            payload = {}
        candidate = payload.get("api_key") if isinstance(payload, dict) and payload.get("configured") is True else None
        if isinstance(candidate, str) and candidate.strip():
            self.env["SHODAN_API_KEY"] = candidate.strip()
        key = self.env.get("SHODAN_API_KEY", "").strip()
        if not key or len(key) > 512 or any(ord(char) < 33 or ord(char) > 126 for char in key):
            return ""
        return key

    async def _shodan_pace(self, min_interval: float) -> None:
        """Keep sequential provider requests inside the plan's request rate."""
        last = getattr(self, "_shodan_last_request_at", None)
        if last is not None:
            delay = min_interval - (time.monotonic() - last)
            if delay > 0:
                await asyncio.sleep(delay)
        self._shodan_last_request_at = time.monotonic()

    async def _shodan_targets(self, work: dict, domains: list[str]) -> list[tuple[str, str]]:
        """The ``(name, address)`` pairs this scan asks about.

        Only addresses the platform itself names: the ones our monitored domains resolve
        to right now, and the ``ip_address`` assets an operator registered. Nothing a
        provider reported is fed back to the provider from here, so a lookup is always
        evidence about our own service rather than a follow-up about somebody else's -
        which is also what lets the core read a host lookup as a fact about us.
        """
        targets: list[tuple[str, str]] = []
        seen: set[str] = set()
        for domain in domains:
            addresses = await asyncio.to_thread(resolve_public_ips, domain)
            if not addresses:
                # An unresolvable or non-public name is not an address this worker has
                # anything to ask about; saying so is better than a silent skip an
                # operator would read as "checked and clean".
                self._errors.append("no_public_address")
                continue
            for address in addresses:
                if address in seen:
                    continue
                seen.add(address)
                targets.append((domain, address))
        for address in self._addresses(work):
            if address in seen:
                continue
            seen.add(address)
            targets.append((address, address))
        if len(targets) > MAX_SHODAN_ADDRESSES:
            self._errors.append("address_limit_reached")
            targets = targets[:MAX_SHODAN_ADDRESSES]
        return targets

    def _shodan_lookup_observations(
        self, *, subject: str, address: str, document: dict, checked_at: datetime
    ) -> tuple[list[dict], list[tuple[str, str, str, str]]]:
        """The rows one host lookup contributes, and the certificates to ask about.

        One row per service that carries a certificate, which is what becomes a sighting
        at this address, plus one row for the address itself when the provider's index
        knows it but indexes no certificate there - so "the provider has nothing on this
        address" is visible instead of reading as a clean scan.
        """
        hostnames = [
            item for item in (_text(entry, 253) for entry in (document.get("hostnames") or [])[:20] if isinstance(entry, str)) if item
        ]
        ports = sorted({
            port for port in (document.get("ports") or [])
            if isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535
        })
        common = {
            "evidence": "shodan_host_lookup",
            "lookup": "host_lookup",
            "source_domain": subject,
            "ip": address,
            # What the free endpoint answered: this address, and the certificate it
            # serves according to an index we did not collect ourselves.
            "host_lookup_confirmed": True,
            "checked_at": checked_at.isoformat(),
            # The provider observed the address at its own moment, which is not when we
            # read the record: `checked_at` is the read, this is the index's own time.
            "provider_last_update": _text(document.get("last_update"), 64),
            "hostnames": hostnames,
            "open_ports": ports,
        }
        rows: list[dict] = []
        discovered: list[tuple[str, str, str, str]] = []
        for service in _shodan_services(document):
            facts = _shodan_certificate_facts(service)
            if not facts.get("fingerprint_sha256"):
                # A service the index saw without a certificate has no identity to
                # attach, and an identity-less row scores nothing: the address row below
                # is where the operator reads that fact.
                continue
            port = service.get("port") if isinstance(service.get("port"), int) and not isinstance(service.get("port"), bool) else None
            rows.append({
                "observation_type": "host_lookup",
                "subject": subject,
                "record_type": f"TLS:{port}" if port else "TLS",
                "value": address,
                "expires_at": facts.get("not_after"),
                "status": "historical",
                "metadata": {
                    **common,
                    **facts,
                    **_shodan_signals(document, service),
                    **(
                        {"port": port, "transport": _text(service.get("transport"), 16)}
                        if port
                        else {}
                    ),
                },
            })
            if facts.get("fingerprint_sha1"):
                discovered.append((
                    subject,
                    facts["fingerprint_sha256"],
                    facts["fingerprint_sha1"],
                    facts.get("serial_decimal") or "",
                ))
        if not rows:
            rows.append({
                "observation_type": "host_lookup",
                "subject": subject,
                "record_type": "HOST",
                "value": address,
                "status": "historical",
                "metadata": {**common, "check_state": "no_certificate"},
            })
        return rows, discovered

    def _shodan_response_observations(
        self, *, subject: str, fingerprint_sha256: str, matches: list[dict]
    ) -> list[dict]:
        """Where the searched certificate is served, one row per endpoint reported.

        Our own endpoint is in this answer too and is deliberately kept: whether an
        address is ours is the platform's decision (a verified probe, a monitored
        ``ip_address`` asset), and a worker that filtered the answer here would hide the
        copy it cannot name.
        """
        rows: list[dict] = []
        for match in matches:
            raw_address = _text(match.get("ip_str") or match.get("ip"), 64)
            try:
                address = str(ipaddress.ip_address(raw_address)) if raw_address else None
            except ValueError:
                address = None
            if address is None:
                self._errors.append("invalid_response_endpoint")
                continue
            name = next(
                (candidate for candidate in (_domain(entry) for entry in (match.get("hostnames") or [])[:20]) if candidate),
                None,
            ) or address
            port = match.get("port") if isinstance(match.get("port"), int) and not isinstance(match.get("port"), bool) else None
            if port is not None and not 1 <= port <= 65535:
                port = None
            facts = _shodan_certificate_facts(match)
            if not facts.get("fingerprint_sha256"):
                # The index answered the filter without repeating the certificate's
                # SHA-256. The identity we searched for is the one this endpoint serves
                # according to the provider's own match, and `matched_by` says so.
                facts = {"fingerprint_sha256": fingerprint_sha256, "id": fingerprint_sha256}
            rows.append({
                "observation_type": "certificate_response",
                "subject": name,
                "record_type": "TLS",
                "value": f"https://{name}:{port}" if port else f"https://{name}",
                "expires_at": facts.get("not_after"),
                "status": "historical",
                "metadata": {
                    "evidence": "shodan_certificate_response",
                    "lookup": "certificate_search",
                    "source_domain": subject,
                    "wildcard": False,
                    "ip": address,
                    # The index names the certificate this address serves: that is the
                    # confirmation R1's confidence is allowed to count, and the reason
                    # this half exists even though it costs a credit.
                    "host_lookup_confirmed": True,
                    "matched_by": "searched_fingerprint",
                    "provider_observed_at": _text(match.get("timestamp"), 64),
                    **(
                        {"port": port, "transport": _text(match.get("transport"), 16)}
                        if port
                        else {}
                    ),
                    **facts,
                    **_shodan_signals(match),
                },
            })
            if len(rows) >= MAX_SHODAN_MATCHES:
                break
        return rows

    async def _shodan_search(
        self, client: httpx.AsyncClient, *, key: str, sha1: str, serial: str, remaining: int, before_request
    ) -> tuple[list[dict], str | None]:
        """One certificate's reverse question: where else is it being served.

        The SHA-1 fingerprint is the filter that answers it (the SHA-256 spelling is
        accepted by the provider and matches nothing - spike, 2026-10-15), and the
        serial is the fallback for a certificate the fingerprint index has not caught up
        with. Both are provider-derived values used inside a search expression, so both
        are validated before they are interpolated, and each request is reserved against
        the account's own quota because each one is a query credit.
        """
        queries: list[str] = []
        if _shodan_hex(sha1, 40):
            queries.append(f'ssl.cert.fingerprint:"{sha1}"')
        else:
            self._errors.append("invalid_fingerprint")
        if serial and serial.isdecimal() and len(serial) <= MAX_SHODAN_SEARCH_VALUE:
            queries.append(f'ssl.cert.serial:"{serial}"')
        for index, query in enumerate(queries):
            if index >= remaining:
                break
            payload, error, _ = await self._get_json(
                client,
                f"{SHODAN_API_BASE}/shodan/host/search",
                params={"key": key, "query": query, "page": 1},
                before_request=before_request,
            )
            if error:
                return [], error
            matches = payload.get("matches") if isinstance(payload, dict) else None
            if not isinstance(matches, list):
                return [], "invalid_response"
            usable = [item for item in matches[:MAX_SHODAN_MATCHES] if isinstance(item, dict)]
            if usable:
                return usable, None
        return [], None

    async def _run_shodan(self, work: dict) -> list[dict]:
        """Confirm what our own addresses serve, then ask where a certificate is served.

        The free half is the confirmation the certificate rules were missing: an
        independent index naming the certificate an address of ours serves, together
        with the organisation, ASN, JARM, title and favicon hash that R4's echo rule and
        the shared-infrastructure suppression score on. The credit-spending half answers
        the reverse question about a certificate this scan just found, bounded per scan.
        """
        policy = self._shodan_policy(work)
        if policy is None:
            return []
        key = await self._shodan_api_key()
        if not key:
            self._errors.append("api_key_not_configured")
            return []
        targets = await self._shodan_targets(work, self._domains(work))
        if not targets:
            return []
        min_interval = _env_float(
            self.env, "SHODAN_MIN_REQUEST_INTERVAL_SECONDS",
            DEFAULT_SHODAN_MIN_REQUEST_INTERVAL_SECONDS, 0.0, 3600.0,
        )
        timeout = httpx.Timeout(
            _env_float(self.env, "SHODAN_REQUEST_TIMEOUT_SECONDS", 30.0, 5.0, 120.0), connect=5.0
        )
        observations: list[dict] = []
        discovered: list[tuple[str, str, str, str]] = []
        seen_fingerprints: set[str] = set()
        host_lookups = 0
        searches = 0

        async def reserve(bucket: str) -> None:
            """One physical provider request: local budget, then the account's quota.

            The core's quota is the ceiling an operator approves per account, and a
            refusal from it (unapproved, over budget, disabled source) is a stop rather
            than a provider failure to retry into - so it is reported as such and the
            phase ends with the evidence gathered so far.
            """
            try:
                await self.reserve_provider_request(bucket)
            except ConnectorAPIError:
                self._errors.append("provider_quota_refused")
                raise _RequestBudgetReached from None
            await self._shodan_pace(min_interval)

        async def reserve_host_lookup() -> None:
            nonlocal host_lookups
            if host_lookups >= policy["max_host_lookups"]:
                raise _RequestBudgetReached
            await reserve("lookup")
            host_lookups += 1

        async def reserve_search() -> None:
            nonlocal searches
            if searches >= policy["max_searches"]:
                raise _RequestBudgetReached
            await reserve("search")
            searches += 1

        now = datetime.now(timezone.utc)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            for name, address in targets:
                if host_lookups >= policy["max_host_lookups"]:
                    self._errors.append("host_lookup_budget_reached")
                    break
                if len(observations) >= MAX_OBSERVATIONS - MAX_SHODAN_MATCHES:
                    self._errors.append("observation_limit_reached")
                    break
                document, error, _ = await self._get_json(
                    client,
                    f"{SHODAN_API_BASE}/shodan/host/{quote(address, safe='')}",
                    params={"key": key},
                    before_request=reserve_host_lookup,
                )
                if error == "request_budget_reached":
                    if host_lookups >= policy["max_host_lookups"]:
                        self._errors.append("host_lookup_budget_reached")
                    break
                if error or not isinstance(document, dict):
                    self._errors.append(error or "invalid_response")
                    continue
                rows, certificates = self._shodan_lookup_observations(
                    subject=name, address=address, document=document, checked_at=now
                )
                observations.extend(rows)
                for domain, fingerprint_sha256, sha1, serial in certificates:
                    if sha1 in seen_fingerprints:
                        continue
                    seen_fingerprints.add(sha1)
                    discovered.append((domain, fingerprint_sha256, sha1, serial))
            for domain, fingerprint_sha256, sha1, serial in discovered:
                if searches >= policy["max_searches"]:
                    # Fewer certificates were asked about than were found, which is a
                    # partial answer rather than a clean one.
                    self._errors.append("search_budget_reached")
                    break
                if len(observations) >= MAX_OBSERVATIONS - MAX_SHODAN_MATCHES:
                    self._errors.append("observation_limit_reached")
                    break
                matches, error = await self._shodan_search(
                    client, key=key, sha1=sha1, serial=serial,
                    remaining=policy["max_searches"] - searches,
                    before_request=reserve_search,
                )
                if error == "request_budget_reached":
                    self._errors.append("search_budget_reached")
                    break
                if error:
                    self._errors.append(error)
                    continue
                observations.extend(self._shodan_response_observations(
                    subject=domain, fingerprint_sha256=fingerprint_sha256, matches=matches
                ))
        self._scan_facts = {
            "addresses": len(targets),
            "host_lookups": host_lookups,
            # Each search request is one query credit: the number is the bill, so it is
            # reported rather than left to be inferred from the observation count.
            "search_requests": searches,
            "search_candidates": len(discovered),
        }
        return observations[:MAX_OBSERVATIONS]

    async def run_scan(self, work: dict) -> tuple[list[dict], dict]:
        self._errors = []
        self._scan_facts = {}
        domains = self._domains(work)
        addresses = self._addresses(work) if self.TARGETS_ADDRESSES else []
        if not domains and not addresses:
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
            elif self.SOURCE == "tlsprobe":
                observations = await self._run_tlsprobe(domains)
            elif self.SOURCE == "shodan":
                observations = await self._run_shodan(work)
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
        summary = {"source": self.SOURCE, "domains_scanned": len(domains), "observations": len(observations), "provider_errors": sorted(set(self._errors)), "error_code": self._errors[0] if status == "error" else None, "status": status}
        # A source's own counters are what makes a quiet scan readable: how many
        # addresses were asked about, how much of the paid budget was spent, and how
        # many candidates the budget could not cover.
        summary.update(self._scan_facts)
        return [], summary

    async def submit_observations(self, job_id: str, observations: list[dict]) -> None:
        for start in range(0, len(observations), SUBMIT_BATCH):
            batch = observations[start:start + SUBMIT_BATCH]
            result = await self.submit_findings(job_id, batch)
            if result.get("rejected", 0) or result.get("accepted") != len(batch):
                raise RuntimeError("core_rejected_dns_observations")


class TLSProbeConnector(DNSConnector):
    """The certificate a monitored host serves right now, from a real handshake.

    CT is a statement about issuance; this is the statement about deployment. It
    feeds the same expiry monitor as a third control kind, so the 30/14/7/3/1/0
    reminders follow the certificate that is actually served.
    """

    SOURCE, NAME, JOB_TYPE = "tlsprobe", "dns-tlsprobe", "dns.tlsprobe"

    async def _run_tlsprobe(self, domains: list[str]) -> list[dict]:
        ports, port_errors = parse_tls_ports(self.env.get("DNS_SECURITY_TLS_PORTS"))
        self._errors.extend(port_errors)
        if not ports:
            return []
        path, path_errors = parse_tls_path(self.env.get("DNS_SECURITY_TLS_PATH"))
        self._errors.extend(path_errors)
        budget = _env_int(self.env, "DNS_SECURITY_TLS_MAX_PROBES", DEFAULT_TLS_MAX_PROBES, 1, MAX_TLS_MAX_PROBES)
        version = await curl_version()
        if not version_is_sufficient(version):
            # Only curl 7.88 and newer can hand over the chain this design reads.
            # A worker on an older build must say so instead of reporting hosts as
            # certificate-less.
            self._errors.append("curl_certs_unsupported")
            return []
        now = datetime.now(timezone.utc)
        observations: list[dict] = []
        plan: list[tuple[str, str, int]] = []
        for domain in domains:
            addresses = await asyncio.to_thread(resolve_public_ips, domain)
            if not addresses:
                # A private, loopback or unresolvable name is not a service this
                # worker may touch; recording that is better than a silent skip an
                # operator would read as "checked and clean".
                for port in ports:
                    observations.append(self._tls_control(domain, port, check_state="skipped_no_public_address", checked_at=now, metadata={"curl_version": version}))
                continue
            for port in ports:
                for address in addresses:
                    plan.append((domain, address, port))
        if len(plan) > budget:
            self._errors.append("probe_budget_reached")
            plan = plan[:budget]
        semaphore = asyncio.Semaphore(TLS_PROBE_CONCURRENCY)

        async def probe(host: str, address: str, port: int) -> dict:
            async with semaphore:
                try:
                    code, stdout, _stderr = await run_curl(build_argv(host, address, port, path))
                except (OSError, NotImplementedError):
                    return {"host": host, "address": address, "port": port, "exit": None, "verify_result": None, "num_certs": None, "tls_version": None, "facts": [], "verification": "curl_unavailable"}
                parsed = parse_curl_output(stdout)
                facts = read_chain(parsed["chain"])
                exit_code = parsed["exit"] if parsed["exit"] is not None else code
                state, verification = classify_tls_probe(
                    exit_code=exit_code, verify_result=parsed["verify_result"],
                    facts=facts[0] if facts else None, host=host, now=now,
                )
                return {
                    "host": host, "address": address, "port": port, "exit": exit_code,
                    "verify_result": parsed["verify_result"], "num_certs": parsed["num_certs"],
                    "tls_version": parsed["tls_version"], "facts": facts,
                    "state": state, "verification": verification,
                }

        for result in await asyncio.gather(*(probe(*item) for item in plan)):
            facts = result["facts"]
            state = result.get("state", "failed")
            leaf = facts[0] if facts else None
            if state != "verified":
                self._errors.append(f"tls_{result['verification']}")
            observations.append(self._tls_control(
                result["host"], result["port"], check_state=state, checked_at=now, leaf=leaf,
                expires_at=leaf["not_after"] if leaf else None,
                metadata={
                    "probe_ip": result["address"], "tls_version": result["tls_version"],
                    "verify_result": result["verify_result"], "curl_exit": result["exit"],
                    "num_certs": result["num_certs"],
                    "curl_version": version, "verification": result["verification"],
                },
            ))
            if leaf is not None:
                observations.append(self._tls_evidence(result["host"], result["address"], result["port"], leaf, facts, result["verification"]))
        return observations

    @staticmethod
    def _tls_control(host: str, port: int, *, check_state: str, checked_at: datetime, metadata: dict, leaf: dict | None = None, expires_at: str | None = None) -> dict:
        """One mutable control row per (host, port): the current answer for this host.

        The port is part of the record type because the subject alone cannot tell a
        web interface from a management port, and the storage identity is
        (source, subject, record type) for everything that is a current fact.
        """
        return {
            "observation_type": "tls_probe",
            "subject": host,
            "record_type": "TLS" if port == 443 else f"TLS:{port}",
            "expires_at": expires_at,
            "status": "current" if check_state == "verified" else "unknown",
            "metadata": {
                "check_state": check_state,
                "checked_at": checked_at.isoformat(),
                "port": port,
                "source_domain": host,
                "lookup": "active_probe",
                "evidence": "active_tls_probe",
                # The served certificate's identity and start date sit on the control row
                # as well: the expiry cycle is keyed by them, so a renewal has to be
                # visible without reading the evidence rows.
                **({"certificate_id": leaf["fingerprint_sha256"], "not_before": leaf["not_before"]} if leaf else {}),
                **metadata,
            },
        }

    @staticmethod
    def _tls_evidence(host: str, address: str, port: int, leaf: dict, chain: list[dict], verification: str) -> dict:
        """The served certificate as its own row, keyed by fingerprint.

        `metadata.id` is what the storage identity uses, so the same certificate seen
        on two hosts stays one identity with two sightings - which is the shape the
        stolen-certificate work needs, and a chain never collapses into one row.
        """
        return {
            "observation_type": "tls_certificate",
            "subject": host,
            "value": host,
            "expires_at": leaf["not_after"],
            "status": "current" if verification == "verified" else "unknown",
            "metadata": {
                "id": leaf["fingerprint_sha256"],
                "fingerprint_sha256": leaf["fingerprint_sha256"],
                "fingerprint_sha1": leaf["fingerprint_sha1"],
                "spki_sha256": leaf["spki_sha256"],
                "serial_hex": leaf["serial_hex"],
                "not_before": leaf["not_before"],
                "san_dns": leaf["san_dns"],
                "chain_fingerprints": [item["fingerprint_sha256"] for item in chain],
                "probe_ip": address,
                "port": port,
                "verification": verification,
                "evidence": "active_tls_probe",
                "source_domain": host,
                "lookup": "active_probe",
            },
        }


class RDAPConnector(DNSConnector):
    SOURCE, NAME, JOB_TYPE = "rdap", "dns-rdap", "dns.rdap"


class ResolverConnector(DNSConnector):
    SOURCE, NAME, JOB_TYPE = "resolver", "dns-resolver", "dns.resolver"


class CTLogsConnector(DNSConnector):
    SOURCE, NAME, JOB_TYPE = "ctlogs", "dns-ctlogs", "dns.ctlogs"


class VirusTotalConnector(DNSConnector):
    SOURCE, NAME, JOB_TYPE = "virustotal", "dns-virustotal", "dns.virustotal"


class ShodanConnector(DNSConnector):
    """Shodan's index of our own addresses, and where a certificate of ours is served.

    The certificate rules need two answers, and the provider prices them differently
    (see ``SHODAN_API_BASE``), so this worker asks for them separately:

    * **One address of ours, read for free.** The host lookup names the certificate the
      address serves - an independent confirmation of what our own probe read - and
      brings the organisation, ASN, JARM, page title and favicon hash that R4's echo
      comparison and the shared-infrastructure suppression score on.
    * **One certificate we just found, asked about once.** The host search answers where
      else that certificate is being served, which is the foreign address R1 alerts on.
      It costs one query credit per request, so the capability is capped per scan and
      can be set to zero without giving up the free half.

    It reads provider data only: no request is ever sent to an address the provider
    reported, and the free half asks about addresses the platform already names.
    """

    SOURCE, NAME, JOB_TYPE = "shodan", "dns-shodan", "dns.shodan"
    TARGETS_ADDRESSES = True

    def manifest_payload(self):
        """Declare the per-scan capabilities so the registry can render their form."""
        manifest = super().manifest_payload()
        manifest.setdefault(
            "config_schema",
            {
                key: {
                    "type": "int",
                    "default": limits[2],
                    "description": f"Integer {limits[0]}..{limits[1]}",
                    "label": key.replace("_", " "),
                }
                for key, limits in SHODAN_POLICY.items()
            },
        )
        return manifest


def main() -> None:
    name = os.environ.get("CONNECTOR_NAME", "dns-rdap")
    workers = (RDAPConnector, ResolverConnector, CTLogsConnector, VirusTotalConnector, TLSProbeConnector, ShodanConnector)
    connectors = {cls.NAME: cls for cls in workers}
    # Transitional: workers started with the pre-rename name keep working until their env is updated.
    connectors.update({f"{cls.SOURCE}-dns-security-default": cls for cls in workers})
    cls = connectors.get(name)
    if cls is None:
        raise RuntimeError("CONNECTOR_NAME must be one of the DNS Security worker names")
    cls().main()


if __name__ == "__main__":
    main()
