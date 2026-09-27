"""Shodan connector.

Brand-hunting over Shodan host search with three capabilities, each
individually togglable:

* ``scan_ssl_text``  — ``ssl:"<domain>"`` searches (SSL certificate text)
* ``scan_http_title`` — ``http.title:"<title>"`` searches (page titles)
* ``scan_favicon``    — ``http.favicon.hash:`` search for domain assets

Capability switches arrive from the core registry per scan (admin-editable
in the UI) with connector env vars as fallback defaults:
``SHODAN_SCAN_SSL_TEXT`` / ``SHODAN_SCAN_HTTP_TITLE`` /
``SHODAN_SCAN_FAVICON`` (default "true"). They are namespaced like the other
Shodan settings (``SHODAN_API_KEY``, ``SHODAN_MIN_REQUEST_INTERVAL_SECONDS``),
because ``.env`` is a single namespace shared by every service. They only apply
until an administrator saves the capability in its configuration form: the
registry value then reaches every later scan.

Each capability reports its own outcome in the job summary
(``capability_results``): how many provider queries it ran, how many hosts those
queries matched, how many findings it tried to submit and how many the core
actually stored. Without that split, "the favicon search found nothing" is
indistinguishable from "the favicon search is broken", and an operator has to
re-run the scan by hand to find out which one it is.

This connector owns all Shodan API access; the core only receives normalized findings.
"""

from __future__ import annotations

import asyncio
import base64
import os
import time
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone

import httpx
import mmh3
import structlog

from opendrp_connector import ConnectorBase
from opendrp_connector.network import is_safe_external_ip

log = structlog.get_logger()

_SHODAN_MAX_PAGES = 3
_SHODAN_PAGE_SIZE = 100
_SHODAN_MAX_RETRIES = 2
_SHODAN_DEFAULT_MIN_INTERVAL = 1.0
_SHODAN_DEFAULT_TIMEOUT = 30.0
_SHODAN_MAX_RETRY_DELAY = 30.0
_FAVICON_FETCH_TIMEOUT = 10.0
_FAVICON_MAX_BYTES = 2 * 1024 * 1024  # a favicon larger than 2 MB is suspicious
#: How many same-host redirects a favicon lookup may follow. ``/favicon.ico``
#: is commonly a redirect (to ``/static/icon.png``, or http -> https), and a
#: lookup that gives up on the first hop silently reports zero findings.
_FAVICON_MAX_REDIRECTS = 3
#: Findings per submit request. Small batches keep one wide scan from holding
#: thousands of rows in memory and make progress visible in the job summary.
_SUBMIT_BATCH_SIZE = 25


def _env_flag(value: str | None, default: bool = True) -> bool:
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


class ShodanConnector(ConnectorBase):
    API = "https://api.shodan.io/shodan/host/search"
    HEADERS = {"User-Agent": "OpenDRP-Connector/1.0"}

    def __init__(self) -> None:
        super().__init__()
        self.api_key = self.env.get("SHODAN_API_KEY", "").strip()
        self._provider_errors: list[str] = []
        self._last_provider_request = 0.0
        self._min_request_interval = max(
            0.0,
            min(60.0, float(self.env.get("SHODAN_MIN_REQUEST_INTERVAL_SECONDS", str(_SHODAN_DEFAULT_MIN_INTERVAL)))),
        )
        self._request_timeout = max(
            5.0,
            min(120.0, float(self.env.get("SHODAN_REQUEST_TIMEOUT_SECONDS", str(_SHODAN_DEFAULT_TIMEOUT)))),
        )

    # ------------------------------------------------------------------
    # Capabilities: registry config (from work payload) wins over env.
    # ------------------------------------------------------------------

    def _capabilities(self, config: dict) -> dict[str, bool]:
        return {
            "scan_ssl_text": bool(config.get("scan_ssl_text", _env_flag(self.env.get("SHODAN_SCAN_SSL_TEXT")))),
            "scan_http_title": bool(config.get("scan_http_title", _env_flag(self.env.get("SHODAN_SCAN_HTTP_TITLE")))),
            "scan_favicon": bool(config.get("scan_favicon", _env_flag(self.env.get("SHODAN_SCAN_FAVICON")))),
        }

    # ------------------------------------------------------------------
    # Shodan API
    # ------------------------------------------------------------------

    async def _pace_provider_request(self) -> None:
        """Keep sequential queries below a conservative provider request rate.

        Shodan's useful limit is query credits, not merely HTTP requests, and
        the limit varies by plan. A small minimum interval prevents a rescan
        with several capabilities/pages from bursting all queries at once while
        still allowing operators to tune it for their plan.
        """
        elapsed = time.monotonic() - self._last_provider_request
        delay = self._min_request_interval - elapsed
        if delay > 0:
            await asyncio.sleep(delay)
        self._last_provider_request = time.monotonic()

    @staticmethod
    def _retry_after(response: httpx.Response) -> float | None:
        raw = response.headers.get("Retry-After")
        if not raw:
            return None
        try:
            return max(0.0, float(raw))
        except ValueError:
            try:
                target = parsedate_to_datetime(raw)
                if target.tzinfo is None:
                    target = target.replace(tzinfo=timezone.utc)
                return max(0.0, (target - datetime.now(timezone.utc)).total_seconds())
            except (TypeError, ValueError, OverflowError):
                return None

    async def _search(self, query: str, exclude: set[str]) -> list[dict]:
        if not self.api_key:
            log.warning("shodan_no_api_key")
            return []
        results: list[dict] = []
        timeout = httpx.Timeout(self._request_timeout, connect=min(10.0, self._request_timeout))
        async with httpx.AsyncClient(timeout=timeout) as client:
            page = 1
            while page <= _SHODAN_MAX_PAGES:
                params = {"key": self.api_key, "query": query, "page": page, "minify": True}
                for attempt in range(_SHODAN_MAX_RETRIES + 1):
                    try:
                        await self._pace_provider_request()
                        r = await client.get(self.API, params=params, headers=self.HEADERS)
                        retryable = r.status_code == 429 or 500 <= r.status_code < 600
                        if retryable and attempt < _SHODAN_MAX_RETRIES:
                            delay = self._retry_after(r)
                            if delay is None:
                                delay = min(_SHODAN_MAX_RETRY_DELAY, 2 ** attempt)
                            await asyncio.sleep(min(_SHODAN_MAX_RETRY_DELAY, delay))
                            continue
                        if r.status_code != 200:
                            code = "quota_exhausted" if r.status_code == 403 and "credit" in r.text.lower() else f"http_{r.status_code}"
                            self._provider_errors.append(code)
                            log.warning("shodan_search_non_200", status=r.status_code, error_code=code, query=query)
                            break
                        try:
                            payload = r.json()
                        except ValueError:
                            self._provider_errors.append("invalid_json")
                            log.warning("shodan_search_invalid_json", query=query)
                            break
                        matches = payload.get("matches", [])
                        if not isinstance(matches, list):
                            self._provider_errors.append("invalid_response")
                            break
                        results.extend(matches)
                        if len(matches) < _SHODAN_PAGE_SIZE:
                            page = _SHODAN_MAX_PAGES + 1
                        break
                    except httpx.TimeoutException as exc:
                        if attempt < _SHODAN_MAX_RETRIES:
                            await asyncio.sleep(min(_SHODAN_MAX_RETRY_DELAY, 2 ** attempt))
                            continue
                        if "network_timeout" not in self._provider_errors:
                            self._provider_errors.append("network_timeout")
                        log.warning("shodan_req_timeout", query=query, err=type(exc).__name__)
                        break
                    except httpx.HTTPError as exc:
                        if attempt < _SHODAN_MAX_RETRIES:
                            await asyncio.sleep(min(_SHODAN_MAX_RETRY_DELAY, 2 ** attempt))
                            continue
                        if "network_error" not in self._provider_errors:
                            self._provider_errors.append("network_error")
                        log.warning("shodan_req_failed", query=query, err=type(exc).__name__)
                        break
                page += 1
        filtered = []
        for m in results:
            ip = m.get("ip_str") or ""
            domains = {str(d) for d in (m.get("domains") or [])}
            hostns = {str(h) for h in (m.get("hostnames") or [])}
            if ip in exclude:
                continue
            if domains & exclude:
                continue
            if hostns & exclude:
                continue
            filtered.append(m)
        return filtered

    @staticmethod
    def _pick_host(m: dict) -> str | None:
        candidates = (m.get("domains") or []) + (m.get("hostnames") or [])
        for c in candidates:
            s = str(c).strip().lower()
            if s:
                return s[:512]
        ip = m.get("ip_str")
        if ip:
            return str(ip).strip()[:512]
        return None

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------

    async def run_scan(self, work: dict) -> tuple[list[dict], dict]:
        self._provider_errors = []
        params = work.get("params", {})
        config = work.get("config") or {}
        caps = self._capabilities(config)

        kw_domains = params.get("keyword_domains") or []  # [{value, type}]
        kw_titles = params.get("keyword_titles") or []
        exclude = set(params.get("exclude") or [])

        if not self.api_key:
            return [], {
                "task": "shodan_brand_hunting",
                "skipped": "SHODAN_API_KEY not configured",
                "status": "skipped",
                "new_discovered": 0,
            }

        active = [name for name, on in caps.items() if on]
        if not active:
            return [], {
                "task": "shodan_brand_hunting",
                "skipped": "no_capabilities_enabled",
                "capabilities_run": [],
                "capability_results": {},
                "new_discovered": 0,
            }

        job_id = str(work["job_id"])
        run_caps: list[str] = []
        capability_results: dict[str, dict] = {}
        saved = 0

        if caps["scan_ssl_text"]:
            run_caps.append("ssl")
            capability_results["ssl"] = await self._keyword_capability(
                job_id=job_id,
                source="shodan_ssl",
                queries=[
                    (f'ssl:"{self._keyword_value(item)}"', self._keyword_value(item))
                    for item in kw_domains
                ],
                exclude=exclude,
            )
            saved += capability_results["ssl"]["stored"]

        if caps["scan_http_title"]:
            run_caps.append("title")
            capability_results["title"] = await self._keyword_capability(
                job_id=job_id,
                source="shodan_title",
                queries=[
                    (f'http.title:"{self._keyword_value(item)}"', self._keyword_value(item))
                    for item in kw_titles
                ],
                exclude=exclude,
            )
            saved += capability_results["title"]["stored"]

        if caps["scan_favicon"]:
            run_caps.append("favicon")
            capability_results["favicon"] = await self._favicon_capability(
                job_id=job_id,
                domain_assets=[
                    self._keyword_value(item)
                    for item in kw_domains
                    if (item.get("type") if isinstance(item, dict) else "domain") == "domain"
                ],
                exclude=exclude,
            )
            saved += capability_results["favicon"]["stored"]

        return [], {
            "task": "shodan_brand_hunting",
            "kw_domains": len(kw_domains),
            "kw_titles": len(kw_titles),
            "capabilities_run": run_caps,
            "capability_results": capability_results,
            "new_discovered": saved,
            "status": "partial" if self._provider_errors else "success",
            "provider_errors": sorted(set(self._provider_errors)),
        }

    # ------------------------------------------------------------------
    # Capability execution
    # ------------------------------------------------------------------

    @staticmethod
    def _keyword_value(item) -> str:
        """Read one keyword entry.

        ``keyword_domains`` arrives as ``{"value": ..., "type": ...}``; titles
        arrive as plain strings, but accepting the typed shape for both keeps the
        connector indifferent to how the core chose to shape its inventory.
        """
        if isinstance(item, dict):
            return str(item.get("value") or "")
        return str(item)

    @staticmethod
    def _empty_tally() -> dict:
        """The per-capability counters every capability reports.

        ``matches`` counts provider hits, ``candidates`` the findings built from
        them, ``stored`` the ones the core accepted. ``matches`` above ``stored``
        is therefore either deduplication (``phishing_domain`` is unique in the
        core, so a re-discovered host is rejected, not updated) or hosts the
        exclude set removed — never a silent drop.
        """
        return {"queries": 0, "matches": 0, "candidates": 0, "stored": 0, "skipped": None}

    async def _submit_batch(self, job_id: str, batch: list[dict]) -> int:
        """Submit one batch; returns how many findings the core stored."""
        result = await self.submit_findings(job_id, batch)
        return int(result.get("accepted", 0))

    async def _keyword_capability(
        self,
        *,
        job_id: str,
        source: str,
        queries: list[tuple[str, str]],
        exclude: set[str],
    ) -> dict:
        """Run one ``<field>:"<keyword>"`` capability and report its outcome.

        ``queries`` pairs every provider query with the keyword it was built
        from, because that keyword is the ``matched_asset`` of each finding the
        query returns. Findings go out in bounded batches as they arrive, so a
        wide scan reports progress instead of holding every row in memory and a
        single submit at the end.
        """
        tally = self._empty_tally()
        batch: list[dict] = []
        for query, matched in queries:
            matches = await self._search(query, exclude)
            tally["queries"] += 1
            tally["matches"] += len(matches)
            for m in matches:
                host = self._pick_host(m)
                if not host:
                    continue
                batch.append(self._finding(host, matched, m, source))
                tally["candidates"] += 1
                if len(batch) >= _SUBMIT_BATCH_SIZE:
                    tally["stored"] += await self._submit_batch(job_id, batch)
                    batch = []
        if batch:
            tally["stored"] += await self._submit_batch(job_id, batch)
        return tally

    async def _favicon_capability(
        self, *, job_id: str, domain_assets: list[str], exclude: set[str]
    ) -> dict:
        """Hash each owned domain's favicon and hunt for the same icon elsewhere.

        The capability works off *our* domains, so it needs at least one
        ``domain`` asset to hash. Saying so is the difference between "nothing
        matched" and "there was nothing to search with": both used to read as a
        bare zero.
        """
        tally = self._empty_tally()
        if not domain_assets:
            tally["skipped"] = "no_domain_assets"
            return tally
        unusable = 0
        for asset in domain_assets:
            outcome = await self._favicon_findings(asset, exclude, job_id)
            if outcome["skipped"]:
                unusable += 1
            for key in ("queries", "matches", "candidates", "stored"):
                tally[key] += outcome[key]
        if unusable == len(domain_assets):
            tally["skipped"] = "favicon_unavailable"
        return tally

    def _finding(self, host: str, matched: str, m: dict, source: str) -> dict:
        return {
            "phishing_domain": host[:512],
            "matched_asset": str(matched)[:512],
            "ip_address": (m.get("ip_str") or "")[:255] or None,
            "web_ports": (str(m.get("port")) if m.get("port") else None),
            "detection_source": source,
        }

    @staticmethod
    def _same_host_redirect(location: str, host: str) -> str | None:
        """The follow-up URL for a same-host redirect, or ``None`` to stop.

        Only the host whose addresses were already resolved and checked against
        :func:`is_safe_external_ip` may be followed: a favicon lookup must never
        be turned into a request against an address the asset chose for us. The
        next URL is rebuilt from that validated host plus the target's path and
        query rather than taken verbatim, so a ``Location`` header cannot smuggle
        userinfo or another authority into the follow-up request.
        """
        from urllib.parse import urlparse

        parsed = urlparse(location)
        if parsed.scheme not in {"http", "https"} or (parsed.hostname or "") != host:
            return None
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return f"{parsed.scheme}://{host}{path}"

    async def _fetch_favicon(self, host: str, scheme: str) -> bytes | None:
        # Assets and redirects are untrusted network targets. Resolve and pin
        # only public addresses; never let a connector turn favicon lookup into
        # a request against loopback, Docker, RFC1918 or cloud metadata.
        import socket

        if os.environ.get("TESTING") == "1" or os.environ.get("APP_ENV") == "test":
            addresses = {host}
        else:
            try:
                addresses = {info[4][0] for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
            except OSError:
                return None
            if not addresses or not all(is_safe_external_ip(address) for address in addresses):
                return None
        url = f"{scheme}://{host.rstrip('/')}/favicon.ico"
        async with httpx.AsyncClient(
            timeout=_FAVICON_FETCH_TIMEOUT,
            verify=(scheme == "https"),
            follow_redirects=False,
            limits=httpx.Limits(max_connections=5),
        ) as client:
            # Redirects are followed by hand, not by httpx, so every hop can be
            # checked against the host that was just validated. A favicon behind
            # a same-host redirect is ordinary; abandoning it made the favicon
            # capability report nothing at all.
            for _ in range(_FAVICON_MAX_REDIRECTS + 1):
                r = await client.get(url, headers={"User-Agent": self.HEADERS["User-Agent"]})
                if r.status_code in {301, 302, 303, 307, 308}:
                    target = self._same_host_redirect(r.headers.get("location", ""), host)
                    if target is None:
                        return None
                    url = target
                    continue
                if r.status_code == 200 and r.content:
                    return r.content[:_FAVICON_MAX_BYTES]
                return None
        return None

    async def _favicon_findings(self, domain_asset: str, exclude: set[str], job_id: str) -> dict:
        """Hash one domain's favicon and search for it. Returns a capability tally."""
        host = domain_asset.rstrip("/")
        favicon_content: bytes | None = None
        for scheme in ("https", "http"):
            try:
                favicon_content = await self._fetch_favicon(host, scheme)
            except Exception:
                continue
            if favicon_content:
                break
        if not favicon_content:
            # No icon to hash: the host serves none, redirects off-host, or is
            # unreachable. Reported as a skip reason, because a bare zero in the
            # findings count reads as "searched and matched nothing".
            log.info("shodan_favicon_unavailable", host=host)
            tally = self._empty_tally()
            tally["skipped"] = "favicon_unavailable"
            return tally

        favicon_hash = mmh3.hash(base64.encodebytes(favicon_content), signed=True)
        matches = await self._search(f"http.favicon.hash:{favicon_hash}", exclude)
        batch: list[dict] = []
        for m in matches:
            ph = self._pick_host(m)
            if not ph:
                continue
            batch.append(self._finding(ph, domain_asset, m, "shodan_favicon"))
        tally = self._empty_tally()
        tally["queries"] = 1
        tally["matches"] = len(matches)
        tally["candidates"] = len(batch)
        if batch:
            tally["stored"] = await self._submit_batch(job_id, batch)
        return tally


def main() -> None:
    connector = ShodanConnector()
    connector.main()


if __name__ == "__main__":
    main()
