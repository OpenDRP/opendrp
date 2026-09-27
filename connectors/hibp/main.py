"""HIBP connector (module type: breaches).

Scans email-account and domain assets against HaveIBeenPwned:

* ``email_account`` assets via ``GET /breachedaccount/{email}``
* ``domain`` assets via ``GET /breacheddomain/{domain}`` — HIBP returns an
  alias -> [breach names] mapping; every (alias, breach) pair is submitted
  as a finding with ``matched_email = alias@domain``.

API key: ``HIBP_API_KEY`` env var. Rate limiting: 1.7 s sleep between
HIBP requests (well within the lowest paid tier).

This connector owns all HIBP API access; the core only receives normalized findings.
"""

from __future__ import annotations

import asyncio
from datetime import date as _date, datetime as _dt

import httpx
import structlog

from opendrp_connector import ConnectorBase

log = structlog.get_logger()

_HIBP_RPS_SLEEP = 1.7


def _parse_date(value):
    if value is None:
        return None
    if isinstance(value, _date) and not isinstance(value, _dt):
        return value.isoformat()
    try:
        return _date.fromisoformat(str(value)[:10]).isoformat()
    except (ValueError, TypeError):
        return None


def _parse_dt(value):
    if value is None:
        return None
    if isinstance(value, _dt):
        return value.isoformat()
    try:
        return _dt.fromisoformat(str(value).replace("Z", "+00:00")[:26]).isoformat()
    except (ValueError, TypeError):
        return None


def _parse_nonnegative_int(value) -> int:
    try:
        return max(int(value or 0), 0)
    except (TypeError, ValueError):
        return 0


def _mask_password(plain: str | None) -> str | None:
    if not plain:
        return None
    if len(plain) <= 4:
        return "*" * len(plain)
    head, tail = plain[:2], plain[-2:]
    middle = "*" * max(len(plain) - 4, 4)
    return f"{head}{middle}{tail}"


class HibpConnector(ConnectorBase):
    BASE = "https://haveibeenpwned.com/api/v3"
    UA = {"User-Agent": "OpenDRP-Connector/1.0"}

    def __init__(self) -> None:
        super().__init__()
        self.api_key = self.env.get("HIBP_API_KEY", "").strip()
        self._provider_errors: list[str] = []

    # ------------------------------------------------------------------
    # HIBP API
    # ------------------------------------------------------------------

    def _hibp_headers(self) -> dict:
        return {**self.UA, "hibp-api-key": self.api_key}

    async def search_email_breaches(self, client: httpx.AsyncClient, email: str) -> list[dict]:
        if not self.api_key:
            return []
        url = f"{self.BASE}/breachedaccount/{email}"
        params = {"truncateResponse": "false", "includeUnverified": "true"}
        try:
            r = await client.get(url, params=params, headers=self._hibp_headers())
        except Exception as e:
            self._provider_errors.append("network_error")
            log.warning("hibp_email_network_failed", err=str(e)[:200])
            return []
        if r.status_code == 404:
            return []
        if r.status_code != 200:
            self._provider_errors.append(f"http_{r.status_code}")
            log.warning("hibp_email_http_error", status=r.status_code, err=r.text[:200])
            return []
        try:
            return r.json() or []
        except Exception as e:
            self._provider_errors.append("invalid_json")
            log.warning("hibp_email_json_failed", err=str(e)[:200])
            return []

    async def search_domain_breaches(self, client: httpx.AsyncClient, domain: str) -> dict[str, list[str]]:
        """Returns {alias: [breach names]} for every breached address."""
        if not self.api_key:
            return {}
        url = f"{self.BASE}/breacheddomain/{domain}"
        try:
            r = await client.get(url, headers=self._hibp_headers())
        except Exception as e:
            self._provider_errors.append("network_error")
            log.warning("hibp_domain_network_failed", err=str(e)[:200])
            return {}
        if r.status_code == 404:
            return {}
        if r.status_code != 200:
            self._provider_errors.append(f"http_{r.status_code}")
            log.warning("hibp_domain_http_error", domain=domain, status=r.status_code, err=r.text[:200])
            return {}
        try:
            raw = r.json()
        except Exception as e:
            self._provider_errors.append("invalid_json")
            log.warning("hibp_domain_json_failed", err=str(e)[:200])
            return {}
        result: dict[str, list[str]] = {}
        if isinstance(raw, dict):
            for alias, value in raw.items():
                a = str(alias).strip()
                if not a:
                    continue
                names: list[str] = []
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, str) and item.strip():
                            names.append(item.strip()[:255])
                        elif isinstance(item, dict):
                            n = item.get("Name")
                            if isinstance(n, str) and n.strip():
                                names.append(n.strip()[:255])
                if names:
                    result[a[:255]] = names
        return result

    async def get_breach_metadata(self, client: httpx.AsyncClient, breach_name: str) -> dict | None:
        safe = str(breach_name).strip()
        if not safe or len(safe) > 255:
            return None
        url = f"{self.BASE}/breach/{safe}"
        try:
            r = await client.get(url, headers=self.UA)
        except Exception:
            return None
        if r.status_code != 200:
            return None
        try:
            return r.json()
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Finding normalization
    # ------------------------------------------------------------------

    def _normalize_breach(self, meta: dict) -> dict:
        """Map one upstream catalogue record onto the neutral finding schema.

        The core stores what every breach source can supply; everything this
        source knows *beyond* that (its own classification flags, the exposed
        secret sample, its catalogue timestamps and logo) travels in
        ``attributes``, so this connector declares its own payload shape instead
        of relying on the core modelling this vendor.
        """
        attributes: dict[str, object] = {
            "is_verified": bool(meta.get("IsVerified", False)),
            "is_fabricated": bool(meta.get("IsFabricated", False)),
            "is_sensitive": bool(meta.get("IsSensitive", False)),
            "is_retired": bool(meta.get("IsRetired", False)),
            "is_spam_list": bool(meta.get("IsSpamList", False)),
            "is_malware": bool(meta.get("IsMalware", False)),
        }
        masked = _mask_password(meta.get("Password"))
        if masked:
            attributes["masked_password"] = masked
        added = _parse_dt(meta.get("AddedDate"))
        if added:
            attributes["added_date"] = added
        modified = _parse_dt(meta.get("ModifiedDate"))
        if modified:
            attributes["modified_date"] = modified
        logo = str(meta.get("LogoPath") or "")[:1024]
        if logo:
            attributes["logo_path"] = logo

        return {
            "breach_name": str(meta.get("Name", ""))[:255],
            "title": str(meta.get("Title", ""))[:255],
            "domain": str(meta.get("Domain") or "")[:255],
            "breach_date": _parse_date(meta.get("BreachDate")),
            "pwn_count": _parse_nonnegative_int(meta.get("PwnCount")),
            "description": (str(meta.get("Description") or "") or None),
            "data_classes": meta.get("DataClasses") or [],
            "attributes": attributes,
        }

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------

    async def run_scan(self, work: dict) -> tuple[list[dict], dict]:
        self._provider_errors = []
        params = work.get("params", {})
        emails = params.get("emails") or []
        domains = params.get("domains") or []
        # Targeted jobs are created by the API with an explicit snapshot.
        # Keep the connector contract generic: no provider-specific endpoint
        # logic is required in the core.

        if not self.api_key:
            return [], {
                "task": "hibp_daily_scan",
                "skipped": "HIBP_API_KEY not configured",
                "status": "skipped",
                "new_breach_rows": 0,
            }

        # ``emails_scanned`` counts monitored *email assets* only. Domain
        # aliases are a different unit of work (one API call each, no asset
        # behind them) and used to be added to this counter, which made the
        # summary claim 15 "emails" for a single monitored mailbox.
        emails_scanned = 0
        domains_scanned = 0
        aliases_found = 0
        new_rows = 0

        timeout = httpx.Timeout(30.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            # 1. Email accounts.
            for email in emails:
                breaches = await self.search_email_breaches(client, email)
                batch = []
                for b in breaches:
                    f = self._normalize_breach(b)
                    f["matched_email"] = email[:255]
                    f["matched_domain"] = None
                    batch.append(f)
                if batch:
                    result = await self.submit_findings(work["job_id"], batch)
                    new_rows += int(result.get("accepted", 0))
                emails_scanned += 1
                await asyncio.sleep(_HIBP_RPS_SLEEP)

            # 2. Domains — alias expansion into per-address findings.
            for domain in domains:
                alias_map = await self.search_domain_breaches(client, domain)
                for alias, breach_names in alias_map.items():
                    full_email = f"{alias}@{domain}"
                    batch = []
                    for name in breach_names:
                        meta = await self.get_breach_metadata(client, name)
                        if meta is None:
                            meta = {"Name": name, "Title": name, "Domain": ""}
                        f = self._normalize_breach(meta)
                        f["matched_email"] = full_email[:255]
                        f["matched_domain"] = domain[:255]
                        batch.append(f)
                    if batch:
                        result = await self.submit_findings(work["job_id"], batch)
                        new_rows += int(result.get("accepted", 0))
                    aliases_found += 1
                    await asyncio.sleep(_HIBP_RPS_SLEEP)
                domains_scanned += 1

        return [], {
            "task": "hibp_daily_scan",
            "emails_scanned": emails_scanned,
            "domains_scanned": domains_scanned,
            "domain_aliases_found": aliases_found,
            "new_breach_rows": new_rows,
            "status": "partial" if self._provider_errors else "success",
            "provider_errors": sorted(set(self._provider_errors)),
        }


def main() -> None:
    connector = HibpConnector()
    connector.main()


if __name__ == "__main__":
    main()
