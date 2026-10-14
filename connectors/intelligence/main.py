"""Opt-in intelligence workers (Netlas) using the normal connector pull protocol."""

import asyncio
import ipaddress
import logging
import os

from opendrp_connector import ConnectorBase
from opendrp_connector.base import ConnectorAPIError

from providers import (
    Adapter,
    CAPABILITIES,
    KEYS,
    ProviderError,
    core_credential,
    endpoints,
    has_subject,
    host,
)

log = logging.getLogger("intelligence")

POLICY = {
    "requests_per_minute": (1, 600, 10),
    "daily_budget": (1, 100000, 100),
    "max_requests": (1, 1000, 20),
    "max_pages": (1, 100, 3),
    "max_results": (1, 5000, 100),
    "max_targets": (1, 1000, 20),
    "scan_timeout_seconds": (10, 3600, 300),
    "cooldown_seconds": (0, 86400, 60),
}


def owned(subject, target):
    """Exact IP or domain suffix only; shared IPs do not prove ownership."""
    return subject == target or subject.endswith("." + target)


def finding(module, provider, record, target, capability, excluded):
    subject = record["subject"]
    metadata = {
        "capability": capability,
        "provider": provider,
        "title": record["title"],
        "association": "exact_ip"
        if subject == target and record["ip"] == target
        else "hostname_match",
    }
    if module == "dns" and record.get("certificate"):
        if not owned(subject, target):
            return None
        certificate = record["certificate"]
        return {
            "observation_type": "certificate",
            "subject": subject,
            "value": subject,
            "status": "historical",
            "expires_at": certificate.get("valid_to"),
            "metadata": {
                **metadata,
                "evidence": "netlas_certificate_collection",
                **({"id": certificate["sha256"]} if certificate.get("sha256") else {}),
                "subject_dn": certificate.get("subject_dn", ""),
                "issuer_dn": certificate.get("issuer_dn", ""),
                "not_before": certificate.get("valid_from", ""),
                "not_after": certificate.get("valid_to", ""),
                "source_domain": target,
                "wildcard": False,
            },
        }
    if module == "phishing":
        try:
            ipaddress.ip_address(subject)
            return None
        except ValueError:
            pass
        if any(owned(subject, item) for item in excluded):
            return None
        return {
            "phishing_domain": subject,
            "matched_asset": target,
            "detection_source": provider,
            "ip_address": record["ip"],
            "web_ports": str(record["port"]) if record["port"] else None,
            "observed_at": record["observed_at"],
            "metadata": {**metadata, "verdict": "candidate_not_verified"},
        }
    if not owned(subject, target):
        return None
    if module == "exposure" and record["port"] is None:
        raise ProviderError("missing_service_port")
    if module == "dns":
        return {
            "observation_type": "hostname",
            "subject": target,
            "value": subject,
            "status": "current",
            "metadata": {
                **metadata,
                "provider_observed_at": record["observed_at"] or "unknown",
                "ip_address": record["ip"] or "unknown",
            },
        }
    return {
        "subject": subject,
        "matched_asset": target,
        "hostname": subject if subject != record["ip"] else None,
        "port": record["port"],
        "transport": record["transport"],
        "protocol": record["protocol"],
        "observed_at": record["observed_at"],
        "metadata": metadata,
    }


class IntelligenceConnector(ConnectorBase):
    def __init__(self):
        self.provider = os.environ.get("INTELLIGENCE_PROVIDER", "")
        if self.provider not in KEYS:
            raise RuntimeError(
                "INTELLIGENCE_PROVIDER must identify a supported provider"
            )
        super().__init__()
        self.credential_state = "unknown"
        self.provider_error = None
        # The environment key is the fallback for accounts without a key stored
        # in the core; a key stored in the core always takes precedence.
        self._env_api_key = self.env.get(KEYS[self.provider], "")

    def manifest_payload(self):
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
                for key, limits in POLICY.items()
            },
        )
        return manifest

    async def register(self):
        await super().register()
        await self.refresh_credential()
        await self.report_readiness()

    async def refresh_credential(self):
        """Load this account's provider key from the core, keeping the last one on failure."""
        try:
            response = await self._request("GET", "/api/v1/connectors/me/credential")
            api_key = core_credential(response.json())
        except (ConnectorAPIError, ValueError) as exc:
            # Network and HTTP failures arrive as ConnectorAPIError; a malformed
            # body arrives as ValueError. Either way the last key stays in use.
            log.warning("could not refresh provider credential: %s", type(exc).__name__)
            return
        self.env[KEYS[self.provider]] = api_key or self._env_api_key

    def readiness_capabilities(self):
        if self.connector_type == "dns":
            return ["passive_dns", "certificate"]
        return [item for item in CAPABILITIES[self.provider] if item != "passive_dns"]

    async def report_readiness(self):
        capabilities = self.readiness_capabilities()
        await self._request(
            "POST",
            "/api/v1/connectors/me/readiness",
            json={
                "credentials_configured": bool(
                    self.env.get(KEYS[self.provider], "").strip()
                ),
                "credential_state": self.credential_state,
                "provider_error": self.provider_error,
                "capabilities": capabilities,
                "operations": ["search", "lookup", "certificate"],
            },
        )

    async def submit_observations(self, job_id, observations):
        for start in range(0, len(observations), 50):
            batch = observations[start : start + 50]
            await self.submit_findings(job_id, batch)

    async def run_scan(self, work):
        await self.refresh_credential()
        policy = {}
        for key, (low, high, default) in POLICY.items():
            value = (work.get("config") or {}).get(key, default)
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise ProviderError("invalid_scan_policy")
            policy[key] = value
        job_id = str(work["job_id"])
        capabilities = self.readiness_capabilities()

        async def reserve(bucket):
            await self._request(
                "POST", "/api/v1/connectors/me/quota/provider",
                params={"job_id": job_id, "bucket": bucket},
                headers={"X-Connector-Lease": self._lease_for(job_id)},
            )

        adapter = Adapter(self.provider, self.env, reserve)
        adapter.max_requests = policy["max_requests"]

        params = work.get("params") or {}
        excluded = [host(value) for value in params.get("exclude", [])]
        targets = [("hostname", host(value)) for value in params.get("domains", [])]
        if self.connector_type == "dns":
            targets = [("passive_dns", host(value)) for value in params.get("domains", [])]
        if self.connector_type == "exposure":
            targets.extend(("ip", str(ipaddress.ip_address(value))) for value in params.get("ips", []))
        if self.connector_type == "phishing":
            targets = [("certificate", value) for _, value in targets]
            targets.extend(("title", str(value)) for value in params.get("keyword_titles", []))

        findings, errors = [], []
        truncated = len(targets) > policy["max_targets"]
        targets = targets[: policy["max_targets"]]

        async def scan_target(capability, target):
            nonlocal truncated
            if capability not in capabilities:
                raise ProviderError("unsupported_capability")
            if capability == "passive_dns":
                rows = await adapter.search_domains(
                    target, max_pages=policy["max_pages"],
                    max_results=max(1, policy["max_results"] - len(findings)),
                )
                observations = adapter.dns_observations(target, rows)
                findings.extend(observations[: max(0, policy["max_results"] - len(findings))])
                if len(findings) < policy["max_results"]:
                    cert_rows = await adapter.search_certificates(
                        target, max_pages=policy["max_pages"],
                        max_results=max(1, policy["max_results"] - len(findings)),
                    )
                    for row in cert_rows:
                        try:
                            records = endpoints(row, adapter)
                        except ProviderError as exc:
                            adapter.record_error(str(exc))
                            continue
                        for record in records:
                            try:
                                observation = finding(
                                    self.connector_type, self.provider, record, target,
                                    "certificate", excluded,
                                )
                            except ProviderError as exc:
                                adapter.record_error(str(exc))
                                continue
                            if observation:
                                findings.append(observation)
                            if len(findings) >= policy["max_results"]:
                                truncated = True
                                break
                        if len(findings) >= policy["max_results"]:
                            break
                self.credential_state = "valid"
                self.provider_error = None
                truncated |= adapter.truncated
                return

            if capability == "lookup":
                rows = await adapter.lookup_host(target, max_results=policy["max_results"])
            else:
                rows = await adapter.search(
                    capability, target, max_pages=policy["max_pages"],
                    max_results=policy["max_results"],
                )
            self.credential_state = "valid"
            self.provider_error = None
            truncated |= adapter.truncated
            for row in rows:
                try:
                    records = endpoints(row, adapter)
                except ProviderError as exc:
                    adapter.record_error(str(exc))
                    continue
                if not records:
                    # `endpoints` drops a record it cannot attribute, so an empty
                    # result is either a row that names no subject at all — a
                    # provider defect the job has to report as partial — or one
                    # whose records were filtered out by design, which is not an
                    # error. A row that yielded nothing and named nothing is the
                    # first kind, and the only one recorded here.
                    if not has_subject(row):
                        adapter.record_error("missing_endpoint_subject")
                    continue
                for record in records:
                    try:
                        observation = finding(
                            self.connector_type, self.provider, record, target,
                            capability, excluded,
                        )
                    except ProviderError as exc:
                        adapter.record_error(str(exc))
                        continue
                    if observation:
                        findings.append(observation)
                    if len(findings) >= policy["max_results"]:
                        truncated = True
                        return

        try:
            async with asyncio.timeout(policy["scan_timeout_seconds"]):
                for capability, target in targets:
                    try:
                        await scan_target(capability, target)
                    except ProviderError as exc:
                        code = str(exc)
                        errors.append(code)
                        if code == "invalid_credentials":
                            self.credential_state = "invalid"
                        if code not in {"unsupported_capability"}:
                            self.provider_error = (
                                code if code in {
                                    "invalid_credentials", "access_denied",
                                    "credits_exhausted", "rate_limited",
                                    "provider_application_error",
                                    "provider_rejected_request",
                                    "network_or_invalid_response",
                                } or code.startswith("http_") else "provider_application_error"
                            )
                            break
        except TimeoutError:
            errors.append("scan_deadline_exceeded")

        for start in range(0, len(findings), 500):
            batch = findings[start:start + 500]
            if self.connector_type == "dns":
                await self.submit_observations(job_id, batch)
            else:
                await self.submit_findings(job_id, batch)
        await self.report_readiness()
        if adapter.record_errors:
            errors.extend(adapter.record_error_codes or ["invalid_record"])
        status = (
            "partial" if truncated or (errors and findings) or adapter.record_errors
            else "error" if errors
            else "skipped" if not targets
            else "success"
        )
        return [], {
            "status": status, "error_code": errors[0] if errors else None,
            "requests": adapter.requests, "observations": len(findings),
            "truncated": truncated, "errors": errors[:20],
        }


if __name__ == "__main__":
    IntelligenceConnector().main()
