"""Exposure endpoint connectors (Netlas or Shodan) using the normal connector pull protocol.

One image serves both providers; ``EXPOSURE_PROVIDER`` selects the lookup client.
Each scan asks the provider which services a target exposes and submits one
observation per distinct port. Ownership is decided by where the endpoint came
from: an IP target is exact, and a domain target is associated with the address
its name resolved to. A shared address alone never proves that a domain owns it.
"""

import asyncio
import ipaddress
import logging
import os

from opendrp_connector import ConnectorBase
from opendrp_connector.base import DEFAULT_SUBMIT_BATCH, ConnectorAPIError

from endpoint_providers import KEY_ENV, EndpointClient, ProviderError, host

log = logging.getLogger("exposure_endpoints")

POLICY = {
    "max_requests": (1, 200, 20),
    "max_targets": (1, 200, 20),
}
CAPABILITY = "endpoint_lookup"
OPERATION = "lookup"

#: Failures that say "this attempt failed", not "this account cannot scan":
#: another target is worth trying, because the provider did answer the ones before
#: it. A refused reservation (`quota_denied`, `source_disabled`,
#: `provider_access_denied`, `quota_backend_unavailable`), `invalid_credentials`,
#: `access_denied` and an exhausted request budget are deliberately absent — the
#: next target would fail for the same reason, and trying it spends a request to
#: learn nothing.
RECOVERABLE_ERRORS = frozenset(
    {
        "network_or_invalid_response",
        "rate_limited",
        "provider_rejected_request",
        "response_too_large",
        "invalid_response",
    }
)

#: How many targets in a row may fail before the scan stops. One flaky lookup must
#: not throw away the rest of the inventory, and a provider that is down must not
#: be asked about two hundred targets to prove it.
MAX_CONSECUTIVE_FAILURES = 3


class ExposureEndpointsConnector(ConnectorBase):
    CAPABILITIES = (CAPABILITY,)
    OPERATIONS = (OPERATION,)

    def __init__(self):
        self.provider = os.environ.get("EXPOSURE_PROVIDER", "")
        if self.provider not in KEY_ENV:
            raise RuntimeError("EXPOSURE_PROVIDER must be one of: netlas, shodan")
        super().__init__()
        if self.connector_type != "exposure":
            raise RuntimeError("exposure endpoint connectors must declare CONNECTOR_TYPE=exposure")
        self.credential_state = "unknown"
        self.provider_error = None
        #: Test seam: an httpx transport replacing the network in the lookup client.
        self.transport = None

    def manifest_payload(self):
        manifest = super().manifest_payload()
        manifest.setdefault(
            "config_schema",
            {
                key: {
                    "type": "int",
                    "default": default,
                    "description": f"Integer {low}..{high}",
                    "label": key.replace("_", " "),
                }
                for key, (low, high, default) in POLICY.items()
            },
        )
        return manifest

    async def register(self):
        await super().register()
        await self.report_readiness()

    def credentials_configured(self) -> bool:
        """Whether the selected provider's key is in this container's environment.

        A key stored in the core is fetched per scan and is not visible here, so the
        readiness row is refreshed after the credential read.
        """
        return bool((self.env.get(KEY_ENV[self.provider]) or "").strip())

    async def _reserve(self, job_id, bucket):
        try:
            await self._request(
                "POST",
                "/api/v1/connectors/me/quota/provider",
                params={"job_id": job_id, "bucket": bucket},
                headers={"X-Connector-Lease": self._lease_for(job_id)},
            )
        except ConnectorAPIError as exc:
            # A refused reservation must stop the scan, not let a request slip past quota.
            # The core's status says which refusal it is, and each one sends the operator
            # to a different page: a spent budget, a source an operator disabled, an
            # account nobody approved, or a quota backend that is down. Collapsing them
            # into one word made the first run of a new connector read as "out of quota".
            code = {
                429: "quota_denied",
                409: "source_disabled",
                403: "provider_access_denied",
                503: "quota_backend_unavailable",
            }.get(exc.status_code, "quota_denied")
            raise ProviderError(code) from exc

    def _policy(self, config):
        policy = {}
        for key, (low, high, default) in POLICY.items():
            value = (config or {}).get(key, default)
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise ValueError("invalid_scan_policy")
            policy[key] = value
        return policy

    async def run_scan(self, work):
        policy = self._policy(work.get("config"))
        job_id = str(work["job_id"])
        params = work.get("params") or {}

        errors = []
        ips, domains = [], []
        for raw in params.get("ips", []):
            try:
                ips.append(str(ipaddress.ip_address(raw)))
            except ValueError:
                errors.append("invalid_endpoint")
        for raw in params.get("domains", []):
            try:
                domains.append(host(raw))
            except ProviderError:
                errors.append("invalid_endpoint")

        targets = [("ip", value) for value in ips] + [("domain", value) for value in domains]
        truncated = len(targets) > policy["max_targets"]
        targets = targets[: policy["max_targets"]]

        async def reserve(bucket):
            await self._reserve(job_id, bucket)

        api_key = os.environ.get(KEY_ENV[self.provider], "")
        client = EndpointClient(
            self.provider,
            api_key,
            reserve,
            max_requests=policy["max_requests"],
            transport=self.transport,
        )
        findings = []
        seen = set()

        def add(subject, matched, hostname, records, association):
            for record in records:
                key = (subject, record["port"], record["transport"])
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    {
                        "subject": subject,
                        "matched_asset": matched,
                        "hostname": hostname,
                        "port": record["port"],
                        "transport": record["transport"],
                        "protocol": record["protocol"],
                        "observed_at": None,
                        "metadata": {
                            "capability": CAPABILITY,
                            "provider": self.provider,
                            "association": association,
                            "resolved_ip": record["ip"] or "",
                        },
                    }
                )

        resolved = {}
        domain_targets = [value for kind, value in targets if kind == "domain"]
        #: Targets the scan could not ask about. It is the denominator that makes
        #: "nothing is exposed" different from "we never got there".
        skipped = 0
        consecutive = 0
        try:
            if self.provider == "shodan" and domain_targets:
                resolved = await client.resolve(domain_targets)
            async with asyncio.timeout(300):
                for position, (kind, value) in enumerate(targets):
                    try:
                        if kind == "ip":
                            add(value, value, None, await client.host_ports(value), "exact_ip")
                        elif self.provider == "netlas":
                            records = await client.host_ports(value)
                            add(value, value, value, records, "domain_resolved_ip")
                        else:
                            address = resolved.get(value)
                            if address is None:
                                errors.append("unresolved_domain")
                                skipped += 1
                                continue
                            records = await client.host_ports(address)
                            add(value, value, value, records, "domain_resolved_ip")
                    except ProviderError as exc:
                        code = str(exc)
                        errors.append(code)
                        self.provider_error = code
                        skipped += 1
                        if code not in RECOVERABLE_ERRORS:
                            # The account, the budget or the capability is the
                            # problem: the remaining targets would fail the same
                            # way, and each attempt would still be charged.
                            skipped += len(targets) - position - 1
                            if code == "invalid_credentials":
                                self.credential_state = "invalid"
                            break
                        consecutive += 1
                        if consecutive >= MAX_CONSECUTIVE_FAILURES:
                            skipped += len(targets) - position - 1
                            break
                        continue
                    consecutive = 0
        except ProviderError as exc:
            # The batched resolve, before any target was asked about.
            errors.append(str(exc))
            self.provider_error = str(exc)
            skipped += len(domain_targets)
            if str(exc) == "invalid_credentials":
                self.credential_state = "invalid"
        except TimeoutError:
            errors.append("scan_deadline_exceeded")
            skipped += len(targets)

        if client.requests and self.credential_state != "invalid":
            # A provider that answered at least one target proved the key works,
            # even when another target timed out: "invalid credentials" is a
            # verdict about the account, not about the scan.
            self.credential_state = "valid"
        self.provider_error = errors[-1] if errors else None

        for start in range(0, len(findings), DEFAULT_SUBMIT_BATCH):
            await self.submit_findings(job_id, findings[start : start + DEFAULT_SUBMIT_BATCH])
        await self.report_readiness()

        if truncated or (errors and findings):
            status = "partial"
        elif errors:
            status = "error"
        elif not targets:
            status = "skipped"
        else:
            status = "success"
        return [], {
            "status": status,
            "error_code": errors[0] if errors else None,
            "requests": client.requests,
            "observations": len(findings),
            "truncated": truncated,
            "targets_total": len(targets),
            "targets_skipped": skipped,
            "errors": errors[:20],
        }


if __name__ == "__main__":
    ExposureEndpointsConnector().main()
