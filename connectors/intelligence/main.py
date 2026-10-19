"""Opt-in intelligence workers (Netlas) using the normal connector pull protocol."""

import asyncio
import ipaddress
import logging
import os

from opendrp_connector import ConnectorBase
from opendrp_connector.base import ConnectorAPIError, DEFAULT_SUBMIT_BATCH

from providers import (
    Adapter,
    CAPABILITIES,
    KEYS,
    ProviderError,
    brand_certificate_expression,
    core_credential,
    endpoints,
    has_subject,
    host,
    mail_facts,
    query,
    whois_facts,
)

log = logging.getLogger("intelligence")

POLICY = {
    "requests_per_minute": (1, 600, 10),
    "daily_budget": (1, 100000, 100),
    "max_requests": (1, 1000, 20),
    "max_pages": (1, 100, 3),
    "max_results": (1, 5000, 100),
    #: How many of the certificates discovered for a monitored domain are asked about in
    #: turn ("where else is this one served"). 0 switches the reverse search off, which is
    #: a legitimate choice for an account whose certificate quota is tight: what it costs
    #: is the foreign-deployment evidence, and nothing else.
    "max_reverse_lookups": (0, 50, 5),
    #: The largest result set a *broad* expression may have before the worker refuses to
    #: page through it. A brand in a certificate, or in page text, can match a hundred
    #: thousand endpoints, and ten pages of those answer nothing an analyst can act on.
    #: The size is asked for first (``/responses_count/``), so refusing costs one request
    #: instead of the scan's whole budget - and the refusal is reported as a reason, not
    #: as an empty result.
    "max_broad_results": (1, 1000000, 1000),
    "max_targets": (1, 1000, 20),
    "scan_timeout_seconds": (10, 3600, 300),
    "cooldown_seconds": (0, 86400, 60),
}

#: Provider codes that end a scan without turning it into an error.
#:
#: The core refuses a reservation when the account's budget is spent, when an operator
#: disabled the source mid-scan, or when this job's lease is gone. All three mean "no
#: more requests may be sent", and none of them is a provider failure: recorded as
#: ``provider_error`` they would tell the operator their credentials are broken and the
#: readiness row would keep saying so long after the cause passed. They are skip reasons
#: instead, and the job reports which one stopped it.
SKIPPED_CODES = {
    "provider_quota_exhausted",
    "source_disabled",
    "provider_access_denied",
}

#: The capabilities whose result set is counted before any page of it is fetched.
COUNTED_CAPABILITIES = {"body", "certificate_brand"}

#: Codes a single target may refuse *itself* with: the value did not survive the query
#: grammar. One unusable keyword is a skip reason, not a failed scan.
REFUSED_CODES = {"invalid_brand_value", "invalid_search_value", "invalid_favicon_hash"}

#: What only a phishing scan can be asked for. Declared for that module alone: a target
#: list for any other module never contains one of these, and a capability nobody can
#: ask for reads as an offer the connector cannot honour.
#: The operator's acknowledgement that their plan permits a page-body search (F-12,
#: WI-25). It is a separate statement from "run the brand scan": a body search is the
#: broadest question this worker can ask, and the provider's terms decide whether the
#: plan may ask it at all. Named like the DNS workers' public-tier acknowledgement.
HTTP_BODY_ACK_KEY = "http_body_acknowledged"
HTTP_BODY_ACK_ENV = "INTELLIGENCE_HTTP_BODY_ACKNOWLEDGED"


def _acknowledged(value: object) -> bool:
    """A flag from registry config (bool) or the environment (text), one rule."""
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


#: How many observations one submission carries. Smaller than the SDK default
#: (500) on purpose: observations are submitted as the scan discovers them, so a
#: smaller batch makes the job's progress visible while a long provider sweep is
#: still running instead of appearing all at once at the end.
OBSERVATION_BATCH = 50


PHISHING_ONLY_CAPABILITIES = {
    "certificate_brand",
    "body",
    "favicon",
    "whois",
    "mx",
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


def candidate_evidence(
    provider, capability, domain, matched_asset, facts, excluded, evidence
):
    """One fact about a domain the platform has already found, as an observation.

    Nothing here is a discovery, and that is the point: ``phishing_domain`` names a
    candidate the scan was *handed*, so the core attaches the observation to that
    candidate instead of creating one. The capability in ``metadata`` is what separates
    these rows from the discovery findings beside them in the evidence list - "a
    certificate named this name" and "this name was registered last week" are
    different statements, and a list that renders both the same way hides which one the
    scan actually learned.
    """
    if any(owned(domain, item) for item in excluded):
        return None
    return {
        "phishing_domain": domain,
        "matched_asset": matched_asset,
        "detection_source": provider,
        "metadata": {
            "capability": capability,
            "provider": provider,
            "evidence": evidence,
            "association": "confirmed_candidate",
            **facts,
        },
    }


class IntelligenceConnector(ConnectorBase):
    #: The buckets this worker may reserve provider quota against. The capability
    #: list is not a class attribute: it depends on the provider and the module, so
    #: ``readiness_capabilities`` below answers it (WI-10).
    OPERATIONS = ("search", "lookup", "certificate")

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
        schema = manifest.setdefault("config_schema", {})
        for key, limits in POLICY.items():
            schema.setdefault(
                key,
                {
                    "type": "int",
                    "default": limits[2],
                    "description": f"Integer {limits[0]}..{limits[1]}",
                    "label": key.replace("_", " "),
                },
            )
        # Only the phishing worker asks a page-body question, so only its form offers
        # the statement: a DNS or exposure worker showing a switch it never reads is
        # how an operator learns to distrust the form.
        if self.connector_type == "phishing":
            schema.setdefault(
                HTTP_BODY_ACK_KEY,
                {
                    "type": "bool",
                    "default": False,
                    "label": "page body search acknowledged",
                    "description": (
                        "Required before http.body searches run: confirm in your "
                        "account that the plan permits them"
                    ),
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
        if self.connector_type == "phishing":
            return [item for item in CAPABILITIES[self.provider] if item != "passive_dns"]
        return [
            item
            for item in CAPABILITIES[self.provider]
            if item != "passive_dns" and item not in PHISHING_ONLY_CAPABILITIES
        ]

    def credentials_configured(self) -> bool:
        """Whether the container carries this provider's key.

        The key itself may also live in the core and is read at scan time; the
        readiness row is republished after every such read, so an absent variable
        is not reported as a broken account.
        """
        return bool(self.env.get(KEYS[self.provider], "").strip())

    async def submit_observations(self, job_id, observations):
        for start in range(0, len(observations), OBSERVATION_BATCH):
            batch = observations[start : start + OBSERVATION_BATCH]
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

        account_budget = None
        account_budget_left = None
        retry_after = None

        async def reserve(bucket):
            nonlocal account_budget, account_budget_left, retry_after
            try:
                response = await self._request(
                    "POST", "/api/v1/connectors/me/quota/provider",
                    params={"job_id": job_id, "bucket": bucket},
                    headers={"X-Connector-Lease": self._lease_for(job_id)},
                )
            except ConnectorAPIError as exc:
                # The core owns the decision of whether this scan may spend at all: a 429
                # is the account's budget, a 409 is an operator who disabled the source, a
                # 403 is a job whose lease is gone. Each is a stop with a name, and the
                # scan reports which one it was instead of failing as a provider error.
                retry_after = exc.retry_after
                if exc.status_code == 429:
                    raise ProviderError(
                        "provider_quota_exhausted", exc.retry_after
                    ) from exc
                if exc.status_code == 409:
                    raise ProviderError("source_disabled") from exc
                if exc.status_code == 403:
                    raise ProviderError("provider_access_denied") from exc
                raise ProviderError("provider_quota_backend_unavailable") from exc
            try:
                payload = response.json()
            except ValueError:
                payload = {}
            if isinstance(payload, dict):
                budget = payload.get("request_budget")
                if isinstance(budget, int) and not isinstance(budget, bool):
                    account_budget = budget
                remaining = payload.get("remaining_today")
                if isinstance(remaining, int) and not isinstance(remaining, bool):
                    account_budget_left = remaining

        adapter = Adapter(self.provider, self.env, reserve)
        adapter.max_requests = policy["max_requests"]

        params = work.get("params") or {}
        config = work.get("config") or {}
        excluded = [host(value) for value in params.get("exclude", [])]
        skipped: dict[str, int] = {}
        # The body question is the broadest one this worker can ask, so the plan that
        # pays for it is acknowledged separately from the scan being enabled (F-12,
        # WI-25). The refusal is counted where the operator reads the summary.
        body_acknowledged = _acknowledged(
            config.get(HTTP_BODY_ACK_KEY, self.env.get(HTTP_BODY_ACK_ENV, ""))
        )

        #: Every target is ``(capability, value, attribution)``. The third element is what
        #: a finding about the value is *about*: for an owned asset it is the asset itself,
        #: and for a candidate it is the asset that candidate was matched to, so a fact
        #: learned about a look-alike stays attached to the brand an operator monitors.
        targets = [
            ("hostname", host(value), host(value))
            for value in params.get("domains", [])
        ]
        if self.connector_type == "dns":
            targets = [
                ("passive_dns", host(value), host(value))
                for value in params.get("domains", [])
            ]
        if self.connector_type == "exposure":
            targets.extend(
                ("ip", str(ipaddress.ip_address(value)), str(ipaddress.ip_address(value)))
                for value in params.get("ips", [])
            )
        if self.connector_type == "phishing":
            # A phishing target is a *name*. An address is not one: what the module looks
            # for is a domain that claims to be ours, and an endpoint serving a copy is
            # evidence about a name. ``ips`` is therefore not read here at all - the
            # exposure module is where addresses are scanned.
            domains = [host(value) for value in params.get("domains", [])]
            targets = [("certificate", value, value) for value in domains]
            # Our own icon, asked about where else it is served. The question starts from
            # a domain we own, because the icon hash is read from the provider's own view
            # of that endpoint.
            targets.extend(("favicon", value, value) for value in domains)
            targets.extend(
                ("title", str(value), str(value))
                for value in params.get("keyword_titles", [])
            )
            brands = [
                str(item.get("value")).strip()
                for item in params.get("keyword_domains", [])
                if isinstance(item, dict) and item.get("type") == "keyword_domain"
            ]
            targets.extend(("certificate_brand", brand, brand) for brand in brands)
            if body_acknowledged:
                targets.extend(("body", brand, brand) for brand in brands)
            elif brands:
                skipped["licence_acknowledgement_required"] = len(brands)
            for item in params.get("candidates", []) or []:
                if not isinstance(item, dict):
                    skipped["candidate_target_refused"] = (
                        skipped.get("candidate_target_refused", 0) + 1
                    )
                    continue
                try:
                    candidate = host(item.get("value"))
                except ProviderError:
                    skipped["candidate_target_refused"] = (
                        skipped.get("candidate_target_refused", 0) + 1
                    )
                    continue
                if any(owned(candidate, item_) for item_ in excluded):
                    # A name the platform owns is never a candidate, whatever a verdict
                    # says: the exclude list is what keeps an owned host from being
                    # reported as a look-alike of itself.
                    continue
                matched = str(item.get("matched_asset") or "").strip()[:512] or candidate
                targets.extend(
                    (
                        ("hostname", candidate, matched),
                        ("whois", candidate, matched),
                        ("mx", candidate, matched),
                    )
                )

        findings, errors = [], []
        truncated = len(targets) > policy["max_targets"]
        targets = targets[: policy["max_targets"]]

        def collect(rows, capability, attribution, evidence=None):
            """Turn provider rows into findings, one record at a time."""
            nonlocal truncated
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
                            self.connector_type, self.provider, record,
                            attribution, capability, excluded,
                        )
                    except ProviderError as exc:
                        adapter.record_error(str(exc))
                        continue
                    if observation:
                        if evidence:
                            observation = {
                                **observation,
                                "metadata": {
                                    **observation["metadata"],
                                    "evidence": evidence,
                                },
                            }
                        findings.append(observation)
                    if len(findings) >= policy["max_results"]:
                        truncated = True
                        return
        async def scan_target(capability, target, attribution):
            nonlocal truncated
            if capability not in capabilities:
                raise ProviderError("unsupported_capability")

            if capability in COUNTED_CAPABILITIES:
                # Broad expressions are counted before they are paged: the size of the
                # result set is one request, and it is the only way to tell "our brand is
                # in twelve certificates" from "our brand appears on a hundred thousand
                # pages". The second is not scanned at all, and says so.
                try:
                    expression = (
                        brand_certificate_expression(target)
                        if capability == "certificate_brand"
                        else query(self.provider, capability, target)
                    )
                    count = await adapter.count_responses(
                        expression,
                        bucket=(
                            "certificate"
                            if capability == "certificate_brand"
                            else "search"
                        ),
                    )
                except ProviderError as exc:
                    if str(exc) in REFUSED_CODES:
                        skipped["target_refused"] = skipped.get("target_refused", 0) + 1
                        return
                    raise
                if count > policy["max_broad_results"]:
                    skipped["expression_too_broad"] = (
                        skipped.get("expression_too_broad", 0) + 1
                    )
                    return

            if capability == "favicon":
                hashes = await adapter.own_favicon_hashes(
                    target, max_results=policy["max_results"]
                )
                self.credential_state = "valid"
                self.provider_error = None
                if not hashes:
                    # Nothing to search *with*: the provider reports no icon hash for this
                    # endpoint. Reported as a skip, because "our icon is nowhere else" and
                    # "no icon hash was available to ask about" are different answers and
                    # a bare zero cannot tell them apart.
                    skipped["favicon_hash_unavailable"] = (
                        skipped.get("favicon_hash_unavailable", 0) + 1
                    )
                    return
                for algorithm, name, evidence in (
                    ("sha256", "favicon", "netlas_favicon_sha256"),
                    ("perceptual", "favicon_similar", "netlas_favicon_perceptual"),
                ):
                    digest = hashes.get(algorithm)
                    if not digest or len(findings) >= policy["max_results"]:
                        continue
                    try:
                        rows = await adapter.search_favicon(
                            algorithm, digest,
                            max_pages=policy["max_pages"],
                            max_results=max(1, policy["max_results"] - len(findings)),
                        )
                    except ProviderError as exc:
                        adapter.record_error(str(exc))
                        continue
                    truncated |= adapter.truncated
                    collect(rows, name, attribution, evidence)
                return

            if capability == "whois":
                rows = await adapter.search_whois(
                    target, max_pages=min(2, policy["max_pages"]),
                    max_results=policy["max_results"],
                )
                facts = whois_facts(rows, adapter)
                self.credential_state = "valid"
                self.provider_error = None
                truncated |= adapter.truncated
                if not facts:
                    skipped["whois_unavailable"] = skipped.get("whois_unavailable", 0) + 1
                    return
                observation = candidate_evidence(
                    self.provider, "whois", target, attribution, facts, excluded,
                    "netlas_whois_collection",
                )
                if observation:
                    findings.append(observation)
                return

            if capability == "mx":
                rows = await adapter.search_mail_records(
                    target, max_pages=min(2, policy["max_pages"]),
                    max_results=policy["max_results"],
                )
                facts = mail_facts(rows, adapter)
                self.credential_state = "valid"
                self.provider_error = None
                truncated |= adapter.truncated
                # A domain without MX answers the question too: "this look-alike cannot
                # receive mail" is a fact an analyst acts on, and it is stored rather than
                # silently dropped because the answer was negative.
                observation = candidate_evidence(
                    self.provider, "mx", target, attribution, facts, excluded,
                    "netlas_passive_dns_mx",
                )
                if observation:
                    findings.append(observation)
                return
            if capability == "passive_dns":
                rows = await adapter.search_domains(
                    target, max_pages=policy["max_pages"],
                    max_results=max(1, policy["max_results"] - len(findings)),
                )
                observations = adapter.dns_observations(target, rows)
                findings.extend(observations[: max(0, policy["max_results"] - len(findings))])
                discovered = []
                if len(findings) < policy["max_results"]:
                    cert_rows = await adapter.search_certificates(
                        target, max_pages=policy["max_pages"],
                        max_results=max(1, policy["max_results"] - len(findings)),
                    )
                    for row in cert_rows:
                        fingerprint = row.get("fingerprint_sha256")
                        if isinstance(fingerprint, str):
                            discovered.append(fingerprint)
                        try:
                            records = endpoints(row, adapter)
                        except ProviderError as exc:
                            adapter.record_error(str(exc))
                            continue
                        for record in records:
                            try:
                                observation = finding(
                                    self.connector_type, self.provider, record,
                                    attribution, "certificate", excluded,
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
                # The reverse question, asked about the certificates that name a monitored
                # domain: where else is this one being served. It is what turns "our
                # certificate" and "an address that is not ours" into one finding, and it
                # is the only path in this connector that produces a foreign address with
                # the JARM and organisation the scoring rules read.
                for fingerprint in list(dict.fromkeys(discovered))[: policy["max_reverse_lookups"]]:
                    if len(findings) >= policy["max_results"]:
                        truncated = True
                        break
                    try:
                        responses = await adapter.search_certificate_responses(
                            fingerprint, max_pages=policy["max_pages"],
                            max_results=max(1, policy["max_results"] - len(findings)),
                        )
                    except ProviderError as exc:
                        adapter.record_error(str(exc))
                        continue
                    observations = adapter.certificate_responses(target, responses)
                    findings.extend(observations[: max(0, policy["max_results"] - len(findings))])
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
            collect(rows, capability, attribution)

        try:
            async with asyncio.timeout(policy["scan_timeout_seconds"]):
                for capability, target, attribution in targets:
                    try:
                        await scan_target(capability, target, attribution)
                    except ProviderError as exc:
                        code = str(exc)
                        if code in SKIPPED_CODES:
                            skipped[code] = skipped.get(code, 0) + 1
                            break
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

        for start in range(0, len(findings), DEFAULT_SUBMIT_BATCH):
            batch = findings[start : start + DEFAULT_SUBMIT_BATCH]
            if self.connector_type == "dns":
                await self.submit_observations(job_id, batch)
            else:
                await self.submit_findings(job_id, batch)
        await self.report_readiness()
        if adapter.record_errors:
            errors.extend(adapter.record_error_codes or ["invalid_record"])
        status = (
            "partial" if truncated or (errors and findings) or adapter.record_errors
            or (skipped and findings)
            else "error" if errors
            else "skipped" if skipped or not targets
            else "success"
        )
        return [], {
            "status": status, "error_code": errors[0] if errors else None,
            "requests": adapter.requests, "observations": len(findings),
            "truncated": truncated, "errors": errors[:20],
            # What the scan could not do, and what it spent doing what it could. A job
            # that reports observation counts alone reads as a complete scan, and a
            # skipped target is then indistinguishable from one that found nothing.
            "skipped": skipped,
            "spent": adapter.requests,
            "budget_left": max(0, adapter.max_requests - adapter.requests),
            "daily_budget": account_budget,
            "daily_budget_left": account_budget_left,
            "retry_after_seconds": retry_after,
        }


if __name__ == "__main__":
    IntelligenceConnector().main()
