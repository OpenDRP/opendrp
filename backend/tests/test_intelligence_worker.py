import importlib.util
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest

from app.schemas.connector import ExposureFinding
from app.services.connector_manifest import ConfigField

_ROOT = (
    Path("/connectors")
    if Path("/connectors").exists()
    else Path(__file__).resolve().parents[2] / "connectors"
)
sys.path.insert(0, str(_ROOT / "base"))
sys.path.insert(0, str(_ROOT / "intelligence"))
_spec = importlib.util.spec_from_file_location(
    "intelligence_worker", _ROOT / "intelligence/main.py"
)
worker = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(worker)


@pytest.fixture
def connector(monkeypatch):
    for key, value in {
        "CORE_URL": "http://core:8000",
        "CONNECTOR_TOKEN": "fixture-core-token",
        "CONNECTOR_NAME": "netlas-exposure",
        "CONNECTOR_TYPE": "exposure",
        "CONNECTOR_JOB_TYPE": "exposure.netlas",
        "CONNECTOR_ASSET_TYPES": "domain,ip_address",
        "INTELLIGENCE_PROVIDER": "netlas",
        "NETLAS_API_TOKEN": "fixture-provider-token",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("CONNECTOR_CONFIG_SCHEMA", raising=False)
    return worker.IntelligenceConnector()


@pytest.mark.asyncio
async def test_registration_only_reports_local_readiness(connector):
    connector._request = AsyncMock(return_value=httpx.Response(200, json={}))
    await connector.register()
    # Register, then read the account's provider key from the core, then report
    # readiness: the key is rotated in the core, so it is fetched per worker
    # rather than read once from the container's environment.
    assert connector._request.await_count == 3
    assert connector._request.await_args_list[0].args[1] == "/api/v1/connectors/register"
    assert connector._request.await_args_list[1].args[1] == "/api/v1/connectors/me/credential"
    payload = connector._request.await_args_list[-1].kwargs["json"]
    assert (
        payload["credentials_configured"] and payload["credential_state"] == "unknown"
    )
    assert payload["provider_error"] is None
    assert "passive_dns" not in payload["capabilities"]
    for schema in connector.manifest["config_schema"].values():
        ConfigField.model_validate(schema)


@pytest.mark.asyncio
async def test_scan_uses_lease_quota_and_submits_only_owned_endpoints(
    connector, monkeypatch
):
    from providers import Adapter

    created = []

    def factory(provider, env, reserve):
        def handler(request):
            assert request.url.host == "app.netlas.io"
            return httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "data": {
                                "host": "www.example.com",
                                "ip": "192.0.2.1",
                                "port": 443,
                            }
                        },
                        {
                            "data": {
                                "host": "foreign.example.net",
                                "ip": "192.0.2.1",
                                "port": 443,
                            }
                        },
                    ]
                },
            )

        source = Adapter(provider, env, reserve, transport=httpx.MockTransport(handler))
        created.append(source)
        return source

    monkeypatch.setattr(worker, "Adapter", factory)
    connector._active_job = ("job-fixture", "lease-fixture")
    connector._request = AsyncMock(
        return_value=httpx.Response(200, json={"reserved": True})
    )
    connector.submit_findings = AsyncMock(return_value={"accepted": 1})
    findings, summary = await connector.run_scan(
        {
            "job_id": "job-fixture",
            "config": {},
            "params": {"domains": ["example.com"], "exclude": ["example.com"]},
        }
    )
    assert findings == [] and summary["status"] == "success"
    assert summary["observations"] == 1
    # The scan refreshes the account credential before it touches the provider, so
    # the quota reservation is not necessarily the first core call: find it by the
    # bucket it names rather than by position.
    reservation = next(
        call
        for call in connector._request.await_args_list
        if call.kwargs.get("params", {}).get("bucket")
    )
    assert reservation.kwargs["params"]["job_id"] == "job-fixture"
    assert reservation.kwargs["headers"]["X-Connector-Lease"] == "lease-fixture"
    submitted = connector.submit_findings.await_args.args[1]
    assert ExposureFinding.model_validate(submitted[0]).subject == "www.example.com"
    assert created[0].requests == 1
    readiness = connector._request.await_args_list[-1].kwargs["json"]
    assert (
        readiness["credential_state"] == "valid" and readiness["provider_error"] is None
    )


@pytest.mark.asyncio
async def test_netlas_dns_security_scans_documented_passive_dns_without_live_resolver_calls(
    connector, monkeypatch
):
    from providers import Adapter

    connector.connector_type = "dns"
    connector.name = "dns-netlas"
    connector._active_job = ("job-fixture", "lease-fixture")
    seen = []

    def factory(provider, env, reserve):
        def handler(request):
            seen.append(request)
            if request.url.path.endswith("/certs/"):
                return httpx.Response(200, json={"items": []})
            return httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "data": {
                                "domain": "www.example.com",
                                "a": ["192.0.2.10"],
                                "aaaa": ["2001:db8::10"],
                                "ns": ["ns1.example.com"],
                                "last_updated": "2026-01-01T00:00:00Z",
                            }
                        }
                    ]
                },
            )

        return Adapter(provider, env, reserve, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(worker, "Adapter", factory)
    connector._request = AsyncMock(
        return_value=httpx.Response(200, json={"reserved": True})
    )
    connector.submit_findings = AsyncMock(
        side_effect=lambda _job, rows: {"accepted": len(rows), "rejected": 0}
    )

    _, summary = await connector.run_scan(
        {
            "job_id": "job-fixture",
            "config": {},
            "params": {"domains": ["example.com"]},
        }
    )

    assert len(seen) == 2
    assert seen[0].url.path == "/api/domains/"
    assert seen[1].url.path == "/api/certs/"
    assert seen[0].url.params["q"] == "domain:*.example.com"
    assert summary["status"] == "success" and summary["observations"] == 3
    submitted = connector.submit_findings.await_args.args[1]
    assert {row["record_type"] for row in submitted} == {"A", "AAAA", "NS"}
    assert all(row["observation_type"] == "passive_dns" for row in submitted)
    reservations = [
        call.kwargs["params"]["bucket"]
        for call in connector._request.await_args_list
        if call.kwargs.get("params", {}).get("bucket")
    ]
    assert reservations == ["search", "certificate"]
    readiness = connector._request.await_args_list[-1].kwargs["json"]
    assert readiness["capabilities"] == ["passive_dns", "certificate"]
    assert "certificate" in readiness["operations"]


@pytest.mark.asyncio
async def test_netlas_dns_security_collects_certificate_evidence_through_certificate_quota(
    connector, monkeypatch
):
    from providers import Adapter

    connector.connector_type = "dns"
    connector.name = "dns-netlas"
    connector._active_job = ("job-fixture", "lease-fixture")
    seen = []

    def factory(provider, env, reserve):
        def handler(request):
            seen.append(request)
            if request.url.path.endswith("/certs/"):
                return httpx.Response(
                    200,
                    json={
                        "items": [
                            {
                                "data": {
                                    "names": [
                                        "example.com",
                                        "www.example.com",
                                        "*.example.com",
                                    ],
                                    "fingerprint_sha256": "b" * 64,
                                    "subject_dn": "CN=example.com",
                                    "issuer_dn": "CN=Fixture CA",
                                    "validity": {
                                        "start": "2025-01-01T00:00:00Z",
                                        "end": "2026-01-01T00:00:00Z",
                                    },
                                }
                            }
                        ]
                    },
                )
            if request.url.path.endswith("/responses/"):
                # The reverse question, asked about the certificate just discovered:
                # where else is it being served. It stays empty here - the shape of the
                # observation, not of the answer, is what this test pins - so the third
                # request is asserted below rather than an observation it would produce.
                return httpx.Response(200, json={"items": []})
            return httpx.Response(200, json={"items": []})

        return Adapter(provider, env, reserve, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(worker, "Adapter", factory)
    connector._request = AsyncMock(
        return_value=httpx.Response(200, json={"reserved": True})
    )
    connector.submit_findings = AsyncMock(
        side_effect=lambda _job, rows: {"accepted": len(rows), "rejected": 0}
    )
    _, summary = await connector.run_scan(
        {
            "job_id": "job-fixture",
            "config": {},
            "params": {"domains": ["example.com"]},
        }
    )
    assert len(seen) == 3
    assert [request.url.path for request in seen] == [
        "/api/domains/",
        "/api/certs/",
        "/api/responses/",
    ]
    # The reverse search is keyed by the fingerprint that was just discovered, and it is
    # paid for from the certificate budget like every other certificate operation.
    assert seen[2].url.params["q"] == 'certificate.fingerprint_sha256:"' + "b" * 64 + '"'
    assert summary["status"] == "success" and summary["observations"] == 2
    assert summary["error_code"] is None
    rows = connector.submit_findings.await_args.args[1]
    assert [row["subject"] for row in rows] == ["example.com", "www.example.com"]
    assert all(row["observation_type"] == "certificate" for row in rows)
    assert rows[0]["metadata"]["id"] == "b" * 64
    reservations = [
        call.kwargs["params"]["bucket"]
        for call in connector._request.await_args_list
        if call.kwargs.get("params", {}).get("bucket")
    ]
    assert reservations == ["search", "certificate", "certificate"]




@pytest.mark.asyncio
async def test_malformed_provider_record_keeps_valid_siblings_and_marks_scan_partial(
    connector, monkeypatch
):
    class FakeAdapter:
        requests = 1
        truncated = False
        record_errors = 0
        record_error_codes = []

        def record_error(self, code="invalid_record"):
            self.record_errors += 1
            self.record_error_codes.append(code)

        async def search(self, capability, value, **kwargs):
            return [
                {"host": "bad.example.com", "ip": "192.0.2.4", "port": 70000},
                {"host": "good.example.com", "ip": "192.0.2.5", "port": 443},
                {"port": 443},
            ]

    monkeypatch.setattr(worker, "Adapter", lambda *args: FakeAdapter())
    connector._active_job = ("job-fixture", "lease-fixture")
    connector._request = AsyncMock(
        return_value=httpx.Response(200, json={"reserved": True})
    )
    connector.submit_findings = AsyncMock(return_value={"accepted": 1})

    _, summary = await connector.run_scan(
        {
            "job_id": "job-fixture",
            "config": {},
            "params": {"domains": ["example.com"]},
        }
    )

    assert summary["status"] == "partial"
    assert summary["observations"] == 1
    assert summary["error_code"] == "invalid_endpoint_port"
    assert summary["errors"] == ["invalid_endpoint_port", "missing_endpoint_subject"]
    submitted = connector.submit_findings.await_args.args[1]
    assert len(submitted) == 1 and submitted[0]["subject"] == "good.example.com"


@pytest.mark.asyncio
async def test_provider_access_failure_is_reported_as_safe_readiness_code(
    connector, monkeypatch
):
    from providers import Adapter

    def factory(provider, env, reserve):
        return Adapter(
            provider,
            env,
            reserve,
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    400, json={"detail": "API key not found: do-not-leak"}
                )
            ),
        )

    monkeypatch.setattr(worker, "Adapter", factory)
    connector._active_job = ("job-fixture", "lease-fixture")
    connector._request = AsyncMock(
        return_value=httpx.Response(200, json={"reserved": True})
    )
    connector.submit_findings = AsyncMock(return_value={"accepted": 0})
    _, summary = await connector.run_scan(
        {"job_id": "job-fixture", "config": {}, "params": {"domains": ["example.com"]}}
    )

    assert summary["status"] == "error"
    assert summary["error_code"] == "invalid_credentials"
    readiness = connector._request.await_args_list[-1].kwargs["json"]
    assert readiness["credential_state"] == "invalid"
    assert readiness["provider_error"] == "invalid_credentials"
    assert "do-not-leak" not in str(readiness)


def test_shared_ip_is_not_ownership_and_phishing_excludes_owned_hosts():
    record = {
        "subject": "foreign.example.net",
        "ip": "192.0.2.1",
        "port": 443,
        "transport": "tcp",
        "protocol": "https",
        "observed_at": None,
        "title": "",
    }
    assert (
        worker.finding("exposure", "netlas", record, "example.com", "hostname", [])
        is None
    )
    assert (
        worker.finding(
            "phishing",
            "netlas",
            {**record, "subject": "www.example.com"},
            "example.com",
            "certificate",
            ["example.com"],
        )
        is None
    )
    assert (
        worker.finding(
            "phishing", "netlas", record, "example.com", "certificate", ["example.com"]
        )["metadata"]["verdict"]
        == "candidate_not_verified"
    )


@pytest.fixture
def phishing(connector):
    connector.connector_type = "phishing"
    connector.name = "phishing-netlas"
    return connector


def recording_adapter(seen, **returns):
    """A provider stand-in that records the questions instead of answering them."""

    class RecordingAdapter:
        requests = 0
        truncated = False
        record_errors = 0
        record_error_codes = []

        def record_error(self, code="invalid_record"):
            self.record_errors += 1
            self.record_error_codes.append(code)

        async def count_responses(self, expression, *, bucket="search"):
            seen.append(("count", expression, bucket))
            return returns.get("count", 0)

        async def search(self, capability, value, **kwargs):
            seen.append(("search", capability, value))
            return []

        async def search_favicon(self, algorithm, value, **kwargs):
            seen.append(("favicon", algorithm, value))
            return []

        async def own_favicon_hashes(self, value, **kwargs):
            seen.append(("own_favicon", value))
            return returns.get("favicon", {})

        async def search_whois(self, value, **kwargs):
            seen.append(("whois", value))
            return []

        async def search_mail_records(self, value, **kwargs):
            seen.append(("mx", value))
            return []

    return RecordingAdapter


def test_the_brand_questions_are_declared_where_they_can_be_asked(connector):
    connector.connector_type = "phishing"
    assert {"certificate_brand", "body", "favicon", "whois", "mx"} <= set(
        connector.readiness_capabilities()
    )
    connector.connector_type = "exposure"
    # A brand, an icon and a candidate fact are not questions an exposure scan can be
    # handed a target for, so they are not offered there.
    assert connector.readiness_capabilities() == [
        "hostname",
        "ip",
        "certificate",
        "title",
        "lookup",
    ]
    connector.connector_type = "dns"
    assert connector.readiness_capabilities() == ["passive_dns", "certificate"]


@pytest.mark.asyncio
async def test_a_phishing_scan_asks_brands_candidates_and_icons_but_never_addresses(
    phishing, monkeypatch
):
    import providers

    seen = []
    monkeypatch.setattr(worker, "Adapter", lambda *args: recording_adapter(seen)())
    phishing._active_job = ("job-fixture", "lease-fixture")
    phishing._request = AsyncMock(
        return_value=httpx.Response(
            200,
            json={"reserved": True, "request_budget": 100, "remaining_today": 98},
        )
    )
    phishing.submit_findings = AsyncMock(return_value={"accepted": 0})
    _, summary = await phishing.run_scan(
        {
            "job_id": "job-fixture",
            "config": {"http_body_acknowledged": True},
            "params": {
                "domains": ["example.com"],
                "keyword_domains": [
                    {"value": "example.com", "type": "domain"},
                    {"value": "ACME Corp.", "type": "keyword_domain"},
                ],
                "keyword_titles": ["ACME portal"],
                "ips": ["203.0.113.7"],
                "candidates": [
                    {"value": "acme-login.example.net", "matched_asset": "ACME"}
                ],
                "exclude": ["example.com", "203.0.113.7"],
            },
        }
    )
    assert ("search", "certificate", "example.com") in seen
    assert ("search", "certificate_brand", "ACME Corp.") in seen
    assert ("search", "body", "ACME Corp.") in seen
    assert ("search", "title", "ACME portal") in seen
    assert ("search", "hostname", "acme-login.example.net") in seen
    assert ("whois", "acme-login.example.net") in seen
    assert ("mx", "acme-login.example.net") in seen
    assert ("own_favicon", "example.com") in seen
    # An address is not a phishing target: what the module looks for is a name, and the
    # exposure module is where addresses are scanned.
    assert [entry for entry in seen if entry[1] == "ip"] == []
    assert not any("203.0.113.7" in str(entry) for entry in seen)
    # The broad questions are counted before any page of them is fetched, and the count
    # is charged to the certificate budget exactly when the search is.
    brand = providers.brand_certificate_expression("ACME Corp.")
    assert ("count", brand, "certificate") in seen
    assert seen.index(("count", brand, "certificate")) < seen.index(
        ("search", "certificate_brand", "ACME Corp.")
    )
    assert ("count", 'http.body:"ACME Corp."', "search") in seen
    assert summary["errors"] == []


@pytest.mark.asyncio
async def test_a_result_set_beyond_the_policy_is_skipped_by_name(phishing, monkeypatch):
    seen = []
    monkeypatch.setattr(
        worker, "Adapter", lambda *args: recording_adapter(seen, count=1000000)()
    )
    phishing._active_job = ("job-fixture", "lease-fixture")
    phishing._request = AsyncMock(
        return_value=httpx.Response(200, json={"reserved": True})
    )
    phishing.submit_findings = AsyncMock(return_value={"accepted": 0})
    _, summary = await phishing.run_scan(
        {
            "job_id": "job-fixture",
            "config": {"http_body_acknowledged": True},
            "params": {
                "keyword_domains": [{"value": "ACME", "type": "keyword_domain"}]
            },
        }
    )
    # The count is the only request a refused expression costs, and the refusal is
    # reported: a scan that silently found nothing looks like a clean answer.
    assert ("search", "body", "ACME") not in seen
    assert ("search", "certificate_brand", "ACME") not in seen
    assert summary["skipped"]["expression_too_broad"] == 2
    assert summary["status"] == "skipped"
    assert summary["errors"] == [] and summary["error_code"] is None


@pytest.mark.asyncio
async def test_a_body_search_without_the_plan_acknowledgement_is_named_not_sent(
    phishing, monkeypatch
):
    """F-12/WI-25: the broadest question waits for the plan it is billed to."""
    seen = []
    monkeypatch.setattr(worker, "Adapter", lambda *args: recording_adapter(seen)())
    phishing._active_job = ("job-fixture", "lease-fixture")
    phishing._request = AsyncMock(
        return_value=httpx.Response(200, json={"reserved": True})
    )
    phishing.submit_findings = AsyncMock(return_value={"accepted": 0})

    _, summary = await phishing.run_scan(
        {
            "job_id": "job-fixture",
            "config": {},
            "params": {
                "keyword_domains": [{"value": "ACME", "type": "keyword_domain"}]
            },
        }
    )

    # Neither the count nor a page of the body expression was requested, and the
    # summary says why instead of leaving a switch that appears to do nothing.
    assert not any(entry[0] == "count" and "http.body" in str(entry) for entry in seen)
    assert ("search", "body", "ACME") not in seen
    assert summary["skipped"]["licence_acknowledgement_required"] == 1
    assert summary["errors"] == []


@pytest.mark.asyncio
async def test_a_quota_refusal_ends_the_scan_as_a_reason_not_an_error(
    connector, monkeypatch
):
    from opendrp_connector.base import ConnectorAPIError
    from providers import Adapter

    monkeypatch.setattr(
        worker,
        "Adapter",
        lambda *args: Adapter(
            args[0],
            args[1],
            args[2],
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json={"items": []})
            ),
        ),
    )
    connector._active_job = ("job-fixture", "lease-fixture")

    async def request(method, path, **kwargs):
        if path == "/api/v1/connectors/me/quota/provider":
            raise ConnectorAPIError(
                429, "Provider request budget exhausted", retry_after=45
            )
        return httpx.Response(200, json={})

    connector._request = AsyncMock(side_effect=request)
    connector.submit_findings = AsyncMock(return_value={"accepted": 0})
    _, summary = await connector.run_scan(
        {"job_id": "job-fixture", "config": {}, "params": {"domains": ["example.com"]}}
    )
    assert summary["status"] == "skipped"
    assert summary["skipped"] == {"provider_quota_exhausted": 1}
    assert summary["error_code"] is None and summary["errors"] == []
    # When the budget frees is the operator's next question, and the core answered it.
    assert summary["retry_after_seconds"] == 45
    readiness = connector._request.await_args_list[-1].kwargs["json"]
    # The provider is fine and the credential was never questioned: the scan reports what
    # stopped it without claiming a source failure that outlives the budget.
    assert readiness["provider_error"] is None
    assert readiness["credential_state"] != "invalid"


@pytest.mark.asyncio
async def test_candidate_evidence_keeps_its_capability_and_its_matched_asset(
    phishing, monkeypatch
):
    from providers import Adapter

    seen = []

    def factory(provider, env, reserve):
        def handler(request):
            seen.append(request)
            if request.url.path == "/api/responses/":
                return httpx.Response(
                    200,
                    json={
                        "items": [
                            {
                                "data": {
                                    "host": "acme-login.example.net",
                                    "ip": "192.0.2.9",
                                    "port": 443,
                                }
                            }
                        ]
                    },
                )
            return httpx.Response(200, json={"items": []})

        return Adapter(provider, env, reserve, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(worker, "Adapter", factory)
    phishing._active_job = ("job-fixture", "lease-fixture")
    phishing._request = AsyncMock(
        return_value=httpx.Response(
            200,
            json={"reserved": True, "request_budget": 100, "remaining_today": 98},
        )
    )
    phishing.submit_findings = AsyncMock(
        side_effect=lambda _job, rows: {"accepted": len(rows), "rejected": 0}
    )
    _, summary = await phishing.run_scan(
        {
            "job_id": "job-fixture",
            "config": {"max_requests": 10},
            "params": {
                "domains": ["example.com"],
                "exclude": ["example.com"],
                "candidates": [
                    {"value": "acme-login.example.net", "matched_asset": "ACME"}
                ],
            },
        }
    )
    rows = phishing.submit_findings.await_args.args[1]
    by_capability = {row["metadata"]["capability"]: row for row in rows}
    assert by_capability["hostname"]["matched_asset"] == "ACME"
    assert by_capability["hostname"]["phishing_domain"] == "acme-login.example.net"
    assert by_capability["hostname"]["metadata"]["verdict"] == "candidate_not_verified"
    # The two facts are evidence about a candidate, not discoveries, and a negative answer
    # is stored: a look-alike that receives no mail is worth as much as one that does.
    assert by_capability["mx"]["metadata"]["mail_capable"] is False
    assert by_capability["mx"]["metadata"]["association"] == "confirmed_candidate"
    assert by_capability["mx"]["matched_asset"] == "ACME"
    assert summary["skipped"] == {
        "favicon_hash_unavailable": 1,
        "whois_unavailable": 1,
    }
    # Spend and what is left of it: the job's own allowance and the account's day, which
    # the core reports on every reservation.
    assert summary["spent"] == summary["requests"] == 5
    assert summary["budget_left"] == 5
    assert summary["daily_budget"] == 100
    assert summary["daily_budget_left"] == 98
    assert summary["status"] == "partial"
