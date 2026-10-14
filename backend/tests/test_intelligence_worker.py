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
    assert len(seen) == 2
    assert [request.url.path for request in seen] == ["/api/domains/", "/api/certs/"]
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
    assert reservations == ["search", "certificate"]




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
