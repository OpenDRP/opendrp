import importlib.util
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest

from app.schemas.connector import ExposureFinding

_ROOT = (
    Path("/connectors")
    if Path("/connectors").exists()
    else Path(__file__).resolve().parents[2] / "connectors"
)
sys.path.insert(0, str(_ROOT / "base"))
sys.path.insert(0, str(_ROOT / "exposure_endpoints"))
_spec = importlib.util.spec_from_file_location(
    "exposure_endpoints_worker", _ROOT / "exposure_endpoints/main.py"
)
worker = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(worker)
endpoint_providers = importlib.import_module("endpoint_providers")

LEASE = "lease-0123456789abcdef"


def _env(monkeypatch, provider, connector_name):
    for key, value in {
        "CORE_URL": "http://core:8000",
        "CONNECTOR_TOKEN": "fixture-core-token",
        "CONNECTOR_NAME": connector_name,
        "CONNECTOR_TYPE": "exposure",
        "CONNECTOR_JOB_TYPE": f"exposure.{provider}-endpoints",
        "CONNECTOR_FINDING_KIND": "exposure",
        "CONNECTOR_ASSET_TYPES": "domain,ip_address",
        "EXPOSURE_PROVIDER": provider,
        "NETLAS_API_TOKEN": "fixture-netlas-token",
        "SHODAN_API_KEY": "fixture-shodan-key",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("CONNECTOR_CONFIG_SCHEMA", raising=False)


def _netlas_host(host_payload):
    def handler(request):
        assert request.headers["Authorization"].startswith("Bearer fixture-")
        return httpx.Response(200, json=host_payload)

    return handler


@pytest.mark.asyncio
async def test_a_refused_reservation_names_the_reason_the_core_gave(netlas):
    """A spent budget, a disabled source and an unapproved account are three answers.

    The core already distinguishes them (429, 409, 403 from `/me/quota/provider`),
    and every one of them used to reach the job summary as `quota_denied`. The most
    common first-run case — a connector run before its source account is approved —
    then read as a quota problem, which is the wrong page to send an operator to.
    """
    from opendrp_connector.base import ConnectorAPIError

    expected = {
        429: "quota_denied",
        409: "source_disabled",
        403: "provider_access_denied",
        503: "quota_backend_unavailable",
    }
    for status, code in expected.items():
        netlas._request = AsyncMock(side_effect=ConnectorAPIError(status, "refused"))
        with pytest.raises(endpoint_providers.ProviderError) as refused:
            await netlas._reserve("job-1", "lookup")
        assert str(refused.value) == code, status


@pytest.fixture
def netlas(monkeypatch):
    _env(monkeypatch, "netlas", "exposure-netlas-endpoints")
    connector = worker.ExposureEndpointsConnector()
    connector._request = AsyncMock(return_value=httpx.Response(200, json={}))
    connector._lease_for = lambda job_id: LEASE
    connector.submit_findings = AsyncMock(return_value={"accepted": 0})
    return connector


@pytest.fixture
def shodan(monkeypatch):
    _env(monkeypatch, "shodan", "exposure-shodan-endpoints")
    connector = worker.ExposureEndpointsConnector()
    connector._request = AsyncMock(return_value=httpx.Response(200, json={}))
    connector._lease_for = lambda job_id: LEASE
    connector.submit_findings = AsyncMock(return_value={"accepted": 0})
    return connector


def _client(provider, handler, *, max_requests=10, reserve=None):
    return endpoint_providers.EndpointClient(
        provider,
        "fixture-key",
        reserve or AsyncMock(),
        max_requests=max_requests,
        transport=httpx.MockTransport(handler),
    )


# --- provider clients -------------------------------------------------------


@pytest.mark.asyncio
async def test_netlas_host_lookup_returns_normalized_ports_and_spends_one_request():
    reserve = AsyncMock()
    client = _client(
        "netlas",
        _netlas_host(
            {
                "ip": "192.0.2.10",
                "ports": [
                    {"port": 443, "prot4": "tcp", "prot7": "https"},
                    {"port": 53, "prot4": "udp", "prot7": "dns"},
                ],
            }
        ),
        reserve=reserve,
    )
    records = await client.host_ports("192.0.2.10")
    assert records == [
        {"ip": "192.0.2.10", "port": 443, "transport": "tcp", "protocol": "https"},
        {"ip": "192.0.2.10", "port": 53, "transport": "udp", "protocol": "dns"},
    ]
    assert client.requests == 1 and reserve.await_count == 1
    assert reserve.await_args.args[0] == "lookup"


@pytest.mark.asyncio
async def test_shodan_host_lookup_maps_data_entries_and_treats_unindexed_ip_as_empty():
    def handler(request):
        assert request.url.path == "/shodan/host/192.0.2.20"
        assert request.url.params["key"] == "fixture-key"
        return httpx.Response(
            200,
            json={
                "ip_str": "192.0.2.20",
                "ports": [22, 8080],
                "data": [{"port": 22, "transport": "tcp", "product": "OpenSSH", "timestamp": "2026-10-01T10:00:00.000000"}],
            },
        )

    client = _client("shodan", handler)
    records = await client.host_ports("192.0.2.20")
    assert {(r["port"], r["transport"]) for r in records} == {(22, "tcp"), (8080, "tcp")}
    assert next(r for r in records if r["port"] == 22)["protocol"] == "openssh"

    def not_indexed(request):
        return httpx.Response(404, json={"error": "No information available for that IP."})

    assert await _client("shodan", not_indexed).host_ports("192.0.2.21") == []


@pytest.mark.asyncio
async def test_request_budget_is_charged_per_attempt_and_stops_before_sending():
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"ports": []})

    client = _client("netlas", handler, max_requests=1)
    await client.host_ports("a.example.com")
    with pytest.raises(endpoint_providers.ProviderError, match="scan_request_budget_exhausted"):
        await client.host_ports("b.example.com")
    assert calls == 1 and client.requests == 1


@pytest.mark.asyncio
async def test_rate_limit_retries_are_quota_accounted_then_reported_safely(monkeypatch):
    # The waiting is the shared client's now, and it waits through this same
    # `asyncio.sleep`: patching the module rather than a local import keeps the
    # test about the accounting it asserts instead of about the wall clock.
    monkeypatch.setattr("asyncio.sleep", AsyncMock())
    reserve = AsyncMock()
    client = _client(
        "netlas",
        lambda request: httpx.Response(429, text="secret-body"),
        reserve=reserve,
    )
    with pytest.raises(endpoint_providers.ProviderError) as error:
        await client.host_ports("a.example.com")
    assert str(error.value) == "rate_limited"
    assert client.requests == 3 and reserve.await_count == 3


@pytest.mark.asyncio
async def test_an_oversized_body_is_refused_while_it_is_being_read():
    """The bound used to be consulted after the whole answer was already in memory.

    Ten chunks of half a megabyte are five megabytes of provider-controlled bytes;
    the read must stop at the bound rather than buffering all of it and comparing
    lengths afterwards, which is what this worker did before.
    """
    pulled = []
    chunk = b"x" * (endpoint_providers.MAX_BODY_BYTES // 4)

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            for _ in range(10):
                pulled.append(len(chunk))
                yield chunk

    client = _client(
        "netlas",
        lambda request: httpx.Response(200, stream=Stream()),
        max_requests=5,
    )
    with pytest.raises(endpoint_providers.ProviderError, match="response_too_large"):
        await client.host_ports("a.example.com")
    # Four chunks fit, the fifth crosses the bound: ten were sent, five were read.
    assert len(pulled) == 5
    assert client.requests == 1, "an oversized answer is not worth retrying"


@pytest.mark.asyncio
async def test_a_long_pause_hint_is_capped_and_never_abandons_the_call(monkeypatch):
    """This worker waits a hint out for at most five seconds, then tries again.

    The shared client would abandon the call when a hint exceeds its sixty-second
    ceiling; this worker's answer to a long hint is the five-second cap instead,
    so the ceiling is switched off explicitly rather than inherited.
    """
    waits = []

    async def fake_sleep(delay):
        waits.append(delay)

    monkeypatch.setattr("asyncio.sleep", fake_sleep)
    calls = []

    def handler(request):
        calls.append(request.url.path)
        if len(calls) == 1:
            return httpx.Response(429, text="slow down", headers={"Retry-After": "3600"})
        return httpx.Response(200, json={"ports": []})

    client = _client("netlas", handler)
    assert await client.host_ports("a.example.com") == []
    assert waits == [5.0]
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_invalid_credentials_fail_without_retrying():
    reserve = AsyncMock()
    client = _client(
        "netlas",
        lambda request: httpx.Response(401, json={"detail": "API key not found"}),
        reserve=reserve,
    )
    with pytest.raises(endpoint_providers.ProviderError) as error:
        await client.host_ports("a.example.com")
    assert str(error.value) == "invalid_credentials"
    assert reserve.await_count == 1


@pytest.mark.asyncio
async def test_shodan_dns_resolve_batches_domains_in_one_request():
    seen = []

    def handler(request):
        seen.append(request.url.params["hostnames"])
        return httpx.Response(200, json={"a.example.com": "192.0.2.30", "b.example.com": None})

    client = _client("shodan", handler)
    resolved = await client.resolve(["a.example.com", "b.example.com"])
    assert resolved == {"a.example.com": "192.0.2.30", "b.example.com": None}
    assert seen == ["a.example.com,b.example.com"] and client.requests == 1


# --- connector scans --------------------------------------------------------


@pytest.mark.asyncio
async def test_netlas_scan_submits_exact_ip_and_resolved_domain_endpoints(netlas):
    netlas.transport = httpx.MockTransport(
        _netlas_host({"ip": "192.0.2.10", "ports": [{"port": 8443, "prot4": "tcp", "prot7": "https"}]})
    )
    work = {
        "job_id": "11111111-1111-1111-1111-111111111111",
        "config": {"max_requests": 5, "max_targets": 5},
        "params": {"ips": ["192.0.2.10"], "domains": ["app.example.com"]},
    }
    _, summary = await netlas.run_scan(work)

    submitted = [item for call in netlas.submit_findings.await_args_list for item in call.args[1]]
    assert len(submitted) == 2
    by_subject = {item["subject"]: item for item in submitted}
    assert by_subject["192.0.2.10"]["metadata"]["association"] == "exact_ip"
    assert by_subject["app.example.com"]["metadata"]["association"] == "domain_resolved_ip"
    assert by_subject["app.example.com"]["hostname"] == "app.example.com"
    assert summary["status"] == "success" and summary["requests"] == 2
    for item in submitted:
        ExposureFinding.model_validate(item)


@pytest.mark.asyncio
async def test_shodan_scan_resolves_domains_then_looks_up_only_resolved_hosts(shodan):
    def handler(request):
        if request.url.path == "/dns/resolve":
            return httpx.Response(200, json={"app.example.com": "192.0.2.40", "gone.example.com": None})
        assert request.url.path == "/shodan/host/192.0.2.40"
        return httpx.Response(200, json={"ports": [80], "data": [{"port": 80, "transport": "tcp", "product": "nginx"}]})

    shodan.transport = httpx.MockTransport(handler)
    work = {
        "job_id": "22222222-2222-2222-2222-222222222222",
        "config": {"max_requests": 5, "max_targets": 5},
        "params": {"domains": ["app.example.com", "gone.example.com"], "ips": []},
    }
    _, summary = await shodan.run_scan(work)
    submitted = [item for call in shodan.submit_findings.await_args_list for item in call.args[1]]
    assert [item["subject"] for item in submitted] == ["app.example.com"]
    assert submitted[0]["port"] == 80
    assert summary["requests"] == 2  # one resolve batch plus one host lookup


@pytest.mark.asyncio
async def test_exhausted_budget_makes_the_scan_partial_not_success(netlas):
    netlas.transport = httpx.MockTransport(_netlas_host({"ip": "192.0.2.10", "ports": [{"port": 80, "prot4": "tcp"}]}))
    work = {
        "job_id": "33333333-3333-3333-3333-333333333333",
        "config": {"max_requests": 1, "max_targets": 5},
        "params": {"ips": ["192.0.2.10", "192.0.2.11"], "domains": []},
    }
    _, summary = await netlas.run_scan(work)
    assert summary["requests"] == 1
    assert summary["status"] == "partial"
    assert "scan_request_budget_exhausted" in summary["errors"]


@pytest.mark.asyncio
async def test_too_many_targets_are_truncated_and_reported(netlas):
    netlas.transport = httpx.MockTransport(_netlas_host({"ip": None, "ports": []}))
    work = {
        "job_id": "44444444-4444-4444-4444-444444444444",
        "config": {"max_requests": 50, "max_targets": 2},
        "params": {"ips": ["192.0.2.1", "192.0.2.2", "192.0.2.3"], "domains": []},
    }
    _, summary = await netlas.run_scan(work)
    assert summary["truncated"] is True
    assert summary["requests"] == 2


@pytest.mark.asyncio
async def test_one_target_failing_does_not_throw_away_the_rest(netlas, monkeypatch):
    """A flaky lookup is one skipped target, not a scan that stops early.

    The loop used to `break` on the first `ProviderError`, so a single 5xx on the
    second target left every target after it unasked — and the summary could not
    say how many were never reached, which read like "nothing is exposed".
    """
    # The retry waits happen inside the shared client, on `asyncio.sleep`.
    monkeypatch.setattr("asyncio.sleep", AsyncMock())

    def handler(request):
        path = request.url.path
        if "192.0.2.11" in path:
            return httpx.Response(503, text="upstream unavailable")
        address = "192.0.2.10" if "192.0.2.10" in path else "192.0.2.12"
        return httpx.Response(
            200,
            json={"ip": address, "ports": [{"port": 443, "prot4": "tcp", "prot7": "https"}]},
        )

    netlas.transport = httpx.MockTransport(handler)
    work = {
        "job_id": "55555555-5555-5555-5555-555555555555",
        "config": {"max_requests": 20, "max_targets": 5},
        "params": {"ips": ["192.0.2.10", "192.0.2.11", "192.0.2.12"], "domains": []},
    }
    _, summary = await netlas.run_scan(work)

    submitted = [item for call in netlas.submit_findings.await_args_list for item in call.args[1]]
    assert {item["subject"] for item in submitted} == {"192.0.2.10", "192.0.2.12"}
    assert summary["targets_total"] == 3
    assert summary["targets_skipped"] == 1
    assert "network_or_invalid_response" in summary["errors"]
    # Two targets answered once, and the failed one spent all three attempts.
    assert summary["requests"] == 5
    assert summary["status"] == "partial"
    assert netlas.credential_state == "valid"


@pytest.mark.asyncio
async def test_invalid_credentials_stop_the_scan_and_are_reported(netlas):
    """A bad key fails every target for the same reason; the scan stops at one."""

    def handler(request):
        return httpx.Response(401, json={"detail": "API key not found"})

    netlas.transport = httpx.MockTransport(handler)
    work = {
        "job_id": "66666666-6666-6666-6666-666666666666",
        "config": {"max_requests": 20, "max_targets": 5},
        "params": {"ips": ["192.0.2.20", "192.0.2.21", "192.0.2.22"], "domains": []},
    }
    _, summary = await netlas.run_scan(work)

    assert summary["requests"] == 1
    assert summary["targets_skipped"] == 3
    assert summary["status"] == "error"
    assert summary["error_code"] == "invalid_credentials"
    assert netlas.credential_state == "invalid"
    netlas.submit_findings.assert_not_awaited()
    # The readiness row has to carry the verdict: the next poll is refused on it.
    readiness = netlas._request.await_args_list[-1].kwargs["json"]
    assert readiness["credential_state"] == "invalid"


def test_connector_refuses_a_module_other_than_exposure(monkeypatch):
    _env(monkeypatch, "netlas", "exposure-netlas-endpoints")
    monkeypatch.setenv("CONNECTOR_TYPE", "phishing")
    with pytest.raises(RuntimeError, match="exposure"):
        worker.ExposureEndpointsConnector()


def test_connector_refuses_an_unknown_provider(monkeypatch):
    _env(monkeypatch, "netlas", "exposure-netlas-endpoints")
    monkeypatch.setenv("EXPOSURE_PROVIDER", "censys")
    with pytest.raises(RuntimeError, match="EXPOSURE_PROVIDER"):
        worker.ExposureEndpointsConnector()
