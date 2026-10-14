import importlib.util
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest

_PATH = Path("/connectors/intelligence/providers.py")
if not _PATH.exists():
    _PATH = Path(__file__).resolve().parents[2] / "connectors/intelligence/providers.py"
_spec = importlib.util.spec_from_file_location("intelligence_providers", _PATH)
providers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(providers)


def adapter(provider, handler):
    return providers.Adapter(
        provider,
        {providers.KEYS.get(provider, "UNUSED_KEY"): "fixture-secret"},
        AsyncMock(),
        transport=httpx.MockTransport(handler),
    )


@pytest.mark.asyncio
async def test_netlas_page_budget_truncates_without_extra_requests():
    def handler(request):
        assert request.url.path == "/api/responses/"
        return httpx.Response(
            200,
            json={
                "items": [
                    {"data": {"host": "example.com", "ip": "192.0.2.1", "port": 443}}
                ]
                * 20
            },
        )

    source = adapter("netlas", handler)
    assert len(await source.search("hostname", "example.com", max_pages=1)) == 20
    assert source.truncated and source.requests == 1


@pytest.mark.asyncio
async def test_rate_limit_retries_are_bounded_and_charged_to_quota(monkeypatch):
    sleeps = []
    monkeypatch.setattr(
        providers.asyncio,
        "sleep",
        AsyncMock(side_effect=lambda delay: sleeps.append(delay)),
    )
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(429, headers={"Retry-After": "60"}, text="fixture-secret")

    source = adapter("netlas", handler)
    with pytest.raises(providers.ProviderError) as error:
        await source.search("title", "Example")
    assert str(error.value) == "rate_limited" and error.value.retry_after == 60
    assert calls == source.requests == 3
    assert sleeps == [5, 5]
    assert source.reserve.await_count == 3


@pytest.mark.asyncio
async def test_transient_server_error_retries_then_succeeds(monkeypatch):
    monkeypatch.setattr(providers.asyncio, "sleep", AsyncMock())
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return (
            httpx.Response(503, text="temporary provider failure")
            if calls == 1
            else httpx.Response(200, json={"items": []})
        )

    source = adapter("netlas", handler)
    assert await source.search("title", "Example") == []
    assert calls == source.requests == 2
    assert source.reserve.await_count == 2


def test_retry_after_parses_http_dates_and_caps_delays():
    assert providers.retry_delay("invalid") is None
    assert providers.retry_delay("999999") == 86400
    assert providers.retry_delay("Thu, 01 Jan 1970 00:00:00 GMT") == 0


@pytest.mark.parametrize(
    ("provider", "status", "body", "expected"),
    [
        (
            "netlas",
            400,
            b'{"detail":"Request had invalid authorization credentials: API key not found"}',
            "invalid_credentials",
        ),
        (
            "netlas",
            400,
            b'{"detail":"invalid query field"}',
            "provider_rejected_request",
        ),
        ("netlas", 403, b'{"message":"Forbidden"}', "access_denied"),
    ],
)
def test_provider_errors_are_normalized_without_leaking_response_text(
    provider, status, body, expected
):
    assert providers.classify_http_error(provider, status, body) == expected
    assert expected not in body.decode(errors="ignore") or expected in {"access_denied"}


@pytest.mark.asyncio
async def test_provider_error_body_is_closed_bounded_and_never_in_exception_text():
    source = adapter(
        "netlas",
        lambda request: httpx.Response(
            400, json={"detail": "API key not found: fixture-secret"}
        ),
    )
    with pytest.raises(providers.ProviderError) as error:
        await source.lookup_host("example.com")
    assert str(error.value) == "invalid_credentials"
    assert "fixture-secret" not in str(error.value)


@pytest.mark.parametrize(
    "value", ["https://user:password@example.com", "https://example.com:99999"]
)
def test_untrusted_endpoints_rejected(value):
    with pytest.raises(providers.ProviderError):
        providers.endpoint({"host": value})


@pytest.mark.asyncio
async def test_netlas_documented_host_summary_is_passive_lookup():
    def handler(request):
        assert request.url.path == "/api/host/example.com/"
        assert request.headers["Authorization"] == "Bearer fixture-secret"
        return httpx.Response(
            200,
            json={
                "type": "domain",
                "ip": "192.0.2.44",
                "ports": [
                    {"port": 443, "protocol": "https", "prot4": "tcp", "prot7": "http"}
                ],
                "whois": {"@timestamp": "2026-01-01T00:00:00Z"},
            },
        )

    source = adapter("netlas", handler)
    rows = await source.lookup_host("example.com")
    normalized = providers.endpoints(rows[0])[0]
    assert normalized["subject"] == "example.com" and normalized["ip"] == "192.0.2.44"
    assert normalized["port"] == 443 and normalized["protocol"] == "http"
    source.reserve.assert_awaited_once_with("lookup")


@pytest.mark.asyncio
async def test_netlas_malformed_port_keeps_valid_sibling_and_records_partial_error():
    def handler(request):
        return httpx.Response(
            200,
            json={
                "ip": "192.0.2.44",
                "ports": [
                    {"port": 443, "protocol": "https"},
                    None,
                    {"port": 8443, "protocol": "https"},
                ],
            },
        )

    source = adapter("netlas", handler)
    rows = await source.lookup_host("example.com")
    assert [row["port"] for row in rows] == [443, 8443]
    assert source.record_errors == 1
    assert source.record_error_codes == ["invalid_record"]


def test_ipv6_and_certificate_only_records():
    assert (
        providers.endpoint({"host": "[2001:db8::1]:443", "ip": "2001:db8::1"})[
            "subject"
        ]
        == "2001:db8::1"
    )
    assert (
        providers.endpoints(
            {
                "certificate_v1": {
                    "resource": {
                        "fingerprint_sha256": "a" * 64,
                        "names": ["example.com"],
                    }
                }
            }
        )
        == []
    )


@pytest.mark.asyncio
async def test_netlas_certificates_search_uses_collection_contract_and_certificate_bucket():
    calls = []

    def handler(request):
        calls.append(request)
        assert request.url.path == "/api/certs/"
        assert request.headers["Authorization"] == "Bearer fixture-secret"
        assert request.url.params["q"] == 'certificate.names.keyword:"example.com"'
        assert request.url.params["start"] == str((len(calls) - 1) * 20)
        assert "extensions.subject_alt_name.dns_names" in request.url.params["fields"]
        documents = [
            {
                "data": {
                    "names": ["example.com", "www.example.com", "*.example.com"],
                    "fingerprint_sha256": "a" * 64,
                    "subject_dn": "CN=example.com",
                    "issuer_dn": "CN=Fixture CA",
                    "validity": {
                        "start": "2025-01-01T00:00:00Z",
                        "end": "2026-01-01T00:00:00Z",
                    },
                }
            }
        ] * (20 if len(calls) == 1 else 1)
        return httpx.Response(200, json={"items": documents})

    source = adapter("netlas", handler)
    rows = await source.search(
        "certificate", "example.com", max_pages=2, max_results=30
    )
    assert len(calls) == 2 and len(rows) == 21
    assert source.reserve.await_args_list[0].args == ("certificate",)
    records = providers.endpoints(rows[0], source)
    assert [row["subject"] for row in records] == ["example.com", "www.example.com"]
    assert records[0]["certificate"] == {
        "sha256": "a" * 64,
        "valid_from": "2025-01-01T00:00:00+00:00",
        "valid_to": "2026-01-01T00:00:00+00:00",
        "subject_dn": "CN=example.com",
        "issuer_dn": "CN=Fixture CA",
    }
    assert source.reserve.await_count == 2
    assert not source.truncated


@pytest.mark.asyncio
async def test_netlas_certificates_omit_malformed_documents_and_mark_partial():
    source = adapter(
        "netlas",
        lambda request: httpx.Response(
            200,
            json={
                "items": [
                    {
                        "data": {
                            "names": ["example.com"],
                            "fingerprint_sha256": "c" * 64,
                        }
                    },
                    {
                        "data": {
                            "names": ["example.com"],
                            "fingerprint_sha256": "not-a-hash",
                        }
                    },
                    {"data": {"names": "example.com", "fingerprint_sha256": "d" * 64}},
                ]
            },
        ),
    )
    rows = await source.search_certificates("example.com")
    assert len(rows) == 1 and rows[0]["fingerprint_sha256"] == "c" * 64
    assert source.record_errors == 2


@pytest.mark.asyncio
async def test_netlas_domains_search_uses_documented_dns_contract_and_normalizes_pages():
    seen = []

    def handler(request):
        seen.append(dict(request.url.params))
        assert request.url.path == "/api/domains/"
        assert request.headers["Authorization"] == "Bearer fixture-secret"
        return httpx.Response(
            200,
            json={
                "items": [
                    {
                        "data": {
                            "domain": "www.example.com",
                            "a": ["192.0.2.1"],
                            "aaaa": ["2001:db8::1"],
                            "last_updated": "2026-01-01T00:00:00Z",
                        }
                    }
                ]
            },
        )

    source = adapter("netlas", handler)
    rows = await source.search_domains("example.com")
    assert rows == [
        {
            "domain": "www.example.com",
            "a": ["192.0.2.1"],
            "aaaa": ["2001:db8::1"],
            "last_updated": "2026-01-01T00:00:00Z",
        }
    ]
    assert seen == [
        {
            "q": "domain:*.example.com",
            "fields": "domain,a,aaaa,ns,last_updated",
            "start": "0",
        }
    ]
    source.reserve.assert_awaited_once_with("search")


@pytest.mark.asyncio
async def test_netlas_domains_malformed_rows_are_isolated_and_result_limit_truncates():
    def handler(request):
        return httpx.Response(
            200,
            json={
                "items": [
                    {"data": {"domain": "a.example.com", "a": ["192.0.2.1"]}},
                    {"data": {"domain": "b.example.com", "a": ["192.0.2.2"]}},
                    {"data": None},
                    {"bad": "shape"},
                ]
            },
        )

    source = adapter("netlas", handler)
    rows = await source.search_domains("example.com", max_results=1)
    assert rows == [{"domain": "a.example.com", "a": ["192.0.2.1"]}]
    assert source.record_errors == 2
    assert source.truncated
    with pytest.raises(providers.ProviderError, match="unsupported_provider"):
        adapter("unknown_provider", lambda request: httpx.Response(200, json={}))


def test_certificate_endpoint_rejects_malformed_names_and_fingerprint():
    source = adapter("netlas", lambda request: httpx.Response(200, json={}))
    records = providers.endpoints(
        {
            "names": ["ok.example.com", "bad name.example.com", 17],
            "fingerprint_sha256": "invalid",
        },
        source,
    )
    assert [record["subject"] for record in records] == ["ok.example.com"]
    assert records[0]["certificate"] == {}
    assert source.record_errors == 2


def test_netlas_dns_rows_keep_only_owned_well_formed_a_and_aaaa_records():
    source = adapter("netlas", lambda request: httpx.Response(200, json={}))
    rows = [
        {
            "domain": "www.example.com",
            "a": ["192.0.2.1", "bad-ip"],
            "aaaa": ["2001:db8::1"],
            "last_updated": "2026-01-01T00:00:00Z",
        },
        {"domain": "attacker.example.net", "a": ["192.0.2.2"]},
        {"domain": "bad name.example.com", "a": ["192.0.2.3"]},
    ]
    observations = source.dns_observations("example.com", rows)
    assert [
        (item["subject"], item["record_type"], item["value"]) for item in observations
    ] == [
        ("www.example.com", "A", "192.0.2.1"),
        ("www.example.com", "AAAA", "2001:db8::1"),
    ]
    assert observations[0]["observation_type"] == "passive_dns"
    assert observations[0]["status"] == "historical"
    assert observations[0]["metadata"]["source_domain"] == "example.com"
    assert observations[0]["metadata"]["evidence"] == "netlas_passive_dns_dataset"
    assert source.record_errors == 3
