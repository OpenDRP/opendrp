import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest

_ROOT = (
    Path("/connectors")
    if Path("/connectors").exists()
    else Path(__file__).resolve().parents[2] / "connectors"
)
# The provider module now makes its calls through the shared SDK client, so the
# SDK has to be importable the way the connector image makes it importable.
sys.path.insert(0, str(_ROOT / "base"))
_PATH = _ROOT / "intelligence/providers.py"
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
    # The waiting happens inside the shared client now, and it waits through this
    # same `asyncio.sleep`: patching the module keeps the test about the accounting
    # it asserts rather than about the wall clock.
    monkeypatch.setattr(
        "asyncio.sleep",
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
    monkeypatch.setattr("asyncio.sleep", AsyncMock())
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


@pytest.mark.asyncio
async def test_a_long_pause_hint_is_capped_and_never_abandons_the_call(monkeypatch):
    """A hint is waited out for at most five seconds, then the call is tried again.

    The shared client abandons a call whose hint exceeds its sixty-second ceiling;
    this worker's answer to a long hint is the five-second cap, so the ceiling is
    switched off explicitly rather than inherited.
    """
    waits = []

    async def fake_sleep(delay):
        waits.append(delay)

    monkeypatch.setattr("asyncio.sleep", fake_sleep)
    calls = []

    def handler(request):
        calls.append(request.url.path)
        if len(calls) == 1:
            return httpx.Response(429, headers={"Retry-After": "3600"}, text="slow down")
        return httpx.Response(200, json={"items": []})

    source = adapter("netlas", handler)
    assert await source.search("title", "Example") == []
    assert waits == [5.0]
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_a_credential_refusal_is_named_at_the_end_of_a_full_body():
    """The classifier sees a bounded snippet, and the phrase has to be inside it.

    This worker used to read 8 KB of a refusal body and the shared client stops at
    4 KB, so the known phrases are asserted where it matters: at the end of a body
    that nearly fills the snippet.
    """
    body = json.dumps({"detail": "x" * 3900 + " API key not found"}).encode()
    assert len(body) <= 4096

    source = adapter(
        "netlas",
        lambda request: httpx.Response(400, content=body),
    )
    with pytest.raises(providers.ProviderError) as error:
        await source.lookup_host("example.com")
    assert str(error.value) == "invalid_credentials"


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


def test_brand_expression_keeps_the_phrase_and_generates_the_wildcard():
    # One expression, two halves: the organisation the certificate claims and the names
    # it carries. The phrase is escaped as a phrase, and the wildcard half is generated
    # from the same value, so a metacharacter can never reach the part that is not quoted.
    assert providers.brand_certificate_expression("ACME Corp.") == (
        'certificate.subject.organization:"ACME Corp." OR certificate.names:*acmecorp*'
    )


@pytest.mark.parametrize(
    "value",
    [
        'ACME" OR certificate.names:*',
        "ACME*",
        # The wildcard half is generated: this one leaves two usable characters, which
        # match everything and mean nothing.
        "a. b",
        "\x01ACME",
        "",
        "ACME\nCorp",
        None,
    ],
)
def test_a_brand_the_grammar_cannot_carry_is_refused(value):
    with pytest.raises(providers.ProviderError) as error:
        providers.brand_certificate_expression(value)
    assert str(error.value) == "invalid_brand_value"


@pytest.mark.asyncio
async def test_brand_certificate_search_uses_the_certificate_collection_and_quota():
    seen = []

    def handler(request):
        seen.append(request)
        assert request.url.path == "/api/certs/"
        assert request.headers["Authorization"] == "Bearer fixture-secret"
        return httpx.Response(200, json={"items": []})

    source = adapter("netlas", handler)
    assert await source.search_brand_certificates("ACME Corp.") == []
    assert seen[0].url.params["q"] == (
        'certificate.subject.organization:"ACME Corp." OR certificate.names:*acmecorp*'
    )
    # The provider rate-limits certificate queries to three a minute, so a brand search
    # is reserved from the certificate bucket rather than from the general one.
    source.reserve.assert_awaited_once_with("certificate")


@pytest.mark.asyncio
async def test_the_result_set_is_counted_before_a_page_is_fetched():
    def handler(request):
        assert request.url.path == "/api/responses_count/"
        assert request.url.params["q"] == 'http.body:"ACME"'
        return httpx.Response(200, json={"count": 4200})

    source = adapter("netlas", handler)
    assert await source.count_responses('http.body:"ACME"') == 4200
    source.reserve.assert_awaited_once_with("search")


@pytest.mark.asyncio
async def test_a_count_that_is_not_a_number_is_not_a_count():
    source = adapter(
        "netlas", lambda request: httpx.Response(200, json={"count": "many"})
    )
    with pytest.raises(providers.ProviderError) as error:
        await source.count_responses("host:example.com")
    assert str(error.value) == "invalid_response"


@pytest.mark.asyncio
async def test_icon_hashes_are_read_from_the_providers_own_view_of_our_endpoint():
    def handler(request):
        assert request.url.path == "/api/responses/"
        assert request.url.params["q"] == 'host:"example.com"'
        assert "http.favicon.perceptual_hash" in request.url.params["fields"]
        return httpx.Response(
            200,
            json={
                "items": [
                    {
                        "data": {
                            "http": {
                                "favicon": {
                                    "hash_sha256": "A" * 64,
                                    "perceptual_hash": "00763c383c3c6e00",
                                }
                            }
                        }
                    },
                    {"data": {"host": "example.com"}},
                ]
            },
        )

    source = adapter("netlas", handler)
    assert await source.own_favicon_hashes("example.com") == {
        "sha256": "a" * 64,
        "perceptual": "00763c383c3c6e00",
    }
    assert source.record_errors == 0


@pytest.mark.asyncio
async def test_an_icon_hash_in_another_alphabet_is_recorded_not_searched():
    source = adapter(
        "netlas",
        lambda request: httpx.Response(
            200,
            json={
                "items": [
                    {"data": {"http": {"favicon": {"perceptual_hash": "not-a-hash"}}}}
                ]
            },
        ),
    )
    assert await source.own_favicon_hashes("example.com") == {}
    assert source.record_error_codes == ["unreadable_favicon_hash"]


@pytest.mark.parametrize(
    ("algorithm", "value", "expected"),
    [
        ("sha256", "a" * 64, 'http.favicon.hash_sha256:"' + "a" * 64 + '"'),
        ("perceptual", "00763c383c3c6e00", "http.favicon.perceptual_hash:00763c383c3c6e00~1"),
    ],
)
@pytest.mark.asyncio
async def test_icon_searches_keep_the_fuzzy_operator_on_the_term(
    algorithm, value, expected
):
    seen = {}

    def handler(request):
        seen["q"] = request.url.params["q"]
        return httpx.Response(200, json={"items": []})

    source = adapter("netlas", handler)
    assert await source.search_favicon(algorithm, value) == []
    assert seen["q"] == expected
    source.reserve.assert_awaited_once_with("search")


def test_an_icon_search_refuses_a_value_it_cannot_use():
    with pytest.raises(providers.ProviderError) as error:
        providers.favicon_expression("perceptual", "zzzz")
    assert str(error.value) == "invalid_favicon_hash"
    with pytest.raises(providers.ProviderError) as error:
        providers.favicon_expression("mmh3", "a" * 8)
    assert str(error.value) == "unsupported_capability"


@pytest.mark.asyncio
async def test_whois_search_uses_the_documented_collection_and_fields():
    def handler(request):
        assert request.url.path == "/api/whois_domains/"
        assert request.url.params["q"] == 'domain:"acme-login.example.net"'
        assert request.url.params["fields"] == (
            "domain,created_date,registrar,registrant.organization"
        )
        return httpx.Response(
            200,
            json={
                "items": [
                    {
                        "data": {
                            "domain": "acme-login.example.net",
                            "created_date": "2026-01-02T00:00:00Z",
                            "registrar": {"name": "Fixture Registrar"},
                        }
                    }
                ]
            },
        )

    source = adapter("netlas", handler)
    rows = await source.search_whois("acme-login.example.net")
    assert rows[0]["domain"] == "acme-login.example.net"
    assert providers.whois_facts(rows, source) == {
        "created": "2026-01-02T00:00:00+00:00",
        "registrar": "Fixture Registrar",
    }
    assert source.record_errors == 0
    source.reserve.assert_awaited_once_with("search")


def test_whois_facts_drop_a_registrar_no_rule_could_read():
    source = adapter("netlas", lambda request: httpx.Response(200, json={}))
    facts = providers.whois_facts(
        [{"created_date": "2026-01-02T00:00:00Z", "registrar": {"name": 17}}], source
    )
    assert facts == {"created": "2026-01-02T00:00:00+00:00"}
    assert source.record_error_codes == ["invalid_whois_registrar"]


@pytest.mark.asyncio
async def test_mail_records_ask_the_documented_existence_test():
    def handler(request):
        assert request.url.path == "/api/domains/"
        assert request.url.params["q"] == 'domain:"acme-login.example.net" AND mx:*'
        assert request.url.params["fields"] == "domain,mx,ns,last_updated"
        return httpx.Response(
            200,
            json={
                "items": [
                    {
                        "data": {
                            "domain": "acme-login.example.net",
                            "mx": ["mx1.evil.example"],
                            "last_updated": "2026-01-02T00:00:00Z",
                        }
                    }
                ]
            },
        )

    source = adapter("netlas", handler)
    rows = await source.search_mail_records("acme-login.example.net")
    assert providers.mail_facts(rows, source) == {
        "mail_capable": True,
        "mx_hosts": ["mx1.evil.example"],
        "provider_observed_at": "2026-01-02T00:00:00+00:00",
    }
    assert source.record_errors == 0
    source.reserve.assert_awaited_once_with("search")


def test_a_domain_without_mail_is_an_answer_and_a_broken_record_is_not():
    source = adapter("netlas", lambda request: httpx.Response(200, json={}))
    assert providers.mail_facts([{"domain": "acme-login.example.net"}], source) == {
        "mail_capable": False,
        "mx_hosts": [],
        "provider_observed_at": "unknown",
    }
    assert providers.mail_facts([{"mx": {"a": 1}}], source)["mail_capable"] is False
    assert source.record_error_codes == ["invalid_mail_record"]


def test_a_title_the_core_would_refuse_is_cleaned_before_it_leaves_the_worker():
    # The core validates a whole batch before it stores any of it, and it refuses a
    # control character in finding metadata. A provider title holding a NUL, a carriage
    # return or a line feed therefore failed the batch and every batch after it. The
    # worker has to deliver a value the core accepts.
    from app.schemas.connector import sanitize_attributes

    record = providers.endpoint(
        {
            "hostname": "login.example.com",
            "port": 443,
            "protocol": "https",
            "title": "Sign in\x00 page\r\nnow",
            "last_updated": "2026-10-01T00:00:00Z",
        }
    )
    assert record["title"] == "Sign in page now"
    assert sanitize_attributes({"title": record["title"]}, strict=True) == {
        "title": "Sign in page now"
    }
