from __future__ import annotations

from unittest.mock import AsyncMock

import httpx
import pytest

from main import CTLogsConnector, DNSConnector, RDAPConnector, ResolverConnector, VirusTotalConnector, _domain


@pytest.mark.asyncio
async def test_exact_lookup_precedes_discovery_selects_issued_and_deduplicates(monkeypatch):
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    def cert(identity, days):
        return {"id": identity, "match": "example.com", "not_before": (now+timedelta(days=days)).isoformat(), "not_after": (now+timedelta(days=90+days)).isoformat()}
    requests = []
    rows = [cert("old",-20),cert("latest",-1),cert("future",2)]
    def handler(request):
        requests.append(request.url.path)
        return httpx.Response(200,json={"rows": rows, "has_next":False})
    mock_transport(monkeypatch,handler)
    connector = make_connector(CTLogsConnector, {"DNS_SECURITY_CTLOGS_PUBLIC_NONCOMMERCIAL": "true"})
    result = await connector._run_ctlogs(["example.com"])
    assert requests == ["/v1/domain/example.com","/v1/subdomains/example.com"]
    check = next(r for r in result if r["observation_type"]=="certificate_check")
    assert check["metadata"]["certificate_id"] == "latest"
    assert check["metadata"]["check_state"] == "verified"
    assert len([r for r in result if r["metadata"].get("id")=="latest"]) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("mode,state", [("invalid","incomplete"),("future","future_only"),("error","failed"),("truncated","incomplete")])
async def test_exact_lookup_never_promotes_uncertain_results(monkeypatch,mode,state):
    from datetime import datetime,timedelta,timezone
    now=datetime.now(timezone.utc)
    def handler(request):
        if mode=="error":
            return httpx.Response(403,json={"error":"denied"})
        if mode=="invalid":
            row={"id":"a","match":"*.example.com"}
        else:
            row={"id":"a","match":"example.com","not_before":(now+timedelta(days=1)).isoformat(),"not_after":(now+timedelta(days=90)).isoformat()}
        return httpx.Response(200,json={"rows":[row],"has_next":mode=="truncated","next_cursor":str(len(request.url.query))})
    mock_transport(monkeypatch,handler)
    connector=make_connector(CTLogsConnector)
    async with httpx.AsyncClient() as client:
        check,evidence=await connector._ct_exact_check(client,"https://api.ctlogs.dev","example.com",{},AsyncMock())
    assert check["metadata"]["check_state"]==state
    assert evidence is None


def test_domain_validation_canonicalizes_idna_and_rejects_urls():
    assert _domain("WWW.Example.COM.") == "www.example.com"
    assert _domain("https://example.com/path") is None
    assert _domain("bad..example.com") is None


@pytest.mark.asyncio
async def test_ct_rows_are_kept_historical_and_use_certificate_identity(monkeypatch):
    connector = CTLogsConnector.__new__(CTLogsConnector)
    connector.env = {
        "DNS_SECURITY_CTLOGS_API_BASE": "https://api.ctlogs.dev",
        "DNS_SECURITY_CTLOGS_PUBLIC_NONCOMMERCIAL": "true",
    }
    connector._errors = []
    connector._client_timeout = None
    response = {
        "rows": [
            {"id": "cert-1", "match": "login.example.com", "not_after": "2026-10-01T00:00:00Z", "serial_hex": "aa", "issuer": "CA"},
            {"id": "cert-2", "match": "login.example.com", "not_after": "2026-11-01T00:00:00Z", "serial_hex": "bb", "issuer": "CA"},
        ]
    }

    class Client:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return None

    connector._get_json = AsyncMock(side_effect=[({"rows": [], "has_next": False}, None, None), (response, None, None)])
    monkeypatch.setattr("main.httpx.AsyncClient", lambda **kwargs: Client())
    monkeypatch.setattr("main.time.monotonic", lambda: 100.0)
    monkeypatch.setattr("main.asyncio.sleep", AsyncMock())
    rows = await connector._run_ctlogs(["example.com"])
    assert rows[0]["metadata"]["check_state"] == "no_certificate"
    rows = rows[1:]
    assert len(rows) == 2
    assert all(row["status"] == "historical" for row in rows)
    assert all(row["metadata"]["evidence"].startswith("certificate_transparency") for row in rows)
    assert connector._get_json.await_count == 2


@pytest.mark.asyncio
async def test_vt_requires_explicit_noncommercial_opt_in():
    connector = VirusTotalConnector.__new__(VirusTotalConnector)
    connector.env = {"DNS_SECURITY_VT_API_KEY": "mock-only"}
    connector._errors = []
    rows = await connector._run_virustotal(["example.com"])
    assert rows == []
    assert connector._errors == ["public_tier_noncommercial_ack_required"]


@pytest.mark.asyncio
async def test_vt_reserves_each_http_retry_before_making_it(monkeypatch):
    connector = VirusTotalConnector.__new__(VirusTotalConnector)
    connector.env = {
        "DNS_SECURITY_VT_API_KEY": "mock-only",
        "DNS_SECURITY_VT_PUBLIC_NONCOMMERCIAL": "true",
    }
    connector._client_timeout = None
    connector._errors = []
    connector.reserve_virustotal_request = AsyncMock()
    response = {"data": [], "links": {}}
    attempts = 0

    class Client:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return None
        def stream(self, method, url, headers=None, params=None):
            from contextlib import asynccontextmanager

            @asynccontextmanager
            async def response_stream():
                yield self.response(url, headers)
            return response_stream()
        def response(self, url, headers=None):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                return httpx.Response(500, json={"error": "temporary"}, request=httpx.Request("GET", url))
            return httpx.Response(200, json=response, request=httpx.Request("GET", url))

    monkeypatch.setattr("main.httpx.AsyncClient", lambda **kwargs: Client())
    monkeypatch.setattr("main.asyncio.sleep", AsyncMock())
    rows = await connector._run_virustotal(["example.com"])
    assert rows == []
    # The domain record takes one slot, the subdomains endpoint one for its failed
    # attempt and one for its retry, and the resolutions endpoint one more.
    assert connector.reserve_virustotal_request.await_count == 4
    assert attempts == 4


@pytest.mark.asyncio
async def test_one_source_failure_does_not_escape_scan():
    connector = DNSConnector.__new__(DNSConnector)
    connector.SOURCE = "rdap"
    connector._errors = []
    connector._domains = lambda work: ["example.com"]
    connector._run_rdap = AsyncMock(side_effect=RuntimeError("mock failure"))
    connector.submit_observations = AsyncMock()
    findings, summary = await connector.run_scan({"job_id": "mock-job", "params": {}})
    assert findings == []
    assert summary["status"] == "error"
    assert summary["provider_errors"] == ["RuntimeError"]


def mock_transport(monkeypatch, handler):
    original = httpx.AsyncClient
    monkeypatch.setattr("main.httpx.AsyncClient", lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs))
    monkeypatch.setattr("main.asyncio.sleep", AsyncMock())


def make_connector(cls, env=None):
    connector = cls.__new__(cls)
    connector.env = env or {}
    connector._errors = []
    connector._client_timeout = httpx.Timeout(1)
    return connector


@pytest.mark.asyncio
async def test_ct_bearer_wildcards_sans_and_cursor_are_preserved(monkeypatch):
    requests = []
    def handler(request):
        requests.append(request)
        assert request.headers["Authorization"] == "Bearer mock-ct-token"
        if "/v1/domain/" in request.url.path:
            return httpx.Response(200, json={"rows": [], "has_next": False})
        if not request.url.params.get("after"):
            return httpx.Response(200, json={"rows": [
                {"id": "cert-1", "match": "*.prod.egov.kz", "not_after": "2026-11-03T11:46:21Z", "serial_hex": "aa", "issuer": "Let's Encrypt", "key_algo": "ECDSA P-256", "san_count": 5},
                {"id": "cert-1", "match": "prod.egov.kz", "not_after": "invalid"},
                {"id": "cert-1", "match": "login.egov.kz"},
                {"id": "unrelated", "match": "evil-egov.kz"},
            ], "has_next": True, "next_cursor": "cursor&1"})
        return httpx.Response(200, json={"rows": [{"id": "cert-2", "match": "aitu-gosuslugi.egov.kz"}], "has_next": False})
    mock_transport(monkeypatch, handler)
    connector = make_connector(CTLogsConnector, {"DNS_SECURITY_CTLOGS_API_TOKEN": "mock-ct-token"})
    rows = await connector._run_ctlogs(["egov.kz"])
    assert rows[0]["metadata"]["check_state"] == "no_certificate"
    rows = rows[1:]
    assert len(rows) == 4
    assert rows[0]["subject"] == "prod.egov.kz"
    assert rows[0]["metadata"]["wildcard"] is True
    assert rows[0]["metadata"]["certificate_match"] == "*.prod.egov.kz"
    assert rows[0]["expires_at"] == "2026-11-03T11:46:21+00:00"
    assert rows[1]["metadata"]["wildcard"] is False
    assert rows[1]["expires_at"] is None
    assert requests[2].url.params["after"] == "cursor&1"
    assert all(row["status"] == "historical" for row in rows)
    assert set(connector._errors) == {"invalid_expiry_date", "invalid_ct_hostname"}


@pytest.mark.asyncio
async def test_ct_repeated_cursor_is_reported(monkeypatch):
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"rows": [], "has_next": True, "next_cursor": "same"})
    mock_transport(monkeypatch, handler)
    connector = make_connector(CTLogsConnector, {"DNS_SECURITY_CTLOGS_PUBLIC_NONCOMMERCIAL": "true"})
    rows = await connector._run_ctlogs(["egov.kz"])
    assert len(rows) == 1 and rows[0]["metadata"]["check_state"] == "incomplete"
    assert len(requests) == 4
    assert connector._errors == ["invalid_pagination", "invalid_pagination"]


@pytest.mark.asyncio
async def test_vt_example_preserves_provenance_history_and_certificate(monkeypatch):
    requests = []
    def handler(request):
        requests.append(request)
        assert request.headers["x-apikey"] == "mock-vt-key"
        if request.url.path == "/api/v3/domains/egov.kz":
            return httpx.Response(200, json={"data": {"type": "domain", "id": "egov.kz", "attributes": {
                "last_analysis_date": 1789164900,
                "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 7, "timeout": 0},
                "reputation": -3,
                "categories": {"Forcepoint ThreatSeeker": "government", "Sophos": "government"},
                "last_https_certificate": {"fingerprint": {"sha256": "AB" * 32}, "validity": {"not_before": "2026-01-07 23:59:59", "not_after": "2027-01-07 23:59:59"}},
            }}, "links": {}})
        if request.url.path.endswith("/subdomains"):
            return httpx.Response(200, json={"data": [{"type": "domain", "id": "pep-mobile.egov.kz", "attributes": {
                "last_analysis_date": 1789164900,
                "last_analysis_stats": {"malicious": 4, "suspicious": 0, "harmless": 60, "undetected": 3, "timeout": 1},
                "reputation": -40,
                "last_dns_records": [{"type": "A", "value": "203.0.113.1"}, {"type": "AAAA", "value": "2001:db8::1"}],
                "last_https_certificate": {"validity": {"not_after": "2027-01-07 23:59:59"}},
            }}], "links": {}})
        return httpx.Response(200, json={"data": [{"type": "resolution", "id": "resolution-1", "attributes": {"ip_address": "203.0.113.1", "host_name": "egov.kz", "date": 1789164900, "resolver": "VirusTotal"}}], "links": {}})
    mock_transport(monkeypatch, handler)
    connector = make_connector(VirusTotalConnector, {"DNS_SECURITY_VT_API_KEY": "mock-vt-key", "DNS_SECURITY_VT_PUBLIC_NONCOMMERCIAL": "true"})
    connector.reserve_virustotal_request = AsyncMock()
    rows = await connector._run_virustotal(["egov.kz"])
    assert [row["observation_type"] for row in rows] == ["vt_domain", "vt_subdomain", "vt_resolution"]
    reputation, subdomain, resolution = rows
    assert reputation["subject"] == "egov.kz" and reputation["status"] == "current"
    assert reputation["metadata"]["reputation"] == -3
    assert reputation["metadata"]["analysis_suspicious"] == 0
    assert reputation["metadata"]["analysis_harmless"] == 70
    assert reputation["metadata"]["categories"] == ["Forcepoint ThreatSeeker: government", "Sophos: government"]
    assert reputation["metadata"]["certificate_fingerprint_sha256"] == "ab" * 32
    assert reputation["metadata"]["certificate_not_after"] == "2027-01-07T23:59:59+00:00"
    assert "suspicious" not in reputation["metadata"]
    assert subdomain["subject"] == "pep-mobile.egov.kz"
    assert subdomain["value"] == "egov.kz"
    assert subdomain["metadata"]["last_dns_records"] == ["A 203.0.113.1", "AAAA 2001:db8::1"]
    assert subdomain["metadata"]["certificate_not_after"] == "2027-01-07T23:59:59+00:00"
    # The provider scores this discovered name malicious, and the row says so.
    assert subdomain["metadata"]["suspicious"] is True
    assert subdomain["metadata"]["analysis_malicious"] == 4
    assert resolution["subject"] == "203.0.113.1"
    assert resolution["metadata"]["resolution_date"] == "1789164900"
    assert resolution["metadata"]["host_name"] == "egov.kz"
    assert rows[1:][0]["status"] == "historical" and resolution["status"] == "historical"
    assert all(request.url.params["limit"] == "10" for request in requests if request.url.path.count("/") > 4)
    assert connector.reserve_virustotal_request.await_count == 3
    assert connector._errors == []


@pytest.mark.asyncio
@pytest.mark.parametrize("next_page", [
    "https://www.virustotal.com.evil.test/api/v3/domains/egov.kz/subdomains?cursor=1",
    "https://user:secret@www.virustotal.com/api/v3/domains/egov.kz/subdomains?cursor=1",
    "https://www.virustotal.com/api/v3/domains/another.test/subdomains?cursor=1",
    "http://www.virustotal.com/api/v3/domains/egov.kz/subdomains?cursor=1",
])
async def test_vt_pagination_does_not_forward_key_to_untrusted_urls(monkeypatch, next_page):
    requests = []
    def handler(request):
        requests.append(request)
        if request.url.path == "/api/v3/domains/egov.kz":
            return httpx.Response(200, json={"data": {"type": "domain", "id": "egov.kz", "attributes": {}}, "links": {}})
        return httpx.Response(200, json={"data": [], "links": {"next": next_page}})
    mock_transport(monkeypatch, handler)
    connector = make_connector(VirusTotalConnector, {"DNS_SECURITY_VT_API_KEY": "mock-only", "DNS_SECURITY_VT_PUBLIC_NONCOMMERCIAL": "true"})
    connector.reserve_virustotal_request = AsyncMock()
    assert [row["observation_type"] for row in await connector._run_virustotal(["egov.kz"])] == ["vt_domain"]
    assert len(requests) == 3  # The domain record plus the two paged endpoints.
    assert connector._errors == ["invalid_pagination", "invalid_pagination"]


@pytest.mark.asyncio
async def test_json_response_limit_is_enforced_while_streaming(monkeypatch):
    import main
    chunks_read = []
    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            for chunk in (b"12345678", b"12345678", b"must-not-read"):
                chunks_read.append(chunk)
                yield chunk
    mock_transport(monkeypatch, lambda request: httpx.Response(200, stream=Stream()))
    monkeypatch.setattr(main, "MAX_RESPONSE_BYTES", 10)
    connector = make_connector(DNSConnector)
    async with httpx.AsyncClient() as client:
        payload, error, _ = await connector._get_json(client, "https://api.ctlogs.dev/test")
    assert payload is None
    assert error == "response_too_large"
    assert len(chunks_read) == 2


@pytest.mark.asyncio
async def test_resolver_submits_complete_rrset_instead_of_overwriting_members(monkeypatch):
    class Answer(list):
        rrset = type("RRset", (), {"ttl": 60})()
    resolver = type("Resolver", (), {"resolve": lambda self, domain, kind, **kwargs: Answer(["203.0.113.2", "203.0.113.1"]) if kind == "A" else Answer()})()
    monkeypatch.setattr("main.dns.resolver.Resolver", lambda **kwargs: resolver)
    connector = make_connector(ResolverConnector)
    rows = await connector._run_resolver(["egov.kz"])
    assert len(rows) == 1
    assert rows[0]["value"] == "203.0.113.1; 203.0.113.2"
    assert rows[0]["metadata"]["record_values"] == ["203.0.113.1", "203.0.113.2"]
    assert rows[0]["metadata"]["source_domain"] == "egov.kz"


@pytest.mark.asyncio
async def test_extended_resolver_reads_spf_and_dmarc_without_widening_the_budget(monkeypatch):
    """F-08: the mail authorization a domain publishes is part of its posture.

    TXT was allowed by the core schema but never queried, so DMARC and SPF changes
    were invisible. Both are fetched as ordinary RRsets under the name that holds
    them - the domain for SPF, `_dmarc.<domain>` for the policy - while the row keeps
    the scanned asset in `source_domain` so it stays linked to it.
    """
    asked = []

    class Answer(list):
        rrset = type("RRset", (), {"ttl": 300})()

    def resolve(self, name, kind, **kwargs):
        asked.append((name, kind))
        if kind != "TXT":
            return Answer()
        if name.startswith("_dmarc."):
            return Answer(["v=DMARC1; p=reject; rua=mailto:dmarc@egov.kz"])
        return Answer(["v=spf1 include:_spf.egov.kz -all"])

    resolver = type("Resolver", (), {"resolve": resolve})()
    monkeypatch.setattr("main.dns.resolver.Resolver", lambda **kwargs: resolver)
    connector = make_connector(ResolverConnector, {"DNS_SECURITY_RESOLVER_EXTENDED": "true"})
    rows = await connector._run_resolver(["egov.kz"])

    assert asked == [
        ("egov.kz", "A"), ("egov.kz", "AAAA"), ("egov.kz", "CNAME"),
        ("egov.kz", "NS"), ("egov.kz", "MX"), ("egov.kz", "CAA"), ("egov.kz", "TXT"),
        ("_dmarc.egov.kz", "TXT"),
    ]
    assert [row["subject"] for row in rows] == ["egov.kz", "_dmarc.egov.kz"]
    assert rows[0]["metadata"]["record_values"] == ["v=spf1 include:_spf.egov.kz -all"]
    assert rows[1]["metadata"]["source_domain"] == "egov.kz"
    assert rows[1]["record_type"] == "TXT"

    # The default profile still asks the three address records only.
    asked.clear()
    assert await make_connector(ResolverConnector)._run_resolver(["egov.kz"]) == []
    assert asked == [("egov.kz", "A"), ("egov.kz", "AAAA"), ("egov.kz", "CNAME")]


@pytest.mark.asyncio
async def test_rdap_bootstrap_redirect_is_public_ip_pinned(monkeypatch):
    requests = []
    def handler(request):
        requests.append(request)
        if len(requests) == 1:
            assert request.headers["Host"] == "rdap.org"
            return httpx.Response(302, headers={"Location": "https://registry.example/domain/egov.kz"})
        assert request.headers["Host"] == "registry.example"
        assert request.extensions["sni_hostname"] == "registry.example"
        assert request.url.host == "8.8.8.8"
        return httpx.Response(200, json={"events": [{"eventAction": "expiration", "eventDate": "2027-01-01T00:00:00Z"}]})
    mock_transport(monkeypatch, handler)
    monkeypatch.setattr("main.resolve_public_ips", lambda host: ("8.8.8.8",))
    connector = make_connector(RDAPConnector)
    rows = await connector._run_rdap(["egov.kz"])
    assert len(rows) == 1
    assert rows[0]["expires_at"] == "2027-01-01T00:00:00+00:00"
    assert len(requests) == 2
    assert connector._errors == []


@pytest.mark.asyncio
async def test_rdap_records_the_registrations_own_status_and_dnssec(monkeypatch):
    """F-07: the registry's statement about the registration, not only its dates.

    RDAP spells EPP statuses as prose and registries spell them in camel case; the
    stored token is the same either way, so the core's rule compares values and not
    spellings. An answer without `status`/`secureDNS` stores neither key, because an
    absent field is silence and not a removal.
    """
    silent = {"on": False}

    def handler(request):
        if silent["on"]:
            return httpx.Response(200, json={"events": [], "status": "active", "secureDNS": {}})
        return httpx.Response(200, json={
            "events": [{"eventAction": "expiration", "eventDate": "2027-01-01T00:00:00Z"}],
            "status": ["client transfer prohibited", "clientHold", "clientHold"],
            "secureDNS": {"delegationSigned": True},
        })
    mock_transport(monkeypatch, handler)
    monkeypatch.setattr("main.resolve_public_ips", lambda host: ("8.8.8.8",))
    rows = await make_connector(RDAPConnector)._run_rdap(["egov.kz"])
    assert rows[0]["metadata"]["epp_status"] == ["clienthold", "clienttransferprohibited"]
    assert rows[0]["metadata"]["secure_dns"] is True

    silent["on"] = True
    quiet = await make_connector(RDAPConnector)._run_rdap(["egov.kz"])
    assert "epp_status" not in quiet[0]["metadata"]
    assert "secure_dns" not in quiet[0]["metadata"]


@pytest.mark.asyncio
async def test_rdap_redirect_to_internal_destination_is_blocked(monkeypatch):
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(302, headers={"Location": "https://internal.example/domain/egov.kz"})
    mock_transport(monkeypatch, handler)
    monkeypatch.setattr("main.resolve_public_ips", lambda host: ("8.8.8.8",) if host == "rdap.org" else ())
    connector = make_connector(RDAPConnector)
    failed = await connector._run_rdap(["egov.kz"])
    assert len(failed) == 1 and failed[0]["metadata"]["check_state"] == "failed"
    assert failed[0]["status"] == "unknown"
    assert len(requests) == 1
    assert connector._errors == ["rdap_destination_blocked"]


@pytest.mark.asyncio
async def test_core_rejection_cannot_be_reported_as_success():
    connector = make_connector(DNSConnector)
    connector.submit_findings = AsyncMock(return_value={"accepted": 0, "rejected": 1})
    with pytest.raises(RuntimeError, match="core_rejected_dns_observations"):
        await connector.submit_observations("job-1", [{"subject": "egov.kz"}])


@pytest.mark.asyncio
async def test_ct_keyless_tier_requires_explicit_noncommercial_opt_in():
    """The provider's terms are not a rate limit, so silence is not consent (F-06).

    Keyless access to this API is restricted to non-commercial use. The worker
    refuses to call it until the operator states which tier they are on, exactly as
    the VirusTotal worker already does; a configured token is that statement.
    """
    connector = CTLogsConnector.__new__(CTLogsConnector)
    connector.env = {}
    connector._errors = []
    assert await connector._run_ctlogs(["example.com"]) == []
    assert connector._errors == ["public_tier_noncommercial_ack_required"]


@pytest.mark.asyncio
async def test_ct_token_alone_is_enough_and_the_worker_still_calls_the_api(monkeypatch):
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"rows": [], "has_next": False, "history_window_days": 90})
    mock_transport(monkeypatch, handler)
    keyed = make_connector(CTLogsConnector, {"DNS_SECURITY_CTLOGS_API_TOKEN": "mock-ct-token"})
    rows = await keyed._run_ctlogs(["example.com"])
    assert [row["observation_type"] for row in rows] == ["certificate_check"]
    assert requests, "a keyed worker must still call the API"


@pytest.mark.asyncio
@pytest.mark.parametrize("truncated,state", [(True, "incomplete"), (False, "no_certificate")])
async def test_ct_empty_result_depends_on_the_reported_history_window(monkeypatch, truncated, state):
    """F-03: an index that searched part of the history reports blindness, not calm.

    `history_truncated` is the provider saying the answer covers a window rather
    than the domain's whole life. Reading that as "no certificate" produced a
    monitor that could never fire while the page looked like a clean result.
    """
    def handler(request):
        body = {"rows": [], "has_next": False, "history_window_days": 90}
        if truncated:
            body["history_truncated"] = True
        return httpx.Response(200, json=body)
    mock_transport(monkeypatch, handler)
    connector = make_connector(CTLogsConnector, {"DNS_SECURITY_CTLOGS_PUBLIC_NONCOMMERCIAL": "true"})
    async with httpx.AsyncClient() as client:
        check, evidence = await connector._ct_exact_check(client, "https://api.ctlogs.dev", "example.com", {}, AsyncMock())
    assert check["metadata"]["check_state"] == state
    assert check["metadata"]["history_window_days"] == 90
    assert check["metadata"]["history_truncated"] is truncated
    assert evidence is None
    assert ("history_window_truncated" in connector._errors) is truncated


@pytest.mark.asyncio
async def test_ct_exact_checks_rotate_so_the_tail_of_the_inventory_is_reached(monkeypatch):
    """F-02: a budget smaller than the inventory cannot always buy the same domains.

    Three domains and room for two exact checks per scan: the head must not consume
    every scan, and the domain whose request the budget refused has to say
    "incomplete" rather than "failed", because no check ever ran for it.
    """
    checked = []
    def handler(request):
        if "/v1/domain/" in request.url.path:
            checked.append(request.url.path.rsplit("/", 1)[-1])
        return httpx.Response(200, json={"rows": [], "has_next": False, "history_window_days": 90})
    mock_transport(monkeypatch, handler)
    connector = make_connector(CTLogsConnector, {
        "DNS_SECURITY_CTLOGS_PUBLIC_NONCOMMERCIAL": "true",
        "DNS_SECURITY_CTLOGS_MAX_REQUESTS_PER_SCAN": "2",
        "DNS_SECURITY_CTLOGS_MIN_REQUEST_INTERVAL_SECONDS": "0",
    })
    domains = ["a.example.com", "b.example.com", "c.example.com"]
    rows = await connector._run_ctlogs(domains)
    assert checked == ["a.example.com", "b.example.com"]
    assert {row["subject"]: row["metadata"]["check_state"] for row in rows} == {
        "a.example.com": "no_certificate",
        "b.example.com": "no_certificate",
        "c.example.com": "incomplete",
    }
    checked.clear()
    await connector._run_ctlogs(domains)
    assert checked == ["c.example.com", "a.example.com"]


def test_ct_budget_and_pacing_settings_fall_back_when_unusable():
    """A typo in `.env` must not become an unbounded scan or a silent no-op."""
    from main import _env_float, _env_int
    assert _env_int({"X": "not-a-number"}, "X", 100, 1, 10) == 100
    assert _env_int({"X": "9999"}, "X", 100, 1, 1000) == 100
    assert _env_int({"X": "7"}, "X", 100, 1, 1000) == 7
    assert _env_float({}, "X", 36.0, 0.0, 3600.0) == 36.0
    assert _env_float({"X": "0"}, "X", 36.0, 0.0, 3600.0) == 0.0


@pytest.mark.asyncio
async def test_retry_after_is_not_shortened_below_provider_requirement(monkeypatch):
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(429, headers={"Retry-After": "120"})
    mock_transport(monkeypatch, handler)
    connector = make_connector(DNSConnector)
    async with httpx.AsyncClient() as client:
        _, error, _ = await connector._get_json(client, "https://api.ctlogs.dev/test")
    assert error == "http_429_retry_later"
    assert len(requests) == 1



