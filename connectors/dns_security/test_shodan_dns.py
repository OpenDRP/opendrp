"""The Shodan DNS worker: one free confirmation, one capped credit per scan.

Two provider answers are behind this worker and they are priced differently (a live
spike on 2026-10-15 confirmed both, and one trap):

* ``/shodan/host/{ip}`` is free and rate limited. It names the certificate an address
  serves, which is what turns "this certificate is ours" into a fact an independent
  index agrees with, and it brings the organisation, ASN, JARM, title and favicon hash
  the certificate rules score on.
* ``/shodan/host/search`` spends one query credit per request (100 a month on a free
  plan), so it is capped per scan and can be switched off. The filter that answers the
  reverse question is ``ssl.cert.fingerprint`` with the *SHA-1* value; the
  plausible-looking ``ssl.cert.fingerprint.sha256`` filter is accepted by the provider
  and silently matches nothing, which is why the query this worker builds is pinned here
  rather than left to the next reader's judgement.

These tests also pin the two things that make the answer trustworthy: only addresses the
platform itself names are asked about, and every physical request is reserved against
the account's approved quota before it is sent.
"""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest

from main import SHODAN_POLICY, ShodanConnector, _shodan_asn, _shodan_serial, _shodan_services, _shodan_when
from opendrp_connector.base import ConnectorAPIError

FINGERPRINT = "3f16372e47de329658b5cdce0d88f55b087659b3f5855c955a293976a998052f"
SHA1 = "e6ab3bb512dc4bf0f05e149f4084b97d66b1cb39"
SERIAL = "119760305370515512493719377464821648688"
JARM = "29d3fd00029d29d00042d43d00041d8f924f5255cbc229bc55efa16391da"
ADDRESS = "203.0.113.10"
FOREIGN = "198.51.100.7"
SEARCH_PATH = "/shodan/host/search"


def certificate(
    *,
    fingerprint_sha256: str = FINGERPRINT,
    fingerprint_sha1: str = SHA1,
    serial: str = SERIAL,
) -> dict:
    return {
        "fingerprint": {"sha256": fingerprint_sha256, "sha1": fingerprint_sha1},
        "serial": serial,
        "issued": "20260918200229Z",
        "expires": "20261211200228Z",
        "subject": {"CN": "shop.example.com"},
        "issuer": {"C": "US", "O": "Example CA", "CN": "Example CA R1"},
        "extensions": [
            {
                "name": "subjectAltName",
                "data": "DNS:shop.example.com, DNS:*.example.com, IP Address:203.0.113.10",
            }
        ],
    }


def service(port: int = 443, jarm: str = JARM) -> dict:
    return {
        "port": port,
        "transport": "tcp",
        "ssl": {"jarm": jarm, "cert": certificate()},
        "http": {"title": "Example Shop", "favicon": {"hash": 12345}},
    }


def host_document(*, address: str = ADDRESS, data: list | None = None) -> dict:
    """The shape ``/shodan/host/{ip}`` answered with in the spike."""
    return {
        "ip_str": address,
        "org": "Example Hosting LLC",
        "asn": "AS64500",
        "ports": [443],
        "hostnames": ["shop.example.com"],
        "last_update": "2026-10-01T00:00:00.000000",
        "data": data if data is not None else [service()],
    }


def match_document(*, hostname: str = "edge.example.net") -> dict:
    """The shape one ``host search`` match had in the spike."""
    return {
        "ip_str": FOREIGN,
        "port": 8443,
        "transport": "tcp",
        "org": "Example Clone Hosting",
        "asn": "AS64501",
        "timestamp": "2026-10-01T12:00:00.000000",
        "hostnames": [hostname],
        "domains": ["example.net"],
        "ssl": {"jarm": JARM, "cert": certificate()},
        "http": {"title": "Example Shop", "favicon": {"hash": 12345}},
    }


def work(*, domains=(), ips=(), config=None) -> dict:
    return {
        "job_id": "job-1",
        "params": {"domains": list(domains), "ips": list(ips)},
        "config": config or {},
    }


def make_connector(env=None) -> ShodanConnector:
    connector = ShodanConnector.__new__(ShodanConnector)
    connector.env = {"SHODAN_API_KEY": "mock-only", **(env or {})}
    connector._errors = []
    connector._scan_facts = {}
    connector._client_timeout = httpx.Timeout(1)
    connector._shodan_api_key = AsyncMock(return_value="mock-only")
    connector.reserve_provider_request = AsyncMock()
    return connector


def mock_transport(monkeypatch, handler):
    original = httpx.AsyncClient
    monkeypatch.setattr(
        "main.httpx.AsyncClient",
        lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs),
    )
    monkeypatch.setattr("main.asyncio.sleep", AsyncMock())


def json_route(calls: list):
    """A handler that answers the search path first and every lookup with one host."""

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.url.path, dict(request.url.params)))
        if request.url.path == SEARCH_PATH:
            return httpx.Response(200, json={"total": 0, "matches": []})
        return httpx.Response(200, json=host_document())

    return handler


def searches(calls: list) -> list[str]:
    return [params["query"] for path, params in calls if path == SEARCH_PATH]


def lookups(calls: list) -> list[str]:
    return [path for path, _ in calls if path != SEARCH_PATH]


# ==============================================================================
# The free half: confirmation without a credit
# ==============================================================================
@pytest.mark.asyncio
async def test_the_free_host_lookup_confirms_without_spending_a_credit(monkeypatch):
    calls: list = []
    mock_transport(monkeypatch, json_route(calls))
    connector = make_connector()
    rows = await connector._run_shodan(work(ips=[ADDRESS], config={"max_searches": 0}))

    assert lookups(calls) == [f"/shodan/host/{ADDRESS}"]
    assert searches(calls) == []
    assert [call.args[0] for call in connector.reserve_provider_request.await_args_list] == ["lookup"]
    assert [row["observation_type"] for row in rows] == ["host_lookup"]

    row = rows[0]
    assert row["subject"] == ADDRESS
    assert row["value"] == ADDRESS
    assert row["record_type"] == "TLS:443"
    assert row["expires_at"] == "2026-12-11T20:02:28+00:00"

    metadata = row["metadata"]
    assert metadata["host_lookup_confirmed"] is True
    assert metadata["ip"] == ADDRESS
    assert metadata["port"] == 443
    assert metadata["lookup"] == "host_lookup"
    assert metadata["evidence"] == "shodan_host_lookup"
    assert metadata["org"] == "Example Hosting LLC"
    assert metadata["asn"] == 64500
    assert metadata["jarm"] == JARM
    # One fact, both spellings: R4 compares the same key on both sides of the echo, and
    # the source that reports the other side uses whichever spelling its provider does.
    assert metadata["title"] == metadata["http_title"] == "Example Shop"
    assert metadata["favicon_hash"] == metadata["http_favicon_hash"] == 12345
    assert metadata["fingerprint_sha256"] == FINGERPRINT
    assert metadata["fingerprint_sha1"] == SHA1
    assert metadata["serial_decimal"] == SERIAL
    assert metadata["serial_hex"] == format(int(SERIAL), "x")
    assert metadata["not_before"] == "2026-09-18T20:02:29+00:00"
    assert metadata["not_after"] == "2026-12-11T20:02:28+00:00"
    assert metadata["subject_dn"] == "CN=shop.example.com"
    assert metadata["issuer_dn"] == "C=US, CN=Example CA R1, O=Example CA"
    assert metadata["san_dns"] == ["shop.example.com", "example.com"]
    assert metadata["open_ports"] == [443]
    assert metadata["hostnames"] == ["shop.example.com"]


@pytest.mark.asyncio
async def test_a_host_without_a_certificate_is_recorded_not_guessed(monkeypatch):
    calls: list = []
    document = host_document(data=[{"port": 80, "http": {"title": "Example"}}])

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.url.path, dict(request.url.params)))
        return httpx.Response(200, json=document)

    mock_transport(monkeypatch, handler)
    connector = make_connector()
    rows = await connector._run_shodan(work(ips=[ADDRESS]))

    assert [row["observation_type"] for row in rows] == ["host_lookup"]
    metadata = rows[0]["metadata"]
    assert metadata["check_state"] == "no_certificate"
    assert "fingerprint_sha256" not in metadata
    assert rows[0]["record_type"] == "HOST"
    # Nothing was discovered, so nothing is asked about: no credit is spent on a
    # certificate the provider never reported.
    assert lookups(calls) == [f"/shodan/host/{ADDRESS}"]
    assert searches(calls) == []


# ==============================================================================
# The paid half: one credit, one question, the filter that actually matches
# ==============================================================================
@pytest.mark.asyncio
async def test_the_search_asks_about_the_certificate_with_its_sha1(monkeypatch):
    calls: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.url.path, dict(request.url.params)))
        if request.url.path == SEARCH_PATH:
            return httpx.Response(200, json={"total": 1, "matches": [match_document()]})
        return httpx.Response(200, json=host_document())

    mock_transport(monkeypatch, handler)
    connector = make_connector()
    rows = await connector._run_shodan(work(ips=[ADDRESS]))

    assert searches(calls) == [f'ssl.cert.fingerprint:"{SHA1}"']
    # The SHA-1 is the filter that answers this question; the SHA-256 spelling of the
    # same field is accepted by the provider and matches nothing (spike, 2026-10-15).
    assert FINGERPRINT not in searches(calls)[0]
    assert [params["page"] for path, params in calls if path == SEARCH_PATH] == ["1"]

    # One lookup, then one search: the paid request is reserved as its own bucket.
    assert [call.args[0] for call in connector.reserve_provider_request.await_args_list] == ["lookup", "search"]

    responses = [row for row in rows if row["observation_type"] == "certificate_response"]
    assert len(responses) == 1
    row = responses[0]
    assert row["subject"] == "edge.example.net"
    assert row["value"] == "https://edge.example.net:8443"
    metadata = row["metadata"]
    assert metadata["ip"] == FOREIGN
    assert metadata["port"] == 8443
    assert metadata["fingerprint_sha256"] == FINGERPRINT
    assert metadata["source_domain"] == ADDRESS
    assert metadata["wildcard"] is False
    assert metadata["matched_by"] == "searched_fingerprint"
    assert metadata["host_lookup_confirmed"] is True
    assert metadata["org"] == "Example Clone Hosting"
    assert metadata["asn"] == 64501
    assert metadata["jarm"] == JARM
    assert metadata["title"] == metadata["http_title"] == "Example Shop"
    assert metadata["favicon_hash"] == metadata["http_favicon_hash"] == 12345
    assert metadata["provider_observed_at"] == "2026-10-01T12:00:00.000000"

    assert connector._scan_facts == {
        "addresses": 1,
        "host_lookups": 1,
        "search_requests": 1,
        "search_candidates": 1,
    }


@pytest.mark.asyncio
async def test_the_paid_half_is_switched_off_by_a_zero_cap(monkeypatch):
    calls: list = []
    mock_transport(monkeypatch, json_route(calls))
    connector = make_connector()
    rows = await connector._run_shodan(work(ips=[ADDRESS], config={"max_searches": 0}))

    assert searches(calls) == []
    assert [row["observation_type"] for row in rows] == ["host_lookup"]
    # A scan that found a certificate it was not allowed to ask about is a partial
    # answer, and saying so is what keeps a zero-cap scan readable.
    assert "search_budget_reached" in connector._errors
    assert connector._scan_facts["search_requests"] == 0
    assert connector._scan_facts["search_candidates"] == 1


@pytest.mark.asyncio
async def test_the_serial_is_only_asked_when_the_scan_still_has_budget(monkeypatch):
    calls: list = []
    mock_transport(monkeypatch, json_route(calls))

    # One credit is the default: the fingerprint question is asked and the serial
    # fallback is not, because a search that matched nothing still cost a credit.
    connector = make_connector()
    await connector._run_shodan(work(ips=[ADDRESS]))
    assert searches(calls) == [f'ssl.cert.fingerprint:"{SHA1}"']

    calls.clear()
    connector = make_connector()
    await connector._run_shodan(work(ips=[ADDRESS], config={"max_searches": 2}))
    assert searches(calls) == [f'ssl.cert.fingerprint:"{SHA1}"', f'ssl.cert.serial:"{SERIAL}"']


# ==============================================================================
# Budgets, refusals, and the addresses this worker may ask about
# ==============================================================================
@pytest.mark.asyncio
async def test_a_quota_refusal_stops_the_paid_half_without_losing_the_free_one(monkeypatch):
    calls: list = []
    mock_transport(monkeypatch, json_route(calls))
    connector = make_connector()
    connector.reserve_provider_request = AsyncMock(
        side_effect=[None, ConnectorAPIError(429, "Provider request budget exhausted")]
    )
    rows = await connector._run_shodan(work(ips=[ADDRESS]))

    assert "provider_quota_refused" in connector._errors
    assert [row["observation_type"] for row in rows] == ["host_lookup"]
    # The lookup was answered before the refusal, and the search was never sent.
    assert lookups(calls) == [f"/shodan/host/{ADDRESS}"]
    assert searches(calls) == []


@pytest.mark.asyncio
async def test_the_host_lookup_budget_bounds_the_addresses(monkeypatch):
    calls: list = []
    mock_transport(monkeypatch, json_route(calls))
    connector = make_connector()
    rows = await connector._run_shodan(
        work(
            ips=[ADDRESS, "203.0.113.11", "203.0.113.12"],
            config={"max_host_lookups": 1, "max_searches": 0},
        )
    )

    assert lookups(calls) == [f"/shodan/host/{ADDRESS}"]
    assert "host_lookup_budget_reached" in connector._errors
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_a_capability_outside_its_range_is_refused_rather_than_clamped(monkeypatch):
    calls: list = []
    mock_transport(monkeypatch, json_route(calls))
    connector = make_connector()
    rows = await connector._run_shodan(work(ips=[ADDRESS], config={"max_searches": 99}))

    assert rows == []
    assert calls == []
    assert connector._errors == ["invalid_scan_policy"]


@pytest.mark.asyncio
async def test_only_addresses_the_platform_names_are_asked_about(monkeypatch):
    calls: list = []
    mock_transport(monkeypatch, json_route(calls))
    monkeypatch.setattr(
        "main.resolve_public_ips",
        lambda host: ("203.0.113.20",) if host == "shop.example.com" else (),
    )

    connector = make_connector()
    rows = await connector._run_shodan(
        work(
            domains=["shop.example.com", "unresolvable.example.com"],
            ips=["8.8.8.8", "not-an-ip"],
            config={"max_searches": 0},
        )
    )

    assert lookups(calls) == ["/shodan/host/203.0.113.20", "/shodan/host/8.8.8.8"]
    assert "no_public_address" in connector._errors
    # The monitored name is kept where the platform has one as the subject, and the
    # address is the subject when the address itself is the asset - while the address
    # is always what the provider was asked about.
    assert sorted(row["subject"] for row in rows) == ["8.8.8.8", "shop.example.com"]
    assert sorted(row["metadata"]["ip"] for row in rows) == ["203.0.113.20", "8.8.8.8"]


@pytest.mark.asyncio
async def test_the_provider_key_comes_from_the_core_before_the_environment(monkeypatch):
    calls: list = []
    mock_transport(monkeypatch, json_route(calls))
    connector = make_connector(env={"SHODAN_API_KEY": "environment-key"})
    del connector._shodan_api_key
    connector._request = AsyncMock(
        return_value=httpx.Response(200, json={"configured": True, "api_key": "core-key"})
    )

    await connector._run_shodan(work(ips=[ADDRESS], config={"max_searches": 0}))

    assert connector._request.await_args_list[0].args[:2] == (
        "GET",
        "/api/v1/connectors/me/credential",
    )
    assert connector.env["SHODAN_API_KEY"] == "core-key"
    assert lookups(calls) == [f"/shodan/host/{ADDRESS}"]


@pytest.mark.asyncio
async def test_no_key_means_no_provider_request_at_all(monkeypatch):
    calls: list = []
    mock_transport(monkeypatch, json_route(calls))
    connector = make_connector()
    connector._shodan_api_key = AsyncMock(return_value="")

    rows = await connector._run_shodan(work(ips=[ADDRESS]))

    assert rows == []
    assert calls == []
    assert connector._errors == ["api_key_not_configured"]


# ==============================================================================
# What the core needs from the worker: declaration, readiness and summary
# ==============================================================================
def test_the_manifest_declares_both_capabilities_within_their_ranges(monkeypatch):
    monkeypatch.setenv("CONNECTOR_JOB_TYPE", "dns.shodan")
    connector = ShodanConnector.__new__(ShodanConnector)
    schema = connector.manifest_payload()["config_schema"]

    assert set(schema) == set(SHODAN_POLICY)
    assert schema["max_searches"]["default"] == 1
    assert "0..20" in schema["max_searches"]["description"]
    assert "0..500" in schema["max_host_lookups"]["description"]


@pytest.mark.asyncio
async def test_registration_declares_capabilities_and_both_operation_buckets():
    connector = ShodanConnector.__new__(ShodanConnector)
    connector.name = "dns-shodan"
    connector.connector_type = "dns"
    connector.api_version = "1.0"
    connector.env = {}
    connector._errors = []
    connector.manifest = {
        "default_job_type": "dns.shodan",
        "finding_kind": "dns_observation",
        "asset_types": ["domain", "ip_address"],
        "config_schema": {},
    }
    connector._request = AsyncMock(return_value=httpx.Response(200, json={}))

    await connector.register()

    assert connector._request.await_args_list[0].args[:2] == ("POST", "/api/v1/connectors/register")
    readiness = connector._request.await_args_list[1]
    assert readiness.args[:2] == ("POST", "/api/v1/connectors/me/readiness")
    body = readiness.kwargs["json"]
    # The two buckets are what the worker may reserve provider quota against; the core
    # refuses any other one.
    assert body["operations"] == ["lookup", "search"]
    assert {"certificate", "hostname", "ip", "title", "favicon", "lookup"} <= set(body["capabilities"])
    assert body["credentials_configured"] is False


@pytest.mark.asyncio
async def test_a_scan_with_only_monitored_addresses_is_work_not_a_skip():
    connector = make_connector()
    connector.SOURCE = "shodan"
    connector._run_shodan = AsyncMock(
        return_value=[
            {
                "observation_type": "host_lookup",
                "subject": ADDRESS,
                "value": ADDRESS,
                "record_type": "TLS:443",
                "metadata": {"ip": ADDRESS, "host_lookup_confirmed": True},
            }
        ]
    )
    connector.submit_observations = AsyncMock()

    findings, summary = await connector.run_scan(work(ips=[ADDRESS]))

    assert findings == []
    assert summary["status"] == "success"
    assert summary["domains_scanned"] == 0
    assert summary["observations"] == 1
    assert connector.submit_observations.await_count == 1


def test_the_service_list_is_bounded_and_one_row_per_port():
    document = {"data": [{"port": 443, "ssl": {}}, {"port": 443, "ssl": {}}, {"port": "x"}, 7]}
    assert [entry.get("port") for entry in _shodan_services(document)] == [443, "x"]
    assert _shodan_services({"ssl": {"cert": {}}}) == [{"ssl": {"cert": {}}}]
    assert _shodan_services({"data": []}) == []


def test_the_timestamp_parser_refuses_anything_but_the_provider_shape():
    assert _shodan_when("20260918200229Z") == "2026-09-18T20:02:29+00:00"
    assert _shodan_when("2026-09-18T20:02:29Z") is None
    assert _shodan_when(None) is None


def test_the_asn_and_serial_parsers_refuse_what_they_cannot_read():
    assert _shodan_asn("AS64500") == 64500
    assert _shodan_asn(64500) == 64500
    assert _shodan_asn("AS") is None
    assert _shodan_asn(True) is None
    assert _shodan_asn(2**32) is None
    assert _shodan_serial(SERIAL) == (format(int(SERIAL), "x"), SERIAL)
    assert _shodan_serial("1234")[0] == "4d2"
    assert _shodan_serial("0x1f") == (None, None)
    assert _shodan_serial("1" * 200) == (None, None)


# ==============================================================================
# The contract with the core, read from the core
# ==============================================================================
_CORE = Path(__file__).resolve().parents[2] / "backend" / "app" / "services" / "tls_identity_service.py"


def _core_source() -> str:
    return _CORE.read_text(encoding="utf-8")


def test_the_signals_this_worker_writes_are_the_keys_the_rules_read():
    """The other half of ``backend/tests/test_signal_producers.py``.

    That gate checks that the declared producer *mentions* each signal; this one checks
    that the keys the worker actually puts in an observation are the keys the scoring
    reads, and that a fingerprint the projection recognises is among them. A rename on
    either side is caught here instead of showing up as a rule that never fires.
    """
    core = _core_source()
    declared = re.search(r"SIGNAL_KEYS = \((.*?)\)\n", core, re.S)
    assert declared is not None, "the core's signal declaration was not found"
    signal_keys = set(re.findall(r'"([a-z_]+)"', declared.group(1)))
    assert signal_keys == {
        "org", "asn", "jarm", "title", "favicon_hash", "http_title", "http_favicon_hash", "host_lookup_confirmed",
    }

    source = Path(__file__).with_name("main.py").read_text(encoding="utf-8")
    written = set(re.findall(r'signals\["([a-z_]+)"\]', source))
    # The confirmation flag is not a fact read out of a provider document: it is the
    # fact that the document was read, so it is written beside the parsed signals.
    assert signal_keys - {"host_lookup_confirmed"} <= written, (
        f"the worker does not write: {sorted(signal_keys - written - {'host_lookup_confirmed'})}"
    )
    assert '"host_lookup_confirmed": True' in source
    assert '"fingerprint_sha256"' in source, "the projection builds an identity from this key"


def test_the_confirmation_flag_the_rule_reads_is_the_one_this_worker_writes():
    rule = re.search(
        r'confirmed = any\(row\.signals\.get\("([a-z_]+)"\)', _core_source()
    )
    assert rule is not None, "R1's confirmation lookup was not found"
    source = Path(__file__).with_name("main.py").read_text(encoding="utf-8")
    assert f'"{rule.group(1)}"' in source


def test_a_host_lookup_is_evidence_the_core_reads_as_ours():
    """The worker's promise and the projection's assumption, checked together.

    The projection reads a ``host_lookup`` row as evidence about our own service, which
    is only true while this worker asks about addresses the platform itself named.
    """
    core = _core_source()
    assert 'observation.observation_type == "host_lookup"' in core
    source = Path(__file__).with_name("main.py").read_text(encoding="utf-8")
    assert '"observation_type": "host_lookup"' in source
