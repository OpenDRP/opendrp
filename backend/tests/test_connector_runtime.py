"""Unit tests for first-party connector runtime behavior.

The core connector protocol is covered separately. These tests exercise the
code that runs inside connector containers without contacting real providers,
DNS servers, subprocesses, or target hosts.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest


_ROOT = Path(__file__).resolve().parents[2]
_CONNECTORS = _ROOT / "connectors"
_BASE = _CONNECTORS / "base"
if str(_BASE) not in sys.path:
    sys.path.insert(0, str(_BASE))


def _load_module(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


_dnsmodule = _load_module("opendrp_test_dnstwist", _CONNECTORS / "dnstwist" / "main.py")
_hibpmodule = _load_module("opendrp_test_hibp", _CONNECTORS / "hibp" / "main.py")
_shodanmodule = _load_module("opendrp_test_shodan", _CONNECTORS / "shodan" / "main.py")

DNSTwistConnector = _dnsmodule.DNSTwistConnector
HibpConnector = _hibpmodule.HibpConnector
ShodanConnector = _shodanmodule.ShodanConnector


@pytest.fixture()
def connector_env(monkeypatch: pytest.MonkeyPatch):
    values = {
        "CORE_URL": "http://core:8000",
        "CONNECTOR_TOKEN": "test-token",
        "CONNECTOR_NAME": "test-connector",
        "CONNECTOR_TYPE": "phishing",
        "CONNECTOR_JOB_TYPE": "phishing.test-connector",
        "HIBP_API_KEY": "hibp-test-key",
        "SHODAN_API_KEY": "shodan-test-key",
        "SHODAN_SCAN_SSL_TEXT": "false",
        "SHODAN_SCAN_HTTP_TITLE": "true",
        "SHODAN_SCAN_FAVICON": "false",
        "POLL_INTERVAL_SEC": "0.01",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    return values


class TestHibpConnector:
    def test_normalization_masks_password_and_parses_metadata(self, connector_env):
        connector = HibpConnector()
        finding = connector._normalize_breach(
            {
                "Name": "Acme",
                "Title": "Acme breach",
                "Domain": "acme.example",
                "BreachDate": "2024-01-02T12:00:00Z",
                "PwnCount": "12",
                "Password": "super-secret",
                "DataClasses": ["Passwords"],
                "IsVerified": True,
                "AddedDate": "2024-01-03T10:20:30Z",
            }
        )
        assert finding["breach_name"] == "Acme"
        assert finding["breach_date"] == "2024-01-02"
        assert finding["pwn_count"] == 12
        assert finding["data_classes"] == ["Passwords"]
        # Source-specific knowledge travels in the declared payload, not in core
        # columns: the core has no field for this vendor's classification.
        assert set(finding["attributes"]) >= {"is_verified", "masked_password", "added_date"}
        assert finding["attributes"]["masked_password"] == "su********et"
        assert finding["attributes"]["is_verified"] is True
        assert finding["attributes"]["added_date"].startswith("2024-01-03T10:20:30")

    def test_malformed_provider_counter_is_safe(self, connector_env):
        connector = HibpConnector()
        finding = connector._normalize_breach(
            {"Name": "Malformed", "PwnCount": "not-a-number"}
        )
        assert finding["pwn_count"] == 0

    def test_negative_provider_counter_is_clamped(self, connector_env):
        connector = HibpConnector()
        finding = connector._normalize_breach(
            {"Name": "Negative", "PwnCount": -10}
        )
        assert finding["pwn_count"] == 0

    @pytest.mark.asyncio
    async def test_email_lookup_handles_404_and_malformed_json(self, connector_env):
        connector = HibpConnector()
        responses = [httpx.Response(404), httpx.Response(200, content=b"not-json")]

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.headers["hibp-api-key"] == "hibp-test-key"
            return responses.pop(0)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            assert await connector.search_email_breaches(client, "user@example.com") == []
            assert await connector.search_email_breaches(client, "user@example.com") == []

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", [429, 500, 401, 403])
    async def test_email_lookup_classifies_provider_http_failures(self, connector_env, status):
        connector = HibpConnector()
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: httpx.Response(status))
        ) as client:
            assert await connector.search_email_breaches(client, "user@example.com") == []
        assert connector._provider_errors == [f"http_{status}"]

    @pytest.mark.asyncio
    async def test_email_lookup_classifies_connection_reset(self, connector_env):
        connector = HibpConnector()

        def handler(request):
            raise httpx.ConnectError("connection reset")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            assert await connector.search_email_breaches(client, "user@example.com") == []
        assert connector._provider_errors == ["network_error"]

    async def test_domain_lookup_filters_malformed_alias_entries(self, connector_env):
        connector = HibpConnector()
        payload = {
            "alice": ["BreachA", {"Name": "BreachB"}, {"Name": ""}],
            " ": ["Ignored"],
            "bob": "not-a-list",
        }

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, json=payload))
        ) as client:
            result = await connector.search_domain_breaches(client, "example.com")

        assert result == {"alice": ["BreachA", "BreachB"]}

    @pytest.mark.asyncio
    async def test_scan_expands_domain_aliases_and_submits_normalized_findings(
        self, connector_env, monkeypatch
    ):
        connector = HibpConnector()
        connector.search_email_breaches = AsyncMock(
            return_value=[{"Name": "EmailBreach", "Title": "Email breach"}]
        )
        connector.search_domain_breaches = AsyncMock(
            return_value={"alice": ["DomainBreach"]}
        )
        connector.get_breach_metadata = AsyncMock(
            return_value={"Name": "DomainBreach", "Title": "Domain breach"}
        )
        connector.submit_findings = AsyncMock(return_value={"accepted": 1})
        monkeypatch.setattr(_hibpmodule.asyncio, "sleep", AsyncMock())

        findings, summary = await connector.run_scan(
            {
                "job_id": "job-1",
                "params": {
                    "emails": ["user@example.com"],
                    "domains": ["example.com"],
                },
            }
        )

        assert findings == []
        # ``emails_scanned`` counts monitored *email assets* only. Domain
        # aliases are a distinct unit of work and used to be folded into this
        # counter, which made a single mailbox look like fifteen scanned
        # addresses.
        assert summary["emails_scanned"] == 1
        assert summary["domains_scanned"] == 1
        assert summary["domain_aliases_found"] == 1
        assert summary["new_breach_rows"] == 2
        submitted = [call.args[1] for call in connector.submit_findings.await_args_list]
        assert submitted[0][0]["matched_email"] == "user@example.com"
        assert submitted[1][0]["matched_email"] == "alice@example.com"
        assert submitted[1][0]["matched_domain"] == "example.com"

    @pytest.mark.asyncio
    async def test_scan_keeps_repeated_breach_names_for_distinct_domain_aliases(
        self, connector_env, monkeypatch
    ):
        """A domain scan must preserve the affected-account dimension."""
        connector = HibpConnector()
        connector.search_email_breaches = AsyncMock(return_value=[])
        connector.search_domain_breaches = AsyncMock(
            return_value={
                "account-exists": ["Adobe"],
                "multiple-breaches": ["Adobe", "Gawker"],
            }
        )
        connector.get_breach_metadata = AsyncMock(
            side_effect=lambda client, name: {"Name": name, "Title": name}
        )
        async def accept_batch(job_id, batch):
            return {"accepted": len(batch)}

        connector.submit_findings = AsyncMock(side_effect=accept_batch)
        monkeypatch.setattr(_hibpmodule.asyncio, "sleep", AsyncMock())

        findings, summary = await connector.run_scan(
            {
                "job_id": "job-1",
                "params": {
                    "emails": [],
                    "domains": ["hibp-integration-tests.com"],
                },
            }
        )

        assert findings == []
        assert summary["domain_aliases_found"] == 2
        assert summary["new_breach_rows"] == 3
        submitted = [
            item
            for call in connector.submit_findings.await_args_list
            for item in call.args[1]
        ]
        assert [(item["breach_name"], item["matched_email"]) for item in submitted] == [
            ("Adobe", "account-exists@hibp-integration-tests.com"),
            ("Adobe", "multiple-breaches@hibp-integration-tests.com"),
            ("Gawker", "multiple-breaches@hibp-integration-tests.com"),
        ]

    @pytest.mark.asyncio
    async def test_scan_without_api_key_is_explicitly_skipped(self, connector_env):
        connector = HibpConnector()
        connector.api_key = ""
        findings, summary = await connector.run_scan({"job_id": "job-1", "params": {}})
        assert findings == []
        assert summary["skipped"] == "HIBP_API_KEY not configured"


class TestShodanConnector:
    def test_capabilities_prefer_registry_values_and_use_env_fallbacks(self, connector_env):
        connector = ShodanConnector()
        assert connector._capabilities({}) == {
            "scan_ssl_text": False,
            "scan_http_title": True,
            "scan_favicon": False,
        }
        assert connector._capabilities({"scan_ssl_text": True})["scan_ssl_text"] is True

    @pytest.mark.asyncio
    async def test_search_paginates_and_excludes_owned_hosts(self, connector_env, monkeypatch):
        connector = ShodanConnector()
        responses = [
            {"matches": [{"ip_str": "203.0.113.10", "domains": ["owned.example"]}] * 100},
            {"matches": [{"ip_str": "198.51.100.20", "domains": ["found.example"]}]},
        ]
        calls: list[dict] = []

        class FakeResponse:
            status_code = 200

            def __init__(self, payload):
                self.payload = payload

            def json(self):
                return self.payload

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def get(self, url, **kwargs):
                calls.append(kwargs["params"])
                return FakeResponse(responses.pop(0))

        monkeypatch.setattr(_shodanmodule.httpx, "AsyncClient", lambda **kwargs: FakeClient())
        result = await connector._search("ssl:\"example.com\"", {"owned.example", "203.0.113.10"})

        assert len(calls) == 2
        assert calls[0]["page"] == 1
        assert calls[1]["page"] == 2
        assert result == [{"ip_str": "198.51.100.20", "domains": ["found.example"]}]

    @pytest.mark.asyncio
    async def test_search_retries_rate_limit_using_retry_after(self, connector_env, monkeypatch):
        connector = ShodanConnector()
        connector._min_request_interval = 0
        responses = []

        class FakeResponse:
            def __init__(self, status_code, payload=None, headers=None, text=""):
                self.status_code = status_code
                self._payload = payload or {}
                self.headers = headers or {}
                self.text = text

            def json(self):
                return self._payload

        responses.extend([
            FakeResponse(429, headers={"Retry-After": "0"}, text="rate limited"),
            FakeResponse(200, {"matches": []}),
        ])

        class FakeClient:
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                return None
            async def get(self, *args, **kwargs):
                return responses.pop(0)

        monkeypatch.setattr(_shodanmodule.httpx, "AsyncClient", lambda **kwargs: FakeClient())
        monkeypatch.setattr(_shodanmodule.asyncio, "sleep", AsyncMock())
        assert await connector._search("ssl:\"example.com\"", set()) == []
        assert connector._provider_errors == []

    @pytest.mark.asyncio
    async def test_search_classifies_timeout_without_failing_the_job(self, connector_env, monkeypatch):
        connector = ShodanConnector()
        connector._min_request_interval = 0
        class FakeClient:
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                return None
            async def get(self, *args, **kwargs):
                raise _shodanmodule.httpx.ReadTimeout("provider timeout")
        monkeypatch.setattr(_shodanmodule.httpx, "AsyncClient", lambda **kwargs: FakeClient())
        monkeypatch.setattr(_shodanmodule.asyncio, "sleep", AsyncMock())
        assert await connector._search("ssl:\"example.com\"", set()) == []
        assert connector._provider_errors == ["network_timeout"]

    @pytest.mark.asyncio
    async def test_search_provider_error_returns_empty(self, connector_env, monkeypatch):
        connector = ShodanConnector()

        class FakeResponse:
            status_code = 401
            text = "invalid key"
            headers = {}

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def get(self, *args, **kwargs):
                return FakeResponse()

        monkeypatch.setattr(_shodanmodule.httpx, "AsyncClient", lambda **kwargs: FakeClient())
        assert await connector._search("ssl:\"example.com\"", set()) == []

    @pytest.mark.asyncio
    async def test_scan_skips_when_all_capabilities_disabled(self, connector_env, monkeypatch):
        connector = ShodanConnector()
        connector.api_key = "valid"
        connector._search = AsyncMock()
        connector.submit_findings = AsyncMock()
        findings, summary = await connector.run_scan(
            {
                "job_id": "job-1",
                "config": {
                    "scan_ssl_text": False,
                    "scan_http_title": False,
                    "scan_favicon": False,
                },
                "params": {"keyword_domains": [], "keyword_titles": []},
            }
        )
        assert findings == []
        assert summary["skipped"] == "no_capabilities_enabled"
        connector._search.assert_not_awaited()
        connector.submit_findings.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_favicon_falls_back_to_http_and_submits_findings(self, connector_env, monkeypatch):
        connector = ShodanConnector()
        connector._fetch_favicon = AsyncMock(side_effect=[None, b"icon-bytes"])
        connector._search = AsyncMock(
            return_value=[{"ip_str": "198.51.100.8", "hostnames": ["hit.example"]}]
        )
        connector.submit_findings = AsyncMock(return_value={"accepted": 1})

        tally = await connector._favicon_findings("brand.example", set(), "job-1")
        assert tally["stored"] == 1
        assert tally["matches"] == 1
        assert tally["queries"] == 1
        assert tally["skipped"] is None
        assert connector._fetch_favicon.await_count == 2
        connector._search.assert_awaited_once()
        assert connector._search.await_args.args[0].startswith("http.favicon.hash:")
        submitted = connector.submit_findings.await_args.args[1]
        assert submitted[0]["detection_source"] == "shodan_favicon"

    @pytest.mark.asyncio
    async def test_scan_reports_what_each_capability_found(self, connector_env, monkeypatch):
        """The regression this reporting exists for.

        A rescan that returns fewer findings than expected used to be
        unreadable: the job summary listed the capabilities that *ran* and one
        aggregate count, so "the title search matched a host we already store"
        and "the title search is broken" looked identical. Each capability now
        reports its own queries/matches/candidates/stored.
        """
        connector = ShodanConnector()
        connector.api_key = "valid"

        def matches_for(query: str, exclude: set[str]) -> list[dict]:
            if query.startswith("ssl:"):
                # Two hosts resolving to one domain is how 21 real Shodan hosts
                # collapse to 10 stored rows: `phishing_domain` is unique.
                return [
                    {"ip_str": "203.0.113.7", "domains": ["look-alike.example"]},
                    {"ip_str": "203.0.113.8", "domains": ["look-alike.example"]},
                ]
            if query.startswith("http.title:"):
                return [{"ip_str": "198.51.100.9", "domains": ["known.example"]}]
            return [{"ip_str": "198.51.100.10", "hostnames": ["favicon-hit.example"]}]

        connector._search = AsyncMock(side_effect=matches_for)
        connector._fetch_favicon = AsyncMock(return_value=b"icon-bytes")
        # Every finding is already known: the core rejects duplicates.
        connector.submit_findings = AsyncMock(return_value={"accepted": 0, "rejected": 1})

        findings, summary = await connector.run_scan(
            {
                "job_id": "job-1",
                "config": {"scan_ssl_text": True, "scan_http_title": True, "scan_favicon": True},
                "params": {
                    "keyword_domains": [
                        {"value": "brand.example", "type": "domain"},
                        {"value": "pwned", "type": "keyword_domain"},
                    ],
                    "keyword_titles": ["HIBP"],
                    "exclude": ["owned.example"],
                },
            }
        )

        assert findings == []
        assert summary["capabilities_run"] == ["ssl", "title", "favicon"]
        assert summary["capability_results"]["ssl"] == {
            "queries": 2,
            "matches": 4,
            "candidates": 4,
            "stored": 0,
            "skipped": None,
        }
        # Matched one host, stored none: an already-known domain, not a failure.
        assert summary["capability_results"]["title"] == {
            "queries": 1,
            "matches": 1,
            "candidates": 1,
            "stored": 0,
            "skipped": None,
        }
        assert summary["capability_results"]["favicon"]["queries"] == 1
        assert summary["capability_results"]["favicon"]["matches"] == 1
        assert summary["new_discovered"] == 0
        # The keyword that drove each query is the matched_asset of its findings.
        assert connector._search.await_args_list[0].args[0] == 'ssl:"brand.example"'
        assert connector._search.await_args_list[2].args[0] == 'http.title:"HIBP"'

    @pytest.mark.asyncio
    async def test_favicon_capability_says_when_there_is_nothing_to_hash(
        self, connector_env, monkeypatch
    ):
        connector = ShodanConnector()
        connector.api_key = "valid"
        connector._search = AsyncMock(return_value=[])
        connector._fetch_favicon = AsyncMock(return_value=None)
        connector.submit_findings = AsyncMock(return_value={"accepted": 0})

        _, summary = await connector.run_scan(
            {
                "job_id": "job-1",
                "config": {"scan_ssl_text": False, "scan_http_title": False, "scan_favicon": True},
                "params": {
                    "keyword_domains": [{"value": "brand.example", "type": "domain"}],
                    "keyword_titles": [],
                },
            }
        )

        result = summary["capability_results"]["favicon"]
        # https then http: both attempts, neither returned an icon.
        assert connector._fetch_favicon.await_count == 2
        assert result["skipped"] == "favicon_unavailable"
        assert result["queries"] == 0
        connector._search.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_favicon_capability_says_when_only_keywords_are_configured(
        self, connector_env, monkeypatch
    ):
        connector = ShodanConnector()
        connector.api_key = "valid"
        connector._search = AsyncMock(return_value=[])
        connector._fetch_favicon = AsyncMock(return_value=b"icon-bytes")
        connector.submit_findings = AsyncMock(return_value={"accepted": 0})

        _, summary = await connector.run_scan(
            {
                "job_id": "job-1",
                "config": {"scan_ssl_text": False, "scan_http_title": False, "scan_favicon": True},
                "params": {
                    "keyword_domains": [{"value": "pwned", "type": "keyword_domain"}],
                    "keyword_titles": [],
                },
            }
        )

        assert summary["capability_results"]["favicon"]["skipped"] == "no_domain_assets"
        connector._fetch_favicon.assert_not_awaited()
        connector._search.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_favicon_follows_a_same_host_redirect(self, connector_env, monkeypatch):
        monkeypatch.setenv("TESTING", "1")
        connector = ShodanConnector()
        requested: list[str] = []

        class FakeResponse:
            def __init__(self, status_code, headers=None, content=b""):
                self.status_code = status_code
                self.headers = headers or {}
                self.content = content

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def get(self, url, **kwargs):
                requested.append(url)
                if url.endswith("/favicon.ico"):
                    return FakeResponse(301, {"location": "https://brand.example/static/icon.png"})
                return FakeResponse(200, content=b"icon-bytes")

        monkeypatch.setattr(_shodanmodule.httpx, "AsyncClient", lambda **kwargs: FakeClient())
        assert await connector._fetch_favicon("brand.example", "https") == b"icon-bytes"
        assert requested == [
            "https://brand.example/favicon.ico",
            "https://brand.example/static/icon.png",
        ]

    @pytest.mark.asyncio
    async def test_favicon_refuses_an_off_host_redirect(self, connector_env, monkeypatch):
        """A redirect is a network target the asset chose; it must not widen the scan."""
        monkeypatch.setenv("TESTING", "1")
        connector = ShodanConnector()
        requested: list[str] = []

        class FakeResponse:
            status_code = 301
            headers = {"location": "http://169.254.169.254/latest/meta-data/"}
            content = b""

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def get(self, url, **kwargs):
                requested.append(url)
                return FakeResponse()

        monkeypatch.setattr(_shodanmodule.httpx, "AsyncClient", lambda **kwargs: FakeClient())
        assert await connector._fetch_favicon("brand.example", "https") is None
        assert requested == ["https://brand.example/favicon.ico"]

    def test_same_host_redirect_rebuilds_the_url_from_the_validated_host(self):
        assert ShodanConnector._same_host_redirect("file:///etc/passwd", "brand.example") is None
        assert ShodanConnector._same_host_redirect("//evil.example/x", "brand.example") is None
        assert ShodanConnector._same_host_redirect("http://evil.example/x", "brand.example") is None
        # The authority is compared, so userinfo cannot smuggle another host in.
        assert (
            ShodanConnector._same_host_redirect("https://brand.example@evil.example/x", "brand.example")
            is None
        )
        assert (
            ShodanConnector._same_host_redirect("https://user:pw@brand.example/x", "brand.example")
            == "https://brand.example/x"
        )
        assert (
            ShodanConnector._same_host_redirect("https://brand.example/a?b=1", "brand.example")
            == "https://brand.example/a?b=1"
        )


class TestDnstwistConnector:
    @pytest.mark.asyncio
    async def test_empty_scan_does_not_spawn_process(self, connector_env, monkeypatch):
        connector = DNSTwistConnector()
        spawn = AsyncMock()
        monkeypatch.setattr(_dnsmodule.asyncio, "create_subprocess_exec", spawn)
        findings, summary = await connector.run_scan({"job_id": "job-1", "params": {}})
        assert findings == []
        assert summary["domains_scanned"] == 0
        spawn.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_command_uses_bounded_defaults_and_system_dns(self, connector_env, monkeypatch):
        connector = DNSTwistConnector()
        captured = {}

        class FakeProcess:
            returncode = 0

            async def communicate(self):
                return b"[]", b""

        async def fake_spawn(*args, **kwargs):
            captured["args"] = args
            return FakeProcess()

        monkeypatch.setattr(_dnsmodule.asyncio, "create_subprocess_exec", fake_spawn)
        await connector.run_domain("example.com", "job-1")
        command = list(captured["args"])
        assert "--fuzzers" in command
        assert "homoglyph" not in command[command.index("--fuzzers") + 1]
        assert "--tld" not in command
        assert "--nameservers" not in command
        assert command[command.index("--threads") + 1] == "8"

    @pytest.mark.asyncio
    async def test_run_domain_filters_original_and_unresolved_entries(
        self, connector_env, monkeypatch
    ):
        connector = DNSTwistConnector()
        payload = [
            {"domain": "example.com", "fuzzer": "*original", "dns_a": ["192.0.2.1"]},
            {"domain": "evil.example", "fuzzer": "homoglyph", "dns_a": ["!invalid"]},
            {
                "domain": "phish.example",
                "fuzzer": "addition",
                "dns_a": ["198.51.100.4"],
            },
        ]

        class FakeProcess:
            returncode = 0

            async def communicate(self):
                return json.dumps(payload).encode(), b""

        async def fake_spawn(*args, **kwargs):
            assert args[0] == "dnstwist"
            assert args[-1] == "example.com"
            return FakeProcess()

        class FakeResolver:
            def __init__(self, **kwargs):
                pass

            async def query(self, *args, **kwargs):
                return []

        class FakeWriter:
            def close(self):
                return None

            async def wait_closed(self):
                return None

        monkeypatch.setattr(_dnsmodule.asyncio, "create_subprocess_exec", fake_spawn)
        monkeypatch.setattr(_dnsmodule.aiodns, "DNSResolver", FakeResolver)
        monkeypatch.setattr(
            _dnsmodule.asyncio,
            "open_connection",
            AsyncMock(return_value=(SimpleNamespace(), FakeWriter())),
        )
        connector.submit_findings = AsyncMock(return_value={"accepted": 1})

        tally = await connector.run_domain("example.com", "job-1")
        # Two permutations survived the original-domain filter, one resolved to
        # a public address, and the core stored it.
        assert tally == {"candidates": 2, "resolved": 1, "stored": 1}
        connector.submit_findings.assert_awaited_once()
        finding = connector.submit_findings.await_args.args[1][0]
        assert finding["phishing_domain"] == "phish.example"
        assert finding["original_domain"] == "example.com"

    @pytest.mark.asyncio
    async def test_run_domain_timeout_kills_process(self, connector_env, monkeypatch):
        connector = DNSTwistConnector()
        killed = {"value": False}

        class HangingProcess:
            returncode = 0

            async def communicate(self):
                raise asyncio.TimeoutError

            def kill(self):
                killed["value"] = True

        async def fake_spawn(*args, **kwargs):
            return HangingProcess()

        monkeypatch.setattr(_dnsmodule.asyncio, "create_subprocess_exec", fake_spawn)
        monkeypatch.setattr(_dnsmodule, "_DNSTWIST_SUBPROCESS_TIMEOUT", 0.001)
        assert await connector.run_domain("example.com", "job-1") == {
            "candidates": 0,
            "resolved": 0,
            "stored": 0,
        }
        assert killed["value"] is True

    @pytest.mark.asyncio
    async def test_summary_separates_generated_resolved_and_stored(
        self, connector_env, monkeypatch
    ):
        """A scan that discovered nothing has to say which of the three steps
        produced the zero: nothing generated, nothing registered, or nothing new."""
        connector = DNSTwistConnector()
        payload = [
            {"domain": "brand-example.com", "fuzzer": "addition", "dns_a": ["198.51.100.4"]},
            {"domain": "brrand.example", "fuzzer": "repetition"},
        ]

        class FakeProcess:
            returncode = 0

            async def communicate(self):
                return json.dumps(payload).encode(), b""

        async def fake_spawn(*args, **kwargs):
            return FakeProcess()

        class FakeResolver:
            def __init__(self, **kwargs):
                pass

            async def query(self, *args, **kwargs):
                return []

        class FakeWriter:
            def close(self):
                return None

            async def wait_closed(self):
                return None

        monkeypatch.setattr(_dnsmodule.asyncio, "create_subprocess_exec", fake_spawn)
        monkeypatch.setattr(_dnsmodule.aiodns, "DNSResolver", FakeResolver)
        monkeypatch.setattr(
            _dnsmodule.asyncio,
            "open_connection",
            AsyncMock(return_value=(SimpleNamespace(), FakeWriter())),
        )
        # The resolved look-alike is one the platform already stores.
        connector.submit_findings = AsyncMock(return_value={"accepted": 0, "rejected": 1})

        _, summary = await connector.run_scan(
            {"job_id": "job-1", "params": {"domains": ["brand.example"]}}
        )

        assert summary["candidates"] == 2
        assert summary["resolved"] == 1
        assert summary["new_discovered"] == 0
        assert summary["domains_with_errors"] == 0
