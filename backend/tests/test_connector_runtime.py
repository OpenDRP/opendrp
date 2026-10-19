"""Unit tests for first-party connector runtime behavior.

The core connector protocol is covered separately. These tests exercise the
code that runs inside connector containers without contacting real providers,
DNS servers, subprocesses, or target hosts.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import socket
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

    @pytest.mark.asyncio
    async def test_a_rate_limit_is_answered_once_because_the_provider_bills_it(
        self, connector_env
    ):
        """A retry the vendor did not ask for is a second charge for one answer.

        The shared client retries three times by default; this provider's rule is one
        attempt, and the connector has to state that rather than inherit it.
        """
        connector = HibpConnector()
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.path)
            return httpx.Response(429, headers={"Retry-After": "30"})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            assert await connector.search_email_breaches(client, "user@example.com") == []

        assert len(calls) == 1
        assert connector._provider_errors == ["http_429"]

    @pytest.mark.asyncio
    async def test_an_oversized_answer_is_refused_before_it_is_decoded(self, connector_env):
        """A stranger's body is bounded, and the bound is checked while reading."""
        connector = HibpConnector()
        body = b"[" + b" " * 2_000_001 + b"]"

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=body)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            assert await connector.search_email_breaches(client, "user@example.com") == []

        assert connector._provider_errors == ["response_too_large"]

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


def _leased(connector):
    """Arm a claimed job before a provider request is exercised.

    The core keys provider quota to the job a connector claimed, so every
    provider call is made under a lease: without one the connector refuses the
    request itself, before it is sent. That refusal is a behavior of its own
    (covered by the SDK contract tests); these tests are about what happens after
    a request is allowed, so they arm a lease and stub the reservation call so it
    succeeds without a core.
    """
    connector._active_job = ("job-search", "lease-search")
    connector._min_request_interval = 0
    connector._request = AsyncMock(
        return_value=httpx.Response(200, json={"reserved": True})
    )
    return connector


class _Stream:
    """The transport shape the shared provider client reads through.

    The client streams an answer and never buffers it, so a connector double has to
    present ``stream`` and an ``aiter_bytes`` body instead of the ``get`` call the
    connector used to make itself. This is the shape of the wire, not the behaviour
    under test: every assertion below is the one it was before the migration.
    """

    def __init__(self, response):
        self._response = response

    async def __aenter__(self):
        return self._response

    async def __aexit__(self, *exc_info):
        return False


class TestShodanConnector:
    def test_capabilities_prefer_registry_values_and_use_env_fallbacks(self, connector_env):
        """The three historical questions follow env; every new one is opt-in.

        A capability that spends query credits on a vendor field name nobody has
        confirmed against this account is off until an operator turns it on — see
        ``connectors/shodan/live_check.py``. The env fallbacks still decide the
        three questions that were already being asked.
        """
        connector = ShodanConnector()
        assert connector._capabilities({}) == {
            "scan_ssl_text": False,
            "scan_http_title": True,
            "scan_favicon": False,
            "scan_http_body": False,
            "scan_cert_subject": False,
            "scan_html_hash": False,
            "scan_pivots": False,
            "scan_host_lookup": False,
        }
        assert connector._capabilities({"scan_ssl_text": True})["scan_ssl_text"] is True

    def test_an_opt_in_question_waits_for_the_plan_acknowledgement(self, connector_env):
        """F-12/WI-25: a switch is not a confirmation of the plan it is billed to."""
        connector = ShodanConnector()
        requested = {"scan_ssl_text": False, "scan_http_body": True}

        # The question is off, and the summary is where the operator finds out why.
        assert connector._capabilities(requested)["scan_http_body"] is False
        assert connector._capabilities({**requested, "provider_terms_acknowledged": True})[
            "scan_http_body"
        ] is True

    @pytest.mark.asyncio
    async def test_a_billable_question_without_the_acknowledgement_is_named_not_sent(
        self, connector_env
    ):
        connector = ShodanConnector()
        connector._count = AsyncMock(return_value=0)
        connector.submit_findings = AsyncMock(return_value={"accepted": 0})

        _, summary = await connector.run_scan(
            {
                "job_id": "job-1",
                "config": {"scan_ssl_text": False, "scan_http_body": True},
                "params": {
                    "keyword_domains": [{"value": "brand.example", "type": "keyword_domain"}],
                    "keyword_titles": [],
                },
            }
        )

        assert summary["skipped"]["licence_acknowledgement_required"] == 1
        assert summary["status"] == "skipped"
        # No provider question of any kind was asked: the count is the first request
        # a body search would have made, and it was never sent.
        connector._count.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_the_page_policy_replaces_the_constant_and_a_bad_value_refuses_the_scan(
        self, connector_env, monkeypatch
    ):
        """W3.1: how many result pages a scan pays for is the operator's number.

        The old constant let one rescan of a wide query spend three pages of query
        credits nobody agreed to; the value now arrives from the core with the job
        and is validated here. A value outside its range fails the scan by name
        instead of being clamped to a default the operator did not choose.
        """
        connector = _leased(ShodanConnector())
        connector._policy = {**connector._policy, "max_pages": 2}
        calls: list[dict] = []

        class FakeResponse:
            status_code = 200
            headers: dict = {}

            def json(self):
                return {"matches": [{"ip_str": "198.51.100.20", "domains": ["found.example"]}] * 100}

            async def aiter_bytes(self):
                yield json.dumps(self.json()).encode()

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            def _respond(self, url, **kwargs):
                calls.append(kwargs["params"])
                return FakeResponse()

            def stream(self, method, url, **kwargs):
                return _Stream(self._respond(url, **kwargs))

        monkeypatch.setattr(_shodanmodule.httpx, "AsyncClient", lambda **kwargs: FakeClient())
        await connector._search('ssl:"example.com"', set())
        assert [call["page"] for call in calls] == [1, 2]

        connector.api_key = "valid"
        with pytest.raises(ValueError, match="invalid_scan_policy:max_pages"):
            await connector.run_scan(
                {
                    "job_id": "job-1",
                    "config": {"scan_ssl_text": True, "max_pages": 500},
                    "params": {"keyword_domains": [{"value": "brand.example", "type": "domain"}]},
                }
            )

    @pytest.mark.asyncio
    async def test_a_broad_expression_is_counted_before_any_page_is_paid_for(
        self, connector_env
    ):
        """W3.1/W3.3: a brand in a page body can match without bound.

        The count is asked first, so a result set an operator cannot read to the end
        is refused by name — and an empty one costs no search request at all. Both
        are the difference between one request and the scan's whole page budget.
        """
        connector = ShodanConnector()
        connector.api_key = "valid"
        connector._search = AsyncMock(return_value=[])
        connector._count = AsyncMock(return_value=5000)
        connector.submit_findings = AsyncMock(return_value={"accepted": 0})

        _, summary = await connector.run_scan(
            {
                "job_id": "job-1",
                "config": {
                    "scan_ssl_text": False,
                    "scan_http_body": True,
                    "provider_terms_acknowledged": True,
                },
                "params": {
                    "keyword_domains": [{"value": "brand.example", "type": "keyword_domain"}],
                    "keyword_titles": [],
                },
            }
        )
        assert summary["capability_results"]["body"]["queries"] == 0
        assert summary["skipped"] == {"expression_too_broad": 1}
        assert summary["status"] == "skipped"
        connector._search.assert_not_awaited()
        connector._count.assert_awaited_once_with('http.html:"brand.example"', set())

        connector._count = AsyncMock(return_value=0)
        _, empty = await connector.run_scan(
            {
                "job_id": "job-1",
                "config": {
                    "scan_ssl_text": False,
                    "scan_http_body": True,
                    "provider_terms_acknowledged": True,
                },
                "params": {
                    "keyword_domains": [{"value": "brand.example", "type": "keyword_domain"}],
                    "keyword_titles": [],
                },
            }
        )
        # Counted as zero: nothing matched, and no page was ever requested.
        assert empty["capability_results"]["body"]["queries"] == 0
        assert empty["skipped"] is None
        connector._search.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_search_paginates_and_excludes_owned_hosts(self, connector_env, monkeypatch):
        connector = _leased(ShodanConnector())
        responses = [
            {"matches": [{"ip_str": "203.0.113.10", "domains": ["owned.example"]}] * 100},
            {"matches": [{"ip_str": "198.51.100.20", "domains": ["found.example"]}]},
        ]
        calls: list[dict] = []

        class FakeResponse:
            status_code = 200

            def __init__(self, payload):
                self.payload = payload
                self.headers = {}

            def json(self):
                return self.payload

            async def aiter_bytes(self):
                yield json.dumps(self.payload).encode()

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            def _respond(self, url, **kwargs):
                calls.append(kwargs["params"])
                return FakeResponse(responses.pop(0))

            def stream(self, method, url, **kwargs):
                return _Stream(self._respond(url, **kwargs))

        monkeypatch.setattr(_shodanmodule.httpx, "AsyncClient", lambda **kwargs: FakeClient())
        result = await connector._search("ssl:\"example.com\"", {"owned.example", "203.0.113.10"})

        assert len(calls) == 2
        assert calls[0]["page"] == 1
        assert calls[1]["page"] == 2
        assert result == [{"ip_str": "198.51.100.20", "domains": ["found.example"]}]

    @pytest.mark.asyncio
    async def test_search_retries_rate_limit_using_retry_after(self, connector_env, monkeypatch):
        connector = _leased(ShodanConnector())
        responses = []

        class FakeResponse:
            def __init__(self, status_code, payload=None, headers=None, text=""):
                self.status_code = status_code
                self._payload = payload or {}
                self.headers = headers or {}
                self.text = text

            def json(self):
                return self._payload

            async def aiter_bytes(self):
                yield json.dumps(self._payload).encode()

        responses.extend([
            FakeResponse(429, headers={"Retry-After": "0"}, text="rate limited"),
            FakeResponse(200, {"matches": []}),
        ])

        class FakeClient:
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                return None
            def _respond(self, url, **kwargs):
                return responses.pop(0)
            def stream(self, method, url, **kwargs):
                return _Stream(self._respond(url, **kwargs))

        monkeypatch.setattr(_shodanmodule.httpx, "AsyncClient", lambda **kwargs: FakeClient())
        monkeypatch.setattr(_shodanmodule.asyncio, "sleep", AsyncMock())
        assert await connector._search("ssl:\"example.com\"", set()) == []
        assert connector._provider_errors == []

    @pytest.mark.asyncio
    async def test_search_classifies_timeout_without_failing_the_job(self, connector_env, monkeypatch):
        connector = _leased(ShodanConnector())
        class FakeClient:
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                return None
            def stream(self, *args, **kwargs):
                raise _shodanmodule.httpx.ReadTimeout("provider timeout")
        monkeypatch.setattr(_shodanmodule.httpx, "AsyncClient", lambda **kwargs: FakeClient())
        monkeypatch.setattr(_shodanmodule.asyncio, "sleep", AsyncMock())
        assert await connector._search("ssl:\"example.com\"", set()) == []
        assert connector._provider_errors == ["network_timeout"]

    @pytest.mark.asyncio
    async def test_search_provider_error_returns_empty(self, connector_env, monkeypatch):
        connector = _leased(ShodanConnector())

        class FakeResponse:
            status_code = 401
            text = "invalid key"
            headers = {}

            async def aiter_bytes(self):
                yield self.text.encode()

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            def stream(self, *args, **kwargs):
                return _Stream(FakeResponse())

        monkeypatch.setattr(_shodanmodule.httpx, "AsyncClient", lambda **kwargs: FakeClient())
        assert await connector._search("ssl:\"example.com\"", set()) == []

    @pytest.mark.asyncio
    async def test_a_403_naming_credit_is_reported_as_a_drained_quota(self, connector_env, monkeypatch):
        """The vendor answers 403 for a spent account, so the body is the evidence.

        Without this the operator reads "access denied" and checks the key, while
        the real answer is that the plan's query credits are gone for the day.
        """
        connector = _leased(ShodanConnector())

        class FakeResponse:
            status_code = 403
            headers = {}

            async def aiter_bytes(self):
                yield b'{"error": "Insufficient query credits"}'

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            def stream(self, *args, **kwargs):
                return _Stream(FakeResponse())

        monkeypatch.setattr(_shodanmodule.httpx, "AsyncClient", lambda **kwargs: FakeClient())
        assert await connector._search("ssl:\"example.com\"", set()) == []
        assert connector._provider_errors == ["quota_exhausted"]

    @pytest.mark.asyncio
    async def test_an_oversized_answer_is_refused_before_it_is_decoded(
        self, connector_env, monkeypatch
    ):
        """A stranger's body is bounded, and the bound is checked while reading.

        This connector used to decode whatever arrived; the shared client refuses
        the answer once it crosses the limit, so an oversized payload is never held
        in memory and never parsed.
        """
        connector = _leased(ShodanConnector())
        body = b"{\"matches\": [" + b" " * (_shodanmodule._SHODAN_MAX_RESPONSE_BYTES + 1) + b"]}"

        class FakeResponse:
            status_code = 200
            headers = {}

            async def aiter_bytes(self):
                for start in range(0, len(body), 65536):
                    yield body[start : start + 65536]

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            def stream(self, *args, **kwargs):
                return _Stream(FakeResponse())

        monkeypatch.setattr(_shodanmodule.httpx, "AsyncClient", lambda **kwargs: FakeClient())
        assert await connector._search("ssl:\"example.com\"", set()) == []
        assert connector._provider_errors == ["response_too_large"]

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
        # The summary shape providers report skips in: a reason and how many targets
        # it cost, the same contract the Netlas worker reports (W2.4). A bare string
        # cannot say "two expressions were too broad".
        assert summary["skipped"] == {"no_capabilities_enabled": 1}
        assert summary["status"] == "skipped"
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
    async def test_an_unquotable_keyword_is_skipped_and_reported(self, connector_env, monkeypatch):
        """AST-30: Shodan has no escape for a quote inside a phrase.

        Interpolating ``acme" -host:owned.example`` straight into the query would
        close the phrase there and append filters of its own — the operator's
        scan would search whatever the keyword asked for. The connector refuses
        the phrase and says which keyword it refused.
        """
        connector = ShodanConnector()
        connector.api_key = "valid"
        connector._search = AsyncMock(return_value=[])
        connector.submit_findings = AsyncMock(return_value={"accepted": 0})

        _, summary = await connector.run_scan(
            {
                "job_id": "job-1",
                "config": {"scan_ssl_text": True, "scan_http_title": True, "scan_favicon": False},
                "params": {
                    "keyword_domains": [
                        {"value": 'acme" -host:owned.example', "type": "keyword_domain"},
                        {"value": "acme.example", "type": "domain"},
                    ],
                    "keyword_titles": ['HIBP" OR http.title:"owned.example'],
                },
            }
        )

        assert summary["skipped_keywords"] == [
            'HIBP" OR http.title:"owned.example',
            'acme" -host:owned.example',
        ]
        assert summary["capability_results"]["ssl"]["queries"] == 1
        assert summary["capability_results"]["ssl"]["skipped"] == ['acme" -host:owned.example']
        assert summary["capability_results"]["title"]["queries"] == 0
        assert summary["capability_results"]["title"]["skipped"] == [
            'HIBP" OR http.title:"owned.example'
        ]
        queries = [call.args[0] for call in connector._search.await_args_list]
        assert queries == ['ssl:"acme.example"']
        assert all("owned.example" not in query for query in queries)

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
                self._content = content

            async def aiter_bytes(self):
                yield self._content

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            def stream(self, method, url, **kwargs):
                # The icon is read as it arrives now, so the fake is a transport:
                # it answers with a streaming context manager, as httpx does.
                from contextlib import asynccontextmanager

                response = (
                    FakeResponse(301, {"location": "https://brand.example/static/icon.png"})
                    if url.endswith("/favicon.ico")
                    else FakeResponse(200, content=b"icon-bytes")
                )

                @asynccontextmanager
                async def stream():
                    requested.append(url)
                    yield response

                return stream()

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

            async def aiter_bytes(self):
                yield b""

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            def stream(self, method, url, **kwargs):
                from contextlib import asynccontextmanager

                @asynccontextmanager
                async def stream():
                    requested.append(url)
                    yield FakeResponse()

                return stream()

        monkeypatch.setattr(_shodanmodule.httpx, "AsyncClient", lambda **kwargs: FakeClient())
        assert await connector._fetch_favicon("brand.example", "https") is None
        assert requested == ["https://brand.example/favicon.ico"]

    @pytest.mark.asyncio
    async def test_favicon_stops_reading_at_the_size_bound(self, connector_env, monkeypatch):
        """A target's host must not decide how much of its body this worker holds.

        Eight half-megabyte chunks are four megabytes; the bound is two. The read
        stops at the fourth chunk and the same truncated slice is returned as
        before — what changes is that the rest is never in memory.
        """
        monkeypatch.setenv("TESTING", "1")
        connector = ShodanConnector()
        pulled: list[int] = []
        chunk = b"x" * (_shodanmodule._FAVICON_MAX_BYTES // 4)

        class FakeResponse:
            status_code = 200
            headers: dict = {}

            async def aiter_bytes(self):
                for _ in range(8):
                    pulled.append(len(chunk))
                    yield chunk

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            def stream(self, method, url, **kwargs):
                from contextlib import asynccontextmanager

                @asynccontextmanager
                async def stream():
                    yield FakeResponse()

                return stream()

        monkeypatch.setattr(_shodanmodule.httpx, "AsyncClient", lambda **kwargs: FakeClient())
        icon = await connector._fetch_favicon("brand.example", "https")
        assert icon is not None and len(icon) == _shodanmodule._FAVICON_MAX_BYTES
        assert len(pulled) == 4, "the fifth chunk is never requested"

    def test_the_paid_query_narrows_our_own_hosts_before_it_is_sent(self, connector_env):
        """W3.2: the exclusion belongs in the query, not only after it was paid for.

        Post-filtering is what guarantees nothing of ours is stored; it is not what
        stops the platform paying for our own estate twice a day. The vendor
        documents both filters and the leading-minus form, so they are written into
        the query — and an owned *address* has no documented negative filter, so it
        is left to the local filter instead of being turned into a syntax that does
        not exist.
        """
        connector = ShodanConnector()
        narrowed = connector._narrow('http.title:"acme"', {"owned.example", "203.0.113.9"})
        assert narrowed == 'http.title:"acme" -domain:"owned.example" -hostname:"owned.example"'

        connector._own_org = "Acme Corp"
        assert connector._narrow('ssl:"acme.example"', set()).endswith('-org:"Acme Corp"')

        # The cap bounds how long a paid query gets; the values beyond it are still
        # filtered locally and are reported rather than silently dropped.
        connector = ShodanConnector()
        connector._policy = {**connector._policy, "max_exclusions": 1}
        connector._narrow('http.title:"acme"', {"a.example", "b.example"})
        assert connector._exclusions_dropped == 1

    @pytest.mark.asyncio
    async def test_the_scan_reports_what_it_spent_and_what_the_account_has_left(
        self, connector_env, monkeypatch
    ):
        """W3.1: "we spent 40 of 100" answers nothing about the next scan.

        The reservation's own answer carries the account's remaining requests for the
        day, and the pages past the first are the unit the vendor's credit guide
        bills. Both are reported, so an operator can see a scan approaching its
        budget without opening the provider's console.
        """
        connector = ShodanConnector()
        connector.api_key = "valid"
        connector._active_job = ("job-1", "lease-1")
        connector._min_request_interval = 0
        connector.submit_findings = AsyncMock(return_value={"accepted": 1})
        connector._request = AsyncMock(
            return_value=httpx.Response(
                200, json={"reserved": True, "request_budget": 100, "remaining_today": 98}
            )
        )
        pages = [
            {"matches": [{"ip_str": "198.51.100.7", "domains": ["found.example"]}] * 100},
            {"matches": [{"ip_str": "198.51.100.8", "domains": ["second.example"]}]},
        ]

        class FakeResponse:
            status_code = 200
            headers: dict = {}

            def __init__(self, payload):
                self.payload = payload

            def json(self):
                return self.payload

            async def aiter_bytes(self):
                yield json.dumps(self.payload).encode()

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            def _respond(self, url, **kwargs):
                return FakeResponse(pages.pop(0))

            def stream(self, method, url, **kwargs):
                return _Stream(self._respond(url, **kwargs))

        monkeypatch.setattr(_shodanmodule.httpx, "AsyncClient", lambda **kwargs: FakeClient())
        _, summary = await connector.run_scan(
            {
                "job_id": "job-1",
                "config": {"scan_ssl_text": True, "max_requests": 5},
                "params": {"keyword_domains": [{"value": "brand.example", "type": "domain"}]},
            }
        )
        # Two pages are two provider requests, and each one reserves its own slot:
        # the job's budget is counted in requests, which is what can be resumed
        # mid-scan without a page being paid for twice.
        assert summary["spent"] == 2
        assert summary["budget_left"] == 3
        assert summary["daily_budget"] == 100
        assert summary["daily_budget_left"] == 98
        assert summary["pages"] == 2
        # Two pages fetched, one of them past the first: that is the billed one.
        assert summary["billed_pages"] == 1
        assert summary["provider_errors"] == []

    @pytest.mark.asyncio
    async def test_a_spent_budget_stops_the_scan_with_a_named_reason(self, connector_env):
        """W3.1: a 429 from the core is the account's budget, not a broken provider.

        Recorded as a provider error it would tell the operator their credentials
        failed and leave the readiness row saying so long after the cause passed.
        """
        from opendrp_connector.base import ConnectorAPIError

        connector = ShodanConnector()
        connector.api_key = "valid"
        connector._active_job = ("job-1", "lease-1")
        connector.submit_findings = AsyncMock(return_value={"accepted": 0})
        connector._request = AsyncMock(
            side_effect=ConnectorAPIError(429, "Provider request budget exhausted", retry_after=45)
        )

        _, summary = await connector.run_scan(
            {
                "job_id": "job-1",
                "config": {"scan_ssl_text": True},
                "params": {"keyword_domains": [{"value": "brand.example", "type": "domain"}]},
            }
        )
        assert summary["skipped"] == {"provider_quota_exhausted": 1}
        assert summary["retry_after_seconds"] == 45
        assert summary["provider_errors"] == []
        assert summary["status"] == "skipped"

    @pytest.mark.asyncio
    async def test_certificates_and_html_hashes_are_asked_the_documented_way(
        self, connector_env
    ):
        """W3.3: the two new paid questions, and what they are built from.

        ``ssl.cert.subject.cn`` asks what a *confirmed* look-alike presents; the HTML
        hash pivot cannot be computed here at all — Shodan's crawlers calculate it and
        no algorithm is published — so it is read from the free lookup of our own
        address first. A missing hash is a named skip, not an empty success.
        """
        connector = ShodanConnector()
        connector.api_key = "valid"
        connector._search = AsyncMock(return_value=[])
        connector._count = AsyncMock(return_value=None)
        connector.submit_findings = AsyncMock(return_value={"accepted": 0})
        connector._lookup_host = AsyncMock(
            return_value={"http": {"html_hash": 1234567890}}
        )

        _, summary = await connector.run_scan(
            {
                "job_id": "job-1",
                "config": {
                    "scan_ssl_text": False,
                    "scan_cert_subject": True,
                    "scan_html_hash": True,
                    "provider_terms_acknowledged": True,
                },
                "params": {
                    "keyword_domains": [],
                    "keyword_titles": [],
                    "candidates": ["look-alike.example"],
                    "ips": ["203.0.113.10"],
                },
            }
        )
        queries = [call.args[0] for call in connector._search.await_args_list]
        assert 'ssl.cert.subject.cn:"look-alike.example"' in queries
        assert "http.html_hash:1234567890" in queries
        assert summary["capability_results"]["cert_subject"]["queries"] == 1
        assert summary["capability_results"]["html_hash"]["queries"] == 1
        # Two free lookups of the same owned address, and neither is charged: one
        # learns what the provider calls this installation (the negative filter a
        # pivot needs), the other reads our own page's HTML hash.
        assert [call.args[0] for call in connector._lookup_host.await_args_list] == [
            "203.0.113.10",
            "203.0.113.10",
        ]

        connector._lookup_host = AsyncMock(return_value={})
        _, empty = await connector.run_scan(
            {
                "job_id": "job-1",
                "config": {
                    "scan_ssl_text": False,
                    "scan_html_hash": True,
                    "provider_terms_acknowledged": True,
                },
                "params": {"ips": ["203.0.113.10"], "keyword_domains": [], "keyword_titles": []},
            }
        )
        assert empty["capability_results"]["html_hash"]["skipped"] == "html_hash_unavailable"
        assert empty["capability_results"]["html_hash"]["queries"] == 0

    @pytest.mark.asyncio
    async def test_pivots_are_seeded_by_what_was_found_and_bounded_by_the_policy(
        self, connector_env
    ):
        """W3.3: one look-alike may lead to the actor behind it, and no further.

        The organisation travels with the banner the discovery arrived in (the paid
        answer already contained it), and ``max_pivots`` is what keeps one finding
        from turning a scan into a crawl.
        """
        connector = ShodanConnector()
        connector.api_key = "valid"
        connector._count = AsyncMock(return_value=None)
        connector.submit_findings = AsyncMock(return_value={"accepted": 1})

        async def search(query: str, exclude: set[str], **kwargs) -> list[dict]:
            if query.startswith("ssl:"):
                return [
                    {
                        "ip_str": "198.51.100.44",
                        "domains": ["look-alike.example"],
                        "org": "Acme Hosting",
                    }
                ]
            return [
                {"ip_str": "198.51.100.45", "domains": ["sibling.example"], "org": "Acme Hosting"}
            ]

        connector._search = AsyncMock(side_effect=search)
        _, summary = await connector.run_scan(
            {
                "job_id": "job-1",
                "config": {
                    "scan_ssl_text": True,
                    "scan_pivots": True,
                    "max_pivots": 1,
                    "provider_terms_acknowledged": True,
                },
                "params": {"keyword_domains": [{"value": "brand.example", "type": "domain"}]},
            }
        )
        queries = [call.args[0] for call in connector._search.await_args_list]
        assert queries == ['ssl:"brand.example"', 'org:"Acme Hosting"']
        assert summary["capability_results"]["pivots"]["queries"] == 1
        assert summary["capability_results"]["pivots"]["stored"] == 1

    @pytest.mark.asyncio
    async def test_the_free_lookup_is_not_charged_and_arrives_as_candidate_evidence(
        self, connector_env, monkeypatch
    ):
        """W3.4: an IP lookup costs no query credit, so it reserves nothing.

        Charging the account's ledger for a call the vendor does not bill would make
        the platform refuse enrichment it never paid for. What the lookup answers
        (network, organisation, title, icon hash, JARM, certificate names) is
        submitted as evidence about the look-alike the scan already found — one
        structured row an analyst reads, not a new discovery.
        """
        connector = ShodanConnector()
        connector.api_key = "valid"
        connector._active_job = ("job-1", "lease-1")
        connector._min_request_interval = 0
        connector.submit_findings = AsyncMock(return_value={"accepted": 1})
        # The reservation is counted rather than stubbed away: "the free lookup never
        # reserved" is the property under test, so the reservation path itself has to
        # be the one under observation.
        connector._request = AsyncMock(
            return_value=httpx.Response(
                200, json={"reserved": True, "request_budget": 100, "remaining_today": 98}
            )
        )
        lookup_payload = {
            "asn": "AS64500",
            "org": "Acme Hosting",
            "http": {"title": "Acme sign in", "favicon": {"hash": 12345}, "html_hash": 987654321},
            "ssl": {
                "jarm": "29d29d00029d29d00029d29d29d29d",
                "cert": {"subject": {"CN": "look-alike.example"}, "issuer": {"CN": "R3"}},
            },
        }
        banner = {"ip_str": "198.51.100.44", "domains": ["look-alike.example"], "org": "Acme Hosting"}

        class FakeResponse:
            status_code = 200
            headers: dict = {}

            def __init__(self, payload):
                self.payload = payload

            def json(self):
                return self.payload

            async def aiter_bytes(self):
                yield json.dumps(self.payload).encode()

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            def __init__(self):
                self.lookups = 0

            def _respond(self, url, **kwargs):
                if url.endswith("/search"):
                    return FakeResponse({"matches": [banner]})
                self.lookups += 1
                return FakeResponse(lookup_payload)

            def stream(self, method, url, **kwargs):
                return _Stream(self._respond(url, **kwargs))

        clients: list[FakeClient] = []

        def fake_client(**kwargs):
            client = FakeClient()
            clients.append(client)
            return client

        monkeypatch.setattr(_shodanmodule.httpx, "AsyncClient", fake_client)

        _, summary = await connector.run_scan(
            {
                "job_id": "job-1",
                "config": {
                    "scan_ssl_text": True,
                    "scan_host_lookup": True,
                    "provider_terms_acknowledged": True,
                },
                "params": {"keyword_domains": [{"value": "brand.example", "type": "domain"}]},
            }
        )

        assert summary["capability_results"]["host_lookup"]["stored"] == 1
        assert [item["detection_source"] for item in connector.submit_findings.await_args_list[-1].args[1]] == [
            "shodan_host_lookup"
        ]
        evidence = connector.submit_findings.await_args_list[-1].args[1][0]
        assert evidence["phishing_domain"] == "look-alike.example"
        assert evidence["metadata"]["capability"] == "host_lookup"
        assert evidence["metadata"]["org"] == "Acme Hosting"
        assert evidence["metadata"]["favicon_hash"] == 12345
        assert evidence["metadata"]["html_hash"] == 987654321
        assert evidence["metadata"]["cert_subject_cn"] == "look-alike.example"
        # The free lookup is asked, and never charged: the only reservation the run
        # made belongs to the paid discovery that seeded it, and the lookup was the
        # only free call.
        assert summary["free_lookups"] == 1
        assert summary["spent"] == 1
        assert connector._request.await_count == 1
        assert sum(client.lookups for client in clients) == 1

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
    async def test_startup_readiness_says_no_provider_key_is_needed(self, connector_env):
        """A compute-only worker declares that fact instead of looking key-less."""
        connector = DNSTwistConnector()
        connector._request = AsyncMock(return_value=httpx.Response(200, json={}))

        await connector.register()

        assert connector._request.await_args_list[0].args[:2] == (
            "POST",
            "/api/v1/connectors/register",
        )
        readiness = connector._request.await_args_list[-1]
        assert readiness.args[:2] == ("POST", "/api/v1/connectors/me/readiness")
        body = readiness.kwargs["json"]
        assert body["credentials_configured"] is False
        assert body["credential_state"] == "unknown"
        assert body["capabilities"] == ["domain"]
        # Nothing it does is billed to a metered provider account.
        assert body["operations"] == []

    @pytest.mark.asyncio
    async def test_empty_scan_does_not_spawn_process(self, connector_env, monkeypatch):
        connector = DNSTwistConnector()
        connector._request = AsyncMock(return_value=httpx.Response(200, json={}))
        spawn = AsyncMock()
        monkeypatch.setattr(_dnsmodule.asyncio, "create_subprocess_exec", spawn)
        findings, summary = await connector.run_scan({"job_id": "job-1", "params": {}})
        assert findings == []
        assert summary["domains_scanned"] == 0
        spawn.assert_not_awaited()
        # Even a scan with nothing to do republishes the row, so an operator sees
        # the worker alive without waiting for real work.
        assert connector._request.await_args_list[-1].args[1] == "/api/v1/connectors/me/readiness"

    @pytest.mark.asyncio
    async def test_fuzzer_classes_bring_their_companion_file_or_are_reported(
        self, connector_env, monkeypatch, tmp_path
    ):
        """W4.1/W4.2: the class decides the fuzzer *and* the dictionary it needs.

        The CLI refuses ``--tld``/``--dictionary`` unless the matching fuzzer is in the
        same ``--fuzzers`` list, which is exactly the coupling a raw fuzzer list cannot
        express: the old knob could build an invocation the binary rejects. A class
        whose dictionary is missing is left out by name instead of taking the domain
        down with it.
        """
        connector = DNSTwistConnector()
        connector.fuzzer_classes = ["typo", "tld"]
        captured: list[list[str]] = []

        class FakeProcess:
            returncode = 0

            async def communicate(self):
                return b"[]", b""

        async def fake_spawn(*args, **kwargs):
            captured.append(list(args))
            return FakeProcess()

        monkeypatch.setattr(_dnsmodule.asyncio, "create_subprocess_exec", fake_spawn)
        monkeypatch.setattr(_dnsmodule, "_PACKAGED_TLD_DICTIONARIES", ())
        connector.tld_dictionary = "/nonexistent/tld.dict"
        await connector.run_domain("example.com", "job-1")
        missing = captured[-1]
        assert "--tld" not in missing
        assert "tld-swap" not in missing[missing.index("--fuzzers") + 1]

        dictionary = tmp_path / "tld.dict"
        dictionary.write_text("com\nnet\n", encoding="utf-8")
        connector.tld_dictionary = str(dictionary)
        await connector.run_domain("example.com", "job-1")
        present = captured[-1]
        assert present[present.index("--tld") + 1] == str(dictionary)
        assert "tld-swap" in present[present.index("--fuzzers") + 1]

    @pytest.mark.asyncio
    async def test_the_candidate_cap_is_reported_and_nothing_is_resolved_past_it(
        self, connector_env, monkeypatch
    ):
        """W4.1: the limit is on candidates, and it is where it costs nothing.

        The CLI has no candidate option — it generates what the fuzzers generate — so a
        permutation that never gets resolved and never gets submitted spends no DNS
        request. How many were dropped is reported, because a silent cap and a domain
        with fewer look-alikes look the same in every other counter.
        """
        connector = DNSTwistConnector()
        connector.max_candidates = 2
        built: list[int] = []

        class TrackingResolver:
            def __init__(self, **kwargs):
                built.append(1)

            async def query(self, *args, **kwargs):
                return []

        payload = [
            {"domain": f"hit{n}.example", "fuzzer": "addition", "dns_a": ["198.51.100.4"]}
            for n in range(4)
        ]

        class FakeProcess:
            returncode = 0

            async def communicate(self):
                return json.dumps(payload).encode(), b""

        async def fake_spawn(*args, **kwargs):
            return FakeProcess()

        monkeypatch.setattr(_dnsmodule.asyncio, "create_subprocess_exec", fake_spawn)
        monkeypatch.setattr(_dnsmodule.aiodns, "DNSResolver", TrackingResolver)
        connector.submit_findings = AsyncMock(return_value={"accepted": 1})

        outcome = await connector.run_domain("example.com", "job-1")
        assert outcome.tally["candidates"] == 2
        assert outcome.truncated is True
        # Every candidate carried its own address, so no resolver was needed at all.
        assert built == []

    @pytest.mark.asyncio
    async def test_a_domain_with_nothing_to_resolve_builds_no_resolver(
        self, connector_env, monkeypatch
    ):
        """W4.4, as the regression it was: a domain with no permutations must not need
        a DNS client at all.

        The resolver used to be constructed before the candidate loop, so on a host
        where ``aiodns`` cannot start (Windows without a Selector event loop) a scan
        whose permutations are simply not registered failed outright instead of
        reporting zero.
        """
        connector = DNSTwistConnector()
        built: list[int] = []

        class ExplodingResolver:
            def __init__(self, **kwargs):
                built.append(1)
                raise RuntimeError("aiodns needs a SelectorEventLoop on Windows")

        class FakeProcess:
            returncode = 0

            async def communicate(self):
                return json.dumps(
                    [{"domain": "unregistered.example", "fuzzer": "addition"}]
                ).encode(), b""

        async def fake_spawn(*args, **kwargs):
            return FakeProcess()

        monkeypatch.setattr(_dnsmodule.asyncio, "create_subprocess_exec", fake_spawn)
        monkeypatch.setattr(_dnsmodule.aiodns, "DNSResolver", ExplodingResolver)

        outcome = await connector.run_domain("example.com", "job-1")
        assert outcome.tally == {"candidates": 1, "resolved": 0, "stored": 0}
        assert outcome.error is False
        assert built == [1]

    @pytest.mark.asyncio
    async def test_the_event_loop_resolver_replaces_aiodns_on_a_host_it_cannot_run_on(
        self, connector_env, monkeypatch
    ):
        """W4.4: the fallback resolves through the loop and keeps the same safety rule."""
        connector = DNSTwistConnector()

        class ExplodingResolver:
            def __init__(self, **kwargs):
                raise RuntimeError("aiodns needs a SelectorEventLoop on Windows")

        class FakeLoop:
            async def getaddrinfo(self, name, port, **kwargs):
                # A public address and one that must never be stored: the fallback has
                # to be the same decision, not a weaker one.
                return [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.51.100.7", 0)),
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
                ]

        monkeypatch.setattr(_dnsmodule.aiodns, "DNSResolver", ExplodingResolver)
        monkeypatch.setattr(_dnsmodule.asyncio, "get_running_loop", lambda: FakeLoop())
        assert await connector._resolve_addresses("look-alike.example") == ["198.51.100.7"]

    @pytest.mark.asyncio
    async def test_mail_facts_report_mail_that_has_no_spf_policy(
        self, connector_env, monkeypatch
    ):
        """W4.3: `mx_without_spf` is answered, not inferred.

        The rule reads "accepts mail and publishes no SPF record", so the mail servers
        come from the CLI's MX check and the policy from one free TXT question. A TXT
        lookup that failed reports neither — silence is not "publishes no SPF".
        """
        connector = DNSTwistConnector()
        connector.mx_check = True
        answers: list = []

        class FakeResolver:
            def __init__(self, **kwargs):
                pass

            async def query(self, name, record_type):
                assert record_type == "TXT"
                return answers

        monkeypatch.setattr(_dnsmodule.aiodns, "DNSResolver", FakeResolver)
        facts = await connector._mail_facts("look-alike.example", {"dns_mx": ["mx1.example"], "mx_spy": True})
        assert facts == {
            "mx_hosts": ["mx1.example"],
            "mx_spy": True,
            "mx_without_spf": True,
            "capability": "mx",
        }

        answers.append(SimpleNamespace(text="v=spf1 -all"))
        published = await connector._mail_facts("look-alike.example", {"dns_mx": ["mx1.example"]})
        assert "mx_without_spf" not in published

        # No MX records: there is nothing for the SPF half to mean.
        assert await connector._mail_facts("look-alike.example", {}) == {}

    @pytest.mark.asyncio
    async def test_content_inspection_runs_only_where_the_module_can(
        self, connector_env, monkeypatch
    ):
        """W4.3: a capability the image cannot run is a named skip, not a quiet zero.

        ``--phash`` and screenshots are deliberately not used: they render pages with a
        headless browser, which this connector does not do.
        """
        connector = DNSTwistConnector()
        connector.content_inspection = True
        captured: list[list[str]] = []

        class FakeProcess:
            returncode = 0

            async def communicate(self):
                return b"[]", b""

        async def fake_spawn(*args, **kwargs):
            captured.append(list(args))
            return FakeProcess()

        monkeypatch.setattr(_dnsmodule.asyncio, "create_subprocess_exec", fake_spawn)
        monkeypatch.setattr(_dnsmodule, "_tlsh_available", lambda: False)
        outcome = await connector.run_domain("example.com", "job-1")
        assert "--lsh" not in captured[-1]
        assert outcome.skips == ["content_inspection_unavailable"]

        monkeypatch.setattr(_dnsmodule, "_tlsh_available", lambda: True)
        await connector.run_domain("example.com", "job-1")
        assert captured[-1][captured[-1].index("--lsh") + 1] == "tlsh"
        assert "--phash" not in captured[-1]

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

        outcome = await connector.run_domain("example.com", "job-1")
        # Two permutations survived the original-domain filter, one resolved to
        # a public address, and the core stored it.
        assert outcome.tally == {"candidates": 2, "resolved": 1, "stored": 1}
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
        outcome = await connector.run_domain("example.com", "job-1")
        assert outcome.tally == {"candidates": 0, "resolved": 0, "stored": 0}
        assert outcome.error is True
        assert killed["value"] is True

    @pytest.mark.asyncio
    async def test_one_domain_error_does_not_touch_another_domains_counters(
        self, connector_env, monkeypatch
    ):
        """The outcome of a domain is its own, not a flag on the worker.

        The error used to be stored on the connector and read after the call, so
        the result of a scan depended on the order in which the instance mutated
        itself. A failing domain must leave the tally and the flags of the next
        one exactly as they would have been alone.
        """
        connector = DNSTwistConnector()
        connector._request = AsyncMock(return_value=httpx.Response(200, json={}))

        async def fake_run_domain(domain: str, job_id: str):
            if domain == "broken.example":
                return _dnsmodule.DomainScan(tally=connector._empty_tally(), error=True)
            tally = connector._empty_tally()
            tally.update({"candidates": 3, "resolved": 2, "stored": 1})
            return _dnsmodule.DomainScan(tally=tally)

        monkeypatch.setattr(connector, "run_domain", fake_run_domain)

        _findings, summary = await connector.run_scan(
            {
                "job_id": "job-1",
                "params": {"domains": ["broken.example", "ok.example"]},
            }
        )

        assert summary["candidates"] == 3
        assert summary["resolved"] == 2
        assert summary["new_discovered"] == 1
        assert summary["domains_with_errors"] == 1
        assert summary["domains_truncated"] == 0
        assert summary["status"] == "partial"

    @pytest.mark.asyncio
    async def test_summary_separates_generated_resolved_and_stored(
        self, connector_env, monkeypatch
    ):
        """A scan that discovered nothing has to say which of the three steps
        produced the zero: nothing generated, nothing registered, or nothing new."""
        connector = DNSTwistConnector()
        connector._request = AsyncMock(return_value=httpx.Response(200, json={}))
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
