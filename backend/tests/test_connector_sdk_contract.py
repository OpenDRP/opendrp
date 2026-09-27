"""Contract tests: connector SDK (Step 10).

``connectors/base/opendrp_connector/base.py`` is the base class every
connector container runs — previously the only completely untested shipping
code (the core-side wire protocol is pinned in
``test_connectors_protocol_api.py``; this file pins the *connector side*).

These tests double as the documented SDK contract:

* construction: required env, ``CONNECTOR_TYPE`` validation, trailing-slash /
  whitespace normalization, ``POLL_INTERVAL_SEC``/``RECONNECT_BACKOFF_MAX_SEC``
  parsing, and the ``self.env`` split (SDK keys excluded, connector-specific
  UPPERCASE keys kept);
* HTTP layer: auth headers, ``ConnectorAPIError`` mapping for 4xx/5xx and
  network failures, response passthrough for 2xx;
* protocol operations: ``register`` payload shape, ``poll_work`` (204/empty →
  None), ``submit_findings`` (empty batch short-circuits without HTTP),
  ``complete``/``report_failure`` (failure reporting never raises),
  ``heartbeat``;
* ``_execute_job``: findings submission + summary merging, failure reporting
  with the exception type prefix;
* ``run_forever``: drains the queue before sleeping, recovers from
  ``ConnectorAPIError`` with backoff doubling capped at ``backoff_max``, treats
  a refused credential (401/403) as fatal with an actionable message instead of
  retrying (identity comes from the token), and stops cleanly via ``stop()``.
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

# Locate the SDK source: CI/host checkouts have <repo>/connectors next to
# backend/; the backend dev container gets a read-only mount at /connectors.
_CANDIDATE_SDK_PATHS = [
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "connectors",
        "base",
    ),
    "/connectors/base",
]
for _p in _CANDIDATE_SDK_PATHS:
    if os.path.isdir(os.path.join(_p, "opendrp_connector")):
        if _p not in sys.path:
            sys.path.insert(0, _p)
        break
else:
    pytest.skip(
        "connector SDK source not available (expected <repo>/connectors or /connectors)",
        allow_module_level=True,
    )

from opendrp_connector.base import (  # noqa: E402
    ConnectorAPIError,
    ConnectorBase,
    ConnectorCredentialError,
)


_ENV: dict[str, str] = {
    "CORE_URL": "http://core:8000/",
    "CONNECTOR_TOKEN": "  secret-token  ",
    "CONNECTOR_NAME": "  MyConnector ",
    "CONNECTOR_TYPE": " Phishing ",
    "CONNECTOR_JOB_TYPE": "phishing.dnstwist",
    "SHODAN_API_KEY": "sk-123",
    "SHODAN_SCAN_SSL_TEXT": "true",
    "PATH": "/usr/bin",
}

#: What a claim hands back. The SDK requires it on every job-scoped call, so
#: these tests put the connector in the state a successful poll leaves it in.
_LEASE = "lease-token-abcdefghijklmnop"


@pytest.fixture()
def connector(monkeypatch: pytest.MonkeyPatch) -> ConnectorBase:
    for k, v in _ENV.items():
        monkeypatch.setenv(k, v)
    return ConnectorBase()


def _claim(connector: ConnectorBase, job_id: str = "job-1") -> str:
    """Record the claim the SDK would hold after ``poll_work``."""
    connector._active_job = (job_id, _LEASE)
    return _LEASE


def _mk_client(
    connector: ConnectorBase, handler
) -> list[httpx.Request]:
    """Attach a MockTransport client; returns the recorded request list.

    Mirrors ``_client_session``'s construction (same base_url and headers)
    so the recorded requests carry exactly what the SDK would send.
    """
    requests: list[httpx.Request] = []

    def _record(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return handler(request)

    connector._client = httpx.AsyncClient(
        base_url=connector.core_url,
        timeout=httpx.Timeout(35.0, connect=10.0),
        headers=connector._headers(),
        transport=httpx.MockTransport(_record),
    )
    return requests


def _ok(json: Any = None, status_code: int = 200, content: bytes | None = None) -> httpx.Response:
    if content is not None:
        return httpx.Response(status_code, content=content)
    if json is None:
        return httpx.Response(status_code)
    return httpx.Response(status_code, json=json)


class TestConstruction:
    def test_missing_required_env_lists_all_missing(self, monkeypatch):
        for k in ("CORE_URL", "CONNECTOR_TOKEN", "CONNECTOR_NAME", "CONNECTOR_TYPE"):
            monkeypatch.delenv(k, raising=False)
        with pytest.raises(RuntimeError, match="CORE_URL.*CONNECTOR_TOKEN"):
            ConnectorBase()

    def test_env_normalization(self, connector):
        assert connector.core_url == "http://core:8000"  # trailing slash stripped
        assert connector.token == "secret-token"  # whitespace stripped
        assert connector.name == "myconnector"  # lowercased
        assert connector.connector_type == "phishing"

    def test_invalid_connector_type_rejected(self, monkeypatch):
        # The SDK validates the shape only; the module set is core-owned data
        # (the core rejects a module it cannot persist findings for).
        for k, v in _ENV.items():
            monkeypatch.setenv(k, v)
        monkeypatch.setenv("CONNECTOR_TYPE", "Not A Module")
        with pytest.raises(RuntimeError, match="CONNECTOR_TYPE must be a lowercase module"):
            ConnectorBase()

    def test_a_connector_without_a_job_type_does_not_start(self, monkeypatch):
        """A connector that could claim no work must fail, not restart-loop."""
        for k, v in _ENV.items():
            monkeypatch.setenv(k, v)
        monkeypatch.delenv("CONNECTOR_JOB_TYPE", raising=False)
        with pytest.raises(RuntimeError, match="CONNECTOR_JOB_TYPE is required"):
            ConnectorBase()

    def test_manifest_payload_declares_job_type_and_config_schema(self, connector, monkeypatch):
        monkeypatch.setenv("CONNECTOR_FINDING_KIND", "phishing")
        monkeypatch.setenv("CONNECTOR_ASSET_TYPES", "domain, keyword_title")
        monkeypatch.setenv(
            "CONNECTOR_CONFIG_SCHEMA",
            '{"scan_certificates": {"type": "bool", "default": true}}',
        )
        assert connector.manifest_payload() == {
            "default_job_type": "phishing.dnstwist",
            "finding_kind": "phishing",
            "asset_types": ["domain", "keyword_title"],
            "config_schema": {"scan_certificates": {"type": "bool", "default": True}},
        }

    def test_the_declaration_is_validated_once_at_construction(self, connector):
        # ``register`` sends this, so a bad declaration must fail before the
        # connector starts talking to the core.
        assert connector.manifest == {"default_job_type": "phishing.dnstwist"}

    def test_manifest_variables_are_not_exposed_as_connector_env(self, connector):
        fresh = ConnectorBase()
        assert "CONNECTOR_JOB_TYPE" not in fresh.env
        assert "CONNECTOR_CONFIG_SCHEMA" not in fresh.env

    def test_invalid_config_schema_json_fails_fast(self, connector, monkeypatch):
        monkeypatch.setenv("CONNECTOR_CONFIG_SCHEMA", "not-json")
        with pytest.raises(RuntimeError, match="CONNECTOR_CONFIG_SCHEMA is not valid JSON"):
            connector.manifest_payload()

    def test_env_split_sdk_keys_excluded(self, connector):
        assert "SHODAN_API_KEY" in connector.env
        assert "SHODAN_SCAN_SSL_TEXT" in connector.env
        assert "CORE_URL" not in connector.env
        assert "CONNECTOR_TOKEN" not in connector.env
        assert "CONNECTOR_NAME" not in connector.env
        # Any other UPPERCASE process var is connector-specific by design.
        assert "PATH" in connector.env

    def test_interval_defaults_and_overrides(self, connector, monkeypatch):
        assert connector.poll_interval == 5.0
        assert connector.backoff_max == 60.0
        monkeypatch.setenv("POLL_INTERVAL_SEC", "1.5")
        monkeypatch.setenv("RECONNECT_BACKOFF_MAX_SEC", "7")
        c2 = ConnectorBase()
        assert c2.poll_interval == 1.5
        assert c2.backoff_max == 7.0


class TestHttpLayer:
    @pytest.mark.asyncio
    async def test_headers_carry_token_name_and_ua(self, connector):
        requests = _mk_client(connector, lambda req: _ok({"ok": True}))
        await connector.heartbeat()
        req = requests[0]
        assert req.headers["X-Connector-Token"] == "secret-token"
        assert req.headers["X-Connector-Name"] == "myconnector"
        assert req.headers["User-Agent"].startswith("OpenDRP-Connector/")

    @pytest.mark.asyncio
    async def test_http_error_maps_to_connector_api_error(self, connector):
        _mk_client(connector, lambda req: _ok({"detail": "bad token"}, 401))
        with pytest.raises(ConnectorAPIError) as ei:
            await connector.heartbeat()
        assert ei.value.status_code == 401
        assert "bad token" in str(ei.value)

    @pytest.mark.asyncio
    async def test_network_error_maps_to_status_zero(self, connector):
        def _handler(req):
            raise httpx.ConnectError("refused")

        _mk_client(connector, _handler)
        with pytest.raises(ConnectorAPIError) as ei:
            await connector.heartbeat()
        assert ei.value.status_code == 0
        assert "ConnectError" in str(ei.value)


class TestProtocolOperations:
    @pytest.mark.asyncio
    async def test_register_payload_shape(self, connector):
        requests = _mk_client(connector, lambda req: _ok({"status": "registered"}))
        await connector.register()
        import json

        payload = json.loads(requests[0].content)
        assert payload["name"] == "myconnector"
        assert payload["connector_type"] == "phishing"
        assert payload["api_version"]
        assert payload["default_job_type"] == "phishing.dnstwist"
        assert "version" in payload["info"]
        assert "python" in payload["info"]
        assert requests[0].url.path == "/api/v1/connectors/register"

    @pytest.mark.asyncio
    async def test_poll_work_returns_payload(self, connector):
        body = {"job_id": "abc", "lease_token": _LEASE, "params": {}}
        requests = _mk_client(connector, lambda req: _ok(body))
        work = await connector.poll_work()
        assert work == body
        assert connector._active_job == ("abc", _LEASE)
        assert requests[0].url.path == "/api/v1/connectors/me/work"

    @pytest.mark.asyncio
    async def test_work_without_a_lease_token_is_refused(self, connector):
        """The core claims work by handing out a lease; nothing else is work."""
        _mk_client(connector, lambda req: _ok({"job_id": "abc", "params": {}}))
        with pytest.raises(ConnectorAPIError, match="without a lease token"):
            await connector.poll_work()
        assert connector._active_job is None

    @pytest.mark.asyncio
    async def test_poll_work_204_returns_none(self, connector):
        _mk_client(connector, lambda req: _ok(status_code=204))
        assert await connector.poll_work() is None

    @pytest.mark.asyncio
    async def test_poll_work_empty_body_returns_none(self, connector):
        _mk_client(connector, lambda req: _ok(content=b""))
        assert await connector.poll_work() is None

    @pytest.mark.asyncio
    async def test_submit_findings_empty_batch_skips_http(self, connector):
        requests = _mk_client(connector, lambda req: _ok({}))
        result = await connector.submit_findings("job-1", [])
        assert result == {"accepted": 0, "rejected": 0}
        assert requests == []  # no HTTP call

    @pytest.mark.asyncio
    async def test_submit_findings_retries_transient_read_timeout(self, connector, monkeypatch):
        _claim(connector)
        calls = {"n": 0}
        async def _request(method, path, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise ConnectorAPIError(0, "network: ReadTimeout")
            return _ok({"accepted": 1, "rejected": 0})
        connector._request = _request  # type: ignore[method-assign]
        monkeypatch.setattr("opendrp_connector.base.asyncio.sleep", AsyncMock())
        result = await connector.submit_findings("job-1", [{"type": "phishing"}])
        assert result["accepted"] == 1
        assert calls["n"] == 2

    @pytest.mark.asyncio
    async def test_complete_retries_transient_core_timeout(self, connector, monkeypatch):
        _claim(connector)
        calls = {"n": 0}
        async def _request(method, path, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise ConnectorAPIError(0, "network: ReadTimeout")
            return _ok()
        connector._request = _request  # type: ignore[method-assign]
        monkeypatch.setattr("opendrp_connector.base.asyncio.sleep", AsyncMock())
        await connector.complete("job-1", {"scanned": 1})
        assert calls["n"] == 2

    @pytest.mark.asyncio
    async def test_submit_findings_posts_list(self, connector):
        _claim(connector)
        requests = _mk_client(connector, lambda req: _ok({"accepted": 1, "rejected": 0}))
        findings = [{"type": "phishing", "domain": "x.example.com"}]
        result = await connector.submit_findings("job-1", findings)
        assert result == {"accepted": 1, "rejected": 0}
        import json

        assert json.loads(requests[0].content) == findings
        assert requests[0].headers["X-Connector-Lease"] == _LEASE
        assert "job-1" in requests[0].url.path

    @pytest.mark.asyncio
    async def test_a_job_scoped_call_without_a_claim_never_reaches_the_core(self, connector):
        """Reporting on a job the connector never claimed is a bug, not a race."""
        requests = _mk_client(connector, lambda req: _ok())
        with pytest.raises(ConnectorAPIError, match="no active lease for job job-1"):
            await connector.submit_findings("job-1", [{"type": "phishing"}])
        with pytest.raises(ConnectorAPIError, match="no active lease"):
            await connector.complete("job-1", {"scanned": 1})
        assert requests == []

    @pytest.mark.asyncio
    async def test_complete_posts_ok_true_with_summary_and_lease(self, connector):
        _claim(connector)
        requests = _mk_client(connector, lambda req: _ok())
        await connector.complete("job-1", {"scanned": 3})
        import json

        assert json.loads(requests[0].content) == {
            "ok": True,
            "summary": {"scanned": 3},
            "lease_token": _LEASE,
        }
        assert "complete/job-1" in requests[0].url.path
        assert connector._active_job is None

    @pytest.mark.asyncio
    async def test_report_failure_posts_ok_false_truncated(self, connector):
        _claim(connector)
        requests = _mk_client(connector, lambda req: _ok())
        await connector.report_failure("job-1", "x" * 5000)
        import json

        body = json.loads(requests[0].content)
        assert body["ok"] is False
        assert body["lease_token"] == _LEASE
        assert len(body["error"]) == 4000  # truncated

    @pytest.mark.asyncio
    async def test_report_failure_swallows_transport_errors(self, connector):
        _claim(connector)

        def _handler(req):
            raise httpx.ConnectError("core gone")

        _mk_client(connector, _handler)
        await connector.report_failure("job-1", "boom")  # must not raise


class _StubConnector(ConnectorBase):
    def __init__(self, **kw: Any) -> None:  # bypass env requirements
        self.core_url = "http://core"
        self.token = "t"
        self.name = "stub"
        self.connector_type = "phishing"
        self.api_version = "test"
        self.manifest = {"default_job_type": "phishing.stub"}
        self.poll_interval = 0.01
        self.backoff_max = 0.03
        self.env = {}
        self._stop = asyncio.Event()
        self._client = None
        self._active_job = None
        self.kw = kw
        self.scans = 0

    async def run_scan(self, work):
        self.scans += 1
        if self.kw.get("scan_error"):
            raise self.kw["scan_error"]
        return self.kw.get("findings", []), dict(self.kw.get("summary", {"scanned": 1}))


class TestExecuteJob:
    @pytest.mark.asyncio
    async def test_success_submits_findings_merges_summary_and_completes(self):
        c = _StubConnector(findings=[{"type": "phishing"}])
        seen: list[tuple[str, dict | list]] = []

        async def _req(method, path, **kwargs):
            seen.append((path, kwargs.get("json")))
            return _ok({"accepted": 1, "rejected": 0})

        c._request = _req  # type: ignore[method-assign]
        await c._execute_job({"job_id": "j1", "lease_token": _LEASE})
        paths = [p for p, _ in seen]
        assert any("findings/j1" in p for p in paths)
        assert any("complete/j1" in p for p in paths)
        complete_body = next(b for p, b in seen if "complete" in p)
        assert complete_body["ok"] is True
        assert complete_body["lease_token"] == _LEASE
        # Summary merged the submit result + duration.
        assert complete_body["summary"]["accepted"] == 1
        assert complete_body["summary"]["rejected"] == 0
        assert "duration_sec" in complete_body["summary"]

    @pytest.mark.asyncio
    async def test_no_findings_completes_without_submit(self):
        c = _StubConnector(findings=[])
        seen: list[str] = []

        async def _req(method, path, **kwargs):
            seen.append(path)
            return _ok()

        c._request = _req  # type: ignore[method-assign]
        await c._execute_job({"job_id": "j2", "lease_token": _LEASE})
        assert not any("findings" in p for p in seen)
        assert any("complete/j2" in p for p in seen)

    @pytest.mark.asyncio
    async def test_scan_exception_reports_failure_with_type_prefix(self):
        c = _StubConnector(scan_error=ValueError("bad params"))
        seen: list[tuple[str, dict]] = []

        async def _req(method, path, **kwargs):
            seen.append((path, kwargs.get("json")))
            return _ok()

        c._request = _req  # type: ignore[method-assign]
        await c._execute_job({"job_id": "j3", "lease_token": _LEASE})  # must not raise
        body = next(b for p, b in seen if "complete" in p)
        assert body["ok"] is False
        assert body["lease_token"] == _LEASE
        assert body["error"].startswith("ValueError: bad params")

    @pytest.mark.asyncio
    async def test_a_job_without_a_lease_is_not_executed(self):
        """The claim is the authority to run; without one nothing is reported."""
        c = _StubConnector()
        seen: list[str] = []

        async def _req(method, path, **kwargs):
            seen.append(path)
            return _ok()

        c._request = _req  # type: ignore[method-assign]
        with pytest.raises(ConnectorAPIError, match="carries no lease token"):
            await c._execute_job({"job_id": "j4"})
        assert seen == []
        assert c.scans == 0


class TestRunForever:
    @pytest.mark.asyncio
    async def test_client_session_lazy_creation_and_reuse(self, connector):
        # Direct unit pin of the lazy singleton behavior (L106).
        assert connector._client is None
        c1 = connector._client_session()
        c2 = connector._client_session()
        assert c1 is c2
        assert c1.base_url == httpx.URL("http://core:8000")
        await c1.aclose()

    @pytest.mark.asyncio
    async def test_run_scan_not_implemented(self, connector):
        with pytest.raises(NotImplementedError):
            await connector.run_scan({"job_id": "x"})

    @pytest.mark.asyncio
    async def test_client_closed_after_stop(self):
        c = _StubConnector()
        _mk_client(c, lambda req: _ok(status_code=204))

        async def _req(method, path, **kwargs):
            return _ok(status_code=204)

        c._request = _req  # type: ignore[method-assign]
        task = asyncio.create_task(c.run_forever())
        await asyncio.sleep(0.08)
        c.stop()
        await asyncio.wait_for(task, timeout=2)
        assert c._client is not None
        assert c._client.is_closed  # teardown closed the session

    @pytest.mark.asyncio
    async def test_drains_queue_then_sleeps_and_stops_cleanly(self):
        c = _StubConnector()
        work_items = [
            {"job_id": "a", "lease_token": _LEASE},
            {"job_id": "b", "lease_token": _LEASE},
            None,
        ]

        async def _req(method, path, **kwargs):
            if path.endswith("/work"):
                w = work_items.pop(0) if work_items else None
                return _ok(w) if w else _ok(status_code=204)
            return _ok()

        c._request = _req  # type: ignore[method-assign]
        task = asyncio.create_task(c.run_forever())
        await asyncio.sleep(0.15)  # let it drain both jobs
        c.stop()
        await asyncio.wait_for(task, timeout=2)
        assert c.scans == 2

    @pytest.mark.asyncio
    async def test_poll_error_backs_off_then_stops(self):
        c = _StubConnector()
        calls = {"n": 0}

        async def _req(method, path, **kwargs):
            calls["n"] += 1
            if path.endswith("/work"):
                raise ConnectorAPIError(503, "unavailable")
            return _ok()

        c._request = _req  # type: ignore[method-assign]
        task = asyncio.create_task(c.run_forever())
        await asyncio.sleep(0.2)
        c.stop()
        await asyncio.wait_for(task, timeout=2)
        assert calls["n"] >= 2  # retried after backoff

    @pytest.mark.asyncio
    async def test_401_is_fatal_and_names_the_fix(self):
        """A refused credential cannot be repaired by retrying or re-registering."""
        c = _StubConnector()
        calls = {"register": 0, "work": 0}

        async def _req(method, path, **kwargs):
            if path.endswith("/register"):
                calls["register"] += 1
                return _ok()
            calls["work"] += 1
            raise ConnectorAPIError(401, "bad token")

        c._request = _req  # type: ignore[method-assign]
        with pytest.raises(ConnectorCredentialError) as ei:
            await asyncio.wait_for(c.run_forever(), timeout=2)
        assert ei.value.status_code == 401
        # The message must tell the operator exactly how to recover.
        message = str(ei.value)
        assert "manage_connector_tokens rotate" in message
        # Rotating is only half of it: a container keeps the environment it
        # was created with, so the message has to ask for a recreate rather
        # than a restart. This is the text an operator reads in the logs.
        assert "recreate" in message
        assert "restart" in message
        assert calls["register"] == 1  # no self-healing re-registration

    @pytest.mark.asyncio
    async def test_403_from_another_connectors_token_is_fatal(self):
        c = _StubConnector()

        async def _req(method, path, **kwargs):
            if path.endswith("/register"):
                return _ok()
            raise ConnectorAPIError(403, "token does not belong to that connector")

        c._request = _req  # type: ignore[method-assign]
        with pytest.raises(ConnectorCredentialError) as ei:
            await asyncio.wait_for(c.run_forever(), timeout=2)
        assert ei.value.status_code == 403

    @pytest.mark.asyncio
    async def test_credential_rejected_at_startup_register_is_fatal(self):
        """Startup registration is the first authenticated call, so it fails loud."""
        c = _StubConnector()

        async def _req(method, path, **kwargs):
            raise ConnectorAPIError(401, "invalid or missing connector token")

        c._request = _req  # type: ignore[method-assign]
        with pytest.raises(ConnectorCredentialError):
            await asyncio.wait_for(c.run_forever(), timeout=2)

    @pytest.mark.asyncio
    async def test_heartbeat_only_when_idle_and_rate_limited(self):
        c = _StubConnector()
        beats = {"n": 0}

        async def _req(method, path, **kwargs):
            if path.endswith("/heartbeat"):
                beats["n"] += 1
            elif path.endswith("/work"):
                return _ok(status_code=204)
            return _ok()

        c._request = _req  # type: ignore[method-assign]
        task = asyncio.create_task(c.run_forever())
        await asyncio.sleep(0.12)
        c.stop()
        await asyncio.wait_for(task, timeout=2)
        assert beats["n"] >= 1

    @pytest.mark.asyncio
    async def test_heartbeat_failure_is_isolated(self):
        """A failing idle heartbeat must not kill the loop (L230-231)."""
        c = _StubConnector()
        polls = {"n": 0}

        async def _req(method, path, **kwargs):
            if path.endswith("/heartbeat"):
                raise ConnectorAPIError(0, "network: ConnectError")
            if path.endswith("/work"):
                polls["n"] += 1
                return _ok(status_code=204)
            return _ok()

        c._request = _req  # type: ignore[method-assign]
        task = asyncio.create_task(c.run_forever())
        await asyncio.sleep(0.12)
        c.stop()
        await asyncio.wait_for(task, timeout=2)
        assert polls["n"] >= 2  # loop kept polling after heartbeat failure

    @pytest.mark.asyncio
    async def test_core_outage_at_startup_is_not_a_credential_error(self):
        """A 5xx is transient: it must not be mistaken for a refused credential."""
        c = _StubConnector()
        calls = {"register": 0}

        async def _req(method, path, **kwargs):
            if path.endswith("/register"):
                calls["register"] += 1
                raise ConnectorAPIError(503, "core starting up")
            return _ok(status_code=204)

        c._request = _req  # type: ignore[method-assign]
        with pytest.raises(ConnectorAPIError) as ei:
            await asyncio.wait_for(c.run_forever(), timeout=2)
        assert ei.value.status_code == 503
        assert calls["register"] == 1

    @pytest.mark.asyncio
    async def test_generic_exception_does_not_kill_loop(self):
        c = _StubConnector()
        polls = {"n": 0}

        async def _req(method, path, **kwargs):
            if path.endswith("/work"):
                polls["n"] += 1
                if polls["n"] == 1:
                    raise RuntimeError("totally unexpected")
                return _ok(status_code=204)
            return _ok()

        c._request = _req  # type: ignore[method-assign]
        task = asyncio.create_task(c.run_forever())
        await asyncio.sleep(0.1)
        c.stop()
        await asyncio.wait_for(task, timeout=2)
        assert polls["n"] >= 2  # recovered from the generic error


class TestSignalsAndMain:
    def test_install_signal_handlers_and_main(self, connector, monkeypatch):
        import asyncio as _asyncio

        ran = {"forever": 0}

        async def _fast_forever():
            ran["forever"] += 1

        monkeypatch.setattr(connector, "run_forever", _fast_forever)
        connector.main()  # full entrypoint: signal handlers + asyncio.run
        assert ran["forever"] == 1
        _asyncio.new_event_loop()  # loop bookkeeping sanity
