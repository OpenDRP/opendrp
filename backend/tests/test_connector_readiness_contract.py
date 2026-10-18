"""Readiness contract: every connector worker declares the same row.

The core admits a provider scan on the capabilities its worker reported and shows
the operator whether the source can scan at all. Before this contract each worker
built its own JSON body (or, for dnstwist, none), so the same question had six
answers and one worker was silent. ``ConnectorBase.report_readiness`` now owns the
shape; this file runs every shipped worker through it.

What is pinned here is the *contract*, not each worker's product knowledge: the
required fields exist, the identifiers the core accepts are the ones sent, the
credential flag reflects the environment honestly, readiness is declared at
start-up, and a failed readiness post never raises (a scan that produced findings
must not be reported as failed because a status row could not be written).
"""

from __future__ import annotations

import importlib.util
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

_CONNECTORS = Path(__file__).resolve().parents[2] / "connectors"
_REQUIRED = (_CONNECTORS, _CONNECTORS / "base")
_MISSING = [path.name for path in _REQUIRED if not path.exists()]
if _MISSING:
    pytest.skip(
        f"not a repository checkout: {', '.join(_MISSING)} missing",
        allow_module_level=True,
    )

# The SDK and the workers' sibling modules (``providers``, ``tls_probe``) are
# imported by bare name inside the connector images; CI puts the SDK on
# PYTHONPATH and each worker directory is its own working directory.
for _directory in (
    _CONNECTORS / "base",
    _CONNECTORS / "dns_security",
    _CONNECTORS / "dnstwist",
    _CONNECTORS / "exposure_endpoints",
    _CONNECTORS / "hibp",
    _CONNECTORS / "intelligence",
    _CONNECTORS / "shodan",
):
    if str(_directory) not in sys.path:
        sys.path.insert(0, str(_directory))

from opendrp_connector.base import (  # noqa: E402
    ConnectorAPIError,
    ConnectorBase,
)


def _load(module_name: str, relative: str) -> Any:
    spec = importlib.util.spec_from_file_location(module_name, _CONNECTORS / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


_MODULES = {
    "dns_security": _load("readiness_contract_dns_security", "dns_security/main.py"),
    "dnstwist": _load("readiness_contract_dnstwist", "dnstwist/main.py"),
    "exposure_endpoints": _load(
        "readiness_contract_exposure_endpoints", "exposure_endpoints/main.py"
    ),
    "hibp": _load("readiness_contract_hibp", "hibp/main.py"),
    "intelligence": _load("readiness_contract_intelligence", "intelligence/main.py"),
    "shodan": _load("readiness_contract_shodan", "shodan/main.py"),
}

#: The identifier shape ``SourceReadiness._namespaced_identifiers`` accepts.
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")

_CORE_ENV = {
    "CORE_URL": "http://core:8000",
    "CONNECTOR_TOKEN": "readiness-contract-token",
}


@dataclass(frozen=True)
class _Worker:
    """One worker container: its declaration and how to build it in-process."""

    key: str
    module: str
    class_name: str
    env: dict[str, str]
    capabilities: tuple[str, ...]
    operations: tuple[str, ...]
    credential_env: tuple[str, ...] = ()
    extra: dict[str, str] = field(default_factory=dict)

    def build(self, *, with_credential: bool = True) -> Any:
        credentials = self.credential_env if with_credential else ()
        configured = {name: self.extra[name] for name in credentials} if credentials else {}
        environ = {**_CORE_ENV, **self.env, **configured}
        previous = {name: os.environ.get(name) for name in environ}
        for name in (*environ, *self.extra):
            os.environ.pop(name, None)
        os.environ.update(environ)
        try:
            return getattr(_MODULES[self.key], self.class_name)()
        finally:
            for name, value in previous.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value


WORKERS = (
    _Worker(
        key="dnstwist",
        module="dnstwist",
        class_name="DNSTwistConnector",
        env={
            "CONNECTOR_NAME": "phishing-dnstwist",
            "CONNECTOR_TYPE": "phishing",
            "CONNECTOR_JOB_TYPE": "phishing.dnstwist",
        },
        capabilities=("domain",),
        operations=(),
    ),
    _Worker(
        key="shodan",
        module="shodan",
        class_name="ShodanConnector",
        env={
            "CONNECTOR_NAME": "phishing-shodan",
            "CONNECTOR_TYPE": "phishing",
            "CONNECTOR_JOB_TYPE": "phishing.shodan",
        },
        capabilities=("certificate", "title", "favicon", "body"),
        operations=("search",),
        credential_env=("SHODAN_API_KEY",),
        extra={"SHODAN_API_KEY": "contract-provider-key"},
    ),
    _Worker(
        key="hibp",
        module="hibp",
        class_name="HibpConnector",
        env={
            "CONNECTOR_NAME": "breaches-hibp",
            "CONNECTOR_TYPE": "breaches",
            "CONNECTOR_JOB_TYPE": "breaches.hibp",
        },
        capabilities=("email_account", "domain", "catalogue", "paste"),
        operations=("lookup", "search"),
        credential_env=("HIBP_API_KEY",),
        extra={"HIBP_API_KEY": "contract-provider-key"},
    ),
    _Worker(
        key="intelligence",
        module="intelligence",
        class_name="IntelligenceConnector",
        env={
            "CONNECTOR_NAME": "exposure-netlas",
            "CONNECTOR_TYPE": "exposure",
            "CONNECTOR_JOB_TYPE": "exposure.netlas",
            "INTELLIGENCE_PROVIDER": "netlas",
        },
        capabilities=("hostname",),
        operations=("search", "lookup", "certificate"),
        credential_env=("NETLAS_API_TOKEN",),
        extra={"NETLAS_API_TOKEN": "contract-provider-key"},
    ),
    _Worker(
        key="dns_security",
        module="dns_security",
        class_name="ShodanConnector",
        env={
            "CONNECTOR_NAME": "dns-shodan",
            "CONNECTOR_TYPE": "dns",
            "CONNECTOR_JOB_TYPE": "dns.shodan",
        },
        capabilities=("certificate", "hostname", "ip", "title", "favicon", "lookup"),
        operations=("lookup", "search"),
        credential_env=("SHODAN_API_KEY",),
        extra={"SHODAN_API_KEY": "contract-provider-key"},
    ),
    _Worker(
        key="exposure_endpoints",
        module="exposure_endpoints",
        class_name="ExposureEndpointsConnector",
        env={
            "CONNECTOR_NAME": "exposure-shodan-endpoints",
            "CONNECTOR_TYPE": "exposure",
            "CONNECTOR_JOB_TYPE": "exposure.shodan-endpoints",
            "EXPOSURE_PROVIDER": "shodan",
        },
        capabilities=("endpoint_lookup",),
        operations=("lookup",),
        credential_env=("SHODAN_API_KEY",),
        extra={"SHODAN_API_KEY": "contract-provider-key"},
    ),
)

_BY_KEY = {worker.key: worker for worker in WORKERS}


@pytest.fixture
def worker(request):
    return _BY_KEY[request.param]


@pytest.mark.parametrize(
    "worker", [worker.key for worker in WORKERS], ids=[w.key for w in WORKERS], indirect=True
)
def test_the_sdk_owns_the_readiness_report(worker) -> None:
    """A worker may shape the row, but it does not own the posting or the errors."""
    connector = worker.build()
    assert type(connector).report_readiness is ConnectorBase.report_readiness
    # The one permitted override is the payload itself (HIBP publishes the
    # source's own data-class labels); the transport, fields and failure policy
    # still come from the SDK.
    if worker.key != "hibp":
        assert type(connector).readiness_payload is ConnectorBase.readiness_payload


@pytest.mark.parametrize(
    "worker", [worker.key for worker in WORKERS], ids=[w.key for w in WORKERS], indirect=True
)
def test_the_row_names_only_what_the_core_accepts(worker) -> None:
    payload = worker.build().readiness_payload()

    expected = {
        "credentials_configured",
        "credential_state",
        "provider_error",
        "capabilities",
        "operations",
    }
    if "data_class_labels" in payload:
        expected.add("data_class_labels")
    assert set(payload) == expected
    assert payload["credential_state"] == "unknown"
    assert payload["provider_error"] is None
    assert payload["capabilities"], f"{worker.key} declares no capability at all"
    for identifier in (*payload["capabilities"], *payload["operations"]):
        assert _IDENTIFIER.fullmatch(identifier), identifier
    assert len(set(payload["capabilities"])) == len(payload["capabilities"])
    # The declaration is the operator's answer to "can this source scan?", so the
    # shipped capabilities and operations are exactly the documented ones.
    assert set(worker.capabilities) <= set(payload["capabilities"])
    assert payload["operations"] == list(worker.operations)


@pytest.mark.parametrize(
    "worker", [worker.key for worker in WORKERS], ids=[w.key for w in WORKERS], indirect=True
)
def test_the_credential_flag_reflects_the_environment(worker) -> None:
    assert worker.build(with_credential=False).credentials_configured() is False
    if worker.credential_env:
        assert worker.build().credentials_configured() is True


@pytest.mark.parametrize(
    "worker", [worker.key for worker in WORKERS], ids=[w.key for w in WORKERS], indirect=True
)
@pytest.mark.asyncio
async def test_reporting_posts_the_row_and_never_raises(worker) -> None:
    connector = worker.build()
    connector._request = AsyncMock(return_value=httpx.Response(200, json={"status": "ok"}))

    assert await connector.report_readiness() is True
    call = connector._request.await_args
    assert call.args[:2] == ("POST", "/api/v1/connectors/me/readiness")
    assert call.kwargs["json"] == connector.readiness_payload()

    connector._request = AsyncMock(side_effect=ConnectorAPIError(503, "core down"))
    assert await connector.report_readiness() is False


@pytest.mark.parametrize(
    "worker", [worker.key for worker in WORKERS], ids=[w.key for w in WORKERS], indirect=True
)
@pytest.mark.asyncio
async def test_startup_announces_the_declaration(worker) -> None:
    """Every worker registers and then says what it is; none ships silent."""
    connector = worker.build()
    connector._request = AsyncMock(return_value=httpx.Response(200, json={}))

    await connector.register()

    paths = [call.args[1] for call in connector._request.await_args_list]
    assert paths[0] == "/api/v1/connectors/register"
    assert paths[-1] == "/api/v1/connectors/me/readiness"
    body = connector._request.await_args_list[-1].kwargs["json"]
    assert body == connector.readiness_payload()
    assert body["capabilities"], f"{worker.key} registered without a capability"
