"""WI-16: the DNSTwist CLI is a versioned dependency, not an implementation detail.

The connector parses the CLI's JSON, uses its fuzzer vocabulary and leans on its
resolved-address dictionary. All three are properties of the release installed in
the image, and that release used to arrive from the distribution with nothing
pinning it — so a base-image bump could change what a scan finds without a line
changing in this repository, and no gate and no diff would say so.

Three halves, tested separately:

* the image pin and the version the connector is written against are the same
  decision, so neither can move alone;
* a container whose ``dnstwist`` reports another release **refuses to start**;
* the refusal happens before the connector registers, so a broken image cannot
  claim work and report a quiet ``partial`` or a clean scan — the distinction
  that matters, because for a scanner "I could not run my tool" and "I found
  nothing" must not look the same in the job history.
"""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_CONNECTORS = _ROOT / "connectors"
_BASE = _CONNECTORS / "base"
if str(_BASE) not in sys.path:
    sys.path.insert(0, str(_BASE))

from opendrp_connector import ConnectorBase, ConnectorPreflightError  # noqa: E402


def _load_module(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


_module = _load_module("opendrp_test_dnstwist_version", _CONNECTORS / "dnstwist" / "main.py")
DNSTwistConnector = _module.DNSTwistConnector

#: The exact apt pin the images carry, built from the version the connector
#: expects, so the two spellings of one release are compared rather than trusted.
_PIN = f"dnstwist=0~{_module._EXPECTED_DNSTWIST_VERSION}-1"


class _FakeProcess:
    def __init__(self, output: bytes, returncode: int) -> None:
        self._output = output
        self.returncode = returncode

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._output, b""

    def kill(self) -> None:  # pragma: no cover - only reached on cancellation
        pass

    async def wait(self) -> int:  # pragma: no cover
        return self.returncode


def _fake_cli(
    monkeypatch: pytest.MonkeyPatch,
    output: bytes = b"",
    returncode: int = 0,
    error: Exception | None = None,
) -> list[tuple[Any, ...]]:
    """Replace the subprocess spawn and record the argv it was called with."""
    calls: list[tuple[Any, ...]] = []

    async def fake_exec(*args: Any, **kwargs: Any):
        calls.append(args)
        if error is not None:
            raise error
        return _FakeProcess(output, returncode)

    monkeypatch.setattr(_module.asyncio, "create_subprocess_exec", fake_exec)
    return calls


@pytest.fixture()
def connector_env(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    values = {
        "CORE_URL": "http://core:8000",
        "CONNECTOR_TOKEN": "test-token",
        "CONNECTOR_NAME": "dnstwist",
        "CONNECTOR_TYPE": "phishing",
        "CONNECTOR_JOB_TYPE": "phishing.dnstwist",
        "POLL_INTERVAL_SEC": "0.01",
        # The liveness watchdog writes a file on its own timer; disabled here so a
        # test never touches the host's temporary directory.
        "CONNECTOR_LIVENESS_FILE": "",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    return values


@pytest.fixture()
def connector(connector_env: dict[str, str]) -> Any:
    return DNSTwistConnector()


def _reports(version: str) -> bytes:
    return f"dnstwist {version}\n".encode()


# ==============================================================================
# The pin and the expectation are one decision
# ==============================================================================
@pytest.mark.parametrize(
    "dockerfile", ["connectors/dnstwist/Dockerfile", "backend/Dockerfile"]
)
def test_the_pinned_package_version_matches_the_expected_cli_version(dockerfile: str):
    """A Debian version ``0~20250130-1`` is upstream ``20250130``.

    That release is what ``dnstwist --version`` prints, and it is what the
    connector refuses to run without — so the pin and the constant are checked
    against each other instead of being trusted to stay in step by convention.
    """
    text = (_ROOT / dockerfile).read_text(encoding="utf-8")
    assert _PIN in text, (
        f"{dockerfile} does not pin {_PIN}; the image would install whatever the "
        "archive serves that day while the connector refuses to run it"
    )


def test_the_version_probe_asks_the_cli_for_its_version(monkeypatch: pytest.MonkeyPatch):
    calls = _fake_cli(monkeypatch, output=_reports(_module._EXPECTED_DNSTWIST_VERSION))

    assert asyncio.run(_module.installed_cli_version()) == _module._EXPECTED_DNSTWIST_VERSION
    assert calls == [("dnstwist", "--version")], calls


# ==============================================================================
# A mismatch refuses to start, and says why
# ==============================================================================
def test_preflight_accepts_the_pinned_version(connector: Any, monkeypatch: pytest.MonkeyPatch):
    _fake_cli(monkeypatch, output=_reports(_module._EXPECTED_DNSTWIST_VERSION))
    asyncio.run(connector.preflight())


def test_preflight_refuses_a_different_version(connector: Any, monkeypatch: pytest.MonkeyPatch):
    _fake_cli(monkeypatch, output=_reports("20240101"))

    with pytest.raises(_module.DnstwistVersionMismatch) as raised:
        asyncio.run(connector.preflight())

    message = str(raised.value)
    # Both versions and the pin, so the operator can act without reading code.
    assert "20240101" in message
    assert _module._EXPECTED_DNSTWIST_VERSION in message
    assert _PIN in message
    assert "connector-phishing-dnstwist" in message
    # And it is the fatal kind, not an ordinary job failure.
    assert isinstance(raised.value, ConnectorPreflightError)


def test_preflight_refuses_a_cli_that_will_not_run(connector: Any, monkeypatch: pytest.MonkeyPatch):
    """Not installed at all is a mismatch too: there is no version to trust."""
    _fake_cli(monkeypatch, error=FileNotFoundError("dnstwist"))

    with pytest.raises(_module.DnstwistVersionMismatch) as raised:
        asyncio.run(connector.preflight())

    assert "did not run" in str(raised.value)


def test_preflight_refuses_a_nonzero_exit(connector: Any, monkeypatch: pytest.MonkeyPatch):
    _fake_cli(monkeypatch, output=b"", returncode=1)

    with pytest.raises(_module.DnstwistVersionMismatch):
        asyncio.run(connector.preflight())


# ==============================================================================
# The refusal happens before the connector claims it is ready
# ==============================================================================
def test_the_runtime_checks_the_connector_before_it_registers(connector_env: dict[str, str]):
    """Ordering, not just existence: preflight → register → poll.

    A connector that registers first and then discovers it cannot scan has already
    told the core it is available, and its jobs are the ones that go quiet.
    """
    order: list[str] = []

    class Probe(ConnectorBase):
        async def preflight(self) -> None:
            order.append("preflight")

        async def _register_or_fail(self) -> None:
            order.append("register")

        async def _poll_loop(self) -> None:
            order.append("poll")

    asyncio.run(Probe().run_forever())

    assert order == ["preflight", "register", "poll"]


def test_a_refused_preflight_exits_the_process_with_a_fatal_line(
    connector: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
):
    """`main()` turns the refusal into a non-zero exit, which is what surfaces it."""
    _fake_cli(monkeypatch, output=_reports("20240101"))

    with pytest.raises(SystemExit) as raised:
        connector.main()

    assert raised.value.code == 1
    assert "[FATAL]" in capsys.readouterr().err
