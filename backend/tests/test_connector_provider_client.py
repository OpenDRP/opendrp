"""The shared provider client, asserted without a provider or a socket.

Every mechanism here is the one three connectors used to implement separately, so
the tests pin the contract rather than one provider's behaviour: a reservation
before each spend, a pace before each attempt, a bounded streamed read, a retry
that honours the provider's own ``Retry-After``, and one outcome vocabulary.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from email.utils import format_datetime

import httpx
import pytest

# Locate the SDK source the same way the other SDK contract tests do.
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

from opendrp_connector.provider import (  # noqa: E402
    ERROR_SNIPPET_BYTES,
    INVALID_JSON,
    INVALID_RESPONSE,
    NETWORK_TIMEOUT,
    RESPONSE_TOO_LARGE,
    ProviderClient,
    ProviderLimits,
    parse_retry_after,
)


class _Response:
    def __init__(self, status: int = 200, body: bytes = b"", headers: dict | None = None):
        self.status_code = status
        self.headers = headers or {}
        self._body = body

    async def aiter_bytes(self):
        # Small chunks so the size bound is exercised mid-body, as a real stream.
        for start in range(0, len(self._body), 3):
            yield self._body[start : start + 3]


class _Stream:
    def __init__(self, response):
        self._response = response

    async def __aenter__(self):
        return self._response

    async def __aexit__(self, *exc_info):
        return False


class _Http:
    def __init__(self, *responses):
        self._responses = list(responses)
        self.calls: list[tuple[str, str, dict]] = []

    def stream(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if not self._responses:
            raise AssertionError("unexpected provider call")
        return _Stream(self._responses.pop(0))


class _FailingHttp:
    def __init__(self, error: Exception, *, times: int = 1):
        self._error = error
        self._times = times
        self.calls = 0

    def stream(self, method, url, **kwargs):
        self.calls += 1
        if self.calls <= self._times:
            raise self._error
        return _Stream(_Response(200, b'{"ok": true}'))


def _sleeper():
    waits: list[float] = []

    async def sleep(delay: float) -> None:
        waits.append(delay)

    return waits, sleep


def _client(http, **kwargs) -> ProviderClient:
    kwargs.setdefault("sleep", _sleeper()[1])
    return ProviderClient(http=http, **kwargs)


async def test_a_200_answer_is_decoded_and_not_retried():
    http = _Http(_Response(200, b'{"ip": "192.0.2.1"}'))
    result = await _client(http).get_json("https://provider.example/x")

    assert result.ok
    assert result.payload == {"ip": "192.0.2.1"}
    assert result.status == 200
    assert len(http.calls) == 1


async def test_a_non_retryable_status_is_named_and_not_retried():
    http = _Http(_Response(404))
    errors: list[str] = []
    result = await _client(http, errors=errors).get_json("https://provider.example/x")

    assert result.outcome == "http_404"
    assert result.response is not None, "a caller may need the response (RDAP Location)"
    assert len(http.calls) == 1
    assert errors == ["http_404"]


async def test_a_5xx_is_retried_until_it_answers():
    http = _Http(_Response(500), _Response(502), _Response(200, b"[]"))
    waits, sleep = _sleeper()
    result = await _client(http, sleep=sleep).get_json("https://provider.example/x")

    assert result.ok and result.payload == []
    assert len(http.calls) == 3
    assert waits == [1, 2]


async def test_the_provider_hint_wins_over_the_local_backoff_and_is_clamped():
    http = _Http(_Response(429, headers={"Retry-After": "7"}), _Response(200, b"{}"))
    waits, sleep = _sleeper()
    limits = ProviderLimits(max_retry_delay=5.0)
    result = await _client(http, sleep=sleep, limits=limits).get_json("https://provider.example/x")

    assert result.ok
    assert waits == [5.0]


async def test_a_hint_longer_than_the_scan_may_wait_abandons_the_call():
    http = _Http(_Response(429, headers={"Retry-After": "120"}))
    waits, sleep = _sleeper()
    limits = ProviderLimits(abort_when_retry_after_exceeds=60.0)
    result = await _client(http, sleep=sleep, limits=limits).get_json("https://provider.example/x")

    assert result.outcome == "http_429_retry_later"
    assert waits == [], "the scan must not be paused for the provider's long hint"
    assert len(http.calls) == 1


async def test_a_body_over_the_bound_is_refused_before_it_is_decoded():
    body = b'{"a": "' + b"x" * 100 + b'"}'
    http = _Http(_Response(200, body))
    limits = ProviderLimits(max_response_bytes=10)
    result = await _client(http, limits=limits).get_json("https://provider.example/x")

    assert result.outcome == RESPONSE_TOO_LARGE
    assert result.payload is None


async def test_invalid_json_and_non_object_payloads_are_named_separately():
    http = _Http(_Response(200, b"not json"), _Response(200, b'"a string"'))
    client = _client(http)

    first = await client.get_json("https://provider.example/a")
    second = await client.get_json("https://provider.example/b")

    assert first.outcome == INVALID_JSON
    assert second.outcome == INVALID_RESPONSE


async def test_the_reservation_is_made_before_every_attempt():
    reservations = []

    async def reserve():
        reservations.append(1)

    http = _Http(_Response(500), _Response(200, b"{}"))
    result = await _client(http, reserve=reserve).get_json("https://provider.example/x")

    assert result.ok
    assert len(reservations) == 2, "a retried call is a second spend"


async def test_a_free_call_spends_no_reservation():
    reservations = []

    async def reserve():
        reservations.append(1)

    http = _Http(_Response(200, b"{}"))
    await _client(http, reserve=reserve).get_json("https://provider.example/x", free=True)

    assert reservations == []


async def test_a_reservation_refusal_propagates_to_the_connector():
    async def reserve():
        raise RuntimeError("provider_request_unowned")

    http = _Http(_Response(200, b"{}"))
    with pytest.raises(RuntimeError, match="provider_request_unowned"):
        await _client(http, reserve=reserve).get_json("https://provider.example/x")
    assert http.calls == []


async def test_every_configured_pacer_runs_before_each_attempt():
    account, route = [], []

    async def pace_account():
        account.append(1)

    async def pace_route():
        route.append(1)

    http = _Http(_Response(500), _Response(200, b"{}"))
    result = await _client(http, pace=[pace_account, pace_route]).get_json(
        "https://provider.example/x"
    )

    assert result.ok
    assert len(account) == 2 and len(route) == 2


async def test_the_status_callback_sees_each_answer():
    seen: list[int] = []
    http = _Http(_Response(500), _Response(200, b"{}"))
    result = await _client(http, on_status=seen.append).get_json("https://provider.example/x")

    assert result.ok
    assert seen == [500, 200]


async def test_a_refused_credential_is_reported_and_not_retried():
    seen: list[int] = []
    http = _Http(_Response(401))
    result = await _client(http, on_status=seen.append).get_json("https://provider.example/x")

    assert result.outcome == "http_401"
    assert len(http.calls) == 1, "repeating a refused key spends the quota for the same answer"
    assert seen == [401], "credential bookkeeping needs the refused status"


async def test_timeouts_are_retried_and_then_named():
    http = _FailingHttp(httpx.ConnectTimeout("boom"), times=2)
    errors: list[str] = []
    limits = ProviderLimits(max_attempts=2)
    result = await _client(http, limits=limits, errors=errors).get_json(
        "https://provider.example/x"
    )

    assert result.outcome == NETWORK_TIMEOUT
    assert http.calls == 2
    assert errors == [NETWORK_TIMEOUT]


async def test_post_sends_the_json_body():
    http = _Http(_Response(200, b"{}"))
    await _client(http).post_json("https://provider.example/x", json={"query": "brand"})

    assert http.calls[0][0] == "POST"
    assert http.calls[0][2]["json"] == {"query": "brand"}


async def test_transport_extensions_reach_the_connection_untouched():
    """A request pinned to an address still has to name the certificate's host.

    The shared client does not resolve, pin or follow redirects; what it must do is
    carry the connection detail the caller shaped to the transport that uses it
    (DNS Security's RDAP bootstrap, whose URL is an address and whose SNI is the
    registry's name).
    """
    http = _Http(_Response(200, b"{}"))
    await _client(http).get_json(
        "https://192.0.2.1/domain/example.com",
        headers={"Host": "rdap.example"},
        extensions={"sni_hostname": "rdap.example"},
    )

    assert http.calls[0][2]["extensions"] == {"sni_hostname": "rdap.example"}
    assert http.calls[0][2]["headers"] == {"Host": "rdap.example"}


async def test_a_call_without_extensions_does_not_invent_any():
    http = _Http(_Response(200, b"{}"))
    await _client(http).get_json("https://provider.example/x")

    assert "extensions" not in http.calls[0][2]


async def test_a_connector_can_name_a_rejection_the_vendor_words_its_way():
    """Some providers refuse in the body: the status alone cannot tell why."""
    http = _Http(_Response(403, b'{"error": "no query credits left"}'))

    def classify(status: int, body: str) -> str | None:
        return "quota_exhausted" if status == 403 and "credit" in body else None

    result = await _client(http, classify_error=classify).get_json(
        "https://provider.example/x"
    )

    assert result.outcome == "quota_exhausted"
    assert result.status == 403
    assert len(http.calls) == 1, "a refusal is not retried"


async def test_a_classifier_sees_only_the_head_of_a_refusal():
    """Naming a refusal must not become the unbounded read this client prevents."""
    http = _Http(_Response(403, b"x" * 8192 + b"missing credit"))
    seen: list[str] = []

    def classify(status: int, text: str) -> str | None:
        seen.append(text)
        return "quota_exhausted" if "credit" in text else None

    result = await _client(http, classify_error=classify).get_json(
        "https://provider.example/x"
    )

    assert result.outcome == "http_403", "nothing beyond the snippet is guessed at"
    assert len(seen) == 1
    assert len(seen[0]) <= ERROR_SNIPPET_BYTES


async def test_a_classifier_does_not_overwrite_the_clients_own_verdict():
    """A wait this client already decided on is not renamed back to the status."""
    http = _Http(_Response(429, b"slow down", headers={"Retry-After": "600"}))
    limits = ProviderLimits(abort_when_retry_after_exceeds=60.0)

    result = await _client(
        http, limits=limits, classify_error=lambda status, body: f"http_{status}"
    ).get_json("https://provider.example/x")

    assert result.outcome == "http_429_retry_later"


def test_retry_after_reads_seconds_dates_and_nonsense():
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    later = format_datetime(datetime(2026, 1, 1, 12, 0, 30, tzinfo=timezone.utc))

    assert parse_retry_after("7", now=now) == 7.0
    assert parse_retry_after(" 7 ", now=now) == 7.0
    assert parse_retry_after("-3", now=now) == 0.0
    assert parse_retry_after(later, now=now) == pytest.approx(30.0, abs=1.0)
    assert parse_retry_after("soon", now=now) is None
    assert parse_retry_after("", now=now) is None
    assert parse_retry_after(None, now=now) is None
