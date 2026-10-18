"""One provider call: paced, budgeted, bounded, retried and classified.

Three connectors that spend money at a third-party API each grew their own copy
of the same four mechanisms — a pace, a quota reservation, a retry loop and a
``Retry-After`` parser — while the outcomes were named three different ways. The
core's readiness and failure reporting could not compare them, and two of the
three decoded an unbounded response body into memory.

This module owns the mechanisms once. What stays in a connector is what only its
provider knows: URLs and parameters, where the key goes, which calls are free,
which rejection text means "quota", and how a payload becomes a finding.

Nothing here follows redirects, resolves hosts or pins an address. A connector
that needs that (DNS Security's RDAP bootstrap) builds the URL itself and keeps
``follow_redirects=False`` on its own client; this client sends the request it is
given and hands back the response so the caller can read ``Location``.
"""

from __future__ import annotations

import asyncio
import json as _json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Awaitable, Callable, Sequence

import httpx

#: The shared outcome vocabulary. A connector may add its own (``quota_exhausted``
#: from a provider's rejection text) but must not rename these: they are what the
#: core compares between providers.
RESPONSE_TOO_LARGE = "response_too_large"
INVALID_JSON = "invalid_json"
INVALID_RESPONSE = "invalid_response"
NETWORK_ERROR = "network_error"
NETWORK_TIMEOUT = "network_timeout"
RETRY_EXHAUSTED = "retry_exhausted"
#: Suffix a 429/5xx carries when the provider's hint is longer than the scan may
#: wait: ``http_429_retry_later``.
RETRY_LATER = "retry_later"


@dataclass(frozen=True)
class ProviderLimits:
    """What every provider call is held to, unless the connector says otherwise.

    The defaults are the strictest of the three connectors that existed when this
    module was written (DNS Security's): three attempts, a 30 second ceiling on
    any single wait, a 2 MB body. A connector whose provider documents different
    values passes them explicitly rather than relying on these.
    """

    max_attempts: int = 3
    max_retry_delay: float = 30.0
    max_response_bytes: int = 2_000_000
    timeout: float = 30.0
    #: Statuses that count as "the provider answered". 200 only, because a 204
    #: from a JSON route is an empty answer, not a payload.
    ok_statuses: tuple[int, ...] = (200,)
    #: A provider asking for a longer pause than this is not waited out inside a
    #: scan: the call is abandoned with ``http_<status>_retry_later`` instead, so
    #: a 30 minute hint cannot silently stretch one job. ``None`` disables it.
    abort_when_retry_after_exceeds: float | None = 60.0


@dataclass(frozen=True)
class ProviderResult:
    """What one provider call produced.

    ``outcome`` is ``None`` on success, otherwise one of the shared names above or
    ``http_<status>``. ``response`` is kept on failure because a caller may need
    it (RDAP reads ``Location`` from a 3xx); it is ``None`` when there was no
    response at all.

    ``snippet`` is the head of the body that came with a refusal, bounded by
    :data:`ERROR_SNIPPET_BYTES`. A connector that writes the provider's own words
    into its log gets them from here rather than re-reading a stream that is
    already closed.
    """

    payload: dict | list | None
    status: int | None
    outcome: str | None
    response: Any | None = field(default=None, repr=False)
    snippet: str | None = field(default=None, repr=False)

    @property
    def ok(self) -> bool:
        return self.outcome is None


def parse_retry_after(value, *, now: datetime | None = None) -> float | None:
    """Read a provider's ``Retry-After`` in either documented form.

    The header may be a number of seconds or an HTTP-date, and both appear in the
    wild: Shodan sends the first, some gateways the second. A value that is
    neither is not a hint, and ``None`` means "use the local backoff".
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return max(0.0, float(text))
    except ValueError:
        pass
    try:
        target = parsedate_to_datetime(text)
    except (TypeError, ValueError, OverflowError):
        return None
    if target.tzinfo is None:
        target = target.replace(tzinfo=timezone.utc)
    reference = now or datetime.now(timezone.utc)
    return max(0.0, (target - reference).total_seconds())


Reserve = Callable[[], Awaitable[None]]
Pace = Callable[[], Awaitable[None]]
OnStatus = Callable[[int], None]
#: ``(status, body snippet) -> outcome``. A provider that refuses in its body
#: rather than its status (Shodan's 403 with the word "credit") needs this; the
#: snippet is bounded, so naming a refusal can never become an unbounded read.
ClassifyError = Callable[[int, str], str | None]

#: How much of a refused response's body a classifier may see. Large enough for
#: the sentence a provider writes, small enough that it is never the whole answer.
ERROR_SNIPPET_BYTES = 4096


class ProviderClient:
    """Make one provider HTTP call under the account's budget and its pace.

    ``reserve`` is awaited before *every* wire attempt, including retries: a
    retried call is a second spend. An exception it raises is the connector's own
    decision (a scan that has run out of budget aborts), so it is propagated
    rather than swallowed.

    ``pace`` is one callable or a sequence, all awaited before each attempt; the
    two-limiter case is HIBP's per-route allowance, where the account's pace is
    not permission to spend a route's own limit faster than it exists.

    ``on_status`` sees every response status as it arrives, which is where a
    connector keeps its credential state (401 → invalid, 200 → valid) without this
    class knowing what a credential is.
    """

    def __init__(
        self,
        *,
        http: httpx.AsyncClient,
        limits: ProviderLimits = ProviderLimits(),
        reserve: Reserve | None = None,
        pace: Pace | Sequence[Pace] | None = None,
        on_status: OnStatus | None = None,
        classify_error: ClassifyError | None = None,
        errors: list[str] | None = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        self._http = http
        self.limits = limits
        self._reserve = reserve
        if pace is None:
            self._pacers: tuple[Pace, ...] = ()
        elif isinstance(pace, (list, tuple)):
            self._pacers = tuple(pace)
        else:
            self._pacers = (pace,)
        self._on_status = on_status
        self._classify = classify_error
        self.errors: list[str] = errors if errors is not None else []
        self._sleep = sleep or asyncio.sleep

    async def get_json(self, url: str, **kwargs) -> ProviderResult:
        return await self._call("GET", url, **kwargs)

    async def post_json(self, url: str, **kwargs) -> ProviderResult:
        return await self._call("POST", url, **kwargs)

    async def _call(
        self,
        method: str,
        url: str,
        *,
        params: dict | None = None,
        headers: dict | None = None,
        json: Any = None,
        free: bool = False,
        timeout: float | httpx.Timeout | None = None,
    ) -> ProviderResult:
        last_outcome = RETRY_EXHAUSTED
        last_response = None
        for attempt in range(self.limits.max_attempts):
            for pacer in self._pacers:
                await pacer()
            if self._reserve is not None and not free:
                await self._reserve()
            try:
                async with self._http.stream(
                    method,
                    url,
                    params=params,
                    headers=headers,
                    json=json,
                    timeout=timeout if timeout is not None else self.limits.timeout,
                ) as response:
                    status = int(response.status_code)
                    if self._on_status is not None:
                        self._on_status(status)
                    if status in self.limits.ok_statuses:
                        payload, outcome = await self._read(response)
                        if outcome is None:
                            return ProviderResult(payload, status, None, response)
                        self._record(outcome)
                        return ProviderResult(None, status, outcome, response)
                    if status == 429 or 500 <= status < 600:
                        last_outcome = f"http_{status}"
                        last_response = response
                        hint = parse_retry_after(response.headers.get("Retry-After"))
                        ceiling = self.limits.abort_when_retry_after_exceeds
                        if hint is not None and ceiling is not None and hint > ceiling:
                            return await self._rejected(
                                response, status, f"http_{status}_{RETRY_LATER}"
                            )
                        if attempt + 1 < self.limits.max_attempts:
                            delay = hint if hint is not None else 2**attempt
                            await self._sleep(min(self.limits.max_retry_delay, delay))
                            continue
                        return await self._rejected(response, status, last_outcome)
                    return await self._rejected(response, status, f"http_{status}")
            except httpx.TimeoutException:
                last_outcome = NETWORK_TIMEOUT
            except httpx.HTTPError:
                last_outcome = NETWORK_ERROR
            if attempt + 1 < self.limits.max_attempts:
                await self._sleep(min(self.limits.max_retry_delay, 2**attempt))
        self._record(last_outcome)
        return ProviderResult(None, None, last_outcome, last_response)

    async def _read(self, response) -> tuple[dict | list | None, str | None]:
        """Stream a body up to the limit, then decode it.

        The read is streamed rather than buffered so an oversized answer is
        refused at the moment it crosses the limit instead of after it has already
        been held in memory — the failure this bound exists to prevent.
        """
        content = bytearray()
        try:
            async for chunk in response.aiter_bytes():
                if len(content) + len(chunk) > self.limits.max_response_bytes:
                    return None, RESPONSE_TOO_LARGE
                content.extend(chunk)
        except httpx.HTTPError:
            return None, NETWORK_ERROR
        try:
            payload = _json.loads(content)
        except (ValueError, UnicodeError):
            return None, INVALID_JSON
        if not isinstance(payload, (dict, list)):
            return None, INVALID_RESPONSE
        return payload, None

    async def _rejected(
        self, response, status: int, outcome: str
    ) -> ProviderResult:
        """Name a refusal the way the connector does, then report it.

        Only a plain ``http_<status>`` is offered to the classifier: an outcome
        that already carries a decision (``http_429_retry_later``) is this
        client's own verdict about the wait, and a connector's error table must
        not overwrite it with the bare status again.

        The head of the body is read either way, because it is what the caller
        logs beside the failure. A waiter that skipped the read would leave the
        operator with a status and no reason.
        """
        snippet = ""
        if outcome == f"http_{status}":
            snippet = await self._snippet(response)
            if self._classify is not None:
                outcome = self._classify(status, snippet) or outcome
        self._record(outcome)
        return ProviderResult(None, status, outcome, response, snippet=snippet)

    async def _snippet(self, response) -> str:
        """Read the head of a refused body, never more than the bound.

        Some providers state the reason in the text of the rejection, and the
        caller needs it to tell a drained account from a forbidden one. Reading
        the whole body here would reintroduce the unbounded read this file
        exists to prevent, so the snippet stops at
        :data:`ERROR_SNIPPET_BYTES` whatever the provider sends.
        """
        content = bytearray()
        try:
            async for chunk in response.aiter_bytes():
                content.extend(chunk)
                if len(content) >= ERROR_SNIPPET_BYTES:
                    break
        except httpx.HTTPError:
            return ""
        return bytes(content[:ERROR_SNIPPET_BYTES]).decode("utf-8", "replace")

    def _record(self, outcome: str) -> None:
        if outcome not in self.errors:
            self.errors.append(outcome)
