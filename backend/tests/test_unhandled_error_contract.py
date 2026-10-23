"""The 500 nobody planned: same opaque body, but traceable.

Starlette renders an unhandled exception in ``ServerErrorMiddleware``, which sits
outside every middleware the application installs. The consequence is invisible
until somebody has to debug one: the response carries neither ``X-Request-ID``
nor the security headers, and the traceback is written by the server's own
logger, which knows nothing about the request's correlation id. In other words
the one response that *is* a bug report is the one that cannot be correlated
with an audit row, a log line or a support ticket.

The handler in ``app.core.exceptions`` moves that response inside
``ExceptionMiddleware``. These tests pin the two things that change — the id and
the structured log line — and the one that must not: the body stays the opaque
"Internal Server Error", so nothing a client parses depends on the internals.
"""

from __future__ import annotations

import httpx
import pytest

from app.core.logging_config import configure_logging
from app.main import app


class _Client:
    """A client that reads the response instead of re-raising the exception.

    The suite's shared ``client`` re-raises whatever the application raises, and
    Starlette's outermost error middleware re-raises *after* the response is
    sent, so a test of that response has to look at it rather than at the
    exception. Production is the same transport question with a different
    answer: uvicorn logs the traceback and the client receives this response.
    """

    def __init__(self) -> None:
        self._transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)

    async def __aenter__(self) -> httpx.AsyncClient:
        self._client = httpx.AsyncClient(
            transport=self._transport, base_url="http://testserver"
        )
        return await self._client.__aenter__()

    async def __aexit__(self, *exc_info) -> None:
        await self._client.__aexit__(*exc_info)


def _add_boom_route() -> None:
    """A route that raises, added to the real app so the real stack is exercised.

    The stack order in ``app/main.py`` is the thing under test, so a throwaway
    FastAPI instance would prove nothing.
    """

    async def _boom() -> None:
        raise RuntimeError("probe failure with a secret-looking value sk-live-1234567890")

    app.add_api_route("/api/v1/_probe_boom", _boom, methods=["GET"])
    app.router.routes = app.router.routes  # keep the reference explicit for readers


@pytest.fixture
def boom_route():
    before = len(app.router.routes)
    _add_boom_route()
    try:
        yield
    finally:
        del app.router.routes[before:]


@pytest.mark.asyncio
async def test_an_unhandled_error_still_carries_the_request_id(boom_route):
    async with _Client() as client:
        response = await client.get(
            "/api/v1/_probe_boom", headers={"X-Request-ID": "probe-500"}
        )

    assert response.status_code == 500
    assert response.text == "Internal Server Error"
    assert response.headers["X-Request-ID"] == "probe-500"
    # The security headers are applied one layer in, so this response has none of
    # them. That is deliberate rather than overlooked: the body is one fixed
    # string served as `text/plain`, there is nothing to sniff and nothing to
    # frame, and repeating the header policy here would give it two owners.
    assert "Content-Security-Policy" not in response.headers


@pytest.mark.asyncio
async def test_an_unhandled_error_is_logged_with_its_correlation_id(boom_route, capsys):
    """One structured line, carrying the id and the exception type — not the message.

    The message is deliberately not forwarded: a route can raise with a value the
    platform was trusted to hold (a provider key, a target address), and this
    line feeds the same JSON stream the audit rows travel on.
    """
    # The logger holds the stream it was built with, so a test that replaces
    # stdout has to re-configure it — the same reason `test_request_context`
    # does this before it reads a line.
    configure_logging(force=True)
    capsys.readouterr()

    async with _Client() as client:
        await client.get("/api/v1/_probe_boom", headers={"X-Request-ID": "correlate-me"})

    logged = capsys.readouterr().out
    assert "unhandled_exception" in logged
    assert "correlate-me" in logged
    assert "RuntimeError" in logged
    assert "sk-live-1234567890" not in logged
