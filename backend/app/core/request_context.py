"""Request correlation.

Every HTTP request is given an identifier that shows up in three places:

* the ``X-Request-ID`` response header, so a person reporting a problem can
  quote it instead of a timestamp;
* every log line emitted while that request is being handled (a structlog
  processor adds it, see ``app/core/logging_config.py``);
* the ``details`` of every audit row the request causes, which is what makes the
  database and the log pipeline answer the same question with the same key.

Without it, "what happened at 14:03:07" has to be answered by joining a log
stream to an audit table on timestamp and client address — two fields that were
never designed to identify a single request, in a platform that writes an audit
row for the *authenticated* address behind a proxy.

Why the value is validated
--------------------------
The header arrives from the client, so it is untrusted input being written into
logs and a database column. A value with a newline can forge log records in
anything that is not JSON-encoded, an unbounded value is a way to inflate the
log volume an attacker can generate per request, and neither is something a
correlation id ever needs. The allowlist is therefore narrow on purpose:
``[A-Za-z0-9._-]{1,64}``. Anything else is replaced by a generated identifier
rather than rejected — a client sending junk should still be traceable.
"""

from __future__ import annotations

import re
import uuid
from contextvars import ContextVar, Token
from typing import Any

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

#: The header the platform reads and returns.
REQUEST_ID_HEADER = "X-Request-ID"

#: Prefix for identifiers this platform generates. Makes a generated id
#: distinguishable from a client's own, which matters when the client is a
#: connector or another service that supplies its own scheme.
GENERATED_PREFIX = "req-"

_MAX_LENGTH = 64

# ``\A``/``\Z`` rather than ``^``/``$``: in Python's ``re``, ``$`` also matches
# just before a trailing newline, so a value ending in a newline would have been
# accepted by the very check whose purpose is to keep newlines out of the sinks.
_REQUEST_ID_PATTERN = re.compile(r"\A[A-Za-z0-9._-]{1,64}\Z")

_request_id_var: ContextVar[str | None] = ContextVar("opendrp_request_id", default=None)


def new_request_id() -> str:
    """A fresh identifier, short enough to quote over the phone."""
    return f"{GENERATED_PREFIX}{uuid.uuid4().hex[:24]}"


def sanitize_request_id(raw: str | None) -> str | None:
    """Return a usable incoming identifier, or ``None`` to generate one.

    Deliberately a strict allowlist rather than an escape: the value is echoed
    back to the client and written to two sinks, and there is no legitimate id
    that needs a character outside this set.
    """
    candidate = (raw or "").strip()
    if not candidate or len(candidate) > _MAX_LENGTH:
        return None
    if not _REQUEST_ID_PATTERN.match(candidate):
        return None
    return candidate


def current_request_id() -> str | None:
    """The identifier for the request being handled, if there is one.

    ``None`` outside a request (a Celery worker, a CLI script), which is the
    honest answer: those are not HTTP requests and inventing an id for them would
    make the field useless for filtering.
    """
    return _request_id_var.get()


def set_request_id(value: str | None) -> Token:
    """Set the current identifier. Used by workers to adopt a producer's id."""
    return _request_id_var.set(value)


def reset_request_id(token: Token) -> None:
    _request_id_var.reset(token)


def request_id_header() -> dict[str, str]:
    """Headers that carry this request's id to another process.

    For enqueueing a task: the worker picks the value out of the task headers and
    records it alongside its own audit rows, so one user action stays one trail
    across the process boundary.
    """
    request_id = current_request_id()
    return {REQUEST_ID_HEADER: request_id} if request_id else {}


class RequestContextMiddleware:
    """Pure ASGI middleware: assign, propagate and return a request id.

    ASGI middleware rather than ``BaseHTTPMiddleware`` on purpose. The latter
    runs the application in a child task, and context variables set in the
    middleware are only visible to that child because of how the task copies the
    context at creation; a later addition that sets the id *after* the call would
    silently stop propagating it. Here the application is awaited in the same
    task, so anything set before the call is visible for its whole duration.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            # Lifespan and websocket scopes have no request to correlate.
            await self.app(scope, receive, send)
            return

        incoming = Headers(scope=scope).get(REQUEST_ID_HEADER)
        request_id = sanitize_request_id(incoming) or new_request_id()
        token = _request_id_var.set(request_id)

        async def send_with_request_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                # Echoed even on a rejection: the id is what makes a 4xx in
                # someone's bug report findable in the logs.
                MutableHeaders(scope=message)[REQUEST_ID_HEADER] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_with_request_id)
        finally:
            # The context is per-request via the task, but resetting keeps the
            # variable's lifetime correct for reused contexts (tests, embedded
            # servers) instead of leaking one request's id into the next.
            _request_id_var.reset(token)


def install_request_context(app: Any) -> None:
    """Register the middleware on a Starlette/FastAPI application."""
    app.add_middleware(RequestContextMiddleware)
