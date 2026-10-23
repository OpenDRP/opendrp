"""The metrics scrape endpoint.

How the platform tells an operator that something is wrong without that operator
asking three endpoints by hand. The metric list, the thresholds worth alerting
on, and the scrape configuration are in ``docs/observability.md``.

Two decisions shape this file:

* **The endpoint does not exist until a token is configured.** With
  ``METRICS_TOKEN`` unset it answers 404 — not 403 — because a scrape endpoint
  reachable by anyone is a map of the platform's internals (connector names,
  backlog sizes, how far the audit chain has been verified) and an unauthenticated
  403 still confirms the path is there. Failure is closed: no token, no endpoint.
* **A refused scrape is logged, a successful one is not.** Every audit row
  matters, and a scraper polling every fifteen seconds would put 5 700 rows a day
  into the audit chain describing a read of aggregate counts — the noise that
  hides the events the chain exists for. Refusals are the interesting half, and
  they are a warning with the client address and nothing else.
"""

from __future__ import annotations

import secrets

from fastapi import APIRouter, Request, status
from fastapi.responses import PlainTextResponse

# The counters are read through the module, not imported as an object: the
# middleware reads the module global on every request for exactly this reason (see
# ``MetricsMiddleware``), and a `from ... import request_metrics` here would pin
# the endpoint to the object that existed at import time — so a reset, which
# rebinds the global, would leave the scrape reporting a previous life's numbers
# while the middleware counted into the new one.
from app.core import metrics as metrics_module
from app.core.config import settings
from app.core.exceptions import NotFoundException, UnauthorizedException
from app.core.logging_config import get_logger
from app.core.metrics import CONTENT_TYPE, collect_database_samples, render

router = APIRouter(prefix="/metrics", tags=["Metrics"])

log = get_logger("opendrp.metrics")

#: The header a scraper presents the token in. A header rather than a query
#: string: a URL is written into proxy access logs, and a credential in one is a
#: credential in every log between the scraper and this process.
METRICS_TOKEN_HEADER = "X-Metrics-Token"

#: The same credential in the standard form, because Prometheus's own
#: `authorization` block only speaks `Bearer` and `Basic`; asking an operator to
#: put a header in through a proxy when the agent understands the credential is a
#: configuration error waiting to happen.
_BEARER_PREFIX = "Bearer "


@router.get(
    "",
    response_class=PlainTextResponse,
    status_code=status.HTTP_200_OK,
    summary="Platform metrics in the Prometheus text exposition format",
    description=(
        "Prometheus text exposition format. Requires the token configured in "
        "`METRICS_TOKEN`, presented as `X-Metrics-Token`; the endpoint answers "
        "404 when no token is configured, so an installation that does not "
        "scrape metrics does not publish the route."
    ),
)
async def scrape_metrics(request: Request) -> PlainTextResponse:
    """Render this replica's metrics, refusing anything but a correct token."""
    configured = settings.METRICS_TOKEN
    if not configured:
        raise NotFoundException("Not found")

    presented = request.headers.get(METRICS_TOKEN_HEADER, "")
    if not presented:
        authorization = request.headers.get("Authorization", "")
        if authorization.startswith(_BEARER_PREFIX):
            presented = authorization[len(_BEARER_PREFIX) :]
    # Constant-time: a token compared with `==` leaks its length and prefix
    # through response timing, which is enough to recover one character at a time.
    if not presented or not secrets.compare_digest(presented, configured):
        # Imported here rather than at module scope for the same reason the audit
        # router does it: `deps` pulls in the whole authorization stack, which
        # this route never uses.
        from app.api.deps import extract_ip

        log.warning(
            "metrics_scrape_refused",
            ip_address=extract_ip(request),
            token_presented=bool(presented),
        )
        raise UnauthorizedException("A metrics scrape must present the configured token")

    # The session is opened after authentication, not by a route dependency: a
    # refused scrape must not take a connection from the pool.
    from app.core.database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        samples = metrics_module.request_metrics.samples() + await collect_database_samples(db)
    return PlainTextResponse(render(samples), media_type=CONTENT_TYPE)
