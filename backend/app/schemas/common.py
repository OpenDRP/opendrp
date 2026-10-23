from typing import Generic, Literal, TypeVar

from pydantic import BaseModel

T = TypeVar("T")

#: The states a health badge can show, shared by the connector and alert-channel
#: readers because the SPA has one `HealthState` type for both.
#:
#: The connector composer produces five of them (``disabled``, ``failed``,
#: ``unknown``, ``degraded``, ``healthy``) and never ``not_configured``, which is a
#: channel probe's answer for settings that are incomplete. One spelling is what keeps
#: the two answers from growing separate vocabularies for the same badge.
HealthState = Literal[
    "healthy", "degraded", "failed", "disabled", "not_configured", "unknown"
]

#: The largest page a list endpoint will return.
#:
#: A second bound beside ``page``, deliberately: an unbounded ``size`` is a
#: request for the whole table, which is the shape that turns a listing into a
#: statement timeout. It is a shared constant because the UI has to name the same
#: number — the shared DataTable used to offer "All" (``size=10000``), and every
#: list endpoint answered that option with HTTP 422, which the operator saw as a
#: table that could not load at all.
MAX_PAGE_SIZE = 200


#: There is deliberately no request-side pagination model here (WI-24).
#:
#: ``PaginationParams(skip, limit <= 500)`` used to live in this module: a second
#: spelling of pagination with a third limit, unused by every route, and a
#: standing contradiction of §4.3's "pagination is spelled ``size`` everywhere" —
#: whoever wired it up next would have reintroduced the divergence the page-size
#: contract removed. Routes declare ``page`` and ``size`` (bounded by
#: :data:`MAX_PAGE_SIZE`) and answer with :class:`PaginatedResponse`.


class PaginatedResponse(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    size: int
    pages: int


class MessageSchema(BaseModel):
    detail: str


class RevokedSessionsResponse(BaseModel):
    """How many refresh families a revocation ended.

    Two routers answer it — ending every session but the browser presenting the
    cookie, and an administrator ending another account's — and both sent the one
    key as an unmodelled dict until plan 038. The count rather than the families:
    what an operator needs is that the action happened, and the session list shows
    what is left.
    """

    revoked: int


class CleanupResponse(BaseModel):
    """What a delete-the-orphans route answers.

    Two routers answer this shape (`POST /breaches/cleanup-orphans` and
    `POST /phishing/threats/cleanup-orphans`) and the SPA reads one interface
    from both, so the declaration is shared: the count is the one the service
    deleted and the audit row carries, and the status says the pass completed
    rather than that nothing was found.
    """

    status: str
    deleted: int
