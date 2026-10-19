from typing import Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")

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
