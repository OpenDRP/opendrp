from typing import Any

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy.exc import DBAPIError, TimeoutError as SQLAlchemyPoolTimeout

from app.core.logging_config import get_logger

log = get_logger("opendrp.db")

#: SQLSTATE 57014 — `query_canceled`, which is what PostgreSQL raises when
#: `statement_timeout` fires. Note that the same state is used for a
#: user-requested cancellation; both mean the statement did not complete, which
#: is all this mapping needs to know.
_STATEMENT_TIMEOUT_SQLSTATE = "57014"


class ForbiddenException(HTTPException):
    def __init__(self, detail: Any = "Insufficient permissions"):
        super().__init__(status_code=403, detail=detail)


class UnauthorizedException(HTTPException):
    """401, optionally carrying headers the caller must send back with it.

    `headers` exists for responses that do more than describe the refusal —
    clearing a cookie the client must stop presenting, for instance. It has to
    travel on the exception because the handler below renders the 401 from its own
    response object: anything set on a route's injected `Response` is discarded
    when that route raises.
    """

    def __init__(
        self, detail: Any = "Not authenticated", *, headers: dict[str, str] | None = None
    ):
        merged = {"WWW-Authenticate": "Bearer"}
        if headers:
            merged.update(headers)
        super().__init__(status_code=401, detail=detail, headers=merged)


class NotFoundException(HTTPException):
    def __init__(self, detail: Any = "Resource not found"):
        super().__init__(status_code=404, detail=detail)


class ConflictException(HTTPException):
    def __init__(self, detail: Any = "Resource conflict"):
        super().__init__(status_code=409, detail=detail)


class BadRequestException(HTTPException):
    def __init__(self, detail: Any = "Bad request"):
        super().__init__(status_code=400, detail=detail)


class RateLimitException(HTTPException):
    """429 for a manual action that is inside the user's configured window."""

    def __init__(self, detail: Any = "Too many requests", *, retry_after: int | None = None):
        headers = {"Retry-After": str(retry_after)} if retry_after is not None else None
        super().__init__(status_code=429, detail=detail, headers=headers)


class DatabaseBusyException(HTTPException):
    """503 for a statement the database itself cancelled.

    A statement that exceeded ``DB_STATEMENT_TIMEOUT_MS`` is a bounded condition:
    it was stopped so that its connection could go back to the pool instead of
    being held indefinitely, and the same request may well succeed on a quieter
    platform. Reporting that as a 500 would tell the caller something broke for
    an unknown reason and hand them nothing to act on — and would put a
    deliberate limit into the same bucket as a bug. 503 with ``Retry-After``
    says what actually happened.
    """

    def __init__(
        self,
        detail: Any = (
            "The database cancelled the query: it exceeded this deployment's "
            "statement timeout. Retry, narrow the query, or raise "
            "DB_STATEMENT_TIMEOUT_MS."
        ),
        *,
        retry_after: int = 5,
    ):
        super().__init__(status_code=503, detail=detail, headers={"Retry-After": str(retry_after)})


def statement_timeout_sqlstate(exc: BaseException) -> str | None:
    """The SQLSTATE behind a SQLAlchemy error, if the driver exposed one.

    asyncpg carries it on the exception; SQLAlchemy wraps that exception in
    ``DBAPIError.orig``. Both are checked because the wrapper's own attributes
    have changed between versions and the driver's have not.
    """
    for candidate in (getattr(exc, "orig", None), exc):
        if candidate is None:
            continue
        state = getattr(candidate, "sqlstate", None) or getattr(candidate, "pgcode", None)
        if state:
            return str(state)
    return None


def _is_database_timeout(exc: BaseException) -> bool:
    """True for a statement the server cancelled, or one the client gave up on.

    Covers both halves of the limit configured in ``core/database.py``:
    PostgreSQL's own ``statement_timeout`` (SQLSTATE 57014) and asyncpg's
    ``command_timeout``, which surfaces as a ``TimeoutError`` raised from inside
    the driver rather than as a SQLSTATE.
    """
    if statement_timeout_sqlstate(exc) == _STATEMENT_TIMEOUT_SQLSTATE:
        return True
    return isinstance(getattr(exc, "orig", None), TimeoutError)


def register_exception_handlers(app) -> None:
    @app.exception_handler(ForbiddenException)
    async def forbidden_handler(request: Request, exc: ForbiddenException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
        )

    @app.exception_handler(UnauthorizedException)
    async def unauthorized_handler(
        request: Request, exc: UnauthorizedException
    ) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=exc.headers or {},
        )

    @app.exception_handler(NotFoundException)
    async def not_found_handler(
        request: Request, exc: NotFoundException
    ) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
        )

    @app.exception_handler(ConflictException)
    async def conflict_handler(
        request: Request, exc: ConflictException
    ) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
        )

    @app.exception_handler(BadRequestException)
    async def bad_request_handler(request: Request, exc: BadRequestException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
        )

    @app.exception_handler(RateLimitException)
    async def rate_limit_handler(request: Request, exc: RateLimitException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=exc.headers or {},
        )


    @app.exception_handler(HTTPException)
    async def http_exception_handler(
        request: Request, exc: HTTPException
    ) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=getattr(exc, "headers", None) or {},
        )

    @app.exception_handler(SQLAlchemyPoolTimeout)
    async def database_pool_timeout_handler(request: Request, exc: SQLAlchemyPoolTimeout):
        """Return a bounded 503 when every database connection is occupied.

        This is distinct from asyncpg's command timeout (wrapped by
        ``DBAPIError`` below): QueuePool raises its own SQLAlchemy exception
        before a statement can start. Letting it fall through as a 500 hides
        pool saturation and encourages clients to retry without a retry hint.
        """
        log.warning(
            "db_pool_timeout",
            path=request.url.path,
            method=request.method,
            error=type(exc).__name__,
        )
        busy = DatabaseBusyException(
            "The database connection pool is busy; retry the request shortly."
        )
        return JSONResponse(
            status_code=busy.status_code,
            content={"detail": busy.detail, "code": "database_busy"},
            headers=busy.headers or {},
        )

    @app.exception_handler(DBAPIError)
    async def database_error_handler(request: Request, exc: DBAPIError):
        """Separate "the database stopped this on purpose" from "this is a bug".

        The timeout branch is the reason this handler exists: without it, a
        saturating query and a genuine defect produce the same response, and only
        one of them is worth alerting on.

        Everything else keeps the default behaviour (a 500 with an opaque body)
        and gains a structured log line, so that handling the timeout did not
        quietly cost the traceback that made an unexpected database error
        debuggable.
        """
        if _is_database_timeout(exc):
            log.warning(
                "db_statement_timeout",
                path=request.url.path,
                method=request.method,
                sqlstate=statement_timeout_sqlstate(exc),
            )
            busy = DatabaseBusyException()
            return JSONResponse(
                status_code=busy.status_code,
                content={"detail": busy.detail, "code": "database_busy"},
                headers=busy.headers or {},
            )

        log.error(
            "db_error",
            path=request.url.path,
            method=request.method,
            sqlstate=statement_timeout_sqlstate(exc),
            err=type(exc).__name__,
        )
        return PlainTextResponse("Internal Server Error", status_code=500)
