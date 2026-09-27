"""Structured logging configuration, and the audit trail's output contract.The failure this module exists to prevent
-----------------------------------------
Audit events were emitted with ``structlog.get_logger()`` and a
``structlog.stdlib.LoggerFactory``, under a processor chain whose first entry is
``structlog.stdlib.filter_by_level`` — a processor that drops the event unless
the *wrapped* logger accepts its level.

With no name argument, ``LoggerFactory.__call__`` does not return the root
logger: it walks the stack and names the logger after the first application
frame outside structlog, so an audit event emitted from ``AuditLogger.emit``
went to a logger called ``app.core.audit``. That name is harmless in itself; the
problem is that nothing ever called ``setLevel`` or ``addHandler`` on it, or on
any of its ancestors. Its effective level therefore came from the standard
library's default root level, WARNING, and it had no handler. An INFO event
fails ``isEnabledFor(INFO)``, ``filter_by_level`` raises ``DropEvent``, and the
event is discarded before any renderer sees it.

So every INFO audit event was lost on the way to stdout while the database row
was still written. The platform's documented promise — "the same event is
emitted as JSON to application output for log pipelines such as Elastic
Security" — was silently false, and nothing failed: the DB row appeared, the API
returned 200, and only the stdout half went missing. The same applied to every
non-audit INFO event in the application.

Three properties follow from that, and each is tested:

1. **Loggers have a name this module controls, a level, and a handler.** The
   factory below supplies a name when structlog asks for one without any, which
   fixes every existing ``structlog.get_logger()`` call site at once — roughly
   twenty of them — rather than depending on each one remembering to pass a
   name. An explicit name still wins. The trade-off is deliberate: platform
   events all report ``logger="opendrp"`` instead of their module, because the
   event names (``connector_poll_error``, ``audit_db_write_failed``, ...) already
   identify the component, and one namespace is what makes the level a single
   decision instead of twenty.
2. **A handler exists and writes to stdout.** A logger with no handler is a
   logger whose records are thrown away: the stdlib only falls back to
   ``lastResort``, which is WARNING and stderr.
3. **``LOG_LEVEL`` cannot silence the audit trail.** Audit events are records,
   not diagnostics: no log-level setting may be able to stop the platform
   recording who deleted an asset. ``opendrp.audit`` is pinned at INFO while the
   rest of the platform follows ``LOG_LEVEL``.

Deliberately absent: any file handler, ``/var/log`` path or rotation logic.
Containers write to stdout (12-factor) and the collector ships from there with
Docker metadata attached; a second, file-based copy of the audit stream would be
a second source of truth with its own retention rules. See
docs/observability.md.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import MutableMapping
from typing import Any, Callable

import structlog

from app.core.request_context import current_request_id

#: Root of every logger this application owns. Deliberately not the root logger:
#: third-party libraries own that one, and sharing it would mean inheriting its
#: level and competing for its handlers.
PLATFORM_LOGGER_NAME = "opendrp"

#: Logger the audit trail is written through. A child of the platform logger so
#: it inherits the stdout handler, with its own level so ``LOG_LEVEL`` cannot
#: silence it.
AUDIT_LOGGER_NAME = "opendrp.audit"

#: The synthetic event name that marks a record as an audit event.
AUDIT_EVENT_NAME = "audit_event"

#: The five fields an audit line carries, in order. This is a published
#: contract: `docs/db.sql`, `docs/description.md` and the logs shipped to a SIEM
#: all describe it, and `test_logging_config.py` fails if a sixth appears.
AUDIT_FIELDS = ("timestamp", "user_id", "action", "ip_address", "details")

_configured = False


def _add_request_id(
    logger: Any,
    method_name: str,
    event_dict: MutableMapping[str, Any],
) -> MutableMapping[str, Any]:
    """Attach the current request's id to every platform log line.

    For audit events this key is removed again by ``_render_audit_event``: the
    five-field contract is enforced above this processor, and an audit event's
    correlation lives inside ``details`` (written by ``AuditLogger``) rather than
    beside it. ``setdefault`` so a caller that already supplied an id — a Celery
    task adopting its producer's — keeps it.
    """
    request_id = current_request_id()
    if request_id is not None:
        event_dict.setdefault("request_id", request_id)
    return event_dict


def _render_audit_event(
    logger: Any,
    method_name: str,
    event_dict: MutableMapping[str, Any],
) -> MutableMapping[str, Any]:
    """Reduce an audit event to exactly the five published fields.

    Runs immediately before the JSON renderer, so an audit line is never a
    superset of the contract: extra keys would reach a SIEM index that maps the
    documented shape and quietly become unindexed noise. Correlation and context
    therefore belong *inside* ``details``, not beside it.
    """
    if event_dict.get("event") != AUDIT_EVENT_NAME:
        return event_dict
    return {key: event_dict.get(key) for key in AUDIT_FIELDS}


def _platform_logger_factory() -> Callable[..., Any]:
    """A stdlib logger factory that names unnamed loggers.

    ``structlog.get_logger()`` with no arguments calls the factory with no
    arguments, and the stdlib factory's answer to that is a logger named after
    the calling module — a name nothing configures, so it inherits the root
    level and has no handler. Substituting the platform name gives those events a
    logger this module sets up.

    Wrapping rather than subclassing the real factory is intentional: this
    depends only on its documented behaviour (``factory(name) -> logger``) and on
    nothing about how it is implemented, so a structlog upgrade cannot turn this
    into a silent regression.
    """
    stdlib_factory = structlog.stdlib.LoggerFactory()

    def factory(*args: Any) -> Any:
        if not args:
            args = (PLATFORM_LOGGER_NAME,)
        return stdlib_factory(*args)

    return factory


def configure_logging(*, force: bool = False) -> None:
    """Point platform logs at stdout as one JSON object per line.

    Idempotent, and called from each entry point (``app.main`` for the API,
    ``app.core.celery_app`` for workers and beat, ``app.core.audit`` because the
    audit contract is what it protects). Calling it twice must be a no-op rather
    than installing a second handler, which would double every line.
    """
    global _configured
    if _configured and not force:
        return

    # Imported here, not at module scope: this module is imported by audit.py,
    # which is imported by the Celery app module, and a module-level settings
    # import would make the import order of the whole package matter.
    from app.core.config import settings

    level = getattr(logging, str(settings.LOG_LEVEL).upper(), logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    # structlog renders the line; the stdlib formatter must add nothing. A
    # timestamp or logger-name prefix would turn one JSON object into a line
    # that a JSON parser rejects.
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.setLevel(logging.DEBUG)

    platform_logger = logging.getLogger(PLATFORM_LOGGER_NAME)
    platform_logger.handlers = [handler]
    platform_logger.setLevel(level)
    # Own the stream. Without this, anything that later adds a root handler (a
    # test runner, a future integration) would print every record twice.
    platform_logger.propagate = False

    # Audit records are not diagnostics. See the module docstring: a level that
    # silences them is a security failure, not a tuning preference.
    logging.getLogger(AUDIT_LOGGER_NAME).setLevel(logging.INFO)

    structlog.configure(
        processors=[
            # Delegates the level decision to the stdlib logger, which is why the
            # handler and the logger level above are what make events appear.
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            _add_request_id,
            _render_audit_event,
            structlog.processors.JSONRenderer(ensure_ascii=False),
        ],
        logger_factory=_platform_logger_factory(),
        # Not cached: this is what lets a logger bound before configuration pick
        # up the configuration when it is first used.
        cache_logger_on_first_use=False,
    )
    _configured = True


def get_logger(name: str | None = None) -> Any:
    """Return a bound structlog logger under the platform namespace.

    Prefer this to ``structlog.get_logger()`` at module scope: it documents the
    intent and does not rely on the factory wrapper above.
    """
    return structlog.get_logger(name or PLATFORM_LOGGER_NAME)
