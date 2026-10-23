"""Platform health as metrics, in the Prometheus text exposition format.

The audit's finding was blunt: an operator had no metric to alert on. The
platform could tell a person that PostgreSQL answered (`/api/v1/ready`) and that
a connector had been seen recently (`/api/v1/connectors/health`), but "the alert
queue is backing up", "no connector has spoken in an hour" and "the audit chain
has not been verified since Tuesday" were visible only by reading three
endpoints by hand, which is the same as not being visible at all.

Two kinds of number live here, and the difference is deliberate:

* **Durable gauges** are read from the database on each scrape, so every replica
  reports the same value and the number survives a restart: delivery backlog,
  recipient holds, connector silence, job states, and where the audit chain
  stands. These are the ones an alert is written against.
* **Process counters** are per replica and reset when it restarts — the HTTP
  request families. They answer "is this replica serving errors" rather than
  "is the platform healthy", and the documentation says so; a counter that looks
  durable and is not would make a restart read as a drop in traffic.

Three rules keep the exposition safe to hand to a scraper:

* **No value from a request ever becomes a label.** Labels come from the
  platform's own enumerations (delivery status, job status, HTTP status class,
  :data:`KNOWN_METHODS`) and from the *name* of a registered connector. An email
  address, a finding title or a request path is data; putting one in a label is
  how a metrics
  endpoint becomes an unbounded memory leak and a copy of the very records the
  audit trail is supposed to hold. ``tests/test_metrics.py`` asserts this for the
  rows it can construct.
* **Every family is declared** in :data:`FAMILIES`, with its type and the
  sentence a dashboard shows. Rendering an undeclared name is an error rather
  than a silent line: the family list is the review surface, and a metric that
  skips it skips the review.
* **The format is written here**, not bought. ``prometheus_client`` would be one
  more dependency in a hash-locked manifest for a hundred lines of text
  formatting, and the exposition format has been stable for a decade.

The endpoint itself lives in ``app/api/v1/routers/metrics.py`` and is disabled
unless ``METRICS_TOKEN`` is set; ``docs/observability.md`` has the metric list,
the thresholds an alert should use, and the scrape configuration.
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import __version__
from app.core.config import settings

#: Prometheus's own content type for this format, version included: a scraper
#: reads the version from here, and a handler that answers `text/plain` alone is
#: treated as an unknown format by some collectors.
CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

#: Family name -> (type, help). Every sample must belong to one of these; see the
#: module docstring for why that is enforced rather than assumed.
FAMILIES: dict[str, tuple[str, str]] = {
    "opendrp_build_info": (
        "gauge",
        "Build and environment of the process answering this scrape; always 1.",
    ),
    "opendrp_process_start_time_seconds": (
        "gauge",
        "Unix time at which this process started.",
    ),
    "opendrp_process_uptime_seconds": (
        "gauge",
        "Seconds since this process started.",
    ),
    "opendrp_http_requests_in_flight": (
        "gauge",
        "Requests this replica is handling right now.",
    ),
    "opendrp_http_requests_total": (
        "counter",
        "Requests this replica has handled, by method and status class.",
    ),
    "opendrp_http_request_duration_seconds_sum": (
        "counter",
        "Total seconds this replica spent handling requests, by status class.",
    ),
    "opendrp_http_request_duration_seconds_count": (
        "counter",
        "Number of timed requests this replica has handled, by status class; "
        "the average is the sum family divided by this one.",
    ),
    "opendrp_alert_deliveries": (
        "gauge",
        "Alert delivery rows by delivery status.",
    ),
    "opendrp_alert_deliveries_oldest_pending_seconds": (
        "gauge",
        "Age of the oldest delivery still waiting to be sent; absent when none is.",
    ),
    "opendrp_alert_recipients_held": (
        "gauge",
        "Recipients held back after a delivery whose acceptance is unknown.",
    ),
    "opendrp_alert_recipient_hold_oldest_seconds": (
        "gauge",
        "Age of the oldest recipient hold; absent when no recipient is held.",
    ),
    "opendrp_connectors_enabled": (
        "gauge",
        "Connectors that may be given work.",
    ),
    "opendrp_connectors_disabled": (
        "gauge",
        "Connectors an operator has switched off.",
    ),
    "opendrp_connector_silence_seconds": (
        "gauge",
        "Seconds since a connector last reported in; -1 means it never has.",
    ),
    "opendrp_jobs": (
        "gauge",
        "Jobs by job status.",
    ),
    "opendrp_jobs_oldest_running_seconds": (
        "gauge",
        "Age of the oldest job still running; absent when nothing is running.",
    ),
    "opendrp_audit_chain_retained_rows": (
        "gauge",
        "Audit rows still retained locally.",
    ),
    "opendrp_audit_chain_committed_seq": (
        "gauge",
        "Highest audit position written to the chain.",
    ),
    "opendrp_audit_chain_retired_through_seq": (
        "gauge",
        "Highest audit position retired after a verified archive; a gap at or "
        "below this is housekeeping, a gap above it is a finding.",
    ),
    "opendrp_audit_chain_last_verified_seq": (
        "gauge",
        "Highest audit position the last verification check reached.",
    ),
    "opendrp_audit_chain_last_verified_timestamp_seconds": (
        "gauge",
        "Unix time of the last audit chain verification; 0 means never verified.",
    ),
    "opendrp_audit_chain_verification_failure_seq": (
        "gauge",
        "Audit position of the last failed verification; 0 means none recorded.",
    ),
    "opendrp_audit_persistence_degraded": (
        "gauge",
        "1 while this replica has seen an audit write fail; the replica drains "
        "mutating traffic until a later write clears it.",
    ),
}

#: Characters that may appear unescaped in a label *name*.
_LABEL_NAME = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]*\Z")

#: Methods the exposition distinguishes. An HTTP method is a token the *client*
#: chooses — a route that serves none of them answers 405, and that response
#: still passes through the middleware — so "record what arrived" would let an
#: unauthenticated caller invent a series per verb. This is the enumeration the
#: label is allowed to take, and anything outside it is one bucket.
KNOWN_METHODS = frozenset(
    {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
)
OTHER_METHOD = "OTHER"


@dataclass(frozen=True, slots=True)
class Sample:
    """One metric line, before it is rendered."""

    name: str
    value: float
    labels: tuple[tuple[str, str], ...] = ()


def _escape_label_value(value: str) -> str:
    """Escape a label value as the exposition format requires.

    Backslash, double quote and newline, in that order — and nothing else,
    including the label's own value: a connector named ``a\\b`` must read as
    itself on the dashboard, and a name with a newline in it must not be able to
    start a new metric line.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _render_labels(labels: Sequence[tuple[str, str]]) -> str:
    if not labels:
        return ""
    # Sorted, so the same series renders identically between two scrapes: an
    # unstable order is a diff in every scrape and a churn of time series in the
    # database that stores them.
    rendered = ",".join(
        f'{name}="{_escape_label_value(value)}"' for name, value in sorted(labels)
    )
    return "{" + rendered + "}"


def _format_value(value: float) -> str:
    """Prometheus expects a decimal; integers render without a trailing ``.0``."""
    if value != value:  # NaN
        return "NaN"
    if value in (float("inf"), float("-inf")):
        return "Inf" if value > 0 else "-Inf"
    if float(value).is_integer():
        return str(int(value))
    return repr(float(value))


def render(samples: Iterable[Sample]) -> str:
    """Render samples as one exposition document.

    Families are declared in :data:`FAMILIES`, which fixes their order: each
    family is emitted once, with its ``# HELP`` and ``# TYPE`` lines, followed by
    its own series. An undeclared name raises rather than being written out.
    """
    by_name: dict[str, list[Sample]] = {}
    for sample in samples:
        if sample.name not in FAMILIES:
            raise ValueError(
                f"{sample.name!r} is not declared in FAMILIES; declare it with its "
                "type and the sentence a dashboard shows, or do not expose it"
            )
        for label_name, _value in sample.labels:
            if not _LABEL_NAME.match(label_name):
                raise ValueError(f"{label_name!r} is not a usable label name")
        by_name.setdefault(sample.name, []).append(sample)

    lines: list[str] = []
    for name, (kind, help_text) in FAMILIES.items():
        series = by_name.get(name)
        if not series:
            continue
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {kind}")
        for sample in sorted(series, key=lambda item: sorted(item.labels)):
            lines.append(
                f"{name}{_render_labels(sample.labels)} {_format_value(sample.value)}"
            )
    return "\n".join(lines) + "\n"


class RequestMetrics:
    """Per-replica HTTP counters, fed by the ASGI middleware below.

    A single event loop handles every request, but a lock is still taken: the
    application also runs worker threads (the SMTP probes), and a counter that is
    only correct on one thread is a counter that is wrong once somebody adds a
    second. The section is short enough that the uncontended case is a no-op.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: dict[tuple[str, str], int] = {}
        self._duration_sum: dict[str, float] = {}
        self._duration_count: dict[str, int] = {}
        self._in_flight = 0
        self._started_at = datetime.now(timezone.utc)
        self._started_monotonic = time.monotonic()

    @staticmethod
    def status_class(status_code: int) -> str:
        """``2xx`` and friends: the bound on this label's cardinality."""
        hundreds = max(1, min(5, status_code // 100))
        return f"{hundreds}xx"

    @staticmethod
    def method_label(method: str) -> str:
        """The method as a label value, or :data:`OTHER_METHOD`.

        The upper-cased original when the platform serves that verb, so a
        dashboard reads ``GET`` rather than a bucket; every invented verb shares
        one series instead of adding one per request.
        """
        normalized = str(method or "").strip().upper()
        return normalized if normalized in KNOWN_METHODS else OTHER_METHOD

    def request_started(self) -> None:
        with self._lock:
            self._in_flight += 1

    def request_finished(self, method: str, status_code: int, seconds: float) -> None:
        status_class = self.status_class(status_code)
        method = self.method_label(method)
        with self._lock:
            self._in_flight = max(0, self._in_flight - 1)
            key = (method, status_class)
            self._requests[key] = self._requests.get(key, 0) + 1
            self._duration_sum[status_class] = (
                self._duration_sum.get(status_class, 0.0) + seconds
            )
            self._duration_count[status_class] = (
                self._duration_count.get(status_class, 0) + 1
            )

    def samples(self) -> list[Sample]:
        with self._lock:
            requests = dict(self._requests)
            duration_sum = dict(self._duration_sum)
            duration_count = dict(self._duration_count)
            in_flight = self._in_flight
            started_at = self._started_at
            uptime = time.monotonic() - self._started_monotonic

        samples = [
            Sample(
                "opendrp_build_info",
                1,
                (
                    ("environment", settings.APP_ENV),
                    ("version", __version__),
                ),
            ),
            Sample("opendrp_process_start_time_seconds", started_at.timestamp()),
            Sample("opendrp_process_uptime_seconds", uptime),
            Sample("opendrp_http_requests_in_flight", in_flight),
        ]
        for (method, status_class), count in requests.items():
            samples.append(
                Sample(
                    "opendrp_http_requests_total",
                    count,
                    (("method", method), ("status_class", status_class)),
                )
            )
        for status_class, total in duration_sum.items():
            samples.append(
                Sample(
                    "opendrp_http_request_duration_seconds_sum",
                    total,
                    (("status_class", status_class),),
                )
            )
        for status_class, count in duration_count.items():
            samples.append(
                Sample(
                    "opendrp_http_request_duration_seconds_count",
                    count,
                    (("status_class", status_class),),
                )
            )
        return samples


#: The process-wide counters. One instance because a scrape endpoint is a view of
#: *this* process, and tests reset it through :func:`reset_request_metrics`.
request_metrics = RequestMetrics()


def reset_request_metrics() -> None:
    """Start the counters over. Used by tests, whose process handles many apps."""
    global request_metrics
    request_metrics = RequestMetrics()


class MetricsMiddleware:
    """Pure ASGI middleware counting requests for :func:`render`.

    Pure ASGI rather than ``BaseHTTPMiddleware`` for the same reason
    ``RequestContextMiddleware`` is: the latter runs the application in a child
    task, and anything added around it later would measure a different task than
    the one handling the request. ``http.response.start`` is where the final
    status code is known, so the duration is recorded there — a request that
    raises still has a status by then, because the exception handlers in
    ``app.core.exceptions`` always produce a response.

    The counters are read from the module global on every request rather than
    captured in the instance: a middleware object is built once, when the app
    first handles a request, and a test that resets the counters would otherwise
    keep incrementing a discarded object.
    """

    def __init__(self, app) -> None:  # noqa: ANN001 - ASGI application
        self.app = app

    async def __call__(self, scope, receive, send) -> None:  # noqa: ANN001 - ASGI
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        started = time.perf_counter()
        status_code = 500
        request_metrics.request_started()

        async def send_counting(message) -> None:  # noqa: ANN001 - ASGI message
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = int(message["status"])
            await send(message)

        try:
            await self.app(scope, receive, send_counting)
        finally:
            request_metrics.request_finished(
                str(scope.get("method", "GET")),
                status_code,
                time.perf_counter() - started,
            )


def unix_seconds(value: datetime | None) -> float:
    """A stored timestamp as Unix seconds, with a naive value read as UTC.

    The same rule as :func:`age_seconds`, for the gauges that publish a moment
    rather than a difference. ``datetime.timestamp()`` on a naive value uses the
    *process's* local zone, which would move a dashboard's "when was this last
    verified" by the host's offset — the platform stores UTC and says so.
    """
    if value is None:
        return 0.0
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.timestamp()


def age_seconds(reference: datetime | None, now: datetime) -> float | None:
    """Seconds between a stored timestamp and now, or ``None`` when unset.

    Stored timestamps are timezone-aware in PostgreSQL and naive in SQLite, which
    is what the test suite runs on; an aware/naive subtraction raises, so a naive
    value is read as UTC rather than compared. That is the same rule the connector
    health endpoint applies, and it is stated here because getting it wrong is a
    TypeError at scrape time, not a wrong number.
    """
    if reference is None:
        return None
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)
    return max(0.0, (now - reference).total_seconds())


async def collect_database_samples(db: AsyncSession) -> list[Sample]:
    """Read the durable gauges.

    Every query is a grouped count or a single-row minimum over an indexed
    column, so a scrape costs a bounded handful of statements regardless of how
    much history the installation holds — the same reason the endpoint can be
    scraped every fifteen seconds.
    """
    from app.core.audit import audit_is_degraded
    from app.core.audit_chain import chain_state
    from app.models.alert_delivery import AlertDelivery, AlertRecipientState
    from app.models.audit import AuditLog
    from app.models.connector import Connector
    from app.models.job import Job

    now = datetime.now(timezone.utc)
    samples: list[Sample] = []

    for status, count in (
        await db.execute(
            select(AlertDelivery.status, func.count(AlertDelivery.id)).group_by(
                AlertDelivery.status
            )
        )
    ).all():
        samples.append(Sample("opendrp_alert_deliveries", count, (("status", str(status)),)))

    oldest_pending = (
        await db.execute(
            select(func.min(AlertDelivery.created_at)).where(
                AlertDelivery.status == "pending"
            )
        )
    ).scalar()
    pending_age = age_seconds(oldest_pending, now)
    if pending_age is not None:
        samples.append(Sample("opendrp_alert_deliveries_oldest_pending_seconds", pending_age))

    held = (
        await db.execute(
            select(
                func.count(AlertRecipientState.key),
                func.min(AlertRecipientState.next_send_at),
            ).where(AlertRecipientState.next_send_at.is_not(None))
        )
    ).one()
    samples.append(Sample("opendrp_alert_recipients_held", int(held[0] or 0)))
    hold_age = age_seconds(held[1], now)
    if hold_age is not None:
        samples.append(Sample("opendrp_alert_recipient_hold_oldest_seconds", hold_age))

    connector_rows = (
        await db.execute(select(Connector.name, Connector.status, Connector.last_seen_at))
    ).all()
    enabled = sum(1 for row in connector_rows if row[1] == "enabled")
    samples.append(Sample("opendrp_connectors_enabled", enabled))
    samples.append(Sample("opendrp_connectors_disabled", len(connector_rows) - enabled))
    for name, _status, last_seen in connector_rows:
        silence = age_seconds(last_seen, now)
        samples.append(
            Sample(
                "opendrp_connector_silence_seconds",
                -1 if silence is None else silence,
                (("connector", str(name)),),
            )
        )

    for status, count in (
        await db.execute(select(Job.status, func.count(Job.id)).group_by(Job.status))
    ).all():
        samples.append(Sample("opendrp_jobs", count, (("status", str(status)),)))

    oldest_running = (
        await db.execute(
            select(func.min(Job.created_at)).where(Job.status == "running")
        )
    ).scalar()
    running_age = age_seconds(oldest_running, now)
    if running_age is not None:
        samples.append(Sample("opendrp_jobs_oldest_running_seconds", running_age))

    state = await chain_state(db)
    retained_rows = int(
        (await db.execute(select(func.count(AuditLog.id)))).scalar() or 0
    )
    samples.append(Sample("opendrp_audit_chain_retained_rows", retained_rows))
    samples.append(Sample("opendrp_audit_chain_committed_seq", int(state.committed_seq or 0)))
    samples.append(
        Sample("opendrp_audit_chain_retired_through_seq", int(state.retired_through_seq or 0))
    )
    samples.append(
        Sample("opendrp_audit_chain_last_verified_seq", int(state.last_verified_seq or 0))
    )
    samples.append(
        Sample(
            "opendrp_audit_chain_last_verified_timestamp_seconds",
            unix_seconds(state.last_verified_at),
        )
    )
    samples.append(
        Sample(
            "opendrp_audit_chain_verification_failure_seq",
            int(state.last_failure_seq or 0),
        )
    )
    samples.append(Sample("opendrp_audit_persistence_degraded", 1 if audit_is_degraded() else 0))
    return samples
