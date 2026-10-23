"""The metrics endpoint: what it publishes, and to whom.

Two properties are worth a test each rather than a comment:

* **The exposition cannot carry the platform's data.** Labels come from the
  platform's own enumerations and from connector *names*. A value taken from a
  request — a target address, a finding title, a job's error text — must never
  reach a label: labels are what a time-series database indexes, so a value there
  is unbounded cardinality *and* a second copy of records the audit trail is
  supposed to hold. That is asserted for the rows a test can construct, and the
  label-name allowlist is asserted for the whole document.
* **A token is required, and an unconfigured installation publishes nothing.**
  `METRICS_TOKEN` empty means 404 (not 403), so the route — and with it the shape
  of the platform's internals — does not exist for somebody probing an
  installation that scrapes nothing.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from app import __version__
from app.core import metrics as metrics_module
from app.core.config import Settings, settings
from app.core.metrics import (
    FAMILIES,
    Sample,
    _escape_label_value,
    render,
    reset_request_metrics,
)
from app.models.alert_delivery import AlertDelivery, AlertDeliveryStatus
from app.models.audit import AuditLog

pytestmark = pytest.mark.usefixtures("without_testing_switch")

TOKEN = "metrics-scrape-token-for-tests-" + "0" * 12
HEADERS = {"X-Metrics-Token": TOKEN}

#: Every label name the exposition is allowed to carry. Adding one is a
#: deliberate edit to this line as well as to the collector, which is the point:
#: a label is a review decision, not a variable.
ALLOWED_LABELS = {"version", "environment", "method", "status_class", "status", "connector"}

_ENDPOINT = "/api/v1/metrics"


def _enable(monkeypatch, token: str = TOKEN) -> None:
    monkeypatch.setattr(settings, "METRICS_TOKEN", token)


def _label_names(body: str) -> set[str]:
    """Every label *name* in a rendered document, whatever its value."""
    names: set[str] = set()
    for line in body.splitlines():
        if line.startswith("#") or "{" not in line:
            continue
        inside = line.split("{", 1)[1].split("}", 1)[0]
        for pair in inside.split(","):
            if "=" in pair:
                names.add(pair.split("=", 1)[0].strip())
    return names


# ==============================================================================
# The exposition format
# ==============================================================================
def test_a_label_value_cannot_forge_a_metric_line():
    """A newline in a label must not be able to start a second sample."""
    escaped = _escape_label_value('two\nlines "quoted" \\slashed')

    assert "\n" not in escaped
    assert escaped == 'two\\nlines \\"quoted\\" \\\\slashed'
    line = render([Sample("opendrp_jobs", 1, (("status", 'x\nopendrp_fake 1'),))])
    assert line.count("\n") == 3  # HELP, TYPE, one sample
    assert "opendrp_fake" in line  # as an escaped *value*, not as its own metric


def test_an_undeclared_family_is_refused():
    """The family list is the review surface; a sample may not skip it."""
    with pytest.raises(ValueError, match="opendrp_not_declared"):
        render([Sample("opendrp_not_declared", 1)])


def test_every_family_renders_its_help_and_type_exactly_once():
    samples = [
        Sample("opendrp_jobs", 2, (("status", "error"),)),
        Sample("opendrp_jobs", 1, (("status", "running"),)),
        Sample("opendrp_build_info", 1, (("version", "0.0.0"),)),
    ]

    body = render(samples)

    assert body.count("# HELP opendrp_jobs ") == 1
    assert body.count("# TYPE opendrp_jobs gauge") == 1
    assert body.count("opendrp_jobs{") == 2
    # Declared order, not insertion order: two scrapes of the same state render
    # the same bytes, whatever order the collector produced them in.
    assert body.index("# HELP opendrp_build_info") < body.index("# HELP opendrp_jobs")
    assert body.index("opendrp_jobs{status=\"error\"}") < body.index(
        "opendrp_jobs{status=\"running\"}"
    )


def test_integers_render_without_a_decimal_point():
    body = render([Sample("opendrp_jobs", 3.0, (("status", "running"),))])

    assert "opendrp_jobs{status=\"running\"} 3\n" in body


def test_every_family_states_its_type_and_help():
    for name, (kind, help_text) in FAMILIES.items():
        assert kind in {"gauge", "counter"}, name
        # A sentence, not a label: this text is what a dashboard shows next to the
        # number, so a stub like "jobs" is a metric nobody can interpret.
        assert help_text.endswith("."), name
        assert len(help_text) > 15, name


# ==============================================================================
# Who may scrape
# ==============================================================================
@pytest.mark.asyncio
async def test_an_installation_without_a_token_does_not_publish_the_route(client):
    """404, not 403: an unconfigured installation has no such endpoint."""
    response = await client.get(_ENDPOINT)

    assert response.status_code == 404, response.text
    assert "opendrp_" not in response.text


@pytest.mark.asyncio
async def test_a_wrong_or_missing_token_is_refused(client, monkeypatch):
    _enable(monkeypatch)

    missing = await client.get(_ENDPOINT)
    wrong = await client.get(_ENDPOINT, headers={"X-Metrics-Token": "not-the-token"})

    assert missing.status_code == 401, missing.text
    assert wrong.status_code == 401, wrong.text
    assert "opendrp_" not in wrong.text


@pytest.mark.asyncio
async def test_the_token_enables_the_scrape_in_both_spellings(client, monkeypatch):
    _enable(monkeypatch)

    header = await client.get(_ENDPOINT, headers=HEADERS)
    bearer = await client.get(_ENDPOINT, headers={"Authorization": f"Bearer {TOKEN}"})

    for response in (header, bearer):
        assert response.status_code == 200, response.text
        assert response.headers["content-type"].startswith("text/plain")
        assert "version=0.0.4" in response.headers["content-type"]
        assert f'version="{__version__}"' in response.text
        assert f'environment="{settings.APP_ENV}"' in response.text


# ==============================================================================
# What it publishes
# ==============================================================================
@pytest.mark.asyncio
async def test_the_document_carries_only_declared_label_names(client, monkeypatch):
    _enable(monkeypatch)

    response = await client.get(_ENDPOINT, headers=HEADERS)

    assert response.status_code == 200
    assert _label_names(response.text) <= ALLOWED_LABELS
    for line in response.text.splitlines():
        if line and not line.startswith("#"):
            assert line.split(" ")[-1].replace(".", "").replace("-", "").isdigit()


@pytest.mark.asyncio
async def test_a_rows_own_data_never_reaches_the_exposition(
    client, db_session, monkeypatch
):
    """The canary: text that exists in the database and must not be published."""
    _enable(monkeypatch, "canary-free")
    canary = "canary-s3cret@example.com"
    db_session.add(
        AlertDelivery(
            threat_type="phishing",
            channel="email",
            target=canary,
            payload={"phishing_domain": "canary.example", "title": "CANARY-TITLE"},
            status=AlertDeliveryStatus.pending,
        )
    )
    await db_session.commit()

    response = await client.get(_ENDPOINT, headers={"X-Metrics-Token": "canary-free"})

    assert response.status_code == 200, response.text
    assert "canary" not in response.text.lower()
    # The count itself is still reported: the row is visible as a number, which is
    # the whole point of a metric.
    assert 'opendrp_alert_deliveries{status="pending"} 1' in response.text


@pytest.mark.asyncio
async def test_scraping_is_not_written_into_the_audit_chain(client, db_session, monkeypatch):
    """A scrape every 15 seconds must not become 5 700 audit rows a day.

    The refusal path is logged instead; a *successful* scrape is a read of
    aggregate counts, and the audit trail is for events.
    """
    _enable(monkeypatch)
    before = int((await db_session.execute(select(func.count(AuditLog.id)))).scalar() or 0)

    response = await client.get(_ENDPOINT, headers=HEADERS)
    assert response.status_code == 200
    await db_session.commit()

    after = int((await db_session.execute(select(func.count(AuditLog.id)))).scalar() or 0)
    assert after == before


@pytest.mark.asyncio
async def test_this_replicas_requests_are_counted(client, monkeypatch):
    """The per-replica half of the exposition, exercised through the middleware."""
    _enable(monkeypatch)
    reset_request_metrics()

    await client.get("/api/v1/health")
    response = await client.get(_ENDPOINT, headers=HEADERS)

    assert response.status_code == 200
    assert 'opendrp_http_requests_total{method="GET",status_class="2xx"}' in response.text
    # One: the scrape is itself a request this replica is handling at the moment
    # it renders. A zero here would mean the document came from counters nobody
    # is incrementing any more — the state this test exists to catch.
    assert "opendrp_http_requests_in_flight 1" in response.text
    # The counters belong to this process, and the middleware reads the same
    # object the test does — a reset rebinds the module global, which is why
    # nothing may capture it at import time.
    assert metrics_module.request_metrics.samples()


def test_resetting_the_counters_replaces_them_for_the_live_middleware():
    reset_request_metrics()
    metrics_module.request_metrics.request_finished("GET", 500, 0.5)
    assert any(
        sample.labels == (("method", "GET"), ("status_class", "5xx"))
        for sample in metrics_module.request_metrics.samples()
    )

    reset_request_metrics()

    assert not [
        sample for sample in metrics_module.request_metrics.samples() if sample.name.startswith("opendrp_http_requests_total")
    ]


@pytest.mark.asyncio
async def test_a_reset_reaches_the_scrape_endpoint(client, monkeypatch):
    """The endpoint must render the counters the middleware is incrementing.

    ``reset_request_metrics`` rebinds the module global, so anything holding the
    old object keeps reporting a previous life's numbers. The middleware reads
    the global on every request for exactly this reason; the scrape endpoint has
    to do the same, or a fresh process answers a scrape with the counters it had
    before the reset and never advances.
    """
    _enable(monkeypatch)
    reset_request_metrics()
    reset_request_metrics()

    await client.get("/api/v1/health")
    response = await client.get(_ENDPOINT, headers=HEADERS)

    assert response.status_code == 200
    series = [
        line
        for line in response.text.splitlines()
        if line.startswith("opendrp_http_requests_total{")
    ]
    assert series == ['opendrp_http_requests_total{method="GET",status_class="2xx"} 1']


@pytest.mark.asyncio
async def test_a_made_up_method_does_not_become_its_own_series(client, monkeypatch):
    """The method label is an enumeration, not whatever the caller sent.

    An HTTP method is a token the client chooses, and a route that does not
    accept it still passes through this middleware. Recording it verbatim lets an
    unauthenticated caller decide how many series the exposition carries — one
    per invented verb — which is the cardinality explosion the label rules exist
    to prevent, in the time-series database as well as in this process.
    """
    _enable(monkeypatch)
    reset_request_metrics()

    rejected = await client.request("PURGE", "/api/v1/health")
    assert rejected.status_code == 405
    response = await client.get(_ENDPOINT, headers=HEADERS)

    assert 'method="PURGE"' not in response.text
    assert (
        'opendrp_http_requests_total{method="OTHER",status_class="4xx"} 1'
        in response.text
    )


# ==============================================================================
# The setting
# ==============================================================================
class TestTheTokenIsHeldToTheSameBarAsEveryOtherSecret:
    def _production(self, **overrides) -> Settings:
        values = {
            "APP_ENV": "production",
            "OPENDRP_VERSION": "0.2.0",
            "JWT_SECRET_KEY": "j" * 48,
            "ENCRYPTION_KEY": "Zm9yLXRlc3Qtb25seS1mZXJuZXQta2V5LXZhbHVlLXBhZGRlZA==",
            "AUDIT_CHAIN_KEYS": "chain-key-for-tests-only-" * 3,
            "DATABASE_URL": "postgresql://opendrp:a-long-random-password@postgres:5432/opendrp",
            "REDIS_URL": "redis://:a-long-random-password@redis:6379/0",
            "TRUSTED_PROXY_IPS": "127.0.0.1,::1",
        }
        values.update(overrides)
        return Settings(**values)  # type: ignore[call-arg]

    def test_leaving_it_empty_is_allowed(self):
        """Metrics are opt-in: an installation that scrapes nothing is valid."""
        assert self._production(METRICS_TOKEN="").METRICS_TOKEN == ""

    def test_a_short_token_is_refused(self):
        with pytest.raises(ValueError, match="METRICS_TOKEN"):
            self._production(METRICS_TOKEN="too-short")

    def test_a_placeholder_token_is_refused(self):
        with pytest.raises(ValueError, match="METRICS_TOKEN"):
            self._production(METRICS_TOKEN="REPLACE_WITH_A_GENERATED_METRICS_TOKEN")

    def test_a_long_random_token_is_accepted(self):
        token = "s" * 43
        assert self._production(METRICS_TOKEN=token).METRICS_TOKEN == token
