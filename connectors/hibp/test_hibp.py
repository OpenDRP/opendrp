"""The HIBP worker's own guarantees: pace, budget, and no invented metadata.

These four properties are the ones a change here breaks silently, because each of
them is about something that did *not* happen:

* a request that was never sent (the pace held);
* a finding that was never stored (the metadata did not arrive, so no row was
  fabricated with no date);
* a scan that stopped early (the alias or the request budget is what decided that,
  and it says so);
* a second metadata call for an incident already asked about.

The first version of this worker slept a fixed 1.7 seconds between calls and, when
``/breach/{name}`` did not answer, invented ``{"Name": name, "Title": name}`` and
submitted it: a row with no date and no vendor, on a page an analyst reads as
evidence. Both are pinned below.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest


def _load_this_connectors_main():
    """Import the ``main.py`` beside this file, under a name of its own.

    ``from main import ...`` is what the connector suites do, and it is only
    unambiguous while one connector directory is on ``sys.path``. The CI step names
    the whole ``connectors`` tree, so every worker's ``main`` competes for that one
    module name: whichever directory pytest reached first wins, and the other
    suite fails to import its own worker. Loading the neighbour by path under the
    connector's own name removes the ordering question instead of pinning it.
    """
    spec = importlib.util.spec_from_file_location(
        "hibp_main", Path(__file__).with_name("main.py")
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_main = _load_this_connectors_main()
POLICY = _main.POLICY
FLAGS = _main.FLAGS
HibpConnector = _main.HibpConnector
RateLimiter = _main.RateLimiter
_retry_after_seconds = _main._retry_after_seconds

pytestmark = pytest.mark.asyncio

#: Captured once: ``monkeypatch.setattr("hibp_main.httpx.AsyncClient", ...)`` patches
#: the attribute on the ``httpx`` module itself, so a test that installs a transport
#: twice would otherwise wrap its own wrapper.
_REAL_ASYNC_CLIENT = httpx.AsyncClient

#: The name this file's worker is registered under, for patches that have to reach
#: it by string (``monkeypatch.setattr`` is given a target before the module is in
#: ``sys.modules`` under the plain name ``main``, which another connector's tests
#: claim on the same run).
_WORKER_MODULE = "hibp_main"


def make_connector(monkeypatch, **env) -> HibpConnector:
    values = {
        "CORE_URL": "http://core:8000",
        "CONNECTOR_TOKEN": "hibp-token",
        "CONNECTOR_NAME": "breaches-hibp",
        "CONNECTOR_TYPE": "breaches",
        "CONNECTOR_JOB_TYPE": "breaches.hibp",
        "HIBP_API_KEY": "hibp-test-key",
        **env,
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    return HibpConnector()


class ProviderReadiness:
    """The two account questions every scan asks before it scans (WI-14).

    They are provider calls rather than core calls, so they sit beside the handlers
    below — but a handler written to pin the *finding* conversation would have to
    answer two questions about the account it is not about. Answering them here
    keeps those handlers about findings, and what the worker makes of the answers is
    exactly what the WI-14 tests assert.
    """

    def __init__(self, subscription=None, subscribed_domains=None, status: int = 200) -> None:
        self.subscription = {} if subscription is None else subscription
        self.subscribed_domains = [] if subscribed_domains is None else subscribed_domains
        self.status = status
        self.paths: list[str] = []

    def route(self, request: httpx.Request) -> httpx.Response | None:
        path = request.url.path
        if path.endswith("/subscription/status"):
            self.paths.append(path)
            if self.status != 200:
                return httpx.Response(self.status, json={"detail": "refused"})
            return httpx.Response(200, json=self.subscription)
        if path.endswith("/subscribedDomains"):
            self.paths.append(path)
            if self.status != 200:
                return httpx.Response(self.status, json={"detail": "refused"})
            return httpx.Response(200, json=self.subscribed_domains)
        return None


class Catalogue:
    """The catalogue conversation every scan has (WI-13).

    ``/breaches`` answers with the corpus this harness holds — empty by default, which is
    a provider that answered and has nothing to report — and ``/latestBreach`` with the
    newest incident in it, or ``404`` when there is none. A test about the catalogue
    passes its own instance; a test about findings would otherwise have to answer two
    provider questions it is not about.

    The default matters for the *other* tests' meaning: an empty answer keeps their scan
    "success", while an unanswered sweep is a failed phase — so a harness that left this
    route to fall through to a ``404`` handler would quietly turn them all partial.
    """

    def __init__(
        self,
        incidents: list[dict] | None = None,
        *,
        status: int = 200,
        latest_status: int = 200,
    ) -> None:
        self.incidents = [] if incidents is None else incidents
        self.status = status
        self.latest_status = latest_status
        self.paths: list[str] = []

    def route(self, request: httpx.Request) -> httpx.Response | None:
        path = request.url.path
        if path.endswith("/latestBreach"):
            self.paths.append(path)
            if self.latest_status != 200:
                return httpx.Response(self.latest_status, json={"detail": "refused"})
            if not self.incidents:
                return httpx.Response(404, json={"detail": "no breaches"})
            return httpx.Response(200, json=self.newest())
        if path.endswith("/breaches"):
            self.paths.append(path)
            if self.status != 200:
                return httpx.Response(self.status, json={"detail": "refused"})
            return httpx.Response(200, json=self.incidents)
        return None

    def newest(self) -> dict:
        """The incident this provider would name as its latest."""
        return max(
            self.incidents,
            key=lambda item: str(item.get("ModifiedDate") or item.get("AddedDate") or ""),
        )

    @property
    def swept(self) -> bool:
        return any(path.endswith("/breaches") for path in self.paths)


class ControlPlane:
    """The core's own answers, recorded.

    A scan reads its provider key from the core and reports its readiness, so the
    handlers below — which pin the *provider* conversation — would otherwise see two
    calls they never asked for. The control plane is served here, its payloads are
    kept for assertions, and the provider paths stay the handler's business.
    """

    def __init__(
        self,
        credential=None,
        reservation_status: int = 200,
        reservation: dict | None = None,
        catalogue_status: int = 200,
        catalogue_diff: dict | None = None,
    ) -> None:
        self.credential = {"configured": False} if credential is None else credential
        self.reservation_status = reservation_status
        self.reservation = reservation if reservation is not None else {"reserved": True}
        self.catalogue_status = catalogue_status
        self.catalogue_diff = catalogue_diff
        self.credential_reads = 0
        self.reservations: list[dict] = []
        self.readiness: list[dict] = []
        #: Every catalogue batch the worker submitted, in order, as the core received it.
        self.catalogue_batches: list[list[dict]] = []
        self.catalogue_leases: list[str | None] = []

    def route(self, request: httpx.Request) -> httpx.Response | None:
        path = request.url.path
        if path == "/api/v1/connectors/me/credential":
            self.credential_reads += 1
            return httpx.Response(200, json=self.credential)
        if path == "/api/v1/connectors/me/readiness":
            self.readiness.append(json.loads(request.content))
            return httpx.Response(200, json={"status": "ok"})
        if path.startswith("/api/v1/connectors/me/catalogue/"):
            entries = json.loads(request.content)
            self.catalogue_batches.append(entries)
            self.catalogue_leases.append(request.headers.get("X-Connector-Lease"))
            if self.catalogue_status != 200:
                return httpx.Response(self.catalogue_status, json={"detail": "refused"})
            # The diff the core computes: a batch this harness has never seen before is
            # new, which is what a fresh catalogue looks like.
            return httpx.Response(
                200,
                json={
                    "received": len(entries),
                    "created": len(entries),
                    "updated": 0,
                    "unchanged": 0,
                    "new_incidents": 0,
                    "empty": not entries,
                    **(self.catalogue_diff or {}),
                },
            )
        if path == "/api/v1/connectors/me/quota/provider":
            self.reservations.append(
                {
                    "bucket": request.url.params.get("bucket"),
                    "lease": request.headers.get("X-Connector-Lease"),
                }
            )
            if self.reservation_status != 200:
                return httpx.Response(self.reservation_status, json={"detail": "refused"})
            return httpx.Response(200, json=self.reservation)
        return None


def install_transport(
    monkeypatch,
    handler,
    *,
    control: ControlPlane | None = None,
    readiness: ProviderReadiness | None = None,
    catalogue: Catalogue | None = None,
) -> ControlPlane:
    """Serve every HTTP call from ``handler``, and never sleep for real."""
    plane = control or ControlPlane()
    account = readiness or ProviderReadiness()
    corpus = catalogue or Catalogue()
    plane.provider_readiness = account
    plane.catalogue = corpus

    def routed(request: httpx.Request) -> httpx.Response:
        answer = corpus.route(request)
        if answer is None:
            answer = account.route(request)
        if answer is None:
            answer = plane.route(request)
        return answer if answer is not None else handler(request)

    monkeypatch.setattr(
        f"{_WORKER_MODULE}.httpx.AsyncClient",
        lambda **kwargs: _REAL_ASYNC_CLIENT(
            transport=httpx.MockTransport(routed), **kwargs
        ),
    )
    monkeypatch.setattr(f"{_WORKER_MODULE}.asyncio.sleep", AsyncMock())
    return plane


def hold_a_lease(connector: HibpConnector, job_id: str = "job-1") -> None:
    """The claim a worker holds while it scans: quota is reserved per job."""
    connector._active_job = (job_id, "l" * 32)
    connector._lease_deadline = None
    connector._lease_lost = False


def vocabulary_already_read(connector: HibpConnector) -> None:
    """Stand in for a worker whose first scan already read the source's vocabulary.

    That read is once per worker rather than once per scan (F-04), so a test about the
    *finding* conversation — how many requests a scan spends on addresses and incidents —
    sets it the way a running worker would have it, and the test about the read itself
    (``test_the_sources_own_labels_are_read_once_and_republished``) leaves it unset.
    """
    connector._data_class_labels = {}
    connector._data_class_labels_read = True


def breathing_room(connector: HibpConnector) -> None:
    """Patch one scan's request budget so a test is not the thing being bounded."""
    connector._budget_left = 1000
    connector._budget_started = 1000


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def virtual_limiter(requests_per_minute: int, burst: int = 1):
    clock = FakeClock()
    slept: list[float] = []

    async def sleeper(seconds: float) -> None:
        slept.append(seconds)
        clock.advance(seconds)

    return RateLimiter(requests_per_minute, burst, clock=clock, sleeper=sleeper), clock, slept


# ---------------------------------------------------------------------------
# Pacing
# ---------------------------------------------------------------------------


async def test_ten_rpm_never_exceeds_ten_requests_in_a_minute():
    """The allowance is the pace, not a fixed sleep somebody guessed."""
    limiter, clock, _ = virtual_limiter(10, 1)
    for _ in range(10):
        await limiter.acquire()
    #: Ten calls fit inside the minute the allowance describes...
    assert clock.now < 60.0, clock.now
    #: ...and the eleventh waits for the end of it.
    await limiter.acquire()
    assert clock.now == pytest.approx(60.0)


async def test_a_higher_allowance_is_faster_and_still_bounded():
    slow, slow_clock, _ = virtual_limiter(10, 1)
    fast, fast_clock, _ = virtual_limiter(60, 1)
    for limiter in (slow, fast):
        for _ in range(59):
            await limiter.acquire()
    assert slow_clock.now == pytest.approx(348.0)
    assert fast_clock.now == pytest.approx(58.0)


async def test_a_burst_spends_the_bucket_then_waits():
    limiter, clock, _ = virtual_limiter(60, 5)
    for _ in range(5):
        await limiter.acquire()
    assert clock.now == 0.0, "the burst was not available"
    await limiter.acquire()
    assert clock.now == pytest.approx(1.0)


async def test_retry_after_seconds_reads_only_deltas():
    assert _retry_after_seconds("30") == 30.0
    assert _retry_after_seconds(15) == 15.0
    # An HTTP-date is not a delta this worker will guess at, and a hostile value
    # is bounded rather than obeyed.
    assert _retry_after_seconds("Wed, 21 Oct 2026 07:28:00 GMT") == 0.0
    assert _retry_after_seconds("999999") == 3600.0
    assert _retry_after_seconds("-5") == 0.0
    assert _retry_after_seconds(None) == 0.0


async def test_a_429_pauses_the_next_call_by_the_providers_own_answer():
    limiter, clock, _ = virtual_limiter(600, 5)
    limiter.pause(30.0)
    await limiter.acquire()
    assert clock.now == pytest.approx(30.0), "the pause was not waited out"


async def test_the_worker_reads_retry_after_from_the_response(monkeypatch):
    connector = make_connector(monkeypatch)
    connector._limiter = virtual_limiter(10, 1)[0]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "30"})

    install_transport(monkeypatch, handler)
    async with httpx.AsyncClient() as client:
        assert await connector.search_email_breaches(client, "user@example.com") == []

    assert connector._provider_errors == ["http_429"]
    assert connector._limiter.paused_until == pytest.approx(30.0)


# ---------------------------------------------------------------------------
# Metadata: asked once, and never invented
# ---------------------------------------------------------------------------


async def test_one_incident_is_asked_about_once_per_scan(monkeypatch):
    connector = make_connector(monkeypatch)
    vocabulary_already_read(connector)
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)
        if request.url.path.endswith("/breacheddomain/example.com"):
            return httpx.Response(
                200, json={"alice": ["Adobe"], "bob": ["Adobe"], "carol": ["Gawker"]}
            )
        if request.url.path.endswith("/breach/Adobe"):
            return httpx.Response(
                200,
                json={
                    "Name": "Adobe",
                    "Title": "Adobe",
                    "Domain": "adobe.com",
                    "BreachDate": "2013-10-04",
                    "PwnCount": 152000000,
                    "DataClasses": ["Emails", "Passwords"],
                },
            )
        if request.url.path.endswith("/breach/Gawker"):
            return httpx.Response(
                200,
                json={
                    "Name": "Gawker",
                    "Title": "Gawker",
                    "Domain": "gawker.com",
                    "BreachDate": "2010-12-11",
                    "PwnCount": 1000,
                    "DataClasses": ["Emails"],
                },
            )
        raise AssertionError(f"unexpected path {request.url.path}")

    install_transport(monkeypatch, handler)
    connector.submit_findings = AsyncMock(side_effect=lambda job_id, batch: {"accepted": len(batch)})

    findings, summary = await connector.run_scan(
        {"job_id": "job-1", "params": {"emails": [], "domains": ["example.com"]}}
    )

    assert findings == []
    assert requests == [
        "/api/v3/breacheddomain/example.com",
        "/api/v3/breach/Adobe",
        "/api/v3/breach/Gawker",
    ], "an incident was asked about once per affected address"
    assert summary["domain_aliases_found"] == 3
    assert summary["new_breach_rows"] == 3
    assert summary["incomplete_aliases"] == 0
    assert summary["status"] == "success"


async def test_unavailable_metadata_reports_the_address_instead_of_inventing_a_row(monkeypatch):
    """F-02: the stub finding used to arrive with no date and no vendor."""
    connector = make_connector(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/breacheddomain/example.com"):
            return httpx.Response(
                200, json={"alice": ["Adobe"], "bob": ["Adobe"], "carol": ["Gawker"]}
            )
        if request.url.path.endswith("/breach/Gawker"):
            return httpx.Response(
                200,
                json={
                    "Name": "Gawker",
                    "Title": "Gawker",
                    "Domain": "gawker.com",
                    "BreachDate": "2010-12-11",
                    "PwnCount": 1000,
                    "DataClasses": ["Emails"],
                },
            )
        return httpx.Response(404)

    install_transport(monkeypatch, handler)
    submitted: list[dict] = []

    async def capture(job_id, batch):
        submitted.extend(batch)
        return {"accepted": len(batch)}

    connector.submit_findings = AsyncMock(side_effect=capture)

    findings, summary = await connector.run_scan(
        {"job_id": "job-1", "params": {"emails": [], "domains": ["example.com"]}}
    )

    assert findings == []
    assert summary["incomplete_aliases"] == 2, "both addresses over the missing incident"
    assert summary["incomplete_aliases_sample"]
    assert summary["status"] == "partial"
    # Nothing was submitted for the addresses whose metadata did not arrive, and
    # everything that was submitted carries a real date and a real vendor.
    assert [item["matched_email"] for item in submitted] == [
        "carol@example.com"
    ]
    for item in submitted:
        assert item["breach_name"] == "Gawker"
        assert item["breach_date"] == "2010-12-11"
        assert item["domain"] == "gawker.com"


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------


async def test_a_domain_scan_expands_only_the_aliases_it_is_allowed(monkeypatch):
    """F-08: a leaked address list is not an unbounded permission to spend."""
    connector = make_connector(monkeypatch)
    vocabulary_already_read(connector)
    aliases = {f"user{index:03d}": ["Adobe"] for index in range(500)}
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path.endswith("/breacheddomain/example.com"):
            return httpx.Response(200, json=aliases)
        return httpx.Response(
            200,
            json={
                "Name": "Adobe",
                "Title": "Adobe",
                "Domain": "adobe.com",
                "BreachDate": "2013-10-04",
                "PwnCount": 152000000,
                "DataClasses": ["Emails"],
            },
        )

    install_transport(monkeypatch, handler)
    connector.submit_findings = AsyncMock(side_effect=lambda job_id, batch: {"accepted": len(batch)})

    _, summary = await connector.run_scan(
        {
            "job_id": "job-1",
            "config": {"max_aliases_per_domain": 10},
            "params": {"emails": [], "domains": ["example.com"]},
        }
    )

    assert summary["domain_aliases_found"] == 10
    assert summary["aliases_over_limit"] == 490
    assert summary["new_breach_rows"] == 10
    # One domain call, one metadata call, one submit: the incident is asked about
    # once no matter how many addresses name it.
    assert len([path for path in calls if "/breach/" in path]) == 1
    assert len(calls) == 2


async def test_a_scan_stops_at_its_request_budget_and_says_so(monkeypatch):
    """The budget covers the whole scan, including what it asks about the account:
    a scan is not free because it found nothing (WI-03, WI-15)."""
    connector = make_connector(monkeypatch)
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path.endswith("/breacheddomain/example.com"):
            return httpx.Response(200, json={"alice": ["Adobe"]})
        if "/breachedaccount/" in request.url.path:
            return httpx.Response(200, json=[])
        return httpx.Response(
            200,
            json={
                "Name": "Adobe",
                "Title": "Adobe",
                "Domain": "adobe.com",
                "BreachDate": "2013-10-04",
                "PwnCount": 152000000,
                "DataClasses": ["Emails"],
            },
        )

    install_transport(monkeypatch, handler)
    connector.submit_findings = AsyncMock(side_effect=lambda job_id, batch: {"accepted": len(batch)})

    #: Five: the two account questions every scan asks before it scans, the source's
    #: data-class vocabulary, the catalogue sweep, and one address lookup. The domain
    #: phase never gets a request of its own.
    _, summary = await connector.run_scan(
        {
            "job_id": "job-1",
            "config": {"max_requests_per_scan": 5},
            "params": {"emails": ["user@example.com"], "domains": ["example.com"]},
        }
    )

    #: The finding phase spent its one remaining request, and the domain phase never
    #: reached the provider: the vocabulary read is the account-level request the comment
    #: above counts.
    finding_calls = [path for path in calls if "/breach" in path]
    assert finding_calls == ["/api/v3/breachedaccount/user@example.com"], calls
    assert any(path.endswith("/dataClasses/descriptions") for path in calls)
    assert summary["budget_exhausted"] is True
    assert summary["requests_spent"] == 5
    assert summary["request_budget"] == 5
    assert summary["skipped_reasons"].get("request_budget_exhausted")
    assert summary["status"] == "partial"
    # The email phase spent the one request left after the account questions; the
    # domain phase never reached the provider at all.
    assert summary["emails_scanned"] == 1
    assert summary["domains_scanned"] == 0


async def test_an_out_of_range_policy_refuses_the_scan(monkeypatch):
    """A pace nobody can honour is not silently replaced by the default."""
    connector = make_connector(monkeypatch)
    install_transport(monkeypatch, lambda request: httpx.Response(200, json={}))
    with pytest.raises(ValueError, match="invalid_scan_policy:requests_per_minute"):
        await connector.run_scan(
            {
                "job_id": "job-1",
                "config": {"requests_per_minute": 100000},
                "params": {"emails": [], "domains": []},
            }
        )


async def test_the_manifest_declares_the_policy_the_scan_enforces(monkeypatch):
    connector = make_connector(monkeypatch)
    schema = connector.manifest_payload()["config_schema"]
    # Numbers and switches both: the Settings page renders each declared field, and a
    # switch the manifest forgot would be a paid route nobody can turn on (WI-18).
    assert set(schema) == set(POLICY) | set(FLAGS)
    for key, (low, high, default) in POLICY.items():
        assert schema[key]["default"] == default
        assert schema[key]["type"] == "int"
        assert f"{low}..{high}" in schema[key]["description"]
    for key, default in FLAGS.items():
        assert schema[key] == {
            "type": "bool",
            "default": default,
            "description": "Switch; off unless the operator turns it on",
            "label": key.replace("_", " "),
        }


# ---------------------------------------------------------------------------
# The provider account (WI-04, F-15)
# ---------------------------------------------------------------------------

_ONE_INCIDENT = {
    "Name": "Adobe",
    "Title": "Adobe",
    "Domain": "adobe.com",
    "BreachDate": "2013-10-04",
    "PwnCount": 152000000,
    "DataClasses": ["Emails"],
}


def _one_email_scan(handler):
    """A scan of one address that answers with one incident."""

    def routed(request: httpx.Request) -> httpx.Response:
        if "/breachedaccount/" in request.url.path:
            return httpx.Response(200, json=[_ONE_INCIDENT])
        if "/breach/" in request.url.path:
            return httpx.Response(200, json=_ONE_INCIDENT)
        return handler(request)

    return routed


async def test_the_core_key_wins_and_the_environment_remains_the_fallback(monkeypatch):
    connector = make_connector(monkeypatch)
    install_transport(
        monkeypatch,
        lambda request: httpx.Response(404),
        control=ControlPlane(credential={"configured": True, "api_key": "core-key"}),
    )
    await connector.refresh_credential()
    assert connector.api_key == "core-key"
    assert connector._account_bound is True

    # No account key: the variable this worker has always used answers instead, so
    # binding an account is a choice rather than an upgrade requirement.
    env_connector = make_connector(monkeypatch, HIBP_API_KEY="env-key")
    install_transport(
        monkeypatch,
        lambda request: httpx.Response(404),
        control=ControlPlane(credential={"configured": False}),
    )
    await env_connector.refresh_credential()
    assert env_connector.api_key == "env-key"
    assert env_connector._account_bound is False


async def test_a_malformed_or_empty_answer_never_becomes_a_key(monkeypatch):
    for payload in ({"configured": True}, {"configured": True, "api_key": ""}, {}):
        connector = make_connector(monkeypatch, HIBP_API_KEY="env-key")
        install_transport(
            monkeypatch,
            lambda request: httpx.Response(404),
            control=ControlPlane(credential=payload),
        )
        await connector.refresh_credential()
        assert connector.api_key == "env-key", payload
        assert connector._account_bound is False


async def test_a_bound_account_pays_for_every_provider_call(monkeypatch):
    connector = make_connector(monkeypatch)
    hold_a_lease(connector)

    def handler(request: httpx.Request) -> httpx.Response:
        if "/breachedaccount/" in request.url.path:
            return httpx.Response(200, json=[_ONE_INCIDENT])
        if "/breacheddomain/" in request.url.path:
            return httpx.Response(200, json={"alice": ["Adobe"]})
        if "/breach/" in request.url.path:
            return httpx.Response(200, json=_ONE_INCIDENT)
        return httpx.Response(404)

    plane = install_transport(
        monkeypatch,
        handler,
        control=ControlPlane(credential={"configured": True, "api_key": "core-key"}),
    )
    connector.submit_findings = AsyncMock(side_effect=lambda job_id, batch: {"accepted": len(batch)})

    _, summary = await connector.run_scan(
        {
            "job_id": "job-1",
            "params": {"emails": ["user@example.com"], "domains": ["example.com"]},
        }
    )

    assert summary["new_breach_rows"] == 2
    # Eight provider calls — the two account questions, the source's data-class
    # vocabulary, the catalogue sweep, the address, its paste lookup, the domain, and the
    # one incident metadata lookup the domain expansion needed — each reserved against
    # the account, under the job's own lease. The vocabulary and the sweep are charged to
    # ``search``: they ask about the provider's corpus rather than about one identifier
    # (F-04, WI-13, WI-17).
    assert len(plane.reservations) == 8
    assert {reservation["bucket"] for reservation in plane.reservations} == {
        "lookup",
        "search",
    }
    assert all(reservation["lease"] == "l" * 32 for reservation in plane.reservations)


async def test_an_unbound_worker_reserves_nothing(monkeypatch):
    """An environment key is not a budget the platform can see; inventing one would
    refuse scans on an installation that never configured a source account."""
    connector = make_connector(monkeypatch)
    hold_a_lease(connector)
    plane = install_transport(
        monkeypatch, _one_email_scan(lambda request: httpx.Response(404))
    )
    connector.submit_findings = AsyncMock(side_effect=lambda job_id, batch: {"accepted": len(batch)})

    _, summary = await connector.run_scan(
        {"job_id": "job-1", "params": {"emails": ["user@example.com"], "domains": []}}
    )

    assert summary["new_breach_rows"] == 1
    assert plane.reservations == []


async def test_a_refused_reservation_stops_the_scan_and_names_the_reason(monkeypatch):
    """Exhausted, revoked or disabled: the account's answer ends the scan."""
    connector = make_connector(monkeypatch)
    hold_a_lease(connector)
    asked: list[str] = []
    plane = install_transport(
        monkeypatch,
        lambda request: asked.append(request.url.path) or httpx.Response(404),
        control=ControlPlane(
            credential={"configured": True, "api_key": "core-key"},
            reservation_status=403,
        ),
    )
    connector.submit_findings = AsyncMock(side_effect=lambda job_id, batch: {"accepted": len(batch)})

    _, summary = await connector.run_scan(
        {"job_id": "job-1", "params": {"emails": ["user@example.com"], "domains": []}}
    )

    assert asked == [], "a provider request was sent after the budget refused one"
    assert plane.reservations, "the account was never asked at all"
    # The two account questions, the data-class vocabulary, the catalogue sweep, the
    # address lookup and its paste lookup were each refused, and no provider request was
    # sent after the first refusal.
    assert summary["skipped_reasons"].get("provider_access_denied") == 6
    assert summary["catalogue"]["status"] == "failed"
    assert summary["budget_exhausted"] is True
    assert summary["new_breach_rows"] == 0
    assert summary["status"] == "partial"


async def test_the_readiness_row_says_whether_a_key_exists(monkeypatch):
    connector = make_connector(monkeypatch)
    hold_a_lease(connector)
    plane = install_transport(
        monkeypatch, _one_email_scan(lambda request: httpx.Response(404))
    )
    connector.submit_findings = AsyncMock(side_effect=lambda job_id, batch: {"accepted": len(batch)})

    await connector.run_scan(
        {"job_id": "job-1", "params": {"emails": ["user@example.com"], "domains": []}}
    )

    assert plane.readiness, "a scan reported no readiness at all"
    report = plane.readiness[-1]
    assert report["credentials_configured"] is True
    assert report["credential_state"] == "valid"
    # ``paste`` is unconditional (the route is on every paid plan); ``stealer_log`` is
    # absent because the operator has not turned that pass on (WI-17, WI-18).
    assert report["capabilities"] == ["email_account", "domain", "catalogue", "paste"]
    # The buckets are declared before they are used: the core refuses a reservation for
    # a bucket its record of this connector does not name.
    assert report["operations"] == ["lookup", "search"]


async def test_a_refused_key_is_reported_as_an_invalid_credential(monkeypatch):
    """F-04: a 401 is a statement about the key, not about the incident."""
    connector = make_connector(monkeypatch, HIBP_API_KEY="")
    hold_a_lease(connector)
    plane = install_transport(
        monkeypatch,
        lambda request: httpx.Response(401),
        control=ControlPlane(credential={"configured": True, "api_key": "revoked"}),
    )

    _, summary = await connector.run_scan(
        {"job_id": "job-1", "params": {"emails": ["user@example.com"], "domains": []}}
    )

    assert connector.credential_state == "invalid"
    assert connector.provider_error == "invalid_credentials"
    assert summary["provider_errors"] == ["http_401"]
    report = plane.readiness[-1]
    assert report["credential_state"] == "invalid"
    assert report["provider_error"] == "invalid_credentials"


# ---------------------------------------------------------------------------
# What the account can be asked (WI-14, WI-15)
# ---------------------------------------------------------------------------


def _domain_scan_handler(status: int):
    def handler(request: httpx.Request) -> httpx.Response:
        if "/breacheddomain/" in request.url.path:
            return httpx.Response(status, json={})
        return httpx.Response(404)

    return handler


async def _scan_domain(monkeypatch, *, readiness, status: int = 403):
    connector = make_connector(monkeypatch)
    hold_a_lease(connector)
    install_transport(monkeypatch, _domain_scan_handler(status), readiness=readiness)
    connector.submit_findings = AsyncMock(side_effect=lambda job_id, batch: {"accepted": len(batch)})
    _, summary = await connector.run_scan(
        {"job_id": "job-1", "params": {"emails": [], "domains": ["example.com"]}}
    )
    return summary


async def test_the_subscription_lowers_the_pace_and_never_raises_it(monkeypatch):
    """A subscription's number is a ceiling on the operator's, not a replacement."""
    connector = make_connector(monkeypatch)
    install_transport(
        monkeypatch,
        _one_email_scan(lambda request: httpx.Response(404)),
        readiness=ProviderReadiness(subscription={"SubscriptionName": "Pro", "Rpm": 4}),
    )
    connector.submit_findings = AsyncMock(side_effect=lambda job_id, batch: {"accepted": len(batch)})

    _, summary = await connector.run_scan(
        {
            "job_id": "job-1",
            "config": {"requests_per_minute": 60},
            "params": {"emails": ["user@example.com"], "domains": []},
        }
    )

    assert summary["provider_readiness"]["subscription"] == "Pro"
    assert summary["pacing"] == {
        "configured_requests_per_minute": 60,
        "applied_requests_per_minute": 4,
        "adjusted": True,
        "stealer_logs_domain_requests_per_minute": POLICY[
            "stealer_logs_domain_requests_per_minute"
        ][2],
    }
    assert connector._limiter.interval == pytest.approx(15.0)


async def test_a_stricter_operator_value_survives_a_generous_subscription(monkeypatch):
    """The minimum of the two, so a paid tier never speeds past the operator's ask."""
    connector = make_connector(monkeypatch)
    install_transport(
        monkeypatch,
        _one_email_scan(lambda request: httpx.Response(404)),
        readiness=ProviderReadiness(subscription={"Rpm": 600}),
    )
    connector.submit_findings = AsyncMock(side_effect=lambda job_id, batch: {"accepted": len(batch)})

    _, summary = await connector.run_scan(
        {
            "job_id": "job-1",
            "config": {"requests_per_minute": 2},
            "params": {"emails": ["user@example.com"], "domains": []},
        }
    )

    assert summary["pacing"]["applied_requests_per_minute"] == 2
    assert summary["pacing"]["adjusted"] is False


async def test_an_absent_or_unreadable_status_leaves_the_pace_alone(monkeypatch):
    """No `Rpm` in the answer (or no answer) is not a pace of zero, and not a guess."""
    for readiness in (
        ProviderReadiness(subscription={"SubscriptionName": "Free"}),
        ProviderReadiness(status=500),
    ):
        connector = make_connector(monkeypatch)
        install_transport(
            monkeypatch,
            _one_email_scan(lambda request: httpx.Response(404)),
            readiness=readiness,
        )
        connector.submit_findings = AsyncMock(
            side_effect=lambda job_id, batch: {"accepted": len(batch)}
        )
        _, summary = await connector.run_scan(
            {
                "job_id": "job-1",
                "config": {"requests_per_minute": 10},
                "params": {"emails": ["user@example.com"], "domains": []},
            }
        )
        assert summary["pacing"]["applied_requests_per_minute"] == 10
        assert summary["pacing"]["adjusted"] is False


async def test_a_domain_the_account_has_not_verified_is_reported_as_unscanned(monkeypatch):
    """F-04: a refusal is not a clean result, and the reason is named."""
    summary = await _scan_domain(
        monkeypatch, readiness=ProviderReadiness(subscribed_domains=["other.example"])
    )

    assert summary["domains_unscanned"] == [
        {"domain": "example.com", "reason": "domain_not_verified"}
    ]
    assert summary["skipped_reasons"]["domain_not_verified"] == 1
    assert summary["domains_scanned"] == 1
    assert summary["new_breach_rows"] == 0
    assert summary["status"] == "partial"


async def test_a_verified_domain_the_plan_refuses_says_so(monkeypatch):
    """403 has two meanings and the two need different operators."""
    summary = await _scan_domain(
        monkeypatch, readiness=ProviderReadiness(subscribed_domains=["example.com"])
    )

    assert summary["domains_unscanned"] == [
        {"domain": "example.com", "reason": "domain_outside_allowance"}
    ]


async def test_an_unreadable_domain_list_leaves_the_refusal_unnamed(monkeypatch):
    """Not verified and outside the plan cannot be told apart without that list."""
    summary = await _scan_domain(monkeypatch, readiness=ProviderReadiness(status=403))

    assert summary["domains_unscanned"] == [
        {"domain": "example.com", "reason": "domain_access_denied"}
    ]


async def test_an_empty_domain_list_is_a_known_answer_not_an_unknown_one(monkeypatch):
    """An account with no verified domains has verified nothing — including ours."""
    summary = await _scan_domain(monkeypatch, readiness=ProviderReadiness(subscribed_domains=[]))

    assert summary["provider_readiness"]["subscribed_domains"] == 0
    assert summary["domains_unscanned"] == [
        {"domain": "example.com", "reason": "domain_not_verified"}
    ]


async def test_the_summary_carries_the_accounts_remaining_budget(monkeypatch):
    """WI-15: what the scan cost, from the accounting of the account that paid."""
    connector = make_connector(monkeypatch)
    hold_a_lease(connector)
    install_transport(
        monkeypatch,
        _one_email_scan(lambda request: httpx.Response(404)),
        control=ControlPlane(
            credential={"configured": True, "api_key": "core-key"},
            reservation={"reserved": True, "request_budget": 100, "remaining_today": 96},
        ),
    )
    connector.submit_findings = AsyncMock(side_effect=lambda job_id, batch: {"accepted": len(batch)})

    _, summary = await connector.run_scan(
        {"job_id": "job-1", "params": {"emails": ["user@example.com"], "domains": []}}
    )

    assert summary["account_request_budget"] == 100
    assert summary["account_remaining_today"] == 96


async def test_an_environment_key_reports_no_account_budget(monkeypatch):
    """There is no budget to report when nobody can see the key (F-15)."""
    connector = make_connector(monkeypatch)
    install_transport(
        monkeypatch, _one_email_scan(lambda request: httpx.Response(404))
    )
    connector.submit_findings = AsyncMock(side_effect=lambda job_id, batch: {"accepted": len(batch)})

    _, summary = await connector.run_scan(
        {"job_id": "job-1", "params": {"emails": ["user@example.com"], "domains": []}}
    )

    assert "account_request_budget" not in summary
    assert "account_remaining_today" not in summary


async def test_a_scan_without_a_key_asks_nothing_and_says_why(monkeypatch):
    connector = make_connector(monkeypatch, HIBP_API_KEY="")
    calls: list[str] = []
    install_transport(monkeypatch, lambda request: calls.append(request.url.path) or httpx.Response(200, json={}))

    findings, summary = await connector.run_scan({"job_id": "job-1", "params": {}})

    assert findings == []
    assert calls == []
    assert summary["skipped"] == "HIBP_API_KEY not configured"
    assert summary["status"] == "skipped"


# ---------------------------------------------------------------------------
# The incident catalogue (WI-13)
# ---------------------------------------------------------------------------

#: Two incidents as the provider's own catalogue lists them, with the timestamps the
#: platform's diff is measured against.
_CATALOGUE = [
    {
        "Name": "Adobe",
        "Title": "Adobe",
        "Domain": "adobe.com",
        "BreachDate": "2013-10-04",
        "AddedDate": "2013-10-04T00:00:00Z",
        "ModifiedDate": "2013-10-05T00:00:00Z",
        "PwnCount": 152000000,
        "DataClasses": ["Emails", "Passwords"],
        "IsVerified": True,
        "IsSpamList": False,
    },
    {
        "Name": "Dropbox",
        "Title": "Dropbox",
        "Domain": "dropbox.com",
        "BreachDate": "2012-07-01",
        "AddedDate": "2016-08-31T00:00:00Z",
        "ModifiedDate": "2016-09-01T00:00:00Z",
        "PwnCount": 68648009,
        "DataClasses": ["Emails"],
        "IsVerified": True,
        "IsSpamList": False,
        "Password": "hunter2",
    },
]


def _catalogue_scan(monkeypatch, **kwargs):
    """A scan of one address, with the catalogue conversation set up around it."""
    connector = make_connector(monkeypatch)
    hold_a_lease(connector)
    plane = install_transport(
        monkeypatch,
        _one_email_scan(lambda request: httpx.Response(404)),
        **kwargs,
    )
    connector.submit_findings = AsyncMock(
        side_effect=lambda job_id, batch: {"accepted": len(batch)}
    )
    return connector, plane


async def test_the_catalogue_is_stored_before_any_address_is_scanned(monkeypatch):
    """The incident no address of ours is in yet is exactly what a scan cannot find."""
    connector, plane = _catalogue_scan(
        monkeypatch, catalogue=Catalogue(list(_CATALOGUE))
    )

    _, summary = await connector.run_scan(
        {"job_id": "job-1", "params": {"emails": ["user@example.com"], "domains": []}}
    )

    assert plane.catalogue.swept, "the catalogue was never read before the scan"
    assert len(plane.catalogue_batches) == 1
    assert [entry["breach_name"] for entry in plane.catalogue_batches[0]] == [
        "Adobe",
        "Dropbox",
    ]
    # The batch travels with the claim's lease, like a findings batch, and the phase
    # reports what it stored.
    assert plane.catalogue_leases == ["l" * 32]
    assert summary["catalogue"]["status"] == "synced"
    assert summary["catalogue"]["swept"] is True
    assert summary["catalogue"]["created"] == 2
    assert summary["catalogue"]["new_incidents"] == 0
    assert summary["new_breach_rows"] == 1


async def test_a_catalogue_entry_carries_no_secret_sample(monkeypatch):
    """A catalogue describes incidents; the exposed password belongs to a finding."""
    _catalogue_scan(monkeypatch, catalogue=Catalogue(list(_CATALOGUE)))
    entry = _main._catalogue_entry(_CATALOGUE[1])

    assert entry is not None
    assert entry["breach_name"] == "Dropbox"
    assert entry["added_date"] == "2016-08-31T00:00:00+00:00"
    assert entry["data_classes"] == ["Emails"]
    assert entry["attributes"]["is_verified"] is True
    #: The neutral names the core's noise policy reads, not the provider's spellings.
    assert "is_spam_list" in entry["attributes"]
    assert "IsVerified" not in entry["attributes"]
    assert not any("password" in key for key in entry["attributes"])
    assert "hunter2" not in json.dumps(entry)


async def test_a_record_without_a_name_is_not_an_incident(monkeypatch):
    assert _main._catalogue_entry({"Title": "nameless"}) is None
    assert _main._catalogue_entry("not a record") is None


async def test_a_checkpoint_with_nothing_newer_skips_the_sweep(monkeypatch):
    """Between sweeps the cheap question is one call, not the whole corpus."""
    connector, plane = _catalogue_scan(
        monkeypatch, catalogue=Catalogue(list(_CATALOGUE))
    )

    _, summary = await connector.run_scan(
        {
            "job_id": "job-1",
            "params": {
                "emails": ["user@example.com"],
                "domains": [],
                "catalogue": {"last_synced_at": "2026-10-16T00:00:00+00:00"},
            },
        }
    )

    assert plane.catalogue.paths == ["/api/v3/latestBreach"]
    assert plane.catalogue_batches == []
    assert summary["catalogue"]["status"] == "up_to_date"
    assert summary["catalogue"]["swept"] is False
    assert summary["catalogue"]["checkpoint"] == "2026-10-16T00:00:00+00:00"


async def test_a_newer_incident_since_the_checkpoint_triggers_the_sweep(monkeypatch):
    connector, plane = _catalogue_scan(
        monkeypatch, catalogue=Catalogue(list(_CATALOGUE))
    )

    _, summary = await connector.run_scan(
        {
            "job_id": "job-1",
            "params": {
                "emails": [],
                "domains": [],
                "catalogue": {"last_synced_at": "2016-08-01T00:00:00+00:00"},
            },
        }
    )

    assert plane.catalogue.swept
    assert summary["catalogue"]["status"] == "synced"
    assert summary["catalogue"]["entries_read"] == 2


async def test_an_incident_corrected_since_the_checkpoint_triggers_the_sweep(monkeypatch):
    """A corrected incident is newer than its own AddedDate, and is re-read."""
    corrected = [
        {
            "Name": "Adobe",
            "AddedDate": "2013-10-04T00:00:00Z",
            "ModifiedDate": "2026-10-17T00:00:00Z",
        }
    ]
    connector, plane = _catalogue_scan(
        monkeypatch,
        catalogue=Catalogue(corrected),
        #: What the core answers for a batch it already holds: nothing new, one correction.
        control=ControlPlane(catalogue_diff={"created": 0, "updated": 1}),
    )

    _, summary = await connector.run_scan(
        {
            "job_id": "job-1",
            "params": {
                "emails": [],
                "domains": [],
                "catalogue": {"last_synced_at": "2026-10-16T00:00:00+00:00"},
            },
        }
    )

    assert plane.catalogue.swept
    assert summary["catalogue"]["updated"] == 1


async def test_an_unanswerable_checkpoint_asks_for_the_sweep(monkeypatch):
    """\"I could not ask\" is not \"nothing changed\", and the corpus is re-read."""
    connector, plane = _catalogue_scan(
        monkeypatch, catalogue=Catalogue(list(_CATALOGUE), latest_status=500)
    )

    _, summary = await connector.run_scan(
        {
            "job_id": "job-1",
            "params": {
                "emails": [],
                "domains": [],
                "catalogue": {"last_synced_at": "2026-10-16T00:00:00+00:00"},
            },
        }
    )

    assert plane.catalogue.paths[0].endswith("/latestBreach")
    assert plane.catalogue.swept
    assert summary["catalogue"]["latest_unavailable"] is True


async def test_an_empty_provider_catalogue_is_reported_as_empty(monkeypatch):
    """A catalogue with nothing in it is not a domain with nothing in it."""
    connector, plane = _catalogue_scan(
        monkeypatch, catalogue=Catalogue([], latest_status=404)
    )

    _, summary = await connector.run_scan(
        {
            "job_id": "job-1",
            "params": {
                "emails": [],
                "domains": [],
                "catalogue": {"last_synced_at": "2026-10-16T00:00:00+00:00"},
            },
        }
    )

    #: The provider named no latest incident at all, so nothing can be newer than the
    #: checkpoint: no sweep, and the summary says which answer it was.
    assert plane.catalogue.paths == ["/api/v3/latestBreach"]
    assert summary["catalogue"]["status"] == "up_to_date"
    assert summary["catalogue"]["latest_empty"] is True


async def test_a_first_sweep_of_an_empty_catalogue_stores_nothing_and_says_so(monkeypatch):
    connector, plane = _catalogue_scan(monkeypatch, catalogue=Catalogue([]))

    _, summary = await connector.run_scan(
        {"job_id": "job-1", "params": {"emails": [], "domains": []}}
    )

    assert plane.catalogue.swept
    assert plane.catalogue_batches == []
    assert summary["catalogue"]["status"] == "synced"
    assert summary["catalogue"]["empty"] is True
    assert summary["catalogue"]["entries_read"] == 0


async def test_an_unanswered_sweep_is_a_failed_phase_not_an_empty_catalogue(monkeypatch):
    """A refusal in the middle of a scan is not a catalogue the platform just read."""
    connector, plane = _catalogue_scan(
        monkeypatch, catalogue=Catalogue(list(_CATALOGUE), status=403)
    )

    _, summary = await connector.run_scan(
        {"job_id": "job-1", "params": {"emails": [], "domains": []}}
    )

    assert summary["catalogue"]["status"] == "failed"
    assert "empty" not in summary["catalogue"]
    assert plane.catalogue_batches == []
    assert summary["status"] == "partial"


async def test_the_sweep_is_bounded_and_says_so(monkeypatch):
    """The bound is what keeps a first sync a fixed cost, and it is reported."""
    connector, plane = _catalogue_scan(
        monkeypatch, catalogue=Catalogue(list(_CATALOGUE))
    )

    _, summary = await connector.run_scan(
        {
            "job_id": "job-1",
            "config": {"max_catalogue_entries": 1},
            "params": {"emails": [], "domains": []},
        }
    )

    assert len(plane.catalogue_batches[0]) == 1
    assert summary["catalogue"]["entries_read"] == 1
    assert summary["catalogue"]["truncated"] is True
    assert summary["skipped_reasons"]["catalogue_truncated"] == 1


async def test_the_catalogue_is_submitted_in_batches(monkeypatch):
    """A corpus is a batch of batches: one request per bound, and no silent truncation."""
    corpus = [
        {"Name": f"Incident-{index}", "Domain": "vendor.example", "PwnCount": index}
        for index in range(_main.CATALOGUE_BATCH + 1)
    ]
    connector, plane = _catalogue_scan(monkeypatch, catalogue=Catalogue(corpus))

    _, summary = await connector.run_scan(
        {"job_id": "job-1", "params": {"emails": [], "domains": []}}
    )

    assert [len(batch) for batch in plane.catalogue_batches] == [
        _main.CATALOGUE_BATCH,
        1,
    ]
    assert summary["catalogue"]["entries_stored"] == _main.CATALOGUE_BATCH + 1
    assert summary["catalogue"]["truncated"] is False


async def test_a_core_that_refuses_the_catalogue_does_not_cost_the_scan_its_findings(monkeypatch):
    """The findings of a scan are the reason it exists; the catalogue is a phase."""
    connector, plane = _catalogue_scan(
        monkeypatch,
        catalogue=Catalogue(list(_CATALOGUE)),
        control=ControlPlane(catalogue_status=422),
    )

    _, summary = await connector.run_scan(
        {"job_id": "job-1", "params": {"emails": ["user@example.com"], "domains": []}}
    )

    assert summary["catalogue"]["status"] == "failed"
    assert summary["catalogue"]["error"] == "core_rejected_catalogue"
    assert summary["new_breach_rows"] == 1


async def test_the_sources_own_labels_are_read_once_and_republished(monkeypatch):
    """F-04: an analyst reads the provider's word for a class, not a copy of the stored one."""
    connector = make_connector(monkeypatch)
    hold_a_lease(connector)
    reads: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/dataClasses/descriptions"):
            reads.append(request.url.path)
            return httpx.Response(
                200,
                json={
                    "Passwords": "Account passwords",
                    "Email addresses": "Email addresses",
                    "Debt records": 3,  # not a label: dropped rather than published
                    "": "nameless",
                },
            )
        if "/breachedaccount/" in request.url.path:
            return httpx.Response(200, json=[])
        return httpx.Response(404)

    plane = install_transport(monkeypatch, handler)
    connector.submit_findings = AsyncMock(side_effect=lambda job_id, batch: {"accepted": len(batch)})

    _, first = await connector.run_scan(
        {"job_id": "job-1", "params": {"emails": ["user@example.com"], "domains": []}}
    )
    await connector.run_scan(
        {"job_id": "job-1", "params": {"emails": ["other@example.com"], "domains": []}}
    )

    assert len(reads) == 1, "the vocabulary was re-read by the second scan"
    assert first["data_class_labels"] == {"read": True, "labels": 2}
    assert connector._data_class_labels == {
        "Passwords": "Account passwords",
        "Email addresses": "Email addresses",
    }
    # The readiness row carries them, so the page can render a stored class in the
    # source's own words without talking to the provider at all.
    assert plane.readiness[-1]["data_class_labels"] == connector._data_class_labels


async def test_a_source_without_the_vocabulary_route_says_so_without_failing(monkeypatch):
    """An optional read is not a scan that went wrong: 404 is "no labels", not partial."""
    connector, plane = _catalogue_scan(monkeypatch)

    _, summary = await connector.run_scan(
        {"job_id": "job-1", "params": {"emails": ["user@example.com"], "domains": []}}
    )

    assert summary["data_class_labels"] == {"read": False, "labels": 0}
    assert plane.readiness[-1]["data_class_labels"] == {}
    assert summary["status"] == "success"


async def test_the_catalogue_changed_test_reads_both_provider_timestamps(monkeypatch):
    """Unit-level, because the answer decides whether the corpus is re-read at all."""
    changed = _main._catalogue_changed_since

    assert changed({"AddedDate": "2026-10-17T00:00:00Z"}, "2026-10-16T00:00:00+00:00") is True
    assert changed({"AddedDate": "2013-10-04T00:00:00Z"}, "2026-10-16T00:00:00+00:00") is False
    #: A correction after the checkpoint counts even when the incident is old.
    assert (
        changed(
            {"AddedDate": "2013-10-04T00:00:00Z", "ModifiedDate": "2026-10-17T00:00:00Z"},
            "2026-10-16T00:00:00+00:00",
        )
        is True
    )
    #: A record with no timestamps, or a checkpoint we cannot read, is re-read rather
    #: than dropped: neither an absent field nor a malformed one means "unchanged".
    assert changed({}, "2026-10-16T00:00:00+00:00") is True
    assert changed({"AddedDate": "2013-10-04T00:00:00Z"}, "not-a-timestamp") is True


# ---------------------------------------------------------------------------
# Pastes and stealer logs (WI-17, WI-18)
# ---------------------------------------------------------------------------

_PASTES = [
    {
        "Source": "Pastebin",
        "Id": "8Q0BvKD8",
        "Title": "syslog",
        "Date": "2014-03-04T19:14:54Z",
        "EmailCount": 139,
    },
    #: No id: two pastes of one address would collapse into one row, so it is counted
    #: and skipped rather than stored under a name that cannot tell them apart.
    {"Source": "Pastebin", "Title": "untitled", "EmailCount": 12},
]


def _exposure_scan(monkeypatch, handler, *, config=None, params=None, readiness=None):
    """A scan whose findings are captured, with the two account questions answered."""
    connector = make_connector(monkeypatch)
    install_transport(
        monkeypatch,
        handler,
        readiness=readiness or ProviderReadiness(),
    )
    submitted: list[dict] = []

    async def capture(job_id, batch):
        submitted.extend(batch)
        return {"accepted": len(batch)}

    connector.submit_findings = AsyncMock(side_effect=capture)
    job = {
        "job_id": "job-1",
        "config": config or {},
        "params": params or {"emails": ["user@example.com"], "domains": []},
    }
    return connector, submitted, job


def _stealer_handler(seen: list[str], *, sites=("netflix.com", "spotify.com")):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if "/stealerLogsByEmail/" in request.url.path:
            return httpx.Response(200, json=list(sites))
        if "/stealerLogsByEmailDomain/" in request.url.path:
            return httpx.Response(200, json={"alice": list(sites)})
        if "/breacheddomain/" in request.url.path:
            return httpx.Response(200, json={})
        if "/breachedaccount/" in request.url.path:
            return httpx.Response(404)
        return httpx.Response(404)

    return handler


async def test_a_paste_becomes_its_own_row_with_the_pastes_own_date(monkeypatch):
    """WI-17: a paste is exposure of the same address in a different document."""

    def handler(request: httpx.Request) -> httpx.Response:
        if "/pasteAccount/" in request.url.path:
            return httpx.Response(200, json=_PASTES)
        return httpx.Response(404)

    connector, submitted, job = _exposure_scan(monkeypatch, handler)
    _, summary = await connector.run_scan(job)

    assert len(submitted) == 1, "the entry without an id must not become a row"
    row = submitted[0]
    assert row["exposure_kind"] == "paste"
    assert row["breach_name"] == "paste:8Q0BvKD8"
    assert row["matched_email"] == "user@example.com"
    assert row["breach_date"] == "2014-03-04"
    assert row["attributes"]["paste_id"] == "8Q0BvKD8"
    assert row["attributes"]["paste_source"] == "Pastebin"
    assert row["attributes"]["paste_email_count"] == 139
    assert summary["pastes"] == {
        "status": "ran",
        "reason": None,
        "emails_looked_up": 1,
        "rows": 1,
        "unavailable": 0,
    }
    assert summary["skipped_reasons"]["paste_without_id"] == 1


async def test_a_refused_paste_lookup_is_not_an_address_with_no_pastes(monkeypatch):
    """F-04 in a new place: a question nobody answered is not a clean answer."""

    def handler(request: httpx.Request) -> httpx.Response:
        if "/pasteAccount/" in request.url.path:
            return httpx.Response(403, json={"detail": "refused"})
        return httpx.Response(404)

    connector, submitted, job = _exposure_scan(monkeypatch, handler)
    _, summary = await connector.run_scan(job)

    assert submitted == []
    assert summary["pastes"]["emails_looked_up"] == 0
    assert summary["pastes"]["unavailable"] == 1
    assert summary["status"] == "partial"


async def test_a_paste_without_a_date_says_the_metadata_did_not_arrive(monkeypatch):
    """The worker never invents a date; it declares the gap the core already handles."""

    def handler(request: httpx.Request) -> httpx.Response:
        if "/pasteAccount/" in request.url.path:
            return httpx.Response(200, json=[{"Source": "JustPaste", "Id": "abc"}])
        return httpx.Response(404)

    connector, submitted, job = _exposure_scan(monkeypatch, handler)
    await connector.run_scan(job)

    assert submitted[0]["attributes"]["metadata_incomplete"] is True
    assert "breach_date" not in submitted[0] or submitted[0]["breach_date"] is None


async def test_stealer_logs_are_not_asked_for_by_default(monkeypatch):
    """WI-18: the paid routes cost a separate allowance, so the switch is off."""
    seen: list[str] = []
    connector, submitted, job = _exposure_scan(monkeypatch, _stealer_handler(seen))
    _, summary = await connector.run_scan(job)

    assert [path for path in seen if "stealerLogs" in path] == []
    assert summary["stealer_logs"]["status"] == "skipped"
    assert summary["stealer_logs"]["reason"] == "disabled"
    assert summary["status"] == "success", "a setting is not a failed scan"


async def test_stealer_logs_need_the_plans_permission(monkeypatch):
    """Enabled by the operator, absent from the subscription: still no request."""
    seen: list[str] = []
    connector, submitted, job = _exposure_scan(
        monkeypatch,
        _stealer_handler(seen),
        config={"stealer_logs_enabled": True},
        readiness=ProviderReadiness(subscription={"IncludesStealerLogs": False}),
    )
    _, summary = await connector.run_scan(job)

    assert [path for path in seen if "stealerLogs" in path] == []
    assert summary["stealer_logs"]["reason"] == "not_in_subscription"
    assert summary["skipped_reasons"]["stealer_logs_not_in_subscription"] == 1
    assert summary["status"] == "partial", "asked for and not done is not success"


async def test_stealer_logs_are_not_asked_for_when_the_plan_is_unknown(monkeypatch):
    """A status route that did not answer is not permission to spend a paid route."""
    seen: list[str] = []
    connector, _, job = _exposure_scan(
        monkeypatch,
        _stealer_handler(seen),
        config={"stealer_logs_enabled": True},
        readiness=ProviderReadiness(status=500),
    )
    _, summary = await connector.run_scan(job)

    assert [path for path in seen if "stealerLogs" in path] == []
    assert summary["stealer_logs"]["reason"] == "subscription_unknown"


async def test_the_stealer_pass_names_its_sites_for_addresses_and_domains(monkeypatch):
    """WI-18: rows carry the website, never an invented incident or date."""
    seen: list[str] = []
    connector, submitted, job = _exposure_scan(
        monkeypatch,
        _stealer_handler(seen),
        config={"stealer_logs_enabled": True},
        params={
            "emails": ["user@example.com"],
            "domains": ["example.com"],
            "stealer_logs": {"last_seen_at": None},
        },
        readiness=ProviderReadiness(subscription={"IncludesStealerLogs": True}),
    )
    _, summary = await connector.run_scan(job)

    email_rows = [row for row in submitted if row["matched_domain"] is None]
    domain_rows = [row for row in submitted if row["matched_domain"] == "example.com"]
    assert len(email_rows) == 2
    assert len(domain_rows) == 2
    for row in submitted:
        assert row["exposure_kind"] == "stealer_log"
        assert row["breach_name"].startswith("stealerlog:")
        assert row["attributes"]["metadata_incomplete"] is True
        assert row["attributes"]["stealer_log_site"] == row["domain"]
    assert {row["matched_email"] for row in domain_rows} == {"alice@example.com"}
    assert summary["stealer_logs"]["status"] == "ran"
    assert summary["stealer_logs"]["emails_asked"] == 1
    assert summary["stealer_logs"]["domains_asked"] == 1
    assert summary["stealer_logs"]["sites"] == 4
    assert summary["stealer_logs"]["rows"] == 4
    assert summary["status"] == "success"


async def test_the_stealer_pass_waits_for_the_week_to_close(monkeypatch):
    """The provider's separate allowance is why this is not part of every scan."""
    from datetime import datetime, timezone

    seen: list[str] = []
    connector, submitted, job = _exposure_scan(
        monkeypatch,
        _stealer_handler(seen),
        config={"stealer_logs_enabled": True},
        params={
            "emails": ["user@example.com"],
            "domains": [],
            "stealer_logs": {"last_seen_at": datetime.now(timezone.utc).isoformat()},
        },
        readiness=ProviderReadiness(subscription={"IncludesStealerLogs": True}),
    )
    _, summary = await connector.run_scan(job)

    assert [path for path in seen if "stealerLogs" in path] == []
    assert submitted == []
    assert summary["stealer_logs"]["reason"] == "not_due"
    assert summary["stealer_logs"]["due"] is False
    assert summary["status"] == "success", "nothing to do is not a failure"


async def test_more_sites_than_allowed_are_counted_rather_than_stored(monkeypatch):
    """One address is not permission to become a page of rows."""
    seen: list[str] = []
    sites = tuple(f"site{index}.example" for index in range(5))
    connector, submitted, job = _exposure_scan(
        monkeypatch,
        _stealer_handler(seen, sites=sites),
        config={"stealer_logs_enabled": True, "max_stealer_log_sites_per_asset": 2},
        params={
            "emails": ["user@example.com"],
            "domains": [],
            "stealer_logs": {"last_seen_at": None},
        },
        readiness=ProviderReadiness(subscription={"IncludesStealerLogs": True}),
    )
    _, summary = await connector.run_scan(job)

    assert len(submitted) == 2
    assert summary["stealer_logs"]["sites_over_limit"] == 3
    assert summary["stealer_logs"]["sites"] == 2


# ---------------------------------------------------------------------------
# The hash-range form of an address lookup (WI-19)
# ---------------------------------------------------------------------------


def _hash_parts(email, *, case="lower"):
    return _main._email_hash_parts(email, case=case)


async def test_the_hash_prefix_is_the_first_six_characters_of_the_addresses_digest():
    """The provider's own fixture, so the algorithm is pinned rather than assumed."""
    prefix, suffix = _hash_parts("multiple-breaches@hibp-integration-tests.com")

    assert prefix == "6B5917"
    assert prefix + suffix == "6B5917C6C0AADE0C085843D66E4944E108C4A4CD"


async def test_the_lowercased_and_raw_forms_differ_only_for_a_mixed_case_address():
    """The retry exists for exactly this case, and is pointless without it."""
    lower = _hash_parts("user@example.com")
    raw = _hash_parts("user@example.com", case="raw")
    mixed_lower = _hash_parts("  User@Example.com ")
    mixed_raw = _hash_parts("  User@Example.com ", case="raw")

    assert lower == raw
    assert mixed_lower != mixed_raw
    # Whitespace is not part of an address, whichever form is hashed.
    assert mixed_lower == _hash_parts("user@example.com")


def _range_scan(monkeypatch, handler, *, config=None, k_anon=True, status=200, params=None):
    """A scan of one address whose subscription may or may not include the range form."""
    subscription = {"SubscriptionName": "Pro"}
    if k_anon is not None:
        subscription["IncludesKAnon"] = k_anon
    connector, submitted, job = _exposure_scan(
        monkeypatch,
        handler,
        config=config,
        params=params,
        readiness=ProviderReadiness(subscription=subscription, status=status),
    )
    return connector, submitted, job


def _range_route_handler(email, incident=_ONE_INCIDENT, *, suffix=None, seen=None):
    """A provider whose range bucket names one incident for ``email``'s own suffix."""
    prefix, own_suffix = _hash_parts(email) if suffix is None else (None, suffix)
    seen = [] if seen is None else seen

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        seen.append(path)
        if "/breachedaccount/range/" in path:
            asked = path.rsplit("/", 1)[-1]
            if prefix is not None and asked != prefix:
                # The raw-case digest of a mixed-case address is a different bucket.
                raw_prefix, raw_suffix = _hash_parts(email, case="raw")
                if asked != raw_prefix:
                    return httpx.Response(404, json={"detail": "nothing"})
                return httpx.Response(
                    200, json=[{"hashSuffix": raw_suffix, "websites": [incident["Name"]]}]
                )
            return httpx.Response(
                200, json=[{"hashSuffix": own_suffix, "websites": [incident["Name"]]}]
            )
        if "/breach/" in path:
            return httpx.Response(200, json=incident)
        if "/breachedaccount/" in path:
            return httpx.Response(200, json=[incident])
        return httpx.Response(404)

    handler.seen = seen
    return handler


async def test_the_two_forms_produce_the_same_rows(monkeypatch):
    """WI-19's acceptance: the class of lookup is not visible in what it stores.

    The same incident, asked for once as an address and once as a hash prefix, has to
    arrive as the same finding — otherwise \"we stopped sending addresses\" would be a
    change of coverage dressed up as a privacy improvement.
    """
    rows = {}
    for label, k_anon in (("range", True), ("cleartext", False)):
        email = "user@example.com"
        connector, submitted, job = _range_scan(
            monkeypatch, _range_route_handler(email), k_anon=k_anon
        )
        _, summary = await connector.run_scan(job)
        rows[label] = submitted
        assert summary["email_lookup"]["form"] == label, summary["email_lookup"]

    assert rows["range"] == rows["cleartext"]
    assert [row["breach_name"] for row in rows["range"]] == ["Adobe"]
    assert rows["range"][0]["matched_email"] == "user@example.com"


async def test_the_range_form_keeps_the_address_out_of_the_request(monkeypatch):
    """Only the six-character prefix travels; the address is never in a URL."""
    email = "user@example.com"
    handler = _range_route_handler(email)
    connector, submitted, job = _range_scan(monkeypatch, handler)
    _, summary = await connector.run_scan(job)

    prefix, _suffix = _hash_parts(email)
    assert len(submitted) == 1
    breach_requests = [
        path for path in handler.seen if "/breachedaccount/" in path
    ]
    assert breach_requests == [f"/api/v3/breachedaccount/range/{prefix}"]
    # Not in the breach lookup at all — and the one route that still takes an address is
    # named, because the provider offers it in no other form (pastes).
    assert summary["email_lookup"]["form"] == "range"
    assert summary["email_lookup"]["address_routes"] == ["pasteAccount"]
    assert summary["email_lookup"]["reason"] is None
    assert summary["email_lookup"]["range"]["prefixes_asked"] == 1
    assert summary["email_lookup"]["range"]["matched"] == 1
    assert summary["status"] == "success"


async def test_a_plan_without_the_range_search_uses_the_address_form(monkeypatch):
    """Every plan supports the documented route; the range is what some plans sell."""
    email = "user@example.com"
    handler = _range_route_handler(email)
    connector, submitted, job = _range_scan(monkeypatch, handler, k_anon=False)
    _, summary = await connector.run_scan(job)

    assert len(submitted) == 1
    assert any(path.endswith(f"/breachedaccount/{email}") for path in handler.seen)
    assert not any("/breachedaccount/range/" in path for path in handler.seen)
    assert summary["email_lookup"] == {
        "form": "cleartext",
        "reason": "not_in_subscription",
        "emails_unavailable": 0,
        # Both lookups name the address on this plan: the breach one has no other form
        # available, and the paste route has none at all.
        "address_routes": ["breachedaccount", "pasteAccount"],
        "range": {
            "prefixes_asked": 0,
            "matched": 0,
            "unmatched": 0,
            "case_retries": 0,
            "metadata_missing": 0,
        },
    }


async def test_an_unanswered_subscription_does_not_spend_the_range_route(monkeypatch):
    """A paid route is not called on the strength of a question nobody answered."""
    email = "user@example.com"
    handler = _range_route_handler(email)
    connector, submitted, job = _range_scan(monkeypatch, handler, k_anon=None, status=500)
    _, summary = await connector.run_scan(job)

    assert len(submitted) == 1
    assert not any("/breachedaccount/range/" in path for path in handler.seen)
    assert summary["email_lookup"]["form"] == "cleartext"
    assert summary["email_lookup"]["reason"] == "subscription_unknown"


async def test_the_operator_can_keep_the_address_form_on_a_range_plan(monkeypatch):
    """Some operators need what the range answer omits; the switch says so."""
    email = "user@example.com"
    handler = _range_route_handler(email)
    connector, _submitted, job = _range_scan(
        monkeypatch,
        handler,
        config={"breachedaccount_range_enabled": False},
        k_anon=True,
    )
    _, summary = await connector.run_scan(job)

    assert not any("/breachedaccount/range/" in path for path in handler.seen)
    assert summary["email_lookup"]["form"] == "cleartext"
    assert summary["email_lookup"]["reason"] == "disabled_by_operator"


async def test_a_refused_range_answer_is_never_replaced_by_the_address_form(monkeypatch):
    """The point of the form is that the address does not leave; a failure is not a licence."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if "/breachedaccount/range/" in request.url.path:
            return httpx.Response(403, json={"detail": "refused"})
        if "/breachedaccount/" in request.url.path:
            return httpx.Response(200, json=[_ONE_INCIDENT])
        return httpx.Response(404)

    connector, submitted, job = _range_scan(monkeypatch, handler)
    _, summary = await connector.run_scan(job)

    assert submitted == []
    assert not any("/breachedaccount/user@example.com" in path for path in seen)
    assert summary["email_lookup"]["emails_unavailable"] == 1
    assert summary["status"] == "partial"
    assert summary["emails_scanned"] == 1


async def test_a_bucket_without_our_suffix_is_a_negative_answer(monkeypatch):
    """A prefix is shared by many accounts: only our own suffix is about us."""
    email = "user@example.com"
    handler = _range_route_handler(email, suffix="F" * 34)
    connector, submitted, job = _range_scan(monkeypatch, handler)
    _, summary = await connector.run_scan(job)

    assert submitted == []
    assert summary["email_lookup"]["range"]["matched"] == 0
    assert summary["email_lookup"]["range"]["unmatched"] == 1
    assert summary["status"] == "success", "not breached is not a failed scan"


async def test_a_mixed_case_address_asks_its_prefix_twice_only_when_nothing_matched(monkeypatch):
    """The docs do not say how the address is normalized; a negative is confirmed.

    The retry costs one request, only for an address that could hash two ways, and only
    when the first answer was negative — which is what keeps a real account from reading
    as \"not breached\" because of a case difference the provider never documented.
    """
    email = "User@Example.com"
    lower_prefix, _lower_suffix = _hash_parts(email)
    raw_prefix, raw_suffix = _hash_parts(email, case="raw")
    asked: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "/breachedaccount/range/" in path:
            asked.append(path.rsplit("/", 1)[-1])
            if path.rsplit("/", 1)[-1] == lower_prefix:
                # The bucket the lowercased digest falls in holds other accounts only.
                return httpx.Response(200, json=[])
            return httpx.Response(
                200, json=[{"hashSuffix": raw_suffix, "websites": [_ONE_INCIDENT["Name"]]}]
            )
        if "/breach/" in path:
            return httpx.Response(200, json=_ONE_INCIDENT)
        return httpx.Response(404)

    connector, submitted, job = _range_scan(
        monkeypatch,
        handler,
        params={"emails": [email], "domains": []},
    )
    _, summary = await connector.run_scan(job)

    assert asked == [lower_prefix, raw_prefix]
    assert len(submitted) == 1
    assert summary["email_lookup"]["range"]["case_retries"] == 1
    assert summary["email_lookup"]["range"]["matched"] == 1
    assert summary["email_lookup"]["range"]["unmatched"] == 0


async def test_a_mixed_case_address_that_matches_first_is_not_asked_twice(monkeypatch):
    """The retry is a fallback, not a second lookup on every address."""
    email = "User@Example.com"
    prefix, suffix = _hash_parts(email)
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if "/breachedaccount/range/" in request.url.path:
            return httpx.Response(
                200, json=[{"hashSuffix": suffix, "websites": [_ONE_INCIDENT["Name"]]}]
            )
        if "/breach/" in request.url.path:
            return httpx.Response(200, json=_ONE_INCIDENT)
        return httpx.Response(404)

    connector, submitted, job = _range_scan(monkeypatch, handler)
    _, summary = await connector.run_scan(job)

    range_requests = [path for path in seen if "/breachedaccount/range/" in path]
    assert range_requests == [f"/api/v3/breachedaccount/range/{prefix}"]
    assert len(submitted) == 1
    assert summary["email_lookup"]["range"]["case_retries"] == 0


async def test_an_incident_whose_metadata_did_not_arrive_is_counted_not_invented(monkeypatch):
    """The range answer names incidents only; a name without metadata is not a row."""
    email = "user@example.com"
    prefix, suffix = _hash_parts(email)

    def handler(request: httpx.Request) -> httpx.Response:
        if "/breachedaccount/range/" in request.url.path:
            return httpx.Response(
                200, json=[{"hashSuffix": suffix, "websites": ["Adobe", "Gone"]}]
            )
        if request.url.path.endswith("/breach/Adobe"):
            return httpx.Response(200, json=_ONE_INCIDENT)
        return httpx.Response(404)

    connector, submitted, job = _range_scan(monkeypatch, handler)
    _, summary = await connector.run_scan(job)

    assert [row["breach_name"] for row in submitted] == ["Adobe"]
    assert summary["email_lookup"]["range"]["metadata_missing"] == 1


async def test_the_range_plan_can_stop_sending_the_address_altogether(monkeypatch):
    """The paste route has no hash form, so it is the one lookup the operator can drop.

    With it off and the range form on, no request this scan makes contains the address —
    which is the property an installation enabling the range search is actually after.
    """
    email = "user@example.com"
    handler = _range_route_handler(email)
    connector, submitted, job = _range_scan(
        monkeypatch,
        handler,
        config={"pastes_enabled": False},
        k_anon=True,
    )
    _, summary = await connector.run_scan(job)

    assert not any("/pasteAccount/" in path for path in handler.seen)
    assert all(email not in path for path in handler.seen)
    assert summary["pastes"] == {
        "status": "skipped",
        "reason": "disabled",
        "emails_looked_up": 0,
        "rows": 0,
        "unavailable": 0,
    }
    assert summary["email_lookup"]["address_routes"] == []
    assert len(submitted) == 1


# ---------------------------------------------------------------------------
# Domain verification from the product (WI-20)
# ---------------------------------------------------------------------------


def _verification_job(action, domain="example.com", config=None):
    return {
        "job_id": "job-verify",
        "config": config or {},
        "params": {"trigger": "manual", "domain_verification": {"action": action, "domain": domain}},
    }


async def test_generate_returns_the_record_the_operator_has_to_publish(monkeypatch):
    """The value is passed through exactly as the provider gave it."""
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        if request.url.path.endswith("/domainVerification/generateDnsToken"):
            body = json.loads(request.content)
            assert body == {"DomainName": "example.com"}
            return httpx.Response(200, json={"txtRecordValue": "hibp-verify=dweb_abc123"})
        return httpx.Response(404)

    connector, submitted, job = _exposure_scan(monkeypatch, handler)
    _, summary = await connector.run_scan(_verification_job("generate"))

    assert submitted == [], "verification stores no findings"
    assert summary["domain_verification"] == {
        "action": "generate",
        "domain": "example.com",
        "status": "generated",
        "reason": None,
        "txt_record_value": "hibp-verify=dweb_abc123",
    }
    assert summary["status"] == "success"
    assert seen == [("POST", "/api/v3/domainVerification/generateDnsToken")]


async def test_a_verification_job_does_not_scan(monkeypatch):
    """The job asks one question: a full scan on every TXT-record copy would be spent work."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if request.url.path.endswith("/domainVerification/generateDnsToken"):
            return httpx.Response(200, json={"txtRecordValue": "hibp-verify=dweb_abc123"})
        return httpx.Response(404)

    connector, _submitted, job = _exposure_scan(
        monkeypatch,
        handler,
        params={
            "emails": ["user@example.com"],
            "domains": ["example.com"],
            "domain_verification": {"action": "generate", "domain": "example.com"},
        },
    )
    _, summary = await connector.run_scan(
        {
            **job,
            "params": {
                "emails": ["user@example.com"],
                "domains": ["example.com"],
                "domain_verification": {"action": "generate", "domain": "example.com"},
            },
        }
    )

    assert not any("/breachedaccount/" in path for path in seen)
    assert not any("/breacheddomain/" in path for path in seen)
    assert not any("/breaches" in path for path in seen)
    assert not any("/pasteAccount/" in path for path in seen)
    assert summary["domain_verification"]["status"] == "generated"


async def test_verify_says_whether_the_record_is_there_yet(monkeypatch):
    """A 400 is \"not yet\", not \"something broke\": an operator reads the difference."""
    statuses = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/domainVerification/verifyDnsToken"):
            statuses.append(1)
            if len(statuses) == 1:
                return httpx.Response(
                    400, json={"message": "No hibp-verify TXT records were found on the domain."}
                )
            return httpx.Response(200)
        return httpx.Response(404)

    connector, _submitted, _job = _exposure_scan(monkeypatch, handler)
    _, first = await connector.run_scan(_verification_job("verify"))
    assert first["domain_verification"] == {
        "action": "verify",
        "domain": "example.com",
        "status": "not_verified",
        "reason": "token_not_found",
        "txt_record_value": None,
    }
    # A record that is not published yet is a step of the flow, not a provider error.
    assert first["status"] == "success"
    assert first["provider_errors"] == []

    _, second = await connector.run_scan(_verification_job("verify"))
    assert second["domain_verification"]["status"] == "verified"
    assert second["domain_verification"]["reason"] is None


async def test_a_refused_verification_names_the_reason_and_is_partial(monkeypatch):
    """403 and 429 are refusals, and the summary must not read like a missing record."""
    for status, reason in ((403, "access_denied"), (429, "rate_limited")):
        def handler(request: httpx.Request, status: int = status) -> httpx.Response:
            return httpx.Response(status, json={"message": "refused"})

        connector, _submitted, _job = _exposure_scan(monkeypatch, handler)
        _, summary = await connector.run_scan(_verification_job("verify"))

        assert summary["domain_verification"]["status"] == "failed"
        assert summary["domain_verification"]["reason"] == reason
        assert summary["skipped_reasons"][f"domain_verification_{reason}"] == 1
        assert summary["status"] == "partial"


async def test_an_unanswered_generate_is_not_an_empty_record(monkeypatch):
    """A 200 without a value is a malformed answer, not a record with nothing in it."""
    connector, _submitted, _job = _exposure_scan(
        monkeypatch, lambda request: httpx.Response(200, json={})
    )
    _, summary = await connector.run_scan(_verification_job("generate"))

    assert summary["domain_verification"]["status"] == "failed"
    assert summary["domain_verification"]["reason"] == "malformed_answer"
    assert summary["domain_verification"]["txt_record_value"] is None


async def test_a_verification_job_without_a_usable_request_asks_nothing(monkeypatch):
    """The core validates the payload; a direct caller that names nonsense is refused."""
    asked: list[str] = []
    connector, _submitted, _job = _exposure_scan(
        monkeypatch, lambda request: asked.append(request.url.path) or httpx.Response(404)
    )
    _, summary = await connector.run_scan(_verification_job("delete", domain=""))

    assert asked == []
    assert summary["domain_verification"]["reason"] == "invalid_request"
    assert summary["domain_verification"]["status"] == "failed"


async def test_a_provider_record_outside_the_cores_bounds_is_trimmed_not_forwarded(
    monkeypatch,
):
    """One oversized field must not cost the scan every finding after it.

    The core validates a whole submission before it stores any of it, and it
    declares the bounds for these two fields (``BreachFinding``: a description of
    at most 100,000 characters, at most 100 data classes of at most 255
    characters). The worker truncated the name, the title and the domain but
    forwarded these two untouched, so a record past either bound was refused as a
    batch — and the scan raised rather than reporting a partial one.
    """
    from app.schemas.connector import BreachFinding

    connector = make_connector(monkeypatch)
    payload = connector._normalize_breach(
        {
            "Name": "ExampleBreach",
            "Title": "Example",
            "Domain": "example.com",
            "BreachDate": "2020-01-01",
            "PwnCount": 10,
            "Description": "x" * 200_000,
            "DataClasses": [f"class-{index}" for index in range(250)] + [None, ""],
        }
    )
    accepted = BreachFinding.model_validate(payload)
    assert len(accepted.description or "") == 100_000
    assert len(accepted.data_classes) == 100
    assert accepted.data_classes[0] == "class-0"

    # The catalogue entry schema declares the same list bound, so the sweep that
    # hands the core its incidents has to hold it too.
    from app.schemas.connector import BreachCatalogueEntry

    entry = BreachCatalogueEntry.model_validate(
        _main._catalogue_entry(
            {
                "Name": "ExampleBreach",
                "Title": "Example",
                "Domain": "example.com",
                "BreachDate": "2020-01-01",
                "PwnCount": 10,
                "DataClasses": [f"class-{index}" for index in range(250)],
            }
        )
    )
    assert len(entry.data_classes) == 100
