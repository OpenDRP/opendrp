"""Every number a worker puts on one provider call, in one table.

Plans 003 and 004 moved the mechanisms — pace, reservation, retries,
``Retry-After``, the body bound — into one client and deliberately left the
*numbers* to each worker. That was the right call: how long a scan may stall is a
product decision per provider, not something a refactoring should quietly
normalise. The cost is that six numbers now live in five modules, in three shapes
(a module constant, a method, an instance attribute), and nothing said what they
were — so a change to any of them was invisible in review.

This file is the change-detector, not a behavioural test: each worker's own suite
asserts what its numbers *do*. What is pinned here is the table itself, so that
making one worker ask its provider differently shows up as a diff a reviewer can
see, and so the divergence the plans kept on purpose is documented where the
numbers are.

Read the rows as the answers to four questions:

* how many times may one call be attempted?
* how long may a single wait be (the provider's own hint or our backoff)?
* how much of a body may be read?
* **is a longer hint honoured, or does it abandon the call?**

The last column is the one that has no shared answer at all: ``None`` means "wait
it out at the ceiling and retry", a number means "give up above it and report
``http_<status>_retry_later``". That is the policy question the plans deferred,
and the table is what makes it visible instead of accidental.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_CONNECTORS = _ROOT / "connectors"
if not _CONNECTORS.is_dir():  # a trimmed checkout cannot answer the question
    pytest.skip("not a repository checkout: connectors/ missing", allow_module_level=True)

_BASE = _CONNECTORS / "base"
if str(_BASE) not in sys.path:
    sys.path.insert(0, str(_BASE))


def _load(name: str, path: Path, *, sibling_package: Path | None = None):
    """Load a connector module by path, under a name of its own.

    A connector's ``main.py`` imports its neighbours by bare name (``tls_probe``),
    which is how the image lays them out; the sibling directory goes on the path
    for the duration of the import and is taken off again, so loading one worker
    does not decide what another test's ``main`` means.
    """
    added = False
    if sibling_package is not None and str(sibling_package) not in sys.path:
        sys.path.insert(0, str(sibling_package))
        added = True
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        if added:
            sys.path.remove(str(sibling_package))


_shodan = _load("limits_shodan", _CONNECTORS / "shodan" / "main.py")
_hibp = _load("limits_hibp", _CONNECTORS / "hibp" / "main.py")
_dns = _load(
    "limits_dns_security",
    _CONNECTORS / "dns_security" / "main.py",
    sibling_package=_CONNECTORS / "dns_security",
)
_intelligence = _load("limits_intelligence", _CONNECTORS / "intelligence" / "providers.py")
_exposure = _load(
    "limits_exposure", _CONNECTORS / "exposure_endpoints" / "endpoint_providers.py"
)


@pytest.fixture()
def connector_env(monkeypatch: pytest.MonkeyPatch):
    """What a connector process needs to start, and no more.

    The five workers are built without a provider key and without a core: this
    file asks what a call would be held to, not what a scan does.
    """
    monkeypatch.setenv("CORE_URL", "http://core:8000")
    monkeypatch.setenv("CONNECTOR_TOKEN", "fixture-core-token")
    monkeypatch.setenv("CONNECTOR_NAME", "limits-fixture")
    monkeypatch.setenv("CONNECTOR_TYPE", "dns")
    # The manifest is built in `__init__`, and a worker that names no job type
    # cannot claim one — the SDK refuses rather than registering a nameless scan.
    monkeypatch.setenv("CONNECTOR_JOB_TYPE", "dns.limits-fixture")


def _shodan_limits(connector_env):
    return _shodan.ShodanConnector()._provider_limits


def _dns_limits():
    # The numbers are module constants read at call time, which is why this
    # worker can hand a test a lowered bound without rebuilding anything.
    connector = _dns.DNSConnector.__new__(_dns.DNSConnector)
    return connector._provider_limits()


def _limits(worker: str, connector_env):
    return {
        "shodan": lambda: _shodan_limits(connector_env),
        "hibp": lambda: _hibp.PROVIDER_LIMITS,
        "dns_security": _dns_limits,
        "intelligence": lambda: _intelligence.LIMITS,
        "exposure_endpoints": lambda: _exposure.LIMITS,
    }[worker]()


#: The table. `attempts` counts wire attempts, retries included; `ceiling` is the
#: longest single wait this worker will accept; `hint above` is the ceiling above
#: which the provider's `Retry-After` abandons the call instead of being waited out.
TABLE = {
    # Shodan bills a query credit per request, so a retry is a second credit; it
    # waits a hint out to 30s and retries rather than giving up on the call.
    "shodan": dict(attempts=3, ceiling=30.0, body=2_000_000, backoff=1.0, hint_above=None),
    # One attempt: HIBP bills a request whether or not it succeeds. The ceiling and
    # the factor are the shared defaults and unused — there is nothing to wait for.
    "hibp": dict(attempts=1, ceiling=30.0, body=2_000_000, backoff=1.0, hint_above=None),
    # The strictest of the five: four attempts, a minute of waiting, and a call
    # abandoned above that minute so one job cannot be strung out by a provider.
    "dns_security": dict(
        attempts=4, ceiling=60.0, body=2_000_000, backoff=1.0, hint_above=60.0
    ),
    # A quarter of the exponent, five seconds at most, and a long hint waited out
    # at that cap rather than abandoning the call.
    "intelligence": dict(attempts=3, ceiling=5.0, body=2_000_000, backoff=0.25, hint_above=None),
    "exposure_endpoints": dict(
        attempts=3, ceiling=5.0, body=2_000_000, backoff=0.25, hint_above=None
    ),
}


@pytest.mark.parametrize("worker", sorted(TABLE))
def test_the_table_is_what_the_worker_puts_on_a_call(worker, connector_env):
    expected = TABLE[worker]
    limits = _limits(worker, connector_env)

    assert limits.max_attempts == expected["attempts"]
    assert limits.max_retry_delay == expected["ceiling"]
    assert limits.max_response_bytes == expected["body"]
    assert limits.backoff_factor == expected["backoff"]
    assert limits.abort_when_retry_after_exceeds == expected["hint_above"]


@pytest.mark.parametrize("worker", sorted(TABLE))
def test_every_worker_states_its_body_bound_explicitly(worker, connector_env):
    """None of the five relies on the shared default for the one security number."""
    assert _limits(worker, connector_env).max_response_bytes == 2_000_000


#: How the operator page spells the last column. A row either abandons a call whose
#: hint is longer than its ceiling, does not retry at all, or waits the hint out.
_DOC_BEHAVIOURS = {
    "waited out at the ceiling, then retried": "wait",
    "abandoned as `http_<status>_retry_later`": "abandon",
    "not retried — the call has one attempt": "single",
}


def _documented_table() -> dict[str, dict]:
    """The table `connectors/README.md` shows an operator, parsed.

    The page states the policy because an operator reading about a source needs to
    know how long a scan may sit on one answer. `TABLE` is where the numbers live;
    this parsing is what keeps the two from drifting apart, which is the failure a
    documented number always has.
    """
    text = (_ROOT / "connectors" / "README.md").read_text(encoding="utf-8")
    section = text.split("## What one provider call costs", 1)
    assert len(section) == 2, "the connector page no longer states the policy"

    rows: dict[str, dict] = {}
    lines = section[1].splitlines()
    header = next(
        (index for index, line in enumerate(lines) if line.startswith("| Worker |")),
        None,
    )
    assert header is not None, "the policy table lost its header row"
    for line in lines[header + 2 :]:  # skip the header and its separator
        if not line.startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        worker = cells[0].strip("`")
        attempts = int(cells[1])
        wait, unit = cells[2].split()
        assert unit == "s", f"{worker}: the wait column must be seconds"
        bound, bound_unit = cells[3].split()
        assert bound_unit == "MB", f"{worker}: the bound column must be megabytes"
        rows[worker] = dict(
            attempts=attempts,
            ceiling=float(wait),
            body=int(float(bound) * 1_000_000),
            behaviour=_DOC_BEHAVIOURS[cells[4]],
        )
    return rows


def test_the_documented_table_is_the_code_table():
    documented = _documented_table()

    assert sorted(documented) == sorted(TABLE), (
        "the operator page lists a different set of workers than the code table"
    )
    for worker, row in documented.items():
        expected = TABLE[worker]
        assert row["attempts"] == expected["attempts"], worker
        assert row["ceiling"] == expected["ceiling"], worker
        assert row["body"] == expected["body"], worker
        if row["behaviour"] == "abandon":
            assert expected["hint_above"] == expected["ceiling"], (
                f"{worker}: the page says a long hint abandons the call at the "
                f"ceiling, but the code does not"
            )
        elif row["behaviour"] == "wait":
            assert expected["hint_above"] is None, (
                f"{worker}: the page says a long hint is waited out, but the code "
                f"abandons the call"
            )
        else:  # "single"
            assert expected["attempts"] == 1 and expected["hint_above"] is None, (
                f"{worker}: the page says the call has one attempt, but the code "
                f"retries it"
            )


def test_the_loader_really_loads_five_distinct_workers():
    """A table of five identical objects would pass every row above."""
    modules = {id(_shodan), id(_hibp), id(_dns), id(_intelligence), id(_exposure)}
    assert len(modules) == 5
    assert _hibp.PROVIDER_LIMITS is not _intelligence.LIMITS
