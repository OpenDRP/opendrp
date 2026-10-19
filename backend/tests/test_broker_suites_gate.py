"""A test that needs a broker must skip without one — and must run where there is one.

The failure this gate exists for: three scheduler tests in
``test_celery_boundary.py`` and the quota-script test in
``test_source_intelligence.py`` open a real Redis client and exercise behaviour
only a broker has — ``SET NX`` per minute, the dispatch guard that blocks a second
tick, the Lua script that charges an account atomically. They reached for
``settings.REDIS_URL`` (one of them for a hard-coded ``localhost:6379``) and
*failed* when nothing listened there, so every run outside the tooling stack — a
developer's bare virtualenv, for instance — reported four red tests whose cause had
nothing to do with the change under test. The PostgreSQL suites next to them had
always skipped instead, and the four also had no gate: nothing noticed that a test
which *needs* a broker looked exactly like a test that merely *found* one.

What is pinned here:

* every file that opens a real client is declared, so a new one cannot arrive
  un-gated and un-noticed;
* in the files that rely on the broker fixture, every test that reaches a client
  call takes that fixture — the gate reads the module's own call graph, because
  ``_run_sync(_clear_dispatch_guard, ...)`` reaches the client without calling it;
* the fixture turns the skip into an error under ``REQUIRE_INTEGRATION=1`` (what
  CI's integration job sets), so a job that was given a broker and lost it cannot
  report success on tests that never ran — the same doctrine as
  ``tests/test_postgres_only_suites_gate.py``;
* the skip message cannot carry the broker's password into a CI log or a JUnit
  report;
* the job that runs this suite supplies a broker in the first place: the fixture's
  reachability check is only a skip *outside* the environments that have one — the
  environment names the URL, and the service container that answers on its port is
  read as well, because a `REDIS_URL` naming a port nothing listens on skips the
  same tests just as silently.

The workflow is an input here the same way it is for the PostgreSQL gate, and the
dev overlay mounts it where this test resolves it.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import yaml

_ROOT = Path(__file__).resolve().parents[2]
_TESTS = Path(__file__).resolve().parent
_CONFTEST = _TESTS / "conftest.py"
_WORKFLOW = _ROOT / ".github/workflows/ci.yml"

#: The fixture a test takes to declare that it needs a live broker.
_BROKER_FIXTURE = "live_redis"

#: Every test file that opens a real Redis client, and why that is allowed in it.
#: The set is asserted rather than trusted: a file that starts opening one has to
#: be added here (or, better, take the fixture), and an entry that has stopped
#: opening one has to go.
_CLIENT_FILES: dict[str, str] = {
    "test_celery_boundary.py": "the scheduler tests take the live_redis fixture",
    "test_source_intelligence.py": "the quota-script test takes the live_redis fixture",
    "test_production_integrations.py": "module-level gate on INTEGRATION_REDIS_URL",
}

#: The files whose client tests must take the fixture, rather than gate themselves
#: at module level the way `test_production_integrations.py` does.
_FIXTURE_GATED_FILES = ("test_celery_boundary.py", "test_source_intelligence.py")

#: The CI jobs that must each have a broker: the suite job (a skip here would hide
#: the tests from the only run that executes them) and the integration job.
_SUITE_JOB = "backend"
_INTEGRATION_JOB = "production-integration"

if not _WORKFLOW.is_file():
    # A trimmed checkout cannot answer a question about the workflow.
    pytest.skip(f"not a repository checkout: {_WORKFLOW} missing", allow_module_level=True)


def _opens_a_client(node: ast.AST) -> bool:
    """Whether this function constructs a Redis client.

    ``Redis.from_url(...)`` is the only way a test reaches a broker, and it appears
    as an attribute reference; the monkeypatched spellings elsewhere in the suite
    pass the name as a *string* (``monkeypatch.setattr("redis.Redis.from_url", ...)``),
    which is not an attribute node at all.
    """
    return any(
        isinstance(sub, ast.Attribute) and sub.attr == "from_url" for sub in ast.walk(node)
    )


def _referenced_names(node: ast.AST) -> set[str]:
    """Every bare name and attribute the function mentions.

    A helper can be reached without being called — ``_run_sync(_clear_dispatch_guard,
    ...)`` hands it over as an argument — so references are the edge in this graph,
    not calls.
    """
    names: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            names.add(sub.id)
        elif isinstance(sub, ast.Attribute):
            names.add(sub.attr)
    return names


def _argument_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    arguments = node.args
    return {
        argument.arg
        for argument in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs)
    }


def _functions(tree: ast.Module) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    return {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _reaches_a_client(
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    """The client-opening functions this one reaches, directly or through helpers."""
    opening = {name for name, function in functions.items() if _opens_a_client(function)}
    reached = _referenced_names(node) & set(functions)
    seen: set[str] = set()
    pending = list(reached)
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        for other in _referenced_names(functions[name]) & set(functions):
            if other not in seen:
                pending.append(other)
    return seen & opening


def _ungated_tests(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    functions = _functions(tree)
    offenders: list[str] = []
    for name, node in functions.items():
        if not name.startswith("test_"):
            continue
        # A test may open the client itself or reach a helper that does.
        reached = _reaches_a_client(functions, node)
        if _opens_a_client(node):
            reached = reached | {name}
        if not reached:
            continue
        if _BROKER_FIXTURE not in _argument_names(node):
            offenders.append(f"{path.name}::{name} reaches {sorted(reached)}")
    return offenders


def _selects_the_default_suite(command: str) -> bool:
    """Whether this pytest invocation collects ``testpaths`` rather than named files.

    The broker-dependent tests live in the default suite; a step that names other
    directories (the connector worker tree, for instance) does not run them, and
    requiring a broker there would be a rule about nothing.
    """
    tokens = command.split()
    if "pytest" not in tokens:
        return False
    arguments = [
        token
        for token in tokens[tokens.index("pytest") + 1 :]
        if not token.startswith("-")
    ]
    return not any("/" in argument or argument.endswith(".py") for argument in arguments)


def _files_opening_a_client() -> set[str]:
    found: set[str] = set()
    for path in sorted(_TESTS.glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if any(_opens_a_client(function) for function in _functions(tree).values()):
            found.add(path.name)
    return found


def _job(name: str) -> dict:
    workflow = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    jobs = workflow.get("jobs") or {}
    assert name in jobs, f"the workflow no longer has the {name} job"
    return jobs[name]


def _steps(name: str) -> list[dict]:
    steps = _job(name).get("steps") or []
    assert steps, f"{name} has no steps"
    return steps


def _suite_steps() -> list[dict]:
    """The steps of the suite job that collect the default test suite."""
    return [
        step
        for step in _steps(_SUITE_JOB)
        if _selects_the_default_suite(str(step.get("run") or ""))
    ]


def _published_host_ports(services: dict) -> set[int]:
    """Every host port these service containers publish.

    A `ports:` entry is `host:container`, optionally behind an address or ahead of
    a protocol (`127.0.0.1:6379:6379/tcp`), so the host port is the second value
    from the right — the last one when the container and the host port are written
    without a colon at all.
    """
    ports: set[int] = set()
    for service in services.values():
        for entry in (service or {}).get("ports") or []:
            parts = str(entry).split("/")[0].split(":")
            candidate = parts[-2] if len(parts) >= 2 else parts[-1]
            if candidate.isdigit():
                ports.add(int(candidate))
    return ports


def test_every_file_that_opens_a_broker_is_declared() -> None:
    found = _files_opening_a_client()
    declared = set(_CLIENT_FILES)

    undeclared = sorted(found - declared)
    assert undeclared == [], (
        "these test files open a real Redis client and are not declared here: "
        f"{undeclared}. Route them through the `{_BROKER_FIXTURE}` fixture (in "
        "tests/conftest.py) and add them to _FIXTURE_GATED_FILES, or add an entry "
        "to _CLIENT_FILES with the reason it is safe."
    )

    stale = sorted(declared - found)
    assert stale == [], (
        f"these entries in _CLIENT_FILES no longer open a Redis client: {stale} — "
        "the map is what keeps a new client call from arriving unnoticed, so a "
        "stale entry weakens it"
    )


def test_every_test_that_reaches_a_broker_takes_the_fixture() -> None:
    offenders: list[str] = []
    for name in _FIXTURE_GATED_FILES:
        offenders.extend(_ungated_tests(_TESTS / name))

    assert offenders == [], (
        f"a test that opens (or reaches a helper that opens) a broker connection "
        f"must take the `{_BROKER_FIXTURE}` fixture, so that a run without a broker "
        "skips it with a reason instead of failing:\n  " + "\n  ".join(offenders)
    )


def test_the_broker_fixture_refuses_a_silent_skip_when_ci_requires_integration() -> None:
    source = _CONFTEST.read_text(encoding="utf-8")

    assert f"def {_BROKER_FIXTURE}(" in source, (
        f"tests/conftest.py no longer defines the {_BROKER_FIXTURE} fixture the "
        "broker-dependent tests are gated on"
    )
    assert re.search(r'os\.environ\.get\(\s*"REQUIRE_INTEGRATION"\s*\)\s*==\s*"1"', source), (
        "the fixture must fail — not skip — when REQUIRE_INTEGRATION=1: a job that "
        "was given a broker and lost it must not report success on tests that never "
        "ran"
    )
    assert "redis_url_for_display(" in source, (
        "the skip and failure messages must name the broker through "
        "redis_url_for_display, because REDIS_URL carries a password"
    )


def test_the_skip_message_never_carries_the_broker_password() -> None:
    from tests.conftest import redis_url_for_display

    shown = redis_url_for_display("redis://:s3cret-password@redis:6379/0")

    assert shown == "redis://redis:6379/0"
    assert "s3cret-password" not in shown


def test_the_jobs_that_own_these_tests_have_a_broker() -> None:
    """The skip above is for environments without one; these are the ones with."""
    suite_steps = _suite_steps()
    assert suite_steps, f"{_SUITE_JOB} runs no step that collects the default suite"
    for step in suite_steps:
        environment = step.get("env") or {}
        assert environment.get("REDIS_URL"), (
            f"a pytest step of {_SUITE_JOB} has no REDIS_URL, so the broker-dependent "
            "tests would skip in the only run that executes this suite"
        )

    integration_env = [
        step.get("env") or {}
        for step in _steps(_INTEGRATION_JOB)
        if "-m integration" in str(step.get("run") or "")
    ]
    assert integration_env, f"{_INTEGRATION_JOB} no longer selects `-m integration`"
    for environment in integration_env:
        assert environment.get("REQUIRE_INTEGRATION") == "1", (
            f"{_INTEGRATION_JOB} must forbid skipping, or a broker that stopped being "
            "reachable reads as a pass"
        )
        assert environment.get("INTEGRATION_REDIS_URL"), (
            "the integration suites read INTEGRATION_REDIS_URL for their broker"
        )


def test_the_suite_job_starts_the_broker_its_redis_url_points_at() -> None:
    """`REDIS_URL` pointing at a port nothing listens on is the same silent skip.

    The test above reads the environment; this one reads the service containers
    that make that environment reachable. A job that sets `REDIS_URL` while
    starting no broker is indistinguishable, in a report, from a run that had no
    broker to begin with — which is exactly why the fixture cannot warn about it
    and a gate has to.
    """
    services = _job(_SUITE_JOB).get("services") or {}
    brokers = {
        name: service
        for name, service in services.items()
        if "redis" in str(name).lower()
        or "redis" in str((service or {}).get("image", "")).lower()
    }
    assert brokers, (
        f"{_SUITE_JOB} runs the default suite with REDIS_URL set but declares no "
        "Redis service, so the broker-dependent tests skip in the only run that "
        "executes this suite"
    )

    published = _published_host_ports(brokers)
    for step in _suite_steps():
        url = str((step.get("env") or {}).get("REDIS_URL") or "")
        port = urlsplit(url).port
        assert port in published, (
            f"{_SUITE_JOB} points REDIS_URL at {url}, but no Redis service in that "
            f"job publishes port {port} (published: {sorted(published)}) — the "
            "fixture's probe would find nothing and skip"
        )
