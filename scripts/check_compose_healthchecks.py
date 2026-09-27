#!/usr/bin/env python3
"""Gate the operational invariants of docker-compose.yml.

Two properties of the Compose stack are invisible at runtime until they fail
badly, and both are easy to lose in a later edit:

1. **Every service has a healthcheck** — either in this file or as a
   `HEALTHCHECK` instruction in the Dockerfile it builds from. Without one,
   Compose reports a container as `running` while the process inside it is
   wedged, and `depends_on: condition: service_healthy` silently degrades to
   "started". Most of the stack is only reachable *through* those gates.
2. **Every service has a logging policy.** Docker's json-file driver has no size
   bound by default, so the host accumulates log until the volume fills — and
   for this product a full disk means the audit trail stops being written.
3. **Every process that loads the application is given everything the
   application needs.** A service that carries `APP_ENV` is declaring itself to
   the application, and in production `app.core.config` refuses to load without
   a pinned version, explicit secrets and an explicit proxy allowlist. A
   container missing one of them does not "run without that feature": it
   exits, `restart: unless-stopped` restarts it forever, and the work only that
   container did stops happening — silently, because everything else stays
   healthy. That is how a `celery-beat` without `AUDIT_CHAIN_KEYS` shipped: the
   scheduler holds the alert delivery tick, so findings were stored and no
   notification was ever sent.
4. **The network split and the broker password are still in place.** Connectors
   are third-party code by this platform's own design, and they are one Compose
   edit away from being re-attached to the network that holds PostgreSQL and an
   unauthenticated-task-injecting broker. Nothing at runtime complains: the
   stack comes up healthy and the isolation is simply gone. So the file is
   checked rather than trusted, and `REDIS_URL` is checked for a password in the
   same breath, because a password that no client sends is decoration.

The first two are declared once, in a shared `x-logging` anchor, which makes the
failure mode of a forgotten line a *missing* key rather than a wrong value. A
missing key is exactly what this script can see; the network split is checked
against an explicit expectation instead, so a *wrong* value is visible too.

Deliberately stdlib-only, with a hand-rolled indentation scanner rather than a
YAML parser. The repository-hygiene CI job installs nothing, and the alternative
— adding PyYAML to the toolchain so that a check about Compose can run — buys a
dependency to validate a file whose shape we fully control. The scanner fails
closed: a line it cannot classify is a finding, not something to skip.

Usage:  python scripts/check_compose_healthchecks.py [compose-file]

Exit codes: 0 clean, 1 findings, 2 unreadable input.
"""

from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path

DEFAULT_COMPOSE = Path("docker-compose.yml")

#: Indentation levels of the Compose file as this repository writes it.
_TOP_LEVEL = 0
_SERVICE = 2
_SERVICE_KEY = 4
_SERVICE_KEY_VALUE = 6

#: The three networks the stack defines, and what each one is for.
_DATA_NETWORK = "opendrp-net"
_EDGE_NETWORK = "opendrp-edge"
_CONNECTOR_NETWORK = "opendrp-connectors"

#: Who may attach to the connector network. It exists so that connector
#: containers can reach exactly one thing — the API — and nothing else in the
#: deployment can reach a connector except through its HTTP protocol.
_CONNECTOR_NETWORK_ALLOWED = {"backend"}

#: A service whose environment carries `APP_ENV` is one Compose starts as a
#: process of the platform (the frontend, the datastores, the connectors and the
#: archiver are not, which is why they are left alone — handing *them* the JWT
#: secret would be the same defect in the other direction).
_APPLICATION_MARKER = "APP_ENV"

#: Duplicated from the validators on purpose, like the copies `setup.py` keeps:
#: this gate runs in the repository-hygiene job, which installs nothing, so it
#: cannot import the application to ask it.
#: `backend/tests/test_compose_settings_gate.py` is what keeps the copies honest
#: in both directions — every name here is one the real `Settings` refuses
#: without, and a validator that starts demanding another value fails that file.
#:
#: `AUTH_COOKIE_SECURE` is deliberately absent: its default is `true`, which is
#: the value production demands, so omitting it is safe rather than a finding.
_REFUSED_WITHOUT = (
    "OPENDRP_VERSION",
    "DATABASE_URL",
    "JWT_SECRET_KEY",
    "ENCRYPTION_KEY",
    "AUDIT_CHAIN_KEYS",
    "TRUSTED_PROXY_IPS",
)

#: What a process can be *started* without and then cannot work without. An empty
#: `REDIS_URL` passes validation — the loopback exemption accepts it — and Celery
#: then has no broker to publish to or consume from, which is the same silent
#: failure as an import error: the container stays up and does nothing.
_REQUIRED_TO_WORK = ("REDIS_URL",)

_REQUIRED_APP_SETTINGS = _REFUSED_WITHOUT + _REQUIRED_TO_WORK

#: `redis://:password@host` / `rediss://user:password@host`. The password group
#: is required to be non-empty: `redis://:@host` looks like a credential and is
#: not one.
_REDIS_URL_WITH_PASSWORD = re.compile(r"redis(?:s)?://[^@/]*:[^@/]+@", re.IGNORECASE)

_SERVICE_LINE = re.compile(r"^(\s*)([A-Za-z0-9._-]+):(\s*(.*?))?\s*$")


class Service:
    def __init__(self, name: str, line_number: int) -> None:
        self.name = name
        self.line_number = line_number
        #: direct child key -> {sub-key: line number}
        self.keys: dict[str, dict[str, int]] = {}
        #: direct child key -> the inline value after the colon, if any
        self.inline: dict[str, str] = {}
        #: direct child key -> sub-key -> the inline value written on that line
        #: (`environment` entries, so a `REDIS_URL` can be inspected)
        self.values: dict[str, dict[str, str]] = {}
        #: direct child key -> list items (`networks`, `command`)
        self.items: dict[str, list[str]] = {}
        #: `context`/`dockerfile` from the build block, needed to locate the
        #: Dockerfile when the service relies on an image-level healthcheck
        self.build_values: dict[str, str] = {}

    def has(self, key: str) -> bool:
        return key in self.keys

    def sub_keys(self, key: str) -> dict[str, int]:
        return self.keys.get(key, {})

    def env(self, key: str) -> str | None:
        return self.values.get("environment", {}).get(key)

    def networks(self) -> set[str]:
        return set(self.items.get("networks", []))


def _significant_lines(text: str) -> list[tuple[int, str, int]]:
    """Yield ``(line_number, line, indent)`` for non-blank, non-comment lines.

    Comment lines are dropped entirely, which is what makes the commented-out
    optional services (MailHog, OpenCTI) invisible to the checks instead of
    being reported as services without a healthcheck.
    """
    lines: list[tuple[int, str, int]] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        lines.append((number, raw, indent))
    return lines


def parse_services(text: str) -> tuple[list[Service], int]:
    """Collect services and their direct child keys.

    Returns the services in file order and the line number of the `services:`
    block (or 0 when it is absent).
    """
    services: list[Service] = []
    current: Service | None = None
    section: str | None = None
    in_services = False
    services_line = 0

    for number, line, indent in _significant_lines(text):
        if indent == _TOP_LEVEL:
            # A new top-level key ends the services block (`networks:`,
            # `volumes:`, the `x-...` anchors).
            value = line.split(":", 1)[0].strip()
            in_services = value == "services"
            if in_services:
                services_line = number
            current = None
            section = None
            continue

        if not in_services:
            continue

        # List items are matched before the `key:` pattern rather than after it,
        # because `- opendrp-net` has no colon and `_SERVICE_LINE` therefore never
        # matches it: an item handled inside the key branch is an item that is
        # never seen. Getting this wrong is invisible in the output — every
        # service simply reports as having no `networks:`, which reads like a
        # finding about the Compose file rather than about this scanner.
        if indent >= _SERVICE_KEY_VALUE and line.lstrip().startswith("-"):
            if current is not None and section is not None:
                item = line.lstrip()[1:].strip().strip('"').strip("'")
                current.items.setdefault(section, []).append(item)
            continue

        match = _SERVICE_LINE.match(line)
        if match is None:
            continue
        key = match.group(2)
        inline = (match.group(4) or "").strip()

        if indent == _SERVICE:
            current = Service(key, number)
            services.append(current)
            section = None
        elif indent == _SERVICE_KEY and current is not None:
            section = key
            current.keys.setdefault(key, {})
            current.values.setdefault(key, {})
            current.items.setdefault(key, [])
            if inline:
                current.inline[key] = inline
        elif indent == _SERVICE_KEY_VALUE and current is not None and section is not None:
            current.keys.setdefault(section, {})[key] = number
            current.values.setdefault(section, {})[key] = inline
            if section == "build":
                current.build_values[key] = inline

    return services, services_line


def _declared_networks(text: str) -> dict[str, str]:
    """Top-level `networks:` declarations, as name -> the block's text.

    Read with the same scanner as the services so that the two cannot disagree
    about what counts as a declaration: an indent-2 key is a network only while
    the scanner is inside the top-level `networks:` block, which is what keeps a
    service name from being mistaken for one.
    """
    networks: dict[str, str] = {}
    current: str | None = None
    buffer: list[str] = []

    def flush() -> None:
        nonlocal current, buffer
        if current is not None:
            networks[current] = "\n".join(buffer)
        current = None
        buffer = []

    in_networks = False
    for _number, line, indent in _significant_lines(text):
        if indent == _TOP_LEVEL:
            flush()
            in_networks = line.split(":", 1)[0].strip() == "networks"
            continue
        if not in_networks:
            continue
        if indent == _SERVICE:
            flush()
            current = line.split(":", 1)[0].strip()
            continue
        if current is not None:
            buffer.append(line)

    flush()
    return networks


def _dockerfile_has_healthcheck(compose_dir: Path, service: Service) -> bool:
    """True when the service's build target declares a HEALTHCHECK.

    Connector images carry their own probe because it must run *inside* the
    image (it reads the liveness file the SDK's watchdog writes), so the check
    that a connector is observable belongs in the Dockerfile, not duplicated
    here. A service that declares neither still fails.
    """
    if not service.sub_keys("build"):
        return False
    # Compose resolves `dockerfile` relative to `context`, and `build_values`
    # holds the inline values exactly as written (`./backend`, `./connectors/...`).
    context = service.build_values.get("context", ".") or "."
    dockerfile = service.build_values.get("dockerfile", "Dockerfile") or "Dockerfile"
    candidate = (compose_dir / context / dockerfile).resolve()
    try:
        content = candidate.read_text(encoding="utf-8")
    except OSError:
        return False
    for raw in content.splitlines():
        stripped = raw.strip()
        if stripped.startswith("#"):
            continue
        if stripped.upper().startswith("HEALTHCHECK"):
            return True
    return False


#: A `subnet:` line, with an optional `${VAR:-default}` interpolation. The
#: default is what a fresh checkout gets, so that is what can be checked here.
_SUBNET_LINE = re.compile(r"^\s+-\s*subnet:\s*(?:\$\{[A-Za-z0-9_]+:-)?(?P<value>[^}\s]+)", re.MULTILINE)


def _check_subnet_hierarchy(text: str, declared: dict[str, str]) -> list[str]:
    """Every network subnet must sit inside the range the proxy trust uses.

    `TRUSTED_PROXY_IPS` names the parent range, because nginx reaches the API
    from an address in one of these subnets and an audit row must record the real
    client rather than the proxy's container address. If a subnet is moved
    outside the parent, everything still starts — the audit trail just starts
    recording proxy addresses — so the relationship is checked rather than
    documented.
    """
    parent_match = re.search(
        r"^\s+OPENDRP_NETWORK_SUBNET:\s*\$\{OPENDRP_NETWORK_SUBNET:-([^}]+)\}",
        text,
        re.MULTILINE,
    )
    if parent_match is None:
        return [
            "the API service no longer passes OPENDRP_NETWORK_SUBNET: without it "
            "the outbound guard cannot recognise the deployment's own addresses, "
            "and TRUSTED_PROXY_IPS has no range to name"
        ]
    try:
        parent = ipaddress.ip_network(parent_match.group(1).strip(), strict=False)
    except ValueError as exc:
        return [f"OPENDRP_NETWORK_SUBNET default is not a network: {exc}"]

    failures: list[str] = []
    for name, block in declared.items():
        match = _SUBNET_LINE.search(block)
        if match is None:
            failures.append(
                f"network `{name}` declares no `subnet:`: Compose would pick an "
                f"arbitrary range and the address space the guard treats as "
                f"internal would no longer be predictable"
            )
            continue
        try:
            subnet = ipaddress.ip_network(match.group("value"), strict=False)
        except ValueError as exc:
            failures.append(f"network `{name}` subnet is not a network: {exc}")
            continue
        if not subnet.subnet_of(parent):
            failures.append(
                f"network `{name}` subnet {subnet} is outside OPENDRP_NETWORK_SUBNET "
                f"({parent}): nginx would no longer be a trusted proxy and audit "
                f"entries would record the proxy address"
            )
    return failures


def _check_application_settings(services: list[Service]) -> list[str]:
    """Every application process has to be given what it needs to start."""
    failures: list[str] = []
    for service in services:
        if service.env(_APPLICATION_MARKER) is None:
            continue
        missing = [
            key for key in _REQUIRED_APP_SETTINGS if service.env(key) is None
        ]
        if not missing:
            continue
        failures.append(
            f"service `{service.name}` (line {service.line_number}) runs the "
            f"application but is not given {', '.join(missing)}: in production "
            f"`Settings` refuses to load without "
            f"{'them' if len(missing) > 1 else 'it'}, so the container restarts "
            f"forever instead of doing its job - and the only symptom is that "
            f"whatever only this container did never happens"
        )
    return failures


def _check_broker_authentication(services: list[Service]) -> list[str]:
    """Redis must require a password, and every client must send one."""
    failures: list[str] = []
    for service in services:
        url = service.env("REDIS_URL")
        if url is None:
            continue
        if not _REDIS_URL_WITH_PASSWORD.match(url.strip().strip('"')):
            failures.append(
                f"service `{service.name}` (line {service.line_number}) sets a "
                f"`REDIS_URL` without a password: the Celery broker accepts "
                f"unauthenticated task injection, and a client that does not "
                f"send the password cannot be distinguished from an attacker"
            )

    broker = next((s for s in services if s.name == "redis"), None)
    if broker is None:
        failures.append("no `redis` service: there is no Celery broker to check")
        return failures

    command = " ".join(broker.items.get("command", []))
    if "--requirepass" not in command:
        failures.append(
            f"the `redis` service (line {broker.line_number}) does not start with "
            f"`--requirepass`: every container on the data network could then read "
            f"job payloads and inject tasks the worker executes"
        )
    if broker.env("REDIS_PASSWORD") is None:
        failures.append(
            f"the `redis` service (line {broker.line_number}) does not pass "
            f"`REDIS_PASSWORD` into its own container: the healthcheck reads it "
            f"instead of putting the secret on a command line"
        )
    return failures


def _check_network_split(services: list[Service], declared: dict[str, str]) -> list[str]:
    """Connectors reach the API and nothing else."""
    failures: list[str] = []
    expected = (_DATA_NETWORK, _EDGE_NETWORK, _CONNECTOR_NETWORK)
    for name in expected:
        if name not in declared:
            failures.append(
                f"network `{name}` is not declared: the three-way split (edge, "
                f"data, connectors) is what keeps a connector container away "
                f"from PostgreSQL and the broker"
            )

    for service in services:
        attached = service.networks()
        if not attached:
            failures.append(
                f"service `{service.name}` (line {service.line_number}) declares no "
                f"`networks:`: Compose would attach it to its own default network, "
                f"outside every range this file and the guard know about"
            )
            continue
        unknown = sorted(attached - set(declared))
        if unknown:
            failures.append(
                f"service `{service.name}` (line {service.line_number}) is attached "
                f"to undeclared network(s) {', '.join(unknown)}"
            )
        if service.name.startswith("connector-"):
            for unwanted, why in (
                (_DATA_NETWORK, "PostgreSQL and the unauthenticated-injection broker"),
                (_EDGE_NETWORK, "the internet-facing web server"),
            ):
                if unwanted in attached:
                    failures.append(
                        f"connector `{service.name}` is attached to `{unwanted}` "
                        f"({why}): a plugin is code this platform did not write, "
                        f"so it gets the API token it was issued and nothing else"
                    )
        elif _CONNECTOR_NETWORK in attached and service.name not in _CONNECTOR_NETWORK_ALLOWED:
            failures.append(
                f"service `{service.name}` is attached to `{_CONNECTOR_NETWORK}`: "
                f"only {', '.join(sorted(_CONNECTOR_NETWORK_ALLOWED))} may join "
                f"that network, because it exists to expose the API to plugins"
            )

        if service.name in {"postgres", "redis"} and attached != {_DATA_NETWORK}:
            failures.append(
                f"service `{service.name}` is attached to "
                f"{', '.join(sorted(attached))}: the datastores belong to the "
                f"data network alone"
            )
        if service.name == "frontend" and attached != {_EDGE_NETWORK}:
            failures.append(
                f"the `frontend` service is attached to "
                f"{', '.join(sorted(attached))}: the web server and the API are "
                f"the only members of `{_EDGE_NETWORK}`"
            )

    return failures


def check(text: str, compose_dir: Path) -> list[str]:
    failures: list[str] = []
    services, services_line = parse_services(text)

    if services_line == 0 or not services:
        return ["no `services:` block found — the file was not parsed as Compose"]

    declared = _declared_networks(text)
    failures.extend(_check_network_split(services, declared))
    failures.extend(_check_subnet_hierarchy(text, declared))
    failures.extend(_check_broker_authentication(services))
    failures.extend(_check_application_settings(services))

    for service in services:
        missing_limits = [
            key for key in ("mem_limit", "cpus", "pids_limit")
            if not service.has(key)
        ]
        if missing_limits:
            failures.append(
                f"service `{service.name}` (line {service.line_number}) lacks "
                f"resource limit(s): {', '.join(missing_limits)}. Production "
                "must bound memory, CPU and process count to contain a runaway "
                "scan or compromised service."
            )

    if not re.search(r"^x-logging:\s*&[A-Za-z0-9_-]+", text, re.MULTILINE):
        failures.append(
            "x-logging anchor is missing at top level: services cannot share a "
            "logging policy, so each one has to declare its own (and will not)"
        )

    seen: dict[str, int] = {}
    for service in services:
        if service.name in seen:
            failures.append(
                f"service `{service.name}` is declared twice "
                f"(lines {seen[service.name]} and {service.line_number}); YAML "
                f"keeps the last one and silently drops the first"
            )
        seen[service.name] = service.line_number

        healthcheck_sub_keys = service.sub_keys("healthcheck")
        if not service.has("healthcheck"):
            if _dockerfile_has_healthcheck(compose_dir, service):
                pass  # probed by the image, which is where the probe must run
            else:
                failures.append(
                    f"service `{service.name}` (line {service.line_number}) has no "
                    f"healthcheck in this file and no HEALTHCHECK in the "
                    f"Dockerfile it builds from: a wedged process would still "
                    f"report as running and `depends_on: condition: "
                    f"service_healthy` would degrade to a plain start order"
                )
        elif "test" not in healthcheck_sub_keys:
            failures.append(
                f"service `{service.name}` (line {service.line_number}) declares "
                f"a healthcheck without a `test:` command"
            )

        if not service.has("logging"):
            failures.append(
                f"service `{service.name}` (line {service.line_number}) has no "
                f"logging policy: the json-file driver grows without a bound and "
                f"a full disk stops the audit trail being written"
            )
        elif not service.inline.get("logging") and not service.sub_keys("logging"):
            failures.append(
                f"service `{service.name}` (line {service.line_number}) has an "
                f"empty `logging:` value: it can only be the shared "
                f"`*default-logging` anchor or an explicit driver block"
            )

    return failures


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        print("usage: python scripts/check_compose_healthchecks.py [compose-file]")
        return 2
    path = Path(argv[0]) if argv else DEFAULT_COMPOSE

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"compose gate: FAILED — cannot read {path}: {exc}")
        return 2

    failures = check(text, path.resolve().parent)
    if failures:
        print("compose gate: FAILED")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    services, _line = parse_services(text)
    print(
        f"compose gate: OK — {len(services)} services, each with a healthcheck "
        f"and a bounded logging policy; an authenticated broker; and the "
        f"edge/data/connector network split and resource limits intact"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
