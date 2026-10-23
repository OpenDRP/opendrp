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
4. **Every service is hardened, and the exceptions are stated.** `security_opt:
   no-new-privileges`, `cap_drop: [ALL]` and (where the process can live with it)
   a read-only root filesystem are what turn a compromised service into a
   contained one. Three services — the datastores and the web server — shipped
   without any of it, and nothing failed: hardening is invisible until the day it
   is needed. A service that cannot carry it belongs in `_HARDENING_EXCEPTIONS`
   *with the reason written out*, so a deliberate exception and a forgotten line
   do not look the same.
5. **The documented resource limits are the ones in this file.** The tables in
   `docs/configuration.md` told an operator that a limit was 1 GB while Compose
   said something else, and they listed eight services out of twenty-six:
   capacity planning from a page that disagrees with the deployment is worse than
   no page. The table is parsed and compared here rather than trusted — and so are
   the *sums* the two host-sizing pages publish (`configuration.md`'s cumulative
   rows and `deployment.md`'s host requirements), which are the same arithmetic
   one step removed: both had drifted by 1.0 GiB and 1.25 CPU while the per-service
   table beside them stayed green, because a sum nobody recomputes is a copy.
6. **The network split and the broker password are still in place.** Connectors
   are third-party code by this platform's own design, and they are one Compose
   edit away from being re-attached to the network that holds PostgreSQL and an
   unauthenticated-task-injecting broker. Nothing at runtime complains: the
   stack comes up healthy and the isolation is simply gone. So the file is
   checked rather than trusted, and `REDIS_URL` is checked for a password in the
   same breath, because a password that no client sends is decoration.
7. **The trusted proxy range is the edge, and only the edge.** A trusted network
   is a network whose `X-Forwarded-For` entries are believed, so whichever range
   is appended to `TRUSTED_PROXY_IPS` can write any address it likes into the
   audit trail. The parent range is the wrong answer for a reason that is easy
   to miss: it contains the connector network, and connectors are the one part of
   the deployment this platform did not write. The appended range is therefore
   parsed, required to be the edge subnet, and compared against the parent, data
   and connector subnets.

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

#: Service -> why it is allowed to carry no container hardening. The reason is
#: part of the entry on purpose: an exception list without one is how "we will
#: look at this later" becomes permanent. Empty is the correct state — every
#: service in `docker-compose.yml` is hardened — and the mechanism exists so that
#: a future service has to be named here rather than quietly skipped.
_HARDENING_EXCEPTIONS: dict[str, str] = {}

#: The operations reference that documents the limits, and the row shape the
#: gate parses: `| `postgres` | `1.5g` | `1.0` | `256` |`. Values are compared
#: exactly as Compose writes them, so a limit changed in one place and not the
#: other fails the build instead of waiting for an operator to notice.
_LIMITS_DOC = Path("docs") / "configuration.md"
_LIMITS_TABLE_ROW = re.compile(
    r"^\|\s*`(?P<service>[a-z0-9-]+)`\s*\|\s*`(?P<mem>[^`]+)`\s*\|\s*"
    r"`(?P<cpus>[^`]+)`\s*\|\s*`(?P<pids>[^`]+)`\s*\|$"
)

#: A published total: `| <label> | 8.0 GiB | 9.0 | ... |`. Only these rows match;
#: the per-service table above writes `1.5g`, not `GiB`.
_TOTALS_ROW = re.compile(
    r"^\|\s*(?P<label>[^|]+?)\s*\|\s*(?P<mem>\d+(?:\.\d+)?)\s*GiB\s*\|\s*"
    r"(?P<cpu>\d+(?:\.\d+)?)\s*\|"
)

#: The profile sets behind each published total, in the order the table lists
#: them. Both tables are cumulative: a row adds the profiles it names to the row
#: above it. A service under a profile no set here covers is a finding — the sums
#: claim to account for every service in the file, so a new profile has to be
#: given a row rather than silently left out of the arithmetic.
_TOTAL_SETS: tuple[tuple[Path, tuple[frozenset[str], ...]], ...] = (
    (
        Path("docs") / "configuration.md",
        (
            frozenset(),
            frozenset({"netlas"}),
            frozenset({"netlas", "netlas-endpoints", "shodan-endpoints"}),
            frozenset(
                {
                    "netlas",
                    "netlas-endpoints",
                    "shodan-endpoints",
                    "shodan",
                    "hibp",
                    "virustotal",
                }
            ),
            frozenset(
                {
                    "netlas",
                    "netlas-endpoints",
                    "shodan-endpoints",
                    "shodan",
                    "hibp",
                    "virustotal",
                    "backup",
                }
            ),
        ),
    ),
    (
        Path("docs") / "deployment.md",
        (
            frozenset(),
            frozenset({"backup"}),
            frozenset({"netlas", "shodan", "hibp", "virustotal"}),
        ),
    ),
)

#: The sentence that prices the two endpoint workers separately, because they
#: belong to no row of the host-requirement table.
_ENDPOINT_TOTAL = re.compile(
    r"add\s+(?P<mem>\d+(?:\.\d+)?)\s*GiB\s+and\s+(?P<cpu>\d+(?:\.\d+)?)\s*CPU"
)
_ENDPOINT_PROFILES = frozenset({"netlas-endpoints", "shodan-endpoints"})


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

#: The interpolation a `TRUSTED_PROXY_IPS` value ends with, after the comma that
#: separates it from the operator's own list: Compose appends the range the proxy
#: itself lives in, so that nginx is recognised as a hop. The comma is part of
#: the pattern so that a value which *only* names the operator's own variable —
#: nothing appended — is read as a missing append rather than as a wrong range.
_TRUSTED_PROXY_APPEND = re.compile(
    r",\s*\$\{(?P<variable>[A-Za-z0-9_]+):-(?P<default>[^}]+)\}\s*$"
)


#: The networks a trusted range may not reach into, and what the answer would
#: be if it did. Reaching in counts in both directions: a trusted range inside
#: one of these is a container in it, and one containing it is every container in
#: it. The parent range is not listed here — the edge subnet is *inside* it, so
#: containment alone would flag the correct configuration — and is handled
#: separately, as an entry that contains the parent.
_UNTRUSTABLE_NETWORKS = {
    _DATA_NETWORK: "the data network holds the API's own siblings and the datastores",
    _CONNECTOR_NETWORK: "connectors are code this platform did not write",
}


def _check_subnet_hierarchy(text: str, declared: dict[str, str]) -> list[str]:
    """The subnets sit inside the parent, and only the edge may be trusted.

    Two relationships, both of which fail quietly at runtime. A subnet moved
    outside the parent stops the outbound guard recognising the deployment's own
    addresses; a subnet moved outside the *edge* range means nginx is no longer a
    recognised hop, so every audit row records the proxy's container address
    instead of the client's. The third failure is the one this check was extended
    for: naming the parent range trusted — nginx reaches the API from one of
    these subnets, so appending the whole address space makes every container in
    it able to forge the client address in the audit trail.
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
    resolved: dict[str, ipaddress._BaseNetwork] = {}
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
        resolved[name] = subnet
        if not subnet.subnet_of(parent):
            failures.append(
                f"network `{name}` subnet {subnet} is outside OPENDRP_NETWORK_SUBNET "
                f"({parent}): nginx would no longer be a trusted proxy and audit "
                f"entries would record the proxy address"
            )
    failures.extend(_check_proxy_trust(text, resolved, parent))
    return failures


def _overlaps(
    trusted: ipaddress._BaseNetwork, network: ipaddress._BaseNetwork
) -> bool:
    """Whether a trusted range reaches into another range, either way round."""
    try:
        return trusted.overlaps(network)
    except TypeError:  # an IPv4 range beside an IPv6 one
        return False


def _contains(
    outer: ipaddress._BaseNetwork, inner: ipaddress._BaseNetwork
) -> bool:
    """Whether ``outer`` covers ``inner`` (equal ranges included)."""
    try:
        return outer.supernet_of(inner) or outer == inner
    except TypeError:  # an IPv4 range beside an IPv6 one
        return False


def _check_proxy_trust(
    text: str,
    resolved: dict[str, ipaddress._BaseNetwork],
    parent: ipaddress._BaseNetwork,
) -> list[str]:
    """Only the edge subnet may be appended to `TRUSTED_PROXY_IPS`.

    Read from the services rather than from one expected line, because the same
    mistake can be made in any of them and a service that omits the append is
    the quieter defect of the two: the deployment starts, and the audit trail
    silently names the proxy container for every action.
    """
    failures: list[str] = []
    edge = resolved.get(_EDGE_NETWORK)
    if edge is None:
        failures.append(
            f"network `{_EDGE_NETWORK}` declares no subnet, so the range a request "
            f"from the web server has to be trusted from cannot be checked"
        )

    untrustable: list[tuple[str, ipaddress._BaseNetwork, str]] = []
    for field_name, why in _UNTRUSTABLE_NETWORKS.items():
        network = resolved.get(field_name)
        if network is None:
            continue
        untrustable.append((field_name, network, why))

    services, _line = parse_services(text)
    appended: list[str] = []
    for service in services:
        if service.env(_APPLICATION_MARKER) is None:
            continue
        value = (service.env("TRUSTED_PROXY_IPS") or "").strip()
        if not value:
            # A missing value is `_check_application_settings`'s finding.
            continue
        match = _TRUSTED_PROXY_APPEND.search(value)
        if match is None:
            failures.append(
                f"service `{service.name}` (line {service.line_number}) sets "
                f"`TRUSTED_PROXY_IPS` without appending the network the web "
                f"server reaches it from: nginx is then not a recognised hop and "
                f"every audit row records the proxy's container address instead "
                f"of the client's"
            )
            continue
        variable = match.group("variable")
        appended.append(variable)
        if variable != "OPENDRP_EDGE_SUBNET":
            failures.append(
                f"service `{service.name}` (line {service.line_number}) appends "
                f"${{{variable}}} to `TRUSTED_PROXY_IPS`, and "
                f"{_UNTRUSTABLE_NETWORKS.get(variable, 'that is not the edge network')}: "
                f"a container in a trusted network can put any address it likes in "
                f"`X-Forwarded-For` and have it written into the audit trail. "
                f"Append ${{OPENDRP_EDGE_SUBNET}} instead"
            )
        try:
            trusted = ipaddress.ip_network(match.group("default").strip(), strict=False)
        except ValueError as exc:
            failures.append(
                f"service `{service.name}` (line {service.line_number}) appends a "
                f"`TRUSTED_PROXY_IPS` range that is not a network: {exc}"
            )
            continue
        if _contains(trusted, parent):
            failures.append(
                f"service `{service.name}` (line {service.line_number}) trusts "
                f"{trusted}, which covers OPENDRP_NETWORK_SUBNET ({parent}) and "
                f"therefore every network in the deployment — the connector "
                f"network included, and connectors are code this platform did not "
                f"write. A container in a trusted network can put any address it "
                f"likes in `X-Forwarded-For` and have it written into the audit "
                f"trail. Trust loopback and the edge subnet only"
            )
        else:
            for field_name, network, why in untrustable:
                if _overlaps(trusted, network):
                    failures.append(
                        f"service `{service.name}` (line {service.line_number}) "
                        f"trusts {trusted}, which covers {field_name} ({network}): "
                        f"{why}, so its containers could write any address they "
                        f"liked into the audit trail. Trust loopback and the edge "
                        f"subnet only"
                    )
        if edge is not None and trusted != edge:
            failures.append(
                f"service `{service.name}` (line {service.line_number}) trusts "
                f"{trusted} while the edge network is {edge}: the two disagree, so "
                f"either the web server is not recognised as a hop or a range "
                f"nobody uses is trusted"
            )

    if not appended:
        failures.append(
            "no service running the application appends a trusted range to "
            "`TRUSTED_PROXY_IPS`: the web server reaches the API from its own "
            "network, so its `X-Forwarded-For` is ignored and every audit row "
            "records the proxy address"
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


def _check_hardening(services: list[Service]) -> list[str]:
    """Every service is hardened, or is named in the exception list. """
    failures: list[str] = []
    for service in services:
        exception = _HARDENING_EXCEPTIONS.get(service.name)
        if exception is not None:
            if not exception.strip():
                failures.append(
                    f"service `{service.name}` is listed in "
                    f"_HARDENING_EXCEPTIONS without a reason: an exception "
                    f"nobody has to justify is one nobody revisits"
                )
            continue
        missing = [
            key for key in ("security_opt", "cap_drop") if not service.has(key)
        ]
        if missing:
            failures.append(
                f"service `{service.name}` (line {service.line_number}) lacks "
                f"container hardening: {', '.join(missing)}. `no-new-privileges` "
                f"and dropping every capability are what keep a compromised "
                f"service a contained one; if this service cannot carry them, "
                f"add it to _HARDENING_EXCEPTIONS with the reason"
            )
    return failures


def _check_documented_limits(text: str, limits_doc: Path) -> list[str]:
    """The limits an operator reads are the limits Compose applies.

    Only the per-service rows are compared here. The totals a page may quote are
    derived from them, so a wrong total is a documentation defect this gate
    cannot see — which is why the page is expected to state the rows it is
    summing rather than a number on its own.
    """
    try:
        document = limits_doc.read_text(encoding="utf-8")
    except OSError as exc:
        return [
            f"cannot read the resource table ({limits_doc}): {exc} — the limits "
            f"an operator plans capacity from have to be checkable"
        ]

    documented: dict[str, tuple[str, str, str]] = {}
    failures: list[str] = []
    for number, line in enumerate(document.splitlines(), start=1):
        match = _LIMITS_TABLE_ROW.match(line.strip())
        if match is None:
            continue
        name = match.group("service")
        if name in documented:
            failures.append(
                f"{limits_doc}:{number}: `{name}` appears twice in the resource "
                f"table; the second row would silently win"
            )
        documented[name] = (match.group("mem"), match.group("cpus"), match.group("pids"))

    services, _line = parse_services(text)
    for service in services:
        row = documented.get(service.name)
        if row is None:
            failures.append(
                f"service `{service.name}` is not in the resource table of "
                f"{limits_doc}: a service an operator cannot see is a service "
                f"whose memory, CPU and PID bounds are not planned for"
            )
            continue
        expected = tuple(
            service.inline.get(key, "").strip().strip('"').strip("'")
            for key in ("mem_limit", "cpus", "pids_limit")
        )
        if row != expected:
            failures.append(
                f"the resource table says `{service.name}` is "
                f"{row[0]} / {row[1]} CPU / {row[2]} PIDs while Compose sets "
                f"{expected[0]} / {expected[1]} CPU / {expected[2]} PIDs"
            )

    known = {service.name for service in services}
    for name in sorted(set(documented) - known):
        failures.append(
            f"the resource table documents `{name}`, which is not a service in "
            f"this Compose file: a row that outlives its service is a limit an "
            f"operator would try to reason about"
        )
    return failures


def _profiles(service: Service) -> frozenset[str]:
    """The profiles a service is gated on, as written inline in the file."""
    value = service.inline.get("profiles", "")
    return frozenset(
        part.strip().strip('"').strip("'")
        for part in value.strip().strip("[]").split(",")
        if part.strip()
    )


def _memory_gib(value: str) -> float:
    """A Compose `mem_limit` in GiB: `1.5g`, `512m` or a byte count."""
    text = value.strip().strip('"').strip("'").lower()
    if text.endswith("g"):
        return float(text[:-1])
    if text.endswith("m"):
        return float(text[:-1]) / 1024
    return float(text) / (1024**3)


def _service_cpus(service: Service) -> float:
    return float(service.inline.get("cpus", "0").strip().strip('"'))


def _check_documented_totals(
    text: str, root: Path, documents: tuple[tuple[Path, tuple[frozenset[str], ...]], ...] | None = None
) -> list[str]:
    """The sums an operator sizes a host from are the sums this file produces.

    Two pages publish them — `configuration.md` per cumulative profile set and
    `deployment.md` as host requirements — and both were hand-computed copies of
    the Compose file's `mem_limit`/`cpus` values, neither gated while the
    per-service table beside them was. They had drifted by the same 1.0 GiB and
    1.25 CPU: the base row said 7.0 GiB / 7.75 CPU against a file that sums to
    8.0 / 9.0, and every cumulative row inherited it. Sizing a host from the
    page therefore chose a machine smaller than the caps need, which is the
    failure the page exists to prevent.
    """
    services, _line = parse_services(text)
    failures: list[str] = []
    rows_by_document = documents or _TOTAL_SETS
    covered: set[str] = set()
    for spec in rows_by_document:
        for profiles in spec[1]:
            covered |= set(profiles)

    for name, profiles_set in _profiles_by_service(services).items():
        for profile in profiles_set - covered:
            failures.append(
                f"service `{name}` is gated on profile `{profile}`, which no "
                f"published total accounts for: the sums in the two host-sizing "
                f"pages claim to cover every service, so add the profile to a "
                f"row (and to _TOTAL_SETS) or the page understates the host"
            )

    for relative, expected_sets in rows_by_document:
        path = root / relative
        try:
            document = path.read_text(encoding="utf-8")
        except OSError as exc:
            failures.append(
                f"cannot read the published totals ({path}): {exc} — an operator "
                f"sizes a host from those numbers"
            )
            continue

        rows = [
            match
            for line in document.splitlines()
            if (match := _TOTALS_ROW.match(line.strip())) is not None
        ]
        if len(rows) != len(expected_sets):
            failures.append(
                f"{relative}: the totals table has {len(rows)} row(s) where this "
                f"gate knows {len(expected_sets)} set(s): a row added or removed "
                f"without its arithmetic is a number nobody checks"
            )

        for index, (row, allowed) in enumerate(zip(rows, expected_sets), start=1):
            members = [
                service
                for service in services
                if _profiles(service) <= allowed
            ]
            expected_mem = sum(_memory_gib(service.inline.get("mem_limit", "0")) for service in members)
            expected_cpu = sum(_service_cpus(service) for service in members)
            documented_mem = float(row.group("mem"))
            documented_cpu = float(row.group("cpu"))
            if abs(documented_mem - expected_mem) >= 0.05:
                failures.append(
                    f"{relative}:{index}: the row `{row.group('label')}` says "
                    f"{documented_mem:g} GiB while the services it covers sum to "
                    f"{expected_mem:g} GiB in this file"
                )
            if abs(documented_cpu - expected_cpu) >= 0.005:
                failures.append(
                    f"{relative}:{index}: the row `{row.group('label')}` says "
                    f"{documented_cpu:g} CPU while the services it covers sum to "
                    f"{expected_cpu:g} CPU in this file"
                )

        if relative.name == "deployment.md":
            failures.extend(
                _check_endpoint_total(relative, document, services)
            )

    return failures


def _check_endpoint_total(
    relative: Path, document: str, services: list[Service]
) -> list[str]:
    """The two endpoint workers are priced in prose, outside the table.

    They belong to no row (`netlas-endpoints` and `shodan-endpoints` are enabled
    on their own), so the page states their cost in a sentence an operator adds
    by hand. A sentence that disagrees with the file is the same defect as a row
    that does.
    """
    match = _ENDPOINT_TOTAL.search(document)
    if match is None:
        return [
            f"{relative}: the sentence that prices the endpoint workers is gone "
            f"— those two services belong to no row of the table, so their cost "
            f"has to be stated somewhere an operator reads"
        ]

    endpoints = [
        service for service in services if _profiles(service) & _ENDPOINT_PROFILES
    ]
    expected_mem = sum(
        _memory_gib(service.inline.get("mem_limit", "0")) for service in endpoints
    )
    expected_cpu = sum(_service_cpus(service) for service in endpoints)
    failures: list[str] = []
    if abs(float(match.group("mem")) - expected_mem) >= 0.05:
        failures.append(
            f"{relative}: the endpoint sentence says "
            f"{float(match.group('mem')):g} GiB while the endpoint workers sum to "
            f"{expected_mem:g} GiB in this file"
        )
    if abs(float(match.group("cpu")) - expected_cpu) >= 0.005:
        failures.append(
            f"{relative}: the endpoint sentence says "
            f"{float(match.group('cpu')):g} CPU while the endpoint workers sum to "
            f"{expected_cpu:g} CPU in this file"
        )
    return failures


def _profiles_by_service(services: list[Service]) -> dict[str, frozenset[str]]:
    return {service.name: _profiles(service) for service in services}


def check(
    text: str, compose_dir: Path, limits_doc: Path | None = None
) -> list[str]:
    failures: list[str] = []
    services, services_line = parse_services(text)

    if services_line == 0 or not services:
        return ["no `services:` block found — the file was not parsed as Compose"]

    declared = _declared_networks(text)
    failures.extend(_check_network_split(services, declared))
    failures.extend(_check_subnet_hierarchy(text, declared))
    failures.extend(_check_broker_authentication(services))
    failures.extend(_check_application_settings(services))
    failures.extend(_check_hardening(services))
    failures.extend(
        _check_documented_limits(text, limits_doc or (compose_dir / _LIMITS_DOC))
    )
    failures.extend(_check_documented_totals(text, compose_dir))

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
        f"compose gate: OK — {len(services)} services, each with a healthcheck, "
        f"a bounded logging policy, container hardening and resource limits; an "
        f"authenticated broker; the edge/data/connector network split intact with "
        f"only the edge trusted for forwarded addresses; every documented limit "
        f"equal to the one this file sets, and both host-sizing tables summing to "
        f"the caps it applies"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
