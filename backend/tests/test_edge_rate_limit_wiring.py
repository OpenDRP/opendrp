"""The edge rate limits, and the address they are keyed on.

The application's own limiter is per account and deliberately fails open when
Redis is unreachable — that is a documented trade (`docs/security.md`, accepted
risks). What has to remain true in that state is a bound that needs no backing
store at all, and that is what `limit_req`/`limit_conn` in the shipped nginx
configuration are for. Two things can quietly make them useless, and neither
shows up as a failed request:

* **the zones are not applied**, or are applied to the wrong location, so the
  directives parse and nothing is ever refused;
* **the key is the wrong address** — behind the TLS terminator the peer is the
  proxy, so without the realip module every client of the installation shares one
  bucket, and a single busy browser rate-limits everybody else.

The second is checked by running the entrypoint fragment that renders the trusted
-proxy list, the same way the HSTS rendering tests run theirs. The fragment is
what decides whether a client-supplied `X-Forwarded-For` entry counts, so the
tests below assert both directions: a named proxy is rendered, and anything that
is not an address is refused rather than turned into a directive.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple

import pytest

from tests.stub_bin import path as _path_with_nginx_stub

_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "docker/nginx/realip.sh"
_NGINX = _ROOT / "docker/nginx/nginx.conf"
_DEFAULT = _ROOT / "docker/nginx/default.conf"
_HOST_PROXY = _ROOT / "docker/nginx/reverse-proxy.example.conf"
_COMPOSE = _ROOT / "docker-compose.yml"
_TEMPLATE = _ROOT / ".env.example"

_MISSING = [
    path.name
    for path in (_SCRIPT, _NGINX, _DEFAULT, _HOST_PROXY, _COMPOSE, _TEMPLATE)
    if not path.is_file()
]
if _MISSING:
    # The tooling overlay mounts ./docker and the checkout root read-only at the
    # paths this suite resolves; a trimmed checkout cannot answer the question.
    pytest.skip(
        f"not a repository checkout: {', '.join(_MISSING)} missing",
        allow_module_level=True,
    )


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _render(tmp_path: Path, **environment: str) -> Tuple[subprocess.CompletedProcess, str]:
    """Run the entrypoint fragment and read the include it wrote (if any)."""
    include = tmp_path / "realip.inc"
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in {"TRUSTED_PROXY_IPS", "UVICORN_FORWARDED_ALLOW_IPS"}
    }
    # Some runners install nginx globally, so a strict stub goes first: the script's
    # optional `nginx -t` must never inspect this machine's configuration. The stub
    # lives where it can be executed, which is not necessarily where pytest put
    # `tmp_path` — see `tests/stub_bin.py`.
    env["PATH"] = _path_with_nginx_stub()
    env.update(environment)
    result = subprocess.run(
        ["sh", str(_SCRIPT), str(include)],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    text = include.read_text(encoding="utf-8") if include.is_file() else ""
    return result, text


def _locations(nginx: str) -> List[Tuple[str, str]]:
    """Every `location` block, as (opening line, block text)."""
    blocks: List[Tuple[str, str]] = []
    opening: str | None = None
    lines: List[str] = []
    for line in nginx.splitlines():
        stripped = line.strip()
        if opening is None and stripped.startswith("location "):
            opening, lines = stripped, [stripped]
            continue
        if opening is None:
            continue
        lines.append(stripped)
        if sum(part.count("{") - part.count("}") for part in lines) == 0:
            blocks.append((opening, "\n".join(lines)))
            opening = None
    return blocks


def _service_block(compose: str, name: str) -> str:
    lines = compose.splitlines()
    start = next(
        (index for index, line in enumerate(lines) if line.rstrip() == f"  {name}:"),
        None,
    )
    assert start is not None, f"service {name} is not in {_COMPOSE.name}"
    block: List[str] = []
    for line in lines[start + 1:]:
        if line.strip() and not line.startswith("    "):
            break
        block.append(line)
    return "\n".join(block)


# ==============================================================================
# The zones, and where they are applied
# ==============================================================================
def test_the_zones_are_declared_once_at_the_http_level() -> None:
    nginx = _text(_NGINX)

    assert "limit_req_zone $binary_remote_addr zone=opendrp_api:10m" in nginx
    assert "limit_req_zone $binary_remote_addr zone=opendrp_auth:10m" in nginx
    assert "limit_conn_zone $binary_remote_addr zone=opendrp_conn:10m" in nginx
    # 429 rather than nginx's default 503: a refused request is not a broken
    # backend, and the client should not retry it as one.
    assert "limit_req_status 429;" in nginx
    assert "limit_conn_status 429;" in nginx


def test_the_trusted_proxy_list_is_included_at_the_http_level() -> None:
    """`set_real_ip_from` is only valid in `http`, `server` and `location`."""
    nginx = _text(_NGINX)

    assert "include /tmp/opendrp/realip/*.inc;" in nginx
    # Declared before the server blocks are pulled in, so the directive is in
    # scope for every one of them.
    assert nginx.index("include /tmp/opendrp/realip/*.inc;") < nginx.index(
        "include /etc/nginx/conf.d/*.conf;"
    )


def test_the_api_and_auth_locations_apply_the_zones() -> None:
    default = _text(_DEFAULT)
    locations = dict(_locations(default))

    api = next(text for opening, text in locations.items() if opening.startswith("location /api/"))
    auth = next(
        text
        for opening, text in locations.items()
        if opening.startswith("location /api/v1/auth/")
    )

    assert "limit_req zone=opendrp_api burst=60 nodelay;" in api
    assert "limit_conn opendrp_conn 40;" in api
    assert "limit_req zone=opendrp_auth burst=15 nodelay;" in auth
    assert "limit_conn opendrp_conn 20;" in auth
    # `nodelay` is what makes a refused request an immediate 429 instead of a
    # silent queue that keeps the connection open until it times out.
    assert "delay" not in api.split("limit_req")[1].split(";")[0].replace("nodelay", "")


def test_the_authentication_bucket_is_tighter_than_the_api_bucket() -> None:
    """A stuffing run must be refused well before it is expensive.

    The two rates are read from the zones rather than assumed equal, so making
    the auth bucket looser than the general one fails here instead of looking
    like a tuning decision.
    """
    nginx = _text(_NGINX)

    def rate(zone: str) -> int:
        match = re.search(rf"zone={zone}:10m rate=(\d+)r/m;", nginx)
        assert match is not None, zone
        return int(match.group(1))

    assert rate("opendrp_auth") < rate("opendrp_api")


def test_the_host_proxy_applies_the_same_two_buckets() -> None:
    """The example terminator is where `$remote_addr` is the real client."""
    host = _text(_HOST_PROXY)

    assert "limit_req_zone $binary_remote_addr zone=opendrp_host_auth:10m" in host
    assert "limit_req zone=opendrp_host_auth burst=15 nodelay;" in host
    assert "location /api/v1/auth/" in host


# ==============================================================================
# The address the limits are keyed on
# ==============================================================================
def test_a_named_proxy_is_rendered_as_a_trusted_source(tmp_path: Path) -> None:
    result, text = _render(
        tmp_path, TRUSTED_PROXY_IPS="10.0.0.10,10.0.0.0/24"
    )

    assert result.returncode == 0, result.stderr
    assert "set_real_ip_from 10.0.0.10;" in text
    assert "set_real_ip_from 10.0.0.0/24;" in text
    assert "real_ip_header X-Forwarded-For;" in text
    # Recursive: the chain is walked from the right, ignoring trusted hops, which
    # is the same rule the API applies to the audit address.
    assert "real_ip_recursive on;" in text


def test_an_empty_list_trusts_nobody(tmp_path: Path) -> None:
    """The default has to mean "no proxy", not "any proxy"."""
    result, text = _render(tmp_path, TRUSTED_PROXY_IPS="")

    assert result.returncode == 0, result.stderr
    assert "set_real_ip_from" not in text
    assert "real_ip_header" not in text


@pytest.mark.parametrize(
    "value",
    [
        "*",
        "127.0.0.1; }",
        "127.0.0.1;include /etc/passwd",
        "not-an-address",
        "10.0.0.1\nset_real_ip_from 0.0.0.0/0",
    ],
)
def test_anything_that_is_not_an_address_is_refused(tmp_path: Path, value: str) -> None:
    """The value becomes nginx configuration, so it is validated before it lands.

    `*` is the interesting one: it is a legitimate spelling in some proxy
    configurations and exactly the wrong answer here, because every client could
    then choose the address its own limits are counted against.
    """
    result, text = _render(tmp_path, TRUSTED_PROXY_IPS=value)

    assert result.returncode == 2, (value, result.stdout, result.stderr)
    assert "set_real_ip_from" not in text
    assert "TRUSTED_PROXY_IPS" in result.stderr


def test_the_fragment_needs_nothing_but_a_posix_shell() -> None:
    """It runs inside `nginx:alpine`, before the server starts, as busybox sh."""
    source = _SCRIPT.read_text(encoding="utf-8")

    assert source.startswith("#!/bin/sh")
    for bashism in ("[[", "function ", "declare ", "local ", "pipefail", "$RANDOM"):
        assert bashism not in source, bashism


# ==============================================================================
# The value reaches the container
# ==============================================================================
def test_the_frontend_is_given_the_same_trust_list_the_api_uses() -> None:
    """One value, two consumers — a terminator that is trusted by nginx and not
    by the API records the proxy address in every audit row, and one trusted by
    the API and not by nginx gives every client a shared rate-limit bucket."""
    frontend = _service_block(_text(_COMPOSE), "frontend")
    template: Dict[str, str] = dict(
        re.findall(r"^([A-Z_][A-Z0-9_]*)=(.*)$", _text(_TEMPLATE), flags=re.M)
    )

    pattern = r"TRUSTED_PROXY_IPS: \$\{TRUSTED_PROXY_IPS:-(?P<value>[^}]*)\}"
    match = re.search(pattern, frontend)
    assert match is not None, frontend
    assert match.group("value") == template["TRUSTED_PROXY_IPS"]


def test_every_application_process_trusts_the_network_the_web_server_is_on() -> None:
    """The appended range has to be the edge, and the edge has to be a network.

    Trusting the parent range instead would let any container in the deployment —
    the connector network included, which is the part of the deployment this
    platform did not write — choose the address an audit row records. The default
    is compared against the edge network's own declaration, so the two cannot
    drift apart and leave the web server unrecognised as a hop.
    """
    compose = _text(_COMPOSE)
    expected = (
        "TRUSTED_PROXY_IPS: ${TRUSTED_PROXY_IPS:-127.0.0.1,::1},"
        "${OPENDRP_EDGE_SUBNET:-172.18.10.0/24}"
    )

    for name in ("backend", "celery-worker", "celery-beat"):
        block = _service_block(compose, name)
        assert expected in block, block

    assert "- subnet: ${OPENDRP_EDGE_SUBNET:-172.18.10.0/24}" in compose, (
        "the trusted default is not the range the edge network declares"
    )
