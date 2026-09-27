"""The wiring behind the HSTS switch, checked without starting anything.

`tests/test_hsts_rendering.py` proves that the entrypoint fragment turns three
values into a correct directive. This file proves the values reach it, and that
nothing else in the project disagrees with them:

* `.env.example` documents the three settings, and its values are the ones
  `app.core.config` uses as defaults;
* `docker-compose.yml` passes all three to *both* services that can answer an HTTP
  request — the API and the UI's nginx — so a deployment cannot end up with the
  header on one and not the other;
* `docker/nginx/default.conf` includes the rendered fragment in every location
  that declares a header of its own (nginx drops the enclosing block's headers the
  moment a location adds one) and declares no literal HSTS value of its own;
* the frontend image installs and executes the fragment;
* `app.main` adds the header from the same settings, and only when they say so.

The Compose and nginx files are read as text, deliberately: the repository's other
gates do the same, so the hygiene job can run them without installing a YAML
parser, and the shapes these files have are known here.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Dict, List, Tuple

import pytest
from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import PlainTextResponse

from app import main as main_module
from app.core.config import Settings

_ROOT = Path(__file__).resolve().parents[2]
_COMPOSE = _ROOT / "docker-compose.yml"
_TEMPLATE = _ROOT / ".env.example"
_NGINX = _ROOT / "docker/nginx/default.conf"
_FRONTEND_DOCKERFILE = _ROOT / "frontend/Dockerfile"

_MISSING = [path.name for path in (_COMPOSE, _TEMPLATE, _NGINX, _FRONTEND_DOCKERFILE) if not path.is_file()]
if _MISSING:
    # The tooling overlay mounts these read-only at the paths this suite resolves;
    # a trimmed checkout cannot answer the question.
    pytest.skip(
        f"not a repository checkout: {', '.join(_MISSING)} missing",
        allow_module_level=True,
    )

_VARIABLES = ("HSTS_ENABLED", "HSTS_MAX_AGE", "HSTS_INCLUDE_SUBDOMAINS")
_INCLUDE = "include /etc/nginx/hsts.inc;"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _service_block(compose: str, name: str) -> str:
    """The lines of one Compose service, by indentation rather than by YAML."""
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


def _template_values() -> Dict[str, str]:
    """The active (uncommented) entries of `.env.example`."""
    return dict(re.findall(r"^([A-Z_][A-Z0-9_]*)=(.*)$", _text(_TEMPLATE), flags=re.M))


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
        if stripped.count("{") - stripped.count("}") < 0:
            continue
        if sum(part.count("{") - part.count("}") for part in lines) == 0:
            blocks.append((opening, "\n".join(lines)))
            opening = None
    return blocks


# ==============================================================================
# One set of names, everywhere
# ==============================================================================
def test_every_setting_is_documented_with_the_application_default() -> None:
    template = _template_values()
    settings = Settings(_env_file=None)

    assert template["HSTS_ENABLED"] == str(settings.HSTS_ENABLED).lower() == "false"
    assert template["HSTS_MAX_AGE"] == str(settings.HSTS_MAX_AGE) == "31536000"
    assert (
        template["HSTS_INCLUDE_SUBDOMAINS"]
        == str(settings.HSTS_INCLUDE_SUBDOMAINS).lower()
        == "false"
    )


def test_the_template_explains_why_the_default_is_off() -> None:
    """The reasoning is the setting's documentation, not a nice-to-have.

    An operator who has never thought about HSTS has to be able to find out from
    the file in front of them that turning it on is a one-way promise.
    """
    text = _text(_TEMPLATE)
    section = text[text.index("HSTS_ENABLED=") - 2000: text.index("HSTS_ENABLED=")]

    assert "HSTS" in section
    assert "remember" in section.lower()
    assert "self-signed" in section.lower()


def test_compose_passes_every_setting_to_both_http_services() -> None:
    """The API and the UI's nginx both answer requests for the same host.

    A header that only one of them sends is a control that works until the other
    service answers, which is the kind of gap nobody notices until an audit.
    """
    compose = _text(_COMPOSE)

    for service in ("backend", "frontend"):
        block = _service_block(compose, service)
        for name in _VARIABLES:
            assert f"{name}: ${{{name}:-" in block, (service, name)


def test_the_compose_fallbacks_match_the_application_defaults() -> None:
    """A service started without the variable behaves like the documentation says."""
    compose = _text(_COMPOSE)
    template = _template_values()

    for name in _VARIABLES:
        for service in ("backend", "frontend"):
            block = _service_block(compose, service)
            # Built by concatenation rather than as an f-string: the braces that
            # Compose syntax needs are the same ones an f-string consumes.
            pattern = name + r": \$\{" + name + r":-(?P<value>[^}]*)\}"
            match = re.search(pattern, block)
            assert match is not None, (service, name)
            assert match.group("value") == template[name], (service, name)


def test_the_entrypoint_fragment_defaults_the_same_way() -> None:
    """The third reader of the same three names: the shell script."""
    script = _text(_ROOT / "docker/nginx/hsts.sh")
    template = _template_values()

    for name in _VARIABLES:
        assert f'{name}="${{{name}:-{template[name]}}}"' in script, name


# ==============================================================================
# The server configuration
# ==============================================================================
def test_nginx_carries_no_hardcoded_hsts_value() -> None:
    """The defect this replaced: a promise compiled into the image.

    It was unconditional, so every installation sent it — including the ones with
    a self-signed certificate, which is the case the header is worst for.
    """
    nginx = _text(_NGINX)

    assert "add_header Strict-Transport-Security" not in nginx
    # The value lives in the rendered include, which is the only thing that can
    # vary per deployment.
    assert nginx.count(_INCLUDE) >= 3


def test_every_location_with_its_own_headers_includes_the_fragment() -> None:
    """nginx drops the enclosing block's `add_header` directives per location.

    So a location that declares one has to declare the HSTS include too, or the
    header silently disappears for the responses that location serves — the exact
    mistake the flat list of headers in this file was copied three times to avoid.
    """
    blocks = _locations(_text(_NGINX))
    with_headers = [(opening, block) for opening, block in blocks if "add_header" in block]

    assert len(with_headers) >= 3, "the server, the API and the SPA locations"
    for opening, block in with_headers:
        assert _INCLUDE in block, opening


def test_the_frontend_image_installs_and_runs_the_fragment() -> None:
    dockerfile = _text(_FRONTEND_DOCKERFILE)

    assert "COPY ./docker/nginx/hsts.sh /docker-entrypoint.d/" in dockerfile
    assert re.search(r"chmod 0755 /docker-entrypoint\.d/\S+hsts\.sh", dockerfile)
    # A default so the configuration parses in the built image and in any start
    # that bypasses the entrypoint; the entrypoint overwrites it.
    assert "/etc/nginx/hsts.inc" in dockerfile
    # The path the include names, so a rename cannot half-happen.
    assert _INCLUDE in _text(_NGINX)


# ==============================================================================
# The API's half of the same promise
# ==============================================================================
def test_the_static_header_set_carries_no_hsts() -> None:
    """It used to, and that is exactly why it could not be configured."""
    assert "Strict-Transport-Security" not in main_module._SECURITY_HEADERS


def test_the_api_builds_the_header_from_the_settings() -> None:
    off = Settings(_env_file=None, HSTS_ENABLED=False)
    basic = Settings(_env_file=None, HSTS_ENABLED=True, HSTS_MAX_AGE=600)
    subdomains = Settings(
        _env_file=None,
        HSTS_ENABLED=True,
        HSTS_MAX_AGE=600,
        HSTS_INCLUDE_SUBDOMAINS=True,
    )

    assert off.hsts_header_value == ""
    assert basic.hsts_header_value == "max-age=600"
    assert subdomains.hsts_header_value == "max-age=600; includeSubDomains"


def test_a_zero_window_is_refused_rather_than_clamped() -> None:
    """`max-age=0` means `forget HSTS`: the opposite of the switch that produced it."""
    with pytest.raises(ValidationError) as caught:
        Settings(_env_file=None, HSTS_ENABLED=True, HSTS_MAX_AGE=0)

    assert "HSTS_MAX_AGE" in str(caught.value)
    # Disabled with a zero window is not a contradiction: no header is sent.
    assert Settings(_env_file=None, HSTS_ENABLED=False, HSTS_MAX_AGE=0).hsts_header_value == ""


def _dispatch() -> Dict[str, str]:
    """Run one request through the real security-headers middleware."""

    async def call_next(request: Request) -> PlainTextResponse:
        return PlainTextResponse("ok")

    middleware = main_module.SecurityHeadersMiddleware(app=None)  # type: ignore[arg-type]
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "root_path": "",
        "headers": [],
        "client": ("127.0.0.1", 1234),
        "server": ("testserver", 80),
    }
    response = asyncio.run(
        middleware.dispatch(Request(scope), call_next)  # type: ignore[arg-type]
    )
    return {key.lower(): value for key, value in response.headers.items()}


def _with_settings(monkeypatch: pytest.MonkeyPatch, **values: object) -> None:
    from app.core.config import settings as live_settings

    for name, value in values.items():
        monkeypatch.setattr(live_settings, name, value)


def test_the_middleware_sends_the_header_only_when_it_is_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _with_settings(monkeypatch, HSTS_ENABLED=False)
    assert "strict-transport-security" not in _dispatch()

    _with_settings(monkeypatch, HSTS_ENABLED=True, HSTS_MAX_AGE=600, HSTS_INCLUDE_SUBDOMAINS=True)
    assert _dispatch()["strict-transport-security"] == "max-age=600; includeSubDomains"


def test_the_middleware_keeps_a_header_a_terminator_already_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`setdefault`, not assignment: a proxy that sets its own value wins."""
    _with_settings(monkeypatch, HSTS_ENABLED=True, HSTS_MAX_AGE=600)

    async def call_next(request: Request) -> PlainTextResponse:
        response = PlainTextResponse("ok")
        response.headers["Strict-Transport-Security"] = "max-age=1"
        return response

    middleware = main_module.SecurityHeadersMiddleware(app=None)  # type: ignore[arg-type]
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "root_path": "",
        "headers": [],
        "client": ("127.0.0.1", 1234),
        "server": ("testserver", 443),
    }
    response = asyncio.run(middleware.dispatch(Request(scope), call_next))  # type: ignore[arg-type]

    assert response.headers["Strict-Transport-Security"] == "max-age=1"
