"""The HSTS switch, at the point where it becomes an nginx directive.

HSTS is `Strict-Transport-Security`, and nginx cannot read an environment
variable: the directive is either in the configuration or it is absent. So the
three values an operator sets in `.env` are turned into one directive by
`docker/nginx/hsts.sh`, which the image runs at container start
(`/docker-entrypoint.d/40-opendrp-hsts.sh`).

Both of that switch's failure modes are quiet, which is why they are tested here
rather than trusted:

* **the header is sent when it should not be** — an internal installation with a
  self-signed certificate locks its own users out of the host for `HSTS_MAX_AGE`
  seconds, and no server-side action can withdraw that promise early;
* **the header is not sent when it should be** — the deployment believes it is
  protected by a control that is not there, which only shows up in an audit.

The script is run with `sh`, the way the image runs it. A tiny `nginx` test stub
accepts only `nginx -t`, so a runner's globally installed nginx cannot make these
tests depend on its config or permissions; the directive syntax is asserted here
as text. What loads the rendered include inside a real container is covered by
`tests/test_hsts_wiring.py` (the configuration contract) and by the end-to-end
verification in `docs/deployment.md`.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Tuple

import pytest

from app.core.config import Settings

_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "docker/nginx/hsts.sh"

if not _SCRIPT.is_file():
    # The tooling overlay mounts ./docker read-only at this path for exactly this
    # suite; a trimmed checkout cannot answer the question, and a hard error would
    # look like a broken script.
    pytest.skip(
        f"{_SCRIPT} is not present: run this suite from a repository checkout",
        allow_module_level=True,
    )

#: The one line the include is allowed to consist of.
_ADD_HEADER = re.compile(
    r'^add_header Strict-Transport-Security "max-age=(?P<max_age>\d+)'
    r'(?P<subdomains>; includeSubDomains)?" always;$'
)


def _render(tmp_path: Path, *arguments: str, **environment: str) -> Tuple[subprocess.CompletedProcess, str]:
    """Run the entrypoint fragment, and read the include it wrote (if any).

    The environment is filtered rather than inherited wholesale: a developer whose
    shell exports `HSTS_ENABLED` would otherwise be testing their own setting
    instead of the default this file is asserting.
    """
    include = tmp_path / "hsts.inc"
    env = {key: value for key, value in os.environ.items() if not key.startswith("HSTS_")}
    # Some hosted runners install nginx globally. Put a strict stub first so the
    # script's optional `nginx -t` can never inspect runner config or permissions.
    test_bin = tmp_path / "bin"
    test_bin.mkdir(exist_ok=True)
    nginx_stub = test_bin / "nginx"
    nginx_stub.write_text(
        '#!/bin/sh\n[ "$#" -eq 1 ] && [ "$1" = "-t" ] || exit 2\n',
        encoding="utf-8",
    )
    nginx_stub.chmod(0o755)
    env["PATH"] = os.pathsep.join((str(test_bin), os.environ.get("PATH", "")))
    env.update(environment)
    result = subprocess.run(
        ["sh", str(_SCRIPT), *arguments, str(include)],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    text = include.read_text(encoding="utf-8") if include.is_file() else ""
    return result, text


def test_the_shipped_default_sends_no_header(tmp_path: Path) -> None:
    """Off is the default, and off means the directive is absent.

    Not "present with an empty value": a header whose name says HTTPS-only is
    worse than useless when it is actually sent, and an operator who never set
    anything must not be able to get one by accident.
    """
    result, text = _render(tmp_path)

    assert result.returncode == 0
    assert "add_header" not in text
    assert "HSTS_ENABLED" in text  # the include says why it is empty
    assert "disabled" in result.stdout.lower()


def test_the_script_default_matches_the_application_default(tmp_path: Path) -> None:
    """One default, three places that read it: script, compose and `Settings`.

    A disagreement here is a deployment whose API and web server send different
    promises about the same host, which is worse than either one alone.
    """
    settings = Settings(_env_file=None)
    result, text = _render(tmp_path, HSTS_ENABLED="true")
    match = _ADD_HEADER.match(text.strip())

    assert result.returncode == 0
    assert match is not None, text
    assert int(match.group("max_age")) == settings.HSTS_MAX_AGE
    assert settings.HSTS_ENABLED is False


def test_enabled_renders_one_parseable_directive(tmp_path: Path) -> None:
    result, text = _render(tmp_path, HSTS_ENABLED="true", HSTS_MAX_AGE="604800")
    match = _ADD_HEADER.match(text.strip())

    assert result.returncode == 0
    assert match is not None, text
    assert match.group("max_age") == "604800"
    # `includeSubDomains` is a promise about hosts this deployment may not
    # control, so it is not implied by turning HSTS on.
    assert match.group("subdomains") is None
    assert text.count("add_header") == 1


def test_include_subdomains_is_opt_in(tmp_path: Path) -> None:
    result, text = _render(
        tmp_path,
        HSTS_ENABLED="true",
        HSTS_INCLUDE_SUBDOMAINS="true",
    )
    match = _ADD_HEADER.match(text.strip())

    assert result.returncode == 0
    assert match is not None, text
    assert match.group("subdomains") == "; includeSubDomains"


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
def test_the_true_spellings_the_application_accepts_are_accepted(tmp_path: Path, value: str) -> None:
    result, text = _render(tmp_path, HSTS_ENABLED=value)

    assert result.returncode == 0
    assert "add_header" in text


@pytest.mark.parametrize("value", ["false", "0", "no", "off", "", "ture", "yes please"])
def test_anything_else_means_off_rather_than_on(tmp_path: Path, value: str) -> None:
    """A typo must fail safe: this header is the one thing that cannot be undone.

    `ture`, notably, is what someone types at the end of a long day, and the cost
    of reading it as "on" is a year of browsers refusing HTTP for a host whose
    certificate is self-signed.
    """
    result, text = _render(tmp_path, HSTS_ENABLED=value)

    assert result.returncode == 0
    assert "add_header" not in text


@pytest.mark.parametrize("value", ["0", "-1", "1y", "31536000s", "1e9", "forever"])
def test_a_window_nginx_cannot_use_is_refused(tmp_path: Path, value: str) -> None:
    """Refused, not clamped: the two meanings are `forget HSTS` and `remember it`.

    `max-age=0` is how a server tells a browser to *discard* HSTS, so an operator
    who typed it while enabling HSTS meant something, and guessing which of the
    two is how a security setting ends up doing the reverse of its own name. The
    include is not written at all, so a refused value cannot reach nginx.
    """
    result, text = _render(tmp_path, HSTS_ENABLED="true", HSTS_MAX_AGE=value)

    assert result.returncode == 2, (value, result.stdout, result.stderr)
    assert text == ""
    assert "HSTS_MAX_AGE" in result.stderr


def test_an_empty_max_age_falls_back_to_the_default(tmp_path: Path) -> None:
    """`${VAR:-default}` semantics, asserted so nobody has to guess which applies."""
    result, text = _render(tmp_path, HSTS_ENABLED="true", HSTS_MAX_AGE="")
    match = _ADD_HEADER.match(text.strip())

    assert result.returncode == 0
    assert match is not None, text
    assert int(match.group("max_age")) == Settings(_env_file=None).HSTS_MAX_AGE


def test_check_mode_answers_without_writing(tmp_path: Path) -> None:
    """What a diagnostic (or an operator) uses to ask "is HSTS on right now?"."""
    on, _ = _render(tmp_path, "--check", HSTS_ENABLED="true")
    off, _ = _render(tmp_path, "--check", HSTS_ENABLED="false")

    assert on.returncode == 0
    assert off.returncode == 1
    assert not (tmp_path / "hsts.inc").exists()


def test_an_unknown_option_is_an_input_error(tmp_path: Path) -> None:
    result, _ = _render(tmp_path, "--hsts")

    assert result.returncode == 2
    assert "unknown option" in result.stderr


def test_the_message_says_what_was_configured(tmp_path: Path) -> None:
    """The container log is the only record of which promise is being made."""
    enabled, _ = _render(tmp_path, HSTS_ENABLED="true", HSTS_MAX_AGE="600")
    disabled, _ = _render(tmp_path, HSTS_ENABLED="false")

    assert "600" in enabled.stdout
    assert "disabled" in disabled.stdout.lower()


def test_the_script_needs_nothing_but_a_posix_shell(tmp_path: Path) -> None:
    """It runs inside `nginx:alpine`, before the server starts.

    That image has busybox rather than GNU coreutils, and no bash: a bashism here
    is a frontend container that never starts, and the failure arrives as
    "dependency failed to start" from Compose. `sh` in the test container is dash,
    which is the same shell, so running the script is itself part of the proof.
    """
    source = _SCRIPT.read_text(encoding="utf-8")

    assert source.startswith("#!/bin/sh")
    for bashism in ("[[", "function ", "declare ", "local ", "pipefail", "$RANDOM"):
        assert bashism not in source, bashism

    result, text = _render(tmp_path, HSTS_ENABLED="true", HSTS_MAX_AGE="600")
    assert result.returncode == 0, result.stderr
    assert "add_header" in text
