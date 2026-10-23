#!/usr/bin/env python3
"""Fail when the platform's version disagrees with itself.

One release version, stated in several places, and nothing joined them:

* ``backend/app/__init__.py`` — what the running process reports on
  ``/api/v1/health`` and in its OpenAPI document;
* ``backend/pyproject.toml`` — what the package metadata says;
* ``CHANGELOG.md`` — what a person reads before upgrading;
* ``connectors/base/opendrp_connector/__init__.py`` — the connector SDK's own
  version, i.e. the version of the runtime every bundled connector imports;
* ``connectors/base/opendrp_connector/base.py`` (``SDK_VERSION``) — the value a
  connector registers with as ``api_version``, which the core stores on the
  connector row and an operator reads as the connector's version;
* ``connectors/base/pyproject.toml`` — the connector SDK package metadata;
* ``frontend/package.json`` — the SPA package metadata, which is the same
  release the build injects as ``VITE_APP_VERSION`` and the UI displays;
* ``.env.example`` — the value a new installation copies as
  ``OPENDRP_VERSION``: the image tag every service is built or pulled as, and the
  value Settings reports;
* ``docker-compose.yml`` — the ``VITE_APP_VERSION`` build argument's fallback,
  which is the version the built SPA displays when ``.env`` names none;
* ``frontend/Dockerfile`` — that argument's own default, which is what a direct
  ``docker build frontend/`` bakes into the bundle.

Those last three were the ones an upgrade leaves behind, because a release bump
edited the seven statements then gated and none of them: the template and the two build
defaults then name the *previous* release, and an installation built from the new
tree displays two versions at once — Settings reads ``OPENDRP_VERSION`` from
``.env.example``, the health endpoint reads this module's ``__version__``.

A mismatch is not cosmetic. It means an instance reports a version no release
note describes, an upgrade guide applies to a tag the code does not contain, and
a bug report cannot be placed on a timeline. It also means the connector images
and the core that talks to them announce different releases while being built
from one tree. The check is what makes "single source of truth" a property of
the repository instead of a claim in a comment.

The wire-protocol revision is deliberately **not** compared: ``protocol_version``
is an integer describing the shape of the connector protocol, not a release, and
it changes on its own schedule.

Deliberately does not consult git: the same repository is checked inside a
container that has no ``.git``, and the release workflow verifies the tag
against ``__version__`` at the point where the tag actually exists.

Usage: python scripts/check_version_consistency.py [repo-root]

Exit codes: 0 clean, 1 mismatch or missing value, 2 unreadable input.
"""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

_APP_INIT = Path("backend") / "app" / "__init__.py"
_PYPROJECT = Path("backend") / "pyproject.toml"
_CHANGELOG = Path("CHANGELOG.md")
_SDK_INIT = Path("connectors") / "base" / "opendrp_connector" / "__init__.py"
_SDK_BASE = Path("connectors") / "base" / "opendrp_connector" / "base.py"
_SDK_PYPROJECT = Path("connectors") / "base" / "pyproject.toml"
_FRONTEND_PACKAGE = Path("frontend") / "package.json"
_ENV_EXAMPLE = Path(".env.example")
_COMPOSE = Path("docker-compose.yml")
_FRONTEND_DOCKERFILE = Path("frontend") / "Dockerfile"

_HEADING = re.compile(r"^##\s+\[([^\]]+)\]", re.MULTILINE)
_UNRELEASED = "unreleased"


def _assigned_constant(source: str, name: str) -> str | None:
    """Read a module-level ``name = "..."`` through the AST.

    A regex finds the assignment in a comment or a string literal; the parser
    only finds the real one.
    """
    for node in ast.parse(source).body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Name)
                and target.id == name
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                return node.value.value
    return None


def _toml_version(source: str, table: str) -> str | None:
    """A ``version`` from one table, PEP 621 (``project``) or Poetry alike."""
    try:
        import tomllib  # Python 3.11+
    except ModuleNotFoundError:  # pragma: no cover - CI runs 3.12
        match = re.search(
            rf"^\[{re.escape(table)}\](.*?)(^\[|\Z)", source, re.MULTILINE | re.DOTALL
        )
        if not match:
            return None
        version = re.search(r'^version\s*=\s*"([^"]+)"', match.group(1), re.MULTILINE)
        return version.group(1) if version else None
    try:
        data = tomllib.loads(source)
    except tomllib.TOMLDecodeError:
        return None
    section: object = data
    for part in table.split("."):
        if not isinstance(section, dict):
            return None
        section = section.get(part)
    if not isinstance(section, dict):
        return None
    version = section.get("version")
    return version if isinstance(version, str) else None


def _json_version(source: str) -> str | None:
    try:
        data = json.loads(source)
    except ValueError:
        return None
    version = data.get("version") if isinstance(data, dict) else None
    return version if isinstance(version, str) else None


def _changelog_version(source: str) -> str | None:
    """The newest released version, skipping an ``Unreleased`` section.

    ``Unreleased`` is where changes accumulate between releases, so it is the one
    heading that is allowed to differ from the code's version.
    """
    for heading in _HEADING.findall(source):
        if heading.strip().lower() != _UNRELEASED:
            return heading.strip()
    return None


def _env_value(source: str, key: str) -> str | None:
    """A ``KEY=value`` line from a dotenv template, quotes removed."""
    match = re.search(rf"^{re.escape(key)}\s*=\s*(\S+)\s*$", source, re.MULTILINE)
    return match.group(1).strip("\"'") if match else None


def _compose_display_version(source: str) -> str | None:
    """The fallback Compose substitutes into the SPA's build argument.

    Only the *display* version is read. The image tag falls back to ``latest``
    and the API's own ``OPENDRP_VERSION`` to ``dev``; neither is a release, and
    both are deliberate (an installation must pin one, and an unpinned
    development process reports the code it is running). ``VITE_APP_VERSION`` is
    different: it is the string the UI prints, so a stale default is a wrong
    answer rather than a missing pin.
    """
    match = re.search(r"VITE_APP_VERSION:\s*\$\{OPENDRP_VERSION:-([^}]+)\}", source)
    return match.group(1).strip() if match else None


def _dockerfile_arg(source: str, name: str) -> str | None:
    """A ``ARG NAME=value`` default from a Dockerfile."""
    match = re.search(rf"^ARG\s+{re.escape(name)}=(\S+)\s*$", source, re.MULTILINE)
    return match.group(1).strip("\"'") if match else None


#: Every place the release version is stated, with the reader that extracts it.
#: Order is the order failures are reported in.
READINGS = (
    ("backend/app/__init__.py", _APP_INIT, lambda source: _assigned_constant(source, "__version__")),
    ("backend/pyproject.toml", _PYPROJECT, lambda source: _toml_version(source, "tool.poetry")),
    ("CHANGELOG.md", _CHANGELOG, _changelog_version),
    (
        "connectors/base/opendrp_connector/__init__.py",
        _SDK_INIT,
        lambda source: _assigned_constant(source, "__version__"),
    ),
    (
        "connectors/base/opendrp_connector/base.py",
        _SDK_BASE,
        lambda source: _assigned_constant(source, "SDK_VERSION"),
    ),
    ("connectors/base/pyproject.toml", _SDK_PYPROJECT, lambda source: _toml_version(source, "project")),
    ("frontend/package.json", _FRONTEND_PACKAGE, _json_version),
    (
        ".env.example",
        _ENV_EXAMPLE,
        lambda source: _env_value(source, "OPENDRP_VERSION"),
    ),
    ("docker-compose.yml", _COMPOSE, _compose_display_version),
    (
        "frontend/Dockerfile",
        _FRONTEND_DOCKERFILE,
        lambda source: _dockerfile_arg(source, "VITE_APP_VERSION"),
    ),
)

#: How each reading is named in the failure detail, in the same order.
LABELS = (
    "app/__init__.py",
    "pyproject.toml",
    "CHANGELOG.md",
    "connector SDK __version__",
    "connector api_version",
    "connector pyproject.toml",
    "frontend package.json",
    "env template OPENDRP_VERSION",
    "compose VITE_APP_VERSION",
    "frontend Dockerfile VITE_APP_VERSION",
)

#: What to say when a new statement is absent, keyed by its path. The suffix-based
#: hints below fit a Python module, a package manifest or a TOML table; these
#: three files state the version in a line of their own.
_HINTS = {
    ".env.example": "no OPENDRP_VERSION line — expected `OPENDRP_VERSION=x.y.z`",
    "docker-compose.yml": (
        "no SPA display version — expected `VITE_APP_VERSION: ${OPENDRP_VERSION:-x.y.z}` "
        "in the frontend build args"
    ),
    "frontend/Dockerfile": (
        "no ARG default — expected `ARG VITE_APP_VERSION=x.y.z`"
    ),
}


def check(root: Path) -> list[str]:
    failures: list[str] = []

    readings: dict[str, str | None] = {}

    for (relative, path_suffix, reader), label in zip(READINGS, LABELS):
        path = root / path_suffix
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as exc:
            failures.append(f"{relative}: cannot read ({exc})")
            continue
        value = reader(source)
        readings[label] = value
        if value is None:
            expected_hint = _HINTS.get(relative)
            if expected_hint is None:
                if relative.endswith(".py"):
                    name = "SDK_VERSION" if "base.py" in relative else "__version__"
                    expected_hint = (
                        f"no version found — expected `{name} = \"x.y.z\"` in {relative}"
                    )
                elif relative.endswith(".json"):
                    expected_hint = (
                        f'no version found — expected a `"version"` key in {relative}'
                    )
                elif relative.endswith(".toml"):
                    expected_hint = (
                        f"no version found — expected a version in {relative}"
                    )
                else:
                    expected_hint = (
                        f"`{relative}` declares no version — expected a version value"
                    )
            failures.append(f"{relative}: {expected_hint}")

    if failures:
        return failures

    versions = {label: value for label, value in readings.items() if value}
    distinct = set(versions.values())
    if len(distinct) > 1:
        detail = ", ".join(f"{label}={value}" for label, value in versions.items())
        failures.append(
            f"the release version disagrees with itself: {detail}. "
            "Update every statement (the release workflow tags whatever "
            "app/__init__.py declares, and the connector images are built and "
            "tagged with the same version)."
        )
    return failures


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        print("usage: python scripts/check_version_consistency.py [repo-root]")
        return 2
    root = Path(argv[0]) if argv else Path(".")

    try:
        failures = check(root)
    except (OSError, SyntaxError) as exc:
        print(f"version gate: FAILED — cannot read sources: {exc}")
        return 2

    if failures:
        print("version gate: FAILED")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    source = (root / _APP_INIT).read_text(encoding="utf-8")
    version = _assigned_constant(source, "__version__")
    print(
        f"version gate: OK — {len(READINGS)} statements agree on {version} "
        f"({', '.join(LABELS)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
