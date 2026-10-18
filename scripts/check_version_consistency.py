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
  release the build injects as ``VITE_APP_VERSION`` and the UI displays.

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
)


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
            expected_hint = (
                f'`{relative}` declares no version — expected a version value'
            )
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
        "(app, pyproject, CHANGELOG, connector SDK, connector api_version, "
        "connector pyproject, frontend package.json)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
