#!/usr/bin/env python3
"""Fail when the platform's version disagrees with itself.

Three files carry the version and nothing joined them:

* ``backend/app/__init__.py`` — what the running process reports on
  ``/api/v1/health`` and in its OpenAPI document;
* ``backend/pyproject.toml`` — what the package metadata says;
* ``CHANGELOG.md`` — what a person reads before upgrading.

A mismatch is not cosmetic. It means an instance reports a version no release
note describes, an upgrade guide applies to a tag the code does not contain, and
a bug report cannot be placed on a timeline. The check is what makes "single
source of truth" a property of the repository instead of a claim in a comment.

Deliberately does not consult git: the same repository is checked inside a
container that has no ``.git``, and the release workflow verifies the tag
against ``__version__`` at the point where the tag actually exists.

Usage: python scripts/check_version_consistency.py [repo-root]

Exit codes: 0 clean, 1 mismatch or missing value, 2 unreadable input.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

_APP_INIT = Path("backend") / "app" / "__init__.py"
_PYPROJECT = Path("backend") / "pyproject.toml"
_CHANGELOG = Path("CHANGELOG.md")

_HEADING = re.compile(r"^##\s+\[([^\]]+)\]", re.MULTILINE)
_UNRELEASED = "unreleased"


def _python_version(source: str) -> str | None:
    """Read ``__version__`` through the AST rather than by regex.

    A regex finds the assignment in a comment or a string literal; the parser
    only finds the real one.
    """
    for node in ast.parse(source).body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Name)
                and target.id == "__version__"
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                return node.value.value
    return None


def _pyproject_version(source: str) -> str | None:
    try:
        import tomllib  # Python 3.11+
    except ModuleNotFoundError:  # pragma: no cover - CI runs 3.12
        match = re.search(r'^version\s*=\s*"([^"]+)"', source, re.MULTILINE)
        return match.group(1) if match else None
    try:
        data = tomllib.loads(source)
    except tomllib.TOMLDecodeError:
        return None
    version = data.get("tool", {}).get("poetry", {}).get("version")
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


def check(root: Path) -> list[str]:
    failures: list[str] = []

    readings: dict[str, str | None] = {}
    sources: dict[str, str] = {}

    for label, relative, reader in (
        ("app/__init__.py", _APP_INIT, _python_version),
        ("pyproject.toml", _PYPROJECT, _pyproject_version),
        ("CHANGELOG.md", _CHANGELOG, _changelog_version),
    ):
        path = root / relative
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as exc:
            failures.append(f"{relative}: cannot read ({exc})")
            continue
        sources[label] = source
        value = reader(source)
        readings[label] = value
        if value is None:
            expected_hint = '`__version__ = "x.y.z"`' if label.endswith(".py") else "a version"
            failures.append(f"{relative}: no version found — expected {expected_hint}")

    if failures:
        return failures

    versions = {label: value for label, value in readings.items() if value}
    distinct = set(versions.values())
    if len(distinct) > 1:
        detail = ", ".join(f"{label}={value}" for label, value in versions.items())
        failures.append(
            f"the platform version disagrees with itself: {detail}. "
            "Update all three (the release workflow tags whatever "
            "app/__init__.py declares)."
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

    version = _python_version((root / _APP_INIT).read_text(encoding="utf-8"))
    print(f"version gate: OK — app, pyproject and CHANGELOG all say {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
