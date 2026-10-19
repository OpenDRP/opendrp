#!/usr/bin/env python3
"""Fail when the backend's dependency declarations drift apart again.

`requirements.txt` (runtime) and `requirements-dev.txt` (test tooling) are the
single source of truth for Python dependencies: they carry the exact pins the
Docker build installs, so they are also the only manifests whose advisories
describe the shipped images.

`backend/pyproject.toml` used to declare a second, independent set of Poetry
dependency ranges. It drifted: `fastapi = "^0.115.0"` resolved an old Starlette
while `requirements.txt` pinned `starlette==1.6.0`, so every advisory Dependabot
reported named a package the production image never contained — and the pins
that mattered were invisible to it. A security alert list that describes the
wrong tree is worse than none: it is looked at and believed.

The rules therefore are mechanical, not a convention:

* every requirement line in one of the **shipped** manifests
  (``backend/requirements.txt`` and the connector manifests) is an exact pin
  **and** carries at least one ``--hash=sha256:`` continuation, because those are
  the files the production images install with ``--require-hashes``. A pin
  without a hash is a version a substituted artifact can satisfy;
* ``requirements-dev.txt`` is pinned exactly but deliberately not hashed: it is
  never installed into a shipped image, and its own toolchain (pytest, ruff, mypy)
  has no bearing on what a release contains.

Everything else:

* ``backend/pyproject.toml`` declares no dependencies at all — not Poetry
  tables (``[tool.poetry.dependencies]``, ``[tool.poetry.group.*.dependencies]``),
  not PEP 621 ones (``[project] dependencies`` / ``optional-dependencies``).
  The ``[tool.poetry]`` table survives for ``version`` alone (the version gate
  reads it), and ``[tool.mypy]`` for tool configuration;
* every requirement line is an **exact** pin (``name==version``), or the
  connector SDK's local direct reference (``name @ file://…``), or an include
  (``-r other.txt``). A range (``>=``, ``~=``, ``^``), a bare name or a wildcard
  reintroduces non-reproducible resolution, which is the same drift at install
  time instead of declaration time.

Deliberately stdlib-only, like its neighbours in this directory: the
repository-hygiene CI job installs nothing.

Usage:  python scripts/check_dependency_sources.py [--root DIR]

Exit codes: 0 clean, 1 findings, 2 unreadable input.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import List, Sequence, Tuple

_PYPROJECT = Path("backend") / "pyproject.toml"
_REQUIREMENTS: Tuple[Path, ...] = (
    Path("backend") / "requirements.txt",
    Path("backend") / "requirements-dev.txt",
    Path("connectors") / "dnstwist" / "requirements.txt",
    Path("connectors") / "shodan" / "requirements.txt",
    Path("connectors") / "hibp" / "requirements.txt",
)

#: Poetry tables that would redeclare the dependency set by another resolution
#: rule. A group name in the middle is matched as ``.*`` — any Poetry group.
_POETRY_DEP_TABLE = re.compile(r"^\[tool\.poetry(\.[a-z0-9_.-]+)?\.dependencies\]")

#: ``name==1.2.3``, ``name[extra]==1.2.3``, optionally with an environment
#: marker after ``;``. Anything else on a requirement line is a range.
_EXACT_PIN = re.compile(
    r"^[A-Za-z0-9._-]+(\[[A-Za-z0-9,._-]+\])?==[A-Za-z0-9._+!-]+(\s*;\s*.+)?$"
)
_INCLUDE = re.compile(r"^-r\s+\S+$")
#: The connector SDK is consumed from the build context (``file:///opt/sdk``),
#: not from an index, so there is no version to pin it to.
_DIRECT_REF = re.compile(r"^[A-Za-z0-9._-]+\s+@\s+file://\S+$")
#: A hash line in a generated lock: `--hash=sha256:<64 hex>`, optionally with the
#: backslash that continues the block to the next digest.
_HASH_LINE = re.compile(r"^--hash=sha256:[0-9a-f]{64}(?:\s*\\)?$")

#: The manifests that are installed into a shipped image with `--require-hashes`.
#: `requirements-dev.txt` is deliberately absent: it never ships.
_HASHED_REQUIREMENTS: Tuple[Path, ...] = (
    Path("backend") / "requirements.txt",
    Path("connectors") / "dnstwist" / "requirements.txt",
    Path("connectors") / "shodan" / "requirements.txt",
    Path("connectors") / "hibp" / "requirements.txt",
    Path("connectors") / "dns_security" / "requirements.txt",
    Path("connectors") / "intelligence" / "requirements.txt",
)


def check_pyproject(source: str) -> List[str]:
    failures: List[str] = []
    for number, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _POETRY_DEP_TABLE.match(stripped):
            failures.append(
                f"{_PYPROJECT}:{number}: dependency table {stripped} — dependencies "
                "live in requirements.txt / requirements-dev.txt only"
            )
        elif stripped == "[project]":
            failures.append(
                f"{_PYPROJECT}:{number}: PEP 621 [project] table — dependencies "
                "live in requirements.txt / requirements-dev.txt only"
            )
    return failures


def check_requirements(
    relative: Path, source: str, require_hashes: bool = False
) -> List[str]:
    failures: List[str] = []
    hash_count = 0
    pinned_at = 0

    for number, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _HASH_LINE.match(stripped):
            hash_count += 1
            continue

        if pinned_at and require_hashes and hash_count == 0:
            failures.append(
                f"{relative}:{pinned_at}: the pin carries no `--hash=sha256:` "
                f"line, so `pip install --require-hashes` cannot verify the "
                f"artifact it installs"
            )
        hash_count = 0

        # A generated lock continues a pin onto the hash lines with a backslash;
        # the pin itself is what has to be exact.
        candidate = stripped[:-1].strip() if stripped.endswith("\\") else stripped
        if _INCLUDE.match(candidate) or _DIRECT_REF.match(candidate):
            continue
        if _EXACT_PIN.match(candidate):
            pinned_at = number
            continue
        failures.append(
            f"{relative}:{number}: {stripped!r} is not an exact pin — every "
            "requirement is `name==version` (or the SDK's `name @ file://…`, "
            "or `-r` include) so the build and the advisory scan see one tree"
        )

    if pinned_at and require_hashes and hash_count == 0:
        failures.append(
            f"{relative}:{pinned_at}: the pin carries no `--hash=sha256:` line"
        )
    return failures


def check(root: Path) -> List[str]:
    failures: List[str] = []

    pyproject = root / _PYPROJECT
    try:
        failures.extend(check_pyproject(pyproject.read_text(encoding="utf-8")))
    except OSError as exc:
        failures.append(f"{_PYPROJECT}: cannot read ({exc})")

    for relative in _REQUIREMENTS:
        try:
            source = (root / relative).read_text(encoding="utf-8")
        except OSError as exc:
            failures.append(f"{relative}: cannot read ({exc})")
            continue
        failures.extend(
            check_requirements(
                relative, source, require_hashes=relative in _HASHED_REQUIREMENTS
            )
        )

    return failures


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=".", help="repository root (default: .)")
    args = parser.parse_args(list(argv))
    root = Path(args.root)

    try:
        failures = check(root)
    except (OSError, UnicodeDecodeError) as exc:
        print(f"dependency-source gate: FAILED — cannot read inputs: {exc}")
        return 2

    if failures:
        print("dependency-source gate: FAILED")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(
        "dependency-source gate: OK — pyproject declares no dependencies, "
        "every requirement is an exact pin, and the shipped manifests pin a "
        "hash for each of them"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
