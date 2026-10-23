#!/usr/bin/env python3
"""Regenerate a requirements file as a pinned, hash-locked set.

`requirements.txt` is the only manifest the production image installs, and until
this script existed it was an *incomplete* one: the file named the direct
dependencies and left the transitive ones to whatever the index served that day.
`pip install --require-hashes` refuses a file in that state — and rightly, because
a hash can only be checked for a version that is written down.

What the generated file is:

* every direct dependency **and** every transitive one, pinned with `==`;
* two to four `--hash=sha256:` lines per pin, one for each artifact the index
  publishes for that version. All of them, not just the platform this host runs:
  the image is built on `linux/amd64` today and a lock that only carried amd64
  hashes would fail the day somebody builds it on an arm64 runner;
* the comment block that preceded a pin in the source file, carried over. Those
  comments are the record of *why* a version is pinned (the CVE it closes, the
  advisory that is still open); a lock that drops them turns every future
  upgrade into an archaeology exercise.

Resolution runs the way `pip` would on the target interpreter (`--python-version`,
`--implementation cp`, `--abi cp312`, `--platform`), not the way it would on
whatever Python happens to be running this script: a lock generated on 3.14 for
an image that ships 3.12 is a different tree wearing the same filename.

Usage
-----
    python scripts/lock_requirements.py backend/requirements.txt
    python scripts/lock_requirements.py --check backend/requirements.txt
    python scripts/lock_requirements.py connectors/dnstwist/requirements.txt
    python scripts/lock_requirements.py --extends backend/requirements-dev.txt

`--check` resolves and compares without writing anything, which is what a
scheduled job should run: it answers "is this lock still what the index would
resolve today?" without touching a file.

One limit of resolving with `--platform` is handled rather than inherited: pip
resolves for the named platform without evaluating `platform_machine`, so a
dependency a package declares with that marker never reaches the report —
SQLAlchemy declares `greenlet` that way, and a lock without it builds an image
that fails on its first async connection. `MARKER_GATED_RUNTIME` names those
dependencies and states why resolution cannot find them; a source that installs
the package declaring one of them but does not pin it is refused instead of being
locked without it. A source that installs nothing of the sort — every connector
lock, which carries no SQLAlchemy — is not a gap and is locked as it stands.

`--extends` is for a file that installs *on top of* another one, which is what
`requirements-dev.txt` does: it pins the test and lint toolchain and includes the
runtime lock. `pip` turns hash checking on for the whole run as soon as any
requirement carries a hash, so every line of that file needs one — its own
transitive dependencies included — while the pins the include already provides
must not be written down a second time, because two pins for one package are how
the two files start disagreeing.

Requires network access and `pip`; deliberately stdlib-only otherwise, like its
neighbours in this directory.

Exit codes: 0 written/clean, 1 the file differs (with `--check`), 2 unusable
input or a resolution that failed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Sequence

#: The interpreter and platform the shipped images use. `linux/amd64` is what the
#: release matrix builds; the hashes cover every platform the index publishes for
#: each pinned version, so the lock is not amd64-only.
TARGET_PYTHON = "3.12"
TARGET_IMPLEMENTATION = "cp"
TARGET_ABI = "cp312"
#: Every platform tag a candidate wheel may carry. More than one, because the
#: index publishes under whichever tag the release was built for, and a package
#: that ships only a newer tag would otherwise look like a package that does not
#: exist at all — which is how this list was found to be too short: Pillow 12.3.0
#: stopped publishing `manylinux2014` wheels, and the release that fixes its
#: advisories could not be locked. Both tags are ones the images accept:
#: `python:3.12-slim` is glibc 2.36, so `manylinux_2_28` installs there exactly as
#: `manylinux2014` does. The pins and hashes are unaffected either way, because the
#: hashes cover every artifact the index publishes for the version.
TARGET_PLATFORMS = (
    "manylinux2014_x86_64",
    "manylinux_2_24_x86_64",
    "manylinux_2_28_x86_64",
)

_HEADER = """\
# ==============================================================================
# GENERATED FILE - do not edit by hand.
#
# Regenerate after changing a dependency or its pin:
#
#     python scripts/lock_requirements.py {source}
#     python scripts/lock_requirements.py --check {source}
#
# Every direct and transitive dependency is pinned with `==` and carries the
# `--hash=sha256:` digests of every artifact the index publishes for that version,
# so the image is built with `pip install --require-hashes` and a substituted
# package fails the build instead of being installed quietly. The comments below
# each pin are the reason it is pinned; keep them when you regenerate.
#
# The connector SDK is deliberately absent: it is installed from the build
# context with its own `pip install /opt/sdk` line, because hash-checking mode
# cannot hash a directory.
# ==============================================================================
"""

_REQUIREMENT = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)(?:\[[^\]]+\])?\s*==\s*(?P<version>[^\s;]+)")
_COMMENT = re.compile(r"^\s*#")

_PYPI_JSON = "https://pypi.org/pypi/{name}/{version}/json"

#: Dependencies that must be in a lock even though the resolution above cannot
#: find them, keyed by normalised name. `pip install --platform` resolves for the
#: named platform without evaluating `platform_machine`, so a dependency declared
#: with that marker is dropped from the tree: the lock then describes an
#: installation that builds and fails at import. Each entry says what needs it and
#: why resolution misses it; `build_lock` fails when the source does not pin one,
#: so the list cannot rot into a comment nobody reads.
MARKER_GATED_RUNTIME: Dict[str, str] = {
    "greenlet": (
        "SQLAlchemy's asyncio engine imports it, and SQLAlchemy declares it with a "
        "`platform_machine` marker that a `--platform` resolution does not evaluate"
    ),
}

#: The package whose own metadata declares each entry above through a
#: `platform_machine` marker — the only reason the entry can be missing from a
#: resolution in the first place. A manifest that installs none of them cannot
#: need the gated dependency at all: the seven connector locks carry no SQLAlchemy
#: and so no greenlet, and requiring it from them made this script refuse to
#: regenerate a connector lock at all (`does not pin greenlet`) — which is why
#: those files were never regenerated, and why their headers could drift unseen.
MARKER_GATED_BY: Dict[str, str] = {"greenlet": "sqlalchemy"}

#: Where a generated file's own instructions are written from. Anchored to the
#: repository rather than to the caller's working directory, because the header is
#: the only place the file says how to maintain it.
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class Failed(Exception):
    """The lock could not be produced."""


def _normalise(name: str) -> str:
    """PEP 503 normalisation: `Email_Validator` and `email-validator` are one name."""
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def _pip_download_requirements(
    source: Path,
    destination: Path,
    python: str,
    implementation: str,
    abi: str,
    platforms: Sequence[str],
) -> List[str]:
    """Ask pip to resolve the file for the target interpreter and return the pins.

    `pip download` is used rather than a resolver of our own: it is the same
    resolver the image build runs, so the lock describes the tree pip will
    actually install.
    """
    command = [
        sys.executable,
        "-m",
        "pip",
        # `install --dry-run --report` rather than `pip download`: download has no
        # report, and the resolved tree pip itself reports is the one the image
        # build will install. Nothing is written outside the target directory.
        "install",
        "--dry-run",
        "--quiet",
        "--no-cache-dir",
        "--ignore-installed",
        "--only-binary=:all:",
        "--target",
        str(destination),
        # The report is the resolved tree with the names and versions pip itself
        # chose. Reading the wheel filenames instead would be a second parser of
        # a format that already has one, and it gets `charset_normalizer`,
        # build tags and local versions wrong.
        "--report",
        "-",
        "--python-version",
        python,
        "--implementation",
        implementation,
        "--abi",
        abi,
    ]
    for platform in platforms:
        command.extend(["--platform", platform])
    command.extend(["--requirement", str(source)])

    # `PYTHONIOENCODING` plus an explicit utf-8 decode: pip's report is JSON and
    # some package descriptions contain characters the Windows console code page
    # cannot encode, which fails the child process rather than the parse.
    capture_environment = dict(os.environ, PYTHONIOENCODING="utf-8")
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=capture_environment,
    )
    if result.returncode != 0:
        detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "unknown error"
        raise Failed(f"pip could not resolve {source}: {detail}")

    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise Failed(f"pip produced no readable report for {source}: {exc}") from exc

    pins: Dict[str, str] = {}
    for entry in report.get("install", []):
        metadata = entry.get("metadata", {})
        name = str(metadata.get("name", "")).strip().lower()
        version = str(metadata.get("version", "")).strip()
        if name and version:
            pins[name] = version
    if not pins:
        raise Failed(f"pip resolved {source} to nothing")
    return [f"{name}=={version}" for name, version in sorted(pins.items())]


def _hashes(name: str, version: str) -> List[str]:
    """Every sha256 the index publishes for this exact version."""
    request = urllib.request.Request(
        _PYPI_JSON.format(name=name, version=version),
        headers={"Accept": "application/json", "User-Agent": "opendrp-lock-requirements"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.load(response)
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        raise Failed(f"cannot read the index entry for {name}=={version}: {exc}") from exc

    digests = {
        entry["digests"]["sha256"]
        for entry in payload.get("urls", [])
        if entry.get("digests", {}).get("sha256")
    }
    if not digests:
        raise Failed(
            f"the index lists no artifacts for {name}=={version}, so no hash can "
            f"be pinned for it"
        )
    return sorted(digests)


def _comments(source: Path) -> Dict[str, List[str]]:
    """The comment block that precedes each requirement in the source file."""
    attached: Dict[str, List[str]] = {}
    pending: List[str] = []
    for line in source.read_text(encoding="utf-8").splitlines():
        if _COMMENT.match(line):
            pending.append(line)
            continue
        if not line.strip():
            # A blank line ends an unattached block: a comment belongs to a pin
            # only when it sits directly above it. This is also what keeps the
            # generated file's own header from being re-attached to the first
            # requirement and duplicated on the next run.
            pending = []
            continue
        match = _REQUIREMENT.match(line.strip())
        if match is not None and pending:
            attached[_normalise(match.group("name"))] = pending
        pending = []
    return attached


def _declared_pins(source: Path) -> Dict[str, str]:
    """``name -> version`` for the pins the file itself declares."""
    return _pins_in_text(source.read_text(encoding="utf-8"))


def _with_marker_gated_runtime(pins: List[str], source: Path) -> List[str]:
    """Keep the dependencies a `--platform` resolution cannot see.

    A dependency that pip dropped because of a marker has to be written down for
    the lock to be complete, and the version has to come from the source file: the
    generator may not invent one. Refusing an unpinned name is the point — it is
    what turns "a regeneration silently dropped greenlet" into a message naming the
    file and the pin to add.
    """
    resolved = {
        _normalise(name): version
        for name, version in (pin.split("==", 1) for pin in pins)
    }
    declared = _declared_pins(source)
    unpinned: List[str] = []
    for name in MARKER_GATED_RUNTIME:
        key = _normalise(name)
        if key in resolved:
            continue
        needed_by = MARKER_GATED_BY.get(name)
        if needed_by is not None and _normalise(needed_by) not in resolved:
            # This manifest installs nothing that declares it, so it is not a gap
            # in this lock. Refusing here is what made every connector manifest
            # unregenerable.
            continue
        version = declared.get(key)
        if version is None:
            unpinned.append(name)
            continue
        resolved[key] = version
    if unpinned:
        listed = ", ".join(sorted(unpinned))
        subject = "it" if len(unpinned) == 1 else "them"
        raise Failed(
            f"{source} does not pin {listed}, and resolution cannot discover "
            f"{subject}: pip resolves with `--platform`, which does not evaluate "
            f"`platform_machine`. Add an explicit pin with the reason it is needed "
            f"(see MARKER_GATED_RUNTIME in this script)."
        )
    return [f"{name}=={version}" for name, version in sorted(resolved.items())]


#: Spellings of a line that pulls in another requirements file.
_INCLUDE_PREFIXES = ("-r ", "--requirement ")


def _curated_spelling(text: str) -> Dict[str, str]:
    """The spelling the project uses, keyed by normalised name.

    `pip` reports `email_validator` where the file that pinned it wrote
    `email-validator`, and rewriting a name nobody asked to change makes every
    diff harder to read.
    """
    return {
        _normalise(match.group("name")): match.group("name")
        for line in text.splitlines()
        if (match := _REQUIREMENT.match(line.strip())) is not None
    }


def _pin_block(
    name: str, version: str, comment: List[str] | None, hashes: List[str]
) -> str:
    """One pin with its reason above it and its digests below it."""
    lines = list(comment) if comment else []
    lines.append(f"{name}=={version} \\")
    lines.extend(
        f"    --hash=sha256:{digest}" + (" \\" if index < len(hashes) - 1 else "")
        for index, digest in enumerate(hashes)
    )
    return "\n".join(lines)


def _pins_in_text(text: str) -> Dict[str, str]:
    """``name -> version`` for the pins a file's *content* declares."""
    pins: Dict[str, str] = {}
    for line in text.splitlines():
        match = _REQUIREMENT.match(line.strip())
        if match is not None:
            pins[_normalise(match.group("name"))] = match.group("version")
    return pins


def _include_sources(source: Path) -> List[tuple[str, str]]:
    """``(spelling, content)`` for every include that exists beside the file.

    The spelling is kept because resolution runs on a staged copy and `pip`
    resolves the include by that path, relative to the staged file.
    """
    found: List[tuple[str, str]] = []
    for line in source.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        for prefix in _INCLUDE_PREFIXES:
            if stripped.startswith(prefix):
                name = stripped[len(prefix) :].strip()
                candidate = (source.parent / name).resolve()
                if candidate.is_file():
                    found.append((name, candidate.read_text(encoding="utf-8")))
    return found


def _provided_pins(source: Path) -> Dict[str, str]:
    """``name -> version`` for every pin the files this one includes declare."""
    pins: Dict[str, str] = {}
    for _name, content in _include_sources(source):
        pins.update(_pins_in_text(content))
    return pins


def _prologue(text: str) -> List[str]:
    """The comment and include lines that precede the first pin.

    The comment block *directly* above that pin is not part of it: `_comments`
    attaches that block to the pin, and this function emits the pin's own block
    right below the prologue. Leaving it in both places writes it twice, and a
    generator that duplicates a comment on every run is not a fixed point — the
    next run then writes it three times.
    """
    prologue: List[str] = []
    for line in text.splitlines():
        if _REQUIREMENT.match(line.strip()) is not None:
            break
        prologue.append(line)
    while prologue and _COMMENT.match(prologue[-1]):
        prologue.pop()
    while prologue and not prologue[-1].strip():
        prologue.pop()
    return prologue


def build_extends_lock(source: Path) -> str:
    """Lock a file that adds to another one, without expanding that other one.

    `requirements-dev.txt` installs on top of the runtime lock it includes, and
    `pip` turns hash checking on for the whole run as soon as any requirement
    carries a hash — so this file needs a hash for its own lines, their
transitive dependencies included, while the runtime pins stay where they are.

    Resolution therefore runs with the include in place, so `pip` keeps the
    constraints of the file it will actually install with (a test dependency must
    not be free to drag a package away from the version the image ships), and the
    pins the include already provides are then left out: writing them here a second
    time is how the two files start disagreeing.
    """
    try:
        text = source.read_text(encoding="utf-8")
    except OSError as exc:
        raise Failed(f"cannot read {source}: {exc}") from exc

    provided = _provided_pins(source)
    kept = [line for line in text.splitlines() if " @ file://" not in line]
    with tempfile.TemporaryDirectory() as workdir:
        staging = Path(workdir)
        trimmed = staging / source.name
        trimmed.write_text("\n".join(kept) + "\n", encoding="utf-8")
        # The included files travel with it: `pip` resolves them relative to the
        # staged file, and resolving without them would drop the constraints the
        # file will really be installed under.
        for spelling, content in _include_sources(source):
            included = staging / spelling
            included.parent.mkdir(parents=True, exist_ok=True)
            included.write_text(content, encoding="utf-8")
        pins = _pip_download_requirements(
            trimmed,
            staging / "wheels",
            TARGET_PYTHON,
            TARGET_IMPLEMENTATION,
            TARGET_ABI,
            TARGET_PLATFORMS,
        )

    pins = [pin for pin in pins if _normalise(pin.split("==", 1)[0]) not in provided]
    if not pins:
        raise Failed(f"{source} adds no dependency of its own to the files it includes")

    comments = _comments(source)
    curated_spelling = _curated_spelling(text)
    blocks: List[str] = ["\n".join(_prologue(text))]
    for pin in pins:
        name, version = pin.split("==", 1)
        name = curated_spelling.get(_normalise(name), name)
        blocks.append(
            _pin_block(name, version, comments.get(_normalise(name)), _hashes(name, version))
        )
    return "\n\n".join(blocks) + "\n"


def _invocation_path(source: Path) -> str:
    """The path written into the header, so the command works from the root.

    It used to be whatever spelling the caller typed. `backend/requirements.txt`
    therefore carried `python scripts/lock_requirements.py requirements.txt`,
    which names the right script from no directory at all: from the repository root
    the argument does not exist, and from `backend/` the script does not. Anchoring
    the path to the repository root makes the line independent of where the
    generator ran.
    """
    try:
        return source.resolve().relative_to(_REPOSITORY_ROOT).as_posix()
    except ValueError:
        return source.as_posix()


def build_lock(source: Path) -> str:
    """The generated content for one requirements file."""
    try:
        text = source.read_text(encoding="utf-8")
    except OSError as exc:
        raise Failed(f"cannot read {source}: {exc}") from exc

    # The connector SDK is a local directory inside the build context. pip's
    # hash-checking mode cannot hash a directory, and the Dockerfiles install it
    # on its own `pip install /opt/sdk` line, so it is deliberately not part of
    # the locked set.
    kept = [
        line
        for line in text.splitlines()
        if " @ file://" not in line
    ]
    if not any(line.strip() and not _COMMENT.match(line) for line in kept):
        raise Failed(f"{source} declares no installable requirement")

    with tempfile.TemporaryDirectory() as workdir:
        staging = Path(workdir)
        trimmed = staging / source.name
        trimmed.write_text("\n".join(kept) + "\n", encoding="utf-8")
        pins = _pip_download_requirements(
            trimmed,
            staging / "wheels",
            TARGET_PYTHON,
            TARGET_IMPLEMENTATION,
            TARGET_ABI,
            TARGET_PLATFORMS,
        )

    pins = _with_marker_gated_runtime(pins, source)
    comments = _comments(source)
    curated_spelling = _curated_spelling(source.read_text(encoding="utf-8"))
    blocks: List[str] = [_HEADER.format(source=_invocation_path(source)).rstrip()]
    for pin in pins:
        name, version = pin.split("==", 1)
        name = curated_spelling.get(_normalise(name), name)
        # The comment goes directly above its pin, with no blank line between
        # them: that is both how the curated file reads and what keeps the block
        # attached when this script reads its own output on the next run.
        blocks.append(
            _pin_block(name, version, comments.get(_normalise(name)), _hashes(name, version))
        )
    return "\n\n".join(blocks) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Regenerate a requirements file as a pinned, hash-locked set."
    )
    parser.add_argument("source", help="requirements file to lock")
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not write; fail if the file on disk is not the lock (exit 1)",
    )
    parser.add_argument(
        "--extends",
        action="store_true",
        help=(
            "lock the dependencies this file adds to the files it includes, "
            "leaving the included pins where they are"
        ),
    )
    args = parser.parse_args(argv)

    source = Path(args.source)
    if not source.is_file():
        print(f"not a file: {source}", file=sys.stderr)
        return 2

    builder = build_extends_lock if args.extends else build_lock
    try:
        generated = builder(source)
    except Failed as exc:
        print(f"cannot build a lock for {source}: {exc}", file=sys.stderr)
        return 2

    # Compared with the line endings normalised: the generated content is written
    # with `\n` (which is what `.gitattributes` asks for), while a checkout on a
    # platform that rewrites text files on the way out gives the same file `\r\n`.
    # Comparing bytes would report a difference that is not one, and the operator
    # would regenerate a file that is already current.
    current = source.read_text(encoding="utf-8").replace("\r\n", "\n")
    if args.check:
        if current == generated:
            print(f"{source}: the lock is what the index resolves today")
            return 0
        print(
            f"{source}: the lock no longer matches the index. Run "
            f"`python scripts/lock_requirements.py {source}` and review the diff.",
            file=sys.stderr,
        )
        return 1

    if current == generated:
        print(f"{source}: unchanged")
        return 0
    source.write_text(generated, encoding="utf-8")
    print(f"{source}: written ({len(generated.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
