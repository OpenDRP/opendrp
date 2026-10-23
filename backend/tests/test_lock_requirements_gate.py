"""The lock generator must not be able to drop a dependency it cannot see.

`scripts/lock_requirements.py` resolves with `pip install --platform`, and pip
does not evaluate `platform_machine` for a target it is only *told* about. A
dependency a package declares with that marker therefore never reaches the
resolution: the lock comes out one dependency short, the image builds, and the
application fails at import. SQLAlchemy declares `greenlet` exactly that way, and
its asyncio engine needs it.

These tests pin the three properties that keep the two shipped files installable:

* the generator keeps such a dependency when the source pins it, and refuses a
  source that does not — a silent drop is the defect, so the failure has to name
  the file and the pin to add;
* `backend/requirements.txt` really does carry every name listed in
  `MARKER_GATED_RUNTIME`, pinned and hashed, so a regeneration that drops one is
  caught without a network call;
* `requirements-dev.txt` — which installs on top of that lock — has a hash for
  every line of its own and does not repeat a pin the file it includes already
  makes. `pip` turns hash checking on for the whole run as soon as any
  requirement carries a hash, and two pins for one package make the install
  unresolvable.
* neither manifest leaves a package in its resolution undeclared. A hash is only
  checkable for a version that is written down, so hash checking refuses the
  whole file when one resolved package is missing — and it refuses it *before*
  collecting anything, which is how `requirements-dev.txt` stood: `pytest`
  carried a hash and `iniconfig`, `pluggy`, `coverage` and `mypy_extensions`,
  which `pytest`, `pytest-cov` and `mypy` need, were nowhere in either file.

The resolution and the index read are stubbed: this is the part of the tool that
decides, and a gate that needs PyPI is a gate that fails when the network does.
The closure walk reads the metadata of the packages the manifests installed,
which every environment that can run this suite has by construction — the runner
itself is one of those pins.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path

import pytest
from packaging.markers import default_environment
from packaging.requirements import Requirement

_BACKEND_ROOT = Path(__file__).resolve().parents[1]
_ROOT = _BACKEND_ROOT.parent
_SCRIPT = _ROOT / "scripts" / "lock_requirements.py"

_spec = importlib.util.spec_from_file_location("lock_requirements", _SCRIPT)
assert _spec is not None and _spec.loader is not None
_lock = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("lock_requirements", _lock)
_spec.loader.exec_module(_lock)

_LOCK_FILE = _BACKEND_ROOT / "requirements.txt"
_DEV_FILE = _BACKEND_ROOT / "requirements-dev.txt"
#: Every file `scripts/lock_requirements.py` generates. The connector images each
#: install one with `--require-hashes`, so each is held to the same rule as the
#: backend's runtime lock.
_GENERATED_LOCKS = [_LOCK_FILE, *sorted((_ROOT / "connectors").glob("*/requirements.txt"))]

_HASH_BLOCK = re.compile(
    r"^(?P<name>[A-Za-z0-9._-]+)==[^\s\\]+ \\\n(?P<body>(?:\s+--hash=sha256:[0-9a-f]{64}[^\n]*\n)+)",
    re.MULTILINE,
)

_SOURCE = """\
# A direct dependency.
fastapi==0.115.0

# The package that declares greenlet through a `platform_machine` marker: a
# manifest without it does not need the pinned wheel at all, which is the case
# every connector lock is.
sqlalchemy==2.0.36

# SQLAlchemy's asyncio engine needs greenlet on linux/amd64, and SQLAlchemy
# declares it with a `platform_machine` marker.
greenlet==3.5.6

# An unrelated transitive pin.
typing-extensions==4.16.0
"""

_PIN = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)==(?P<version>[^\s;\\]+)", re.MULTILINE)


def _declared(path: Path) -> dict[str, str]:
    return {match["name"]: match["version"] for match in _PIN.finditer(path.read_text(encoding="utf-8"))}


def _stub_from_manifest(monkeypatch, manifest: Path) -> None:
    """Answer the resolution with the file's own pins and its own hashes.

    That is what a generator run against an unchanged tree must see, so the only
    thing the comparison can then report is a difference the generator itself
    would introduce — a dropped comment, a re-spelled name, a rewritten header.
    """
    text = manifest.read_text(encoding="utf-8")
    declared = _declared(manifest)
    digests = {
        _normalise(match["name"]): re.findall(r"--hash=sha256:([0-9a-f]{64})", match["body"])
        for match in _HASH_BLOCK.finditer(text)
    }
    monkeypatch.setattr(
        _lock,
        "_pip_download_requirements",
        lambda *args, **kwargs: [f"{name}=={version}" for name, version in declared.items()],
    )
    monkeypatch.setattr(
        _lock, "_hashes", lambda name, version: digests.get(_normalise(name), ["a" * 64])
    )


def _stub(monkeypatch, resolved: list[str], digests: dict[str, list[str]] | None = None):
    """Replace the resolution and the index read with fixed answers."""
    monkeypatch.setattr(
        _lock, "_pip_download_requirements", lambda *args, **kwargs: list(resolved)
    )
    monkeypatch.setattr(
        _lock, "_hashes", lambda name, version: (digests or {}).get(name, ["a" * 64])
    )


@pytest.fixture
def source(tmp_path: Path) -> Path:
    path = tmp_path / "requirements.txt"
    path.write_text(_SOURCE, encoding="utf-8")
    return path


# ==============================================================================
# The dependency the resolution cannot see
# ==============================================================================
def test_a_dropped_marker_gated_dependency_is_kept(monkeypatch, source) -> None:
    """The resolution omits greenlet; the lock must not."""
    _stub(monkeypatch, ["fastapi==0.115.0", "sqlalchemy==2.0.36", "typing-extensions==4.16.0"])

    generated = _lock.build_lock(source)

    assert "greenlet==3.5.6 \\" in generated


def test_a_source_that_does_not_pin_it_is_refused(monkeypatch, tmp_path: Path) -> None:
    """Unpinned means the generator cannot invent a version, so it must stop."""
    path = tmp_path / "requirements.txt"
    path.write_text("sqlalchemy==2.0.36\n", encoding="utf-8")
    _stub(monkeypatch, ["sqlalchemy==2.0.36"])

    with pytest.raises(_lock.Failed) as failure:
        _lock.build_lock(path)

    message = str(failure.value)
    assert "greenlet" in message
    assert "MARKER_GATED_RUNTIME" in message
    assert path.name in message


def test_the_shipped_lock_keeps_every_marked_dependency() -> None:
    """The point of the fix, checked against the file that ships."""
    text = _LOCK_FILE.read_text(encoding="utf-8")

    for name in _lock.MARKER_GATED_RUNTIME:
        assert re.search(rf"^{name}==", text, flags=re.MULTILINE), (
            f"{_LOCK_FILE.name} does not pin {name}: the resolution cannot see it, "
            f"so only a regeneration can drop it, and the image would then fail on "
            f"its first async connection"
        )
        block = re.search(
            rf"^{name}==[^\n]*\n((?:\s+--hash=sha256:[0-9a-f]{{64}}[^\n]*\n)+)",
            text,
            flags=re.MULTILINE,
        )
        assert block is not None, f"{name} is pinned in {_LOCK_FILE.name} without hashes"


def test_every_marked_dependency_states_why_resolution_misses_it() -> None:
    assert _lock.MARKER_GATED_RUNTIME
    for name, reason in _lock.MARKER_GATED_RUNTIME.items():
        assert reason.strip(), f"{name} is listed without a reason"
        assert len(reason) > 40, f"the reason for {name} does not explain anything"
        # Without this the entry applies to every manifest, including the seven
        # connector locks that install nothing which declares it.
        assert name in _lock.MARKER_GATED_BY, (
            f"{name} does not name the package whose metadata declares it, so the "
            "rule cannot tell a manifest that needs it from one that cannot"
        )


def test_a_source_that_installs_none_of_the_declaring_packages_is_locked(monkeypatch, tmp_path: Path) -> None:
    """A connector lock: no SQLAlchemy, so no greenlet to keep."""
    path = tmp_path / "requirements.txt"
    path.write_text("httpx==0.27.2\n", encoding="utf-8")
    _stub(monkeypatch, ["httpx==0.27.2", "anyio==4.6.0"])

    generated = _lock.build_lock(path)

    assert "httpx==0.27.2" in generated
    assert "greenlet" not in generated


# ==============================================================================
# A file that installs on top of another one
# ==============================================================================
def test_the_dev_file_hashes_every_pin_it_declares() -> None:
    """One unhashed line is enough to make `pip install` refuse the file."""
    text = _DEV_FILE.read_text(encoding="utf-8")

    pins = list(_PIN.finditer(text))
    assert pins, "requirements-dev.txt declares no pin"
    for match in pins:
        assert re.search(
            rf"^{re.escape(match['name'])}=={re.escape(match['version'])}[^\n]*\\\n"
            rf"(\s+--hash=sha256:[0-9a-f]{{64}}[^\n]*\n)+",
            text,
            flags=re.MULTILINE,
        ), f"{match['name']}=={match['version']} carries no hash"


def test_the_dev_file_keeps_its_include_and_its_reasons() -> None:
    text = _DEV_FILE.read_text(encoding="utf-8")

    assert "-r requirements.txt" in text
    # A comment attached to a pin is the record of why it is pinned.
    assert "# --- Testing" in text


def test_the_dev_file_does_not_repeat_the_pins_it_includes() -> None:
    """A second pin for one package is a conflict the next regeneration hits."""
    runtime = set(_declared(_LOCK_FILE))
    dev = set(_declared(_DEV_FILE)) - {"requirements"}

    assert not (runtime & dev), f"pinned in both files: {sorted(runtime & dev)}"


def test_the_dev_lock_is_a_fixed_point(tmp_path: Path, monkeypatch) -> None:
    """Regenerating what this file already is must produce the same bytes."""
    (tmp_path / "requirements.txt").write_text(
        _LOCK_FILE.read_text(encoding="utf-8"), encoding="utf-8"
    )
    dev_copy = tmp_path / "requirements-dev.txt"
    dev_copy.write_text(_DEV_FILE.read_text(encoding="utf-8"), encoding="utf-8")

    def resolve(source: Path, *args, **kwargs) -> list[str]:
        return [f"{name}=={version}" for name, version in _declared(source).items()]

    monkeypatch.setattr(_lock, "_pip_download_requirements", resolve)
    monkeypatch.setattr(_lock, "_hashes", lambda name, version: ["b" * 64])

    once = _lock.build_extends_lock(dev_copy)
    dev_copy.write_text(once, encoding="utf-8")
    assert _lock.build_extends_lock(dev_copy) == once


# ==============================================================================
# The closure each manifest is installed under
# ==============================================================================
def _normalise(name: str) -> str:
    """PEP 503: `mypy_extensions`, `mypy-extensions` and `Mypy.Extension` are one name."""
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def _required_by(distribution_name: str) -> set[str]:
    """The dependencies this installed distribution declares for *this* interpreter.

    Markers are evaluated the way `pip` evaluates them when it resolves the file,
    so an extra's dependency (`extra == "test"`) and another platform's
    (`sys_platform == "win32"`) are not asked for here either.
    """
    requires = getattr(distribution(distribution_name), "requires", None) or []
    environment = dict(default_environment(), extra="")
    required: set[str] = set()
    for raw in requires:
        requirement = Requirement(raw)
        if requirement.marker is not None and not requirement.marker.evaluate(environment):
            continue
        required.add(_normalise(requirement.name))
    return required


def _undeclared_closure(manifest: Path, also_provided: Path | None = None) -> list[str]:
    """Every name *manifest* installs but does not pin.

    The walk starts at the pins the file declares and follows the installed
    metadata from there, so a dependency of a dependency is checked too: hash
    checking wants the whole resolution written down, not the first level of it. A
    pin the environment has not installed is skipped rather than reported — that
    is a stale environment, not an incomplete manifest — and `also_provided` is
    how a file that installs on top of another one names the pins the include
    already brings.
    """
    declared = {_normalise(name) for name in _declared(manifest)}
    provided = {_normalise(name) for name in _declared(also_provided)} if also_provided else set()
    seen: set[str] = set()
    frontier = sorted(declared)
    undeclared: set[str] = set()
    while frontier:
        name = frontier.pop()
        if name in seen:
            continue
        seen.add(name)
        try:
            required = _required_by(name)
        except PackageNotFoundError:
            continue
        for requirement in required:
            if requirement in declared or requirement in provided:
                frontier.append(requirement)
            else:
                undeclared.add(requirement)
    return sorted(undeclared)


# ==============================================================================
# The files the generator must reproduce
# ==============================================================================
def test_every_generated_lock_is_a_fixed_point_of_the_generator(monkeypatch) -> None:
    """Regenerating a shipped lock must write the file that is already there.

    The dev file had this test and the eight runtime locks — the files the images
    actually install — did not, which is how `backend/requirements.txt` came to
    carry a header its own generator would not write.
    """
    drifted: list[str] = []
    for manifest in _GENERATED_LOCKS:
        _stub_from_manifest(monkeypatch, manifest)
        generated = _lock.build_lock(manifest)
        current = manifest.read_text(encoding="utf-8").replace("\r\n", "\n")
        if generated != current:
            drifted.append(f"{manifest.relative_to(_ROOT).as_posix()}: {_first_difference(current, generated)}")

    assert drifted == [], (
        "these locks are not what the generator writes, so a regeneration would "
        "change them and the file's own instructions do not describe it:\n  "
        + "\n  ".join(drifted)
    )


def _first_difference(current: str, generated: str) -> str:
    current_lines = current.splitlines()
    generated_lines = generated.splitlines()
    for index, (left, right) in enumerate(zip(current_lines, generated_lines, strict=False)):
        if left != right:
            return f"line {index + 1}: shipped {left.strip()!r}, generated {right.strip()!r}"
    if len(current_lines) != len(generated_lines):
        return f"{len(current_lines)} lines shipped, {len(generated_lines)} generated"
    return "identical line by line"


def test_every_lock_header_names_a_command_that_runs_from_the_root() -> None:
    """The header is the only instruction in the file for maintaining it."""
    broken: list[str] = []
    command = re.compile(r"^#\s+python (?P<script>\S+) (?P<argument>\S+)$")
    for manifest in _GENERATED_LOCKS:
        name = manifest.relative_to(_ROOT).as_posix()
        lines = manifest.read_text(encoding="utf-8").splitlines()
        if not lines or "GENERATED FILE" not in "\n".join(lines[:4]):
            broken.append(f"{name}: does not announce itself as generated")
            continue
        found = 0
        for line in lines:
            match = command.match(line.strip())
            if match is None:
                continue
            found += 1
            script = _ROOT / match["script"]
            argument = _ROOT / match["argument"]
            if not script.is_file():
                broken.append(f"{name}: `{match['script']}` is not a file from the repository root")
            if not argument.is_file():
                broken.append(
                    f"{name}: `{match['argument']}` is not a file from the repository root, "
                    "so the command in its header cannot be run as written"
                )
        if found == 0:
            broken.append(f"{name}: names no regeneration command")

    assert broken == [], "\n  ".join(["", *broken])


def test_the_runtime_lock_declares_its_whole_closure() -> None:
    """The image installs this file alone, with `--require-hashes`."""
    undeclared = _undeclared_closure(_LOCK_FILE)

    assert not undeclared, (
        f"{_LOCK_FILE.name} resolves {undeclared} but pins them nowhere: the image "
        f"installs this file with `pip install --require-hashes`, which refuses the "
        f"file rather than a missing package"
    )


def test_the_dev_file_declares_what_the_include_does_not_provide() -> None:
    """The dev toolchain's own closure, minus the pins its include supplies."""
    undeclared = _undeclared_closure(_DEV_FILE, also_provided=_LOCK_FILE)

    assert not undeclared, (
        f"{_DEV_FILE.name} resolves {undeclared} and neither it nor "
        f"{_LOCK_FILE.name} pins them, so `pip install --require-hashes -r "
        f"{_DEV_FILE.name}` stops before it collects a single package"
    )
