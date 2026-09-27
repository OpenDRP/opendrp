"""There is no compatibility surface, and a gate that keeps it that way.

0.1.0 is the first release, so nothing in this repository has to understand an
earlier version of itself: no second wire format, no tolerated old field, no
revision that only exists to migrate a database that was created by a build
nobody has. Compatibility branches are not free even when they are correct — each
one doubles the set of states the platform can be in, and the second state is the
one no test exercises.

Every assertion here is a property someone could remove deliberately and forget
the consequence of, which is why they live in a test rather than in a comment.
Two kinds are checked:

* **Vocabulary.** A comment that says "kept for compatibility" is how the next
  compatibility branch is justified, so the shipped code may not explain itself
  that way at all — name the mechanism instead.
* **Shape.** One baseline revision, no reference to a revision that no longer
  exists, and none of the machinery that was deleted under a name that could
  come back.

The tests and the changelog are deliberately out of scope: a test has to be able
to assert that a name is *gone*, and the changelog has to be able to say what was
removed.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]

#: Everything that ships: the image contents, the installer, and the Compose files.
_SHIPPED_TREES = (
    "backend/app",
    "backend/alembic/versions",
    "connectors",
    "frontend/src",
    "docker",
    "scripts",
)
_SHIPPED_FILES = (
    "setup.py",
    "Makefile",
    "docker-compose.yml",
    "docker-compose.dev.yml",
    "docker-compose.replicas.yml",
)

#: Reading material an operator or a contributor follows.
_DOC_FILES = ("README.md", "CONTRIBUTING.md")
_DOC_TREES = ("docs",)

_TEXT_SUFFIXES = {".py", ".ts", ".tsx", ".sh", ".yml", ".yaml", ".sql", ".conf", ".json"}
_TEXT_NAMES = {"Makefile", "Dockerfile", ".env.example"}
_SKIP_DIRS = {"node_modules", "dist", "__pycache__", ".mypy_cache", ".ruff_cache", ".pytest_cache"}

_MISSING = [path for path in (*_SHIPPED_TREES, *_SHIPPED_FILES) if not (_ROOT / path).exists()]
if _MISSING:
    pytest.skip(
        f"not a repository checkout: {', '.join(_MISSING)} missing",
        allow_module_level=True,
    )

#: Language that exists to describe a previous version of this project. The list
#: is deliberately short and unambiguous: every entry here means "we are keeping
#: something alive for a state that no longer exists". Words that merely sound
#: similar are left out on purpose — "an older TLS version" and "a previously
#: generated report" are descriptions of the present, not promises to the past.
_COMPAT_VOCABULARY = (
    (r"\blegacy\b", "'legacy' describes a previous version a first release has none of"),
    (r"backwards?[\s-]?compat", "'backward compatible' promises a state that never shipped"),
    (r"back[\s-]?compat", "'back-compat' promises a state that never shipped"),
    (r"\bcompatib", "name the mechanism instead of citing compatibility"),
    (r"\bold\s+(?:format|column|field|name|version)\b", "there is no old format to accept"),
    (
        r"migrat\w*\s+from\s+(?:an?\s+)?(?:old|earlier|previous|legacy)",
        "there is nothing to migrate from",
    ),
    (
        r"\bpreviously\s+(?:named|called|stored|written|used)\b",
        "no earlier version shipped",
    ),
)

#: Names of the compatibility machinery that was deleted. In shipped code they
#: may not return under the same name; the message says what replaced each.
_REMOVED_NAMES = (
    (r"takedown_status", "the column is named 'status'"),
    (r"legacy_rows\b", "every audit row is signed; there is no unsigned prefix"),
    (r"fallback_job_type", "a job type is declared, never inferred"),
    (r"default_job_type_for\b", "a job type is declared, never inferred"),
    (r"send_alert_notification\b", "delivery goes through the alert queue"),
    (r"event_hooks\b", "ingestion hands findings to the alert queue"),
    (r"connector\.scan(?!\.)", "the shared job-type bucket was removed; each connector owns its type"),
    (r"/api/v1/hibp\b", "the API group is /api/v1/breaches"),
    (r"/hibp/(?:scan|breaches)\b", "the API group is /api/v1/breaches"),
    (r"\blimit\b\s*=\s*Query\(None", "page size is spelled 'size' only"),
)

#: A revision file name, as referenced by a document or a comment.
_REVISION_REFERENCE = re.compile(r"\b(0\d{3}_[a-z0-9_]+)\b")

_BASELINE = "0001_initial_schema"


def _iter_files(paths: tuple[str, ...]) -> list[Path]:
    """Every text file under these paths, skipping build and tool caches."""
    found: list[Path] = []
    for raw in paths:
        path = _ROOT / raw
        if path.is_file():
            found.append(path)
            continue
        for candidate in sorted(path.rglob("*")):
            if not candidate.is_file():
                continue
            if any(part in _SKIP_DIRS for part in candidate.parts):
                continue
            if candidate.suffix in _TEXT_SUFFIXES or candidate.name in _TEXT_NAMES:
                found.append(candidate)
    return found


def _lines(paths: tuple[str, ...]):
    for path in _iter_files(paths):
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):  # pragma: no cover - binary or unreadable
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            yield path, number, line


# ==============================================================================
# Vocabulary
# ==============================================================================
def test_shipped_code_does_not_explain_itself_as_compatibility() -> None:
    """A "kept for compatibility" comment is how the next branch gets written."""
    offences: list[str] = []
    for pattern, why in _COMPAT_VOCABULARY:
        matcher = re.compile(pattern, re.IGNORECASE)
        for path, number, line in _lines((*_SHIPPED_TREES, *_SHIPPED_FILES)):
            if matcher.search(line):
                offences.append(f"{path.relative_to(_ROOT)}:{number}: {why}\n    {line.strip()}")

    assert not offences, "compatibility vocabulary in shipped code:\n" + "\n".join(offences)


def test_documentation_describes_one_version() -> None:
    """Operator-facing prose may not send a reader looking for an older state."""
    offences: list[str] = []
    for pattern, why in _COMPAT_VOCABULARY:
        matcher = re.compile(pattern, re.IGNORECASE)
        for path, number, line in _lines((*_DOC_FILES, *_DOC_TREES)):
            if matcher.search(line):
                offences.append(f"{path.relative_to(_ROOT)}:{number}: {why}\n    {line.strip()}")

    assert not offences, "compatibility vocabulary in documentation:\n" + "\n".join(offences)


# ==============================================================================
# Shape
# ==============================================================================
def test_the_removed_machinery_is_not_back_under_the_same_name() -> None:
    offences: list[str] = []
    for pattern, replacement in _REMOVED_NAMES:
        matcher = re.compile(pattern)
        for path, number, line in _lines((*_SHIPPED_TREES, *_SHIPPED_FILES, *_DOC_FILES, *_DOC_TREES)):
            if matcher.search(line):
                offences.append(
                    f"{path.relative_to(_ROOT)}:{number}: {replacement}\n    {line.strip()}"
                )

    assert not offences, "removed compatibility machinery is back:\n" + "\n".join(offences)


def test_there_is_exactly_one_migration_and_it_is_the_baseline() -> None:
    """A second revision would be a migration this release cannot need.

    Everything the schema ever required is in the baseline, so a new file here
    means either a compatibility migration or a change that should have gone into
    the baseline.
    """
    versions = _ROOT / "backend" / "alembic" / "versions"
    revisions = sorted(
        path.name for path in versions.glob("*.py") if not path.name.startswith("__")
    )

    assert revisions == [f"{_BASELINE}.py"], f"unexpected revision files: {revisions}"


def test_the_baseline_starts_from_nothing() -> None:
    baseline = (_ROOT / "backend" / "alembic" / "versions" / f"{_BASELINE}.py").read_text(
        encoding="utf-8"
    )

    assert re.search(
        r"^down_revision\s*(?::[^=]+)?=\s*None\s*$", baseline, flags=re.M
    ), "the baseline must not follow another revision"


def test_nothing_references_a_revision_that_does_not_exist() -> None:
    """A document or a comment naming a deleted revision is how a reader ends up
    looking for a file that is not there."""
    versions = _ROOT / "backend" / "alembic" / "versions"
    existing = {path.stem for path in versions.glob("*.py")}
    scanned = (
        *_SHIPPED_TREES,
        *_SHIPPED_FILES,
        *_DOC_FILES,
        *_DOC_TREES,
        ".github/workflows",
    )

    stale: list[str] = []
    for path, number, line in _lines(scanned):
        if path.parent == versions:
            continue
        for reference in _REVISION_REFERENCE.findall(line):
            if reference not in existing:
                stale.append(f"{path.relative_to(_ROOT)}:{number}: {reference}\n    {line.strip()}")

    assert not stale, "references to revisions that do not exist:\n" + "\n".join(stale)
