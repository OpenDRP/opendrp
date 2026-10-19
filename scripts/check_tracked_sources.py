#!/usr/bin/env python3
"""Fail when source files exist in the working tree but are excluded by git.

An over-broad ignore pattern removes real code from the published repository
without any local signal: the files are present, every local test passes, and
only a fresh clone shows the loss. That is exactly what happened here -- `lib/`
(a Python packaging pattern) also matched `frontend/src/lib`, so fourteen
frontend sources never reached GitHub and the published build could not resolve
`@/lib/utils`.

This check lists the files git reports as ignored, keeps only the ones that look
like source, and fails if any of them is outside a known build or dependency
directory or a directory whose ignore rule is deliberate (see
`ALLOWED_IGNORED_DIRS` below). Run it from the repository root:

    python scripts/check_tracked_sources.py [repo-root]

Exit codes: 0 clean, 1 offenders found, 0 with a notice when the directory is not
a git checkout (the backend container mounts only its own subtree).
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

SOURCE_SUFFIXES = {
    ".py",
    ".pyi",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".json",
    ".md",
    ".sql",
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".css",
    ".scss",
    ".html",
    ".sh",
    ".dockerfile",
}

# Filenames without a useful suffix that still carry source.
SOURCE_NAMES = {"Dockerfile", "Makefile", ".gitattributes", ".gitignore", ".dockerignore"}

#: A directory that is a Python virtual environment: `.venv`, `venv3`,
#: `.venv-alerts`, `.venv313`. The shape is `venv` (optionally dot-prefixed,
#: as `.gitignore` spells it) followed only by a version or a suffix. Letters are
#: part of that suffix -- `.venv-alerts` is a name a developer really used -- and
#: leaving them out of the class is why the gate failed on its own author.
_VENV_DIR = re.compile(r"^\.?venv[0-9a-z._-]*$", re.IGNORECASE)

# Directories whose ignored contents are expected: dependencies, caches and
# build output. Anything else that is ignored is treated as a mistake.
ARTIFACT_DIRS = {
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    ".tox",
    ".venv",
    "venv",
    "env",
    ".eggs",
    "eggs",
    "dist",
    "dist-ssr",
    "build",
    "coverage",
    "htmlcov",
    "reports_store",
    ".git",
    ".freebuff",
    ".vite",
}

# Ignored paths that are deliberate.
ALLOWED_IGNORED = {
    "AGENTS.md",  # agent instructions, local to the maintainer's checkout
    ".env",
    ".env.local",
    ".env.example",
    "coverage-critical.json",
    "coverage-full.json",
}

# Directories whose ignored contents are deliberate for a reason other than being
# build output: `docs/internal/` holds the audits and remediation plans this
# project wrote for itself, and `.gitignore` keeps them out of the repository on
# purpose -- the decision and its reason are recorded in
# `docs/internal/repo-hygiene-cleanup-2026-10-11.md`. A checkout that happens to
# hold them is therefore not a checkout that is missing source, which is the
# defect this gate exists for. The `lib/` incident that motivated the gate is the
# opposite case -- real code under an ignored directory -- and still fails.
ALLOWED_IGNORED_DIRS = {"docs/internal"}


def _is_in_allowed_ignored_dir(path: str) -> bool:
    """True for a path inside a directory whose ignore rule is deliberate."""
    return any(
        path == directory or path.startswith(f"{directory}/")
        for directory in ALLOWED_IGNORED_DIRS
    )


def _run(args: list[str], root: Path) -> str:
    result = subprocess.run(args, cwd=root, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def _ignored_files(root: Path) -> list[str]:
    output = _run(
        ["git", "status", "--ignored", "--porcelain", "--untracked-files=all"], root
    )
    paths: list[str] = []
    for line in output.splitlines():
        if line.startswith("!! "):
            value = line[3:].strip()
            # git quotes paths containing special characters.
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            paths.append(value)
    return paths


def _is_artifact(path: str) -> bool:
    parts = set(Path(path).parts)
    if parts & ARTIFACT_DIRS:
        return True
    # A virtual environment is an artifact whatever it is called. `.venv`,
    # `venv` and `env` are the names the rules knew; a developer who keeps two of
    # them side by side (`.venv313`, `.venv-alerts`) got a red `repo-hygiene` job
    # for a file that has nothing to do with the change being tested. The shape
    # is matched rather than listed, so the next name does not need a commit.
    return any(_VENV_DIR.match(part) for part in parts)


def _looks_like_source(path: str) -> bool:
    p = Path(path)
    return p.suffix.lower() in SOURCE_SUFFIXES or p.name in SOURCE_NAMES


def _rules_for(paths: list[str], root: Path) -> dict[str, str]:
    if not paths:
        return {}
    result = subprocess.run(
        ["git", "check-ignore", "-v", "--stdin"],
        cwd=root,
        input="\n".join(paths),
        capture_output=True,
        text=True,
        check=False,
    )
    # git emits `<source>:<linenum>:<pattern>\t<pathname>`.
    rules: dict[str, str] = {}
    for line in result.stdout.splitlines():
        source, _, pathname = line.partition("\t")
        if pathname:
            rules[pathname.strip()] = source.strip()
    return rules


def main(argv: list[str]) -> int:
    root = Path(argv[1] if len(argv) > 1 else ".").resolve()
    if not (root / ".git").exists():
        print(f"repo hygiene: {root} is not a git checkout, skipping")
        return 0

    offenders = [
        path
        for path in _ignored_files(root)
        if Path(path).name not in ALLOWED_IGNORED
        and not _is_in_allowed_ignored_dir(path)
        and not _is_artifact(path)
        and _looks_like_source(path)
    ]

    if not offenders:
        print("repo hygiene: OK - no source files are excluded from the repository")
        return 0

    rules = _rules_for(offenders, root)
    print("repo hygiene: FAILED - ignored source files would be missing from a clone:")
    for path in sorted(offenders):
        rule = rules.get(path, "unknown rule")
        print(f"  {path}   (ignored by: {rule})")
    print()
    print("Fix the ignore rule (scope it, e.g. `backend/lib/` instead of `lib/`) or")
    print("add the path to ALLOWED_IGNORED in scripts/check_tracked_sources.py.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
