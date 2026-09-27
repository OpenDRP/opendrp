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
directory. Run it from the repository root:

    python scripts/check_tracked_sources.py [repo-root]

Exit codes: 0 clean, 1 offenders found, 0 with a notice when the directory is not
a git checkout (the backend container mounts only its own subtree).
"""

from __future__ import annotations

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
    return bool(set(Path(path).parts) & ARTIFACT_DIRS)


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
