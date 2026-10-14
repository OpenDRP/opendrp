#!/usr/bin/env python3
"""Fail when the documentation stops being a tree an operator can navigate.

Three failures are invisible in a rendered page and each of them shipped here:

1. **A relative link that points nowhere.** A rename in `docs/` leaves the pages
   that referenced it silently broken: the text still reads as an instruction and
   the reader follows it into a 404. Nothing in the repository noticed, because
   Markdown has no compiler.

2. **A page nobody can reach.** Internal audit records accumulated in `docs/`
   with no index entry, so a reader could not tell a live runbook from a
   historical note, and the only way to find a page was to list the directory.
   Reachability is checked rather than assumed: every page under `docs/` has to
   be linked from `README.md` or from the internal index.

3. **A stale migration head.** `docs/production-readiness.md` named a revision as
   the end of the chain while the tree had already moved past it, and a reader
   planning an upgrade had no way to know which of the two was true. Every
   backticked `NNNN_name` revision reference is checked against the revisions that
   exist, and a sentence that presents one as the *current* head has to name the
   head that is actually there.

`docs/internal/` records what was true when it was written, so neither revision
rule applies there: those pages quote a historical head and a historical chain on
purpose, and the audit trail of what a document used to say is worth keeping.
Their links are still checked like everyone else's, because a link that leads
nowhere strands a reader whenever the page was written.

Deliberately stdlib-only, like its neighbours in this directory: the
repository-hygiene CI job installs nothing.

Usage:  python scripts/check_docs_consistency.py [--root DIR]

Exit codes: 0 clean, 1 findings, 2 unreadable input.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Set, Tuple
from urllib.parse import unquote

#: Files an operator is expected to land on. Reachability is measured from these.
_INDEX_FILES: Tuple[Path, ...] = (
    Path("README.md"),
    Path("docs/internal/README.md"),
)

#: Documentation roots, mirroring `scripts/check_portable_commands.py`.
_ROOT_DOCUMENTS: Tuple[str, ...] = (
    "README.md",
    "CHANGELOG.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "AGENTS.md",
)
_DOC_DIRS: Tuple[str, ...] = ("docs", "connectors", ".github")

#: Generated or vendored content: a checkout is not the only thing on disk.
SKIP_DIRS = frozenset(
    {".git", ".freebuff", "__pycache__", "node_modules", ".venv", "venv", "dist"}
)

#: Targets that are not files in this repository.
_EXTERNAL_PREFIXES = ("http://", "https://", "mailto:", "tel:", "data:", "#", "//")

_INLINE_LINK = re.compile(
    r"!?\[(?P<label>[^\]]*)\]\(\s*<?(?P<target>[^)>\s]+)>?(?:\s+\"[^\"]*\")?\s*\)"
)
_FENCE = re.compile(r"^\s*(?:```|~~~)")

#: A revision reference, always written in backticks so it reads as a name.
_REVISION_TOKEN = re.compile(r"`(?P<id>\d{4}_[a-z0-9_]+)`")

#: Sentences that present a revision as the state of the tree *now*. The two
#: spellings are the ones this documentation actually uses; a page that quotes an
#: old claim without dating it is exactly the defect being looked for.
_HEAD_CLAIMS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bhead is `(?P<id>\d{4}_[a-z0-9_]+)`"),
    re.compile(r"(?i)\bmigrations? through `(?P<id>\d{4}_[a-z0-9_]+)`"),
)

_VERSIONS_DIR = Path("backend") / "alembic" / "versions"
_REVISION = re.compile(r"^\s*revision(?::[^=]+)?\s*=\s*[\"'](?P<id>[^\"']+)[\"']", re.M)
_DOWN_REVISION = re.compile(
    r"^\s*down_revision(?::[^=]+)?\s*=\s*(?P<value>.+?)\s*$", re.M
)
_QUOTED = re.compile(r"[\"'](?P<id>[^\"']+)[\"']")

#: `docs/internal/**` records history; a head claim there is a quotation.
_INTERNAL_PREFIX = Path("docs") / "internal"


class Unreadable(Exception):
    """An input file exists but cannot be read as UTF-8 text."""


def documents(root: Path) -> List[Path]:
    """The documentation files under `root`, in a stable order."""
    found: List[Path] = []
    for name in _ROOT_DOCUMENTS:
        path = root / name
        if path.is_file():
            found.append(path)
    for name in _DOC_DIRS:
        base = root / name
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.md")):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            found.append(path)
    return found


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise Unreadable(f"{path}: {exc}") from exc


def _lines_outside_fences(text: str) -> Iterable[Tuple[int, str]]:
    """Yield `(line_number, line)` for lines that are not inside a code block.

    A command in a fenced block is an example, not a link, and a `[...](...)`
    inside one is a shell glob or a Markdown sample rather than a reference to
    maintain.
    """
    in_fence = False
    for number, line in enumerate(text.splitlines(), start=1):
        if _FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        yield number, line


def _link_targets(text: str) -> Iterable[Tuple[int, str]]:
    """Yield `(line_number, target)` for every relative link in the text."""
    for number, line in _lines_outside_fences(text):
        for match in _INLINE_LINK.finditer(line):
            target = match.group("target").strip()
            if not target or target.startswith(_EXTERNAL_PREFIXES):
                continue
            yield number, target


def _resolve(source: Path, target: str, root: Path) -> Path:
    """The file a link points at, with any anchor or query removed."""
    path_part = target.split("#", 1)[0].split("?", 1)[0]
    path_part = unquote(path_part)
    return (source.parent / path_part).resolve()


def check_links(root: Path, files: Sequence[Path]) -> List[str]:
    failures: List[str] = []
    for path in files:
        # `as_posix` rather than the platform separator: the same finding has to
        # read the same on a Windows checkout and on the Linux runner.
        relative = path.relative_to(root).as_posix()
        for number, target in _link_targets(_read(path)):
            resolved = _resolve(path, target, root)
            if resolved.exists():
                continue
            failures.append(
                f"{relative}:{number}: link to `{target}` does not resolve: the "
                f"reader follows it into a page that does not exist, and nothing "
                f"else in the repository notices"
            )
    return failures


def _link_edges(
    root: Path, files: Sequence[Path]
) -> Dict[Path, Set[Path]]:
    """The documentation graph: page -> the pages it links to."""
    known = {path.resolve() for path in files}
    edges: Dict[Path, Set[Path]] = {}
    for path in files:
        linked: Set[Path] = set()
        for _number, target in _link_targets(_read(path)):
            resolved = _resolve(path, target, root)
            if resolved in known:
                linked.add(resolved)
        edges[path.resolve()] = linked
    return edges


def check_reachability(root: Path, files: Sequence[Path]) -> List[str]:
    failures: List[str] = []
    indexes = [root / name for name in _INDEX_FILES]
    existing = [path for path in indexes if path.is_file()]
    if not existing:
        return [
            "no index found (expected one of "
            f"{', '.join(str(name) for name in _INDEX_FILES)}): a documentation "
            "tree without an entry point is a directory listing"
        ]

    edges = _link_edges(root, files)
    reachable: Set[Path] = set()
    queue = [path.resolve() for path in existing]
    while queue:
        current = queue.pop()
        if current in reachable:
            continue
        reachable.add(current)
        queue.extend(edges.get(current, set()) - reachable)

    for path in files:
        relative = path.relative_to(root)
        # Only `docs/` is a tree to navigate. The root files are entry points in
        # their own right (`CONTRIBUTING.md`, `SECURITY.md`, `AGENTS.md`), and so
        # is the pull-request template: nobody reaches them through a link.
        if relative.parts[0] != "docs":
            continue
        if path.resolve() in reachable:
            continue
        failures.append(
            f"{relative.as_posix()}: not reachable from "
            f"{' or '.join(str(name) for name in _INDEX_FILES)}: an operator "
            f"cannot find this page, and a historical record cannot be told from "
            f"a live instruction"
        )
    return failures


def _revision_graph(root: Path) -> Tuple[Set[str], List[str], List[str]]:
    """The revision names that exist, and the failures the graph itself shows."""
    versions = root / _VERSIONS_DIR
    #: Everything a page may legitimately name: the revision id a file declares,
    #: and the file's own stem. The two differ — a file's stem carries the release
    #: name its revision added, while the id it declares is shorter — and an
    #: operator writing a page cannot be expected to know which they are quoting.
    revisions: Set[str] = set()
    ids: Set[str] = set()
    parents: Set[str] = set()
    failures: List[str] = []

    try:
        files = sorted(versions.glob("*.py"))
    except OSError as exc:
        return set(), [f"{_VERSIONS_DIR}: cannot list revisions ({exc})"], []

    if not files:
        return set(), [f"{_VERSIONS_DIR}: no revision files found"], []

    for path in files:
        text = _read(path)
        revisions.add(path.stem)
        match = _REVISION.search(text)
        revision_id = match.group("id") if match is not None else path.stem
        if match is None:
            failures.append(
                f"{path.name}: declares no `revision` name, so the chain cannot be "
                f"followed from this file"
            )
        revisions.add(revision_id)
        ids.add(revision_id)

        down = _DOWN_REVISION.search(text)
        if down is None:
            failures.append(f"{path.name}: declares no `down_revision`")
            continue
        value = down.group("value").strip()
        if value.startswith("None"):
            continue  # the first revision in the chain
        found = _QUOTED.search(value)
        if found is None:
            failures.append(
                f"{path.name}: `down_revision` is not a literal revision name, so "
                f"the chain cannot be followed without importing Alembic"
            )
            continue
        parents.add(found.group("id"))

    for orphan in sorted(parents - ids):
        failures.append(
            f"`{orphan}` is named as a parent revision but no file declares it"
        )

    head_ids = sorted(ids - parents)
    if len(head_ids) != 1:
        failures.append(
            f"the revision graph has {len(head_ids)} head(s): "
            f"{', '.join(head_ids) or 'none'} - the head rule below cannot be "
            f"checked against an ambiguous chain"
        )
    return revisions, failures, head_ids


def check_revisions(root: Path, files: Sequence[Path]) -> List[str]:
    revisions, failures, heads = _revision_graph(root)
    if not revisions:
        return failures
    head = heads[0] if len(heads) == 1 else None

    for path in files:
        relative = path.relative_to(root)
        display = relative.as_posix()
        if relative.parts[:2] == _INTERNAL_PREFIX.parts:
            # A dated record names the chain as it stood then; a revision that a
            # baseline has since absorbed is history, not a promise about this
            # tree. Rewriting the record to match would falsify the audit trail.
            continue
        for number, line in _lines_outside_fences(_read(path)):
            for match in _REVISION_TOKEN.finditer(line):
                token = match.group("id")
                if token not in revisions:
                    failures.append(
                        f"{display}:{number}: `{token}` is not a revision in "
                        f"{_VERSIONS_DIR}: a name nobody can check is a name that "
                        f"rots the moment the chain moves"
                    )
            if head is None:
                continue
            for claim in _HEAD_CLAIMS:
                claimed = claim.search(line)
                if claimed is None:
                    continue
                if claimed.group("id") != head:
                    failures.append(
                        f"{display}:{number}: the page presents "
                        f"`{claimed.group('id')}` as the current migration head "
                        f"while the tree ends at `{head}`: an operator planning an "
                        f"upgrade reads this as the state of the schema"
                    )
    return failures


def check(root: Path) -> List[str]:
    files = documents(root)
    if not files:
        return [f"nothing to check under {root}: is this a checkout?"]

    failures: List[str] = []
    failures.extend(check_links(root, files))
    failures.extend(check_reachability(root, files))
    failures.extend(check_revisions(root, files))
    return failures


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail when the documentation tree stops holding together."
    )
    parser.add_argument(
        "--root", default=".", help="checkout to scan (default: the working directory)"
    )
    args = parser.parse_args(argv)

    root = Path(args.root)
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2

    try:
        failures = check(root)
    except Unreadable as exc:
        print(f"docs gate: FAILED — cannot read input: {exc}", file=sys.stderr)
        return 2

    if failures:
        print("docs gate: FAILED")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    files = documents(root)
    print(
        f"docs gate: OK — {len(files)} document(s): every relative link resolves, "
        f"every page is reachable from its index, and every migration reference "
        f"names a revision that exists"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
