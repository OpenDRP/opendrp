#!/usr/bin/env python3
"""Fail when the documentation stops being a tree an operator can navigate.

Six failures are invisible in a rendered page and each of them shipped here:

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

4. **A page a document names and the repository does not have.** The alerts
   runbook was folded into `README.md`, and `docs/observability.md` went on telling
   an operator on call to reconcile a held recipient on a page that had stopped
   existing. The name was in backticks, not in a link, so rule 1 could not see it
   and nothing else could either: a written-out page name is an instruction
   whether or not it is clickable. Every `*.md` name a tracked document writes is
   resolved against the checkout — beside its own page and at the repository root,
   the two ways a reader would look.

5. **A fragment that names no section.** `docs/configuration.md#pooling` reads as
   a precise reference, and when the heading behind it is renamed the link keeps
   resolving — to the top of the right page. The reader lands somewhere plausible
   and reads the wrong paragraph. Every `#fragment` on a link into a Markdown page
   is checked against the anchors that page actually offers: its headings, slugged
   the way GitHub slugs them (lowercased, spaces to hyphens, punctuation dropped,
   repeats suffixed `-1`, `-2`), and its explicit `<a name>`/`id=` anchors.

6. **A block that renders as text instead of what it is.** An unclosed code fence
   swallows every heading after it: the page turns into one grey rectangle, its
   table of contents points into nothing, and the reader concludes the runbook
   ends where the sample begins. A table row with a cell missing renders as a
   paragraph, so a settings matrix silently loses the column its reader was
   looking for. Fences are balanced (a marker closes only its own kind, and an
   unclosed one is reported where it opened) and every table row is required to
   carry as many cells as its header — an escaped pipe in a cell is text, not a
   separator.

`docs/internal/` records what was true when it was written, so no rule but the
first applies there: those pages quote a historical head, a historical chain, the
page names of their own time and the sections they linked to then on purpose, and
the audit trail of what a document used to say is worth keeping. `CHANGELOG.md`
is the same kind of record for the surfaces a release removed — an entry naming
the page it deleted is the entry doing its job — so rules 3, 4 and 5 leave it
alone as well. The links of both are still checked like everyone else's, because
a link that leads nowhere strands a reader whenever the page was written.

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

#: A page named in a document — `docs/observability.md`, `connectors/README.md`,
#: or a bare `security.md` beside the page that names it. The negative lookaheads
#: keep the match off a longer path (`.../other.md`) and off a file that merely
#: contains a dot (`report.md.bak`).
_PAGE_NAME = re.compile(r"(?<![\w.-])(?P<name>[A-Za-z0-9_][A-Za-z0-9_./-]*\.md)(?![\w/-])")
#: A URL that ends in `.md` names somebody else's page, not one of ours.
_URL_TAIL = re.compile(r"https?://\S*$")
#: A Markdown link target, which rule 1 resolves; reporting it twice would make
#: one broken link read as two findings.
_LINK_TARGET_TAIL = re.compile(r"\]\(\s*<?$")

#: Where a bare page name is looked for, relative to the checkout and to the
#: document that names it. `docs/` and `connectors/` are the directories whose
#: pages are habitually named without a path.
_PAGE_DIRS: Tuple[str, ...] = ("docs", "connectors", ".github")

#: A record of a removed surface, not a promise about this tree.
_HISTORY_DOCUMENTS: Tuple[str, ...] = ("CHANGELOG.md",)

#: Sentences that present a revision as the state of the tree *now*. The two
#: spellings are the ones this documentation actually uses; a page that quotes an
#: old claim without dating it is exactly the defect being looked for.
_HEAD_CLAIMS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bhead is `(?P<id>\d{4}_[a-z0-9_]+)`"),
    re.compile(r"(?i)\bmigrations? through `(?P<id>\d{4}_[a-z0-9_]+)`"),
)

_VERSIONS_DIR = Path("backend") / "alembic" / "versions"
#: An ATX heading: up to three spaces, one to six `#`, the text. A closing run of
#: `#` is decoration, not part of the title.
_ATX_HEADING = re.compile(r"^ {0,3}(?P<hashes>#{1,6})(?:[ \t]+(?P<text>.*?))?[ \t]*$")
_ATX_CLOSING = re.compile(r"[ \t]+#+[ \t]*$")
#: A link label, kept while its target is dropped: GitHub builds the anchor from
#: what the reader sees, not from where the link points.
_INLINE_LINK_LABEL = re.compile(r"\[(?P<label>[^\]]*)\]\([^)]*\)")
#: An HTML tag in a heading, which GitHub does not render into the anchor.
_HTML_TAG = re.compile(r"<[^>]+>")
#: What GitHub keeps in a slug: word characters (letters, digits, `_`), hyphens
#: and spaces. Everything else is punctuation and is cut.
_SLUG_DROPPED = re.compile(r"[^\w\- ]+", re.UNICODE)
#: An anchor a page declares by hand, `<a name="x">` or `id="x"`.
_EXPLICIT_ANCHOR = re.compile(r"\b(?:name|id)\s*=\s*[\"'](?P<name>[^\"']+)[\"']")
#: A link that is not somebody else's page: the fragment rule looks at ours.
_OFFSITE_PREFIXES = ("http://", "https://", "mailto:", "tel:", "data:", "//")
_MARKDOWN_SUFFIXES = (".md", ".markdown")

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


#: A table's delimiter row: one or more dashes per column, optionally aligned.
_TABLE_DELIMITER = re.compile(r"^:?-+:?$")
_FENCE_MARKER = re.compile(r"^\s*(?P<marker>`{3,}|~{3,})")


def _table_cells(line: str) -> List[str]:
    """The cells of one table row, with escaped pipes kept as text.

    GFM splits on an unescaped `|` whether or not it sits in a code span, so a
    literal pipe is written `\\|`; that is the one escape this walks.
    """
    text = line.strip()
    cells: List[str] = []
    current: List[str] = []
    ended_with_pipe = False
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            current.append(text[index + 1])
            ended_with_pipe = False
            index += 2
            continue
        if char == "|":
            cells.append("".join(current))
            current = []
            ended_with_pipe = True
            index += 1
            continue
        current.append(char)
        ended_with_pipe = False
        index += 1
    if not ended_with_pipe:
        cells.append("".join(current))
    if text.startswith("|") and cells and not cells[0].strip():
        cells = cells[1:]
    return [cell.strip() for cell in cells]


def _is_table_row(line: str) -> bool:
    """Whether the line looks like a table row at all, pipes and all."""
    return "|" in line and bool(line.strip())


def _is_delimiter_row(line: str) -> bool:
    if "-" not in line or "|" not in line:
        return False
    cells = _table_cells(line)
    return len(cells) >= 1 and all(_TABLE_DELIMITER.match(cell) for cell in cells)


def check_fences(root: Path, files: Sequence[Path]) -> List[str]:
    """Every opened code block is closed, by a marker of its own kind."""
    failures: List[str] = []
    for path in files:
        display = path.relative_to(root).as_posix()
        opened: Tuple[int, str] | None = None
        for number, line in enumerate(_read(path).splitlines(), start=1):
            match = _FENCE_MARKER.match(line)
            if match is None:
                continue
            marker = match.group("marker")
            if opened is None:
                opened = (number, marker)
                continue
            opening_line, opening_marker = opened
            if marker[0] != opening_marker[0]:
                # A run of the other kind is sample text inside the block, not its
                # close: GFM only ends a fence with the character that opened it.
                continue
            if len(marker) < len(opening_marker):
                continue
            opened = None
        if opened is not None:
            opening_line, marker = opened
            failures.append(
                f"{display}:{opening_line}: a `{marker}` block is opened and never "
                f"closed: everything after it renders inside the sample, so the "
                f"page's headings and tables disappear into a code block"
            )
    return failures


def check_tables(root: Path, files: Sequence[Path]) -> List[str]:
    """A table's rows all carry the number of cells its header promised."""
    failures: List[str] = []
    for path in files:
        display = path.relative_to(root).as_posix()
        lines = _read(path).splitlines()
        in_fence = False
        index = 0
        while index < len(lines):
            line = lines[index]
            if _FENCE_MARKER.match(line):
                in_fence = not in_fence
                index += 1
                continue
            if in_fence:
                index += 1
                continue
            if not _is_table_row(line) or index + 1 >= len(lines):
                index += 1
                continue
            delimiter = lines[index + 1]
            if not _is_delimiter_row(delimiter):
                index += 1
                continue

            header_cells = len(_table_cells(line))
            delimiter_cells = len(_table_cells(delimiter))
            number = index + 1
            if header_cells != delimiter_cells:
                failures.append(
                    f"{display}:{number}: the table header has {header_cells} "
                    f"cell(s) and its separator has {delimiter_cells}: GitHub "
                    f"renders this as a paragraph rather than a table, and the "
                    f"reader loses the matrix it was written as"
                )
                index += 2
                continue

            row = index + 2
            while row < len(lines) and _is_table_row(lines[row]):
                cells = len(_table_cells(lines[row]))
                if cells != header_cells:
                    failures.append(
                        f"{display}:{row + 1}: the table row has {cells} cell(s) "
                        f"where its header has {header_cells}: the missing cell "
                        f"shifts everything after it into the wrong column"
                    )
                row += 1
            index = row
    return failures


def _slugify(title: str) -> str:
    """The anchor GitHub generates for a heading, as far as its text decides it.

    Lowercase, spaces turned into hyphens, punctuation dropped, link labels kept
    and HTML tags removed. The algorithm is GitHub's; a page that follows it can
    be linked into from anywhere, including from a browser's address bar.
    """
    text = _INLINE_LINK_LABEL.sub(lambda match: match.group("label"), title)
    text = _HTML_TAG.sub("", text)
    text = _SLUG_DROPPED.sub("", text.lower())
    return text.strip().replace(" ", "-")


def _anchors_in(text: str) -> Set[str]:
    """Every anchor a Markdown page offers: its headings and its named anchors.

    A repeated heading gets `-1`, `-2`, ... in document order, the way GitHub
    disambiguates two sections that read the same. Headings inside a fenced block
    are sample text, not sections, and are skipped by the same helper the link
    rules use.
    """
    anchors: Set[str] = set()
    repeated: Dict[str, int] = {}
    for _number, line in _lines_outside_fences(text):
        for match in _EXPLICIT_ANCHOR.finditer(line):
            anchors.add(match.group("name"))
        heading = _ATX_HEADING.match(line)
        if heading is None:
            continue
        title = _ATX_CLOSING.sub("", (heading.group("text") or "").strip())
        slug = _slugify(title)
        if not slug:
            continue
        anchors.add(slug)
        seen = repeated.get(slug, 0)
        if seen:
            anchors.add(f"{slug}-{seen}")
        repeated[slug] = seen + 1
    return anchors


def _fragment_targets(text: str) -> Iterable[Tuple[int, str]]:
    """Yield `(line_number, target)` for every link that names a fragment.

    A same-page link (`#section`) is included, because the page it points into is
    the one the reader is already reading.
    """
    for number, line in _lines_outside_fences(text):
        for match in _INLINE_LINK.finditer(line):
            target = match.group("target").strip()
            if "#" not in target:
                continue
            if target.startswith(_OFFSITE_PREFIXES):
                continue
            yield number, target


def check_anchors(root: Path, files: Sequence[Path]) -> List[str]:
    """Every `#fragment` on a Markdown page has to name a place on that page.

    A link whose page resolves but whose anchor does not is the same experience as
    a link to nowhere: the reader lands at the top of a page that has since been
    reorganized, and concludes the instruction is stale. `docs/internal/**` and
    `CHANGELOG.md` are excluded for the reason rule 3 excludes them — a dated
    record quotes the tree of its own time, and a heading it linked to then may
    legitimately be gone now.
    """
    failures: List[str] = []
    known: Dict[Path, Set[str]] = {}

    def anchors_of(path: Path) -> Set[str]:
        key = path.resolve()
        if key not in known:
            known[key] = _anchors_in(_read(path))
        return known[key]

    for path in files:
        relative = path.relative_to(root)
        if relative.parts[:2] == _INTERNAL_PREFIX.parts:
            continue
        if relative.name in _HISTORY_DOCUMENTS:
            continue
        display = relative.as_posix()
        # A heading nothing can slug is a heading nothing can link to; saying so
        # is better than letting a page quietly offer no anchor for it.
        for number, line in _lines_outside_fences(_read(path)):
            heading = _ATX_HEADING.match(line)
            if heading is None:
                continue
            title = _ATX_CLOSING.sub("", (heading.group("text") or "").strip())
            if title and not _slugify(title):
                failures.append(
                    f"{display}:{number}: the heading `{title}` slugs to nothing, "
                    f"so no link can name it: give it a word and the reader can "
                    f"be sent to it"
                )
        for number, target in _fragment_targets(_read(path)):
            fragment = unquote(target.split("#", 1)[1])
            if not fragment:
                # `page.md#` names the page; it makes no promise about a place in it.
                continue
            destination = path if target.startswith("#") else _resolve(path, target, root)
            if destination.suffix.lower() not in _MARKDOWN_SUFFIXES:
                continue
            if not destination.is_file():
                # The link rule reports the missing page; a second finding for its
                # anchor would make one broken link read as two.
                continue
            if fragment in anchors_of(destination):
                continue
            try:
                named = destination.relative_to(root).as_posix()
            except ValueError:  # pragma: no cover - a link outside the checkout
                named = str(destination)
            failures.append(
                f"{display}:{number}: link to `{target}` names the anchor "
                f"`{fragment}`, which `{named}` does not have: the page resolves, "
                f"so the reader is dropped at its top and reads a section that "
                f"has moved or been renamed"
            )
    return failures


def check_named_pages(root: Path, files: Sequence[Path]) -> List[str]:
    """Every page name a document writes has to be a page that exists."""
    failures: List[str] = []
    for path in files:
        relative = path.relative_to(root)
        if relative.parts[:2] == _INTERNAL_PREFIX.parts:
            continue
        if relative.name in _HISTORY_DOCUMENTS:
            continue
        display = relative.as_posix()
        for number, line in _lines_outside_fences(_read(path)):
            for match in _PAGE_NAME.finditer(line):
                before = line[: match.start()]
                if _URL_TAIL.search(before) or _LINK_TARGET_TAIL.search(before):
                    continue
                name = match.group("name")
                if _page_exists(root, path, name):
                    continue
                failures.append(
                    f"{display}:{number}: `{name}` is named as a page but no such "
                    f"file exists: a reader who goes looking for it finds nothing, "
                    f"and no link rule applies because the name is not a link"
                )
    return failures


def _page_exists(root: Path, source: Path, name: str) -> bool:
    """Whether `name`, written in `source`, names a file in the checkout.

    The reader's two readings are the ones tried: the path as written (at the
    repository root), and the same name next to the page that mentions it.
    """
    candidates = [root / name, source.parent / name]
    candidates.extend(root / directory / name for directory in _PAGE_DIRS)
    return any(candidate.exists() for candidate in candidates)


def check(root: Path) -> List[str]:
    files = documents(root)
    if not files:
        return [f"nothing to check under {root}: is this a checkout?"]

    failures: List[str] = []
    failures.extend(check_links(root, files))
    failures.extend(check_reachability(root, files))
    failures.extend(check_revisions(root, files))
    failures.extend(check_anchors(root, files))
    failures.extend(check_fences(root, files))
    failures.extend(check_tables(root, files))
    failures.extend(check_named_pages(root, files))
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
        f"every page is reachable from its index, every migration reference "
        f"names a revision that exists, every `#fragment` names a heading the "
        f"page has, every code fence is closed, every table row matches its "
        f"header, and every page a document names is a page this repository "
        f"has"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
