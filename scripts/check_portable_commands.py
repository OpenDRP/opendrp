#!/usr/bin/env python3
"""Fail when a documented command can only be pasted into one kind of shell.

The quick start's `manage_admin` command was four lines held together by trailing
backslashes. That is a POSIX continuation: bash and zsh read it, PowerShell and
`cmd.exe` do not. An operator on Windows pasted the block and got three errors out
of it - the first line ran without its arguments, and the remaining two were
parsed as expressions beginning with `--`. Nothing about the command looked
wrong, it was correct on Linux, and no test could see the difference.

The documentation is a list of instructions, and an instruction is only useful if
it can be pasted whole. The platform is meant to be installable from Linux,
Windows or macOS, so the rule is mechanical and applies to every file an operator
copies from:

* a backslash at the end of a line -- bash and zsh continuation;
* a backtick at the end of a line -- PowerShell continuation;
* a caret at the end of a line -- cmd.exe continuation.

None of the three travels, and none is visible in a rendered Markdown page, which
is why this is checked rather than remembered. A command that is too long to read
on one line is still one line. The one legitimate use of a trailing backslash is
a Windows directory written with its separator, so those are written without it.

Markdown is scanned inside fenced code blocks, and there all three characters
matter, because that is where commands live. A usage example inside a docstring is
scanned as well - it is what someone reads when the README is not at hand - and
only the backslash is wrong there, because a docstring also quotes values in
backticks. A configuration template is checked for the backslash alone, for the
same reason: its comments quote values in backticks and wrap nothing. Docstring
lines are read from the source rather than from the parsed value, because a
backslash at the end of a line is a continuation for Python too: the parser
returns those two lines already joined, with the character gone.

Deliberately stdlib-only, like its neighbours in this directory: the
repository-hygiene CI job installs nothing.

Usage:  python scripts/check_portable_commands.py [--root DIR]

Exit codes: 0 clean, 1 findings, 2 unreadable input.
"""

from __future__ import annotations

import argparse
import ast
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Optional, Sequence, Tuple

#: Spelled out as an escape rather than as a literal character, so that this file
#: satisfies the rule it enforces.
POSIX_CONTINUATION = chr(92)
POWERSHELL_CONTINUATION = '`'
CMD_CONTINUATION = '^'

POSIX_RULE = (POSIX_CONTINUATION, "bash/zsh line continuation")
POWERSHELL_RULE = (POWERSHELL_CONTINUATION, "PowerShell line continuation")
CMD_RULE = (CMD_CONTINUATION, "cmd.exe line continuation")

#: A fenced code block is a command, and a command has to be one line in every
#: shell. The message names the shell, because "this line ends with a backslash"
#: is not obviously a defect to someone working on Linux.
CODE_BLOCK_RULES: Tuple[Tuple[str, str], ...] = (POSIX_RULE, POWERSHELL_RULE, CMD_RULE)

#: A docstring usage example, or a comment in the configuration template. Only
#: the backslash is wrong here, because both quote values in backticks.
PROSE_RULES: Tuple[Tuple[str, str], ...] = (POSIX_RULE,)

#: Documentation an operator copies from. Listed rather than discovered by
#: walking the checkout, so the same files are scanned on a host, inside a
#: container and in CI.
DOC_ROOT_FILES: Tuple[str, ...] = (
    "README.md",
    "CHANGELOG.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    ".env.example",
)
DOC_ROOT_DIRS: Tuple[str, ...] = ("docs", "connectors", ".github")

#: The operator-facing programs: their docstrings are the instructions someone
#: reads when the README is not at hand.
SCRIPT_DIRS: Tuple[str, ...] = ("backend/scripts", "connectors")
SCRIPT_FILES: Tuple[str, ...] = ("setup.py",)

#: Generated or vendored content: a repository is not the only thing on disk.
SKIP_DIRS = frozenset(
    {".git", ".freebuff", "__pycache__", "node_modules", ".venv", "venv", "dist"}
)


class Unreadable(Exception):
    """An input file exists but cannot be read as UTF-8 text."""


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int
    character: str
    shell: str
    text: str

    def __str__(self) -> str:
        return (
            f"{self.path}:{self.line}: {self.shell} - the command cannot be pasted "
            f"on one line in another shell: {self.text.strip()!r}"
        )


def documents(root: Path) -> List[Path]:
    """The documentation files that exist under `root`, in a stable order."""
    found: List[Path] = []
    for name in DOC_ROOT_FILES:
        path = root / name
        if path.is_file():
            found.append(path)
    for name in DOC_ROOT_DIRS:
        base = root / name
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.md")):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            found.append(path)
    return found


def _rules_for(path: Path) -> Tuple[Tuple[str, str], ...]:
    """Which continuation characters matter in this kind of file."""
    return CODE_BLOCK_RULES if path.suffix == ".md" else PROSE_RULES


def _lines(path: Path, text: str) -> Iterator[Tuple[int, str]]:
    if path.suffix != ".md":
        for number, line in enumerate(text.splitlines(), start=1):
            yield number, line
        return
    in_fence = False
    for number, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            yield number, line


def _findings_on(
    path: Path, number: int, line: str, rules: Sequence[Tuple[str, str]]
) -> List[Finding]:
    """The findings for one line, given the rules that apply where it came from."""
    stripped = line.rstrip()
    return [
        Finding(path, number, character, shell, line)
        for character, shell in rules
        if stripped.endswith(character)
    ]


def scan(path: Path) -> List[Finding]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise Unreadable(f"{path}: {exc}") from exc

    findings: List[Finding] = []
    rules = _rules_for(path)
    for number, line in _lines(path, text):
        findings.extend(_findings_on(path, number, line, rules))
    return findings


def programs(root: Path) -> List[Path]:
    """The scripts whose docstrings an operator reads."""
    found: List[Path] = []
    for name in SCRIPT_FILES:
        path = root / name
        if path.is_file():
            found.append(path)
    for name in SCRIPT_DIRS:
        base = root / name
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            found.append(path)
    return found


def _docstring_lines(path: Path) -> Iterator[Tuple[int, str]]:
    """Every source line of every docstring, with its line number.

    The lines come from the source rather than from the parsed docstring: a
    backslash at the end of a line is a continuation for Python as well, so the
    value the parser returns has the two lines already joined, and the character
    that caused it is gone.
    """
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (OSError, UnicodeDecodeError, SyntaxError) as exc:
        raise Unreadable(f"{path}: {exc}") from exc

    lines = source.splitlines()
    holders = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
    for node in ast.walk(tree):
        if not isinstance(node, holders) or not getattr(node, "body", None):
            continue
        first = node.body[0]
        if not isinstance(first, ast.Expr):
            continue
        value = first.value
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            continue
        end = first.end_lineno or first.lineno
        for number in range(first.lineno, end + 1):
            if 1 <= number <= len(lines):
                yield number, lines[number - 1]


def scan_docstrings(path: Path) -> List[Finding]:
    findings: List[Finding] = []
    for number, line in _docstring_lines(path):
        findings.extend(_findings_on(path, number, line, PROSE_RULES))
    return findings


def analyse(root: Path, programs_override: Optional[Sequence[Path]] = None) -> List[Finding]:
    """All findings under `root`.

    `programs_override` exists for the test suite, which resolves the backend
    directory differently from the command line: the development overlay mounts
    it at `/app` rather than at `<checkout>/backend`.
    """
    findings: List[Finding] = []
    for path in documents(root):
        findings.extend(scan(path))
    for path in programs(root) if programs_override is None else programs_override:
        findings.extend(scan_docstrings(path))
    return findings


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail when a documented command needs a shell-specific line continuation."
    )
    parser.add_argument(
        "--root",
        default=".",
        help="checkout to scan (default: the working directory)",
    )
    args = parser.parse_args(argv)

    root = Path(args.root)
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2

    found = documents(root)
    if not found:
        print(f"nothing to scan under {root}: is this a checkout?", file=sys.stderr)
        return 2

    try:
        findings = analyse(root)
    except Unreadable as exc:
        print(f"cannot read input: {exc}", file=sys.stderr)
        return 2

    if not findings:
        print(
            f"{len(found)} documentation file(s) and "
            f"{len(programs(root))} program docstring(s): every command fits on one line"
        )
        return 0

    for finding in findings:
        print(finding)
    print()
    print(
        f"{len(findings)} finding(s). Bash, PowerShell and cmd.exe do not agree on "
        "continuations, so a wrapped command is a command that fails on two of "
        "them: keep it on one line."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
