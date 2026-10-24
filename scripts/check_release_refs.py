#!/usr/bin/env python3
"""Fail when the release workflow checks out a ref a branch can shadow.

A tag and a branch may share a name, and this repository kept both: `v0.2.1` was
a branch *and* the tag of the release. `actions/checkout` with `ref: v0.2.1`
fetches `+refs/heads/v0.2.1*` and `+refs/tags/v0.2.1*` and then resolves the
name — to the branch. The v0.2.1 release was built that way: it compiled the
branch, whose connector locks still pinned the `certifi` the tag had already
replaced, and the only thing that noticed was Trivy, after the images had been
pushed.

The version branches were deleted on 2026-10-24, and
`scripts/check_release_branches.py` fails CI if one is created again. This gate
remains the second half of the pair: qualification is what makes a name
unambiguous for a reader or a tool that types it, and it holds even in the window
before anyone notices a branch exists.

Nothing about that run looked wrong from the inside. The version in the branch
is the same `0.2.1`, so "the tag does not name the code's version" passed; the
tag itself existed; only the tree being built was the wrong one. A name that
Git has to disambiguate is the bug, so the gate insists on the disambiguated
form: every `actions/checkout` in the release workflow must name its ref with
`refs/tags/` in it. `${{ github.ref }}` inside a tag-triggered expression still
qualifies, because on that event it *is* `refs/tags/<tag>`.

Usage
-----
    python scripts/check_release_refs.py
    python scripts/check_release_refs.py path/to/workflow.yml

Exit codes: 0 every checkout is qualified, 1 one is not (each failure is printed
with its line number), 2 the workflow cannot be read.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

_RELEASE = Path(__file__).resolve().parents[1] / ".github/workflows/release.yml"

#: `- uses: actions/checkout@<sha>`, at any indentation inside `steps:`.
_CHECKOUT = re.compile(r"^(?P<indent> *)- +uses: +actions/checkout@")
#: A key that names the ref to check out. `image-ref:` and friends are not it.
_REF_KEY = re.compile(r"^(?P<indent> +)ref: *(?P<value>.+?)\s*$")

#: What a checkout ref has to contain to be unambiguous.
_QUALIFIED = "refs/tags/"


def checkout_refs(source: str) -> list[tuple[int, str | None]]:
    """The `(line number, ref)` of every checkout step in a workflow.

    The line number is the `ref:` key's own when the step sets one, and the
    step's `- uses:` line when it does not — either way it points at the line an
    author has to edit. `ref` is `None` for a step that sets none, which is a
    failure too: checkout then takes the ref that triggered the run, and on
    `workflow_dispatch` that is whatever branch the dispatcher picked.
    """
    found: list[tuple[int, str | None]] = []
    lines = source.splitlines()
    index = 0
    while index < len(lines):
        match = _CHECKOUT.match(lines[index])
        if match is None:
            index += 1
            continue
        step_indent = len(match.group("indent"))
        step_line = index + 1
        ref: str | None = None
        ref_line = step_line
        index += 1
        # The step ends at the next line indented no deeper than its `- uses`,
        # or at the end of the file. `with:` sits deeper than the dash, and so
        # does the `ref:` under it.
        while index < len(lines):
            line = lines[index]
            if line.strip():
                indent = len(line) - len(line.lstrip())
                if indent <= step_indent and line.lstrip().startswith("- "):
                    break
                if indent <= step_indent and not line.lstrip().startswith("#"):
                    break
            ref_match = _REF_KEY.match(line)
            if ref_match is not None and ref is None:
                ref = ref_match.group("value")
                ref_line = index + 1
            index += 1
        found.append((ref_line, ref))
    return found


def validate_release_refs(source: str) -> list[str]:
    """Every checkout in the workflow names a `refs/tags/` ref."""
    failures: list[str] = []
    refs = checkout_refs(source)
    if not refs:
        return ["the release workflow has no actions/checkout step to check"]
    for line_number, ref in refs:
        if ref is None:
            failures.append(
                f"line {line_number}: the checkout sets no ref, so it takes the "
                f"triggering ref; name one under {_QUALIFIED}"
            )
        elif _QUALIFIED not in ref:
            failures.append(
                f"line {line_number}: checkout ref {ref!r} is not qualified to "
                f"{_QUALIFIED}, so a branch whose name matches the tag would be "
                f"checked out instead of the tag"
            )
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail when a release checkout names a ref a branch can shadow."
    )
    parser.add_argument(
        "workflow",
        nargs="?",
        default=str(_RELEASE),
        help="workflow file to check (defaults to the release workflow)",
    )
    args = parser.parse_args(argv)

    path = Path(args.workflow)
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"cannot read {path}: {exc}", file=sys.stderr)
        return 2

    failures = validate_release_refs(source)
    if failures:
        for failure in failures:
            print(f"{path}: {failure}", file=sys.stderr)
        return 1

    print(f"{path}: every checkout names a qualified {'refs/tags/'} ref")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
