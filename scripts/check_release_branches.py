#!/usr/bin/env python3
"""Fail when a version branch exists: the tag is the only ref a release is known by.

`v0.2.1` used to be a branch *and* a tag in this repository, and the two pointed
at different trees: the branch still pinned the `certifi` the tag had already
replaced. The first v0.2.1 release run checked out the bare name, resolved the
branch, and built it — the tag-versus-code check passed, because both declare
`0.2.1`, and only the image scan noticed, after the push.

Two things came of that. The workflow names `refs/tags/<tag>` in every checkout
(`scripts/check_release_refs.py` keeps it that way), and the branch was deleted.
Deleting it is the part that removes the ambiguity rather than working around it:
the tag is the release, and the branch was a second ref with the same name, a
different lifetime and nothing in it the tag did not have — every version branch
was a copy of a released state, kept for a `git clone --branch` that nothing in
this repository or its documentation performs.

So the branches are gone (v0.1.0 … v0.2.1, 2026-10-24), and this gate keeps them
from coming back. A `git push origin v0.3.0` typed where `git push origin
v0.3.0^{}`-style tag creation was meant now fails the build with the command that
removes it, instead of quietly creating the second ref the next release has to
work around.

Usage
-----
    python scripts/check_release_branches.py                  # asks origin
    python scripts/check_release_branches.py --remote upstream
    python scripts/check_release_branches.py --input listing.txt

`--input` reads a saved `git ls-remote --heads <remote>` listing, which is how the
tests drive this without a network or a repository.

Exit codes: 0 no version branch exists, 1 one does (each is printed with its
commit), 2 the branch list cannot be read.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

#: A release's own name with a leading `v` — the branch form the tags must not compete with.
_VERSION_BRANCH = re.compile(r"^v\d+\.\d+\.\d+$")

#: One line of `git ls-remote --heads`: `<sha>\trefs/heads/<name>`.
_HEAD = re.compile(r"^(?P<sha>[0-9a-f]{40})\s+refs/heads/(?P<name>.+?)\s*$")


def heads(listing: str) -> list[tuple[str, str]]:
    """The `(sha, branch name)` pairs in a `git ls-remote --heads` listing."""
    found: list[tuple[str, str]] = []
    for line in listing.splitlines():
        match = _HEAD.match(line)
        if match is not None:
            found.append((match.group("sha"), match.group("name")))
    return found


def version_branches(listing: str) -> list[tuple[str, str]]:
    """The pairs whose name is a release version: `v1.2.3` and nothing else."""
    return [(sha, name) for sha, name in heads(listing) if _VERSION_BRANCH.match(name)]


def validate(listing: str) -> list[str]:
    """Every version branch, as a failure naming the command that removes it."""
    return [
        f"branch {name!r} at {sha[:8]} is a version branch: the tag of that name "
        f"is the release, and a branch beside it is the ref that made the v0.2.1 "
        f"release build the wrong tree — delete it with "
        f"`git push origin --delete refs/heads/{name}`"
        for sha, name in version_branches(listing)
    ]


class GitError(RuntimeError):
    """The branch list could not be read from the remote."""


def read_listing(remote: str) -> str:
    """`git ls-remote --heads <remote>`, or a `GitError` when git cannot answer."""
    completed = subprocess.run(
        ["git", "ls-remote", "--heads", remote],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise GitError(completed.stderr.strip() or f"git ls-remote exited {completed.returncode}")
    return completed.stdout


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail when a version branch exists beside its release tag."
    )
    parser.add_argument(
        "--remote",
        default="origin",
        help="remote whose branches are read (defaults to origin)",
    )
    parser.add_argument(
        "--input",
        default=None,
        help="read a saved `git ls-remote --heads` listing instead of asking the remote",
    )
    args = parser.parse_args(argv)

    if args.input is not None:
        path = Path(args.input)
        try:
            listing = path.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"cannot read {path}: {exc}", file=sys.stderr)
            return 2
        source = str(path)
    else:
        try:
            listing = read_listing(args.remote)
        except (GitError, OSError) as exc:
            print(f"cannot list the branches of {args.remote}: {exc}", file=sys.stderr)
            return 2
        source = f"{args.remote} (git ls-remote --heads)"

    failures = validate(listing)
    if failures:
        for failure in failures:
            print(f"{source}: {failure}", file=sys.stderr)
        return 1

    print(
        f"{source}: no version branch exists — "
        f"{len(heads(listing))} branch(es) checked, the tags are the releases"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
