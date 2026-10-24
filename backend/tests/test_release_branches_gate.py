"""A version branch must never exist beside its tag.

`v0.2.1` was both a branch and a tag, the two pointed at different trees, and the
first v0.2.1 release built the branch. The workflow now names `refs/tags/` in every
checkout, but that only removes the ambiguity from the workflow: as long as a
`vX.Y.Z` branch exists, a bare-name checkout, a mistyped `git push origin v0.3.0`
or a reader's assumption can still pick the wrong ref. The branches were deleted
(v0.1.0 … v0.2.1, 2026-10-24) and this gate keeps them from returning.

The tests drive the gate with saved `git ls-remote --heads` listings, so they need
no network and no repository; the script and the workflow that runs it are read
from the checkout, and a trimmed checkout skips rather than passing on an empty
file.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "scripts" / "check_release_branches.py"
_CI = _ROOT / ".github" / "workflows" / "ci.yml"

if not _SCRIPT.is_file() or not _CI.is_file():
    pytest.skip(
        f"not a repository checkout: {_SCRIPT.name} or {_CI.name} missing",
        allow_module_level=True,
    )

_SPEC = importlib.util.spec_from_file_location("opendrp_release_branches", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_GATE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_GATE)

_MAIN = "68cd72961ccc5ee5bcb522c928d1531bfa53e406\trefs/heads/main\n"
_FEATURE = "35151c041f6368a0fc0d1db1df702a165356cf88\trefs/heads/ci/dev-deps-and-tag-trigger\n"
_VERSION = "fde7ad3b1b2b1b1b1b1b1b1b1b1b1b1b1b1b1b1b\trefs/heads/v0.2.1\n"


def _listing(tmp_path: Path, *lines: str) -> Path:
    path = tmp_path / "heads.txt"
    path.write_text("".join(lines), encoding="utf-8")
    return path


def test_ordinary_branches_pass() -> None:
    assert _GATE.validate(_MAIN + _FEATURE) == []


def test_a_version_branch_is_reported_with_the_command_that_removes_it() -> None:
    failures = _GATE.validate(_MAIN + _VERSION)

    assert len(failures) == 1
    assert "'v0.2.1'" in failures[0]
    assert failures[0].startswith("branch 'v0.2.1' at fde7ad3b")
    assert "git push origin --delete refs/heads/v0.2.1" in failures[0]


def test_every_version_branch_is_reported() -> None:
    failures = _GATE.validate(_VERSION + _VERSION.replace("v0.2.1", "v0.1.2"))

    assert len(failures) == 2


def test_a_name_that_only_looks_like_a_version_is_not_one() -> None:
    other = "".join(
        f"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\trefs/heads/{name}\n"
        for name in ("v0.2", "v0.2.1-rc1", "version-0.2.1", "release/v0.2.1", "vnext")
    )

    assert _GATE.validate(other) == []


def test_tag_refs_in_the_listing_are_ignored() -> None:
    """`--heads` never returns tags, but a saved listing may carry them."""

    tags = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\trefs/tags/v0.2.1\n"

    assert _GATE.validate(_MAIN + tags) == []


def test_main_exits_one_and_names_each_branch(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    listing = _listing(tmp_path, _MAIN, _VERSION)

    assert _GATE.main(["--input", str(listing)]) == 1

    captured = capsys.readouterr()
    assert str(listing) in captured.err
    assert "v0.2.1" in captured.err


def test_main_exits_zero_when_no_version_branch_exists(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    listing = _listing(tmp_path, _MAIN, _FEATURE)

    assert _GATE.main(["--input", str(listing)]) == 0

    captured = capsys.readouterr()
    assert "no version branch exists" in captured.out
    assert "2 branch(es) checked" in captured.out


def test_an_unreadable_listing_is_exit_two(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert _GATE.main(["--input", str(tmp_path / "absent.txt")]) == 2
    assert "cannot read" in capsys.readouterr().err


def test_a_listing_with_no_heads_line_passes_rather_than_failing_open(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An empty answer is not an error, but it must not be read as a version branch either."""

    listing = _listing(tmp_path, "not a ls-remote line\n")

    assert _GATE.main(["--input", str(listing)]) == 0
    assert "0 branch(es) checked" in capsys.readouterr().out


def test_ci_runs_the_gate() -> None:
    """A gate no workflow runs is a script, not a gate."""

    assert "scripts/check_release_branches.py" in _CI.read_text(encoding="utf-8")
