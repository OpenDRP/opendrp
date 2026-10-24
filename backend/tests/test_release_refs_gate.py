"""The release workflow must check out a tag by a ref no branch can shadow.

`v0.2.1` exists as both a branch and a tag in this repository, and
`actions/checkout` with `ref: v0.2.1` resolves the branch. The v0.2.1 release was
built that way and shipped connector images with the `certifi` the tag had
already replaced — the tag check passed, because the branch declares the same
version. The gate this module tests reads the workflow's checkouts and refuses
any ref that is not spelled `refs/tags/...`.

The workflow, the script and `docker-compose.dev.yml` are the only inputs, and
the dev overlay mounts them read-only; a trimmed checkout skips rather than
passing on an empty file.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "scripts" / "check_release_refs.py"

if not _SCRIPT.is_file():
    pytest.skip(f"not a repository checkout: {_SCRIPT.name} missing", allow_module_level=True)

_SPEC = importlib.util.spec_from_file_location("opendrp_release_refs", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_GATE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_GATE)


def _release() -> str:
    return (_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")


def test_shipped_release_workflow_qualifies_every_checkout() -> None:
    assert _GATE.validate_release_refs(_release()) == []


def test_bare_tag_name_is_reported() -> None:
    source = _release().replace(
        "ref: refs/tags/${{ needs.verify-version.outputs.release_tag }}",
        "ref: ${{ needs.verify-version.outputs.release_tag }}",
    )

    failures = _GATE.validate_release_refs(source)

    assert failures, "a bare ref must not pass"
    assert all("is not qualified to refs/tags/" in failure for failure in failures)


def test_dispatch_checkout_without_the_tag_prefix_is_reported() -> None:
    source = _release().replace(
        "format('refs/tags/{0}', inputs.release_tag)",
        "inputs.release_tag",
    )

    failures = _GATE.validate_release_refs(source)

    assert len(failures) == 1
    assert "inputs.release_tag" in failures[0]


def test_checkout_without_a_ref_is_reported() -> None:
    source = """jobs:
  release:
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
      - name: Publish
        run: echo publish
"""

    failures = _GATE.validate_release_refs(source)

    assert failures == [
        "line 4: the checkout sets no ref, so it takes the triggering ref; "
        "name one under refs/tags/"
    ]


def test_workflow_without_a_checkout_is_reported() -> None:
    failures = _GATE.validate_release_refs("jobs:\n  release:\n    steps:\n      - run: echo hi\n")

    assert failures == ["the release workflow has no actions/checkout step to check"]


def test_image_ref_is_not_mistaken_for_a_checkout_ref() -> None:
    source = """jobs:
  build:
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          ref: refs/tags/v0.2.1
      - uses: aquasecurity/trivy-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1 # 0.35.0
        with:
          image-ref: ghcr.io/opendrp/opendrp/backend:0.2.1
"""

    assert _GATE.validate_release_refs(source) == []


def test_a_checkout_after_the_qualified_one_is_still_read() -> None:
    """The scan must not stop at the first step: every checkout in the file counts."""

    source = """jobs:
  build:
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          ref: refs/tags/v0.2.1
  publish:
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          ref: v0.2.1
"""

    failures = _GATE.validate_release_refs(source)

    assert len(failures) == 1
    assert "line 11" in failures[0]


def test_failure_points_at_the_ref_line_not_the_step() -> None:
    refs = _GATE.checkout_refs(_release())

    assert [line for line, _ in refs] == sorted(line for line, _ in refs)
    for line, ref in refs:
        assert ref is not None
        assert ref.strip() == _release().splitlines()[line - 1].strip().removeprefix("ref: ").strip()
