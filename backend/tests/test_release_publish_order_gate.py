"""The release workflow must create its release tags only after the scan passes.

The first v0.2.1 run pushed `<version>` and `latest`, then failed on Trivy: the
gate stopped the workflow after the publication and the rejected images stayed
reachable by `latest` until someone re-ran the release. The gate this module
tests reads the `build-and-push` job and refuses any shape in which a release tag
exists before the scan — a build that pushes one, a `docker push` before it, a
promotion step ordered ahead of it, or a scan that names a tag instead of the
digest the promotion copies.

The workflow is the only input, so a trimmed checkout skips rather than passing on
an empty file.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "scripts" / "check_release_publish_order.py"

if not _SCRIPT.is_file():
    pytest.skip(f"not a repository checkout: {_SCRIPT.name} missing", allow_module_level=True)

_SPEC = importlib.util.spec_from_file_location("opendrp_release_publish_order", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_GATE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_GATE)


def _release() -> str:
    return (_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")


def _job(steps: str) -> str:
    """A workflow whose only job is `build-and-push`, with `steps` as its body."""
    body = "".join(f"      {line}\n" if line else "\n" for line in steps.strip("\n").splitlines())
    return f"jobs:\n  build-and-push:\n    runs-on: ubuntu-latest\n    steps:\n{body}"


def test_shipped_release_workflow_publishes_only_after_the_scan() -> None:
    assert _GATE.validate_release_order(_release()) == []


def test_the_old_order_is_reported() -> None:
    """The shape that shipped v0.2.1: one step pushes the release tags and latest."""

    source = _release().replace(
        ":${{ needs.verify-version.outputs.version }}-candidate",
        ":${{ needs.verify-version.outputs.version }},"
        "${{ steps.prefix.outputs.value }}/${{ matrix.image }}:latest",
    )

    failures = _GATE.validate_release_order(source)

    assert failures, "the v0.2.1 order must not pass"
    assert any("-candidate tag" in failure for failure in failures)
    assert any(":latest" in failure for failure in failures)


def test_a_build_that_does_not_push_is_reported() -> None:
    """`load: true` would leave the scan nothing to name by digest."""

    source = _release().replace("          push: true", "          push: false")

    failures = _GATE.validate_release_order(source)

    assert len(failures) == 1
    assert "does not push" in failures[0]


def test_a_scan_that_reads_a_tag_is_reported() -> None:
    source = _release().replace(
        "@${{ steps.build.outputs.digest }}",
        ":${{ needs.verify-version.outputs.version }}-candidate",
    )

    failures = _GATE.validate_release_order(source)

    assert len(failures) == 1
    assert "rather than a digest" in failures[0]


def test_a_promotion_before_the_scan_is_reported() -> None:
    source = _job(
        """
- name: Promote the scanned digest to the release tags
  env:
    VERSION: ${{ needs.verify-version.outputs.version }}
  run: |
    docker buildx imagetools create --tag "${IMAGE}:${VERSION}" --tag "${IMAGE}:latest" "${IMAGE}@${{ steps.build.outputs.digest }}"
- name: Build the candidate image
  uses: docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8
  with:
    push: true
    tags: ghcr.io/opendrp/opendrp:1.0.0-candidate
- name: Scan the candidate digest
  uses: aquasecurity/trivy-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1
  with:
    image-ref: ghcr.io/opendrp/opendrp@${{ steps.build.outputs.digest }}
"""
    )

    failures = _GATE.validate_release_order(source)

    assert len(failures) == 1
    assert failures[0].startswith("line 5: ")
    assert "created before the scan" in failures[0]


def test_a_docker_push_before_the_scan_is_reported() -> None:
    source = _job(
        """
- name: Push by hand
  run: docker push ghcr.io/opendrp/opendrp:1.0.0
- name: Build the candidate image
  uses: docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8
  with:
    push: true
    tags: ghcr.io/opendrp/opendrp:1.0.0-candidate
- name: Scan the candidate digest
  uses: aquasecurity/trivy-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1
  with:
    image-ref: ghcr.io/opendrp/opendrp@${{ steps.build.outputs.digest }}
- name: Promote
  env:
    VERSION: ${{ needs.verify-version.outputs.version }}
  run: docker buildx imagetools create --tag "${IMAGE}:${VERSION}" --tag "${IMAGE}:latest" "${IMAGE}@${{ steps.build.outputs.digest }}"
"""
    )

    failures = _GATE.validate_release_order(source)

    assert len(failures) == 1
    assert failures[0].startswith("line 5: ")
    assert "docker push runs before the scan" in failures[0]


def test_a_promotion_without_the_scanned_digest_is_reported() -> None:
    source = _job(
        """
- name: Build the candidate image
  uses: docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8
  with:
    push: true
    tags: ghcr.io/opendrp/opendrp:1.0.0-candidate
- name: Scan the candidate digest
  uses: aquasecurity/trivy-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1
  with:
    image-ref: ghcr.io/opendrp/opendrp@${{ steps.build.outputs.digest }}
- name: Promote
  env:
    VERSION: ${{ needs.verify-version.outputs.version }}
  run: docker buildx imagetools create --tag "${IMAGE}:${VERSION}" --tag "${IMAGE}:latest" "${IMAGE}:1.0.0-candidate"
"""
    )

    failures = _GATE.validate_release_order(source)

    assert len(failures) == 1
    assert "does not copy the scanned digest" in failures[0]


def test_a_promotion_without_latest_is_reported() -> None:
    source = _job(
        """
- name: Build the candidate image
  uses: docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8
  with:
    push: true
    tags: ghcr.io/opendrp/opendrp:1.0.0-candidate
- name: Scan the candidate digest
  uses: aquasecurity/trivy-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1
  with:
    image-ref: ghcr.io/opendrp/opendrp@${{ steps.build.outputs.digest }}
- name: Promote
  env:
    VERSION: ${{ needs.verify-version.outputs.version }}
  run: docker buildx imagetools create --tag "${IMAGE}:${VERSION}" "${IMAGE}@${{ steps.build.outputs.digest }}"
"""
    )

    failures = _GATE.validate_release_order(source)

    assert len(failures) == 1
    assert "`latest` tag" in failures[0]


def test_no_scan_step_is_reported() -> None:
    source = _job(
        """
- name: Build the candidate image
  uses: docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8
  with:
    push: true
    tags: ghcr.io/opendrp/opendrp:1.0.0-candidate
- name: Promote
  env:
    VERSION: ${{ needs.verify-version.outputs.version }}
  run: docker buildx imagetools create --tag "${IMAGE}:${VERSION}" --tag "${IMAGE}:latest" "${IMAGE}@${{ steps.build.outputs.digest }}"
"""
    )

    failures = _GATE.validate_release_order(source)

    assert len(failures) == 1
    assert "exactly one aquasecurity/trivy-action step, found 0" in failures[0]


def test_two_builds_are_reported() -> None:
    """A rebuild is a different artifact from the one the scan read."""

    source = _job(
        """
- name: Build the candidate image
  uses: docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8
  with:
    push: true
    tags: ghcr.io/opendrp/opendrp:1.0.0-candidate
- name: Build it again
  uses: docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8
  with:
    push: true
    tags: ghcr.io/opendrp/opendrp:1.0.0-candidate
- name: Scan the candidate digest
  uses: aquasecurity/trivy-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1
  with:
    image-ref: ghcr.io/opendrp/opendrp@${{ steps.build.outputs.digest }}
- name: Promote
  env:
    VERSION: ${{ needs.verify-version.outputs.version }}
  run: docker buildx imagetools create --tag "${IMAGE}:${VERSION}" --tag "${IMAGE}:latest" "${IMAGE}@${{ steps.build.outputs.digest }}"
"""
    )

    failures = _GATE.validate_release_order(source)

    assert len(failures) == 1
    assert "exactly one docker/build-push-action step, found 2" in failures[0]


def test_no_promotion_step_is_reported() -> None:
    source = _job(
        """
- name: Build the candidate image
  uses: docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8
  with:
    push: true
    tags: ghcr.io/opendrp/opendrp:1.0.0-candidate
- name: Scan the candidate digest
  uses: aquasecurity/trivy-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1
  with:
    image-ref: ghcr.io/opendrp/opendrp@${{ steps.build.outputs.digest }}
"""
    )

    failures = _GATE.validate_release_order(source)

    assert failures == [
        "no step promotes the scanned digest to the release tags "
        "(docker buildx imagetools create)"
    ]


def test_a_workflow_without_the_build_job_is_reported() -> None:
    failures = _GATE.validate_release_order(
        "jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
    )

    assert failures == ["the release workflow has no build-and-push job"]


def test_a_build_job_without_steps_is_reported() -> None:
    failures = _GATE.validate_release_order(
        "jobs:\n  build-and-push:\n    runs-on: ubuntu-latest\n"
    )

    assert failures == ["the build-and-push job has no steps"]
