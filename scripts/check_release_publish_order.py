#!/usr/bin/env python3
"""Fail when the release workflow creates a release tag before the scan passes.

The first v0.2.1 release run built the wrong tree (see
`scripts/check_release_refs.py`), and the order of the steps turned that into a
publication rather than a red build: `docker/build-push-action` pushed the
`<version>` and `latest` tags, *then* Trivy read the pushed image and failed. The
gate stopped the workflow, but an operator pulling `latest` in the meantime got
the images the gate had just rejected, and only a re-run replaced them.

The order this gate enforces is the one that makes the scan load-bearing:

  * the `build-and-push` job builds once and pushes exactly one tag,
    `...-candidate` — a tag no Compose file names and no page documents;
  * Trivy scans that build's **digest**, not a tag, so the thing reviewed is a
    single immutable manifest;
  * `<version>` and `latest` are created afterwards, from that digest, by
    `docker buildx imagetools create` — a manifest copy, so the bytes under the
    release tags are the bytes the scan read, attestations included;
  * nothing else in the job pushes a tag: a second `docker push`, a build that
    pushes a release tag, or a local build that is pushed later all fail here.

Why not build locally (`load: true`), scan, then push? Because the docker
exporter cannot carry the SBOM and provenance attestations this release promises
— BuildKit drops them silently — so that shape would trade a documented
supply-chain property for the ordering. Pushing one candidate tag is the price of
keeping both.

Usage
-----
    python scripts/check_release_publish_order.py
    python scripts/check_release_publish_order.py path/to/workflow.yml

Exit codes: 0 the order holds, 1 it does not (each failure is printed with its
line number), 2 the workflow cannot be read.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

_RELEASE = Path(__file__).resolve().parents[1] / ".github/workflows/release.yml"

#: The job that builds and publishes the images. The release-notes job is a
#: different concern and has no tags to create.
_JOB = "build-and-push"

#: The only suffix a tag pushed before the scan may carry.
_CANDIDATE = "-candidate"

#: `- name:` / `- uses:` at the indent the job's steps use.
_STEP_START = re.compile(r"^(?P<indent> *)- +(?P<rest>\S.*)$")

#: The one-shot keys this gate reads. They are all written inline in the
#: workflow, so a value is the rest of its line.
_PUSH = re.compile(r"^\s*push: *(?P<value>.+?)\s*$")
_TAGS = re.compile(r"^\s*tags: *(?P<value>.+?)\s*$")
_IMAGE_REF = re.compile(r"^\s*image-ref: *(?P<value>.+?)\s*$")

#: A shell push of a tag by hand, and the promotion step itself.
_DOCKER_PUSH = re.compile(r"\bdocker +push\b")
_IMAGETOOLS = re.compile(r"\bimagetools +create\b")


class Step:
    """One `- ...` entry of a job's `steps:` list."""

    def __init__(self, line_number: int, lines: list[str]) -> None:
        self.line_number = line_number
        self.lines = lines

    @property
    def text(self) -> str:
        return "\n".join(self.lines)

    def value(self, pattern: re.Pattern[str]) -> str | None:
        for line in self.lines:
            match = pattern.match(line)
            if match is not None:
                return match.group("value")
        return None

    def uses(self) -> str | None:
        for line in self.lines:
            match = re.match(r"^\s*(?:- +)?uses: *(?P<value>\S+)", line)
            if match is not None:
                return match.group("value")
        return None


def job_body(source: str, job: str) -> list[tuple[int, str]] | None:
    """The `(1-based line number, text)` of a job's block, `None` if absent."""
    lines = source.splitlines()
    start = None
    for index, line in enumerate(lines):
        if re.match(rf"^  {re.escape(job)}: *$", line):
            start = index
            break
    if start is None:
        return None
    body: list[tuple[int, str]] = []
    for index in range(start + 1, len(lines)):
        line = lines[index]
        # A top-level key (`jobs:`, `on:`) or a line that starts at column 0
        # ends the file's job section; the next job at two-space indent ends
        # this one.
        if line and not line.startswith(" "):
            break
        if re.match(r"^  [A-Za-z0-9_-]+: *$", line):
            break
        body.append((index + 1, line))
    return body


def steps_of(body: list[tuple[int, str]]) -> list[Step]:
    """Split a job body into steps, at the dash indent the `steps:` list uses.

    The dash indent is read from the list that follows the `steps:` key, not
    from the first dash in the job: the matrix above it is a list too, and its
    dashes sit deeper, so guessing from the first one finds the matrix entries
    and misses every step.
    """
    steps_line = None
    for index, (_, line) in enumerate(body):
        if re.match(r"^\s*steps: *$", line):
            steps_line = index
            break
    if steps_line is None:
        return []

    dash_indent = None
    for _, line in body[steps_line + 1 :]:
        match = _STEP_START.match(line)
        if match is not None:
            dash_indent = len(match.group("indent"))
            break
    if dash_indent is None:
        return []

    steps: list[Step] = []
    current: Step | None = None
    for line_number, line in body[steps_line + 1 :]:
        match = _STEP_START.match(line)
        is_start = match is not None and len(match.group("indent")) == dash_indent
        if is_start:
            if current is not None:
                steps.append(current)
            current = Step(line_number, [line])
            continue
        if current is None:
            continue
        # A key at or above the dash's own indent closes the step.
        if line.strip() and len(line) - len(line.lstrip()) <= dash_indent:
            steps.append(current)
            current = None
            continue
        current.lines.append(line)
    if current is not None:
        steps.append(current)
    return steps


def _is_build(step: Step) -> bool:
    uses = step.uses()
    return uses is not None and uses.startswith("docker/build-push-action")


def _is_scan(step: Step) -> bool:
    uses = step.uses()
    return uses is not None and uses.startswith("aquasecurity/trivy-action")


def _is_promotion(step: Step) -> bool:
    return _IMAGETOOLS.search(step.text) is not None


def validate_release_order(source: str) -> list[str]:
    """The build job pushes a candidate, scans a digest, and only then tags."""
    body = job_body(source, _JOB)
    if body is None:
        return [f"the release workflow has no {_JOB} job"]

    steps = steps_of(body)
    if not steps:
        return [f"the {_JOB} job has no steps"]

    builds = [index for index, step in enumerate(steps) if _is_build(step)]
    scans = [index for index, step in enumerate(steps) if _is_scan(step)]
    promotions = [index for index, step in enumerate(steps) if _is_promotion(step)]

    failures: list[str] = []

    if len(builds) != 1:
        failures.append(
            f"the {_JOB} job must contain exactly one docker/build-push-action "
            f"step, found {len(builds)}: a second build is a second artifact, and "
            "the scan would not be the one the release tags name"
        )
    if len(scans) != 1:
        failures.append(
            f"the {_JOB} job must contain exactly one aquasecurity/trivy-action "
            f"step, found {len(scans)}"
        )
    if not promotions:
        failures.append(
            "no step promotes the scanned digest to the release tags "
            "(docker buildx imagetools create)"
        )

    if len(builds) == 1:
        build = steps[builds[0]]
        push = (build.value(_PUSH) or "").strip().strip("\"'").lower()
        if push != "true":
            failures.append(
                f"line {build.line_number}: the build does not push (`push: "
                f"{push or 'unset'}`), so it produces no digest for the scan to "
                "name and the release tags would have to come from a build the "
                "scan never saw"
            )
        tags = build.value(_TAGS)
        if tags is None:
            failures.append(
                f"line {build.line_number}: the build sets no tags, so there is "
                "no candidate tag for the scan to read"
            )
        else:
            for tag in tags.split(","):
                tag = tag.strip()
                if not tag:
                    continue
                if not tag.endswith(_CANDIDATE):
                    failures.append(
                        f"line {build.line_number}: the build pushes {tag!r}, "
                        f"which is not a {_CANDIDATE} tag: a release tag must "
                        "not exist before the scan"
                    )

    scan_index = scans[0] if len(scans) == 1 else None
    if scan_index is not None:
        scan = steps[scan_index]
        image_ref = scan.value(_IMAGE_REF) or ""
        if "@" not in image_ref or "digest" not in image_ref:
            failures.append(
                f"line {scan.line_number}: the scan reads {image_ref or 'no image'!r} "
                "rather than a digest: a tag can move between the scan and the "
                "promotion, a digest cannot"
            )

    # Only meaningful with a scan to be "before": without one, the failure above
    # already says the job has no gate, and calling the promotion early would
    # point at a line that is not the problem.
    if scan_index is not None:
        for step in steps[:scan_index]:
            if _is_promotion(step):
                failures.append(
                    f"line {step.line_number}: the release tags are created before "
                    "the scan, so a failed scan still publishes"
                )
            elif _DOCKER_PUSH.search(step.text):
                failures.append(
                    f"line {step.line_number}: a docker push runs before the scan, "
                    "so it can publish an image the scan has not read"
                )

    for index in promotions:
        step = steps[index]
        if scan_index is not None and index < scan_index:
            continue  # already reported above, once
        if "needs.verify-version.outputs.version" not in step.text:
            failures.append(
                f"line {step.line_number}: the promotion does not create the "
                "release tag for this version"
            )
        if "latest" not in step.text:
            failures.append(
                f"line {step.line_number}: the promotion does not create the "
                "`latest` tag, which Compose resolves by default"
            )
        if "@" not in step.text or "digest" not in step.text.lower():
            failures.append(
                f"line {step.line_number}: the promotion does not copy the "
                "scanned digest, so what is tagged is not what was scanned"
            )

    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail when a release tag is created before the image scan."
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

    failures = validate_release_order(source)
    if failures:
        for failure in failures:
            print(f"{path}: {failure}", file=sys.stderr)
        return 1

    print(f"{path}: the release tags are created from the scanned digest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
