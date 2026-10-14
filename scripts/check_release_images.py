#!/usr/bin/env python3
"""Fail when Compose-built OpenDRP images are missing from the release matrix."""

from __future__ import annotations

import argparse
import json
import ntpath
import posixpath
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_RELEASE = ROOT / ".github/workflows/release.yml"
_IMAGE_REF = re.compile(r"^ghcr\.io/opendrp/opendrp/([a-z0-9-]+):")


def _release_matrix(source: str) -> tuple[dict[str, tuple[str, str]], list[str]]:
    """Read image/context/dockerfile records in the build job's matrix."""
    entries: dict[str, tuple[str, str]] = {}
    failures: list[str] = []
    in_build_job = False
    in_matrix = False
    in_include = False
    image: str | None = None
    context: str | None = None
    dockerfile: str | None = None

    def finish() -> None:
        nonlocal image, context, dockerfile
        if image is None:
            return
        if context is None or dockerfile is None:
            failures.append(f"release matrix image {image!r} lacks context or dockerfile")
        elif image in entries:
            failures.append(f"duplicate release matrix image {image!r}")
        else:
            entries[image] = (context, dockerfile)
        image, context, dockerfile = None, None, None

    for line in source.splitlines():
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if indent == 2 and stripped.startswith("build-and-push:"):
            in_build_job = True
        elif indent == 2 and stripped.endswith(":") and not stripped.startswith("#"):
            if in_build_job:
                finish()
            in_build_job = False
            in_matrix = False
            in_include = False
        if not in_build_job:
            continue
        if indent == 6 and stripped == "matrix:":
            in_matrix = True
            continue
        if in_matrix and indent == 8 and stripped == "include:":
            in_include = True
            continue
        if in_include and indent == 6:
            finish()
            in_include = False
            in_matrix = False
            continue
        if not in_include:
            continue
        match = re.fullmatch(r"- image: ([a-z0-9-]+)", stripped)
        if match:
            finish()
            image = match.group(1)
            continue
        if image is None:
            continue
        match = re.fullmatch(r"context: (.+)", stripped)
        if match:
            context = match.group(1)
            continue
        match = re.fullmatch(r"dockerfile: (.+)", stripped)
        if match:
            dockerfile = match.group(1)
    finish()
    if not entries and not failures:
        failures.append("release workflow build job has no readable matrix include")
    return entries, failures


def _repo_path(path: str, root: str | Path = ROOT) -> str:
    """Normalize POSIX or Windows paths to repo-relative POSIX form."""
    root_path = str(root)
    if ntpath.isabs(path):
        normalized_root = ntpath.normpath(root_path)
        normalized_path = ntpath.normpath(path)
        try:
            inside_root = ntpath.commonpath([normalized_path, normalized_root]).casefold() == normalized_root.casefold()
        except ValueError:
            inside_root = False
        if not inside_root:
            return normalized_path.replace("\\", "/")
        path = ntpath.relpath(normalized_path, normalized_root).replace("\\", "/")
    else:
        path = path.replace("\\", "/")
        root_posix = root_path.replace("\\", "/")
        if posixpath.isabs(path):
            normalized_root = posixpath.normpath(root_posix)
            normalized_path = posixpath.normpath(path)
            if posixpath.commonpath([normalized_path, normalized_root]) != normalized_root:
                return normalized_path
            path = posixpath.relpath(normalized_path, normalized_root)
    return posixpath.normpath(path.removeprefix("./"))


def _resolve_repository_file(
    image: str, label: str, source_path: str, *, context: str | None = None
) -> tuple[str, list[str]]:
    """Normalize a workflow path and ensure it exists inside the checkout."""
    failures: list[str] = []
    normalized = _repo_path(source_path)
    if context is not None and label == "dockerfile" and not ntpath.isabs(source_path) and not posixpath.isabs(source_path.replace("\\", "/")):
        normalized = _repo_path(f"{_repo_path(context)}/{source_path}")
    target = (ROOT / normalized).resolve()
    try:
        target.relative_to(ROOT.resolve())
    except ValueError:
        failures.append(f"release matrix image {image!r} {label} escapes the repository: {source_path!r}")
        return normalized, failures
    if label == "context":
        exists = target.is_dir()
    else:
        exists = target.is_file()
    if not exists:
        failures.append(f"release matrix image {image!r} {label} does not exist: {source_path!r}")
    return normalized, failures


def validate_release_coverage(release_source: str, compose_config: dict) -> list[str]:
    """Compare resolved Compose images, matrix build definitions and source files."""
    matrix, failures = _release_matrix(release_source)
    normalized_matrix: dict[str, tuple[str, str]] = {}
    for image, (context, dockerfile) in sorted(matrix.items()):
        context_path, context_failures = _resolve_repository_file(image, "context", context)
        dockerfile_path, dockerfile_failures = _resolve_repository_file(
            image, "dockerfile", dockerfile
        )
        failures.extend(context_failures)
        failures.extend(dockerfile_failures)
        normalized_matrix[image] = (context_path, dockerfile_path)

    services = compose_config.get("services")
    if not isinstance(services, dict):
        return [*failures, "resolved Compose config has no services object"]

    compose: dict[str, tuple[str, str]] = {}
    for service_name, service in services.items():
        if not isinstance(service, dict):
            failures.append(f"Compose service {service_name!r} is not an object")
            continue
        reference = service.get("image")
        if not isinstance(reference, str):
            continue
        match = _IMAGE_REF.match(reference)
        build = service.get("build")
        if not match and not isinstance(build, dict):
            continue  # Prebuilt third-party images such as Postgres/Redis.
        image = (
            match.group(1)
            if match
            else reference.rsplit("/", 1)[-1].rsplit(":", 1)[0]
        )
        if not re.fullmatch(r"[a-z0-9-]+", image):
            failures.append(f"Compose service {service_name!r} has an unreadable release image name")
            continue
        if not isinstance(build, dict):
            failures.append(f"Compose service {service_name!r} uses OpenDRP image {image!r} without build metadata")
            continue
        if not match and image not in normalized_matrix:
            failures.append(f"release matrix is missing Compose image {image!r}")
            continue
        context = build.get("context")
        dockerfile = build.get("dockerfile", "Dockerfile")
        if not isinstance(context, str) or not isinstance(dockerfile, str):
            failures.append(f"Compose service {service_name!r} has unreadable build metadata")
            continue
        context_path = _repo_path(context)
        dockerfile_path = (
            _repo_path(dockerfile)
            if ntpath.isabs(dockerfile) or posixpath.isabs(dockerfile.replace("\\", "/"))
            else _repo_path(f"{context_path}/{dockerfile}")
        )
        compose_dockerfile = (ROOT / dockerfile_path).resolve()
        try:
            compose_dockerfile.relative_to(ROOT.resolve())
        except ValueError:
            failures.append(f"Compose image {image!r} Dockerfile escapes the repository: {dockerfile!r}")
        else:
            if not compose_dockerfile.is_file():
                failures.append(f"Compose image {image!r} Dockerfile does not exist: {dockerfile!r}")
        expected = (context_path, dockerfile_path)
        previous = compose.get(image)
        if previous is not None and previous != expected:
            failures.append(f"Compose image {image!r} has conflicting build definitions")
        compose[image] = expected

    for image, definition in sorted(compose.items()):
        built = normalized_matrix.get(image)
        if built is None:
            failures.append(f"release matrix is missing Compose image {image!r}")
        elif built != definition:
            failures.append(
                f"release matrix image {image!r} uses context/dockerfile {built!r}, "
                f"but Compose builds {definition!r}"
            )
    for image in sorted(normalized_matrix.keys() - compose.keys()):
        failures.append(f"release matrix image {image!r} is not referenced by Compose")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("compose_json", type=Path, help="resolved `docker compose config --format json` output")
    args = parser.parse_args(argv)
    try:
        release = _RELEASE.read_text(encoding="utf-8")
        compose = json.loads(args.compose_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"release image gate: FAILED — {exc}")
        return 2
    failures = validate_release_coverage(release, compose)
    if failures:
        print("release image gate: FAILED")
        for failure in failures:
            print(f"  {failure}")
        return 1
    print("release image gate: OK — every resolved Compose image has a matching release build")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
