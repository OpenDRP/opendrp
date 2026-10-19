"""The release image matrix must cover every image Compose can deploy.

The gate answers a question about the whole checkout -- the workflow's matrix, the
images Compose builds and the Dockerfiles those come from -- and every one of those
inputs is mounted read-only at the path this test resolves (`docker-compose.dev.yml`),
because a matrix that publishes one image less than the deployment needs fails only
at `docker compose pull`, in the operator's hands.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "scripts" / "check_release_images.py"

if not _SCRIPT.is_file():
    # The dev overlay mounts the repository's scripts/ read-only for this suite;
    # a trimmed checkout cannot answer the question.
    pytest.skip(
        f"not a repository checkout: {_SCRIPT.name} missing", allow_module_level=True
    )

_SPEC = importlib.util.spec_from_file_location("opendrp_release_images", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_GATE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_GATE)


def _release() -> str:
    return (_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")


def _compose_config() -> dict[str, object]:
    definitions = {
        "backend": ("backend", "Dockerfile"),
        "frontend": (".", "./frontend/Dockerfile"),
        "connector-dnstwist": (".", "./connectors/dnstwist/Dockerfile"),
        "connector-shodan": (".", "./connectors/shodan/Dockerfile"),
        "connector-hibp": (".", "./connectors/hibp/Dockerfile"),
        "connector-dns-security": (".", "./connectors/dns_security/Dockerfile"),
        "connector-intelligence": (".", "connectors/intelligence/Dockerfile"),
        # Both endpoint workers (`connector-exposure-netlas-endpoints` and
        # `connector-exposure-shodan-endpoints`) are built from this one image,
        # which the release matrix has to publish like any other.
        "connector-exposure-endpoints": (
            ".",
            "./connectors/exposure_endpoints/Dockerfile",
        ),
    }
    return {
        "services": {
            image: {
                "image": f"ghcr.io/opendrp/opendrp/{image}:0.2.0",
                "build": {"context": context, "dockerfile": dockerfile},
            }
            for image, (context, dockerfile) in definitions.items()
        }
    }


def test_shipped_release_matrix_covers_every_compose_image() -> None:
    assert _GATE.validate_release_coverage(_release(), _compose_config()) == []


def test_compose_absolute_windows_paths_are_repo_relative() -> None:
    assert _GATE._repo_path("C:\\work\\opendrp\\backend", root="C:\\work\\opendrp") == "backend"
    assert _GATE._repo_path("/work/opendrp/backend", root="/work/opendrp") == "backend"


def test_missing_images_from_release_matrix_are_reported() -> None:
    source = _release().replace(
        "          - image: connector-dns-security\n"
        "            context: .\n"
        "            dockerfile: ./connectors/dns_security/Dockerfile\n",
        "",
    ).replace(
        "          - image: connector-intelligence\n"
        "            context: .\n"
        "            dockerfile: ./connectors/intelligence/Dockerfile\n",
        "",
    )

    failures = _GATE.validate_release_coverage(source, _compose_config())

    assert any("connector-dns-security" in failure and "missing" in failure for failure in failures)
    assert any("connector-intelligence" in failure and "missing" in failure for failure in failures)


def test_release_image_not_referenced_by_compose_is_reported() -> None:
    config = _compose_config()
    del config["services"]["connector-intelligence"]

    failures = _GATE.validate_release_coverage(_release(), config)

    assert any("connector-intelligence" in failure and "not referenced" in failure for failure in failures)


def test_wrong_dockerfile_for_a_published_image_is_reported() -> None:
    config = _compose_config()
    config["services"]["connector-intelligence"]["build"]["dockerfile"] = "./connectors/dns_security/Dockerfile"

    failures = _GATE.validate_release_coverage(_release(), config)

    assert any("connector-intelligence" in failure and "context/dockerfile" in failure for failure in failures)


def test_matrix_parser_does_not_consume_a_later_job() -> None:
    release = """jobs:\n  build-and-push:\n    strategy:\n      matrix:\n        include:\n          - image: first\n            context: .\n            dockerfile: ./backend/Dockerfile\n    steps:\n  publish:\n    strategy:\n      matrix:\n        include:\n          - image: later-job\n            context: .\n            dockerfile: ./frontend/Dockerfile\n"""

    matrix, failures = _GATE._release_matrix(release)

    assert failures == []
    assert matrix == {"first": (".", "./backend/Dockerfile")}


def test_open_drp_image_without_build_metadata_is_reported() -> None:
    config = _compose_config()
    del config["services"]["connector-intelligence"]["build"]

    failures = _GATE.validate_release_coverage(_release(), config)

    assert any("connector-intelligence" in failure and "without build metadata" in failure for failure in failures)


def test_missing_dockerfile_in_matrix_is_reported_even_without_compose_reference() -> None:
    release = """jobs:\n  build-and-push:\n    strategy:\n      matrix:\n        include:\n          - image: orphan\n            context: .\n            dockerfile: ./missing/Dockerfile\n    steps:\n"""

    failures = _GATE.validate_release_coverage(release, {"services": {}})

    assert any("orphan" in failure and "dockerfile does not exist" in failure for failure in failures)


@pytest.mark.skipif(
    _ROOT.parent == _ROOT,
    reason=(
        "the checkout root is the filesystem root, so nothing can be outside it "
        "for the gate to refuse"
    ),
)
def test_matrix_paths_cannot_escape_the_repository() -> None:
    release = """jobs:\n  build-and-push:\n    strategy:\n      matrix:\n        include:\n          - image: escape\n            context: ..\n            dockerfile: ../secret.Dockerfile\n    steps:\n"""

    failures = _GATE.validate_release_coverage(release, {"services": {}})

    assert any("escape" in failure and "escapes the repository" in failure for failure in failures)


def test_missing_compose_build_is_reported_as_uncovered_image() -> None:
    config = _compose_config()
    config["services"]["connector-intelligence"]["build"]["dockerfile"] = "./missing/Dockerfile"

    failures = _GATE.validate_release_coverage(_release(), config)

    assert any("connector-intelligence" in failure and "uses context/dockerfile" in failure for failure in failures)
    assert any("connector-intelligence" in failure and "Dockerfile does not exist" in failure for failure in failures)


def test_compose_image_without_registry_namespace_is_still_covered() -> None:
    config = _compose_config()
    config["services"]["connector-intelligence"]["image"] = "connector-intelligence:0.2.0"

    assert _GATE.validate_release_coverage(_release(), config) == []


def test_absolute_dockerfile_is_normalized_from_repository_root() -> None:
    config = _compose_config()
    config["services"]["connector-intelligence"]["build"]["context"] = str(_ROOT.resolve())
    config["services"]["connector-intelligence"]["build"]["dockerfile"] = str(
        (_ROOT / "connectors/intelligence/Dockerfile").resolve()
    )

    assert _GATE.validate_release_coverage(_release(), config) == []


def test_unknown_release_registry_image_is_not_silently_ignored() -> None:
    config = _compose_config()
    config["services"]["untracked"] = {
        "image": "ghcr.io/opendrp/opendrp/connector-untracked:0.2.0",
        "build": {"context": ".", "dockerfile": "./connectors/intelligence/Dockerfile"},
    }

    failures = _GATE.validate_release_coverage(_release(), config)

    assert any("connector-untracked" in failure and "missing Compose image" in failure for failure in failures)


def test_every_compose_image_with_build_is_in_release_matrix() -> None:
    config = _compose_config()
    config["services"]["backend"] = {
        "image": "custom-registry.example/opendrp-backend:0.2.0",
        "build": {"context": "backend", "dockerfile": "Dockerfile"},
    }

    failures = _GATE.validate_release_coverage(_release(), config)

    assert any("opendrp-backend" in failure and "missing Compose image" in failure for failure in failures)


def test_dockerfile_outside_repository_is_reported_from_config() -> None:
    config = _compose_config()
    config["services"]["connector-intelligence"]["build"]["dockerfile"] = "../outside/Dockerfile"

    failures = _GATE.validate_release_coverage(_release(), config)

    assert any("connector-intelligence" in failure and "context/dockerfile" in failure for failure in failures)


