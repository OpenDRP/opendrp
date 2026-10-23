"""The nginx rule that broke a client route, and the gate nobody tested.

`docker/nginx/default.conf` carries the SPA fallback, and the fallback is the
reason `/assets` (a page) and `assets/` (the build directory) do not collide:
`try_files $uri $uri/ /index.html` makes nginx answer `/assets` with a directory
redirect before React can render the Assets page, and it does so with nginx's
listening port rather than the published one. Both were real defects, and the
gate that now checks them shipped without a test and with the configuration path
hard-coded — so a deleted rule, a renamed file or a weakened check was invisible,
and no test could point the gate at a fixture to prove otherwise.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_GATE = _ROOT / "scripts" / "check_frontend_spa.py"

if not _GATE.is_file():
    # The dev overlay mounts the repository's scripts/ read-only for this suite;
    # a trimmed checkout cannot answer the question.
    pytest.skip(f"not a repository checkout: {_GATE.name} missing", allow_module_level=True)


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


gate = _load(_GATE, "opendrp_test_check_frontend_spa")

_GOOD = (
    "server {\n"
    "    listen 80;\n"
    "    port_in_redirect off;\n"
    "    location / {\n"
    "        try_files $uri /index.html;\n"
    "    }\n"
    "}\n"
)


def _checkout(tmp_path: Path, config: str | None) -> Path:
    """A root holding `docker/nginx/default.conf`, or the directory alone."""
    directory = tmp_path / "docker" / "nginx"
    directory.mkdir(parents=True)
    if config is not None:
        (directory / "default.conf").write_text(config, encoding="utf-8")
    return tmp_path


# ==============================================================================
# The shipped configuration
# ==============================================================================
def test_the_shipped_nginx_configuration_passes() -> None:
    assert gate.check(_ROOT) == []


def test_main_reads_the_root_it_is_given(tmp_path: Path) -> None:
    root = _checkout(tmp_path, _GOOD)

    assert gate.main(["--root", str(root)]) == 0


# ==============================================================================
# The three rules
# ==============================================================================
def test_a_directory_redirect_in_the_fallback_is_reported(tmp_path: Path) -> None:
    """`/assets` is a page and `assets/` is the build directory."""
    root = _checkout(
        tmp_path,
        _GOOD.replace("try_files $uri /index.html;", "try_files $uri $uri/ /index.html;"),
    )

    failures = gate.check(root)

    assert len(failures) == 1, failures
    assert "$uri/" in failures[0]


def test_a_missing_port_rule_is_reported(tmp_path: Path) -> None:
    root = _checkout(tmp_path, _GOOD.replace("    port_in_redirect off;\n", ""))

    failures = gate.check(root)

    assert len(failures) == 1, failures
    assert "port_in_redirect" in failures[0]


def test_a_configuration_without_the_index_fallback_is_reported(
    tmp_path: Path,
) -> None:
    root = _checkout(tmp_path, _GOOD.replace("try_files $uri /index.html;", "return 404;"))

    failures = gate.check(root)

    assert len(failures) == 1, failures
    assert "try_files $uri /index.html;" in failures[0]


def test_a_missing_configuration_is_an_input_error(tmp_path: Path) -> None:
    root = _checkout(tmp_path, None)

    assert gate.main(["--root", str(root)]) == 2
