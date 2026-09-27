"""One installation shape, and a gate that keeps it that way.

The project used to offer two: a "dev" profile the wizard wrote for a checkout,
and a production one for a host. The cost was not the extra branch in the wizard —
it was that the thing a developer tested was not the thing an operator ran. That
difference hid, for example, a canonical origin compiled into the release bundle
(`CANONICAL_ORIGIN=http://localhost:3000`), which sent every real user to their own
machine and could not appear in any test that ran against the development stack.

The overlay itself stays: `make up-tools` is a source-mounted container with
pytest, ruff and mypy, and the test and lint targets exec into it. What this file
asserts is that it is *tooling* — never a second way to deploy, never selected by a
variable, never the file set the documented installation path names.

Every assertion here is a property someone could remove deliberately and forget
the consequence of, which is why they are properties rather than a comment.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from typing import Dict, List

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_MAKEFILE = _ROOT / "Makefile"
_SETUP = _ROOT / "setup.py"
_TEMPLATE = _ROOT / ".env.example"
_OVERLAY = _ROOT / "docker-compose.dev.yml"

_REQUIRED = [_MAKEFILE, _SETUP, _TEMPLATE, _OVERLAY]
_MISSING = [path.name for path in _REQUIRED if not path.is_file()]
if _MISSING:
    pytest.skip(
        f"not a repository checkout: {', '.join(_MISSING)} missing",
        allow_module_level=True,
    )

spec = importlib.util.spec_from_file_location("opendrp_shape_setup", _SETUP)
assert spec is not None and spec.loader is not None
wizard = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = wizard
spec.loader.exec_module(wizard)

#: Documentation an operator follows. The changelog is deliberately absent: it has
#: to be able to describe what was removed.
_OPERATOR_DOCS = [
    _ROOT / "README.md",
    _ROOT / "CONTRIBUTING.md",
    *sorted((_ROOT / "docs").glob("*.md")),
]


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _values(path: Path) -> Dict[str, str]:
    return dict(re.findall(r"^([A-Z_][A-Z0-9_]*)=(.*)$", _text(path), flags=re.M))


def _recipe(makefile: str, target: str) -> str:
    """The recipe of one target, including its prerequisite line."""
    lines = makefile.splitlines()
    start = next(
        (index for index, line in enumerate(lines) if line.startswith(f"{target}:")),
        None,
    )
    assert start is not None, f"{target} is not a Makefile target"
    block: List[str] = [lines[start]]
    for line in lines[start + 1:]:
        if line.strip() and not line.startswith("\t"):
            break
        block.append(line)
    return "\n".join(block)


# ==============================================================================
# The wizard
# ==============================================================================
def test_the_wizard_writes_one_file_set_and_it_is_the_installation() -> None:
    assert wizard.COMPOSE_FILES == ("docker-compose.yml",)


def test_the_wizard_has_no_shape_to_choose() -> None:
    """The answers carry an installation, not a choice about which one."""
    assert not hasattr(wizard.Answers(), "profile")
    answers = wizard.Answers(public_url="https://drp.example.com", release_version="1.2.3")

    values = wizard.installation_values(answers)
    assert values["APP_ENV"] == "production"
    assert values["AUTH_COOKIE_SECURE"] == "true"
    assert values["CANONICAL_ORIGIN"] == ""


def test_the_wizard_takes_no_flag_that_selects_a_shape(capsys) -> None:
    """There is no second shape to ask for, so the flag does not exist."""
    with pytest.raises(SystemExit) as refused:
        wizard.main(["--profile", "dev"])

    assert refused.value.code == 2
    assert "--profile" in capsys.readouterr().err


# ==============================================================================
# The Makefile
# ==============================================================================
def test_make_up_is_the_installation() -> None:
    makefile = _text(_MAKEFILE)

    assert "COMPOSE = docker compose -f docker-compose.yml\n" in makefile
    assert not re.search(r"^SHAPE\s*[?:]?=", makefile, flags=re.M), (
        "a SHAPE variable is how the two file sets came back the last time"
    )
    assert "docker-compose.dev.yml" not in _recipe(makefile, "up")


def test_the_tooling_stack_is_named_and_cannot_be_mistaken_for_an_installation() -> None:
    makefile = _text(_MAKEFILE)
    recipe = _recipe(makefile, "up-tools")

    assert "$(TOOLS)" in recipe
    # The variable's own definition, so the name and the file set cannot drift.
    assert (
        "TOOLS = docker compose -f docker-compose.yml -f docker-compose.dev.yml\n"
        in makefile
    )


def test_there_is_no_second_target_that_starts_the_stack() -> None:
    """An alias is how a second deployment shape comes back: something to keep
    working, and then something to keep behaving differently."""
    makefile = _text(_MAKEFILE)

    assert not re.search(r"^up-prod:", makefile, flags=re.M)
    assert "up-prod" not in makefile.split(".PHONY:", 1)[1].splitlines()[0]


@pytest.mark.parametrize(
    "target",
    [
        "test-backend",
        "test-backend-fast",
        "test-backend-integration",
        "test-backend-critical-coverage",
        "typecheck-backend",
        "lint-backend",
        "mypy-backend",
    ],
)
def test_the_targets_that_need_test_tooling_check_that_the_tooling_stack_is_up(
    target: str,
) -> None:
    """Otherwise they fail with `pytest: not found` from a healthy container.

    The message names the symptom and hides the cause, which is that the target
    addressed a file set whose image deliberately ships no test framework.
    """
    recipe = _recipe(_text(_MAKEFILE), target)

    assert recipe.startswith(f"{target}: tools-check"), recipe.splitlines()[0]
    assert "$(TOOLS)" in recipe


# ==============================================================================
# The template and the overlay
# ==============================================================================
def test_the_template_is_the_installation_shape() -> None:
    """Copying `.env.example` by hand has to give the same answer as the wizard."""
    values = _values(_TEMPLATE)

    assert values["APP_ENV"] == "production"
    assert values["AUTH_COOKIE_SECURE"] == "true"
    assert values["CANONICAL_ORIGIN"] == ""
    assert values["FRONTEND_PORT"].startswith("127.0.0.1:")
    assert re.fullmatch(r"\d+\.\d+\.\d+", values["OPENDRP_VERSION"])


def test_the_template_is_a_dotenv_file_and_nothing_else() -> None:
    """Every line is a comment or an assignment.

    The wizard rewrites this file's lines in place, so anything else it carries
    is copied into every `.env` it writes — a stray heading or divider would end
    up in an operator's production configuration, which is the one thing the
    file is not.
    """
    for number, line in enumerate(_text(_TEMPLATE).splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        assert re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", line), (
            f".env.example:{number} is neither a comment nor an assignment: {line!r}"
        )


def test_the_overlay_is_tooling_and_nothing_else() -> None:
    overlay = _text(_OVERLAY)

    # The override that made a development build advertise a loopback canonical
    # origin: with the setting managed in `.env` it has no business here, and it
    # was the mechanism by which the two shapes differed in what a browser saw.
    assert "VITE_CANONICAL_ORIGIN" not in overlay
    assert "tooling" in overlay.lower()
    # It still has a purpose, or it would not be shipped: mounts and test tooling.
    assert "INSTALL_DEV_REQUIREMENTS" in overlay
    assert "./backend:/app" in overlay


# ==============================================================================
# What an operator reads
# ==============================================================================
@pytest.mark.parametrize("path", _OPERATOR_DOCS, ids=lambda path: path.name)
def test_the_documented_installation_is_the_installation(path: Path) -> None:
    text = _text(path)

    assert "up-prod" not in text, f"{path.name} tells an operator to use up-prod"
    assert "SHAPE=" not in text, f"{path.name} selects a Compose shape"
