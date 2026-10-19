"""Tests for ``scripts/check_withdrawn_providers.py``.

The gate exists because a removal that is only half done fails silently. Censys,
FOFA and Criminal IP were dropped from the connectors, the Compose files, the
settings, the registry rows and most of the documentation — and then three source
lists survived: the DNS Security page still offered all three as source filters,
the Exposure page offered three providers the module does not have, and
``docs/dns-security.md`` advertised Censys as an optional source. Nothing failed,
because a filter entry that can never match and a page that describes a provider
that is not shipped are both perfectly valid input.

What the tests below pin is therefore the decision itself — which spellings count
as a reference, and which files are allowed to carry one — plus the three
properties that keep the allowlist honest: an exemption for a file that no longer
exists fails, an exemption for a revision file is refused outright (the rows are
not seeded, so a revision mentioning them would be the defect), and a new file
that mentions a withdrawn provider does not.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_GATE = _ROOT / "scripts" / "check_withdrawn_providers.py"

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


gate = _load(_GATE, "opendrp_test_check_withdrawn_providers")


# ==============================================================================
# What counts as a reference
# ==============================================================================
@pytest.mark.parametrize(
    "text",
    [
        "| Censys (optional) | Plan-gated passive DNS evidence |",
        "CENSYS_API_KEY=",
        "netlas, censys, fofa, criminalip",
        "FOFA and Criminal IP registry rows",
        "the Criminal IP connector was removed",
        "criminal_ip",
        "criminal-ip",
    ],
)
def test_every_spelling_of_a_withdrawn_provider_is_a_reference(text: str) -> None:
    assert gate.matches(text)


@pytest.mark.parametrize(
    "text",
    [
        "fofapro is not a provider",
        "censysscan",
        "criminalized",
        "mmh3 5.0.1",
        "Netlas, VirusTotal, Shodan and HIBP remain",
    ],
)
def test_a_word_that_merely_contains_the_letters_is_not_a_reference(text: str) -> None:
    """`fofa` inside `fofapro` is a different word, and flagging it is noise."""
    assert gate.matches(text) == []


def test_both_names_in_one_line_are_reported() -> None:
    assert gate.matches("FOFA / Criminal IP (optional)") == ["criminal ip", "fofa"]


# ==============================================================================
# The allowlist: correct places, and the exemptions that are not one
# ==============================================================================
def _tree(root: Path, files: dict[str, str]) -> Path:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _exempt_tree(root: Path) -> Path:
    """A synthetic repository holding exactly the allowlisted files."""
    return _tree(root, {relative: "withdrawn: Censys, FOFA, Criminal IP\n" for relative in gate.ALLOWED})


def test_every_exemption_names_a_reason() -> None:
    """An entry without a reason is an exemption nobody can review."""
    assert gate.ALLOWED
    assert all(reason.strip() for reason in gate.ALLOWED.values())


def test_the_allowlisted_places_pass(tmp_path: Path, capsys) -> None:
    root = _tree(_exempt_tree(tmp_path), {"backend/app/main.py": "print('clean')\n"})

    assert gate.main(["check_withdrawn_providers.py", str(root)]) == 0
    assert "OK" in capsys.readouterr().out


def test_a_missing_exemption_fails(tmp_path: Path, capsys) -> None:
    """A renamed file must not leave an exemption behind that covers nothing."""
    root = _exempt_tree(tmp_path)
    (root / "docs" / "upgrading.md").unlink()

    assert gate.main(["check_withdrawn_providers.py", str(root)]) == 1
    assert "remove the exemption" in capsys.readouterr().out


def test_no_exemption_covers_a_revision_file() -> None:
    """Withdrawal is a property of the schema, not a step a deployment replays.

    A revision file here would mean these providers are still written somewhere:
    a revision seeds the rows and a later one deletes them, so every fresh
    installation would create them and then remove them, and the removal would
    be the only thing keeping them out. The schema this release ships is created
    without them, which is what makes the names in the source and the
    documentation the whole of the problem the gate has left to solve.
    """
    exempted_revisions = [
        relative
        for relative in gate.ALLOWED
        if relative.startswith("backend/alembic/versions/")
    ]

    assert exempted_revisions == []


def test_a_new_reference_fails_with_its_line(tmp_path: Path, capsys) -> None:
    root = _exempt_tree(tmp_path)
    (root / "frontend" / "src" / "pages").mkdir(parents=True)
    (root / "frontend" / "src" / "pages" / "ExposurePage.tsx").write_text(
        'const SOURCES = ["netlas", "censys", "fofa", "criminalip"];\n',
        encoding="utf-8",
    )

    assert gate.main(["check_withdrawn_providers.py", str(root)]) == 1
    out = capsys.readouterr().out
    assert "frontend/src/pages/ExposurePage.tsx:1" in out
    assert "censys" in out


@pytest.mark.parametrize("relative", ["docs/internal/connectors-audit-2026-10-11.md"])
def test_the_internal_records_are_outside_the_repository(
    tmp_path: Path, capsys, relative: str
) -> None:
    """`docs/internal` is git-ignored on purpose (see check_tracked_sources)."""
    root = _exempt_tree(tmp_path)
    _tree(root, {relative: "Censys, FOFA and Criminal IP were audited here\n"})

    assert gate.main(["check_withdrawn_providers.py", str(root)]) == 0
    assert "OK" in capsys.readouterr().out


def test_a_developer_env_file_is_not_source(tmp_path: Path, capsys) -> None:
    root = _exempt_tree(tmp_path)
    _tree(
        root,
        {
            ".env": "CENSYS_API_KEY=\nFOFA_API_KEY=\n",
            ".env.local": "CRIMINALIP_API_KEY=\n",
        },
    )

    assert gate.main(["check_withdrawn_providers.py", str(root)]) == 0
    assert "OK" in capsys.readouterr().out


def test_the_environment_template_is_source(tmp_path: Path, capsys) -> None:
    """`.env.example` is tracked, so a leftover key in it is a real finding."""
    root = _exempt_tree(tmp_path)
    _tree(root, {".env.example": "FOFA_API_KEY=\n"})

    assert gate.main(["check_withdrawn_providers.py", str(root)]) == 1
    assert ".env.example:1" in capsys.readouterr().out


def test_build_output_is_not_scanned(tmp_path: Path, capsys) -> None:
    root = _exempt_tree(tmp_path)
    _tree(
        root,
        {
            "frontend/dist/assets/index.js": "censys\n",
            "node_modules/pkg/index.js": "fofa\n",
        },
    )

    assert gate.main(["check_withdrawn_providers.py", str(root)]) == 0
    assert "OK" in capsys.readouterr().out


def test_a_missing_root_is_an_input_error(tmp_path: Path, capsys) -> None:
    assert gate.main(["check_withdrawn_providers.py", str(tmp_path / "nope")]) == 2


def test_too_many_arguments_is_an_input_error(capsys) -> None:
    assert gate.main(["check_withdrawn_providers.py", ".", "extra"]) == 2


# ==============================================================================
# The repository this gate protects
# ==============================================================================
@pytest.mark.skipif(
    # `_ROOT` is the checkout root on a real clone and `/` inside the test
    # container, where the mounts are partial: scanning `/` there would walk the
    # whole image and answer a question about the wrong tree.
    _ROOT.parent == _ROOT
    or not (_ROOT / "docker-compose.yml").is_file()
    or not (_ROOT / "backend" / "alembic").is_dir(),
    reason="not a repository checkout (the test container mounts the backend subtree)",
)
def test_the_real_repository_holds_no_withdrawn_provider(capsys) -> None:
    assert gate.main(["check_withdrawn_providers.py", str(_ROOT)]) == 0
    assert "OK" in capsys.readouterr().out
