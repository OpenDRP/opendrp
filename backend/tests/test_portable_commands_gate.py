"""The documentation gate, and the commands the platform prints itself.

`scripts/check_portable_commands.py` exists because a command spread over several
lines with trailing backslashes is a bash/zsh idiom: PowerShell and `cmd.exe` read
the rest as separate lines. An operator on Windows pasted the quick start's
`manage_admin` block and got three errors out of one instruction, and nothing in
the repository could notice - a Markdown code block renders identically either
way, so the defect is invisible to review.

The gate is driven over fixture checkouts here, in both directions, and the
shipped documentation is checked with it too.

No literal newline or continuation character is written in this file: both are
spelled with `chr()`, because a test about line wrapping should not depend on how
its own source is escaped, and its fixtures should contain exactly the characters
a real file would.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import List

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_GATE = _ROOT / "scripts" / "check_portable_commands.py"

if not _GATE.is_file():
    # The dev overlay mounts the repository's scripts/ read-only for this suite; a
    # checkout trimmed of it cannot answer the question, and a hard error would
    # look like a gate failure rather than a missing file.
    pytest.skip(
        f"{_GATE} is not present: run this suite from a repository checkout",
        allow_module_level=True,
    )


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


gate = _load(_GATE, "opendrp_test_check_portable_commands")

#: One backslash and one newline, as a command in a file spells them.
CONT = chr(92)
NEWLINE = chr(10)

#: The four-line block the quick start used to tell an operator to paste.
WRAPPED = (
    "```bash"
    + NEWLINE
    + f"docker compose -f docker-compose.yml -f docker-compose.dev.yml exec backend {CONT}"
    + NEWLINE
    + f"  python -m scripts.manage_admin create {CONT}"
    + NEWLINE
    + f"  --email admin@example.com {CONT}"
    + NEWLINE
    + "  --password 'StrongPassword123!'"
    + NEWLINE
    + "```"
    + NEWLINE
)

#: The same command as it ships now: one line, double quotes.
ONE_LINE = (
    "```bash"
    + NEWLINE
    + "docker compose -f docker-compose.yml -f docker-compose.dev.yml exec backend "
    + 'python -m scripts.manage_admin create --email admin@example.com --password "ChangeMeAdminPass123!"'
    + NEWLINE
    + "```"
    + NEWLINE
)


def _write(root: Path, relative: str, text: str) -> Path:
    """Write a fixture file, ending it the way a text file ends."""
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text if text.endswith(NEWLINE) else text + NEWLINE, encoding="utf-8")
    return path


def _module_with_docstring(body: str) -> str:
    """A Python module whose docstring is `body`, quoted the way source does."""
    quotes = chr(34) * 3
    return quotes + body + quotes + NEWLINE


def _program_paths() -> List[Path]:
    """The operator-facing programs, resolved the way this suite resolves paths.

    The backend directory is `backend/` in a checkout and `/app` in the
    development container, so it is taken from this file rather than from `_ROOT`.
    """
    backend = Path(__file__).resolve().parents[1]
    found = sorted((backend / "scripts").rglob("*.py"))
    found += sorted((_ROOT / "connectors").rglob("*.py"))
    found.append(_ROOT / "setup.py")
    return [path for path in found if path.is_file()]


# ==============================================================================
# The shipped documentation
# ==============================================================================
def test_the_shipped_documentation_is_portable() -> None:
    """The rule over README, docs/, connectors/, .env.example and the docstrings."""
    assert (_ROOT / "README.md").is_file()
    assert (_ROOT / "docs").is_dir()

    findings = gate.analyse(_ROOT, _program_paths())

    assert findings == [], NEWLINE.join(str(finding) for finding in findings)


# ==============================================================================
# Fixture checkouts, in both directions
# ==============================================================================
def test_every_continuation_of_a_wrapped_command_is_a_finding(tmp_path: Path) -> None:
    _write(tmp_path, "README.md", WRAPPED)

    findings = gate.analyse(tmp_path)

    assert [finding.line for finding in findings] == [2, 3, 4]
    assert all("bash/zsh" in str(finding) for finding in findings)


def test_the_same_command_on_one_line_passes(tmp_path: Path) -> None:
    """The control: the rule has to accept the shape the documentation ships now."""
    _write(tmp_path, "README.md", ONE_LINE)

    assert gate.analyse(tmp_path) == []


def test_prose_that_ends_with_a_backtick_is_not_a_finding(tmp_path: Path) -> None:
    """Markdown closes inline code with a backtick; that is not a continuation."""
    _write(
        tmp_path,
        "README.md",
        "The container reads `.env` when it is created: `docker compose up -d`",
    )

    assert gate.analyse(tmp_path) == []


def test_a_powershell_continuation_inside_a_fence_is_a_finding(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "README.md",
        "```powershell"
        + NEWLINE
        + "docker compose exec backend python -m scripts.manage_admin create `"
        + NEWLINE
        + "  --email admin@example.com"
        + NEWLINE
        + "```",
    )

    findings = gate.analyse(tmp_path)

    assert [finding.line for finding in findings] == [2]
    assert "PowerShell" in str(findings[0])


def test_a_cmd_continuation_inside_a_fence_is_a_finding(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "README.md",
        "```bat"
        + NEWLINE
        + "docker compose exec backend python -m scripts.manage_admin create ^"
        + NEWLINE
        + "  --email admin@example.com"
        + NEWLINE
        + "```",
    )

    findings = gate.analyse(tmp_path)

    assert [finding.line for finding in findings] == [2]
    assert "cmd.exe" in str(findings[0])


def test_the_template_is_checked_for_backslashes_only(tmp_path: Path) -> None:
    """Its comments quote values in backticks, which is prose, not a continuation."""
    _write(
        tmp_path,
        ".env.example",
        "# Read it back with `make verify-audit-chain`" + NEWLINE + "AUDIT_RETENTION_DAYS=365",
    )
    assert gate.analyse(tmp_path) == []

    _write(
        tmp_path,
        ".env.example",
        "#   docker compose exec -T backend python -m scripts.manage_connector_tokens "
        + CONT
        + NEWLINE
        + "#     issue dnstwist --type phishing",
    )
    assert [finding.line for finding in gate.analyse(tmp_path)] == [1]


def test_a_usage_example_in_a_docstring_is_checked(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "backend/scripts/example.py",
        _module_with_docstring(
            "Do a thing."
            + NEWLINE
            + NEWLINE
            + "Run it with:"
            + NEWLINE
            + NEWLINE
            + f"    docker compose exec backend python -m scripts.example {CONT}"
            + NEWLINE
            + "        --force"
            + NEWLINE
        ),
    )

    assert [finding.line for finding in gate.analyse(tmp_path)] == [5]


def test_an_escaped_backslash_in_a_docstring_is_the_same_defect(tmp_path: Path) -> None:
    """The file holds two backslashes, the rendered docstring shows one."""
    _write(
        tmp_path,
        "connectors/example/main.py",
        _module_with_docstring(
            "Do a thing."
            + NEWLINE
            + NEWLINE
            + f"    docker compose exec backend python -m scripts.example {CONT * 2}"
            + NEWLINE
            + "        --force"
            + NEWLINE
        ),
    )

    assert [finding.line for finding in gate.analyse(tmp_path)] == [3]


def test_a_line_continuation_in_code_is_not_a_finding(tmp_path: Path) -> None:
    """Only docstrings are read: a line of code may continue on purpose."""
    _write(
        tmp_path,
        "backend/scripts/example.py",
        _module_with_docstring("Docstring.")
        + NEWLINE
        + f"TOTAL = 1 + {CONT}"
        + NEWLINE
        + "    2",
    )

    assert gate.analyse(tmp_path) == []


def test_main_reports_findings_and_an_input_error(tmp_path: Path, capsys) -> None:
    _write(tmp_path, "README.md", ONE_LINE)
    assert gate.main(["--root", str(tmp_path)]) == 0

    _write(tmp_path, "README.md", WRAPPED)
    assert gate.main(["--root", str(tmp_path)]) == 1
    assert "keep it on one line" in capsys.readouterr().out

    assert gate.main(["--root", str(tmp_path / "absent")]) == 2


def test_undecodable_input_is_an_input_error(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_bytes(bytes([0xFF, 0xFE]) + b" not utf-8")

    assert gate.main(["--root", str(tmp_path)]) == 2
