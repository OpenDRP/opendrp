"""The README's deferred-advisory list must not drift from the audits.

`README.md` carried a "Known deferred findings" paragraph that named four packages
and claimed every fix was a major bump. By the time anyone read it the packages
were clear — a patch and a minor had lifted all four — so the paragraph was wrong
in both directions a list can be wrong: it named advisories that no longer existed
and it would not have named one that appeared, because the frontend's dev audit
ran with `continue-on-error` and nothing compared its output with the prose.

`scripts/check_deferred_advisories.py` is that comparison: the `security` job
writes its audit JSON, and the gate reads the README's declaration and the audits
and fails on either difference. These tests drive it over fixtures, so they need
neither a network nor an installed dependency tree, and the tests that read the
checkout skip rather than passing on a trimmed one.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "scripts" / "check_deferred_advisories.py"
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_README = _ROOT / "README.md"

if not _SCRIPT.is_file() or not _CI.is_file():
    pytest.skip(
        f"not a repository checkout: {_SCRIPT.name} or {_CI.name} missing",
        allow_module_level=True,
    )

_SPEC = importlib.util.spec_from_file_location("opendrp_deferred_advisories", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_GATE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_GATE)

_HEADER = (
    "Known deferred findings, tracked rather than ignored:\n\n"
    "| Package | Ecosystem | Why it is deferred |\n"
    "|---|---|---|\n"
)


def _readme(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "README.md"
    path.write_text(
        "# Project\n\nSome prose.\n\n## Dependencies\n\n" + body + "\n## Development commands\n\nMore.\n",
        encoding="utf-8",
    )
    return path


def _npm(tmp_path: Path, *packages: str, name: str = "npm-audit.json") -> Path:
    path = tmp_path / name
    path.write_text(
        json.dumps(
            {
                "auditReportVersion": 2,
                "vulnerabilities": {
                    package: {"name": package, "severity": "high", "via": []} for package in packages
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _pip_entries(packages: tuple[str, ...]) -> list[dict[str, object]]:
    """`pip-audit`'s per-dependency rows; a leading `!` marks a clean one."""

    return [
        {
            "name": package.lstrip("!"),
            "version": "1.0",
            "vulns": [] if package.startswith("!") else [{"id": "CVE-1"}],
        }
        for package in packages
    ]


def _pip(tmp_path: Path, *packages: str, name: str = "pip-audit.json") -> Path:
    """`pip-audit -f json` as 2.x writes it: the `dependencies` envelope."""

    path = tmp_path / name
    path.write_text(
        json.dumps({"dependencies": _pip_entries(packages), "fixes": []}),
        encoding="utf-8",
    )
    return path


def _pip_legacy(tmp_path: Path, *packages: str, name: str = "pip-audit-0.json") -> Path:
    """`pip-audit -f json` as 0.x wrote it: the bare list of dependencies."""

    path = tmp_path / name
    path.write_text(json.dumps(_pip_entries(packages)), encoding="utf-8")
    return path


def test_nothing_deferred_and_clean_audits_agree(tmp_path: Path) -> None:
    readme = _readme(tmp_path, "Known deferred findings: **none at the time of writing.**\n")

    assert _GATE.main([str(readme), str(_npm(tmp_path)), str(_pip(tmp_path, "!urllib3"))]) == 0


def test_a_new_advisory_the_readme_does_not_name_fails(tmp_path: Path) -> None:
    readme = _readme(tmp_path, "Known deferred findings: none at the time of writing.\n")

    assert _GATE.main([str(readme), str(_npm(tmp_path, "vite"))]) == 1


def test_the_missing_advisory_is_named_with_the_row_to_add(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    readme = _readme(tmp_path, "Known deferred findings: none at the time of writing.\n")

    assert _GATE.main([str(readme), str(_npm(tmp_path, "@vitest/mocker"))]) == 1

    err = capsys.readouterr().err
    assert "@vitest/mocker (npm)" in err
    assert "| `@vitest/mocker` | npm |" in err


def test_a_declared_advisory_the_audits_no_longer_report_fails(tmp_path: Path) -> None:
    readme = _readme(
        tmp_path,
        _HEADER + "| `source-map-js` | npm | build-time transitive of postcss |\n\nProse after.\n",
    )

    assert _GATE.main([str(readme), str(_npm(tmp_path))]) == 1


def test_the_stale_row_is_reported_as_stale(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    readme = _readme(tmp_path, _HEADER + "| `source-map-js` | npm | build-time only |\n")

    assert _GATE.main([str(readme), str(_npm(tmp_path))]) == 1

    err = capsys.readouterr().err
    assert "the README defers source-map-js (npm)" in err
    assert "drop the row" in err


def test_a_declared_advisory_an_audit_reports_agrees(tmp_path: Path) -> None:
    readme = _readme(tmp_path, _HEADER + "| `source-map-js` | npm | build-time only |\n")

    assert _GATE.main([str(readme), str(_npm(tmp_path, "source-map-js"))]) == 0


def test_both_directions_are_reported_together(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    readme = _readme(tmp_path, _HEADER + "| `esbuild` | npm | dev only |\n")

    assert _GATE.main([str(readme), str(_npm(tmp_path, "vite"))]) == 1

    err = capsys.readouterr().err
    assert "the audit reports vite (npm)" in err
    assert "the README defers esbuild (npm)" in err


def test_pip_names_are_compared_the_way_pythons_index_spells_them(tmp_path: Path) -> None:
    """`PyYAML`, `pyyaml` and `Py_YAML` are one distribution (PEP 503)."""

    readme = _readme(tmp_path, _HEADER + "| `PyYAML` | pip | dev only |\n")

    assert _GATE.main([str(readme), str(_pip(tmp_path, "pyyaml"))]) == 0


def test_the_same_name_in_two_ecosystems_is_two_advisories(tmp_path: Path) -> None:
    readme = _readme(tmp_path, _HEADER + "| `requests` | pip | dev only |\n")

    assert _GATE.main([str(readme), str(_pip(tmp_path, "requests")), str(_npm(tmp_path, "requests"))]) == 1


def test_a_section_that_says_neither_none_nor_a_table_is_unreadable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    readme = _readme(tmp_path, "Known deferred findings: tracked in an issue somewhere.\n")

    assert _GATE.main([str(readme), str(_npm(tmp_path))]) == 2
    assert "says neither" in capsys.readouterr().err


def test_none_beside_a_table_is_ambiguous(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    readme = _readme(tmp_path, _HEADER + "| `vite` | npm | dev only |\n\nNothing else; none at the time of writing.\n")

    assert _GATE.main([str(readme), str(_npm(tmp_path, "vite"))]) == 2
    assert "one of the two is the list" in capsys.readouterr().err


def test_a_missing_section_is_unreadable(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    readme = _readme(tmp_path, "Known advisories live elsewhere.\n")

    assert _GATE.main([str(readme), str(_npm(tmp_path))]) == 2
    assert "no 'Known deferred findings' section" in capsys.readouterr().err


def test_a_row_whose_ecosystem_is_not_audited_here_is_unreadable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    readme = _readme(tmp_path, _HEADER + "| `log4j-core` | maven | dev only |\n")

    assert _GATE.main([str(readme), str(_npm(tmp_path))]) == 2
    assert "the ecosystems here are npm, pip" in capsys.readouterr().err


def test_a_package_cell_without_backticks_is_unreadable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    readme = _readme(tmp_path, _HEADER + "| vite | npm | dev only |\n")

    assert _GATE.main([str(readme), str(_npm(tmp_path))]) == 2
    assert "no package in backticks" in capsys.readouterr().err


def test_an_audit_in_neither_shape_is_unreadable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    other = tmp_path / "other.json"
    other.write_text(json.dumps({"results": []}), encoding="utf-8")
    readme = _readme(tmp_path, "Known deferred findings: none at the time of writing.\n")

    assert _GATE.main([str(readme), str(other)]) == 2
    assert "neither an npm audit nor a pip-audit report" in capsys.readouterr().err


def test_a_pip_audit_dependency_list_without_a_name_is_unreadable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The envelope is read only as far as it makes sense: a row without a name
    cannot be compared with anything."""

    other = tmp_path / "odd.json"
    other.write_text(json.dumps({"dependencies": [{"version": "1.0"}]}), encoding="utf-8")
    readme = _readme(tmp_path, "Known deferred findings: none at the time of writing.\n")

    assert _GATE.main([str(readme), str(other)]) == 2
    assert "has no `name`" in capsys.readouterr().err


def test_an_unreadable_audit_file_is_exit_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    readme = _readme(tmp_path, "Known deferred findings: none at the time of writing.\n")

    assert _GATE.main([str(readme), str(tmp_path / "absent.json")]) == 2
    assert "cannot read" in capsys.readouterr().err


def test_a_clean_pip_audit_entry_is_not_an_advisory(tmp_path: Path) -> None:
    """`pip-audit` lists every pinned package; only `vulns` makes one deferred."""

    assert _GATE.read_audit(_pip(tmp_path, "!certifi", "!pytest")) == set()


def test_the_2x_envelope_is_read(tmp_path: Path) -> None:
    """pip-audit 2.10.1 writes `{"dependencies": [...], "fixes": []}`, which the
    first version of this gate read as "not a pip-audit report" and exited 2."""

    report = _pip(tmp_path, "certifi")

    assert json.loads(report.read_text(encoding="utf-8"))["dependencies"][0]["vulns"]
    assert _GATE.read_audit(report) == {_GATE.Advisory("pip", "certifi")}


def test_the_legacy_bare_list_is_still_read(tmp_path: Path) -> None:
    """An older pip-audit on a developer's PATH writes the list; the gate reads it."""

    assert _GATE.read_audit(_pip_legacy(tmp_path, "certifi")) == {
        _GATE.Advisory("pip", "certifi")
    }


def test_an_enveloped_advisory_agrees_with_the_readme_row(tmp_path: Path) -> None:
    readme = _readme(tmp_path, _HEADER + "| `PyYAML` | pip | dev only |\n")

    assert _GATE.main([str(readme), str(_pip(tmp_path, "pyyaml"))]) == 0


def test_the_shipped_readme_declares_nothing_now() -> None:
    """The paragraph the gate checks is the one that aged: keep the marker honest."""

    declared, problems = _GATE.deferred(_README.read_text(encoding="utf-8"))

    assert problems == []
    assert declared == set()


def test_the_shipped_readme_names_no_audit_output_as_its_list() -> None:
    """A table would mean a deferral exists; that is a deliberate change, not a drift."""

    body = "\n".join(_GATE.section(_README.read_text(encoding="utf-8")))

    assert _GATE.NOTHING_DEFERRED in body.lower()


def test_ci_writes_the_audits_and_runs_the_gate() -> None:
    """A gate no workflow runs is a script, not a gate — and it needs the JSON."""

    workflow = _CI.read_text(encoding="utf-8")

    assert "scripts/check_deferred_advisories.py" in workflow
    assert "npm audit --json" in workflow
    assert "pip-audit" in workflow
