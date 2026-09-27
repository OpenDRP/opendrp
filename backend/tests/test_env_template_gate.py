"""The template gate has to fail on both ways a knob can be fictional.

`scripts/check_env_template.py` exists because two defects reached a release
without any test or runtime symptom noticing them:

* settings documented in `.env.example` that Compose never passes into a
  container, so the value an operator edits is silently ignored — the template
  even instructed them to raise one of them for a large inventory;
* variables Compose reads that the template never mentions, so the knob exists
  and nobody can find it.

These tests drive the gate over fixture files, in both directions, including the
regression that a naive scanner gets wrong: a `${VAR:?...}` written inside a
Compose *comment* is not a variable.

Rule 5 is the same class of defect one step earlier: a setting that belongs to
one connector, named as if it belonged to the platform. `.env` is a single
namespace, so an unprefixed name is a collision the second connector discovers.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Iterable, Optional, Sequence

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_GATE = _ROOT / "scripts" / "check_env_template.py"

if not _GATE.is_file():
    # The dev overlay mounts the repository's scripts/ read-only for this suite;
    # a checkout that has been trimmed of it cannot answer the question, and a
    # hard error here would look like a gate failure rather than a missing file.
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


gate = _load(_GATE, "opendrp_test_check_env_template")

SHIPPED_COMPOSE = [(_ROOT / name) for name in gate.DEFAULT_COMPOSE_FILES]


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _analyse(
    tmp_path: Path,
    template_text: str,
    compose_text: str,
    sources: Optional[dict] = None,
    settings_text: str = "",
    source_roots: Optional[Sequence[Path]] = None,
) -> list:
    """Run the gate over fixture files and return its findings.

    `sources` is a mapping of relative path to content; by default the gate is
    pointed at the directories those files were written into, which is how the
    real invocation points it at `backend/app`, `connectors` and so on.
    """
    template = _write(tmp_path / ".env.example", template_text)
    compose = _write(tmp_path / "docker-compose.yml", compose_text)
    settings = _write(tmp_path / "config.py", settings_text or "class Settings:\n    pass\n")
    written = [_write(tmp_path / relative, text) for relative, text in (sources or {}).items()]
    if source_roots is not None:
        roots = list(source_roots)
    else:
        roots = sorted({path.parent for path in written}) if written else [tmp_path / "app"]
        for root in roots:
            root.mkdir(parents=True, exist_ok=True)
    return gate.analyse(template, [compose], roots, settings)


def _rules(findings: Iterable) -> list:
    return [finding.rule for finding in findings]


# ==============================================================================
# The shipped files
# ==============================================================================
def test_the_shipped_configuration_passes_the_gate() -> None:
    """The real template, the real Compose files, the real settings model."""
    assert (_ROOT / ".env.example").is_file()
    for path in SHIPPED_COMPOSE:
        assert path.is_file(), f"missing input: {path}"

    findings = gate.analyse(
        _ROOT / ".env.example",
        SHIPPED_COMPOSE,
        [_ROOT / root for root in gate.SOURCE_ROOTS],
        _ROOT / "backend/app/core/config.py",
    )

    assert findings == [], "\n".join(str(finding) for finding in findings)


def test_main_exits_zero_on_the_shipped_configuration() -> None:
    assert gate.main(["--root", str(_ROOT)]) == 0


def test_an_unreadable_input_is_reported_as_such(tmp_path: Path) -> None:
    code = gate.main(
        [
            "--template",
            str(tmp_path / "absent.env.example"),
            str(tmp_path / "absent-compose.yml"),
        ]
    )

    assert code == 2


# ==============================================================================
# Rule 1 — Compose reads it, the template does not document it
# ==============================================================================
#: A template with nothing active, so that a fixture about one rule cannot be
#: answered by another. Commented entries document without configuring.
_EMPTY_TEMPLATE = "# (nothing active in this fixture)\n"


def test_a_compose_variable_the_template_never_mentions_is_a_finding(tmp_path: Path) -> None:
    findings = _analyse(
        tmp_path,
        _EMPTY_TEMPLATE,
        "services:\n  api:\n    environment:\n      UVICORN_WORKERS: ${UVICORN_WORKERS:-1}\n",
    )

    assert _rules(findings) == [1]
    assert "UVICORN_WORKERS" in str(findings[0])
    assert "docker-compose.yml" in str(findings[0])


def test_a_commented_entry_counts_as_documentation(tmp_path: Path) -> None:
    """The advanced overrides are presented exactly this way."""
    findings = _analyse(
        tmp_path,
        "# UVICORN_WORKERS=1\n",
        "services:\n  api:\n    environment:\n      UVICORN_WORKERS: ${UVICORN_WORKERS:-1}\n",
    )

    assert findings == []


def test_the_container_side_expansion_is_the_same_variable(tmp_path: Path) -> None:
    """`$${NAME}` is how a command block forwards a host value, not a new name."""
    findings = _analyse(
        tmp_path,
        "UVICORN_WORKERS=1\n",
        "services:\n  api:\n    command: uvicorn --workers \"$${UVICORN_WORKERS:-1}\"\n",
        sources={"api.py": 'workers = os.environ.get("UVICORN_WORKERS")\n'},
    )

    assert findings == []


def test_an_internal_variable_can_be_allowlisted_with_a_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(gate.INTERNAL_VARS, "INTERNAL_ONLY", "built by the release job")
    findings = _analyse(
        tmp_path,
        _EMPTY_TEMPLATE,
        "services:\n  api:\n    image: example:${INTERNAL_ONLY:-latest}\n",
    )

    assert findings == []


# ==============================================================================
# Rule 2 — the template defines it, nothing reads it
# ==============================================================================
def test_a_template_entry_nothing_reads_is_a_finding(tmp_path: Path) -> None:
    findings = _analyse(tmp_path, "ORPHAN_SETTING=1\n", "services:\n  api:\n    image: x\n")

    assert _rules(findings) == [2]
    assert "ORPHAN_SETTING" in str(findings[0])


def test_a_template_entry_read_by_the_source_is_not_a_finding(tmp_path: Path) -> None:
    findings = _analyse(
        tmp_path,
        "ORPHAN_SETTING=1\n",
        "services:\n  api:\n    image: x\n",
        sources={"consumer.py": "value = os.environ.get(\"ORPHAN_SETTING\")\n"},
    )

    assert findings == []


def test_the_scanned_roots_exclude_tests_ci_and_documentation() -> None:
    """A knob only a test or a changelog refers to is asserting a default.

    This is a test of the configuration, not of the scan: the scanner faithfully
    reports what it is pointed at, and the rule that matters is what the real
    invocation points it at.
    """
    assert "backend/app" in gate.SOURCE_ROOTS
    assert "connectors" in gate.SOURCE_ROOTS
    for excluded in ("tests", "docs", ".github"):
        assert not any(excluded in root for root in gate.SOURCE_ROOTS)
    assert not any(".md" in suffix for suffix in gate.SOURCE_SUFFIXES)


# ==============================================================================
# Rule 3 — an application setting nothing passes into a container
# ==============================================================================
def test_a_settings_field_no_compose_file_passes_is_a_finding(tmp_path: Path) -> None:
    findings = _analyse(
        tmp_path,
        "DB_STATEMENT_TIMEOUT_MS=30000\n",
        "services:\n  api:\n    image: x\n",
        settings_text=(
            "class Settings(BaseSettings):\n"
            "    DB_STATEMENT_TIMEOUT_MS: int = Field(default=30000)\n"
        ),
    )

    assert _rules(findings) == [3]
    assert "DB_STATEMENT_TIMEOUT_MS" in str(findings[0])
    assert "would do nothing" in str(findings[0])


def test_passing_the_setting_through_resolves_the_finding(tmp_path: Path) -> None:
    findings = _analyse(
        tmp_path,
        "DB_STATEMENT_TIMEOUT_MS=30000\n",
        "services:\n  api:\n    environment:\n"
        "      DB_STATEMENT_TIMEOUT_MS: ${DB_STATEMENT_TIMEOUT_MS:-30000}\n",
        settings_text=(
            "class Settings(BaseSettings):\n"
            "    DB_STATEMENT_TIMEOUT_MS: int = Field(default=30000)\n"
        ),
    )

    assert findings == []


def test_a_host_only_setting_may_be_allowlisted_with_a_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The escape hatch for a setting the application reads outside Compose."""
    template = "HOST_ONLY_SETTING=external\n"
    compose = "services:\n  api:\n    image: x\n"
    settings_text = (
        "class Settings(BaseSettings):\n"
        '    HOST_ONLY_SETTING: str = Field(default="")\n'
    )

    without = _analyse(tmp_path, template, compose, settings_text=settings_text)
    assert _rules(without) == [3]

    monkeypatch.setitem(gate.HOST_ONLY_VARS, "HOST_ONLY_SETTING", "read outside Compose")
    with_allowlist = _analyse(tmp_path, template, compose, settings_text=settings_text)

    assert with_allowlist == []


# ==============================================================================
# Rule 4 — Compose sets it to a literal, shadowing the template
# ==============================================================================
def test_a_literal_value_in_compose_shadows_the_template_entry(tmp_path: Path) -> None:
    findings = _analyse(
        tmp_path,
        "SCAN_SSL_TEXT=true\n",
        "services:\n  connector:\n    environment:\n      SCAN_SSL_TEXT: \"true\"\n",
        sources={"connector.py": "flag = os.environ.get(\"SCAN_SSL_TEXT\")\n"},
    )

    assert _rules(findings) == [4]
    assert "SCAN_SSL_TEXT" in str(findings[0])
    assert "shadowed" in str(findings[0])


def test_interpolating_the_value_removes_the_shadow(tmp_path: Path) -> None:
    findings = _analyse(
        tmp_path,
        "SCAN_SSL_TEXT=true\n",
        "services:\n  connector:\n    environment:\n"
        "      SCAN_SSL_TEXT: ${SCAN_SSL_TEXT:-true}\n",
        sources={"connector.py": "flag = os.environ.get(\"SCAN_SSL_TEXT\")\n"},
    )

    assert findings == []


# ==============================================================================
# The scanner itself
# ==============================================================================
def test_a_variable_named_in_a_compose_comment_is_not_a_variable(tmp_path: Path) -> None:
    """The repository's own Compose files document the `${VAR:?...}` idiom."""
    findings = _analyse(
        tmp_path,
        _EMPTY_TEMPLATE,
        "services:\n  api:\n"
        "    # (${VAR:?...}) makes every compose command fail on an unprovisioned host\n"
        "    image: x\n",
    )

    assert findings == []


def test_screaming_case_keys_are_read_but_lowercase_mappings_are_ignored(
    tmp_path: Path,
) -> None:
    findings = _analyse(
        tmp_path,
        "UVICORN_WORKERS=1\n",
        "services:\n  api:\n    environment:\n      UVICORN_WORKERS: ${UVICORN_WORKERS:-1}\n"
        "    networks:\n      - opendrp-net\n",
    )

    assert findings == []


# ==============================================================================
# Rule 5 — a connector-scoped setting is namespaced after its connector
# ==============================================================================
def _connector_fixture(tmp_path: Path, name: str) -> list:
    """A template entry, a Compose interpolation and one connector reading it."""
    return _analyse(
        tmp_path,
        f"{name}=true\n",
        "services:\n  connector-shodan:\n    environment:\n"
        f"      {name}: ${{{name}:-true}}\n",
        sources={"connectors/shodan/main.py": f'flag = os.environ.get("{name}")\n'},
    )


def test_a_connector_setting_without_its_namespace_is_a_finding(
    tmp_path: Path,
) -> None:
    """The defect this rule was written for: `SCAN_SSL_TEXT` is the Shodan one."""
    findings = _connector_fixture(tmp_path, "SCAN_SSL_TEXT")

    assert _rules(findings) == [5]
    assert "SCAN_SSL_TEXT is read by a connector" in str(findings[0])
    # The finding names the namespace the rename has to use, so the fix is
    # mechanical rather than a search for the convention.
    assert "SHODAN" in str(findings[0])


def test_the_namespaced_form_passes(tmp_path: Path) -> None:
    assert _connector_fixture(tmp_path, "SHODAN_SCAN_SSL_TEXT") == []


def test_a_setting_the_platform_reads_too_is_not_connector_scoped(
    tmp_path: Path,
) -> None:
    """A connector honouring a platform setting is not a namespace collision."""
    findings = _analyse(
        tmp_path,
        "SHARED_TIMEOUT_SECONDS=5\n",
        "services:\n  api:\n    environment:\n"
        "      SHARED_TIMEOUT_SECONDS: ${SHARED_TIMEOUT_SECONDS:-5}\n",
        sources={
            "connectors/shodan/main.py": 'timeout = os.environ.get("SHARED_TIMEOUT_SECONDS")\n',
            "backend/app/core/outbound.py": 'timeout = "SHARED_TIMEOUT_SECONDS"\n',
        },
    )

    assert findings == []


def test_the_connector_protocol_prefix_is_the_platforms(tmp_path: Path) -> None:
    """`CONNECTOR_TOKEN` and `CORE_URL` are the protocol, not a capability."""
    findings = _analyse(
        tmp_path,
        "CONNECTOR_LOG_LEVEL=INFO\n",
        "services:\n  connector-shodan:\n    environment:\n"
        "      CONNECTOR_LOG_LEVEL: ${CONNECTOR_LOG_LEVEL:-INFO}\n",
        sources={
            "connectors/shodan/main.py": 'level = os.environ.get("CONNECTOR_LOG_LEVEL")\n',
        },
    )

    assert findings == []
