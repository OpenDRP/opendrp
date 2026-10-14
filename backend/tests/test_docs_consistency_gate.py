"""The documentation gate has to see a tree that stopped holding together.

Three failures shipped here without anything noticing, and each of them is a
question a reader asks:

* a relative link that points at a page which was renamed — the text still reads
  as an instruction, and the reader finds out otherwise;
* a page no index reaches — `docs/` accumulated audit records, and nothing told a
  reader which page was live guidance and which was history;
* a migration reference that is stale — the readiness page named a revision as
  the end of the chain while the tree had already moved past it, so an operator
  planning an upgrade had two answers and no way to choose.

Each test below builds the smallest checkout that demonstrates one of them. The
shipped tree is asserted to be clean as well, which is what keeps the gate from
being a rule nobody satisfies.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Dict

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_GATE = _ROOT / "scripts" / "check_docs_consistency.py"

if not _GATE.is_file():
    # The dev overlay mounts the repository's scripts/ read-only for this suite;
    # a trimmed checkout cannot answer the question.
    pytest.skip(
        f"not a repository checkout: {_GATE.name} missing", allow_module_level=True
    )


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


gate = _load(_GATE, "opendrp_test_check_docs_consistency")

#: A two-revision chain with one head: the smallest tree that exercises the head
#: rule. Invented rather than quoted from the shipped chain, which is a single
#: revision now and would make the rule untestable here.
_REVISIONS = {
    "backend/alembic/versions/0001_initial_schema.py": (
        'revision = "0001_initial_schema"\ndown_revision = None\n'
    ),
    "backend/alembic/versions/0002_add_widget_columns.py": (
        'revision = "0002_add_widget_columns"\n'
        'down_revision = "0001_initial_schema"\n'
    ),
}


def _checkout(tmp_path: Path, files: Dict[str, str], **revisions: str) -> Path:
    """Write a minimal documentation tree and return its root."""
    content = dict(_REVISIONS)
    content.update(revisions)
    for relative, text in {**content, **files}.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return tmp_path


# ==============================================================================
# The shipped tree
# ==============================================================================
@pytest.mark.skipif(
    # `_ROOT` is the checkout root on a real clone and `/` inside the test
    # container, where the mounts are partial: an empty tree there is a fact
    # about the container, not a finding about the documentation.
    _ROOT.parent == _ROOT
    or not (_ROOT / "docker-compose.yml").is_file()
    or not (_ROOT / "backend" / "alembic").is_dir(),
    reason="not a repository checkout (the test container mounts the backend subtree)",
)
def test_the_shipped_documentation_tree_is_clean() -> None:
    assert gate.check(_ROOT) == []


# ==============================================================================
# Links
# ==============================================================================
def test_a_link_that_points_nowhere_is_reported(tmp_path: Path) -> None:
    root = _checkout(
        tmp_path,
        {
            # One link resolves and one does not, so the finding is the broken one
            # rather than a page nothing reaches.
            "README.md": (
                "# OpenDRP\n\n"
                "See [the runbook](docs/deployment.md) and [the config](docs/configuration.md).\n"
            ),
            "docs/configuration.md": "# Configuration\n",
        },
    )

    failures = gate.check(root)

    assert len(failures) == 1, failures
    assert "docs/deployment.md" in failures[0]
    assert "does not resolve" in failures[0]


def test_a_link_inside_a_fenced_block_is_not_a_link(tmp_path: Path) -> None:
    """A `[x](y)` in a code sample is an example, not a page to maintain."""
    root = _checkout(
        tmp_path,
        {
            "README.md": (
                "# OpenDRP\n\n"
                "See [the runbook](docs/deployment.md).\n\n"
                "```markdown\n[example](docs/does-not-exist.md)\n```\n"
            ),
            "docs/deployment.md": "# Deployment\n",
        },
    )

    assert gate.check(root) == []


def test_an_anchor_and_a_query_are_stripped_before_resolving(tmp_path: Path) -> None:
    root = _checkout(
        tmp_path,
        {
            "README.md": "# OpenDRP\n\n[config](docs/configuration.md#database-pool-budget)\n",
            "docs/configuration.md": "# Configuration\n",
        },
    )

    assert gate.check(root) == []


# ==============================================================================
# Reachability
# ==============================================================================
def test_a_page_no_index_reaches_is_reported(tmp_path: Path) -> None:
    root = _checkout(
        tmp_path,
        {
            "README.md": "# OpenDRP\n",
            "docs/orphan.md": "# Orphan\n",
        },
    )

    failures = gate.check(root)

    assert len(failures) == 1, failures
    assert "docs/orphan.md" in failures[0]
    assert "not reachable" in failures[0]


def test_the_internal_index_makes_a_record_reachable(tmp_path: Path) -> None:
    """The arrangement this repository actually uses for its audit records."""
    root = _checkout(
        tmp_path,
        {
            "README.md": "# OpenDRP\n\n[records](docs/internal/README.md)\n",
            "docs/internal/README.md": "# Internal records\n\n[audit](audit-2026-01-01.md)\n",
            "docs/internal/audit-2026-01-01.md": "# Audit\n",
        },
    )

    assert gate.check(root) == []


def test_a_tree_without_any_index_is_reported(tmp_path: Path) -> None:
    root = _checkout(tmp_path, {"docs/page.md": "# Page\n"})

    failures = gate.check(root)

    assert len(failures) == 1, failures
    assert "no index found" in failures[0]


def test_root_instruction_files_need_no_inbound_link(tmp_path: Path) -> None:
    """`CONTRIBUTING.md` and `AGENTS.md` are landed on, not linked to."""
    root = _checkout(
        tmp_path,
        {
            "README.md": "# OpenDRP\n",
            "CONTRIBUTING.md": "# Contributing\n",
            "AGENTS.md": "# Agents\n",
        },
    )

    assert gate.check(root) == []


# ==============================================================================
# Migration references
# ==============================================================================
def test_a_revision_that_does_not_exist_is_reported(tmp_path: Path) -> None:
    root = _checkout(
        tmp_path,
        {
            "README.md": "# OpenDRP\n\n[page](docs/page.md)\n",
            "docs/page.md": "# Page\n\nShipped in `0042_a_revision_that_never_was`.\n",
        },
    )

    failures = gate.check(root)

    assert len(failures) == 1, failures
    assert "0042_a_revision_that_never_was" in failures[0]


def test_a_stale_head_claim_is_reported(tmp_path: Path) -> None:
    """The defect this rule was written for, in the words it was written in."""
    root = _checkout(
        tmp_path,
        {
            "README.md": "# OpenDRP\n\n[readiness](docs/production-readiness.md)\n",
            "docs/production-readiness.md": (
                "# Readiness\n\n"
                "The current migration head is `0001_initial_schema` (two revisions).\n"
            ),
        },
    )

    failures = gate.check(root)

    assert len(failures) == 1, failures
    assert "0002_add_widget_columns" in failures[0]
    assert "0001_initial_schema" in failures[0]


def test_an_internal_record_may_quote_the_head_it_was_written_against(
    tmp_path: Path,
) -> None:
    """History is allowed to be history: that is the whole point of the directory."""
    root = _checkout(
        tmp_path,
        {
            "README.md": "# OpenDRP\n",
            "docs/internal/README.md": "# Internal records\n\n[audit](audit.md)\n",
            "docs/internal/audit.md": (
                "# Audit\n\nAt the time of writing, migrations through "
                "`0001_initial_schema` were the state of the tree.\n"
            ),
        },
    )

    assert gate.check(root) == []


def test_an_internal_record_may_cite_a_revision_the_baseline_absorbed(
    tmp_path: Path,
) -> None:
    """A record names the chain of its own time; rewriting it would falsify it."""
    root = _checkout(
        tmp_path,
        {
            "README.md": "# OpenDRP\n\n[records](docs/internal/README.md)\n",
            "docs/internal/README.md": "# Internal records\n\n[audit](audit.md)\n",
            "docs/internal/audit.md": (
                "# Audit\n\n"
                "The matching indexes shipped in `0010_report_reliability`.\n"
            ),
        },
    )

    assert gate.check(root) == []


def test_an_ambiguous_chain_is_reported_rather_than_guessed(tmp_path: Path) -> None:
    """Two heads mean the head rule cannot be applied, and that is a finding."""
    root = _checkout(
        tmp_path,
        {
            "README.md": "# OpenDRP\n\n[page](docs/page.md)\n",
            "docs/page.md": "# Page\n",
            "backend/alembic/versions/0002_other_branch.py": (
                'revision = "0002_other_branch"\ndown_revision = "0001_initial_schema"\n'
            ),
        },
    )

    failures = gate.check(root)

    assert len(failures) == 1, failures
    assert "head(s)" in failures[0]
