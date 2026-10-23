"""The settings table in `docs/configuration.md` is generated, and stays current.

Step S19's exit is a settings audit table: every setting's default, what validates
it, and whether it is documented. Written by hand it would be true on the day it
was written and wrong at the next commit, so it is rendered from
`app/core/config.py` by `scripts/settings_reference.py` and checked here.

Three properties are asserted, and each is a different way the table can lie:

* it exists and matches the renderer exactly — otherwise a new setting arrives
  without a row, or a default changes without the page following;
* every row carries a validator — the column is what makes the table an audit
  rather than a list, and an empty cell would read as "validated" to anyone
  skimming;
* the settings that decide *where data lives* are named in `.env.example`, because
  an operator who cannot find the knob will use the default and mount a volume
  somewhere else.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts import settings_reference as sr

_DOCS = Path(__file__).resolve().parents[2] / "docs"
_PAGE = _DOCS / "configuration.md"

#: Settings `.env.example` does not carry as a `KEY=` line, each with the reason.
#: The list is the review: a setting that is neither here nor in the template is
#: one an operator cannot find, and a setting that joins this list joins it in a
#: diff somebody read.
_TEMPLATE_GAPS = {
    # Assembled by the template from POSTGRES_* and POSTGRES_PASSWORD, and written
    # out commented so the shape is visible without being a second source of truth.
    "DATABASE_URL",
    # Same idea over REDIS_PASSWORD.
    "REDIS_URL",
    # Supplied by a volume mount in the shipped Compose stack, so the template must
    # not override it; both are documented in docs/configuration.md instead.
    "REPORTS_STORE_DIR",
    "AUDIT_ARCHIVE_DIR",
    # Set per service in docker-compose.yml (the API is 1, the workers carry their
    # own), and printed by `python setup.py --check` in the pool budget.
    "UVICORN_WORKERS",
    # Retention switches and windows: the shipped defaults are the documented ones,
    # and `AUDIT_RETENTION_HOLD` exists for an operator who is mid-investigation.
    "AUDIT_RETENTION_HOLD",
    "ALERT_HISTORY_RETENTION_DAYS",
    # Internal pacing and diagnostics; nobody runs the stack differently by
    # changing either.
    "ALERT_RECIPIENT_INTERVAL_SECONDS",
    "DB_APPLICATION_NAME",
}


def test_the_page_carries_a_generated_section() -> None:
    page = _PAGE.read_text(encoding="utf-8")
    assert sr.BEGIN in page and sr.END in page, (
        "docs/configuration.md has no generated settings section; run "
        "`python -m scripts.settings_reference` and paste it between the markers"
    )


def test_the_table_matches_the_settings_model() -> None:
    page = _PAGE.read_text(encoding="utf-8")
    current = page.split(sr.BEGIN, 1)[1].split(sr.END, 1)[0].strip()
    expected = sr.render().split(sr.BEGIN, 1)[1].split(sr.END, 1)[0].strip()
    assert current == expected, (
        "the settings table is stale: run `python -m scripts.settings_reference` "
        "and replace the section between the markers"
    )


def test_every_settings_row_names_a_validator() -> None:
    empty = [name for name, _default, validator in sr.rows() if not validator.strip()]
    assert empty == [], f"these settings have no validator column: {empty}"


def test_every_settings_row_has_a_default_or_says_it_is_generated() -> None:
    missing = [name for name, default, _validator in sr.rows() if not default.strip()]
    assert missing == [], f"these settings render without a default: {missing}"


def test_the_template_gaps_are_exactly_the_reviewed_ones() -> None:
    """`.env.example` omits nine settings, and this is the list that says why.

    An exact set rather than a subset: a new setting that lands in neither the
    template nor this list is one an operator cannot discover, and a setting that
    silently stops being carried by the template (a rename, a deleted line) would
    otherwise pass unnoticed — both directions fail here.
    """
    assert set(sr.env_example_gaps()) == _TEMPLATE_GAPS


@pytest.mark.parametrize("name", ["REPORTS_STORE_DIR", "AUDIT_ARCHIVE_DIR"])
def test_the_two_paths_are_documented_even_though_the_template_omits_them(name: str) -> None:
    """The paths are read by the renderer's own gap check, and by an operator.

    `.env.example` is a Compose template; both paths are set by a volume mount in
    the shipped stack, which is why the template does not name them. What it must
    not do is leave them undocumented: the archive directory decides *whether
    audit retention runs at all*.
    """
    page = _PAGE.read_text(encoding="utf-8")
    assert f"`{name}`" in page, f"{name} is not documented in docs/configuration.md"
