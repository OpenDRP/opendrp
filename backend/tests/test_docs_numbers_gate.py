"""A number a published page states has to be the number the code holds.

Every value below was checked by hand during the documentation audit of
2026-10-15, and nothing repeated the comparison afterwards. That is the failure
mode this file exists to close: a limit is raised in one module, the page that
promised the old one keeps reading as current, and the operator who sizes a
batch from it learns the truth from a `422`.

Each entry is one claim: the page, the sentence that makes it, a pattern whose
first group is the number the sentence states, and the single place that number
comes from. The number is never written twice — the expected value is read from
the constant, the settings object, or (for the password's byte ceiling, which is
the hash function's boundary rather than a named constant) from the validator's
own behaviour. `test_the_claim_is_still_in_the_page` and
`test_the_page_states_the_number_the_code_holds` are deliberately separate: a
sentence deleted from a page is a finding, not a silent pass.

What is not here, and why:

* the dated measurements in [production-readiness.md](../../docs/production-readiness.md)
  — coverage percentages, the migration run, host requirements — are one
  reading of one tree on one day, and the page says so; comparing them to today's
  code would turn a record into a promise it never made;
* Compose's `stop_grace_period` is read from `docker-compose.yml`, because that
  file is what a restart obeys: a copy of `60` in this table would agree with the
  page while the installation gave the worker something else;
* the version claim is compared to `app.__version__` rather than to
  `scripts/check_version_consistency.py`: that script already fails the build
  when the copies disagree, and this gate asks the narrower question — does the
  page still name the version the code declares.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import pytest

from app.schemas.asset import (
    BULK_MAX_IDS,
    EXPORT_MAX_ROWS,
    IMPORT_MAX_BYTES,
    IMPORT_MAX_ITEMS,
)
from app.schemas.user import validate_password_strength

_ROOT = Path(__file__).resolve().parents[2]

Number = int | float

#: The words a page spells a small bound with, because prose reads better than a
#: digit there. Normalised in one place so a pattern may capture either spelling.
_NUMBER_WORDS = {
    "zero": 0,
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
    "twelve": 12,
}


def _password_min_length() -> int:
    from app.schemas.user import PASSWORD_MIN_LENGTH

    return PASSWORD_MIN_LENGTH


def _max_page_size() -> int:
    from app.schemas.common import MAX_PAGE_SIZE

    return MAX_PAGE_SIZE


def _duration_seconds(value: str) -> int:
    """A Compose duration (`60s`, `1m30s`) in seconds, the unit it is compared in."""
    units = {"s": 1, "m": 60, "h": 3600}
    total = 0
    for amount, unit in re.findall(r"(\d+)([smh])", value):
        total += int(amount) * units[unit]
    assert total, f"`{value}` is not a duration this gate understands"
    return total


def _compose_grace_seconds(service: str) -> int:
    """The stop grace period `docker-compose.yml` gives one service.

    The file is the single source: Compose is what acts on the value, so a number
    copied into this table would keep agreeing with the page while a restart did
    something else.
    """
    import yaml

    compose = yaml.safe_load((_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    value = compose["services"][service]["stop_grace_period"]
    assert isinstance(value, str), f"{service} has a numeric stop_grace_period"
    return _duration_seconds(value)


def _recovery_code_count() -> int:
    # The constant lives with the codes themselves since RWI-08: the router no
    # longer owns the one-time list, `app/core/recovery_codes.py` does.
    from app.core.recovery_codes import CODE_COUNT

    return CODE_COUNT


def _smtp_probe_workers() -> int:
    from app.api.v1.routers.alerts import _SMTP_PROBE_MAX_WORKERS

    return _SMTP_PROBE_MAX_WORKERS


def _audit_retention_days() -> int:
    from app.core.config import settings

    return settings.AUDIT_RETENTION_DAYS


def _report_retention_days() -> int:
    from app.core.config import settings

    return settings.REPORT_RETENTION_DAYS


def _alert_history_retention_days() -> int:
    from app.core.config import settings

    return settings.ALERT_HISTORY_RETENTION_DAYS


def _password_byte_ceiling() -> int:
    """The longest UTF-8 password the validator accepts, measured, not asserted.

    bcrypt silently ignores everything past 72 bytes, so the bound belongs to the
    validator rather than to a number in documentation. Probing it keeps the page
    honest if the validator ever moves — a copied `72` would not.
    """
    from app.schemas.user import PASSWORD_MIN_LENGTH

    for total in range(PASSWORD_MIN_LENGTH, 200):
        # `Aa1` satisfies both required character classes and is three bytes; the
        # rest is padding, so the only reason to refuse is the byte ceiling.
        candidate = "Aa1" + "x" * max(total - 3, 0)
        try:
            validate_password_strength(candidate)
        except ValueError:
            return total - 1
    raise AssertionError("the validator accepted a password longer than 199 bytes")


def _import_megabytes() -> float:
    return IMPORT_MAX_BYTES / (1024 * 1024)


def _platform_version() -> str:
    from app import __version__

    return __version__


def _public_routes() -> int:
    """The routes the route-access gate lets through without a capability.

    Read from the gate's own map, not from the routers: whether a route requires
    a capability is decided by the dependency it attaches, and the gate is the
    one place that enumerates the exceptions. A count in this file would agree
    with itself while the surface it describes grew.
    """
    from tests.test_route_access_gate import _PUBLIC_REASONS

    return len(_PUBLIC_REASONS)


@dataclass(frozen=True)
class Claim:
    #: Page a reader lands on, relative to the checkout root.
    page: str
    #: What the sentence promises, for the failure message.
    promise: str
    #: One capturing group: the number as the page writes it.
    pattern: str
    #: The single place the value comes from.
    source: Callable[[], object]
    #: How the source is named, so a failure points at the file to edit.
    source_name: str


_CLAIMS: tuple[Claim, ...] = (
    # ---- README.md: the asset limits an operator plans a batch against --------
    Claim(
        page="README.md",
        promise="an inventory import carries at most this many rows",
        pattern=r"(\d+) rows and \d+ MiB per import",
        source=lambda: IMPORT_MAX_ITEMS,
        source_name="app.schemas.asset.IMPORT_MAX_ITEMS",
    ),
    Claim(
        page="README.md",
        promise="an inventory import is at most this many MiB",
        pattern=r"\d+ rows and (\d+(?:\.\d+)?) MiB per import",
        source=_import_megabytes,
        source_name="app.schemas.asset.IMPORT_MAX_BYTES",
    ),
    Claim(
        page="README.md",
        promise="a bulk action names at most this many ids",
        pattern=r"(\d+) ids per bulk action",
        source=lambda: BULK_MAX_IDS,
        source_name="app.schemas.asset.BULK_MAX_IDS",
    ),
    Claim(
        page="README.md",
        promise="an export carries at most this many rows",
        pattern=r"([\d\u00a0 ]+) rows per export",
        source=lambda: EXPORT_MAX_ROWS,
        source_name="app.schemas.asset.EXPORT_MAX_ROWS",
    ),
    # ---- docs/observability.md: how long evidence is kept -------------------
    Claim(
        page="docs/observability.md",
        promise="audit rows are kept this many days by default",
        pattern=r"\| `drp_audit_logs` \(evidence in the product\) \| (\d+) days",
        source=_audit_retention_days,
        source_name="settings.AUDIT_RETENTION_DAYS",
    ),
    Claim(
        page="docs/observability.md",
        promise="generated PDFs are kept this many days by default",
        pattern=r"\| Generated PDFs in the report store \| (\d+) days",
        source=_report_retention_days,
        source_name="settings.REPORT_RETENTION_DAYS",
    ),
    Claim(
        page="docs/observability.md",
        promise="terminal alert deliveries are kept this many days by default",
        pattern=(
            r"\| Terminal alert deliveries and processed ingestion events \| "
            r"(\d+) days"
        ),
        source=_alert_history_retention_days,
        source_name="settings.ALERT_HISTORY_RETENTION_DAYS",
    ),
    Claim(
        page="docs/observability.md",
        promise="an SMTP health check runs in a pool of this many workers",
        pattern=r"SMTP checks use a fixed pool of (\w+) workers",
        source=_smtp_probe_workers,
        source_name="app.api.v1.routers.alerts._SMTP_PROBE_MAX_WORKERS",
    ),
    # ---- docs/description.md: the credential policy -------------------------
    Claim(
        page="docs/description.md",
        promise="a new password is at least this many characters",
        pattern=r"needs at least (\d+)\s+characters",
        source=_password_min_length,
        source_name="app.schemas.user.PASSWORD_MIN_LENGTH",
    ),
    Claim(
        page="docs/description.md",
        promise="a new password is at most this many UTF-8 bytes",
        pattern=r"no more than (\d+)\s+UTF-8 bytes",
        source=_password_byte_ceiling,
        source_name="app.schemas.user.validate_password_strength",
    ),
    Claim(
        page="docs/description.md",
        promise="enrolment shows this many one-time recovery codes",
        pattern=r"shows (\w+) one-time recovery codes",
        source=_recovery_code_count,
        source_name="app.core.recovery_codes.CODE_COUNT",
    ),
    # ---- the API's own pagination bound -------------------------------------
    Claim(
        page="docs/api.md",
        promise="a list endpoint serves at most this many rows per page",
        pattern=r"may not exceed (\d+) rows",
        source=_max_page_size,
        source_name="app.schemas.common.MAX_PAGE_SIZE",
    ),
    # ---- Compose's shutdown budget ------------------------------------------
    Claim(
        page="docs/deployment.md",
        promise="the report worker is given this many seconds to stop",
        pattern=r"report worker (\d+) seconds to finish",
        source=lambda: _compose_grace_seconds("celery-worker"),
        source_name="docker-compose.yml services.celery-worker.stop_grace_period",
    ),
    Claim(
        page="docs/deployment.md",
        promise="the alert worker is given this many seconds to stop",
        pattern=r"alert worker (\d+) seconds",
        source=lambda: _compose_grace_seconds("celery-worker-alerts"),
        source_name="docker-compose.yml services.celery-worker-alerts.stop_grace_period",
    ),
    # ---- the public surface the route-access gate leaves open ---------------
    # Not an appendix measurement: the page states a current guarantee about the
    # endpoints that need no capability, so it is compared like any other bound.
    Claim(
        page="docs/production-readiness.md",
        promise="this many routes are public without a capability",
        pattern=r"one of the (\w+) named public routes",
        source=_public_routes,
        source_name="tests.test_route_access_gate._PUBLIC_REASONS",
    ),
    # ---- the version a page pins to this checkout ---------------------------
    Claim(
        page="docs/deployment.md",
        promise="this checkout declares this version",
        pattern=r"This checkout declares version `([^`]+)`",
        source=_platform_version,
        source_name="app.__version__",
    ),
    Claim(
        page="docs/upgrading.md",
        promise="this version publishes no registry images",
        pattern=(
            r"([0-9]+\.[0-9]+\.[0-9]+) declares its version but publishes no "
            r"registry images"
        ),
        source=_platform_version,
        source_name="app.__version__",
    ),
)


def _read(page: str) -> str:
    return (_ROOT / page).read_text(encoding="utf-8")


def _find(claim: Claim, text: str) -> list[re.Match[str]]:
    """Every occurrence of the claim, across the page's line wrapping.

    Prose is wrapped at eighty columns, so a sentence a reader sees whole is two
    lines in the source. A literal space in a pattern therefore matches any run of
    whitespace; the `\\s+` the patterns already write mean the same thing.
    """
    return list(re.finditer(claim.pattern.replace(" ", r"\s+"), text))


def _as_number(raw: str) -> Number:
    token = raw.strip()
    word = _NUMBER_WORDS.get(token.lower())
    if word is not None:
        return word
    # `10 000` and `10,000` are the same number written for their audience; a
    # narrow no-break space is what a page that avoids a line break uses.
    cleaned = re.sub(r"[\s,_\u00a0\u202f]", "", token)
    return float(cleaned) if "." in cleaned else int(cleaned)


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


#: Stable test ids: a reader of CI output sees the page and the promise, not an
#: index into a table that shifts whenever a claim is added.
_IDS = [f"{claim.page}: {claim.promise}" for claim in _CLAIMS]


@pytest.mark.parametrize("claim", _CLAIMS, ids=_IDS)
def test_the_claim_is_still_in_the_page(claim: Claim) -> None:
    """A sentence removed from a page is a finding, not a silent pass.

    The value check below would otherwise pass by finding nothing to compare,
    which is exactly how a deleted promise reads as a satisfied one.
    """
    matches = _find(claim, _read(claim.page))

    assert matches, (
        f"{claim.page} no longer states that {claim.promise}: the page dropped "
        f"the sentence this gate compares against {claim.source_name}, so the "
        f"number is now unverified — restore the sentence or retire the claim"
    )


@pytest.mark.parametrize("claim", _CLAIMS, ids=_IDS)
def test_the_page_states_the_number_the_code_holds(claim: Claim) -> None:
    text = _read(claim.page)
    matches = _find(claim, text)
    assert matches, (
        f"{claim.page} no longer states that {claim.promise}: there is no number "
        f"to compare against {claim.source_name}"
    )

    expected = claim.source()
    if isinstance(expected, str):
        claimed: object = matches[0].group(1)
    else:
        claimed = _as_number(matches[0].group(1))
    line = _line_number(text, matches[0].start())

    assert claimed == expected, (
        f"{claim.page}:{line} states {claimed} where {claim.source_name} is "
        f"{expected}: the page promises a bound the platform does not enforce, "
        f"and an operator who plans work from it is refused by the API"
    )


def test_the_claims_name_pages_that_exist() -> None:
    """A page a claim points at is a page this repository has.

    Kept separate from the per-claim tests because a rename should read as a
    broken table entry, not as a missing sentence on a page nobody opened.
    """
    missing = sorted({claim.page for claim in _CLAIMS if not (_ROOT / claim.page).is_file()})

    assert not missing, (
        f"the number gate points at page(s) this checkout does not have: "
        f"{', '.join(missing)} — the claim table has outlived the page it was "
        f"written against"
    )
