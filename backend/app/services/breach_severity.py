"""How loud a finding is, from the classes of data it exposed (F-13, F-14).

A leak of plaintext passwords is a credential-stuffing incident whatever its size,
and a list of email addresses is a spam target: the size of a breach says how many
people are affected, and the classes of data say what can be done with it. The
page, the API filter and the stored column therefore all read one rule from here,
and the result is written to the row when the row is written — a derived number
computed in three places would eventually disagree with itself.

The names come from the sources' own vocabularies (`Passwords`, `Hashed
passwords`, `Physical addresses`, …), so matching is by keyword rather than by an
exact list: a source that phrases a known class differently is still classified,
and a class nothing here recognizes contributes nothing and leaves the row
``unknown`` instead of being guessed into a bucket.
"""

from __future__ import annotations

from typing import Any, Iterable

from sqlalchemy import case
from sqlalchemy.sql.elements import ColumnElement

#: Loudest first. ``unknown`` is not "low": it is "the platform has no opinion",
#: which is what an unrecognized class must stay rather than becoming a quiet finding.
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "unknown")

#: A total order for sorting and for "the loudest class on this row wins".
SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "unknown": 0,
}


def normalize_data_class(name: Any) -> str:
    """A class name as the matcher reads it: lowercase, single-spaced, trimmed."""
    return " ".join(str(name or "").strip().lower().split())


def _severity_of_one(name: str) -> str | None:
    """The severity one class contributes, or ``None`` when it is unrecognized.

    Order matters: ``Hashed passwords`` contains ``password`` but is not the same
    exposure as plaintext credentials, and ``Password hints`` is a weaker signal
    than the password itself. Each is therefore tested before the generic keyword
    it contains.
    """
    if not name:
        return None
    if "hashed password" in name or "encrypted password" in name:
        return "high"
    if "password hint" in name:
        return "medium"
    if "password" in name or "passphrase" in name:
        # Plaintext credentials are the strongest thing a breach can expose: the
        # account can be taken over without cracking anything.
        return "critical"
    if "security question" in name:
        return "critical"
    if any(token in name for token in ("social security", "passport", "government issued id", "national id")):
        return "critical"
    if "partial credit card" in name:
        return "high"
    if any(token in name for token in ("credit card", "bank account", "account balance", "crypto wallet")):
        return "critical"
    if any(token in name for token in ("payment", "billing", "financial", "tax record", "salary")):
        return "high"
    if any(token in name for token in ("auth token", "api key", "session token", "private key")):
        return "high"
    # The identifiers people are known by are the weakest exposure, and two of them
    # contain words the next rule looks for ("user name" holds "name"), so they are
    # asked first.
    if any(
        token in name
        for token in ("email", "username", "user name", "ip address", "browser", "device", "location")
    ):
        return "low"
    if any(
        token in name
        for token in (
            "physical address",
            "postal address",
            "address",
            "phone",
            "date of birth",
            "birth date",
            "name",
            "employer",
            "job title",
            "education",
            "gender",
        )
    ):
        return "medium"
    return None


def severity_for_data_classes(classes: Iterable[Any] | None) -> str:
    """The severity of the loudest class on a row, or ``unknown`` when none is known.

    ``unknown`` is a statement about the platform, not about the incident: it means
    the source named a class this rule has never seen, which is why it is kept
    apart from ``low`` rather than being silently ranked at the bottom.
    """
    loudest = 0
    seen = False
    for item in classes or []:
        contribution = _severity_of_one(normalize_data_class(item))
        if contribution is None:
            continue
        seen = True
        loudest = max(loudest, SEVERITY_RANK[contribution])
    if not seen:
        return "unknown"
    return next(name for name, rank in SEVERITY_RANK.items() if rank == loudest)


def severity_rank(severity: str | None) -> int:
    """The sort position of a stored severity; an absent one sorts below ``low``."""
    return SEVERITY_RANK.get(str(severity or "").strip().lower(), 0)


#: What an operator reads, mirroring the page: the stored token is what filters and
#: sorts answer, and this is the word printed beside a finding in a report.
SEVERITY_LABELS: dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "unknown": "Unclassified",
}


def severity_label(severity: str | None) -> str:
    return SEVERITY_LABELS.get(str(severity or "").strip().lower(), SEVERITY_LABELS["unknown"])


def severity_rank_case(column: Any) -> ColumnElement[int]:
    """The stored severity as its rank, for ``ORDER BY`` on either database.

    One expression rather than one per query: the list and the report both read it,
    and a second hand-written ``CASE`` is how the two would eventually disagree about
    which finding is loudest. A value this module does not know sorts below ``low``.
    """
    return case(
        (column == "critical", 4),
        (column == "high", 3),
        (column == "medium", 2),
        (column == "low", 1),
        else_=0,
    )
