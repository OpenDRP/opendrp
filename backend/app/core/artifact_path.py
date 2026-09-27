"""Where a generated report artifact is allowed to live, and how it is named.

A report is the only thing this platform writes to disk, and the only thing it
ever reads back from a path stored in a row. That combination is where an
arbitrary-file-read usually comes from: the value in the column is treated as a
path, and everything that can influence the column — a worker running with a
different mount point, a restored backup from an older release, a later feature
that lets an operator import report metadata, or simply someone with write access
to the database — can then point the reader at a file the platform never wrote.

The fix is to stop storing a path at all. `reports.file_path` holds an
opaque artifact *name* (``<uuid>.pdf``), the directory is configuration, and this
module is the only place the two are combined. Everything it returns:

* is a plain name — no separators, no ``..``, no drive letter, no absolute path;
* resolves, after following symlinks, to a **regular file inside the store
  directory** — so a symlink planted in the store cannot be used as the escape
  either;
* ends in a suffix the platform actually produces.

When a stored value does not meet those rules the caller is told *why*, in
machine-readable form, because "the row points somewhere it should not" is a
finding worth an audit record rather than a 404 indistinguishable from a deleted
file.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

from app.core.config import settings

#: The only artifact type the platform produces.
ARTIFACT_SUFFIX = ".pdf"

#: Longest name that is still a name rather than a payload.
_MAX_NAME_LENGTH = 255

#: Outcome of interpreting a stored value. Strings rather than an enum so that
#: they can be written straight into an audit record and read by a person.
REASON_OK = "ok"
REASON_NO_NAME = "no_name"
REASON_MISSING = "missing"
REASON_NOT_A_NAME = "not_a_name"
REASON_OUTSIDE_STORE = "outside_store"


def store_directory() -> Path:
    """The configured artifact directory, with symlinks resolved."""
    return Path(os.path.realpath(str(settings.REPORTS_STORE_DIR or ".")))


def artifact_filename(report_id: uuid.UUID | str) -> str:
    """The name a report's artifact is stored under.

    Derived from the report's id rather than from its display name: a name the
    caller chooses is a name the caller can put a path into, and this way there is
    nothing to sanitise on the way in.
    """
    return f"{uuid.UUID(str(report_id))}{ARTIFACT_SUFFIX}"


def artifact_path(report_id: uuid.UUID | str) -> Path:
    """Absolute path to write a report's artifact to."""
    return store_directory() / artifact_filename(report_id)


def _is_plain_name(name: str) -> bool:
    """True when ``name`` is a single path component with no traversal in it.

    Checked as a property of the string rather than by comparing with
    ``os.path.basename``: on POSIX a backslash is an ordinary character, so a name
    like ``..\\..\\etc\\passwd`` passes a basename test and is still a traversal on
    the platform it was written for. Both separators are rejected outright.
    """
    if not name or len(name) > _MAX_NAME_LENGTH:
        return False
    if name in {".", ".."}:
        return False
    if "\x00" in name or "\n" in name or "\r" in name:
        return False
    if "/" in name or "\\" in name:
        return False
    if ":" in name:
        # Windows drive letters and alternate data streams; nothing this platform
        # produces contains a colon. This is also what covers `C:report.pdf` on
        # POSIX and `C:\\report.pdf` on Windows, which is why no platform-specific
        # drive check is needed here — an earlier version called
        # ``os.path.isdrive``, which does not exist on ``posixpath`` and turned
        # every classification into an ``AttributeError`` on Linux.
        return False
    if os.path.isabs(name):
        return False
    return True


def classify_artifact(stored: str | None) -> tuple[Path | None, str]:
    """Interpret a stored artifact value.

    Returns the path to serve (or ``None``) together with a reason from the
    ``REASON_*`` constants:

    ``ok``
        A readable regular file inside the store.
    ``no_name``
        The row carries no artifact name at all.
    ``missing``
        A valid name whose file is absent or unreadable — an operational incident
        (a restored backup that did not include the volume, a manual cleanup),
        not a security event.
    ``not_a_name``
        The value is not a plain artifact name: it has a directory component, a
        traversal, or a suffix the platform does not produce.
    ``outside_store``
        The name resolved to somewhere other than the store directory, which for
        a plain name means a symlink inside the store (or a store directory that
        is itself a symlink to somewhere unexpected).
    """
    raw = str(stored or "").strip()
    if not raw:
        return None, REASON_NO_NAME

    # Deliberately no "take the basename and retry" fallback: that is what turns
    # a stored name into a path lookup. The column holds a plain artifact name,
    # on the mount every replica shares, and a directory component in it is a
    # finding rather than something to normalise away quietly.
    if not _is_plain_name(raw):
        return None, REASON_NOT_A_NAME
    if not raw.lower().endswith(ARTIFACT_SUFFIX):
        return None, REASON_NOT_A_NAME
    if len(raw) <= len(ARTIFACT_SUFFIX):
        # A suffix with no stem (`.pdf`). Nothing this platform produces looks
        # like that, and accepting it would mean serving a file whose name was
        # chosen to look like an extension.
        return None, REASON_NOT_A_NAME

    directory = store_directory()
    try:
        resolved = Path(os.path.realpath(directory / raw))
    except OSError:
        return None, REASON_MISSING

    if not _is_inside(resolved, directory):
        # Only reachable through a symlink: `raw` is one component with no
        # traversal in it, so the path cannot climb out on its own.
        return None, REASON_OUTSIDE_STORE
    if not resolved.is_file():
        return None, REASON_MISSING
    return resolved, REASON_OK


def resolve_artifact(stored: str | None) -> Path | None:
    """The readable path for a stored artifact value, or ``None``.

    A convenience over :func:`classify_artifact` for callers that only need to
    know whether the artifact can be served.
    """
    path, _reason = classify_artifact(stored)
    return path


def _is_inside(path: Path, directory: Path) -> bool:
    """True when ``path`` lies inside ``directory`` (both already resolved)."""
    try:
        return path.resolve().is_relative_to(directory.resolve())
    except (OSError, ValueError):
        return False


def describe_rejection(stored: str | None, reason: str) -> dict:
    """Audit details for a stored value that was refused.

    Carries the *basename* and the reason, never the raw stored string: the whole
    point is that the value may be a path from somewhere else on the host, and an
    audit record is read by more people than the operator who wrote the row.
    """
    raw = str(stored or "")
    return {
        "artifact_name": raw.replace("\\", "/").rsplit("/", 1)[-1][:255],
        "had_directory_component": ("/" in raw or "\\" in raw),
        "reason": reason,
        "store_dir_len": len(str(settings.REPORTS_STORE_DIR or "")),
    }
