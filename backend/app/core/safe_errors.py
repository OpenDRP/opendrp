"""Safe, bounded rendering of errors returned by external providers.

Provider exceptions frequently contain request URLs, query parameters, response
bodies, or connector configuration. Those values are useful in a local debug log
but are not safe to persist in the database or expose through a health endpoint.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_SECRET_KEY_RE = re.compile(
    r"(?i)(?P<key>(?:api[_-]?key|token|secret|password|passwd|authorization|bearer))"
    r"(?P<sep>\s*[:=]\s+|\s+)(?P<value>[^\s,;&]+)"
)


def _redact_url(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        parsed = urlsplit(match.group(0))
        if not parsed.scheme or not parsed.netloc:
            return match.group(0)
        query = []
        for key, item in parse_qsl(parsed.query, keep_blank_values=True):
            if re.search(r"(?i)(key|token|secret|password|auth|signature)", key):
                item = "[REDACTED]"
            query.append((key, item))
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))

    return re.sub(r"https?://[^\s]+", replace, value)


def sanitize_external_error(error: object, *, limit: int = 600) -> str:
    """Return a useful but credential-safe provider error summary.

    The exception class remains available for triage; URLs, common secret-shaped
    key/value pairs, response bodies, and excessive text are bounded. This is
    intentionally deterministic so the same error is safe in DB rows, JSON API
    responses, and structured logs.
    """
    if error is None:
        return "external provider error"
    text = _redact_url(str(error))
    text = re.sub(
        r"(?i)\b(api[_-]?key|token|secret|password|passwd|authorization|bearer)\s*[:=]\s*[^\s,;&]+",
        lambda m: f"{m.group(1)}=[REDACTED]",
        text,
    )
    text = re.sub(
        r"(?i)\b(api[_-]?key|token|secret|password|passwd|authorization|bearer)\s+[^\s,;&]+",
        lambda m: f"{m.group(1)}=[REDACTED]",
        text,
    )
    # Also cover compact query/body forms such as ``token=...`` where the
    # separator has no whitespace.
    text = re.sub(
        r"(?i)\b(?:api[_-]?key|token|secret|password|passwd|authorization|bearer)\s*=[^\s,;&]+",
        lambda m: m.group(0).split("=", 1)[0] + "=[REDACTED]",
        text,
    )
    def _redact_compact_secret(match: re.Match[str]) -> str:
        label_match = re.match(r"(?i)[a-z_-]+", match.group(0))
        label = label_match.group(0) if label_match else "secret"
        return label + "=[REDACTED]"

    text = re.sub(
        r"(?i)\b(?:api[_-]?key|token|secret|password|passwd|authorization|bearer)(?:\s*[:=]\s*|\s+)[^\s,;&]+",
        _redact_compact_secret,
        text,
    )
    text = re.sub(r"[\x00-\x1f\x7f]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit] or "external provider error"


__all__ = ["sanitize_external_error"]
