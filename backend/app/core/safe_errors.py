"""Safe, bounded rendering of errors returned by external providers.

Provider exceptions frequently contain request URLs, query parameters, response
bodies, or connector configuration. Those values are useful in a local debug log
but are not safe to persist in the database or expose through a health endpoint.

Redaction is layered, in this order, because the shapes overlap:

1. absolute URLs — query parameters whose *name* looks like a credential, plus
   bot tokens in the path (Telegram), are masked while the host and the rest of
   the query stay legible;
2. well-known vendor key prefixes (`sk-`, `ghp_`, `AIza`, `AKIA`, `xox…`) — these
   are unambiguous wherever they appear, including inside a provider body;
3. `Bearer`/`Basic`/`Digest` credentials — masked as a whole, because matching
   only the scheme word leaves the token behind it in clear text;
4. `label<sep>value` pairs, quoted or not (`"token":"…"`, `token=…`,
   `Authorization: …`) — the label and quoting are kept, the value replaced;
5. a spaced label followed by a value that looks like a key (`API key sk-…`) —
   only when the value carries a digit, so prose such as "the API key was
   rejected" survives triage intact.

Everything is deterministic so the same error renders identically in DB rows,
JSON API responses and structured logs, and the result is bounded.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

#: Vendor-issued key shapes. A provider body that echoes the key back is the
#: most common way a credential reaches a stored error string.
_VENDOR_KEY_RE = re.compile(
    r"\b(?:"
    r"sk-[A-Za-z0-9_-]{16,}"
    r"|gh[pousr]_[A-Za-z0-9]{20,}"
    r"|AIza[0-9A-Za-z_-]{30,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|xox[abprs]-[A-Za-z0-9-]{10,}"
    r")"
)

#: `Authorization: Bearer <token>` and bare `Bearer <token>`.
_AUTH_SCHEME_RE = re.compile(
    r"(?i)\b(?P<scheme>bearer|basic|digest)\s+[A-Za-z0-9._~+/=-]{8,}"
)

_LABELS = (
    r"api[ _-]?key|apikey|access[ _-]?token|refresh[ _-]?token|id[ _-]?token"
    r"|auth[ _-]?token|client[ _-]?secret|token|secret|password|passwd|pwd"
    r"|authorization|x-api-key|signature"
)

#: `token=…`, `"token":"…"`, `password: …` — the separator is required, so
#: ordinary prose containing the label ("the token was rejected") is untouched.
_SECRET_PAIR_RE = re.compile(
    r'(?i)(?<![\w-])(?P<label>"?(?:' + _LABELS + r')"?)(?P<sep>\s*[:=]\s*)'
    r'(?P<quote>["\']?)(?P<value>[^\s,;&}"\']+)'
)

#: `API key sk-…` — no separator. Requires a digit in the value so that
#: "API key rejected by the provider" is not mangled.
_SPACED_LABEL_RE = re.compile(
    r"(?i)\b(?P<label>api[ _-]?key|apikey|access[ _-]?token|client[ _-]?secret)"
    r"\s+(?P<value>(?=[^\s]*\d)[^\s,;&}\"']{8,})"
)


def _redact_url(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        parsed = urlsplit(match.group(0))
        if not parsed.scheme or not parsed.netloc:
            return match.group(0)
        query = []
        for key, item in parse_qsl(parsed.query, keep_blank_values=True):
            if re.search(r"(?i)(key|token|secret|password|auth|signature|sig)", key):
                item = "[REDACTED]"
            query.append((key, item))
        netloc = parsed.netloc.rsplit("@", 1)[-1]
        path = re.sub(r"/bot[^/]+", "/bot[REDACTED]", parsed.path)
        return urlunsplit((parsed.scheme, netloc, path, urlencode(query), ""))

    return re.sub(r"https?://[^\s\"']+", replace, value)


def _redact_pair(match: re.Match[str]) -> str:
    label = match.group("label")
    sep = match.group("sep")
    quote = match.group("quote")
    closing = quote if quote and match.string[match.end() - 1 : match.end()] == quote else ""
    if match.group("value") in {"[REDACTED]", "REDACTED", ""}:
        return match.group(0)
    return f"{label}{sep}{quote}[REDACTED]{closing}"


def sanitize_external_error(error: object, *, limit: int = 600) -> str:
    """Return a useful but credential-safe provider error summary.

    The exception class and provider message remain available for triage; URLs,
    credential-shaped values, response bodies and excessive text are bounded.
    """
    if error is None:
        return "external provider error"
    text = _redact_url(str(error))
    text = _VENDOR_KEY_RE.sub("[REDACTED]", text)
    text = _AUTH_SCHEME_RE.sub(lambda m: f"{m.group('scheme')} [REDACTED]", text)
    text = _SECRET_PAIR_RE.sub(_redact_pair, text)
    text = _SPACED_LABEL_RE.sub(
        lambda m: f"{m.group('label')} [REDACTED]", text
    )
    text = re.sub(r"[\x00-\x1f\x7f]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit] or "external provider error"


__all__ = ["sanitize_external_error"]
