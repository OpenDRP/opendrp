"""TOTP (RFC 6238) for the platform's second authentication factor.

Implemented here rather than pulled in as a dependency. The algorithm is about
twenty lines of standard library — HMAC-SHA1 over a counter, dynamic truncation,
six digits — and the two things that would otherwise be an argument for a library
are exactly the two things this file pins explicitly: the step size and the
accepted clock-skew window. A dependency would also put a third party on the
authentication path of a security product, where the blast radius of a
compromised release is every account.

Two decisions are deliberate and worth knowing when reading the code:

* **SHA-1.** Not a choice made here: RFC 6238's interoperable profile is
  HMAC-SHA1, every authenticator app implements it, and the construction is
  HMAC, not a signature — the hash's collision resistance is not what the
  security rests on.
* **A ±1 step window.** Client clocks drift, and rejecting a code that is valid
  for another 20 seconds produces support tickets rather than security. The
  replay risk that a window creates is handled where it can be handled exactly:
  the caller records the step it accepted (see ``users.totp_last_used_step``), so
  the same code cannot be used twice no matter how wide the window is.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode

DIGITS = 6
STEP_SECONDS = 30
#: Steps accepted either side of the current one, i.e. ±30 seconds of skew.
DEFAULT_WINDOW = 1

_SECRET_BYTES = 20  # 160 bits, the size RFC 4226 recommends for HMAC-SHA1


def generate_secret() -> str:
    """A fresh base32 secret, padding stripped.

    Unpadded because that is what authenticator apps and `otpauth://` URLs expect;
    `_decode_secret` puts the padding back.
    """
    return base64.b32encode(secrets.token_bytes(_SECRET_BYTES)).decode("ascii").rstrip("=")


def normalize_secret(secret: str) -> str:
    """Accept a secret as a human typed it: upper case, no spaces or padding."""
    return (secret or "").strip().replace(" ", "").replace("-", "").upper().rstrip("=")


def _decode_secret(secret: str) -> bytes:
    normalized = normalize_secret(secret)
    padding = "=" * (-len(normalized) % 8)
    return base64.b32decode(normalized + padding)


def current_step(at: float | None = None) -> int:
    """The counter value for a moment in time."""
    return int((time.time() if at is None else at) // STEP_SECONDS)


def code_at(secret: str, counter: int) -> str:
    """The six-digit code for one counter value."""
    if counter < 0:
        return ""
    digest = hmac.new(
        _decode_secret(secret), struct.pack(">Q", counter), hashlib.sha1
    ).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{truncated % 10 ** DIGITS:0{DIGITS}d}"


def verify(
    secret: str,
    code: str,
    *,
    at: float | None = None,
    window: int = DEFAULT_WINDOW,
) -> int | None:
    """Return the counter value this code matches, or ``None``.

    Returning the *step* rather than a boolean is what lets the caller refuse a
    replay: a code that matched a step at or before the last accepted one has been
    seen already.

    Comparison is constant-time (``secrets.compare_digest``) even though a TOTP
    code is short-lived and rate-limited — the cost is nil, and a timing signal in
    an authentication path is the kind of thing that is only ever noticed after it
    matters.
    """
    candidate = (code or "").strip().replace(" ", "")
    if len(candidate) != DIGITS or not candidate.isdigit():
        return None
    try:
        _decode_secret(secret)
    except Exception:
        # A corrupt or truncated stored secret must deny the login instead of
        # raising inside the authentication path.
        return None

    step = current_step(at)
    for offset in range(-window, window + 1):
        if secrets.compare_digest(code_at(secret, step + offset), candidate):
            return step + offset
    return None


def provisioning_uri(secret: str, *, account: str, issuer: str) -> str:
    """The `otpauth://` URI an authenticator app scans.

    The label carries both issuer and account because that is what most apps
    display; the issuer is repeated as a parameter because RFC 6238's profile for
    provisioning URIs requires it, and apps that use it will not group entries
    without it.
    """
    label = quote(f"{issuer}:{account}", safe="")
    query = urlencode(
        {
            "secret": normalize_secret(secret),
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": DIGITS,
            "period": STEP_SECONDS,
        }
    )
    return f"otpauth://totp/{label}?{query}"
