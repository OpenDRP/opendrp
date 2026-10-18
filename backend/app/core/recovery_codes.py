"""One-time second-factor recovery codes: generate, digest, verify.

The codes are the way back into an account whose authenticator is gone, so they
are credentials: 12 characters from a 30-symbol alphabet (≈59 bits), returned in
plaintext exactly once and never logged. Only a digest is stored.

**Why HMAC and not bcrypt.** Ten bcrypt hashes cost ≈2.3 s to produce at enrolment
and up to ten bcrypt comparisons to check a code — paid on the event loop, for a
value that is already 59 bits of random, so the slow hash buys nothing an attacker
who can read the table did not already have. An HMAC-SHA256 digest with a
server-side key is the right primitive here: fast enough to stay off the loop's
critical path, and unguessable without the key that lives in the environment, not
in the database.

**The key** is derived from ``ENCRYPTION_KEY`` with a label of its own, and the
previous encryption keys verify too, so rotating ``ENCRYPTION_KEY`` the documented
way (new key first, old one in ``ENCRYPTION_PREVIOUS_KEYS``, rewrap, drop) does not
invalidate a single printed code for the duration of the rotation.

**A bcrypt digest among the stored codes keeps working.** A digest written with the
slow hash cannot be converted without its plaintext, and the only plaintext the
platform ever sees is the code being consumed — which is deleted on use. So
:func:`is_bcrypt_hash` marks those entries for the caller to verify with
``security.verify_password`` (on a worker thread), new codes are HMAC, and a list
becomes entirely HMAC as codes are used or the codes are rotated. That is the
property the audit asked for — no account loses access to its own recovery path —
and it is honest about what a spent code can leave behind: nothing.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from app.core.config import settings

#: Shared alphabet: no ``0``/``O`` or ``1``/``I``, because these are read off a
#: screen and typed by hand.
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CODE_LENGTH = 12
CODE_COUNT = 10

#: Marks a digest this module wrote. A value without it is a bcrypt hash from an
#: earlier release and is verified the old way.
PREFIX = "hmac-sha256:"

_DERIVATION_LABEL = b"opendrp-recovery-code-v1"


def _digest_keys() -> list[bytes]:
    """HMAC keys for the configured encryption keys, newest first.

    The same ordering as ``crypto.configured_keys``: index 0 signs, the rest only
    verify, so a rotation keeps the codes that were issued before it working.
    """
    material = [settings.ENCRYPTION_KEY, *settings.encryption_previous_keys()]
    return [
        hmac.new(value.encode("utf-8"), _DERIVATION_LABEL, hashlib.sha256).digest()
        for value in material
        if value
    ]


def _digest(code: str, key: bytes) -> str:
    return f"{PREFIX}{hmac.new(key, code.encode('utf-8'), hashlib.sha256).hexdigest()}"


def digest(code: str) -> str:
    """The stored form of ``code``, signed with the current key."""
    return _digest(code, _digest_keys()[0])


def generate() -> tuple[list[str], list[str]]:
    """Return fresh plaintext codes and their digests, in the same order."""
    plain = [
        "".join(secrets.choice(ALPHABET) for _ in range(CODE_LENGTH))
        for _ in range(CODE_COUNT)
    ]
    return plain, [digest(code) for code in plain]


def is_bcrypt_hash(stored: str) -> bool:
    """Whether ``stored`` is a bcrypt hash rather than an HMAC digest."""
    return not stored.startswith(PREFIX)


def verify(code: str, stored: str) -> bool:
    """Whether ``code`` matches an HMAC digest.

    Only HMAC digests: a bcrypt value needs the blocking comparison, which the
    caller runs on a worker thread (see ``_consume_recovery_code``).
    """
    if is_bcrypt_hash(stored):
        return False
    presented = stored[len(PREFIX) :]
    for key in _digest_keys():
        candidate = hmac.new(key, code.encode("utf-8"), hashlib.sha256).hexdigest()
        if hmac.compare_digest(candidate, presented):
            return True
    return False


__all__ = [
    "ALPHABET",
    "CODE_COUNT",
    "CODE_LENGTH",
    "PREFIX",
    "digest",
    "generate",
    "is_bcrypt_hash",
    "verify",
]
