"""Password hashing and JWT issuing/validation.

Two dependencies were replaced here:

* ``python-jose`` → **PyJWT**. python-jose has a history of *algorithm
  confusion* defects (CVE-2024-33663; an advisory from September 2026 still
  covers releases up to 3.5.0), which is a whole class of flaw rather than a
  single CVE. PyJWT requires the caller to state the accepted algorithms
  explicitly, and the accepted algorithm is pinned by configuration.
* ``passlib`` → the **``bcrypt``** package directly. passlib is unmaintained,
  and the previous code had to monkeypatch a private passlib hook
  (``_detect_wrap_bug``) to keep it working with modern bcrypt releases — a
  fragile workaround that would break on the next bcrypt bump.

Neither change alters the stored data: hashes stay ``$2b$`` bcrypt and tokens
stay HS256 JWTs signed with ``JWT_SECRET_KEY``, so existing password hashes and
already-issued refresh-token families keep working.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import uuid4

import bcrypt
import jwt
from jwt.exceptions import PyJWTError

from app.core.config import settings

# bcrypt hashes at most 72 bytes of the password. passlib's bcrypt handler
# silently truncated longer input, while the modern ``bcrypt`` package raises
# ValueError instead. Truncation is therefore applied explicitly so that every
# hash written before this change still verifies (and so that a long password
# cannot turn a login into a 500).
_BCRYPT_MAX_BYTES = 72
_BCRYPT_ROUNDS = 12


def _password_bytes(password: str) -> bytes:
    """Encode and truncate a password exactly as bcrypt will consume it."""
    return password.encode("utf-8")[:_BCRYPT_MAX_BYTES]


def create_access_token(
    data: dict, expires_delta: Optional[timedelta] = None
) -> tuple[str, int]:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
        )
    expires_in = int((expire - datetime.now(timezone.utc)).total_seconds())
    to_encode.update(
        {
            "exp": expire,
            "type": "access",
            "jti": str(uuid4()),
        }
    )
    encoded_jwt = jwt.encode(
        to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )
    return encoded_jwt, expires_in


def create_refresh_token(
    data: dict, *, family_id: str | None = None
) -> tuple[str, int, str, str]:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(
        days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS
    )
    expires_in = int((expire - datetime.now(timezone.utc)).total_seconds())
    jti = str(uuid4())
    fid = family_id or str(uuid4())
    to_encode.update(
        {
            "exp": expire,
            "type": "refresh",
            "jti": jti,
            "family_id": fid,
        }
    )
    encoded_jwt = jwt.encode(
        to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )
    return encoded_jwt, expires_in, jti, fid


def decode_token(token: str) -> dict[str, Any]:
    """Decode and validate a token, returning ``{}`` when it is not usable.

    Only the configured algorithm is accepted, so a token whose header asks for
    anything else (including ``none``) is rejected outright. ``exp`` is required:
    a token without an expiry would otherwise be a permanent credential.

    Every configured secret is tried, newest first. Without that, replacing
    ``JWT_SECRET_KEY`` would sign every user out at the moment of rotation —
    including refresh tokens, which are the credential that would otherwise let
    them back in — and the rotation would therefore be deferred until an incident
    forced it. Tokens signed with a retired secret stop working the moment it is
    removed from ``JWT_PREVIOUS_SECRET_KEYS``, which is the intended (and the
    only) way to withdraw them.
    """
    for secret in settings.jwt_verification_keys():
        try:
            return jwt.decode(
                token,
                secret,
                algorithms=[settings.JWT_ALGORITHM],
                options={"require": ["exp"]},
            )
        except PyJWTError:
            continue
    return {}


def hash_password(password: str) -> str:
    return bcrypt.hashpw(
        _password_bytes(password), bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)
    ).decode("ascii")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password, returning ``False`` for any malformed stored hash.

    Never raises: a corrupt ``password_hash`` column must deny access rather
    than turn every login attempt into a server error.
    """
    if not hashed_password:
        return False
    try:
        return bcrypt.checkpw(
            _password_bytes(plain_password), hashed_password.encode("ascii")
        )
    except (ValueError, TypeError, UnicodeEncodeError):
        return False
