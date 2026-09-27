"""Regression coverage for the credential layer after the security hardening.

Two dependencies were swapped here, and both swaps must stay invisible to data
that is already stored:

* ``python-jose`` → **PyJWT** (CVE-2024-33663 algorithm confusion; a September
  2026 advisory still covers releases up to 3.5.0);
* ``passlib`` → the **``bcrypt``** package (passlib is unmaintained and needed a
  monkeypatch of its private ``_detect_wrap_bug`` hook to work at all).

The hashes in ``PASSLIB_HASHES`` were produced by passlib 1.7.4 with bcrypt
4.0.1 — the exact code this module replaced. If they stop verifying, existing
operators are locked out of the platform, so they are pinned as literals rather
than regenerated at test time.
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from pydantic import ValidationError

from app.core.config import JWT_ALGORITHMS_ALLOWED, Settings, settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)

_LONG_ASCII = "A1" + "x" * 90 + "Z9"  # 94 bytes: crosses the bcrypt 72-byte limit
_LONG_CYRILLIC = "Пароль" * 10 + "X1"  # 104 bytes: also crosses a UTF-8 boundary

# (password, a password that must be rejected, passlib-produced hash)
PASSLIB_HASHES = [
    (
        "LegacyPass123",
        "LegacyPass124",
        "$2b$12$NgI/B1c9HOVn1aqPswCNpOdczQC9MWh44V53..vziCSsybi7Nd5zC",
    ),
    (
        _LONG_ASCII,
        "A2" + "x" * 90 + "Z9",
        "$2b$12$PxqeYep0RxmAuj0dfH1oZu.XCS4.PQTnLXHy2GnqP6OTHfghGrj5.",
    ),
    (
        _LONG_CYRILLIC,
        "Рароль" * 10 + "X1",
        "$2b$12$7QEe1qilYmVygsrdodqJC.sOJ7iNa0vbF4oppm.GN4i3NK3hoFR.O",
    ),
]


@pytest.mark.parametrize(("password", "wrong", "hashed"), PASSLIB_HASHES)
def test_hashes_written_by_passlib_still_verify(password, wrong, hashed):
    assert verify_password(password, hashed) is True


@pytest.mark.parametrize(("password", "wrong", "hashed"), PASSLIB_HASHES)
def test_passlib_hashes_still_reject_a_wrong_password(password, wrong, hashed):
    assert verify_password(wrong, hashed) is False


@pytest.mark.parametrize(
    "hashed",
    [
        "",
        "not-a-hash",
        "$2b$12$tooshort",
        "$2b$12$" + "!" * 53,
        "$1$legacy$" + "a" * 22,
    ],
)
def test_malformed_stored_hashes_deny_instead_of_raising(hashed):
    """A corrupt password_hash column must deny access, not 500 the endpoint."""
    assert verify_password("anything", hashed) is False


@pytest.mark.parametrize("hashed", [None, 0, False])
def test_missing_stored_hash_denies(hashed):
    assert verify_password("anything", hashed) is False


def test_hash_password_returns_ascii_bcrypt_hash():
    hashed = hash_password("Str0ngPassword!")
    assert hashed.startswith("$2b$")
    assert hashed.isascii()
    assert verify_password("Str0ngPassword!", hashed) is True


@pytest.mark.parametrize("password", [_LONG_ASCII, _LONG_CYRILLIC])
def test_passwords_longer_than_72_bytes_round_trip(password):
    """bcrypt rejects >72 bytes outright, so the truncation must be explicit."""
    assert len(password.encode("utf-8")) > 72
    assert verify_password(password, hash_password(password)) is True


def test_bcrypt_truncation_semantics_are_unchanged():
    """Documents inherent bcrypt behaviour, not something this change altered.

    Everything past byte 72 is ignored, so two passwords sharing a 72-byte
    prefix are interchangeable. passlib behaved identically and the platform has
    never enforced a maximum password length, so this is stated as a known
    property rather than silently relied upon.
    """
    prefix = "A1" + "x" * 70  # exactly 72 bytes
    assert verify_password(prefix, hash_password(prefix + "A-TAIL-THAT-IS-IGNORED"))


@pytest.mark.parametrize(
    "algorithm",
    ["none", "None", "NONE", "RS256", "ES256", "HS128", "HS255", "", " ", "md5"],
)
def test_unusable_signing_algorithms_are_rejected(algorithm):
    """``none`` would accept unsigned tokens; the rest cannot work with HMAC."""
    with pytest.raises(ValidationError):
        Settings(JWT_ALGORITHM=algorithm)


@pytest.mark.parametrize("algorithm", sorted(JWT_ALGORITHMS_ALLOWED))
def test_allowed_algorithms_are_accepted_and_normalised(algorithm):
    assert Settings(JWT_ALGORITHM=algorithm.lower()).JWT_ALGORITHM == algorithm


def _other_allowed_algorithm() -> str:
    return "HS512" if settings.JWT_ALGORITHM != "HS512" else "HS256"


def test_decode_token_rejects_a_token_signed_with_another_algorithm():
    token = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "type": "access",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        },
        settings.JWT_SECRET_KEY,
        algorithm=_other_allowed_algorithm(),
    )
    assert decode_token(token) == {}


def _unsigned_token() -> str:
    def part(payload: dict) -> str:
        raw = json.dumps(payload, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    header = part({"alg": "none", "typ": "JWT"})
    body = part(
        {
            "sub": str(uuid.uuid4()),
            "type": "access",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        }
    )
    return f"{header}.{body}."


def test_decode_token_rejects_unsigned_alg_none_token():
    assert decode_token(_unsigned_token()) == {}


def test_decode_token_requires_an_expiry():
    token = jwt.encode(
        {"sub": str(uuid.uuid4()), "type": "access"},
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    assert decode_token(token) == {}


def test_decode_token_rejects_expired_and_malformed_tokens():
    expired = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "type": "access",
            "exp": datetime.now(timezone.utc) - timedelta(minutes=1),
        },
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    assert decode_token(expired) == {}
    for malformed in ("", "not-a-token", "a.b.c", "...."):
        assert decode_token(malformed) == {}


def test_tokens_carry_the_expected_claims():
    user_id = str(uuid.uuid4())

    access, expires_in = create_access_token({"sub": user_id, "role": "admin"})
    access_payload = decode_token(access)
    assert access_payload["type"] == "access"
    assert access_payload["sub"] == user_id
    assert access_payload["jti"]
    assert expires_in > 0

    refresh, refresh_expires, jti, family_id = create_refresh_token(
        {"sub": user_id, "role": "admin"}
    )
    refresh_payload = decode_token(refresh)
    assert refresh_payload["type"] == "refresh"
    assert refresh_payload["jti"] == jti
    assert refresh_payload["family_id"] == family_id
    assert refresh_expires > expires_in
