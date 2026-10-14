"""`rewrap` must cover every column the encryption key protects.

The documented rotation is: put the new key first, `rewrap`, confirm with
`status`, then drop the previous key. Its weak point is the *set* of columns the
script walks: a stored ciphertext the script does not know about is not
re-encrypted, `status` therefore reports the rotation as finished, and the key it
still needs is deleted. A user's `totp_secret` is exactly that kind of value —
`app/api/v1/routers/auth.py` writes it with the same `ENCRYPTION_KEY` the settings
secrets use — so these tests treat the second factor as one of the columns that
must be rotated, not as a special case.

The settings and source-account halves of `rewrap_stored` are covered where they
belong: `test_key_rotation.py` for the crypto contract and
`test_source_account_api_keys.py` for a provider key end to end.
"""

from __future__ import annotations

import uuid

import pytest
from cryptography.fernet import Fernet, InvalidToken

from app.core import crypto
from app.core.config import settings
from app.core.crypto import encrypt_value, key_index_for
from app.models.user import User, UserRole
from scripts.rotate_keys import rewrap_stored, stored_secrets, summarize_secrets

OLD_KEY = Fernet.generate_key().decode("ascii")
NEW_KEY = Fernet.generate_key().decode("ascii")

SECOND_FACTOR = "JBSWY3DPEHPK3PXP"


@pytest.fixture(autouse=True)
def _rebuild_cipher():
    """The cipher is cached per key set; every test here changes that set."""
    crypto.reset_cache()
    yield
    crypto.reset_cache()


@pytest.fixture
def on_the_old_key(monkeypatch):
    """The state an installation is in before a rotation: one key, key [0]."""
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", OLD_KEY)
    monkeypatch.setattr(settings, "ENCRYPTION_PREVIOUS_KEYS", "")
    crypto.reset_cache()


@pytest.fixture
def rotated(monkeypatch):
    """The state after the operator installed the new key and kept the old one."""
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", NEW_KEY)
    monkeypatch.setattr(settings, "ENCRYPTION_PREVIOUS_KEYS", OLD_KEY)
    crypto.reset_cache()


def _written_before_the_rotation(value: str) -> str:
    """The ciphertext an installation holds *before* it installs the new key.

    `encrypt_value` writes with the newest configured key, so calling it after the
    `rotated` fixture is in force produces a value on key [0] and the rotation
    would have nothing to move. What these tests are about is the value the old
    key wrote, which is the key the fixture leaves as key [1].
    """
    return Fernet(OLD_KEY.encode("ascii")).encrypt(value.encode("utf-8")).decode("utf-8")


async def _user(db_session, email: str, secret: str | None) -> User:
    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash="not-used-by-this-test",
        role=UserRole.viewer,
        is_active=True,
        totp_secret=secret,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


async def test_stored_secrets_collects_each_users_second_factor(
    db_session, on_the_old_key
):
    await _user(db_session, "enrolled@example.com", encrypt_value(SECOND_FACTOR))
    await _user(db_session, "no-factor@example.com", None)

    labels = [item.label for item in await stored_secrets(db_session)]

    assert labels == ["users.totp_secret (enrolled@example.com)"]


async def test_rewrap_moves_a_second_factor_to_the_newest_key(
    db_session, on_the_old_key, rotated
):
    user = await _user(
        db_session, "enrolled@example.com", _written_before_the_rotation(SECOND_FACTOR)
    )
    assert key_index_for(user.totp_secret) == 1

    changed, failures = await rewrap_stored(db_session)

    assert failures == []
    assert changed >= 1
    assert key_index_for(user.totp_secret) == 0
    assert crypto.decrypt_value(user.totp_secret) == SECOND_FACTOR
    # The point of the rotation: the key that leaked can no longer read it.
    with pytest.raises(InvalidToken):
        Fernet(OLD_KEY.encode()).decrypt(user.totp_secret.encode())


async def test_an_empty_second_factor_is_left_alone(db_session, on_the_old_key, rotated):
    user = await _user(db_session, "no-factor@example.com", None)

    changed, failures = await rewrap_stored(db_session)

    assert (changed, failures) == (0, [])
    assert user.totp_secret is None


async def test_a_second_rewrap_is_a_no_op(db_session, on_the_old_key, rotated):
    """`rewrap` runs twice in the documented procedure; the second run is safe."""
    user = await _user(
        db_session, "enrolled@example.com", _written_before_the_rotation(SECOND_FACTOR)
    )
    assert (await rewrap_stored(db_session))[0] >= 1
    before = user.totp_secret

    changed, failures = await rewrap_stored(db_session)

    assert (changed, failures) == (0, [])
    assert user.totp_secret == before


async def test_an_unreadable_second_factor_is_reported_not_dropped(
    db_session, on_the_old_key, rotated
):
    """A value no configured key can read must abort the run, not be rewritten."""
    stranger = Fernet(Fernet.generate_key()).encrypt(b"written-elsewhere").decode()
    user = await _user(db_session, "enrolled@example.com", stranger)

    changed, failures = await rewrap_stored(db_session)

    assert changed == 0
    assert failures == ["users.totp_secret (enrolled@example.com)"]
    assert user.totp_secret == stranger


async def test_status_attributes_each_second_factor_to_its_key(
    db_session, on_the_old_key, rotated
):
    """What `status` prints comes from `summarize_secrets`, per configured key."""
    await _user(
        db_session, "enrolled@example.com", _written_before_the_rotation(SECOND_FACTOR)
    )

    found = await stored_secrets(db_session)
    per_key, unreadable = summarize_secrets(found)

    assert unreadable == []
    assert per_key == {0: 0, 1: 1}
