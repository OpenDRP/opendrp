"""Rotation must be possible without losing what the old key wrote.

Every test here is about a property that decides whether an operator can rotate a
leaked credential at all: if replacing `ENCRYPTION_KEY` made the stored
`system_settings` secrets unreadable, the rotation would only ever happen during
an incident, and if replacing `JWT_SECRET_KEY` signed everyone out — refresh
tokens included — the same is true of the signing key. Both are therefore tested
as behaviour, not documented as intent.
"""

from __future__ import annotations

import jwt
import pytest
from cryptography.fernet import Fernet, InvalidToken

from app.core import crypto
from app.core.config import Settings, settings
from app.core.security import create_access_token, decode_token

OLD_KEY = Fernet.generate_key().decode("ascii")
NEW_KEY = Fernet.generate_key().decode("ascii")
OLD_SECRET = "old-jwt-secret-" + "a" * 40
NEW_SECRET = "new-jwt-secret-" + "b" * 40


@pytest.fixture(autouse=True)
def _rebuild_cipher():
    """The cipher is cached per key set; each test changes that set."""
    crypto.reset_cache()
    yield
    crypto.reset_cache()


class TestEncryptionKeyRotation:
    def test_a_value_written_with_the_old_key_still_decrypts(self, monkeypatch):
        monkeypatch.setattr(settings, "ENCRYPTION_KEY", OLD_KEY)
        monkeypatch.setattr(settings, "ENCRYPTION_PREVIOUS_KEYS", "")
        ciphertext = crypto.encrypt_value("smtp-app-password")
        assert crypto.key_index_for(ciphertext) == 0

        monkeypatch.setattr(settings, "ENCRYPTION_KEY", NEW_KEY)
        monkeypatch.setattr(settings, "ENCRYPTION_PREVIOUS_KEYS", OLD_KEY)

        assert crypto.decrypt_value(ciphertext) == "smtp-app-password"
        assert crypto.key_index_for(ciphertext) == 1

    def test_new_values_use_the_newest_key_while_the_old_one_is_still_listed(
        self, monkeypatch
    ):
        monkeypatch.setattr(settings, "ENCRYPTION_KEY", NEW_KEY)
        monkeypatch.setattr(settings, "ENCRYPTION_PREVIOUS_KEYS", OLD_KEY)
        ciphertext = crypto.encrypt_value("fresh-secret")
        assert crypto.key_index_for(ciphertext) == 0
        # The old key must not be able to read it, or "rotate" would mean
        # "keep writing with the key that leaked".
        with pytest.raises(InvalidToken):
            Fernet(OLD_KEY.encode()).decrypt(ciphertext.encode())

    def test_rewrap_moves_a_value_to_the_newest_key_without_changing_it(self, monkeypatch):
        monkeypatch.setattr(settings, "ENCRYPTION_KEY", OLD_KEY)
        monkeypatch.setattr(settings, "ENCRYPTION_PREVIOUS_KEYS", "")
        ciphertext = crypto.encrypt_value("telegram-token")

        monkeypatch.setattr(settings, "ENCRYPTION_KEY", NEW_KEY)
        monkeypatch.setattr(settings, "ENCRYPTION_PREVIOUS_KEYS", OLD_KEY)
        rewrapped = crypto.rewrap_value(ciphertext)

        assert rewrapped != ciphertext
        assert crypto.decrypt_value(rewrapped) == "telegram-token"
        assert crypto.key_index_for(rewrapped) == 0

    def test_after_rewrap_the_old_key_can_be_removed(self, monkeypatch):
        monkeypatch.setattr(settings, "ENCRYPTION_KEY", OLD_KEY)
        monkeypatch.setattr(settings, "ENCRYPTION_PREVIOUS_KEYS", "")
        ciphertext = crypto.encrypt_value("alert-recipient")

        monkeypatch.setattr(settings, "ENCRYPTION_KEY", NEW_KEY)
        monkeypatch.setattr(settings, "ENCRYPTION_PREVIOUS_KEYS", OLD_KEY)
        rewrapped = crypto.rewrap_value(ciphertext)

        # This is the state `scripts/rotate_keys status` reports as safe to act on.
        monkeypatch.setattr(settings, "ENCRYPTION_PREVIOUS_KEYS", "")
        assert crypto.decrypt_value(rewrapped) == "alert-recipient"

    def test_rewrap_refuses_a_value_no_configured_key_can_read(self, monkeypatch):
        stranger = Fernet(Fernet.generate_key()).encrypt(b"written-elsewhere").decode()

        monkeypatch.setattr(settings, "ENCRYPTION_KEY", NEW_KEY)
        monkeypatch.setattr(settings, "ENCRYPTION_PREVIOUS_KEYS", "")
        monkeypatch.setattr(settings, "APP_ENV", "production")

        # Raising is the point: the next step of the documented procedure deletes
        # a key, and silently skipping the value would destroy it.
        with pytest.raises(RuntimeError):
            crypto.rewrap_value(stranger)

    def test_an_unreadable_value_is_attributed_to_no_key(self, monkeypatch):
        stranger = Fernet(Fernet.generate_key()).encrypt(b"x").decode()
        monkeypatch.setattr(settings, "ENCRYPTION_KEY", NEW_KEY)
        monkeypatch.setattr(settings, "ENCRYPTION_PREVIOUS_KEYS", OLD_KEY)
        assert crypto.key_index_for(stranger) is None

    def test_a_malformed_previous_key_is_reported_not_worked_around(self, monkeypatch):
        monkeypatch.setattr(settings, "ENCRYPTION_KEY", NEW_KEY)
        monkeypatch.setattr(settings, "ENCRYPTION_PREVIOUS_KEYS", "not-a-fernet-key")
        crypto.reset_cache()
        with pytest.raises(RuntimeError):
            crypto.encrypt_value("anything")

    def test_previous_keys_accepts_a_comma_separated_list(self, monkeypatch):
        monkeypatch.setattr(settings, "ENCRYPTION_PREVIOUS_KEYS", f" {OLD_KEY} , , ")
        assert settings.encryption_previous_keys() == [OLD_KEY]


class TestJwtSecretRotation:
    def test_a_token_signed_before_rotation_is_still_accepted(self, monkeypatch):
        monkeypatch.setattr(settings, "JWT_SECRET_KEY", OLD_SECRET)
        monkeypatch.setattr(settings, "JWT_PREVIOUS_SECRET_KEYS", "")
        token, _ = create_access_token({"sub": "user-1", "role": "admin"})

        monkeypatch.setattr(settings, "JWT_SECRET_KEY", NEW_SECRET)
        monkeypatch.setattr(settings, "JWT_PREVIOUS_SECRET_KEYS", OLD_SECRET)
        payload = decode_token(token)
        assert payload["sub"] == "user-1"

    def test_removing_the_previous_secret_withdraws_the_old_tokens(self, monkeypatch):
        monkeypatch.setattr(settings, "JWT_SECRET_KEY", OLD_SECRET)
        monkeypatch.setattr(settings, "JWT_PREVIOUS_SECRET_KEYS", "")
        token, _ = create_access_token({"sub": "user-1", "role": "admin"})

        monkeypatch.setattr(settings, "JWT_SECRET_KEY", NEW_SECRET)
        monkeypatch.setattr(settings, "JWT_PREVIOUS_SECRET_KEYS", OLD_SECRET)
        assert decode_token(token) != {}

        monkeypatch.setattr(settings, "JWT_PREVIOUS_SECRET_KEYS", "")
        assert decode_token(token) == {}

    def test_new_tokens_are_signed_with_the_current_secret(self, monkeypatch):
        monkeypatch.setattr(settings, "JWT_SECRET_KEY", NEW_SECRET)
        monkeypatch.setattr(settings, "JWT_PREVIOUS_SECRET_KEYS", OLD_SECRET)
        token, _ = create_access_token({"sub": "user-2", "role": "viewer"})

        decoded = jwt.decode(
            token,
            NEW_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["exp"]},
        )
        assert decoded["sub"] == "user-2"

    def test_blank_entries_are_ignored(self, monkeypatch):
        monkeypatch.setattr(settings, "JWT_PREVIOUS_SECRET_KEYS", f" {OLD_SECRET} , ,")
        assert settings.jwt_verification_keys() == [settings.JWT_SECRET_KEY, OLD_SECRET]

    def test_an_algorithm_outside_the_allowlist_is_still_refused(self, monkeypatch):
        """The rotation path must not widen the accepted algorithms."""
        monkeypatch.setattr(settings, "JWT_SECRET_KEY", OLD_SECRET)
        monkeypatch.setattr(settings, "JWT_PREVIOUS_SECRET_KEYS", "")
        unsigned = jwt.encode({"sub": "x", "type": "access"}, key="", algorithm="none")
        monkeypatch.setattr(settings, "JWT_SECRET_KEY", NEW_SECRET)
        monkeypatch.setattr(settings, "JWT_PREVIOUS_SECRET_KEYS", OLD_SECRET)
        assert decode_token(unsigned) == {}


class TestProductionValidationOfPreviousKeys:
    def _production(self, **overrides) -> Settings:
        values = {
            "APP_ENV": "production",
            "OPENDRP_VERSION": "0.1.1",
            "JWT_SECRET_KEY": NEW_SECRET,
            "ENCRYPTION_KEY": NEW_KEY,
            "AUTH_COOKIE_SECURE": True,
            "DATABASE_URL": "postgresql://opendrp:str0ng-db-password@db:5432/opendrp",
            "AUDIT_CHAIN_KEYS": "chain-key-for-tests-only-" * 3,
        }
        values.update(overrides)
        return Settings(**values)  # type: ignore[call-arg]

    def test_a_short_previous_secret_is_rejected(self):
        with pytest.raises(ValueError):
            self._production(JWT_PREVIOUS_SECRET_KEYS="short")

    def test_a_placeholder_previous_secret_is_rejected(self):
        with pytest.raises(ValueError):
            self._production(JWT_PREVIOUS_SECRET_KEYS="REPLACE_WITH_AT_LEAST_32_RANDOM_CHARACTERS")

    def test_a_previous_secret_of_the_required_length_is_accepted(self):
        config = self._production(JWT_PREVIOUS_SECRET_KEYS=OLD_SECRET)
        assert config.jwt_verification_keys() == [NEW_SECRET, OLD_SECRET]


def test_the_documented_rotation_sequence_round_trips(monkeypatch):
    """The sequence in docs/upgrading.md, as one test.

    Written as the operator's steps rather than as unit behaviour, because the
    procedure is the artifact that has to be correct: generate, list the old key,
    rewrap, verify, then drop it.
    """
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", OLD_KEY)
    monkeypatch.setattr(settings, "ENCRYPTION_PREVIOUS_KEYS", "")
    ciphertext = crypto.encrypt_value("whois-abuse-contact")

    # 1. New key first, old key listed as a previous key; restart the backend
    #    (the cache reset stands in for the new process).
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", NEW_KEY)
    monkeypatch.setattr(settings, "ENCRYPTION_PREVIOUS_KEYS", OLD_KEY)
    crypto.reset_cache()
    assert crypto.decrypt_value(ciphertext) == "whois-abuse-contact"

    # 2. `rotate_keys rewrap`, then `rotate_keys status`: nothing depends on key 1.
    rewrapped = crypto.rewrap_value(ciphertext)
    assert crypto.key_index_for(rewrapped) == 0

    # 3. Only now is the previous key removable.
    monkeypatch.setattr(settings, "ENCRYPTION_PREVIOUS_KEYS", "")
    crypto.reset_cache()
    assert crypto.decrypt_value(rewrapped) == "whois-abuse-contact"
