import pytest

from app.core.crypto import decrypt_value, encrypt_value, mask_value


class TestEncryptDecryptRoundtrip:
    def test_none_returns_none(self):
        assert encrypt_value(None) is None
        assert decrypt_value(None) is None

    def test_empty_string_returns_itself(self):
        assert encrypt_value("") == ""
        assert decrypt_value("") == ""

    def test_short_secret_roundtrip(self):
        plain = "hello"
        enc = encrypt_value(plain)
        assert enc != plain
        assert "gAAAAA" in enc or len(enc) > 30
        assert decrypt_value(enc) == plain

    def test_long_api_key_roundtrip(self):
        plain = "SK-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ==extra"
        enc = encrypt_value(plain)
        assert decrypt_value(enc) == plain

    def test_multiple_values_stored_separately(self):
        vals = ["shodan-api-key-1", "hibp-api-key-2", "telegram:123456:token"]
        for v in vals:
            enc = encrypt_value(v)
            assert decrypt_value(enc) == v

    def test_decrypt_bad_token_raises(self):
        """A value that is not a token is an error, not a value.

        The development fallback that returned the input would hand back
        ciphertext (or an operator's typo) as if it were the decrypted secret.
        Returning the wrong value is worse than failing: a wrong SMTP password is
        a silent outage, while an exception names the field that is broken.
        """
        with pytest.raises(RuntimeError, match="Unable to decrypt"):
            decrypt_value("this-is-not-a-valid-fernet-token!!!")

    def test_decrypt_random_base64_raises(self):
        import base64

        junk = base64.urlsafe_b64encode(b"random bytes not a fernet token").decode()
        with pytest.raises(RuntimeError, match="Unable to decrypt"):
            decrypt_value(junk)

    def test_decrypt_absent_values_stay_absent(self):
        """``None``/``""`` mean "not configured" and must not raise."""
        assert decrypt_value(None) is None
        assert decrypt_value("") == ""


class TestAnInvalidKeyIsRefusedEverywhere:
    def test_a_value_that_is_not_a_fernet_key_is_a_startup_error(self, monkeypatch):
        """No environment derives a key from a value that is not one.

        Deriving one was how a development database written with a placeholder
        kept opening. It also hid the failure it should have reported: the derived
        key cannot read what the real key wrote, and it is not the key the operator
        believes protects the stored secrets. A passphrase typed into
        `ENCRYPTION_KEY` is now named as the broken setting instead.
        """
        from app.core import crypto
        from app.core.config import settings

        monkeypatch.setattr(settings, "APP_ENV", "development")
        monkeypatch.setattr(settings, "ENCRYPTION_KEY", "not-a-fernet-key")
        monkeypatch.setattr(settings, "ENCRYPTION_PREVIOUS_KEYS", "")
        crypto.reset_cache()
        try:
            with pytest.raises(RuntimeError, match="ENCRYPTION_KEY is not a valid Fernet key"):
                crypto.encrypt_value("anything")
        finally:
            crypto.reset_cache()


class TestMaskValue:
    def test_default_two_sides(self):
        masked = mask_value("secret123")
        assert masked.startswith("se")
        assert masked.endswith("23")
        assert "*" in masked
        assert masked != "secret123"

    def test_short_string_all_masked(self):
        assert mask_value("abc", keep_first=2, keep_last=2) == "***"
        assert mask_value("12", keep_first=2, keep_last=2) == "**"

    def test_empty_or_none_returns_same(self):
        assert mask_value("") == ""

    def test_custom_mask_char(self):
        assert mask_value("helloworld", keep_first=1, keep_last=1, mask_char="#").count("#") == 8

    def test_shodan_key_masked_keeps_last4(self):
        key = "ShOdan_API_KeY_12345"
        m = mask_value(key, keep_first=4, keep_last=5)
        assert m.startswith("ShOd")
        assert m.endswith("12345")
        assert len(m) == len(key)
