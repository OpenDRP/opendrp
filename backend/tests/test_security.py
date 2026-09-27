from datetime import timedelta
from uuid import uuid4


from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)


class TestPasswordHashing:
    def test_hash_is_not_plaintext(self):
        pw = "MyStrongPassword123!"
        h = hash_password(pw)
        assert pw not in h
        assert h.startswith(("$2b$", "$2a$", "$2y$"))

    def test_verify_correct_password(self):
        pw = "HelloWorld42!"
        assert verify_password(pw, hash_password(pw)) is True

    def test_verify_wrong_password_returns_false_not_raises(self):
        h = hash_password("correct-horse")
        assert verify_password("wrong-battery", h) is False

    def test_unique_hashes_same_password(self):
        pw = "same-pw"
        h1 = hash_password(pw)
        h2 = hash_password(pw)
        assert h1 != h2
        assert verify_password(pw, h1) is True
        assert verify_password(pw, h2) is True

    def test_long_password_over_72_bytes_supported(self):
        long_pw = "Start-C0mpl3x-" + "A" * 80 + "-EndPassw0rd!"
        assert len(long_pw) > 72
        h = hash_password(long_pw)
        assert verify_password(long_pw, h) is True
        wrong = "WRONG-C0mpl3x-" + "A" * 80 + "-EndPassw0rd!"
        assert wrong != long_pw
        assert verify_password(wrong, h) is False


class TestJWT:
    def test_access_token_has_sub_and_role(self):
        user_id = str(uuid4())
        tok, exp_in = create_access_token({"sub": user_id, "role": "admin"})
        assert isinstance(tok, str) and tok
        assert isinstance(exp_in, int) and 50 < exp_in < 3600 * 24
        payload = decode_token(tok)
        assert payload["sub"] == user_id
        assert payload["role"] == "admin"
        assert payload["type"] == "access"

    def test_refresh_token_has_type_refresh(self):
        tok, exp_in, _jti, _fid = create_refresh_token({"sub": str(uuid4())})
        payload = decode_token(tok)
        assert payload["type"] == "refresh"
        assert payload["jti"]
        assert payload["family_id"]
        assert exp_in > 3600 * 24 * 2

    def test_expired_token_returns_empty_payload(self):
        tok, _ = create_access_token(
            {"sub": str(uuid4())}, expires_delta=timedelta(seconds=-2)
        )
        assert decode_token(tok) == {}

    def test_invalid_token_returns_empty_payload(self):
        assert decode_token("not-a-real-jwt.sig.nature") == {}
        assert decode_token("") == {}

    def test_custom_expires_delta(self):
        short, exp = create_access_token(
            {"sub": str(uuid4())}, expires_delta=timedelta(minutes=2)
        )
        assert 60 < exp < 240
        payload = decode_token(short)
        assert "exp" in payload
