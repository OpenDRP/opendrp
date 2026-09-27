def test_imports():
    from app.main import app
    from app.core.security import hash_password, verify_password
    from app.core.crypto import mask_value

    assert app is not None
    assert (
        mask_value("secret123", keep_first=2, keep_last=2).count("*") >= 4
    )
    hp = hash_password("test")
    assert verify_password("test", hp) is True
    assert verify_password("wrong", hp) is False
