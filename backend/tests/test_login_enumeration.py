"""The login endpoint must not reveal whether an account exists.

Two channels used to leak that fact:

* an unknown address skipped the bcrypt comparison, so it answered markedly
  faster than a wrong password;
* a locked or disabled account got its own status code (``423``/``403``-style
  answer) instead of the generic ``401``.

Both are closed here, and the tests pin the *indistinguishability* rather than
the individual status codes, so any future change that re-introduces a
distinguishing signal fails.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

LOGIN = "/api/v1/auth/login"
WRONG_PASSWORD = "WrongPass9!"
UNKNOWN_EMAIL = "ghost@example.com"


@pytest.mark.asyncio
async def test_unknown_disabled_and_wrong_password_answers_are_identical(
    client, test_admin, test_inactive_admin
):
    unknown = await client.post(
        LOGIN, json={"email": UNKNOWN_EMAIL, "password": WRONG_PASSWORD}
    )
    wrong = await client.post(
        LOGIN, json={"email": test_admin.email, "password": WRONG_PASSWORD}
    )
    disabled = await client.post(
        LOGIN,
        json={"email": test_inactive_admin.email, "password": "TestPass123!"},
    )

    assert unknown.status_code == wrong.status_code == disabled.status_code == 401
    assert unknown.json() == wrong.json() == disabled.json()

    # No cookie, no Retry-After, nothing that separates the three cases.
    for response in (unknown, wrong, disabled):
        assert "set-cookie" not in {k.lower() for k in response.headers}
        assert "retry-after" not in {k.lower() for k in response.headers}


@pytest.mark.asyncio
async def test_unknown_account_still_pays_for_a_password_hash(client):
    """The dummy comparison is what keeps the timing channel closed.

    The comparison now runs on a worker thread (``verify_password_async``), so the
    spy goes on ``app.core.security.verify_password`` — the function the thread
    actually calls — rather than on the router's imported name.
    """
    from app.core import security as security_module

    seen: list[str] = []
    original = security_module.verify_password

    def spy(plain: str, hashed: str) -> bool:
        seen.append(hashed)
        return original(plain, hashed)

    with patch.object(security_module, "verify_password", side_effect=spy):
        response = await client.post(
            LOGIN, json={"email": UNKNOWN_EMAIL, "password": WRONG_PASSWORD}
        )

    assert response.status_code == 401
    assert seen, "an unknown address must still run a bcrypt verification"
    assert seen[0] == security_module.DUMMY_PASSWORD_HASH


@pytest.mark.asyncio
async def test_the_dummy_hash_is_built_once_at_import(client):
    """A real bcrypt hash, built before any request rather than during one.

    It used to be memoised on first use inside the handler: a ~230 ms bcrypt call
    on the event loop, in the one place the code was trying not to be observable.
    Building it during module import is what the constant proves; the patch below
    fails the login if anything tries to build one again.
    """
    from app.core import security as security_module

    dummy = security_module.DUMMY_PASSWORD_HASH
    assert dummy.startswith("$2b$")

    with patch.object(
        security_module, "hash_password", side_effect=AssertionError("built during a request")
    ):
        response = await client.post(
            LOGIN, json={"email": UNKNOWN_EMAIL, "password": WRONG_PASSWORD}
        )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_locked_account_is_indistinguishable_from_an_unknown_one(
    client, test_viewer
):
    for _ in range(8):
        await client.post(
            LOGIN, json={"email": test_viewer.email, "password": WRONG_PASSWORD}
        )

    locked = await client.post(
        LOGIN, json={"email": test_viewer.email, "password": "TestPass123!"}
    )
    unknown = await client.post(
        LOGIN, json={"email": UNKNOWN_EMAIL, "password": WRONG_PASSWORD}
    )

    assert locked.status_code == unknown.status_code == 401
    assert locked.json() == unknown.json()
    assert "retry-after" not in {k.lower() for k in locked.headers}
