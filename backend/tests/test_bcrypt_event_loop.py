"""Password hashing must not stop the process that is serving everybody else.

The audit measured 232 ms per bcrypt hash and 232 ms per verification on this
platform's hardware, and the handlers called both synchronously from ``async``
functions — so a sign-in held the event loop for as long as bcrypt ran, and five
of them held it for 1.16 s (measured before the change; the same measurement after
is in ``docs/production-readiness.md``). bcrypt releases the GIL, so moving it to
a worker thread costs no throughput.

Two properties are pinned here:

* the wrapper really does the work off the loop — asserted by making the work take
  half a second and requiring a parallel request to be answered meanwhile, which
  is the behavioural form of the audit's "p95 ``/ready``" criterion;
* the synchronous function is still what the CLI uses, so the change is about
  *where* the call runs, not about the hash it produces.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from app.core import security


@pytest.mark.asyncio
async def test_a_slow_hash_does_not_block_a_parallel_request(client, monkeypatch):
    """A request must be answered while a password is being hashed."""

    def slow_hash(password: str) -> str:
        time.sleep(0.5)
        return security.DUMMY_PASSWORD_HASH

    monkeypatch.setattr(security, "hash_password", slow_hash)

    task = asyncio.create_task(security.hash_password_async("any-password"))
    await asyncio.sleep(0.05)  # give the worker thread the loop's slot

    started = time.monotonic()
    response = await client.get("/api/v1/health")
    elapsed = time.monotonic() - started
    await task

    assert response.status_code == 200
    assert elapsed < 0.2, (
        "the health probe waited for the hash: the loop was blocked for "
        f"{elapsed:.2f}s by work that belongs on a thread"
    )


@pytest.mark.asyncio
async def test_the_async_wrapper_returns_the_same_hash():
    hashed = await security.hash_password_async("CorrectHorse123")
    assert hashed.startswith("$2b$")
    assert security.verify_password("CorrectHorse123", hashed)
    assert not security.verify_password("WrongHorse123", hashed)
    assert await security.verify_password_async("CorrectHorse123", hashed)


@pytest.mark.asyncio
async def test_a_malformed_stored_hash_still_denies_without_raising():
    assert await security.verify_password_async("anything", "not-a-bcrypt-hash") is False
