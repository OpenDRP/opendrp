"""Resumable bounded full audit verification; no write lock during hashing."""
from datetime import datetime, timezone

from sqlalchemy import update

from app.core.audit_chain import GENESIS_PREV_HASH, _acquire_write_lock, chain_state, verify
from app.models.audit import AUDIT_CHAIN_STATE_ID, AuditChain


async def verify_full_chunk(db, *, max_rows=10000):
    await _acquire_write_lock(db)
    state = await chain_state(db)
    if not state.full_verify_upper_hash:
        state.full_verify_upper_seq = state.committed_seq
        state.full_verify_upper_hash = state.committed_tip_hash or GENESIS_PREV_HASH
        state.full_verify_cursor = state.retired_through_seq
        state.full_verify_cursor_hash = state.retired_tip_hash or GENESIS_PREV_HASH
    upper = (state.full_verify_upper_seq, state.full_verify_upper_hash)
    cursor, anchor = state.full_verify_cursor, state.full_verify_cursor_hash
    await db.commit()
    result = await verify(db, since=cursor, upper=upper, anchor_hash=anchor, max_rows=max_rows, persist=False)
    await db.commit()
    values = {}
    if result.ok:
        values = {"full_verify_cursor": result.through_seq, "full_verify_cursor_hash": result.tip_hash or anchor}
        if not result.truncated:
            values.update(full_verify_upper_hash=None, last_full_verified_at=datetime.now(timezone.utc), last_failure_seq=None, last_failure_reason=None)
    else:
        values = {"last_failure_seq": result.first_broken_seq, "last_failure_reason": result.reason}
    # Multiple verifiers may read the same chunk; only its unchanged owner cursor
    # can advance it. A failed chunk remains at the boundary for investigation.
    outcome = await db.execute(update(AuditChain).where(AuditChain.id == AUDIT_CHAIN_STATE_ID, AuditChain.full_verify_upper_seq == upper[0], AuditChain.full_verify_upper_hash == upper[1], AuditChain.full_verify_cursor == cursor).values(**values))
    await db.commit()
    if outcome.rowcount != 1:
        raise RuntimeError("Full verification cursor changed concurrently; retry")
    return result
