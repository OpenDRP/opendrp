"""The audit hash chain: what makes an edit to the audit trail visible.

An audit trail that anyone with database access can edit is a record of what
*someone chose to leave in it*. This module turns it into a record a reader can
check: every entry carries an HMAC over its own five fields and the previous
entry's hash, at a monotonic position, keyed from the environment rather than
from the database the chain protects.

What it detects
---------------
* **An edited row** — the hash no longer recomputes.
* **A deleted row, or a sequence of them** — the positions are no longer
  contiguous. Retention *legitimately* deletes a prefix by age, so
  ``drp_audit_chain.retired_through_seq`` records how far that has happened: a gap
  at or below that watermark is housekeeping, a gap above it is a finding.
  This is why retirement is bookkeeping rather than inference — the sweep deletes
  by *timestamp* while the chain orders by *position*, and a task that adopts its
  producer's timestamp can place an older timestamp at a higher position.
* **An inserted row** — a new row needs the previous hash to produce a valid one,
  and the key to produce it at all.
* **A row with no hash at all** — ``drp_audit_logs.entry_hash`` is NOT NULL and
  the only writer computes it in the inserting transaction, so an unsigned row
  is not history that predates the chain: it is a row someone put there another
  way.

What it does not detect, stated plainly
---------------------------------------
An attacker who can rewrite the database **and** the chain-state row can delete
history and recompute nothing else, and verification of what remains will pass —
as long as they also move ``retired_through_seq``, which is itself an edit that
requires the state row. What makes that detectable is the second copy: the audit
event is also written to stdout, with the same two hashes inside ``details``, and
that stream is the SIEM's. A database whose chain disagrees with the SIEM's copy
is the finding, and neither copy alone can be trusted to say so. The chain is
what lets the two be compared without guessing.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.audit import AUDIT_CHAIN_STATE_ID, AuditChain, AuditLog

#: The hash the very first entry links to. A constant rather than ``NULL`` so that
#: "the chain starts here" is a value a verifier can compare against, and so that
#: a NULL ``prev_hash`` unambiguously means "a row the writer did not sign".
GENESIS_PREV_HASH = "0" * 64

#: Advisory-lock key serialising the write side. Spelled as ASCII ("OpenDRP2") so
#: that a lock seen in ``pg_locks`` during an incident is recognisable. Distinct
#: from the migration wrapper's key, which must not serialise against audit writes.
CHAIN_LOCK_KEY = 0x4F70656E44525032

#: Keys the chain itself puts inside ``details``. Excluded when recomputing a
#: row's hash — a hash cannot cover itself. They are reserved against caller use
#: by the writer overwriting them after it has hashed (app/core/audit.py), which
#: is why a caller that passes one of these names cannot influence the hash and
#: cannot plant a value the verifier would read.
#:
#: ``audit_key_id`` is here so that an *exported* stream, which has no ``key_id``
#: column to read, can still name the key that signed a line — without it a
#: rotated installation could not verify its own SIEM copy.
RESERVED_DETAIL_KEYS = ("audit_hash", "audit_prev_hash", "audit_key_id")

#: Bounds one verification pass, so a corrupt or enormous table cannot make the
#: nightly task run for hours. A truncated pass still advances
#: ``last_verified_seq``: verification is incremental, and the next run continues.
DEFAULT_MAX_ROWS = 250_000

REASON_GAP = "gap"
REASON_BROKEN_LINK = "broken_link"
REASON_HASH_MISMATCH = "hash_mismatch"
REASON_KEY_ID_MISMATCH = "key_id_mismatch"
REASON_UNSIGNED = "unsigned_row"
REASON_UNKNOWN_KEY = "unknown_key_id"


def chain_keys() -> tuple[str, ...]:
    """Signing keys, newest first: the first signs, the rest only verify."""
    return tuple(settings.audit_chain_keys)


def key_id_for(key: str) -> int:
    """A stable identifier for one signing key.

    Positional ids would be easier to read in a query result and are wrong here.
    The key list is newest-first, so the key at position 0 changes the moment a
    new one is added — every row signed before that rotation records an id that
    now points at a different key, and a verification pass would report the whole
    history as tampered. That is a false alarm with the worst possible shape: an
    operator reading ``hash_mismatch`` after following the documented rotation.

    So the id names the key rather than its place: the low 15 bits of the key's
    SHA-256, which fits the ``SmallInteger`` column. A collision is possible in
    principle and handled in practice — verification tries every configured key
    with a matching fingerprint — and for a single deployment rotating a handful
    of keys it is not a practical concern.
    """
    digest = hashlib.sha256(key.encode("utf-8")).digest()
    return int.from_bytes(digest[:2], "big") & 0x7FFF


def chain_key_pairs() -> tuple[tuple[int, str], ...]:
    """Configured keys with their fingerprints, newest first."""
    return tuple((key_id_for(key), key) for key in chain_keys())


def canonical_timestamp(value: datetime) -> str:
    """A dialect-independent rendering of a timestamp for hashing.

    Deliberately not ``isoformat()``. SQLite drops the UTC offset of a
    ``DateTime(timezone=True)`` column while PostgreSQL keeps it, so the same row
    would hash differently depending on which database read it — and the chain
    would appear broken in exactly the test environment whose job is to catch
    that. A fixed format, normalised to UTC, hashes the same everywhere.
    """
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")


def payload_details(details: dict | None) -> dict:
    """The caller's details, without the reserved keys the chain adds itself."""
    return {
        key: value
        for key, value in (details or {}).items()
        if key not in RESERVED_DETAIL_KEYS
    }


def entry_payload(
    *,
    timestamp: datetime | str,
    user_id: uuid.UUID | str | None,
    action: str,
    ip_address: str,
    details: dict | None,
) -> str:
    """The exact bytes a row's hash covers.

    Sorted keys and no whitespace: the same logical row must hash identically
    after a JSON round trip through PostgreSQL, SQLite and the SIEM, and any
    variation in key order or spacing would look like tampering.
    """
    timestamp_text = (
        timestamp if isinstance(timestamp, str) else canonical_timestamp(timestamp)
    )
    material = {
        "timestamp": timestamp_text,
        "user_id": str(user_id) if user_id else None,
        "action": action,
        "ip_address": ip_address,
        "details": payload_details(details),
    }
    return json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_entry_hash(
    key: str, *, payload: str, prev_hash: str, key_id: int
) -> str:
    """HMAC-SHA256 over the payload, the link and the key id.

    The key id is covered so that a row's key cannot be swapped to one whose key
    is easier to obtain without that being visible.
    """
    material = f"{key_id}:{prev_hash}:{payload}".encode("utf-8")
    return hmac.new(key.encode("utf-8"), material, hashlib.sha256).hexdigest()


async def _acquire_write_lock(db: AsyncSession) -> None:
    """Serialise chain appends, so two writers cannot read the same tip.

    Transaction-scoped on purpose: the lock is released by the commit that
    persists the row, so a crashed writer cannot leave the chain wedged. On
    SQLite (the test suite) the whole database is already single-writer, so there
    is nothing to take.
    """
    if _dialect(db) != "postgresql":
        return
    await db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": CHAIN_LOCK_KEY})


def _dialect(db: AsyncSession) -> str:
    try:
        bind = db.get_bind()
    except Exception:  # pragma: no cover - defensive
        bind = None
    dialect = getattr(getattr(bind, "dialect", None), "name", None)
    if dialect:
        return str(dialect)
    return "sqlite"


async def chain_state(db: AsyncSession) -> AuditChain:
    """The singleton chain-state row, created on first use."""
    state = await db.get(AuditChain, AUDIT_CHAIN_STATE_ID)
    if state is not None:
        return state
    state = AuditChain(
        id=AUDIT_CHAIN_STATE_ID,
        retired_through_seq=0,
        last_verified_seq=0,
    )
    db.add(state)
    await db.flush()
    return state


async def next_seq(db: AsyncSession) -> int:
    """The position the next entry takes.

    On PostgreSQL the sequence the migration created, which is what keeps the
    position monotonic without a table scan. On SQLite the maximum, which is safe
    because a single process writes there and the transaction is already open.
    """
    if _dialect(db) == "postgresql":
        value = await db.scalar(text("SELECT nextval('drp_audit_logs_seq_seq')"))
        return int(value or 0)
    current = await db.scalar(select(func.max(AuditLog.seq)))
    return int(current or 0) + 1


async def tip_hash(db: AsyncSession) -> str:
    """The hash the next entry links to.

    The newest row, or the recorded retirement tip when that row has been
    deleted by retention, or genesis when nothing has been written yet.
    """
    newest = await db.scalar(
        select(AuditLog.entry_hash).order_by(AuditLog.seq.desc()).limit(1)
    )
    if newest:
        return str(newest)
    state = await chain_state(db)
    return str(state.retired_tip_hash or GENESIS_PREV_HASH)


@dataclass
class ChainLink:
    """Everything a signed row needs to be written."""

    seq: int
    prev_hash: str
    entry_hash: str
    key_id: int
    keys: tuple[str, ...] = field(default=(), repr=False)


async def prepare_entry(
    db: AsyncSession,
    *,
    timestamp: datetime,
    user_id: uuid.UUID | str | None,
    action: str,
    ip_address: str,
    details: dict | None,
) -> ChainLink:
    """Allocate a position and compute the link for one new audit entry.

    Must be called inside the same transaction as the insert: the lock is
    transaction-scoped, and the tip read here is only valid while it is held.
    """
    await _acquire_write_lock(db)
    keys = chain_keys()
    seq = await next_seq(db)
    prev_hash = await tip_hash(db)
    payload = entry_payload(
        timestamp=timestamp,
        user_id=user_id,
        action=action,
        ip_address=ip_address,
        details=details,
    )
    key_id = key_id_for(keys[0])
    entry_hash = compute_entry_hash(
        keys[0], payload=payload, prev_hash=prev_hash, key_id=key_id
    )
    return ChainLink(
        seq=seq, prev_hash=prev_hash, entry_hash=entry_hash, key_id=key_id, keys=keys
    )


async def retire(
    db: AsyncSession, *, through_seq: int, tip_hash: str | None
) -> None:
    """Record what retention has legitimately deleted.

    Called inside the deleting transaction, so the watermark and the deletion
    cannot disagree: a crash either leaves both or neither. The tip records where
    the surviving history has to resume from: the hash the deleted prefix ended
    on, so the next verification pass measures the remaining rows against it
    instead of against genesis.
    """
    if through_seq <= 0:
        return
    state = await chain_state(db)
    if through_seq > state.retired_through_seq:
        state.retired_through_seq = through_seq
    if tip_hash and tip_hash != state.retired_tip_hash:
        state.retired_tip_hash = tip_hash


@dataclass
class ChainVerification:
    """The outcome of one verification pass."""

    checked: int = 0
    from_seq: int = 0
    through_seq: int = 0
    retired_through_seq: int = 0
    tip_hash: str | None = None
    first_broken_seq: int | None = None
    reason: str | None = None
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.first_broken_seq is None

    def as_details(self) -> dict:
        details: dict[str, object] = {
            "checked": self.checked,
            "from_seq": self.from_seq,
            "through_seq": self.through_seq,
            "retired_through_seq": self.retired_through_seq,
            "truncated": self.truncated,
        }
        if not self.ok:
            details["first_broken_seq"] = self.first_broken_seq
            details["reason"] = self.reason
        return details


async def verify(
    db: AsyncSession,
    *,
    since: int | None = None,
    full: bool = False,
    max_rows: int = DEFAULT_MAX_ROWS,
) -> ChainVerification:
    """Walk the retained chain and report the first entry that does not fit.

    Incremental by default: the pass starts where the previous one finished, so
    the nightly check costs one query over the new entries rather than one over
    the year. ``full=True`` re-derives everything from the beginning, which is
    what an operator runs after a restore.

    Verification never repairs anything. A chain that does not verify is the
    finding; "fixing" it would destroy the only evidence that it was broken.
    """
    state = await chain_state(db)
    from_seq = 0 if full else (state.last_verified_seq if since is None else since)

    anchor = await db.scalar(
        select(AuditLog.entry_hash)
        .where(AuditLog.seq <= from_seq)
        .order_by(AuditLog.seq.desc())
        .limit(1)
    )
    # What the first row the pass reads has to link to. Three cases, and the
    # third is the one that matters after retention has run: a *full* pass starts
    # at position 0, so there is no row to anchor on, and the hash the deleted
    # prefix ended on is the only link the surviving history can be measured
    # against. Treating that as genesis would report every installation that has
    # been running longer than the retention window as tampered — on the pass an
    # operator runs after a restore, which is exactly when a false alarm costs
    # the most.
    expected_prev: str = str(anchor or state.retired_tip_hash or GENESIS_PREV_HASH)

    result = ChainVerification(
        from_seq=from_seq,
        through_seq=from_seq,
        retired_through_seq=state.retired_through_seq,
    )
    # (fingerprint, key) pairs, so a row is checked against the key that claims to
    # have signed it rather than against whichever key is currently first.
    pairs = chain_key_pairs()
    # Starts at the pass's own start position rather than ``None``: the first row
    # of an incremental pass has to be checked for contiguity against where the
    # pass began, otherwise a deletion at the head of the new range is invisible
    # until the next full verification.
    last_seq: int = from_seq

    query = (
        select(
            AuditLog.seq,
            AuditLog.timestamp,
            AuditLog.user_id,
            AuditLog.action,
            AuditLog.ip_address,
            AuditLog.details,
            AuditLog.entry_hash,
            AuditLog.prev_hash,
            AuditLog.key_id,
        )
        .where(AuditLog.seq > from_seq)
        .order_by(AuditLog.seq)
    )
    stream = await db.stream(query)
    try:
        async for row in stream:
            if result.checked >= max_rows:
                result.truncated = True
                break

            if row.entry_hash is None:  # pragma: no cover - see below
                # Unreachable in a schema this platform created: the column is
                # NOT NULL and the only writer signs inside the inserting
                # transaction. Kept as defence in depth, because a database whose
                # column was altered is exactly the case a verification pass is
                # asked about, and "no hash" must never read as "fine".
                result.first_broken_seq = int(row.seq)
                result.reason = REASON_UNSIGNED
                break

            if int(row.seq) != last_seq + 1:
                # Legitimate only while every skipped position is below the
                # watermark retention recorded.
                first_missing = last_seq + 1
                if first_missing > state.retired_through_seq:
                    result.first_broken_seq = first_missing
                    result.reason = REASON_GAP
                    break

            key_id = int(row.key_id or 0)
            candidates = [key for fingerprint, key in pairs if fingerprint == key_id]
            if not candidates:
                # The key that signed this row is not configured: a key that was
                # dropped from the rotation list, or an id that was written by
                # something other than this platform. Either way the row cannot be
                # vouched for, and saying so is the honest answer — recomputing it
                # with a different key would only produce a hash mismatch.
                result.first_broken_seq = int(row.seq)
                result.reason = REASON_UNKNOWN_KEY
                break

            payload = entry_payload(
                timestamp=row.timestamp,
                user_id=row.user_id,
                action=row.action,
                ip_address=row.ip_address,
                details=row.details,
            )
            prev_hash = str(row.prev_hash or "")
            matching = next(
                (
                    candidate
                    for candidate in candidates
                    if compute_entry_hash(
                        candidate, payload=payload, prev_hash=prev_hash, key_id=key_id
                    )
                    == row.entry_hash
                ),
                None,
            )
            if matching is None:
                result.first_broken_seq = int(row.seq)
                result.reason = (
                    REASON_KEY_ID_MISMATCH
                    if _verifies_with_another_key(
                        pairs, key_id, payload, prev_hash, row.entry_hash
                    )
                    else REASON_HASH_MISMATCH
                )
                break
            if row.prev_hash != expected_prev:
                result.first_broken_seq = int(row.seq)
                result.reason = REASON_BROKEN_LINK
                break

            result.checked += 1
            result.tip_hash = str(row.entry_hash)
            expected_prev = str(row.entry_hash)
            last_seq = int(row.seq)
    finally:
        await stream.close()

    # A truncated pass still advances the watermark for the prefix it did read,
    # which is what keeps a long first run from repeating its work every night.
    advanced_through = last_seq if result.ok else from_seq
    result.through_seq = int(advanced_through or from_seq)

    if result.ok:
        state.last_verified_seq = max(int(state.last_verified_seq or 0), result.through_seq)
        state.last_verified_at = datetime.now(timezone.utc)
        await db.commit()
    return result


def _verifies_with_another_key(
    pairs: tuple[tuple[int, str], ...],
    key_id: int,
    payload: str,
    prev_hash: str,
    entry_hash: str | None,
) -> bool:
    """True when the row's hash is intact under a *different* (key, key id).

    Distinguishes "the content was edited" from "the key id was edited": the
    first is a rewritten row, the second is a rewritten row *identifier*, and
    they are worth telling apart in the report even though both fail the pass.
    The candidate id is used both to pick the key and inside the signed material,
    because that is what the original writer signed with.
    """
    for candidate_id, key in pairs:
        if candidate_id == key_id:
            continue
        if (
            compute_entry_hash(
                key, payload=payload, prev_hash=prev_hash, key_id=candidate_id
            )
            == entry_hash
        ):
            return True
    return False
