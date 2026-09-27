"""What the audit hash chain actually catches, and what it must not cry wolf about.

Two halves, and the second is the one that decides whether the first is useful.

The chain exists so that someone who can write to the audit table cannot rewrite
history unnoticed. So the tests here edit a row, delete a row, and blank a row's
signature, and each has to be reported at the position where it happened.

The other half is the false positives, because a verifier that reports tampering
after an ordinary operation is a verifier an operator learns to ignore. Two
operations must stay quiet: retention deleting old rows (it records what it
deleted, so the gap is expected housekeeping) and rotating the signing key (each
row names the key that signed it, so history stays verifiable). Both are
documented procedures in docs/upgrading.md, and both are tested as behaviour.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from app.core.audit import AuditLogger
from app.core.audit_chain import (
    GENESIS_PREV_HASH,
    REASON_BROKEN_LINK,
    REASON_GAP,
    REASON_HASH_MISMATCH,
    REASON_KEY_ID_MISMATCH,
    REASON_UNKNOWN_KEY,
    chain_key_pairs,
    chain_keys,
    compute_entry_hash,
    entry_payload,
    key_id_for,
    prepare_entry,
    retire,
    verify,
)
from app.core.config import settings
from app.models.audit import AuditChain, AuditLog

KEY_A = "audit-chain-key-a-" + "1" * 32
KEY_B = "audit-chain-key-b-" + "2" * 32
#: A third key that is never configured, standing in for one an attacker brought.
FOREIGN_KEY = "audit-chain-key-foreign-" + "3" * 28


async def _emit(db, *, action: str = "asset.view", ip: str = "203.0.113.7", details: dict | None = None):
    await AuditLogger.emit(
        db,
        action=action,
        ip_address=ip,
        user_id=None,
        details=details if details is not None else {"source": "test"},
    )


async def _emit_many(db, count: int) -> list[AuditLog]:
    for index in range(count):
        await _emit(db, action="asset.view", details={"index": index})
    rows = (
        await db.execute(select(AuditLog).order_by(AuditLog.seq))
    ).scalars().all()
    return list(rows)


async def _rows(db) -> list[AuditLog]:
    return list((await db.execute(select(AuditLog).order_by(AuditLog.seq))).scalars().all())


class TestTheLink:
    @pytest.mark.anyio
    async def test_each_entry_positions_itself_and_links_to_the_one_before(self, db_session):
        rows = await _emit_many(db_session, 3)

        assert [row.seq for row in rows] == [1, 2, 3]
        assert rows[0].prev_hash == GENESIS_PREV_HASH
        assert rows[1].prev_hash == rows[0].entry_hash
        assert rows[2].prev_hash == rows[1].entry_hash
        for row in rows:
            assert row.entry_hash is not None and len(row.entry_hash) == 64
            assert row.prev_hash is not None and len(row.prev_hash) == 64

    @pytest.mark.anyio
    async def test_the_hash_covers_the_row_and_not_the_copies_of_it(self, db_session):
        """`audit_hash` lives in `details` and is excluded when hashing.

        A hash cannot cover itself. If the field were included, verifying a row
        would require knowing its hash in order to compute its hash, and every row
        would fail — which is the kind of bug that ends with the check disabled.
        """
        rows = await _emit_many(db_session, 1)
        row = rows[0]
        assert row.details["audit_hash"] == row.entry_hash
        assert row.details["audit_prev_hash"] == row.prev_hash
        assert row.details["audit_key_id"] == row.key_id

        payload = entry_payload(
            timestamp=row.timestamp,
            user_id=row.user_id,
            action=row.action,
            ip_address=row.ip_address,
            details=row.details,
        )
        assert compute_entry_hash(
            chain_keys()[0], payload=payload, prev_hash=row.prev_hash, key_id=row.key_id
        ) == row.entry_hash

    @pytest.mark.anyio
    async def test_an_untouched_chain_verifies(self, db_session):
        rows = await _emit_many(db_session, 4)

        result = await verify(db_session, full=True)

        assert result.ok
        assert result.reason is None
        assert result.checked == 4
        assert result.tip_hash == rows[-1].entry_hash
        assert result.through_seq == 4

    @pytest.mark.anyio
    async def test_verification_is_incremental_and_continues_where_it_stopped(self, db_session):
        await _emit_many(db_session, 2)
        first = await verify(db_session)
        assert first.checked == 2

        await _emit_many(db_session, 1)
        second = await verify(db_session)

        # The second pass starts at the recorded watermark, so it re-reads only
        # what was written since — a nightly check has to cost one query over the
        # new entries, not one over the year.
        assert second.from_seq == first.through_seq == 2
        assert second.checked == 1
        assert second.ok

    @pytest.mark.anyio
    async def test_a_full_pass_ignores_the_watermark(self, db_session):
        await _emit_many(db_session, 3)
        await verify(db_session)

        result = await verify(db_session, full=True)

        assert result.from_seq == 0
        assert result.checked == 3

    @pytest.mark.anyio
    async def test_the_row_cap_truncates_without_failing_the_pass(self, db_session):
        await _emit_many(db_session, 5)

        result = await verify(db_session, full=True, max_rows=3)

        assert result.ok, "a bounded read is not a finding"
        assert result.truncated is True
        assert result.checked == 3
        # The pass advances to what it did read, so the next run continues rather
        # than starting the same bounded read over again.
        assert result.through_seq == 3


class TestTamperingIsReported:
    @pytest.mark.anyio
    async def test_an_edited_row_is_reported_at_its_position(self, db_session):
        await _emit_many(db_session, 3)
        await db_session.execute(
            text("UPDATE drp_audit_logs SET action = 'asset.delete' WHERE seq = 2")
        )

        result = await verify(db_session, full=True)

        assert not result.ok
        assert result.first_broken_seq == 2
        assert result.reason == REASON_HASH_MISMATCH

    @pytest.mark.anyio
    async def test_an_edited_detail_is_reported(self, db_session):
        await _emit_many(db_session, 2)
        # The whole point of hashing `details` is that a change *inside* the blob
        # is as visible as a change to the action beside it.
        await db_session.execute(
            text("UPDATE drp_audit_logs SET details = :details WHERE seq = 1"),
            {"details": '{"index": 999}'},
        )

        result = await verify(db_session, full=True)

        assert not result.ok
        assert result.first_broken_seq == 1
        assert result.reason == REASON_HASH_MISMATCH

    @pytest.mark.anyio
    async def test_a_deleted_row_leaves_a_gap_where_it_was(self, db_session):
        await _emit_many(db_session, 3)
        await db_session.execute(text("DELETE FROM drp_audit_logs WHERE seq = 2"))

        result = await verify(db_session, full=True)

        assert not result.ok
        assert result.first_broken_seq == 2
        assert result.reason == REASON_GAP

    @pytest.mark.anyio
    async def test_a_row_re_linked_to_somewhere_else_is_reported(self, db_session):
        """A row can be internally consistent and still not belong to this chain.

        Re-linking row 3 to genesis means its stored hash is recomputed here the
        same way a forger would, so the row passes the hash check and fails the
        one that matters: the entry before it did not hash to what it claims.
        """
        await _emit_many(db_session, 3)
        target = (await _rows(db_session))[2]
        relinked = compute_entry_hash(
            chain_keys()[0],
            payload=entry_payload(
                timestamp=target.timestamp,
                user_id=target.user_id,
                action=target.action,
                ip_address=target.ip_address,
                details=target.details,
            ),
            prev_hash=GENESIS_PREV_HASH,
            key_id=target.key_id,
        )
        await db_session.execute(
            text("UPDATE drp_audit_logs SET entry_hash = :hash, prev_hash = :prev WHERE seq = 3"),
            {"hash": relinked, "prev": GENESIS_PREV_HASH},
        )

        result = await verify(db_session, full=True)

        assert not result.ok
        assert result.first_broken_seq == 3
        assert result.reason == REASON_BROKEN_LINK

    @pytest.mark.anyio
    async def test_an_unsigned_row_is_not_a_state_the_table_can_hold(self, db_session):
        """\"Someone removed the hash\" is refused by the schema, not explained.

        The only writer signs in the inserting transaction, so an unsigned row
        has no legitimate producer and the verifier never has to excuse one.
        """
        await _emit_many(db_session, 2)

        with pytest.raises(IntegrityError):
            await db_session.execute(
                text("UPDATE drp_audit_logs SET entry_hash = NULL WHERE seq = 2")
            )
        await db_session.rollback()

        assert (await verify(db_session, full=True)).ok

    @pytest.mark.anyio
    async def test_a_row_forged_outside_the_writer_is_reported(self, db_session):
        """Defence in depth: a row the platform did not sign does not verify.

        The NOT NULL column stops the simplest version of this (no hash at all),
        and the hash itself stops the rest: a row inserted by hand cannot carry a
        hash that recomputes under the installation's key.
        """
        await _emit_many(db_session, 2)
        await db_session.execute(text("DELETE FROM drp_audit_logs WHERE seq = 2"))
        await db_session.execute(
            text(
                "INSERT INTO drp_audit_logs "
                "(id, timestamp, user_id, action, ip_address, details, seq, entry_hash, prev_hash, key_id) "
                "VALUES ('00000000000000000000000000000002', CURRENT_TIMESTAMP, NULL, "
                "'asset.view', '203.0.113.9', '{}', 2, 'forged', NULL, 0)"
            )
        )
        await db_session.commit()

        result = await verify(db_session, full=True)

        assert not result.ok
        assert result.first_broken_seq == 2

    @pytest.mark.anyio
    async def test_a_row_signed_by_a_key_nobody_configured_is_reported(
        self, db_session, monkeypatch
    ):
        monkeypatch.setattr(settings, "AUDIT_CHAIN_KEYS", KEY_A)
        monkeypatch.setattr(settings, "AUDIT_CHAIN_PREVIOUS_KEYS", "")
        await _emit_many(db_session, 2)

        # An id that names no configured key, derived rather than picked so the
        # test cannot fail because two fingerprints happened to collide.
        configured = {kid for kid, _ in chain_key_pairs()}
        unknown_id = next(i for i in range(32768) if i not in configured)
        await db_session.execute(
            text("UPDATE drp_audit_logs SET key_id = :kid WHERE seq = 2"),
            {"kid": unknown_id},
        )

        result = await verify(db_session, full=True)

        assert not result.ok
        assert result.first_broken_seq == 2
        assert result.reason == REASON_UNKNOWN_KEY

    @pytest.mark.anyio
    async def test_a_rewritten_key_reference_is_told_apart_from_rewritten_content(
        self, db_session, monkeypatch
    ):
        """`key_id_mismatch` versus `hash_mismatch`, because they are different edits.

        The row here is signed by KEY_A and relabelled as KEY_B's, both configured.
        Its content is untouched and its hash still verifies under the key that
        actually signed it, so the useful answer is not "the row was rewritten"
        but "the key reference was" — which is what an operator needs to know to
        decide where to look.
        """
        monkeypatch.setattr(settings, "AUDIT_CHAIN_KEYS", KEY_A)
        monkeypatch.setattr(settings, "AUDIT_CHAIN_PREVIOUS_KEYS", KEY_B)
        await _emit_many(db_session, 1)

        await db_session.execute(
            text("UPDATE drp_audit_logs SET key_id = :kid WHERE seq = 1"),
            {"kid": key_id_for(KEY_B)},
        )

        result = await verify(db_session, full=True)

        assert not result.ok
        assert result.first_broken_seq == 1
        assert result.reason == REASON_KEY_ID_MISMATCH

    @pytest.mark.anyio
    async def test_verification_never_repairs_what_it_finds(self, db_session):
        await _emit_many(db_session, 2)
        await db_session.execute(text("DELETE FROM drp_audit_logs WHERE seq = 1"))

        before = await verify(db_session, full=True)
        after = await verify(db_session, full=True)

        # Repairing would destroy the only evidence that the chain was broken, so
        # the second pass reports the same finding rather than a clean result.
        assert not before.ok and not after.ok
        assert before.first_broken_seq == after.first_broken_seq == 1


class TestLegitimateHistory:
    """The operation that must not look like tampering: retention by age."""

    @pytest.mark.anyio
    async def test_retention_that_records_its_watermark_is_housekeeping(self, db_session):
        await _emit_many(db_session, 5)
        rows = await _rows(db_session)
        retired_tip = rows[2].entry_hash

        await db_session.execute(text("DELETE FROM drp_audit_logs WHERE seq <= 3"))
        await retire(db_session, through_seq=3, tip_hash=retired_tip)
        await db_session.commit()

        result = await verify(db_session, full=True)

        assert result.ok, "a recorded deletion is not a finding"
        assert result.retired_through_seq == 3
        assert result.checked == 2
        # The first surviving entry still links to the hash the retired prefix
        # ended on, which is why the tip is recorded rather than the rows kept.
        assert rows[3].prev_hash == retired_tip

    @pytest.mark.anyio
    async def test_the_same_deletion_without_the_watermark_is_a_finding(self, db_session):
        await _emit_many(db_session, 5)
        await db_session.execute(text("DELETE FROM drp_audit_logs WHERE seq <= 3"))
        await db_session.commit()

        result = await verify(db_session, full=True)

        assert not result.ok
        assert result.first_broken_seq == 1
        assert result.reason == REASON_GAP

    @pytest.mark.anyio
    async def test_the_watermark_only_covers_what_was_recorded(self, db_session):
        """Deleting *above* the watermark is still a finding."""
        await _emit_many(db_session, 5)
        rows = await _rows(db_session)
        await db_session.execute(text("DELETE FROM drp_audit_logs WHERE seq = 1"))
        await retire(db_session, through_seq=1, tip_hash=rows[0].entry_hash)
        await db_session.execute(text("DELETE FROM drp_audit_logs WHERE seq = 4"))
        await db_session.commit()

        result = await verify(db_session, full=True)

        assert not result.ok
        assert result.first_broken_seq == 4
        assert result.reason == REASON_GAP

    @pytest.mark.anyio
    async def test_rotating_the_signing_key_keeps_earlier_history_verifiable(
        self, db_session, monkeypatch
    ):
        """The documented rotation, as the property it has to have.

        Old entries were signed with the old key and record its fingerprint, so
        the pass finds that key in the rotation list and re-derives them. Were the
        id positional, the key that now sits first would be tried against history
        it never signed, and an operator following the documented procedure would
        be handed `hash_mismatch` over their whole audit trail.
        """
        monkeypatch.setattr(settings, "AUDIT_CHAIN_KEYS", KEY_A)
        monkeypatch.setattr(settings, "AUDIT_CHAIN_PREVIOUS_KEYS", "")
        await _emit_many(db_session, 2)
        signed_with_a = (await _rows(db_session))[0].key_id
        assert signed_with_a == key_id_for(KEY_A)

        # Rotate: the new key signs, the old one stays for verification.
        monkeypatch.setattr(settings, "AUDIT_CHAIN_KEYS", KEY_B)
        monkeypatch.setattr(settings, "AUDIT_CHAIN_PREVIOUS_KEYS", KEY_A)
        await _emit_many(db_session, 1)

        rows = await _rows(db_session)
        assert rows[2].key_id == key_id_for(KEY_B)

        result = await verify(db_session, full=True)

        assert result.ok
        assert result.checked == 3

    @pytest.mark.anyio
    async def test_dropping_the_old_key_from_the_rotation_list_is_reported(
        self, db_session, monkeypatch
    ):
        """The one way rotation *can* create a false alarm, and it is deliberate.

        Entries signed by a key that is no longer configured cannot be verified at
        all. Reporting them is the honest outcome — the alternative is hashing
        them under a different key and calling the mismatch tampering.
        """
        monkeypatch.setattr(settings, "AUDIT_CHAIN_KEYS", KEY_A)
        monkeypatch.setattr(settings, "AUDIT_CHAIN_PREVIOUS_KEYS", "")
        await _emit_many(db_session, 1)

        monkeypatch.setattr(settings, "AUDIT_CHAIN_KEYS", KEY_B)
        monkeypatch.setattr(settings, "AUDIT_CHAIN_PREVIOUS_KEYS", "")

        result = await verify(db_session, full=True)

        assert not result.ok
        assert result.first_broken_seq == 1
        assert result.reason == REASON_UNKNOWN_KEY


class TestKeyIdentity:
    def test_a_key_id_is_stable_across_the_order_of_the_list(self, monkeypatch):
        monkeypatch.setattr(settings, "AUDIT_CHAIN_KEYS", KEY_A)
        monkeypatch.setattr(settings, "AUDIT_CHAIN_PREVIOUS_KEYS", "")
        before = chain_key_pairs()

        monkeypatch.setattr(settings, "AUDIT_CHAIN_KEYS", KEY_B)
        monkeypatch.setattr(settings, "AUDIT_CHAIN_PREVIOUS_KEYS", KEY_A)
        after = chain_key_pairs()

        assert after[0][0] == key_id_for(KEY_B)
        assert after[1][0] == before[0][0], "an old key keeps the id it signed under"
        assert key_id_for(KEY_A) != key_id_for(KEY_B)

    def test_a_key_id_fits_the_column(self):
        for key in (KEY_A, KEY_B, FOREIGN_KEY, "x"):
            assert 0 <= key_id_for(key) <= 32767

    def test_the_key_id_is_part_of_what_is_signed(self):
        """Otherwise a row could be re-pointed at an easier key without detection."""
        payload = "payload"
        assert compute_entry_hash(KEY_A, payload=payload, prev_hash="0", key_id=1) != (
            compute_entry_hash(KEY_A, payload=payload, prev_hash="0", key_id=2)
        )

    def test_the_key_id_is_not_the_key(self):
        assert str(key_id_for(KEY_A)) not in KEY_A
        assert len(KEY_A) > 16


class TestStateRow:
    @pytest.mark.anyio
    async def test_the_state_row_is_created_on_first_use_and_there_is_only_one(self, db_session):
        rows = await _emit_many(db_session, 2)

        state = (await db_session.execute(select(AuditChain))).scalars().all()

        assert len(state) == 1
        assert state[0].retired_through_seq == 0
        assert state[0].retired_tip_hash is None
        # The pass watermark is written by verification, not by writing rows.
        assert state[0].last_verified_seq == 0
        assert rows[0].seq == 1

    @pytest.mark.anyio
    async def test_a_pass_records_when_it_ran(self, db_session):
        await _emit_many(db_session, 1)

        await verify(db_session, full=True)

        state = (await db_session.execute(select(AuditChain))).scalars().one()
        assert state.last_verified_seq == 1
        assert state.last_verified_at is not None

    @pytest.mark.anyio
    async def test_a_failed_pass_does_not_advance_the_watermark(self, db_session):
        await _emit_many(db_session, 3)
        ok = await verify(db_session, full=True)
        assert ok.ok
        await db_session.execute(text("DELETE FROM drp_audit_logs WHERE seq = 2"))

        result = await verify(db_session, full=True)

        assert not result.ok
        state = (await db_session.execute(select(AuditChain))).scalars().one()
        # The watermark stays where the last *successful* pass left it, so the
        # finding is not swallowed by a later pass that starts after it.
        assert state.last_verified_seq == 3


class TestPositionAllocation:
    @pytest.mark.anyio
    async def test_two_positions_cannot_be_claimed_by_two_rows(self, db_session):
        await _emit_many(db_session, 1)
        duplicate = AuditLog(
            timestamp=datetime.now(timezone.utc),
            user_id=None,
            action="asset.view",
            ip_address="203.0.113.7",
            details={},
            seq=1,
        )
        db_session.add(duplicate)
        with pytest.raises(IntegrityError):
            await db_session.commit()
        await db_session.rollback()

    @pytest.mark.anyio
    async def test_the_next_position_follows_the_highest_one_written(self, db_session):
        await _emit_many(db_session, 3)

        link = await prepare_entry(
            db_session,
            timestamp=datetime.now(timezone.utc),
            user_id=uuid.uuid4(),
            action="asset.view",
            ip_address="203.0.113.7",
            details={},
        )

        assert link.seq == 4
        assert link.key_id == key_id_for(chain_keys()[0])
