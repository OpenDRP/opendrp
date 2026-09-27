"""The audit trail, and the chain that makes an edit to it visible.

``drp_audit_logs`` is the platform's record of who did what: it is read during
incidents, produced during audits, and shipped to a SIEM. A record with that role
has a second requirement beyond "it is written down" — someone who can edit the
database must not be able to edit it *unnoticed*. That is what the hash chain is
for:

* ``seq`` is a monotonic position, assigned by the writer inside the same
  transaction as the insert. It is what makes a deletion visible: a missing
  position is a missing row.
* ``entry_hash`` is an HMAC over this row's five fields and the previous row's
  hash. It is keyed from the environment (`AUDIT_CHAIN_KEYS`), so an attacker who
  can write to the database but cannot read the deployment's environment cannot
  produce a row that verifies. The column is NOT NULL: the only writer signs
  inside the inserting transaction, so an unsigned row means the row did not come
  from that writer.
* ``prev_hash`` is the link. It is stored rather than recomputed so that a
  verification pass can start anywhere — including after the prefix retention
  has legitimately deleted. It is NULL only for the first entry of a chain,
  which links to nothing.
* ``key_id`` records which key signed the row, which is what lets a key be
  rotated without invalidating history. It is a fingerprint of the key rather
  than its position in the configured list (see ``audit_chain.key_id_for``): a
  position would be re-pointed at a different key by the next rotation.
"""

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, JSON, SmallInteger, String, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, TimestampMixin, UUIDMixin

#: The single row every chain operation reads and writes. A constant rather than
#: a lookup: there is exactly one chain per installation.
AUDIT_CHAIN_STATE_ID = 1


class AuditLog(Base, UUIDMixin):
    __tablename__ = "drp_audit_logs"

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    user_id: Mapped[UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
    )
    action: Mapped[str] = mapped_column(
        String(120),
        nullable=False,
        index=True,
    )
    ip_address: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    details: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )

    #: Monotonic position in the chain. Unique, because two rows claiming the same
    #: position is exactly the "delete one, shift the rest" shape this exists to
    #: catch.
    seq: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        unique=True,
        index=True,
    )
    #: Required. The single writer computes it in the same transaction as the
    #: insert, so an unsigned row cannot be produced by the platform at all.
    entry_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    #: The previous entry's hash; NULL only for the first entry of a chain.
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    key_id: Mapped[int] = mapped_column(
        SmallInteger,
        nullable=False,
        default=0,
        server_default="0",
    )


class AuditChain(Base, TimestampMixin):
    """The state a chain needs beyond its rows.

    Three things cannot be derived from the rows themselves:

    * **What retention legitimately retired.** The sweep deletes by age, and the
      audit trail is hashed by position. ``retired_through_seq`` records the
      highest position the sweep has removed, so that a gap below it is expected
      housekeeping and a gap above it is a finding.
    * **The hash the retired prefix ended on**, which is what the first surviving
      entry links back to (``retired_tip_hash``).
    * **How far verification has already been performed**, so the nightly check
      can be incremental instead of recomputing a year of history every night
      (``last_verified_seq``).
    """

    __tablename__ = "drp_audit_chain"

    id: Mapped[int] = mapped_column(
        SmallInteger,
        primary_key=True,
        default=AUDIT_CHAIN_STATE_ID,
        server_default=str(AUDIT_CHAIN_STATE_ID),
    )
    retired_through_seq: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
        server_default="0",
    )
    retired_tip_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_verified_seq: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
        server_default="0",
    )
    last_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
