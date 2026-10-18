from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, JSON, SmallInteger, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, TimestampMixin, UUIDMixin


class TLSCertificateIdentity(Base, UUIDMixin, TimestampMixin):
    """One certificate, as an object that outlives any single hostname.

    Design B in the DNS & TLS audit reasons about *certificates*, not about
    observations: the same certificate is legitimately seen by our own probe, by
    Certificate Transparency and by a provider, on our addresses and on someone
    else's, and the interesting question — "is a certificate of ours served
    somewhere that is not ours?" — is asked of the certificate rather than of any
    one row. The raw provider evidence stays in ``dns_security_observations``;
    this is the deduplicated identity the rules and the review workflow work on.

    ``origin`` records which kind of evidence created the row first
    (``our_probe`` | ``ct`` | ``provider``), because a fingerprint learned from
    our own handshake and one learned from a third party's index say different
    things about ownership.
    """

    __tablename__ = "tls_certificate_identities"
    __table_args__ = (
        Index("ix_tls_identity_spki", "spki_sha256"),
        Index("ix_tls_identity_serial", "serial_hex"),
    )

    fingerprint_sha256: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    fingerprint_sha1: Mapped[str | None] = mapped_column(String(40), nullable=True)
    #: Subject Public Key Info digest: the identity that survives a re-issue, which is
    #: what makes key reuse visible across two different certificates.
    spki_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    serial_hex: Mapped[str | None] = mapped_column(String(128), nullable=True)
    subject_dn: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    issuer_dn: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    san_dns: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    key_algo: Mapped[str | None] = mapped_column(String(64), nullable=True)
    origin: Mapped[str] = mapped_column(String(32), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class TLSCertificateSighting(Base, UUIDMixin, TimestampMixin):
    """Where one certificate was observed, and what we decided about it.

    A sighting without an address is still a sighting: a provider may index a
    certificate in its own records without saying where it is served, and that is
    evidence about existence rather than about deployment. ``is_ours`` is the
    platform's own answer — a probe of a monitored host, or a sighting whose
    address belongs to one of our ``ip_address`` assets — and it is never taken
    from a source's opinion.

    The verdict is the review workflow's state, and it is what keeps the feature
    usable: a sighting a human marked ``expected``, or that the scoring itself
    classified as ``shared_infrastructure``, produces no alert, while a
    ``confirmed_foreign`` one is a fact the operator has accepted.
    """

    __tablename__ = "tls_certificate_sightings"
    __table_args__ = (
        # One row per (certificate, address, port, observing source): re-observing the
        # same fact refreshes it instead of stacking a second identical sighting.
        UniqueConstraint(
            "identity_id", "ip", "port", "source", name="uq_tls_sighting_identity_endpoint_source"
        ),
        Index("ix_tls_sighting_identity", "identity_id"),
        Index("ix_tls_sighting_verdict", "verdict"),
        Index("ix_tls_sighting_ip", "ip"),
    )

    identity_id: Mapped[UUID] = mapped_column(
        ForeignKey("tls_certificate_identities.id", ondelete="CASCADE"), nullable=False
    )
    subject: Mapped[str | None] = mapped_column(String(253), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_ours: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    confidence: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)
    #: The provider facts a rule scored on (jarm, title, favicon, org, asn, ...), kept
    #: as one object so a new provider signal never needs a new column.
    signals: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False, default="candidate")
    reviewed_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    review_note: Mapped[str | None] = mapped_column(String(2000), nullable=True)


class CertificateScopeException(Base, UUIDMixin, TimestampMixin):
    """An identity a rule must not alert on, and why.

    Shared hosting, a customer CDN and a partner appliance all serve our
    certificate legitimately, and without a place to say so the scoring
    re-discovers the same benign fingerprint every scan.
    """

    __tablename__ = "certificate_scope_exceptions"
    __table_args__ = (
        UniqueConstraint("match_kind", "match_value", name="uq_certificate_scope_exception"),
        Index("ix_tls_exception_kind_value", "match_kind", "match_value"),
    )

    match_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    match_value: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    created_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
