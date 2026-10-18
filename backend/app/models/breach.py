from datetime import date, datetime

from sqlalchemy import Date, DateTime, Index, Integer, JSON, String, Text, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, TimestampMixin, UUIDMixin


class Breach(Base, UUIDMixin, TimestampMixin):
    """A breach finding matched to a monitored asset.

    The columns are the fields *every* breach source can supply: which incident,
    which of our assets it hit, when it happened, how much data was involved,
    and which classes of data were exposed. Anything a particular source knows
    beyond that — verification flags, exposed-secret samples, the source's own
    catalog timestamps — travels in :attr:`attributes`, so supporting a new
    breach source never requires a core schema change.

    Named for what it stores rather than for the first source that filled it: the
    connector protocol accepts breaches from any provider, so nothing about this
    module names one — not the table, not the API group the UI calls, not the
    finding shape.
    """

    __tablename__ = "drp_breaches"
    __table_args__ = (
        UniqueConstraint("source_id", "breach_name", "matched_email", name="uq_breach_email"),
        # Domain scans may return several affected aliases for one domain and
        # breach. Only domain-only findings use the domain fallback key.
        Index(
            "uq_breach_domain_only",
            "source_id",
            "breach_name",
            "matched_domain",
            unique=True,
            postgresql_where=text("matched_domain IS NOT NULL AND matched_email IS NULL"),
            sqlite_where=text("matched_domain IS NOT NULL AND matched_email IS NULL"),
        ),
    )

    source_id: Mapped[str] = mapped_column(
        String(100), nullable=False, default="unattributed"
    )
    breach_name: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    breach_date: Mapped[date] = mapped_column(Date, nullable=False)
    pwn_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    data_classes: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    matched_email: Mapped[str | None] = mapped_column(
        String(255), nullable=True, index=True
    )
    matched_domain: Mapped[str | None] = mapped_column(
        String(255), nullable=True, index=True
    )
    status: Mapped[str] = mapped_column(
        String(50), default="active", nullable=False, index=True
    )
    #: Which kind of exposure this row records: a breach of an account, a paste it
    #: appeared in, or a stealer log a site was found in. The module's dedup keys do
    #: not move for it — the class is also encoded in ``breach_name``
    #: (``paste:<id>``, ``stealerlog:<site>``) — so an installation that adopts this
    #: column keeps its existing unique pairs and indexes, and a row stored before the
    #: column existed is a breach because that is all the module could represent.
    exposure_kind: Mapped[str] = mapped_column(
        String(32), default="breach", server_default="breach", nullable=False, index=True
    )
    #: How loud this row is, from the classes of data it exposed (F-13). Written when
    #: the row is written (`app/services/breach_severity.py`), not computed on read:
    #: the list filters and sorts on it, and a value computed per query would be a
    #: second rule beside the one the page and the report use.
    severity: Mapped[str] = mapped_column(
        String(16), default="unknown", server_default="unknown", nullable=False, index=True
    )
    #: Provider-specific payload (scalars or lists of strings), sanitized at the
    #: protocol boundary and re-sanitized on ingestion.
    attributes: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    #: When the source last reported this incident. A row's facts can be unchanged
    #: for months while the incident is still arriving in every scan, and "is this
    #: still current?" is a different question from "did it change?" (WI-08, WI-11).
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    #: When the source first confirmed the incident. Distinct from ``last_seen_at``
    #: and from ``attributes.is_verified``: the flag is the source's standing
    #: statement, and this is the moment it became true, which is what an operator
    #: reconstructing a timeline needs (WI-11).
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    @property
    def metadata_incomplete(self) -> bool:
        """Whether this row was stored without the facts that normally describe it.

        The source said so itself (a paste or a dump with no catalogue entry), and it
        travels to the API and the page rather than staying buried in
        ``attributes``: a row whose date is the observation instant must not read as
        an incident that happened on that day (F-02).
        """
        return (self.attributes or {}).get("metadata_incomplete") is True


class BreachCatalogue(Base, UUIDMixin, TimestampMixin):
    """One incident in the provider's catalogue, whether or not it hit us (F-09).

    Findings are what happened to *our* accounts, and they are only reported for an
    address somebody added to the inventory. The catalogue is the other half: what
    the provider already knows about incidents at large, which is the only way a
    breach of a domain we monitor is seen **before** an operator adds the address.
    A source's catalogue is one row per ``(source, breach_name)``, refreshed by the
    sync pass, and the platform's own diff is what makes an incident "new" — the
    provider's API has no "added since" question to ask.

    ``attributes`` carries what the source knows beyond the neutral fields (its
    verification and classification flags), the same way a finding's does; the core
    models no vendor.
    """

    __tablename__ = "breach_catalogue"
    __table_args__ = (
        UniqueConstraint(
            "source", "breach_name", name="uq_breach_catalogue_incident"
        ),
        # One source's catalogue by vendor domain: what a sync reads to answer "is this
        # incident about a domain we watch", and what an operator reads to answer "what
        # does the source say about our vendor".
        Index("ix_breach_catalogue_source_domain", "source", "domain"),
    )

    source: Mapped[str] = mapped_column(String(100), nullable=False)
    breach_name: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    #: The vendor's domain. This is the field the sync matches against the asset
    #: inventory, so it is stored exactly as the source reported it, lowercased.
    domain: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    breach_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    #: The source's own catalogue timestamps: when it added the incident, and when
    #: it last changed it. Distinct from this row's ``created_at``/``updated_at``,
    #: which are when *we* first saw and last refreshed it.
    added_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    modified_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    pwn_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    data_classes: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    attributes: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    #: When this row was last confirmed present by a sync. A row nothing has
    #: confirmed for a long time is a candidate for the source having withdrawn the
    #: incident, which is why the window the connector is given is measured from it.
    last_synced_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    @property
    def metadata_incomplete(self) -> bool:
        """Whether this row was stored without the facts that normally describe it.

        The source said so itself (a paste or a dump with no catalogue entry), and it
        travels to the API and the page rather than staying buried in
        ``attributes``: a row whose date is the observation instant must not read as
        an incident that happened on that day (F-02).
        """
        return (self.attributes or {}).get("metadata_incomplete") is True
