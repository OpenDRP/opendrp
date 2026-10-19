from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Index, SmallInteger, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, TimestampMixin, UUIDMixin


class PhishingDomain(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "drp_phishing_domains"
    __table_args__ = (
        # The candidate list's own access paths (WI-11): `min_confidence` filters
        # and the "highest confidence first" order both start at `confidence`, and
        # the composite adds the status an operator narrows to as a filter-only
        # column on the same index. The status-only list keeps the index it always
        # had, so neither query loses its access path.
        Index("ix_phishing_confidence", "confidence"),
        Index("ix_phishing_domains_confidence_status", "confidence", "status"),
    )

    phishing_domain: Mapped[str] = mapped_column(
        String(512), unique=True, nullable=False, index=True
    )
    #: Indexed because every asset-scoped read — the "asset → findings" view
    #: (WI-12), the cascade, orphan cleanup — filters on this column (WI-15).
    matched_asset: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(255), nullable=True)
    web_ports: Mapped[str | None] = mapped_column(String(255), nullable=True)
    detection_source: Mapped[str] = mapped_column(String(100), nullable=False)
    original_domain: Mapped[str | None] = mapped_column(String(512), nullable=True)
    whois_registrar: Mapped[str | None] = mapped_column(String(255), nullable=True)
    whois_abuse_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    domain_created_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: Investigation state of the finding: ``active``, ``investigating`` or
    #: ``resolved``. The platform has no takedown workflow.
    status: Mapped[str] = mapped_column(
        String(50), default="active", nullable=False, index=True
    )
    #: The candidate's scored confidence, 0…100 (WI-08). Stored rather than summed
    #: on read: the list orders and filters by it, the alert budget thresholds on
    #: it, and neither can afford an aggregate over the signal table per row. ``0``
    #: is also the honest answer for a candidate scored before this column existed,
    #: which is what an adopted database holds until its next scan scores the row
    #: again (`docs/upgrading.md`).
    confidence: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)
    #: The map the score is explained by — signal name to the value that fired —
    #: kept as one object so a new signal never needs a new column. The evidence
    #: behind each entry (which source answered, when, what it contributed) lives in
    #: :class:`PhishingCandidateSignal`; this is the summary the list, the filter
    #: and the alert read.
    signals: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    #: When this candidate was last handed to the daily digest (WI-10). A digest
    #: that runs once a day reports a candidate whose page has not changed only
    #: once, and the mark is what makes that hold across a worker restart rather
    #: than only within one process's memory.
    digest_queued_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: What an analyst decided about the candidate: ``confirmed``, ``rejected`` or
    #: nothing (WI-12, W1.6). The score answers "how much does this look like ours",
    #: and it is a *guess* built from signals; a person who has looked at the page is
    #: not guessing. A verdict therefore outranks the score wherever the two disagree:
    #: a confirmed candidate alerts however low it scores, and a rejected one is
    #: silent however high. ``None`` is the ordinary state and means nobody has
    #: decided yet — deliberately not a third string, so "not reviewed" cannot be
    #: mistaken for a decision somebody made.
    verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    #: Why the verdict was reached, in the analyst's words. Required for a rejection:
    #: "rejected, no reason" is indistinguishable from an accidental click, and the
    #: reason is the only thing that lets a later reader re-derive the decision —
    #: the candidate itself carries no trace of why it was dismissed.
    verdict_reason: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    #: Who decided, and when. Both are cleared with the verdict: an un-decision has
    #: no author, and keeping a name beside a verdict that no longer exists would
    #: read as an anonymous decision.
    verdict_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    verdict_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class PhishingCandidateSignal(Base, UUIDMixin):
    """One signal observed on one candidate: the evidence behind its score.

    A score nobody can explain afterwards is a number an analyst has to take on
    faith. Every signal that fires is therefore recorded here with what it fired
    on, what it contributed and who answered, so "why is this candidate at 85?" is
    answered from rows instead of by re-deriving the weights of whatever version
    of the code happened to run (WI-08). The map on the candidate row is the
    summary; this table is the trail behind it, and the cascade keeps the two in
    step when a candidate is deleted.
    """

    __tablename__ = "phishing_candidate_signals"
    __table_args__ = (
        Index("ix_phishing_candidate_signals_candidate", "candidate_id"),
    )

    candidate_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("drp_phishing_domains.id", ondelete="CASCADE"), nullable=False
    )
    #: The signal's name, as the scoring service's weights declare it.
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    #: The fact the signal fired on — a count, a boolean, a string, a similarity.
    #: JSON because a signal's value is whatever its own rule measures, and a
    #: column per signal would be a schema change per rule.
    value: Mapped[Any] = mapped_column(JSON, nullable=False)
    #: The points this signal contributed to the candidate's confidence, so the
    #: total can be re-derived after the weights change.
    confidence: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)
    #: When the fact was observed. Nullable on purpose: a signal derived from a
    #: source that reported no time of its own is still a signal about the
    #: candidate, and the moment the platform recorded it is not the same fact.
    observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: Who answered: a connector name, ``whois``, ``dns`` or ``platform``.
    source: Mapped[str | None] = mapped_column(String(100), nullable=True)
