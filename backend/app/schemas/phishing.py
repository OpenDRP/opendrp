import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, computed_field, field_validator

from app.schemas.common import PaginatedResponse
from app.services.alert_policy import AlertPolicy
from app.services.phishing.age import domain_age_days
from app.services.phishing_score_service import alert_band, fired_signals

ThreatStatus = Literal["active", "investigating", "resolved"]
DetectionSource = str

#: The signals the alert budget knows, as ``?signal=`` accepts them (WI-11, W1.5).
#: Spelled out rather than derived from the service's table: a parameter's vocabulary
#: is part of the published contract, and FastAPI can only refuse an undeclared value
#: from a declared type. A test pins this list against ``SIGNAL_WEIGHTS``, so the two
#: cannot drift into an API that accepts a signal nothing scores.
AlertSignalName = Literal[
    "young_domain",
    "mx_without_spf",
    "title_match",
    "favicon_perceptual_match",
    "html_similarity",
    "brand_in_body",
    "source_corroboration",
    "parked_hint",
    "aged_domain",
    "tls_issuer_reuse",
]

#: How the alert budget would report a candidate. The numbers behind the band are the
#: deployment's settings, so the band is computed by the server from the same values
#: the delivery path reads — a list that hard-coded "60" would be telling an operator
#: about a threshold their installation may not have.
AlertBand = Literal["direct", "digest", "list"]

#: The fields ``GET /phishing/threats`` may be ordered by (WI-05). An allowlist rather
#: than a free string, because the value reaches ``ORDER BY`` and caller input must
#: never be concatenated into a statement: the framework refuses anything outside this
#: set with 422 before a query is built. ``age`` is the registration date the computed
#: age comes from — the only field of a candidate a *look-alike* is judged by that is
#: not about when the platform noticed it.
PhishingSortField = Literal["created_at", "age", "confidence"]
SortDirection = Literal["asc", "desc"]

#: What an analyst decided about a candidate (WI-12, W1.6): ``confirmed`` is "this is
#: ours to act on" and ``rejected`` is "answering it would be noise". A closed set,
#: because a free string would let a client write a verdict no rule reads and the
#: candidate would look reviewed while nothing about its routing changed.
PhishingVerdict = Literal["confirmed", "rejected"]


class PhishingThreatBase(BaseModel):
    phishing_domain: str = Field(..., max_length=512)
    matched_asset: str = Field(..., max_length=512)
    ip_address: str | None = Field(None, max_length=255)
    web_ports: str | None = Field(None, max_length=255)
    detection_source: DetectionSource = Field(default="dnstwist", max_length=100)
    original_domain: str | None = Field(None, max_length=512)
    whois_registrar: str | None = Field(None, max_length=255)
    whois_abuse_email: str | None = Field(None, max_length=255)
    domain_created_at: datetime | None = None
    #: Investigation state: ``active``, ``investigating`` or ``resolved``.
    status: ThreatStatus = "active"


class PhishingThreatResponse(PhishingThreatBase):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime
    #: The candidate's scored confidence, 0…100 (WI-08), and the signals it came
    #: from — signal name to the points it contributed, in weight-table order. The
    #: number without the explanation is a score an analyst has to take on faith, and
    #: the list is where the triage decision is made.
    confidence: int = Field(default=0, ge=0, le=100)
    signals: dict[str, int] = Field(default_factory=dict)
    #: The analyst's decision, and why (WI-12). ``None`` is "nobody has decided yet",
    #: which the list has to be able to tell apart from a decision — the two lead to
    #: opposite routing, and a candidate that merely *looks* reviewed is worse than
    #: one that is obviously untouched.
    verdict: PhishingVerdict | None = None
    verdict_reason: str | None = Field(default=None, max_length=2000)
    verdict_by: uuid.UUID | None = None
    verdict_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    #: The policy this response's band is computed under. A private attribute
    #: rather than a module-level "current settings": the band belongs to the pair
    #: (candidate, policy), and two requests can be answered under two different
    #: policies — the one an operator had before a save and the one they have after.
    _policy: AlertPolicy | None = PrivateAttr(default=None)

    #: The sources that reported this candidate, read from the evidence rows rather
    #: than stored on the candidate (WI-30): a source is an observation, and the
    #: column the list shows has to be the same set the score counted.
    _sources: list[str] = PrivateAttr(default_factory=list)

    @classmethod
    def from_row(
        cls,
        row: object,
        *,
        policy: AlertPolicy | None = None,
        sources: list[str] | None = None,
    ) -> "PhishingThreatResponse":
        """A candidate as the API reports it, under the policy in force.

        The router reads the policy once per request and hands it in, so the band a
        list shows is the band the delivery path would act on: an operator who raises
        the direct threshold in Settings must not keep reading "immediate" next to a
        candidate the channel has stopped interrupting anybody for. Without a policy
        the environment's answer is used, which is what a schema with no database can
        state.

        ``sources`` comes the same way and for the same reason: it is a separate
        table, read once for the page that is being rendered, and a response built
        without it says "nobody has reported this" rather than inventing a source
        from the candidate's own ``detection_source``.
        """
        response = cls.model_validate(row)
        response._policy = policy
        response._sources = list(sources or [])
        return response

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sources(self) -> list[str]:
        """Which sources reported the candidate, distinct and sorted (WI-30).

        The names, not a number: "we saw this twice" and "two independent providers
        saw this" are different statements, and only the second one is the
        corroboration the score rewards. An empty list is the honest answer for a
        candidate whose evidence has been pruned or whose connectors recorded none —
        it is not the same as the single source that *found* the name, which is
        ``detection_source``.
        """
        return list(self._sources)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_count(self) -> int:
        """How many sources, so a list can sort or filter without counting strings."""
        return len(self._sources)

    @field_validator("signals", mode="before")
    @classmethod
    def _explain_the_score(cls, value: object) -> dict[str, int]:
        """The stored facts, turned into the signals that fired and what they added.

        The column holds the facts the platform observed — including the ones that
        did not reach their threshold, which is what lets the list explain a low
        score. What a reader of the API needs is the other half: which of them
        counted. Same function the delivered message uses, so the list and the alert
        cannot print two different explanations of one candidate.
        """
        return fired_signals(value if isinstance(value, dict) else {})

    @computed_field  # type: ignore[prop-decorator]
    @property
    def alert_band(self) -> AlertBand:
        """What the channel would do with this candidate, under the policy in force."""
        return alert_band(self.confidence, policy=self._policy)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def domain_age_days(self) -> int | None:
        """Whole days since the registration, or None when nobody resolved it.

        Computed on the way out rather than stored: an age is a function of the moment
        it is read, so a stored copy is a day stale the day after it was written
        (WI-05). ``None`` is not zero — it means the platform has not learned the
        registration date yet, and a reader has to be able to tell those apart before
        trusting the number. The same helper answers the alert and (in wave 1) the
        scoring signal, so the three cannot disagree.
        """
        return domain_age_days(self.domain_created_at)


class PhishingThreatUpdate(BaseModel):
    """What a client may change about a candidate.

    ``verdict`` is set and cleared by the same field: omitting it leaves the decision
    alone, and sending an explicit ``null`` takes it back — an analyst who rejected
    the wrong row has to be able to undo that, and a separate "clear" route would be
    a second way to write one column.
    """

    status: ThreatStatus | None = None
    matched_asset: str | None = None
    verdict: PhishingVerdict | None = None
    verdict_reason: str | None = Field(default=None, max_length=2000)


class PhishingListResponse(PaginatedResponse):
    items: list[PhishingThreatResponse]
