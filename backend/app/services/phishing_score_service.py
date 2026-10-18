"""The phishing candidate's confidence score, and the band it puts the alert in.

Before this service the module had one answer to "is this worth waking someone
for?" — a candidate either existed or did not — so a parked lookalike with no DNS
history and a clone of the login page that already presents our certificate issuer
arrived in the same message, and the channel carried one alert per scan whatever it
found (F-08 in the phishing audit). An analyst cannot triage that, and the honest
response to it is to stop reading the alerts.

The score is deliberately not a model. It is the sum of the weights §4.4 of the
audit specifies, each of which fires on one fact the platform actually observed:

===========================================  =======
signal                                       points
===========================================  =======
``young_domain`` — registered under 60 days     +25
``mx_without_spf`` — mail-capable, no SPF       +15
``title_match`` — page title carries the brand  +20
``favicon_perceptual_match`` — our icon          +20
``html_similarity`` — page over 0.8 similar      +25
``brand_in_body`` — brand in the page body       +15
``source_corroboration`` — 2+ sources            +15
``parked_hint`` — the domain looks parked        −30
``aged_domain`` — registered over 730 days       −10
``tls_issuer_reuse`` — our issuer on this host   +20
===========================================  =======

Three properties make such a table auditable, and all three are enforced here:

* **A fact is scored by the rule that names it, or refused.** ``record_signal``
  raises on a name that is not in :data:`SIGNAL_WEIGHTS`, so a typo — or a fact
  recorded before a rule for it exists — cannot be stored, shown in the list and
  silently contribute nothing.
* **A missing fact is never a positive one.** Every predicate reads its own value
  and nothing else: an absent key contributes nothing, and a value that did not
  reach its threshold is still stored so the list can explain why the score is low
  instead of showing an empty cell.
* **The score is bounded.** The total is clamped to 0…100, so no combination of
  signals can produce a number the list column, the filter and the alert band
  cannot represent.

Why the weights are constants and the thresholds are settings: a weight is a
statement about this platform's own signals, and changing one invalidates
``PhishingCandidateSignal`` rows recorded under it (that is what ``score_pending``
is for), while the thresholds are how noisy an operator is willing to let their
channel be — the difference between "alert me" and "tell me once a day" is a
deployment's own policy, not a fact about a lookalike.

Callers own the transaction: ``record_signal``, ``forget_signal``,
``record_stored_signals`` and ``score_candidate`` flush, and the ingestion path that
calls them commits once at the end, so a candidate and its signals are written
together. ``score_pending`` is the exception — it is a maintenance pass with no
surrounding transaction, so it commits what it rewrote.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Literal, Mapping

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.phishing import PhishingCandidateSignal, PhishingDomain
from app.models.source_observation import SourceObservation
from app.services.alert_policy import AlertPolicy, policy_from_environment
from app.services.phishing.age import domain_age_days

#: A candidate's recorded signals: signal name to the value that was observed.
Facts = Mapping[str, Any]

#: Confidence in the table the list, the filter and the alert read.
Band = Literal["direct", "digest", "list"]

#: Text a provider or a connector may report in place of a boolean. A published
#: ``"false"`` is not a present fact, and reading it as one would score a false
#: negative as evidence.
_NOT_TRUE = frozenset({"", "0", "false", "no", "none", "null", "off"})

#: The thresholds §4.4 states, named because two places have to agree on them: the
#: rule that weights the fact, and the derivation that reads the fact out of stored
#: data (:func:`record_stored_signals`). A rule and a derivation that disagree by a
#: day would record a signal the same release does not score.
YOUNG_DOMAIN_DAYS = 60
AGED_DOMAIN_DAYS = 730
HTML_SIMILARITY_MIN = 0.8
SOURCE_CORROBORATION_MIN = 2

#: Where a signal derived from the platform's own stored data comes from. The
#: evidence row's ``source`` distinguishes that from a connector's report of the
#: same fact, which is what lets one be retracted without touching the other.
PLATFORM_SOURCE = "platform"

#: Which signal a *stored provider observation* supports, as signal -> the
#: capabilities that state it. The capability is the question the connector asked, and
#: each capability here is the fact its rule is named after: a page the provider found
#: by ``http.title:"<brand>"`` is a page whose title carried the brand, and an icon it
#: found through its own perceptual hash is an icon that matches ours by one of those.
#: The mapping lives here rather than in the connectors because the score is the
#: platform's own statement about its evidence, and two connectors that answered the
#: same question must not score differently. An exact byte-for-byte icon match
#: (capability ``favicon``) is deliberately absent: what §4.4 weighs is the perceptual
#: rule, and storing the stronger fact under that name would misstate the evidence.
OBSERVATION_SIGNALS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("title_match", ("title",)),
    ("brand_in_body", ("body", "html")),
    ("favicon_perceptual_match", ("favicon_similar",)),
)

#: The fact a connector reports when the free enrichment read a look-alike's page
#: title and it carried the brand. It is a fact and not a capability because the
#: lookup's question is "what is this host", and the answer is what the connector
#: compared — the platform records what was observed instead of re-deriving it.
BRAND_IN_TITLE = "brand_in_title"

#: Reported *facts* (metadata keys) that a rule of §4.4 is named after, as key ->
#: signal. Different from :data:`OBSERVATION_SIGNALS` on purpose: a capability says
#: which question was asked, and a fact says what the connector measured while
#: answering it. Both end up in the same place — the fact is stored with the evidence
#: and the *platform* decides it is worth points — so a connector cannot score
#: anything by inventing a key; an undeclared key is evidence and nothing else.
#: ``mx_without_spf`` is the one whose name is also the rule's, because the connector
#: answers both halves of that rule itself (mail servers, then the SPF policy).
REPORTED_FACT_SIGNALS: tuple[tuple[str, str], ...] = (
    (BRAND_IN_TITLE, "title_match"),
    ("mx_without_spf", "mx_without_spf"),
)

#: Every signal this module derives from stored observations. Declared once so the
#: reconciliation loop cannot cover the capabilities and forget the facts (or the
#: other way around), which would leave a signal that is recorded and never retracted.
OBSERVATION_SIGNAL_NAMES: tuple[str, ...] = tuple(
    name for name, _ in OBSERVATION_SIGNALS
) + tuple(
    signal for _fact, signal in REPORTED_FACT_SIGNALS
)

#: Registration and resale operators whose name, seen in the stored WHOIS fields,
#: means the domain is listed rather than in use (WI-09). Matched as a case-folded
#: substring of the registrar or the abuse contact, and the operator that matched is
#: recorded as the signal's value — a hint an analyst can check, not a verdict. The
#: list is knowledge about the domain market rather than a deployment's policy, so it
#: is a constant here; a registration that names none of these records no hint.
PARKING_OPERATORS: tuple[str, ...] = (
    "above.com",
    "afternic",
    "bodis",
    "brandbucket",
    "cashparking",
    "dan.com",
    "hugedomains",
    "parkingcrew",
    "sedo",
    "squadhelp",
    "undeveloped",
)


def _number(value: Any) -> float | None:
    """A float, when the value is a number. Booleans are not numbers here.

    ``True`` is an ``int`` in Python, and a boolean signal that reached a numeric
    rule by mistake would score as 1 — the sort of quiet mistyping this module
    refuses everywhere else.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _count(value: Any) -> int | None:
    """A whole number, when the value is one: a count of sources, days or ports."""
    number = _number(value)
    if number is None or not number.is_integer():
        return None
    return int(number)


def _below(limit: float) -> Callable[[Any], bool]:
    """A numeric threshold, in one direction: fires under ``limit``.

    The value has to *be* a number. `(_count(value) or 0) < 60` would read a value
    the rule cannot measure — a missing key, or a provider publishing the fact as a
    word — as zero, which is the most suspicious value there is: a fact nobody
    observed would score a candidate as brand new.
    """

    def fires(value: Any) -> bool:
        number = _number(value)
        return number is not None and number < limit

    return fires


def _above(limit: float) -> Callable[[Any], bool]:
    """A numeric threshold, in the other direction: fires over ``limit``."""

    def fires(value: Any) -> bool:
        number = _number(value)
        return number is not None and number > limit

    return fires


def _at_least(limit: int) -> Callable[[Any], bool]:
    """A count threshold: fires at or above ``limit`` whole units."""

    def fires(value: Any) -> bool:
        count = _count(value)
        return count is not None and count >= limit

    return fires


def _truthy(value: Any) -> bool:
    """Whether a fact is present at all.

    Absent (``None``), empty and false are all "the platform did not observe this",
    which makes them the same answer for a score. A string is read as one of the
    values its own vocabulary can publish (``"false"``, ``"none"``) rather than as
    a non-empty value — the payload comes from a provider, and ``"false"`` is a
    perfectly ordinary way for one to say no.
    """
    if isinstance(value, str):
        return value.strip().lower() not in _NOT_TRUE
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if value is None:
        return False
    return bool(value)


@dataclass(frozen=True)
class SignalRule:
    """One weight of the additive score, and the fact that makes it fire."""

    #: The name recorded on the candidate and in :class:`PhishingCandidateSignal`.
    name: str
    #: What the signal is worth when it fires. Negative signals are the platform's
    #: way of saying "this looks less like an attack, not more".
    weight: int
    #: Whether the observed value fires the rule. Reads only its own value.
    fires: Callable[[Any], bool]
    #: Why it fired, in the words the list and the message use for an operator.
    reason: str

    def points(self, value: Any) -> int:
        """What this one observation contributes to a candidate's confidence."""
        return self.weight if self.fires(value) else 0


#: The weights of §4.4, in the order the list and the message present them. This is
#: the single source of truth for both :data:`SIGNAL_WEIGHTS` and the scoring pass,
#: so a rule cannot be declared without being scored, or scored without being
#: declared.
SIGNAL_RULES: tuple[SignalRule, ...] = (
    SignalRule(
        "young_domain",
        25,
        _below(YOUNG_DOMAIN_DAYS),
        "registered fewer than 60 days before it was found",
    ),
    SignalRule(
        "mx_without_spf",
        15,
        _truthy,
        "accepts mail and publishes no SPF record",
    ),
    SignalRule(
        "title_match",
        20,
        _truthy,
        "the page title carries the brand",
    ),
    SignalRule(
        "favicon_perceptual_match",
        20,
        _truthy,
        "the favicon matches ours by perceptual hash",
    ),
    SignalRule(
        "html_similarity",
        25,
        _above(HTML_SIMILARITY_MIN),
        "the page body is more than 0.8 similar to ours",
    ),
    SignalRule(
        "brand_in_body",
        15,
        _truthy,
        "the brand name appears in the page body",
    ),
    SignalRule(
        "source_corroboration",
        15,
        _at_least(SOURCE_CORROBORATION_MIN),
        "two or more independent sources reported it",
    ),
    SignalRule(
        "parked_hint",
        -30,
        _truthy,
        "the domain looks parked rather than in use",
    ),
    SignalRule(
        "aged_domain",
        -10,
        _above(AGED_DOMAIN_DAYS),
        "registered more than two years before it was found",
    ),
    SignalRule(
        "tls_issuer_reuse",
        20,
        _truthy,
        "our own certificate issuer answers for this host",
    ),
)

#: The declared weights: signal name to points, for callers that display the table
#: (the API's signal filter, the frontend's explanation of a score).
SIGNAL_WEIGHTS: dict[str, int] = {rule.name: rule.weight for rule in SIGNAL_RULES}

_RULES_BY_NAME: dict[str, SignalRule] = {rule.name: rule for rule in SIGNAL_RULES}

#: The declared range of a confidence, as the list column and the filter show it.
CONFIDENCE_MIN = 0
CONFIDENCE_MAX = 100


def observation_signals(payload: Any) -> dict[str, str]:
    """The signals one stored observation supports, as signal -> what evidenced it.

    Reads the capability the connector recorded and the facts it reported, and answers
    only what the observation itself states — nothing is inferred from a neighbouring
    row, and a capability this platform does not score contributes nothing. The
    evidence value is what the list shows an analyst asking "why does this candidate
    have twenty points?": the question that produced the fact, not a boolean.
    """
    if not isinstance(payload, Mapping):
        return {}
    metadata = payload.get("metadata")
    if not isinstance(metadata, Mapping):
        return {}
    signals: dict[str, str] = {}
    capability = metadata.get("capability")
    if isinstance(capability, str):
        for name, capabilities in OBSERVATION_SIGNALS:
            if capability in capabilities and name not in signals:
                signals[name] = capability
    for key, signal in REPORTED_FACT_SIGNALS:
        if _truthy(metadata.get(key)):
            signals.setdefault(signal, key)
    return signals


async def observation_facts(db: AsyncSession, *, candidate: PhishingDomain) -> dict[str, str]:
    """Everything this candidate's stored provider observations support, merged.

    One observation row per (source, subject, capability), so a candidate two
    questions answered has two rows and the union is what the score reads. The first
    evidence for a signal wins: to the rules the fact is present or absent, what it is
    worth does not depend on how many rows say so, and the weight that *does* count
    sources is ``source_corroboration``, which has a rule of its own.
    """
    payloads = (
        await db.execute(
            select(SourceObservation.payload).where(
                SourceObservation.module == "phishing",
                SourceObservation.candidate_id == candidate.id,
            )
        )
    ).scalars()
    facts: dict[str, str] = {}
    for payload in payloads:
        for name, evidence in observation_signals(payload).items():
            facts.setdefault(name, evidence)
    return facts


def fired_signals(signals: Facts | None) -> dict[str, int]:
    """The rules that fire on ``signals``, and what each contributes.

    The breakdown behind a score, in table order — this is what a list row or an
    alert shows instead of a bare number, and it is computed from the recorded
    facts rather than from the weights that happened to be loaded when the row was
    scored.
    """
    observed = signals or {}
    return {
        name: rule.weight
        for name, rule in _RULES_BY_NAME.items()
        if name in observed and rule.fires(observed[name])
    }


def score_signals(signals: Facts | None) -> int:
    """``Σ weights`` over the signals that fire, clamped to 0…100."""
    total = sum(fired_signals(signals).values())
    return max(CONFIDENCE_MIN, min(CONFIDENCE_MAX, total))


def alert_band(confidence: int, *, policy: AlertPolicy | None = None) -> Band:
    """What the channel should do with a candidate at this confidence.

    The thresholds are read per call, not at import: an operator raising one expects
    the next scan to respect it, not the next release. ``policy`` is the resolved
    alert policy (`app.services.alert_policy`) — the settings row where it states a
    value and the environment where it does not — and the delivery path resolves it
    once per pass and passes it down. Without one the environment answers, which is
    what a pure function with no database can state.

    The policy refuses a digest threshold at or above the direct one (and the
    settings row cannot be saved in that state), so the middle band cannot be
    configured away into silence.
    """
    if policy is None:
        policy = policy_from_environment()
    if confidence >= policy.confidence_direct:
        return "direct"
    if confidence >= policy.confidence_digest:
        return "digest"
    return "list"


async def record_signal(
    db: AsyncSession,
    *,
    candidate: PhishingDomain,
    name: str,
    value: Any,
    source: str | None,
    observed_at: datetime | None = None,
) -> PhishingCandidateSignal:
    """Record one signal on a candidate and rescore it.

    Three writes, one fact: the candidate's summary map gains the observation, its
    stored confidence is recomputed from the whole map, and the evidence row says
    what was seen, what it was worth and who answered. The three cannot drift
    apart because none of them is computed by a caller.

    A repeated observation updates the evidence row for the same signal and source
    instead of appending a second one. A daily scan re-observes the same facts, so
    appending would grow the trail by a row per scan per signal forever while
    saying nothing new, and "why is this candidate at 85?" would have to be
    answered by picking one of thirty rows. Two *different* sources are kept
    apart: that is corroboration, and it is evidence, not an update.

    The unclamped contribution is stored on the evidence row even when the signal
    is worth nothing, so a weight change can be applied to history by
    :func:`score_pending` rather than by re-scanning.

    Raises:
        ValueError: ``name`` is not a declared signal. Recording a fact no rule
            reads would leave it visible in the list and invisible to the score.
    """
    rule = _RULES_BY_NAME.get(name)
    if rule is None:
        raise ValueError(
            f"unknown phishing signal: {name!r}; declared signals are "
            f"{sorted(_RULES_BY_NAME)}"
        )

    if candidate.id is None:
        # The evidence row names the candidate by id, and the ORM's default is
        # applied at INSERT — so an unflushed row has to be flushed first rather
        # than recorded against a null id.
        await db.flush()

    observed = observed_at or datetime.now(timezone.utc)
    points = rule.points(value)

    row = (
        await db.execute(
            select(PhishingCandidateSignal)
            .where(
                PhishingCandidateSignal.candidate_id == candidate.id,
                PhishingCandidateSignal.name == name,
                PhishingCandidateSignal.source == source,
            )
            .limit(1)
        )
    ).scalars().first()
    if row is None:
        row = PhishingCandidateSignal(
            candidate_id=candidate.id,
            name=name,
            value=value,
            confidence=points,
            observed_at=observed,
            source=source,
        )
        db.add(row)
    else:
        row.value = value
        row.confidence = points
        row.observed_at = observed

    # Reassignment, not mutation: SQLAlchemy tracks the attribute, and a JSON
    # column mutated in place would not be written back.
    candidate.signals = {**(candidate.signals or {}), name: value}
    candidate.confidence = score_signals(candidate.signals)
    await db.flush()
    return row


async def forget_signal(
    db: AsyncSession,
    *,
    candidate: PhishingDomain,
    name: str,
    source: str | None,
) -> bool:
    """Retract one signal as one source last recorded it, and rescore the candidate.

    A signal that is re-observed has to be able to stop applying. A registration
    that named a marketplace when the WHOIS lookup ran and names a registrar today is
    no longer parked, and the hint from last month would otherwise keep subtracting
    from the score while nothing supports it — a stale fact scoring forever is worse
    than no signal, because the list explains it as current evidence.

    Retraction is per source. The evidence row that is dropped is the one this source
    wrote; if another source still stands behind the same signal, the candidate's
    summary keeps that evidence's value, since removing the key would take away a
    contribution whose row is still there. The signal's history is not lost — what
    the platform was told and when lives in the ingestion events and the audit log,
    which is where an investigation reads it.

    Returns whether anything was retracted.
    """
    rows = list(
        (
            await db.execute(
                select(PhishingCandidateSignal).where(
                    PhishingCandidateSignal.candidate_id == candidate.id,
                    PhishingCandidateSignal.name == name,
                    PhishingCandidateSignal.source == source,
                )
            )
        ).scalars()
    )
    if not rows:
        return False

    for row in rows:
        await db.delete(row)
    await db.flush()

    remaining = list(
        (
            await db.execute(
                select(PhishingCandidateSignal).where(
                    PhishingCandidateSignal.candidate_id == candidate.id,
                    PhishingCandidateSignal.name == name,
                )
            )
        ).scalars()
    )
    signals = dict(candidate.signals or {})
    if remaining:
        latest = max(
            remaining,
            key=lambda row_: row_.observed_at
            or datetime.min.replace(tzinfo=timezone.utc),
        )
        signals[name] = latest.value
    else:
        signals.pop(name, None)
    candidate.signals = signals
    candidate.confidence = score_signals(signals)
    await db.flush()
    return True


def parking_operator(candidate: PhishingDomain) -> str | None:
    """The resale/parking operator the stored registration names, if any (WI-09).

    Read from the WHOIS fields the platform already stores rather than from a new
    query: a domain registered through a marketplace is listed for sale — which is
    what "parked" means for triage — and that is visible in the registrar or the
    abuse contact the enrichment pass recorded. Nothing stored names one of them
    returns ``None``, and the value that is recorded is the operator that matched, so
    the list shows *why* the hint fired rather than a bare ``true``.
    """
    text = " ".join(
        str(value).casefold()
        for value in (candidate.whois_registrar, candidate.whois_abuse_email)
        if value
    )
    if not text:
        return None
    return next((name for name in PARKING_OPERATORS if name in text), None)


async def record_stored_signals(
    db: AsyncSession,
    *,
    candidate: PhishingDomain,
) -> dict[str, int]:
    """Record every signal the platform can answer for from what it already holds.

    Three of §4.4's weights need no provider and no new query, which is why they can
    be applied the moment a candidate is stored instead of waiting for wave 4:

    * the registration age, from the timestamp the WHOIS enrichment pass resolved
      (``young_domain`` / ``aged_domain``);
    * how many independent sources reported the candidate, counted from
      ``source_observations`` — the corroboration that separates a look-alike one
      provider noticed from one three did (``source_corroboration``);
    * whether the stored registration names a resale or parking operator
      (``parked_hint``).

    The facts a *provider* reported are reconciled in the same pass, out of the
    observation rows that stored them: a page a provider found by matching the brand
    in its title is a ``title_match``, one it found through its own perceptual icon
    hash is a ``favicon_perceptual_match`` (see :data:`OBSERVATION_SIGNALS`), and a
    candidate that accepts mail without publishing an SPF policy is an
    ``mx_without_spf`` (see :data:`REPORTED_FACT_SIGNALS`). No provider is called for
    any of it — the connectors already paid for the answer, and scoring it twice would
    be paying twice.

    Facts are re-observed rather than reported once, so this reconciles instead of
    appending: a signal that no longer holds is retracted as well as a new one
    recorded, and that applies to the provider-backed ones too — a candidate the
    module stops seeing in a title search is not still a title match. An unknown
    registration date retracts the age signals for the same reason: silence is not
    evidence, and a candidate whose date was never resolved must not keep the score an
    earlier lookup gave it. The retraction only reaches signals this platform
    *derived*: the evidence rows a connector wrote stay where they are, so what the
    provider said and when is still readable.

    Returns the signals that fire afterwards, in table order, which is what the
    caller would otherwise recompute to decide how loudly to report the candidate.
    """
    age = domain_age_days(candidate.domain_created_at)
    if age is not None and age < YOUNG_DOMAIN_DAYS:
        current = "young_domain"
    elif age is not None and age > AGED_DOMAIN_DAYS:
        current = "aged_domain"
    else:
        current = None

    for name in ("young_domain", "aged_domain"):
        if name == current:
            await record_signal(
                db,
                candidate=candidate,
                name=name,
                value=age,
                source=PLATFORM_SOURCE,
            )
        else:
            await forget_signal(
                db, candidate=candidate, name=name, source=PLATFORM_SOURCE
            )

    corroborating = {
        source
        for source in (
            await db.execute(
                select(SourceObservation.source)
                .where(
                    SourceObservation.module == "phishing",
                    SourceObservation.candidate_id == candidate.id,
                )
                .distinct()
            )
        ).scalars()
        if source
    }
    await record_signal(
        db,
        candidate=candidate,
        name="source_corroboration",
        value=len(corroborating),
        source=PLATFORM_SOURCE,
    )

    operator = parking_operator(candidate)
    if operator:
        await record_signal(
            db,
            candidate=candidate,
            name="parked_hint",
            value=operator,
            source=PLATFORM_SOURCE,
        )
    else:
        await forget_signal(
            db, candidate=candidate, name="parked_hint", source=PLATFORM_SOURCE
        )

    reported = await observation_facts(db, candidate=candidate)
    for name in OBSERVATION_SIGNAL_NAMES:
        if name in reported:
            await record_signal(
                db,
                candidate=candidate,
                name=name,
                value=reported[name],
                source=PLATFORM_SOURCE,
            )
        else:
            await forget_signal(
                db, candidate=candidate, name=name, source=PLATFORM_SOURCE
            )

    return dict(fired_signals(candidate.signals))


async def score_candidate(
    db: AsyncSession,
    *,
    candidate: PhishingDomain,
    signals: Facts | None = None,
) -> int:
    """Recompute a candidate's confidence from its recorded signals.

    Passing ``signals`` answers a hypothetical — "what would this candidate be
    worth with a matching favicon?" — without touching the row, which is what the
    API needs to preview a filter. Scoring the candidate's own map is the write
    path: the stored confidence and the signals it is derived from are updated
    together, so the number in the list always has the facts behind it.
    """
    if signals is not None:
        return score_signals(signals)
    total = score_signals(candidate.signals)
    candidate.confidence = total
    await db.flush()
    return total


async def score_pending(
    db: AsyncSession,
    candidate_ids: Iterable[Any] | None = None,
) -> int:
    """Rescore stored candidates and return how many scores moved.

    What this is for: the weights of §4.4 are code, and a release that changes one
    leaves every existing row holding a score that was computed under the old
    table. Rescoring from the recorded signals is what keeps the column honest
    without re-running a scan, and the returned count is the only way a maintenance
    run can say how much of the list a changed weight actually moved.

    Candidates with no signals are skipped rather than counted: there is nothing to
    recompute, and a row already at its score is not rewritten either — which is
    what makes a second pass a reported no-op. ``candidate_ids`` narrows the pass to
    the rows a caller knows changed; the whole list is the default because a weight
    change applies to all of it.
    """
    query = select(PhishingDomain)
    if candidate_ids is not None:
        query = query.where(PhishingDomain.id.in_(list(candidate_ids)))

    rewritten = 0
    for row in (await db.execute(query)).scalars():
        if not row.signals:
            continue
        total = score_signals(row.signals)
        if total != row.confidence:
            row.confidence = total
            rewritten += 1

    # The pass has no surrounding transaction to join: it is a maintenance run, and
    # a rescore it reported as done must survive its own return.
    await db.commit()
    return rewritten
