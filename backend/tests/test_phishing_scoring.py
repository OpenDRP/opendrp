"""The additive confidence score and the alert bands it drives (WI-07/WI-08, W1.2).

Today every candidate a worker reports is worth the same: the module has one
severity and one message per run, so eighty parked lookalikes and the one clone of
the login page that already carries our certificate issuer arrive looking identical
(F-08 in the phishing audit). WI-08 replaces that with a score an analyst can audit
by hand — ``confidence = Σ weights`` — and a band per score that decides whether the
channel stays quiet, digests, or interrupts someone.

These tests pin the three things that make such a score trustworthy rather than
merely present: every weight of the audit's §4.4 fires on its own fact and never on
a missing one, the total is clamped to the declared range so no combination of
signals can produce a number the list cannot show, and the facts behind the number
survive as rows, so "why is this candidate at 85?" is answered from data instead of
by re-deriving today's weights.

The thresholds are asserted through the settings object rather than as literals,
because the shipped default is the value an operator may raise without a release.
"""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models.phishing import PhishingCandidateSignal, PhishingDomain
from app.models.source_observation import SourceObservation
from app.services import phishing_score_service as scoring


async def candidate(db, **overrides) -> PhishingDomain:
    """A stored candidate, with only the fields these tests care about set."""
    values = {
        "phishing_domain": "evil.example.com",
        "matched_asset": "example.com",
        "detection_source": "dnstwist",
    }
    values.update(overrides)
    row = PhishingDomain(**values)
    db.add(row)
    await db.flush()
    return row


async def evidence(db, row) -> list[PhishingCandidateSignal]:
    """The signal rows recorded for one candidate, in name order."""
    rows = (
        await db.execute(
            select(PhishingCandidateSignal)
            .where(PhishingCandidateSignal.candidate_id == row.id)
            .order_by(PhishingCandidateSignal.name)
        )
    ).scalars()
    return list(rows)


#: One entry per rule of §4.4: the fact that fires it and the points it adds.
FIRING_SIGNALS = (
    ("young_domain", 12, 25),
    ("mx_without_spf", True, 15),
    ("title_match", True, 20),
    ("favicon_perceptual_match", True, 20),
    ("html_similarity", 0.93, 25),
    ("brand_in_body", True, 15),
    ("source_corroboration", 3, 15),
    ("parked_hint", True, -30),
    ("aged_domain", 900, -10),
    ("tls_issuer_reuse", True, 20),
)

#: Facts whose own value falls outside their rule. They are stored anyway — the
#: list has to be able to explain a zero — and contribute nothing.
BELOW_THRESHOLD = (
    ("young_domain", 400),
    ("html_similarity", 0.5),
    ("source_corroboration", 1),
    ("mx_without_spf", False),
    ("title_match", False),
    ("favicon_perceptual_match", False),
    ("brand_in_body", False),
    ("parked_hint", False),
    ("aged_domain", 100),
    ("tls_issuer_reuse", False),
)


def test_the_declared_weights_are_the_audits_weights():
    """The table is exactly §4.4: nothing added, nothing renamed, nothing dropped."""
    assert scoring.SIGNAL_WEIGHTS == {
        name: weight for name, _, weight in FIRING_SIGNALS
    }


@pytest.mark.parametrize(("name", "value", "weight"), FIRING_SIGNALS)
def test_each_rule_fires_on_its_own_fact(name, value, weight):
    assert scoring.fired_signals({name: value}) == {name: weight}
    assert scoring.fired_signals({name: value}) != scoring.fired_signals({})


@pytest.mark.parametrize(("name", "value"), BELOW_THRESHOLD)
def test_each_rule_stays_quiet_below_its_threshold(name, value):
    assert scoring.fired_signals({name: value}) == {}


#: Every rule that measures something by its value.
MEASURED_SIGNALS = (
    "young_domain",
    "html_similarity",
    "source_corroboration",
    "aged_domain",
)

#: Every rule that fires on a fact being present.
PRESENCE_SIGNALS = (
    "mx_without_spf",
    "title_match",
    "favicon_perceptual_match",
    "brand_in_body",
    "parked_hint",
    "tls_issuer_reuse",
)


@pytest.mark.parametrize("name", MEASURED_SIGNALS)
@pytest.mark.parametrize("value", [None, "", "unknown", "recent", [], {}, True, False])
def test_a_measured_rule_never_fires_on_a_value_it_cannot_measure(name, value):
    """`unknown` is not `0`, and a boolean is not the count it looks like.

    `(_count(value) or 0) < 60` reads the smallest possible age out of a value the
    rule could not read at all — the most suspicious answer there is, invented from
    a fact nobody observed. A provider publishing `"unknown"` gets silence here, and
    `True` is a boolean rather than the `1` Python would count it as.
    """
    assert scoring.fired_signals({name: value}) == {}


@pytest.mark.parametrize("name", PRESENCE_SIGNALS)
@pytest.mark.parametrize("value", ["false", "FALSE", "no", "off", "0", "none", ""])
def test_a_fact_published_as_a_false_word_is_not_a_present_fact(name, value):
    """A provider saying no in words is still saying no.

    The payload is external input: reading the string `"false"` as a present fact
    would score a rule review from a provider that answered `false`.
    """
    assert scoring.fired_signals({name: value}) == {}
    assert scoring.fired_signals({name: "true"}) == {name: scoring.SIGNAL_WEIGHTS[name]}


@pytest.mark.parametrize(("name", "value", "weight"), FIRING_SIGNALS)
@pytest.mark.asyncio
async def test_a_signal_is_recorded_with_what_it_contributed(
    db_session, name, value, weight
):
    """The score of a candidate is the weight of the fact that was observed."""
    row = await candidate(db_session)

    await scoring.record_signal(
        db_session, candidate=row, name=name, value=value, source="dnstwist"
    )

    assert row.signals == {name: value}
    assert row.confidence == max(0, min(100, weight))
    recorded = await evidence(db_session, row)
    assert len(recorded) == 1
    assert recorded[0].name == name
    assert recorded[0].value == value
    # The unclamped contribution: what this one fact was worth, so the total can
    # be re-derived after the weights change.
    assert recorded[0].confidence == weight
    assert recorded[0].source == "dnstwist"
    assert recorded[0].observed_at is not None


@pytest.mark.asyncio
async def test_the_signals_add_up(db_session):
    """§4.4 is additive: two facts are worth their sum."""
    row = await candidate(db_session)
    for name, value in (("young_domain", 10), ("tls_issuer_reuse", True)):
        await scoring.record_signal(
            db_session, candidate=row, name=name, value=value, source="probe"
        )

    assert row.signals == {"young_domain": 10, "tls_issuer_reuse": True}
    assert row.confidence == 45
    assert await scoring.score_candidate(db_session, candidate=row) == 45


@pytest.mark.asyncio
async def test_every_signal_at_once_is_clamped_to_the_declared_maximum(db_session):
    """The list column is a 0…100 figure, so the sum has to stay one."""
    row = await candidate(db_session)
    for name, value, _ in FIRING_SIGNALS:
        if name != "aged_domain":  # Contradicts `young_domain`; one of them is false.
            await scoring.record_signal(
                db_session, candidate=row, name=name, value=value, source="probe"
            )

    assert 25 + 15 + 20 + 20 + 25 + 15 + 15 - 30 + 20 == 125
    assert row.confidence == 100
    assert scoring.alert_band(row.confidence) == "direct"


@pytest.mark.asyncio
async def test_a_negative_signal_cannot_drive_the_score_below_zero(db_session):
    """A parked lookalike with nothing else going for it is a 0, not a −30."""
    row = await candidate(db_session)

    await scoring.record_signal(
        db_session, candidate=row, name="parked_hint", value=True, source="dnstwist"
    )

    assert row.confidence == 0
    assert row.signals == {"parked_hint": True}
    assert (await evidence(db_session, row))[0].confidence == -30


@pytest.mark.asyncio
async def test_a_candidate_without_signals_scores_zero(db_session):
    """No fact observed is the honest score, and the row still exists."""
    row = await candidate(db_session)

    assert await scoring.score_candidate(db_session, candidate=row) == 0
    assert row.signals == {}
    assert row.confidence == 0
    assert scoring.fired_signals({}) == {}


@pytest.mark.parametrize(("name", "value"), BELOW_THRESHOLD)
@pytest.mark.asyncio
async def test_a_fact_below_its_threshold_is_stored_and_scores_nothing(
    db_session, name, value
):
    row = await candidate(db_session)

    await scoring.record_signal(
        db_session, candidate=row, name=name, value=value, source="probe"
    )

    assert row.confidence == 0
    # Stored, not discarded: "we looked, and it did not match" is a finding too.
    assert row.signals == {name: value}
    assert scoring.alert_band(row.confidence) == "list"


@pytest.mark.asyncio
async def test_a_fact_the_weights_do_not_know_is_refused(db_session):
    """The recorded set and the scored set are the same set.

    A typo — `young-domain`, or a fact recorded before a rule for it exists —
    would otherwise be stored, shown in the list's signal column, and contribute
    nothing: the silent mismatch the table exists to prevent.
    """
    row = await candidate(db_session)

    with pytest.raises(ValueError, match="young-domain"):
        await scoring.record_signal(
            db_session, candidate=row, name="young-domain", value=1, source="typo"
        )

    assert row.signals == {}
    assert scoring.fired_signals({"young-domain": 1}) == {}


@pytest.mark.asyncio
async def test_re_observing_a_signal_updates_its_row_instead_of_piling_up(db_session):
    """A daily scan re-observes the same fact; the trail stays readable.

    The second observation is the interesting one: a signal that did not reach its
    threshold yesterday and does today has to start counting, from one row that
    says what is true now — not from two rows whose only difference is the date.
    """
    row = await candidate(db_session)
    observed_at = datetime.now(timezone.utc)

    await scoring.record_signal(
        db_session,
        candidate=row,
        name="html_similarity",
        value=0.5,
        source="dnstwist",
        observed_at=observed_at,
    )
    assert row.confidence == 0

    await scoring.record_signal(
        db_session,
        candidate=row,
        name="html_similarity",
        value=0.9,
        source="dnstwist",
        observed_at=observed_at,
    )

    recorded = await evidence(db_session, row)
    assert len(recorded) == 1
    assert recorded[0].value == 0.9
    assert recorded[0].confidence == 25
    assert row.signals == {"html_similarity": 0.9}
    assert row.confidence == 25


@pytest.mark.asyncio
async def test_two_sources_reporting_one_signal_are_two_rows(db_session):
    """The other half of the same rule: different evidence is not an update."""
    row = await candidate(db_session)
    await scoring.record_signal(
        db_session, candidate=row, name="brand_in_body", value=True, source="netlas"
    )
    await scoring.record_signal(
        db_session, candidate=row, name="brand_in_body", value=True, source="shodan"
    )

    recorded = await evidence(db_session, row)
    assert sorted(row_.source for row_ in recorded) == ["netlas", "shodan"]
    # The candidate's own score counts the fact once, whichever source saw it.
    assert row.signals == {"brand_in_body": True}
    assert row.confidence == 15


@pytest.mark.asyncio
async def test_scoring_a_hypothetical_leaves_the_stored_row_alone(db_session):
    """`signals=` answers "what would this be worth" without rewriting history."""
    row = await candidate(db_session)
    await scoring.record_signal(
        db_session, candidate=row, name="young_domain", value=10, source="whois"
    )

    assert await scoring.score_candidate(
        db_session, candidate=row, signals={"tls_issuer_reuse": True}
    ) == 20
    assert row.confidence == 25
    assert row.signals == {"young_domain": 10}


@pytest.mark.asyncio
async def test_rescoring_rewrites_only_the_rows_whose_score_moved(db_session):
    """A weight change is applied by rescoring, not by waiting for the next scan.

    The pass reports what it rewrote, so a maintenance run can say how much of the
    list a changed weight actually moved. A candidate with no signals has nothing
    to recompute, and one already at its score is not rewritten either — which is
    what makes a second pass a reported no-op instead of silent work.
    """
    scored = await candidate(db_session, phishing_domain="scored.example.com")
    empty = await candidate(db_session, phishing_domain="empty.example.com")
    await scoring.record_signal(
        db_session, candidate=scored, name="title_match", value=True, source="dnstwist"
    )
    scored.confidence = 0  # What a weight change leaves behind on an old row.
    await db_session.flush()

    assert (
        await scoring.score_pending(db_session, candidate_ids=[scored.id, empty.id]) == 1
    )
    assert scored.confidence == 20
    assert empty.confidence == 0

    assert await scoring.score_pending(db_session) == 0


class TestStoredSignals:
    """The signals the platform can answer for without asking anyone (WI-09, W1.3).

    Three weights of §4.4 are derivable from what is already stored, and they are the
    three that decide most of the score: how old the registration is, how many
    independent sources reported the candidate, and whether the registration names a
    domain marketplace. Deriving them here is also what makes the score available to
    the first alert instead of only after wave 4's providers arrive.
    """

    @pytest.mark.asyncio
    async def test_a_young_registration_scores_and_a_replacement_age_is_observed(
        self, db_session
    ):
        row = await candidate(
            db_session,
            domain_created_at=datetime.now(timezone.utc) - timedelta(days=10),
        )

        # Only the signals that fire are returned: a corroboration count of one is
        # recorded — the list has to be able to explain the zero — but it is not a
        # contribution.
        assert await scoring.record_stored_signals(db_session, candidate=row) == {
            "young_domain": 25
        }
        assert row.confidence == 25
        assert row.signals == {"young_domain": 10, "source_corroboration": 0}

        # The same candidate a few years later: the fact moved, and the score has to
        # follow it rather than keep the weight of the registration it once had.
        row.domain_created_at = datetime.now(timezone.utc) - timedelta(days=800)
        assert await scoring.record_stored_signals(db_session, candidate=row) == {
            "aged_domain": -10
        }
        assert row.signals == {"aged_domain": 800, "source_corroboration": 0}
        assert row.confidence == 0
        # The retracted signal left no evidence behind, and the new one is there.
        assert [row_.name for row_ in await evidence(db_session, row)] == [
            "aged_domain",
            "source_corroboration",
        ]

    @pytest.mark.asyncio
    async def test_an_unresolved_registration_records_no_age_signal(self, db_session):
        """No date is not "registered today": the age signals stay absent."""
        row = await candidate(db_session)

        assert await scoring.record_stored_signals(db_session, candidate=row) == {}
        assert row.signals == {"source_corroboration": 0}
        assert row.confidence == 0

    @pytest.mark.asyncio
    async def test_two_sources_reporting_the_candidate_corroborate_it(self, db_session):
        row = await candidate(db_session)
        for source in ("dnstwist", "netlas"):
            db_session.add(
                SourceObservation(
                    module="phishing",
                    source=source,
                    observation_key=f"key-{source}",
                    subject="evil.example.com",
                    matched_asset="example.com",
                    candidate_id=row.id,
                    first_seen_at=datetime.now(timezone.utc),
                    last_seen_at=datetime.now(timezone.utc),
                    payload={},
                )
            )
        await db_session.flush()

        assert await scoring.record_stored_signals(db_session, candidate=row) == {
            "source_corroboration": 15
        }
        assert row.signals["source_corroboration"] == 2

        # The same provider reporting twice is one source, not two.
        db_session.add(
            SourceObservation(
                module="phishing",
                source="dnstwist",
                observation_key="key-again",
                subject="evil.example.com",
                matched_asset="example.com",
                candidate_id=row.id,
                first_seen_at=datetime.now(timezone.utc),
                last_seen_at=datetime.now(timezone.utc),
                payload={},
            )
        )
        await db_session.flush()
        await scoring.record_stored_signals(db_session, candidate=row)
        assert row.signals["source_corroboration"] == 2

    @pytest.mark.asyncio
    async def test_a_registration_naming_a_marketplace_is_a_parked_hint(self, db_session):
        row = await candidate(db_session, whois_registrar="Sedo.com LLC")

        assert await scoring.record_stored_signals(db_session, candidate=row) == {
            "parked_hint": -30
        }
        # The operator that matched is the value, so the list shows why it fired.
        assert row.signals["parked_hint"] == "sedo"
        assert row.confidence == 0  # Clamped: a lone parked hint is a zero.

        # A registrar that is no longer a marketplace stops subtracting.
        row.whois_registrar = "Example Registrar Pty Ltd"
        assert await scoring.record_stored_signals(db_session, candidate=row) == {}
        assert "parked_hint" not in row.signals

    @pytest.mark.asyncio
    async def test_an_abuse_contact_can_carry_the_hint_too(self, db_session):
        row = await candidate(db_session, whois_abuse_email="abuse@hugedomains.com")

        assert await scoring.record_stored_signals(db_session, candidate=row) == {
            "parked_hint": -30
        }

    @pytest.mark.asyncio
    async def test_forgetting_one_sources_evidence_keeps_anothers(self, db_session):
        """Retraction is per source: the summary follows the evidence that remains.

        A connector and the platform's own derivation can both stand behind one
        signal. Retracting the derivation's copy must not remove the contribution
        whose evidence row is still there — that would make the stored score and the
        rows behind it disagree.
        """
        row = await candidate(db_session)
        await scoring.record_signal(
            db_session, candidate=row, name="title_match", value=True, source="dnstwist"
        )
        await scoring.record_signal(
            db_session,
            candidate=row,
            name="title_match",
            value=True,
            source=scoring.PLATFORM_SOURCE,
        )
        assert row.confidence == 20

        assert (
            await scoring.forget_signal(
                db_session,
                candidate=row,
                name="title_match",
                source=scoring.PLATFORM_SOURCE,
            )
            is True
        )
        assert row.confidence == 20
        assert row.signals == {"title_match": True}
        assert [row_.source for row_ in await evidence(db_session, row)] == ["dnstwist"]

        assert (
            await scoring.forget_signal(
                db_session, candidate=row, name="title_match", source="dnstwist"
            )
            is True
        )
        assert row.signals == {}
        assert row.confidence == 0

    @pytest.mark.asyncio
    async def test_forgetting_a_signal_nobody_recorded_changes_nothing(self, db_session):
        row = await candidate(db_session)

        assert (
            await scoring.forget_signal(
                db_session, candidate=row, name="brand_in_body", source="netlas"
            )
            is False
        )
        assert row.signals == {}


class TestStoredSignalsOnIngest:
    """The same three signals, through the path a connector actually takes."""

    @pytest.mark.asyncio
    async def test_an_ingested_candidate_is_scored_when_it_is_stored(self, db_session):
        from app.models import Connector, PhishingDomain
        from app.services.ingestion_service import ingest_findings

        connector = Connector(
            name="dnstwist-phishing-default",
            connector_type="phishing",
            default_job_type="phishing.dnstwist",
            status="enabled",
        )
        db_session.add(connector)
        await db_session.flush()

        result = await ingest_findings(
            db_session,
            connector=connector,
            job_id=None,
            findings=[{"phishing_domain": "evil.example.com", "matched_asset": "example.com"}],
        )
        await db_session.commit()
        assert result.created == 1

        row = (
            await db_session.execute(
                select(PhishingDomain).where(
                    PhishingDomain.phishing_domain == "evil.example.com"
                )
            )
        ).scalar_one()
        # One source reported it, and no registration date has been resolved yet.
        assert row.signals == {"source_corroboration": 1}
        assert row.confidence == 0


class TestAlertBand:
    """The band is what the channel does: interrupt, digest, or stay quiet."""

    def test_the_shipped_thresholds_split_the_score_into_three_bands(self):
        assert settings.ALERT_CONFIDENCE_DIRECT == 60
        assert settings.ALERT_CONFIDENCE_DIGEST == 30
        assert scoring.alert_band(95) == "direct"
        assert scoring.alert_band(60) == "direct"
        assert scoring.alert_band(59) == "digest"
        assert scoring.alert_band(30) == "digest"
        assert scoring.alert_band(29) == "list"
        assert scoring.alert_band(0) == "list"

    def test_the_thresholds_are_read_at_call_time(self, monkeypatch):
        monkeypatch.setattr(settings, "ALERT_CONFIDENCE_DIRECT", 90)
        monkeypatch.setattr(settings, "ALERT_CONFIDENCE_DIGEST", 45)

        assert scoring.alert_band(90) == "direct"
        assert scoring.alert_band(89) == "digest"
        assert scoring.alert_band(45) == "digest"
        assert scoring.alert_band(44) == "list"

    def test_a_digest_threshold_that_reaches_the_direct_one_refuses_to_load(self):
        """Otherwise the digest band is empty and a configured feature is dead.

        `DIGEST = DIRECT` reads as "digest everything above 60", which is the same
        as saying there is no digest at all: every score that would have been
        digested alerts instead. Refusing it at startup points at the setting
        rather than leaving an operator to wonder why the daily summary never
        arrives.
        """
        from app.core.config import Settings

        with pytest.raises(ValueError, match="ALERT_CONFIDENCE_DIGEST"):
            Settings(ALERT_CONFIDENCE_DIRECT=60, ALERT_CONFIDENCE_DIGEST=60)

        with pytest.raises(ValueError, match="ALERT_CONFIDENCE_DIGEST"):
            Settings(ALERT_CONFIDENCE_DIRECT=60, ALERT_CONFIDENCE_DIGEST=61)
