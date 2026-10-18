"""Scoring the facts a *provider* reported, out of the evidence already stored.

Wave 1 recorded the weights of §4.4 and produced three of them from what the
platform holds by itself (registration age, corroboration, parking). The rest —
the brand in a page title, the brand in a page body, our icon matched by a
provider's perceptual hash — are facts a connector learns while scanning, and
wave 2 started storing them as observations: a certificate that claims the brand,
a registration record, a mail answer, and (wave 3) the page body, the page title
and the enrichment of a look-alike host.

Storing them was not scoring them: a candidate found by a title search sat next
to one found by an address match with the same confidence, because nothing read
the capability back off the evidence row. These tests pin the mapping that closes
that gap, and the two properties it has to keep:

* **the capability is the fact.** Only a question that *is* the rule fires it — a
  page found by matching our brand in its title is a ``title_match``; the same page
  found by a mail question is not;
* **evidence can be withdrawn.** Re-running the derivation with no observation for
  a signal retracts it, so a candidate the module stops seeing in a title search
  does not keep the twenty points a title match is worth.
"""

import uuid

import pytest
from sqlalchemy import select

from app.models import Connector
from app.models.phishing import PhishingCandidateSignal, PhishingDomain
from app.models.source_observation import SourceObservation
from app.services.ingestion_service import ingest_findings
from app.services.phishing_score_service import (
    observation_facts,
    observation_signals,
    record_stored_signals,
)


def finding(**overrides) -> dict:
    base = {"phishing_domain": "look-alike.example", "matched_asset": "brand.example"}
    base.update(overrides)
    return base


async def phishing_connector(db) -> Connector:
    connector = Connector(
        name=f"shodan-phishing-{uuid.uuid4().hex[:8]}",
        connector_type="phishing",
        default_job_type="phishing.shodan",
        status="enabled",
    )
    db.add(connector)
    await db.flush()
    return connector


async def feed(db, connector, item) -> str:
    result = await ingest_findings(db, connector=connector, job_id=None, findings=[item])
    await db.commit()
    if result.created:
        return "created"
    if result.rejected:
        return "rejected"
    return "updated" if result.updated else "unchanged"


def test_the_capability_is_the_fact_and_nothing_else_is_read():
    assert observation_signals({"metadata": {"capability": "title"}}) == {
        "title_match": "title"
    }
    assert observation_signals({"metadata": {"capability": "body"}}) == {
        "brand_in_body": "body"
    }
    assert observation_signals({"metadata": {"capability": "favicon_similar"}}) == {
        "favicon_perceptual_match": "favicon_similar"
    }
    # The enrichment compares the page title it read against the operators' brands
    # itself, and reports that as a fact rather than as a capability.
    assert observation_signals({"metadata": {"brand_in_title": True}}) == {
        "title_match": "brand_in_title"
    }
    # A reported *fact* is scored only where a rule of §4.4 is named after it, and the
    # mail pair is answered by the connector itself: servers plus a policy question.
    assert observation_signals(
        {"metadata": {"capability": "mx", "mx_hosts": ["mx1.example"], "mx_without_spf": True}}
    ) == {"mx_without_spf": "mx_without_spf"}
    assert observation_signals(
        {"metadata": {"capability": "mx", "mx_hosts": ["mx1.example"], "mx_spy": True}}
    ) == {}
    # A question this platform does not score contributes nothing rather than
    # something: a certificate claiming the brand is evidence, not a §4.4 weight.
    assert observation_signals({"metadata": {"capability": "certificate_brand"}}) == {}
    # Not-a-dict payloads (an old row, a hand-written fixture) are refused, not
    # guessed at.
    assert observation_signals(None) == {}
    assert observation_signals({"metadata": "title"}) == {}
    # A published "false" is not a present fact: reading it as one would score a
    # negative answer as evidence.
    assert observation_signals({"metadata": {"brand_in_title": "false"}}) == {}


@pytest.mark.asyncio
async def test_a_title_search_scores_the_candidate_it_found(db_session):
    connector = await phishing_connector(db_session)
    assert await feed(db_session, connector, finding()) == "created"
    first = (
        await db_session.execute(
            select(PhishingDomain).where(PhishingDomain.phishing_domain == "look-alike.example")
        )
    ).scalar_one()
    # One source is not corroboration, and the derivation records the count it
    # measured rather than only the facts that fire: the value is what the list
    # explains the score with (WI-07).
    assert first.signals == {"source_corroboration": 1}
    assert first.confidence == 0

    # The same candidate, this time found by a question whose answer *is* the rule:
    # the page title carried the brand.
    await feed(
        db_session,
        connector,
        finding(metadata={"capability": "title", "provider": "shodan"}),
    )
    await db_session.refresh(first)
    assert first.signals.get("title_match") == "title"
    assert first.confidence == 20

    # A second provider answering the same question is corroboration, not a second
    # title match: the weight is per fact, and the rule that counts sources has one.
    await feed(
        db_session,
        connector,
        finding(metadata={"capability": "favicon_similar", "provider": "netlas"}),
    )
    await db_session.refresh(first)
    assert first.signals.get("favicon_perceptual_match") == "favicon_similar"
    assert first.confidence == 40

    rows = list(
        (
            await db_session.execute(
                select(PhishingCandidateSignal).where(
                    PhishingCandidateSignal.candidate_id == first.id
                )
            )
        ).scalars()
    )
    assert {(row.name, row.confidence) for row in rows} == {
        ("title_match", 20),
        ("favicon_perceptual_match", 20),
        # The platform's own derivation still runs beside the provider-backed ones.
        ("source_corroboration", 0),
    }


@pytest.mark.asyncio
async def test_mail_facts_from_a_second_source_score_the_same_rule(db_session):
    """The MX rule is answered by whichever connector can answer both halves.

    The DNSTwist worker reports ``mx_without_spf`` from the CLI's MX check plus one
    free TXT question, and the platform scores it through the same table a provider's
    capability goes through — the source of the fact changes who pays for it, not what
    it is worth.
    """
    connector = await phishing_connector(db_session)
    await feed(db_session, connector, finding())
    row = (
        await db_session.execute(
            select(PhishingDomain).where(PhishingDomain.phishing_domain == "look-alike.example")
        )
    ).scalar_one()
    await feed(
        db_session,
        connector,
        finding(
            metadata={
                "capability": "mx",
                "mx_hosts": ["mx1.example"],
                "mx_spy": True,
                "mx_without_spf": True,
            }
        ),
    )
    await db_session.refresh(row)
    # The value is the evidence, not a bare boolean: the list explains the score with
    # the fact that produced it, exactly as a capability-mapped signal does.
    assert row.signals.get("mx_without_spf") == "mx_without_spf"
    assert row.confidence == 15


@pytest.mark.asyncio
async def test_provider_evidence_is_reconciled_and_a_withdrawn_fact_stops_scoring(db_session):
    connector = await phishing_connector(db_session)
    await feed(db_session, connector, finding())
    row = (
        await db_session.execute(
            select(PhishingDomain).where(PhishingDomain.phishing_domain == "look-alike.example")
        )
    ).scalar_one()
    await feed(db_session, connector, finding(metadata={"capability": "body"}))
    await db_session.refresh(row)
    assert row.confidence == 15
    assert await observation_facts(db_session, candidate=row) == {"brand_in_body": "body"}

    # The evidence row goes away (an operator deletes what a source reported). The
    # derived signal has to go with it: a fact nobody states any more cannot keep
    # scoring, and the list would otherwise explain a score with evidence that is
    # not there.
    observations = list(
        (
            await db_session.execute(
                select(SourceObservation).where(SourceObservation.candidate_id == row.id)
            )
        ).scalars()
    )
    reported = [
        item
        for item in observations
        if (item.payload or {}).get("metadata", {}).get("capability") == "body"
    ]
    assert len(reported) == 1
    await db_session.delete(reported[0])
    await db_session.flush()
    await record_stored_signals(db_session, candidate=row)
    await db_session.commit()
    await db_session.refresh(row)
    assert "brand_in_body" not in (row.signals or {})
    assert row.confidence == 0
