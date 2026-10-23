"""WHOIS enrichment: every failure path must be survivable.

``WhoisService.enrich`` runs after a phishing finding is persisted, so it is a
*side effect*: a WHOIS outage, a malformed response or a slow registrar must
never fail the ingestion that already succeeded. That is why most of what is
pinned here is "returns quietly and changes nothing".

Also pinned: which value wins when the registrar returns several addresses (an
abuse contact beats a generic one, because that is the address an analyst has to
write to), and that an existing value is never overwritten — re-running
enrichment must not churn a finding.

And the answers that are not facts (WI-25). The service names each of them,
because the caller's next step differs for each: a registry that has had enough
of us is a pause for a whole server, a name nobody registered is an answer worth
re-asking for tomorrow, a budget that expired is a retry, and a row that already
carries the facts is not asked about at all. Telling them apart is what keeps a
refused registry from being retried once per candidate and a completed candidate
from being queried again.
"""

from __future__ import annotations

import datetime as dt
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from whois.parser import PywhoisError

from app.services.phishing import whois_service as whois_module
from app.services.phishing.whois_service import WhoisService


class _Response(dict):
    """A response as python-whois builds it: a mapping with the raw text beside it.

    The text is the only place a refusal is visible — the parser drops the fields
    a record would have, so a refusal and a thin registration look identical by
    the mapping alone.
    """

    def __init__(self, text: str, **fields) -> None:
        super().__init__(**fields)
        self.text = text


class _Threat:
    """Stand-in for a phishing finding row (enrich touches five attributes)."""

    def __init__(
        self,
        *,
        registrar: str | None = None,
        abuse_email: str | None = None,
        created_at: dt.datetime | None = None,
    ) -> None:
        self.phishing_domain = "evil.example"
        self.whois_registrar = registrar
        self.whois_abuse_email = abuse_email
        self.domain_created_at = created_at


def _db() -> AsyncMock:
    db = AsyncMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    return db


def _patch_whois(monkeypatch, payload) -> None:
    """Replace the lookup, not the guard: every hop is the client's business."""
    monkeypatch.setattr(whois_module, "lookup", lambda _domain: payload)


@pytest.fixture(autouse=True)
def _no_outbound_lookup(monkeypatch) -> None:
    """Keep the destination guard out of these tests.

    ``enrich`` calls ``ensure_allowed`` before every lookup, and that call
    resolves the domain over the real resolver. The enrichment shares one budget
    between the guard and the lookup, so a resolver that hangs for the whole
    budget left the finding untouched — the failure this file is not about. The
    destination policy has its own suite (``test_outbound_guard.py``); here the
    guard is inlined to "this host is fine".
    """
    monkeypatch.setattr(
        whois_module, "ensure_allowed", lambda target, port=None: (target,)
    )


@pytest.mark.asyncio
async def test_registrar_abuse_contact_and_creation_date_are_recorded(monkeypatch):
    _patch_whois(
        monkeypatch,
        {
            "registrar": "Example Registrar Inc.",
            "emails": ["support@registrar.example", "abuse@registrar.example"],
            "creation_date": dt.datetime(2019, 4, 3, 12, 0, tzinfo=dt.timezone.utc),
        },
    )
    threat = _Threat()
    db = _db()

    await WhoisService(db).enrich(threat)

    assert threat.whois_registrar == "Example Registrar Inc."
    # The abuse contact beats the generic support address from the same response.
    assert threat.whois_abuse_email == "abuse@registrar.example"
    assert threat.domain_created_at == dt.datetime(2019, 4, 3, 12, 0, tzinfo=dt.timezone.utc)
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once()


@pytest.mark.asyncio
async def test_a_registry_that_has_had_enough_of_us_is_reported_not_stored(monkeypatch):
    """A refusal can be shaped like a record; it must not be stored as one."""
    _patch_whois(
        monkeypatch,
        _Response("WHOIS LIMIT EXCEEDED", registrar="Example Registrar Inc."),
    )
    threat = _Threat()
    db = _db()

    assert await WhoisService(db).enrich(threat) == whois_module.RATE_LIMITED

    # Nothing from a refusal is written: the caller holds the event instead, and a
    # registrar lifted off a rate-limit page would be a fact nobody observed.
    assert threat.whois_registrar is None
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_name_nobody_registered_is_an_answer_rather_than_a_failure(monkeypatch):
    """python-whois raises for "No match for ..."; that is the registry answering."""

    def _no_match(_domain):
        raise PywhoisError('No match for "evil.example".')

    monkeypatch.setattr(whois_module, "lookup", _no_match)
    db = _db()

    assert await WhoisService(db).enrich(_Threat()) == whois_module.NO_RECORD
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_row_that_already_carries_the_facts_is_not_asked_about(monkeypatch):
    """The candidate row is the cache (WI-25): a complete row costs no query."""
    asked: list[str] = []
    monkeypatch.setattr(
        whois_module, "lookup", lambda domain: asked.append(domain) or {}
    )
    threat = _Threat(
        registrar="Original Registrar",
        abuse_email="abuse@original.example",
        created_at=dt.datetime(2001, 1, 1),
    )
    db = _db()

    assert await WhoisService(db).enrich(threat) == whois_module.NOTHING_TO_ASK

    assert asked == []
    db.commit.assert_not_awaited()



@pytest.mark.asyncio
async def test_first_address_is_used_when_none_looks_like_an_abuse_contact(monkeypatch):
    _patch_whois(monkeypatch, {"emails": ["first@registrar.example", "second@registrar.example"]})
    threat = _Threat()

    await WhoisService(_db()).enrich(threat)

    assert threat.whois_abuse_email == "first@registrar.example"


@pytest.mark.asyncio
async def test_a_single_string_address_is_accepted(monkeypatch):
    """Some registrars return a scalar rather than a list."""
    _patch_whois(monkeypatch, {"emails": "abuse@registrar.example"})
    threat = _Threat()

    await WhoisService(_db()).enrich(threat)

    assert threat.whois_abuse_email == "abuse@registrar.example"


@pytest.mark.asyncio
async def test_a_non_string_address_is_stringified(monkeypatch):
    _patch_whois(monkeypatch, {"emails": [("abuse", "registrar.example")]})
    threat = _Threat()

    await WhoisService(_db()).enrich(threat)

    assert threat.whois_abuse_email == "('abuse', 'registrar.example')"


@pytest.mark.asyncio
async def test_a_list_of_creation_dates_uses_the_first(monkeypatch):
    _patch_whois(
        monkeypatch,
        {"creation_date": [dt.datetime(2021, 1, 2, 3, 4, 5), dt.datetime(2022, 6, 7, 8, 9, 10)]},
    )
    threat = _Threat()

    await WhoisService(_db()).enrich(threat)

    assert threat.domain_created_at == dt.datetime(2021, 1, 2, 3, 4, 5)


@pytest.mark.asyncio
async def test_a_textual_creation_date_is_parsed(monkeypatch):
    _patch_whois(monkeypatch, {"creation_date": "2018-07-08 09:10:11"})
    threat = _Threat()

    await WhoisService(_db()).enrich(threat)

    assert threat.domain_created_at == dt.datetime(2018, 7, 8, 9, 10, 11)


@pytest.mark.asyncio
async def test_an_unparseable_creation_date_is_ignored_without_failing(monkeypatch):
    _patch_whois(monkeypatch, {"creation_date": "not a date at all", "registrar": "R"})
    threat = _Threat()

    await WhoisService(_db()).enrich(threat)

    assert threat.domain_created_at is None
    # The rest of the response is still applied.
    assert threat.whois_registrar == "R"


@pytest.mark.asyncio
async def test_existing_values_are_never_overwritten(monkeypatch):
    """A partial row is still asked about, and the provider fills only the blanks."""
    _patch_whois(
        monkeypatch,
        {
            "registrar": "New Registrar",
            "emails": ["abuse@new.example"],
            "creation_date": dt.datetime(2030, 1, 1),
        },
    )
    threat = _Threat(
        registrar="Original Registrar",
        abuse_email="abuse@original.example",
    )
    db = _db()

    assert await WhoisService(db).enrich(threat) == whois_module.ANSWERED

    # The registration date is the fact the row was missing, so the lookup ran for
    # it; the facts the row already had are not churned by what came back.
    assert threat.whois_registrar == "Original Registrar"
    assert threat.whois_abuse_email == "abuse@original.example"
    assert threat.domain_created_at == dt.datetime(2030, 1, 1)
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_long_values_are_truncated_to_the_column_width(monkeypatch):
    _patch_whois(
        monkeypatch,
        {"registrar": "R" * 400, "emails": ["a" * 400 + "@x.example"]},
    )
    threat = _Threat()

    await WhoisService(_db()).enrich(threat)

    assert len(threat.whois_registrar) == 255
    assert len(threat.whois_abuse_email) == 255


@pytest.mark.asyncio
async def test_a_registrar_lookup_failure_leaves_the_finding_untouched(monkeypatch):
    def _boom(_domain):
        raise RuntimeError("whois server unreachable")

    monkeypatch.setattr(whois_module, "lookup", _boom)
    threat = _Threat()
    db = _db()

    await WhoisService(db).enrich(threat)

    assert threat.whois_registrar is None
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_an_empty_response_is_a_no_op(monkeypatch):
    _patch_whois(monkeypatch, None)
    db = _db()

    # No answer arrived, which is not the same as an answer of "nothing": the
    # caller may ask again, with a bound.
    assert await WhoisService(db).enrich(_Threat()) == whois_module.UNAVAILABLE
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_slow_registrar_is_abandoned_instead_of_delaying_ingestion(monkeypatch):
    """The 3s budget is what keeps this off the ingestion critical path."""
    _patch_whois(monkeypatch, {"registrar": "Too Slow Ltd."})

    async def _timeout(awaitable, timeout=None):  # noqa: ASYNC109 - stand-in
        # Close the coroutine we are refusing to await, then behave like wait_for.
        awaitable.close()
        raise TimeoutError

    fake_asyncio = SimpleNamespace(
        get_running_loop=whois_module.asyncio.get_running_loop,
        wait_for=_timeout,
    )
    monkeypatch.setattr(whois_module, "asyncio", fake_asyncio)
    threat = _Threat()
    db = _db()

    assert await WhoisService(db).enrich(threat) == whois_module.UNAVAILABLE

    assert threat.whois_registrar is None
    db.commit.assert_not_awaited()


def test_a_lookup_is_paced_by_the_server_that_answers_for_the_name():
    """The unit the drain batches and pauses on: one registry, one budget (WI-25)."""
    assert whois_module.lookup_group_key("Evil.Example.COM") == "com"
    assert whois_module.lookup_group_key("evil.example.co.uk") == "uk"
    # A name with no suffix is its own key rather than sharing one with the rest.
    assert whois_module.lookup_group_key("localhost") == "localhost"
    assert whois_module.lookup_group_key(None) == ""


def test_only_a_plain_label_may_scope_a_pause():
    """The key becomes a LIKE pattern, so its shape is checked before it gets there."""
    assert whois_module.is_server_label("com")
    assert whois_module.is_server_label("xn--p1ai")
    assert not whois_module.is_server_label("")
    assert not whois_module.is_server_label("co*m")
    assert not whois_module.is_server_label("%")
    assert not whois_module.is_server_label("com.")
