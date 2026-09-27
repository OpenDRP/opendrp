"""WHOIS enrichment: every failure path must be survivable.

``WhoisService.enrich`` runs after a phishing finding is persisted, so it is a
*side effect*: a WHOIS outage, a malformed response or a slow registrar must
never fail the ingestion that already succeeded. That is why most of what is
pinned here is "returns quietly and changes nothing".

Also pinned: which value wins when the registrar returns several addresses (an
abuse contact beats a generic one, because that is the address an analyst has to
write to), and that an existing value is never overwritten — re-running
enrichment must not churn a finding.
"""

from __future__ import annotations

import datetime as dt
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.services.phishing import whois_service as whois_module
from app.services.phishing.whois_service import WhoisService


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
    monkeypatch.setattr(whois_module.whois, "whois", lambda _domain: payload)


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
    _patch_whois(
        monkeypatch,
        {
            "registrar": "New Registrar",
            "emails": ["abuse@new.example"],
            "creation_date": dt.datetime(2030, 1, 1),
        },
    )
    original = dt.datetime(2001, 1, 1)
    threat = _Threat(
        registrar="Original Registrar",
        abuse_email="abuse@original.example",
        created_at=original,
    )

    await WhoisService(_db()).enrich(threat)

    assert threat.whois_registrar == "Original Registrar"
    assert threat.whois_abuse_email == "abuse@original.example"
    assert threat.domain_created_at == original


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

    monkeypatch.setattr(whois_module.whois, "whois", _boom)
    threat = _Threat()
    db = _db()

    await WhoisService(db).enrich(threat)

    assert threat.whois_registrar is None
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_an_empty_response_is_a_no_op(monkeypatch):
    _patch_whois(monkeypatch, None)
    db = _db()

    await WhoisService(db).enrich(_Threat())

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

    await WhoisService(db).enrich(threat)

    assert threat.whois_registrar is None
    db.commit.assert_not_awaited()
