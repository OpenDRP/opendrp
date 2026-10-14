"""The single answer to "which configured asset is this finding about" (WI-08).

The audit found three different implementations of that question, each with its
own canonicalization:

* the breach list resolved assets through ``func.lower(Asset.asset_value)``;
* the destructive cascade compared ``matched_asset == asset.asset_value``
  byte-for-byte;
* orphan cleanup loaded whole tables into memory and compared ``casefold()``
  strings, with an email-to-domain derivation the other two did not have.

They disagreed on case, on IDNA (``xn--`` vs ``ü``), on the trailing dot and on
whether an ``email_account`` finding also belongs to its parent domain. This
module is now the only place that decides. Everything else imports it:

* :func:`key_variants` — every spelling of a value that must be recognized as the
  same thing (canonical IDNA/IP/email form **and** the raw spelling that SQL
  ``lower()`` produces, so the SQL and Python paths cannot drift);
* :func:`resolution_candidates` — the ordered ``(asset_type, key)`` pairs used to
  *name* the asset behind a finding, preserving the documented precedence
  (an exact mailbox asset beats the domain derived from that mailbox);
* :func:`keys_predicate` / :func:`resolution_predicate` — the SQL predicates over
  ``normalized_value`` (sargable for ``uq_assets_type_normalized_value``);
* :func:`asset_scope` — the ``is_active`` policy per use: a scan only looks at
  active assets, while display and cleanup must still explain a finding that an
  inactive asset owns.

Chosen rule (pinned by ``tests/test_asset_matching.py``): a finding belongs to an
asset when their :func:`key_variants` sets intersect, or when the finding is an
address whose domain part matches a domain asset. Asset *type* does not take part
in that membership test — an identifier is stored verbatim for ``keyword_*``
assets — but it does decide which asset is named when several match.

Note on non-ASCII hostnames: ``assets.normalized_value`` is stored in IDNA form,
and SQL ``lower()`` cannot perform IDNA, which is why :func:`key_variants`
carries both spellings instead of relying on the SQL side to canonicalize.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

from typing import Any

from sqlalchemy import ColumnElement, and_, func, literal, or_
from sqlalchemy.exc import CompileError
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import InstrumentedAttribute
from sqlalchemy.sql.functions import FunctionElement

from app.models.asset import Asset, AssetType
from app.schemas.asset import normalize_asset_value

#: What reaches these helpers: a mapped attribute inside a query
#: (``PhishingDomain.matched_asset``) or a plain expression (``func.lower(...)``).
ColumnLike = ColumnElement[Any] | InstrumentedAttribute[Any]

#: Only active assets are scanned or queued for monitoring.
POLICY_SCAN = "scan"
#: Display/enrichment: an inactive asset still explains why a finding exists.
POLICY_DISPLAY = "display"
#: Orphan cleanup: an inactive asset still owns its findings.
POLICY_CLEANUP = "cleanup"

#: The modules whose findings can name an asset, in the order both the asset
#: page and the list counters show them. ``findings`` is the generic table the
#: registry-declared modules use.
RELATED_FINDING_MODULES: tuple[str, ...] = (
    "phishing",
    "breaches",
    "dns",
    "exposure",
    "findings",
)

#: The one asset type the email-to-domain rule applies to.
DOMAIN_ASSET_TYPE = AssetType.domain.value

#: The addresses a subnet search looks at. ``schemas.user.AssetType`` is a
#: ``Literal`` alias, so this is the mapped enum's spelling of the same value —
#: one place that names the type rather than a string literal per call site.
IP_ASSET_TYPE = AssetType.ip_address.value

_ASSET_TYPES_WITH_VERBATIM_VALUE = (AssetType.keyword_domain.value, AssetType.keyword_title.value)

_HOSTNAME_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


def _text(value: object) -> str:
    return str(value or "").strip()


def _domain_key(value: str) -> str:
    """Canonical IDNA/lowercase domain, falling back to a plain lowercase key.

    Both sides of a comparison go through this function, so a value that is not a
    valid hostname (a keyword, a threat title) still gets one stable key.
    """
    stripped = value.rstrip(".")
    try:
        return normalize_asset_value("domain", stripped)
    except (ValueError, UnicodeError):
        return stripped.lower()


def _ip_key(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip().strip("[]")))
    except ValueError:
        return None


def _email_key(value: str) -> str:
    try:
        return normalize_asset_value("email_account", value)
    except (ValueError, UnicodeError):
        return value.lower()


def _sql_spelling(value: str) -> str:
    """What ``lower(rtrim(trim(value), '.'))`` yields for the same string."""
    return value.strip().rstrip(".").lower()


def _unicode_spelling(value: str) -> str | None:
    """The Unicode form of a punycode identifier, when it has one.

    ``assets.normalized_value`` stores the IDNA form, while a connector may have
    written the Unicode spelling into a finding. SQL cannot convert between the
    two, so the comparison key set carries both directions.
    """
    stripped = value.strip().rstrip(".")
    try:
        decoded = stripped.encode("ascii").decode("idna").lower()
    except (UnicodeError, ValueError):
        return None
    return decoded if decoded != _sql_spelling(stripped) else None


def key_variants(value: object) -> frozenset[str]:
    """Every spelling of ``value`` that must be recognized as the same identifier."""
    raw = _text(value)
    if not raw:
        return frozenset()
    if "@" in raw:
        # Both the canonical mailbox spelling (local part preserved) and the
        # fully lowercased spelling SQL sees are kept, so an address written as
        # ``User@Example.COM`` still matches an asset stored as
        # ``User@example.com``.
        return frozenset({_email_key(raw), _sql_spelling(raw)})
    ip = _ip_key(raw)
    if ip is not None:
        return frozenset({ip, _sql_spelling(raw)})
    variants = {_domain_key(raw), _sql_spelling(raw)}
    unicode_form = _unicode_spelling(raw)
    if unicode_form:
        variants.add(unicode_form)
    return frozenset(variants)


def canonical_key(value: object) -> str | None:
    """The primary spelling of a value, for comparisons that need a single key."""
    variants = key_variants(value)
    if not variants:
        return None
    raw = _text(value)
    if "@" in raw:
        return _email_key(raw)
    ip = _ip_key(raw)
    if ip is not None:
        return ip
    return _domain_key(raw)


def asset_key_variants(asset_type: object, value: object) -> frozenset[str]:
    """Key variants of an asset row's own value (type-aware).

    ``keyword_*`` values are stored verbatim, so the stored spelling is kept next
    to its lowercase form: the cascade and the anti-join compare through SQL
    ``lower()``, and dropping the lowercase form would silently stop matching an
    asset whose keyword differs only in case.
    """
    raw = _text(value)
    if not raw:
        return frozenset()
    asset_type_value = getattr(asset_type, "value", asset_type)
    if asset_type_value in _ASSET_TYPES_WITH_VERBATIM_VALUE:
        return frozenset({raw, raw.lower()})
    if asset_type_value == AssetType.email_account.value:
        return frozenset({_email_key(raw), _sql_spelling(raw)})
    if asset_type_value == AssetType.ip_address.value:
        ip = _ip_key(raw)
        return frozenset({ip, _sql_spelling(raw)}) if ip else frozenset({_sql_spelling(raw)})
    return key_variants(raw)


def domain_asset_variants(asset_type: object, value: object) -> frozenset[str]:
    """Key variants of an asset only when it is a ``domain`` asset, else empty.

    Used by the email-to-domain rule: only a monitored *domain* explains the
    mailboxes at it, and only deleting a domain widens the cascade that far.
    """
    if getattr(asset_type, "value", asset_type) != AssetType.domain.value:
        return frozenset()
    return asset_key_variants(asset_type, value)


def email_domain_variants(value: object) -> frozenset[str]:
    """Domain keys derived from an email address, for the email-to-domain rule."""
    raw = _text(value)
    if "@" not in raw:
        return frozenset()
    local, _, domain = raw.partition("@")
    if not local or not domain:
        return frozenset()
    return key_variants(domain)


def resolution_candidates(value: object) -> tuple[tuple[str, str], ...]:
    """Ordered ``(asset_type, key)`` pairs used to name the asset behind a finding.

    Order is the documented display precedence: an exact ``email_account`` asset
    wins over the ``domain`` derived from the same address, because when both a
    mailbox and its parent domain are monitored the finding is about the mailbox.
    """
    raw = _text(value)
    if not raw:
        return ()
    if "@" in raw:
        candidates: list[tuple[str, str]] = [
            (AssetType.email_account.value, key)
            for key in sorted(key_variants(raw))
        ]
        candidates.extend(
            (AssetType.domain.value, key)
            for key in sorted(email_domain_variants(raw))
        )
        return tuple(candidates)
    ip = _ip_key(raw)
    if ip is not None:
        return tuple((AssetType.ip_address.value, key) for key in sorted(key_variants(raw)))
    return tuple((AssetType.domain.value, key) for key in sorted(key_variants(raw)))


def sql_key(column: ColumnLike) -> ColumnElement:
    """The one SQL canonicalization of a stored identifier.

    ``lower(rtrim(trim(x), '.'))`` mirrors :func:`_sql_spelling`, so a value stored
    with a trailing dot or mixed case still matches its canonical key.
    """
    return func.lower(func.rtrim(func.trim(column), "."))


def asset_sql_key() -> ColumnElement:
    """Canonicalized asset identifier, preferring the stored canonical column."""
    return sql_key(func.coalesce(Asset.normalized_value, Asset.asset_value))


def keys_predicate(column: ColumnLike, keys: Iterable[str]) -> ColumnElement:
    """``column`` matches any of ``keys`` under the shared canonicalization."""
    values = sorted({key for key in keys if key})
    return sql_key(column).in_(values)


def resolution_predicate(
    candidates: Iterable[tuple[str, str]],
) -> ColumnElement:
    """Asset predicate for :func:`resolution_candidates` output."""
    conditions = [
        and_(Asset.asset_type == asset_type, asset_sql_key().in_([key]))
        for asset_type, key in candidates
        if key
    ]
    return or_(*conditions) if conditions else _never_match()


class EmailDomain(FunctionElement):
    """The domain part of an address, lowercased (``user@Example.COM`` → ``example.com``).

    The one place the platform asks "which domain is this address at" in SQL. It is
    a database function rather than a ``LIKE '%@domain'`` comparison because a
    leading-wildcard ``LIKE`` cannot use an index: the email-to-domain rule is
    evaluated over the whole finding table every time an asset is matched, and once
    the rule also had to answer for a whole page of assets (WI-20) that scan was
    the difference between a fast page and a timeout. Expressed this way the same
    question is an equality against an expression index (migration ``0009``).

    PostgreSQL (``split_part``) and SQLite (``substr``/``instr``, the test engine)
    have different spellings; a dialect with neither is refused rather than
    silently answered by a different rule. Both forms return the text after the
    *first* ``@``, and callers guard the predicate with ``LIKE '%@%'`` so a value
    that is not an address never reaches the comparison.
    """

    name = "email_domain"
    inherit_cache = True


def _email_domain_operand(element: FunctionElement, compiler, **kwargs) -> str:
    clause = list(element.clauses)[0]
    return compiler.process(clause, **kwargs)


@compiles(EmailDomain, "postgresql")
def _postgresql_email_domain(element, compiler, **kwargs):  # pragma: no cover - dialect render
    return f"lower(split_part({_email_domain_operand(element, compiler, **kwargs)}, '@', 2))"


@compiles(EmailDomain, "sqlite")
def _sqlite_email_domain(element, compiler, **kwargs):  # pragma: no cover - dialect render
    column = _email_domain_operand(element, compiler, **kwargs)
    return f"lower(substr({column}, instr({column}, '@') + 1))"


@compiles(EmailDomain)
def _unsupported_email_domain(element, compiler, **kwargs):
    raise CompileError(
        "EmailDomain is implemented for PostgreSQL and SQLite; another database "
        "needs its own spelling of the email-to-domain rule rather than a "
        "different answer to it"
    )


def email_suffix_predicate(column: ColumnLike, domains: Iterable[str]) -> ColumnElement | None:
    """Match ``user@<domain>`` for the given domains, or ``None`` when unusable.

    The domain set is filtered to real hostnames, so a keyword asset value can
    never smuggle a pattern or a stray suffix into the rule, and the ``LIKE`` guard
    keeps a value that is not an address out of the domain comparison entirely.
    """
    usable = sorted({domain for domain in domains if _HOSTNAME_RE.match(domain)})
    if not usable:
        return None
    return and_(
        sql_email_like(column, "%@%"),
        EmailDomain(column).in_(usable),
    )


def email_domain_key(column: ColumnLike) -> ColumnElement:
    """The domain keys of ``column``, one expression for both SQL dialects."""
    return EmailDomain(column)


def sql_email_like(column: ColumnLike, pattern: str) -> ColumnElement:
    """``LIKE`` with the escape the platform uses everywhere."""
    return func.lower(column).like(pattern, escape="\\")


def email_domain_join_predicate(email_column: ColumnLike) -> ColumnElement:
    """Correlated form of the email-to-domain rule, driven by an asset row.

    ``email_column`` is an address at the domain of the *asset row in scope*, so
    the anti-join can decide it without loading either table into memory.
    """
    return and_(
        Asset.asset_type == DOMAIN_ASSET_TYPE,
        func.lower(email_column).like(literal("%@").concat(asset_sql_key())),
    )


def related_finding_models() -> dict[str, Any]:
    """The finding table behind each entry of :data:`RELATED_FINDING_MODULES`.

    Lazy imports: the matching rule itself must stay importable without pulling
    in every model, and one mapping here is what keeps the list counters, the
    asset page and the ``has_findings`` filter talking about the same five
    modules.
    """
    from app.models.breach import Breach
    from app.models.dns_observation import DNSObservation
    from app.models.finding import Finding
    from app.models.phishing import PhishingDomain
    from app.models.source_observation import SourceObservation

    return {
        "phishing": PhishingDomain,
        "breaches": Breach,
        "dns": DNSObservation,
        "exposure": SourceObservation,
        "findings": Finding,
    }


def related_finding_value_columns() -> dict[str, tuple[Any, ...]]:
    """The identifier columns each module matches an asset against.

    One list, used by both the key-set predicates and the correlated existence
    test, so "which columns can link a row to an asset" is stated once.
    """
    models = related_finding_models()
    return {
        "phishing": (models["phishing"].matched_asset,),
        "breaches": (models["breaches"].matched_domain, models["breaches"].matched_email),
        "dns": (models["dns"].subject, models["dns"].value),
        "exposure": (models["exposure"].matched_asset,),
        "findings": (models["findings"].matched_asset,),
    }


def related_finding_observed_at() -> dict[str, Any]:
    """The column that says when each module last saw the row it matched.

    These are not the same kind of moment: a breach reports the date it was
    disclosed, a scan reports when the observation was recorded. Callers publish
    them as ISO text per module rather than as one timestamp, so no comparison
    between the two kinds is ever attempted.
    """
    models = related_finding_models()
    return {
        "phishing": models["phishing"].created_at,
        "breaches": models["breaches"].breach_date,
        "dns": models["dns"].last_seen_at,
        "exposure": func.coalesce(
            models["exposure"].observed_at, models["exposure"].last_seen_at
        ),
        "findings": models["findings"].created_at,
    }


def related_finding_predicates(asset_type: object, value: object) -> dict[str, ColumnElement]:
    """Per-module predicates for "the findings that belong to this asset" (WI-12).

    Built from the same key variants as the cascade and the breach resolver, so
    the "asset to findings" view cannot show a different set than the cascade
    would delete.
    """
    keys = asset_key_variants(asset_type, value)
    columns = related_finding_value_columns()
    predicates = {
        name: or_(*[keys_predicate(column, keys) for column in module_columns])
        for name, module_columns in columns.items()
    }
    # A monitored domain also explains the mailboxes at it, exactly as the cascade
    # and the resolver do; a mailbox key never widens it.
    by_email_domain = email_suffix_predicate(columns["breaches"][1], keys)
    if by_email_domain is not None:
        predicates["breaches"] = or_(predicates["breaches"], by_email_domain)
    return predicates




#: The largest subnet ``GET /assets?search=`` enumerates (WI-16). A subnet search
#: is answered by matching the addresses the subnet contains, so the work is
#: proportional to the network's size; the bound is what stops an accidental
#: ``0.0.0.0/0`` from turning a search box into a timeout. 4096 addresses is a
#: ``/20`` for IPv4 or a ``/116`` for IPv6 — narrower than any range an operator
#: selects on purpose — and it stays far below the bind-parameter limit of both
#: databases (SQLite allows 32766 in a statement, asyncpg 32767).
CIDR_MAX_ADDRESSES = 4096


def cidr_search_values(term: object) -> frozenset[str] | None:
    """The canonical addresses inside ``term``, when ``term`` is a subnet.

    ``None`` means "this is not a subnet", so the caller keeps treating the term
    as a substring. A term is a subnet only when it carries a ``/``, so an
    ordinary search string is never reinterpreted.

    Substring search cannot answer "which of my assets sit in ``10.0.0.0/24``":
    the canonical text of an address neither starts with nor contains its
    network. Matching the enumerated addresses exactly keeps the answer backed by
    ``uq_assets_type_normalized_value`` and keeps one code path for both
    databases the platform runs on — an ``inet`` range comparison would exist
    only on PostgreSQL and would have to be written twice.

    A subnet larger than :data:`CIDR_MAX_ADDRESSES` raises :class:`ValueError`
    instead of answering with part of the inventory: a truncated answer to "is
    this address monitored" is indistinguishable from a complete one, and the
    operator acting on it would be acting on a list that is silently incomplete.
    """
    text = _text(term)
    if "/" not in text:
        return None
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None
    if network.num_addresses > CIDR_MAX_ADDRESSES:
        raise ValueError(
            f"A subnet search covers at most {CIDR_MAX_ADDRESSES} addresses; "
            f"{text} contains {network.num_addresses}. Narrow the prefix."
        )
    return frozenset(str(address) for address in network)


def asset_scope(policy: str) -> tuple[ColumnElement, ...]:
    """``is_active`` filters for the given :data:`POLICY_SCAN`/``DISPLAY``/``CLEANUP``."""
    if policy == POLICY_SCAN:
        return (Asset.is_active.is_(True),)
    if policy in (POLICY_DISPLAY, POLICY_CLEANUP):
        return ()
    raise ValueError(f"Unknown asset matching policy: {policy!r}")


def _never_match() -> ColumnElement:
    return Asset.id.is_(None) & Asset.id.is_not(None)
