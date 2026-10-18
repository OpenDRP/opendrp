"""Registration facts for a phishing candidate — and the registry's own limits.

The lookup is best effort and runs after ingestion has already stored the finding,
so nothing here may fail the write path. What it *can* do is name which of six
things happened, because the answer decides what the caller does next:

``answered``
    the registry returned a record, and whatever it carried was stored;
``no_record``
    the registry says the name is not registered (python-whois raises for that):
    a known answer rather than a failure — and one a later re-ask can find
    changed, because a name nobody has registered yet can be registered;
``rate_limited``
    the registry has stopped answering *this address*. This is the one outcome
    that is about the server rather than about the name, so the caller holds every
    event that would ask the same server again instead of retrying into a refusal
    (WI-25);
``unavailable``
    the socket, the resolver or the budget gave up: no answer arrived, so the
    event may be asked again later, with a bound;
``refused``
    our own outbound guard or the domain's shape refused the target. Asking a
    deliberately blocked destination again on a timer is the retry stream the
    guard exists to prevent, so this answer is terminal for the event;
``nothing_to_ask``
    the candidate row already carries the facts — the row *is* the cache.

``registration_known`` and ``lookup_group_key`` are also what the drain paces
itself with: one lookup per name, and at most one per answering server per pass,
which is the difference between a scan's forty look-alikes arriving at one
registry as a burst and arriving as a trickle.
"""

import asyncio
import datetime as _dt
import re
from typing import Protocol

import structlog
import whois
from dateutil import parser as _dp
from sqlalchemy.ext.asyncio import AsyncSession
from whois.parser import PywhoisError

from app.core.outbound import OutboundBlocked, ensure_allowed, validate_domain_target

log = structlog.get_logger()

ANSWERED = "answered"
NO_RECORD = "no_record"
RATE_LIMITED = "rate_limited"
UNAVAILABLE = "unavailable"
REFUSED = "refused"
NOTHING_TO_ASK = "nothing_to_ask"

#: The facts a lookup exists to resolve, in their column order. ``registration_
#: known`` reads the first and the last of them: the abuse contact is optional
#: (plenty of registries publish none), so requiring it would ask forever.
FACTS = ("whois_registrar", "whois_abuse_email", "domain_created_at")

#: What a registry says instead of a record once it has had enough of a client.
#: Matched case-insensitively against the raw response, because python-whois
#: parses the text and the parsed record then simply has no fields — a refusal is
#: indistinguishable from a thin registration record by the fields alone.
_RATE_LIMIT_MARKERS = (
    "limit exceeded",
    "limits exceeded",
    "queries exceeded",
    "maximum number of requests",
    "rate limit",
    "query rate",
    "too many requests",
    "whois limit",
    "blacklisted",
    "access denied",
)

#: A plain DNS label, which is what a top-level domain is. Anything else (an empty
#: label, a wildcard, a shell metacharacter) is not allowed to scope a pause: the
#: label becomes a LIKE pattern, so its shape is checked before it gets there.
_SERVER_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

#: The thread's answer when python-whois raises "no match for ...".
_NO_RECORD = object()


class SessionLike(Protocol):
    """The two session calls this service makes, and nothing else.

    A lookup is deliberately handed a *detached* stand-in by the batch pass, which
    has already released its locks and writes the outcome itself — so the service
    depends on the two calls it uses rather than on the whole ``AsyncSession``. That
    is what lets the pass pass a stand-in without a cast, and it keeps this module
    from being able to reach anything else on a session it does not own.
    """

    async def commit(self) -> None: ...

    async def refresh(self, instance: object) -> None: ...


def registration_known(threat) -> bool:
    """Whether the row already answers every question a lookup would ask (WI-25).

    The candidate row is the cache, and it is a better one than a table beside it:
    the facts are stored on the row the platform reads anyway, one row means one
    domain, and the domain column is unique. So a second event for the same
    candidate — a re-queued finding, a retry that arrives after a first pass has
    already answered — is completed without a query, and two workers cannot ask a
    registry the same question.

    The registrar and the creation date are the pair that makes this complete: the
    registrar is what a takedown is addressed to and the date is what the age
    signal is derived from, while the abuse contact is optional and may simply not
    exist. A row that has both is not asked about again; a row that has one of them
    is, because the other is the fact worth having.
    """
    return bool(getattr(threat, "whois_registrar", None)) and bool(
        getattr(threat, "domain_created_at", None)
    )


def lookup_group_key(domain: str | None) -> str:
    """The answering server a lookup is paced against, as a short label.

    A WHOIS query goes to the server that answers for the name's top-level domain
    (a second, registrar-run server is reached through the record that comes back),
    and a registry's rate limit applies to that server and to our address. The
    registrable suffix is therefore the honest unit to batch and to pause: two
    look-alikes under ``.com`` are one server's budget, while ``.net`` is a
    different registry that has said nothing to us. A name with no suffix is its
    own key, which keeps unrelated single-label input from sharing a pause.
    """
    name = (domain or "").strip().lower()
    labels = name.rsplit(".", 1)
    if len(labels) == 2 and labels[1]:
        return labels[1]
    return name


def is_server_label(label: str) -> bool:
    """Whether a key from :func:`lookup_group_key` may scope a whole-queue pause."""
    return bool(label) and bool(_SERVER_LABEL.match(label))


def _refused(text: str) -> bool:
    lowered = (text or "").lower()
    return any(marker in lowered for marker in _RATE_LIMIT_MARKERS)


def _registrar_and_contact(info) -> tuple[str | None, str | None]:
    """The registrar, and the address an analyst would write to.

    The abuse contact beats a generic one, because that is the address a takedown
    request goes to; with none of them looking like an abuse desk, the first
    address stands in rather than nothing.
    """
    registrar = info.get("registrar")
    emails = info.get("emails") or []
    abuse_email = None
    if isinstance(emails, list):
        for candidate in emails:
            if "abuse" in str(candidate).lower():
                abuse_email = candidate
                break
        if not abuse_email and emails:
            abuse_email = (
                emails[0] if isinstance(emails[0], str) else str(emails[0])
            )
    elif isinstance(emails, str):
        abuse_email = emails
    return registrar, abuse_email


def _creation_date(info) -> _dt.datetime | None:
    """The registration date, or ``None`` when the registry gave something unreadable."""
    creation = info.get("creation_date")
    if isinstance(creation, list):
        creation = creation[0]
    if not creation:
        return None
    if isinstance(creation, _dt.datetime):
        return creation
    try:
        return _dp.parse(str(creation))
    except Exception:
        return None


class WhoisService:
    def __init__(self, db: "AsyncSession | SessionLike"):
        self.db = db

    async def enrich(self, threat) -> str:
        """Resolve and store the registration facts the candidate arrived without.

        Returns one of this module's outcome names. Facts are written onto the row
        handed in — the drain deliberately passes a detached stand-in, so that no
        row lock is held across the lookup — and a response that carried nothing is
        written nowhere: the caller decides whether that is worth another ask.
        """
        if registration_known(threat):
            return NOTHING_TO_ASK

        # The domain came out of a finding, which means it came from outside the
        # platform, and a WHOIS client resolves whatever it is handed. Both the
        # shape check and the destination check happen before the lookup: this is
        # the one enrichment whose target an attacker can choose.
        try:
            target = validate_domain_target(getattr(threat, "phishing_domain", None))
        except ValueError as exc:
            log.warning("whois_target_refused", reason=str(exc)[:120])
            return REFUSED

        def _sync_whois():
            try:
                # Resolution and lookup both belong off the event loop, so the
                # guard runs in here with them.
                ensure_allowed(target, port=43)
                return whois.whois(target)
            except OutboundBlocked:
                raise
            except PywhoisError:
                # "No match for ...", "Domain Not Found", "no WHOIS server for
                # this kind of object": the registry answered with the absence of
                # a record. That is an answer, and a retryable one — tomorrow the
                # name may exist — but not a failure of the lookup.
                return _NO_RECORD
            except Exception:
                return None

        loop = asyncio.get_running_loop()
        try:
            from app.core.config import settings
            info = await asyncio.wait_for(
                loop.run_in_executor(None, _sync_whois),
                timeout=max(1.0, float(settings.OUTBOUND_DNS_TIMEOUT_SECONDS)),
            )
        except OutboundBlocked as blocked:
            log.warning("outbound_blocked", operation="whois", **blocked.as_audit_details())
            return REFUSED
        except Exception:
            # The budget expired: the registry has not said anything about this
            # name, which is not the same as having nothing to say about it.
            log.info("whois_unavailable", domain=target)
            return UNAVAILABLE
        if info is _NO_RECORD:
            log.info("whois_no_record", domain=target)
            return NO_RECORD
        if not info:
            log.info("whois_unavailable", domain=target)
            return UNAVAILABLE
        if _refused(getattr(info, "text", "")):
            # Read before any fact is stored: a refusal can be shaped like a
            # record, and the caller has to read it as a server's answer rather
            # than as this domain's facts.
            log.warning("whois_rate_limited", domain=target)
            return RATE_LIMITED

        registrar, abuse_email = _registrar_and_contact(info)
        created = _creation_date(info)
        if registrar and not threat.whois_registrar:
            threat.whois_registrar = str(registrar)[:255]
        if abuse_email and not threat.whois_abuse_email:
            threat.whois_abuse_email = str(abuse_email)[:255]
        if created and not threat.domain_created_at:
            threat.domain_created_at = created
        await self.db.commit()
        await self.db.refresh(threat)
        return ANSWERED
