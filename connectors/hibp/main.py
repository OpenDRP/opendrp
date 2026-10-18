"""HIBP connector (module type: breaches).

Scans email-account and domain assets against HaveIBeenPwned:

* ``email_account`` assets via ``GET /breachedaccount/{email}``
* ``domain`` assets via ``GET /breacheddomain/{domain}`` — HIBP returns an
  alias -> [breach names] mapping; every (alias, breach) pair is submitted
  as a finding with ``matched_email = alias@domain``.

API key: ``HIBP_API_KEY`` in the environment, or the key the platform holds for
this connector's source account (``GET /connectors/me/credential``) — the account
is where an operator rotates it without recreating a container.

The worker also reads the source's own incident *catalogue* — ``/breaches``, bounded
by ``max_catalogue_entries``, and ``/latestBreach`` when a previous sync is on
record — and hands the core the entries as a batch (WI-13). The diff is the core's:
the provider has no "added since" question to ask, so the platform compares what
this worker read against the rows it already holds, and an incident naming a domain
somebody monitors is announced before any address of it has been scanned. What the
catalogue is *not* is a second scan: the sweep runs under the same pace and request
budget as everything else, and between sweeps the cheap question is a single call.

Pacing is the subscription's allowance, not a guessed constant (WI-03): a token
bucket over ``requests_per_minute`` (default 10, the conservative reading of the
lowest paid tier until a live subscription says otherwise), with ``Retry-After``
from a 429 obeyed before the next call. Every call the worker makes — including
the ``/breach/{name}`` metadata lookup inside the alias loop and the catalogue
sweep — goes through it, and the aliases one scan may expand and the requests it may
spend are both bounded (WI-10), because a domain scan over a leaked address list is
otherwise an unbounded amount of somebody's money.

This connector owns all HIBP API access; the core only receives normalized
findings.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from datetime import date as _date, datetime as _dt, timedelta as _timedelta, timezone as _timezone

import httpx
import structlog

from opendrp_connector import ConnectorBase
from opendrp_connector.base import ConnectorAPIError, DEFAULT_CATALOGUE_BATCH

log = structlog.get_logger()

#: The provider operation buckets this worker reserves against. Declared in the
#: readiness row before they are ever used, because the core refuses a bucket its
#: record of the connector does not name (WI-04). Every route the worker calls asks
#: a question about *one* identifier — an address, a domain, an incident — which is
#: what ``lookup`` names; the catalogue's questions are about the provider's whole
#: corpus rather than about one identifier, which is what ``search`` names (WI-13).
OPERATIONS = ("lookup", "search")

#: How many data-class labels a worker publishes, and how long each one may be. The
#: provider's vocabulary is a short reference list; the bounds are what keep a source
#: that answers with something larger from writing a payload nobody planned for.
MAX_DATA_CLASS_LABELS = 200
MAX_DATA_CLASS_LABEL_LEN = 256

#: How many catalogue entries ride in one submission. A batch, not the catalogue: the
#: core stores what it is given and the worker keeps what the earlier batches achieved
#: if the sweep is cut short. This equals the SDK's ``DEFAULT_CATALOGUE_BATCH``, which
#: is the core's own limit — the catalogue path gains nothing from a smaller one, since
#: a provider sweep is already paged; the name is kept for readers and tests that
#: already refer to it.
CATALOGUE_BATCH = DEFAULT_CATALOGUE_BATCH
#: What the catalogue phase reports it did. Read by the summary and by the tests, and
#: the words a job reader needs in order to tell "asked, nothing new" from "could not
#: ask" — the second is why the empty case is stated rather than left to a count.
CATALOGUE_SYNCED = "synced"
CATALOGUE_UP_TO_DATE = "up_to_date"
CATALOGUE_FAILED = "failed"

#: The domain-verification actions an operator can ask for (WI-20). They are explicit
#: rather than inferred from the provider's state: "show me the record to publish" and
#: "check whether it is there yet" are different questions, and the second one is what
#: the provider's own dashboard answers with a click.
VERIFICATION_GENERATE = "generate"
VERIFICATION_VERIFY = "verify"
VERIFICATION_ACTIONS = (VERIFICATION_GENERATE, VERIFICATION_VERIFY)


def _verification_reason(status_code: int) -> str:
    """A refusal as a word the operator can act on, rather than the provider's prose.

    403 on these routes means either "this account may not enrol domains" or "this domain
    is somebody else's" — the provider does not say which and a wrong guess is worse than
    an unnamed refusal, so both are reported as ``access_denied`` and the page shows the
    provider's own dashboard as the place to tell them apart. The response's own message
    is never copied into a summary: it is provider text, and every other refusal in this
    worker is reported the same way.
    """
    return {
        401: "invalid_credentials",
        403: "access_denied",
        404: "unknown_domain",
        429: "rate_limited",
    }.get(status_code, "provider_refused")


#: How many findings ride in one submission from the paste and stealer-log phases.
#: Smaller than the SDK's ``DEFAULT_SUBMIT_BATCH`` (500) on purpose: a paste or
#: stealer-log answer can be thousands of rows produced in one go, and submitting
#: them in 200-row batches means a sweep cut short by the scan budget keeps every
#: batch it already delivered instead of losing one large unsubmitted block.
FINDINGS_BATCH = 200


def _core_credential(payload) -> str | None:
    """The provider key the core holds for this connector's account, or ``None``.

    Only an explicit ``configured: true`` with a non-empty string counts, so a
    malformed or truncated response can never turn into a key — the same rule the
    other provider workers apply, and for the same reason: this value decides which
    account's paid quota is spent.
    """
    if not isinstance(payload, dict) or payload.get("configured") is not True:
        return None
    key = payload.get("api_key")
    return key if isinstance(key, str) and key.strip() else None

#: The scan policy an operator may set for this connector, in the same
#: ``(low, high, default)`` shape the other workers declare: the numbers travel to
#: the core in the manifest's ``config_schema`` (so the Settings page renders them)
#: and the scan validates every value against the same table. One table rather than
#: two is what keeps a documented range from disagreeing with the enforced one.
POLICY = {
    #: Requests per minute. 10 is the conservative default: the free and lowest
    #: paid tiers refuse more, and a subscription that allows more says so as an
    #: operator's value rather than as an assumption here.
    "requests_per_minute": (1, 600, 10),
    #: How many requests may be made back to back before the bucket governs. 1 is
    #: a strict even pace; a higher value is for an account whose allowance is
    #: genuinely a per-minute budget rather than a rate.
    "burst": (1, 20, 1),
    #: How many affected addresses one domain scan expands into. A leaked address
    #: list for a large domain is thousands of names, and every one of them used to
    #: be a metadata call (F-08: ~2000 requests from a single scan).
    "max_aliases_per_domain": (1, 10000, 200),
    #: The whole scan's request budget, across every address it expands. A scan that
    #: reaches it stops and says so, rather than discovering the cost by spending it.
    "max_requests_per_scan": (1, 10000, 500),
    #: How many catalogue entries one sweep stores. The provider answers `/breaches`
    #: with its whole corpus — hundreds of incidents, not a page — so this is also the
    #: bound on what a first sync of a fresh installation costs; a sweep that hits it
    #: says so instead of pretending the corpus ended there (WI-13).
    "max_catalogue_entries": (1, 5000, 2000),
    #: How often the stealer-log pass may spend requests at all (WI-18). The provider
    #: sells that access with a separate, much lower allowance, so the pass is not part
    #: of every scan: a week is the default, and a scan inside it asks nothing — not
    #: even the routes — and says it is not due.
    "stealer_logs_interval_hours": (24, 720, 168),
    #: The pace of the two domain-shaped stealer-log routes, which HIBP documents as
    #: "much lower" than the key's own. Three per minute is a guess, and a guess in the
    #: safe direction: the value is a setting so a subscription that allows more can say
    #: so instead of this file pretending to know (SPIKE-06).
    "stealer_logs_domain_requests_per_minute": (1, 60, 3),
    #: How many websites one address (or one alias of a domain) may report before the
    #: rest are counted rather than stored. A stealer-log dump names hundreds of sites
    #: per address; the bound keeps one address from becoming a page of rows.
    "max_stealer_log_sites_per_asset": (1, 1000, 50),
}

#: The switches an operator sets, separate from the numeric policy because a range
#: table cannot express "off unless asked for". ``stealer_logs_enabled`` defaults to
#: false: those routes are Pro-only, have their own allowance, and would otherwise turn
#: a working installation into one that spends a budget nobody approved (WI-18).
FLAGS: dict[str, bool] = {
    "stealer_logs_enabled": False,
    #: Whether the hash-range form replaces the address form when the plan offers it.
    #: On by default: an address that need not leave the platform should not, and the
    #: range search is what HIBP sells for exactly that. An operator turns it off when
    #: they need what the range answer omits (the source states on that route that
    #: sensitive and retired incidents are not included), and the summary then says the
    #: address form was used and why (WI-19).
    "breachedaccount_range_enabled": True,
    #: Whether the paste lookup runs. It is the one address-shaped route this module
    #: still calls on a range plan — the provider answers `/pasteAccount/{email}` and
    #: offers no hash form for it — so an installation whose point in enabling the range
    #: search is that no address leaves in a URL turns this off, and the summary then
    #: reports the paste phase as skipped rather than silently quiet (WI-17, WI-19).
    "pastes_enabled": True,
}

#: How much of the SHA-1 of an address the range search is given. The provider's own
#: contract: six hexadecimal characters in, and the remaining characters of our own
#: digest are what say which entry of that bucket is ours — a prefix is shared by every
#: account in it, so matching without the suffix would attribute strangers' incidents to
#: us.
RANGE_PREFIX_LEN = 6


def _email_hash_parts(email: str, *, case: str = "lower") -> tuple[str, str]:
    """The prefix that is sent and the suffix that stays here (WI-19).

    The provider documents "SHA-1 of the email address" and says the prefix is not
    case-sensitive, but it does not state how the address is normalized before hashing.
    The form used here is the trimmed, lowercased address — the spelling every other
    route of this API treats as the same address — and a mixed-case address that gets a
    negative answer is asked once more with the raw-case digest, so a normalization
    difference cannot turn into a silent "not breached" (see ``_range_breach_names``).
    """
    value = str(email).strip()
    if case == "lower":
        value = value.lower()
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest().upper()
    return digest[:RANGE_PREFIX_LEN], digest[RANGE_PREFIX_LEN:]


def _flags_from_config(config) -> dict[str, bool]:
    """The run's switches; a non-boolean value is a refusal, not a coercion.

    ``bool(\"false\")`` is ``True``, so coercing here would turn the one setting that
    decides whether a paid route is called into the opposite of what the operator
    stored. The core already validates against this same manifest, and the two halves
    agreeing is the point.
    """
    flags: dict[str, bool] = {}
    for key, default in FLAGS.items():
        value = (config or {}).get(key, default)
        if not isinstance(value, bool):
            raise ValueError(f"invalid_scan_flag:{key}")
        flags[key] = value
    return flags


def _policy_from_config(config) -> dict[str, int]:
    """The run's policy, or a refusal to run at all.

    A value outside its range raises instead of falling back to the default: an
    operator who set ``requests_per_minute: 600`` on a tier that allows ten has to
    hear about it, and a worker that quietly used ten would be pacing under a
    setting nobody chose.
    """
    policy: dict[str, int] = {}
    for key, (low, high, default) in POLICY.items():
        value = (config or {}).get(key, default)
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not low <= value <= high
        ):
            raise ValueError(f"invalid_scan_policy:{key}")
        policy[key] = value
    return policy


def _retry_after_seconds(value) -> float:
    """A provider ``Retry-After`` in seconds, bounded to one hour.

    Only delta-seconds are read. HIBP documents the header as a delta, and an
    HTTP-date is not worth guessing at: a value that cannot be parsed as a number
    is no pause at all, which leaves the bucket's own pace as the answer.
    """
    try:
        seconds = float(str(value).strip())
    except (TypeError, ValueError):
        return 0.0
    if seconds != seconds:  # NaN
        return 0.0
    return min(3600.0, max(0.0, seconds))


class RateLimiter:
    """A token bucket over one provider allowance (WI-03).

    The pace is the subscription's own number rather than a constant: the fixed
    1.7-second sleep this replaces was a guess about a tier the worker cannot see —
    slower than the free tier needs and, on a Pro subscription, still not an answer
    to "may I make twenty calls this minute?". The bucket is also the object a 429
    pauses, so a provider saying "wait" is obeyed by the next call rather than by
    the one after it.

    The clock and the sleeper are injectable because the guarantee is about a minute
    of wall clock: a test that cannot state the moment can only assert that some
    sleep happened.
    """

    def __init__(self, requests_per_minute: int, burst: int = 1, *, clock=time.monotonic, sleeper=None):
        self.requests_per_minute = max(1, int(requests_per_minute))
        self.burst = max(1, int(burst))
        self._clock = clock
        self._sleeper = sleeper
        self._tokens = float(self.burst)
        self._updated = clock()
        self._paused_until = 0.0

    @property
    def interval(self) -> float:
        """Seconds between two calls when the bucket is empty."""
        return 60.0 / self.requests_per_minute

    @property
    def paused_until(self) -> float:
        """The instant a ``Retry-After`` holds the next call until, on this clock.

        Read rather than inferred: the scan summary has to be able to say that the
        provider asked it to wait, and a test of that has nothing else to look at.
        """
        return self._paused_until

    async def _sleep(self, seconds: float) -> None:
        # Resolved at call time on purpose: the module's tests (and the connector
        # runtime) replace ``asyncio.sleep``, and a default bound at import time
        # would keep sleeping for real.
        if self._sleeper is not None:
            await self._sleeper(seconds)
        else:
            await asyncio.sleep(seconds)

    def pause(self, seconds: float) -> None:
        """Honour a ``Retry-After``: nothing is asked of the provider before then."""
        if seconds and seconds > 0:
            self._paused_until = max(self._paused_until, self._clock() + float(seconds))

    async def acquire(self) -> None:
        """Wait until one request fits inside the allowance, then take it."""
        now = self._clock()
        if self._paused_until > now:
            wait = self._paused_until - now
            await self._sleep(wait)
            now = self._clock()
            # A clock that did not move (an injected one, or a sleeper that
            # returned early) must not turn this into a spin: the pause has been
            # waited out as far as this limiter can tell, so it is cleared.
            if self._paused_until > now:
                self._paused_until = 0.0
        rate = self.requests_per_minute / 60.0
        self._tokens = min(float(self.burst), self._tokens + (now - self._updated) * rate)
        self._updated = now
        if self._tokens >= 1:
            self._tokens -= 1
            return
        await self._sleep((1 - self._tokens) / rate)
        # The bucket is spent by the call this awaits for; whatever time the sleep
        # took is not banked, because the call is made immediately afterwards.
        self._tokens = 0.0
        self._updated = self._clock()


def _parse_date(value):
    if value is None:
        return None
    if isinstance(value, _date) and not isinstance(value, _dt):
        return value.isoformat()
    try:
        return _date.fromisoformat(str(value)[:10]).isoformat()
    except (ValueError, TypeError):
        return None


def _parse_dt(value):
    if value is None:
        return None
    if isinstance(value, _dt):
        return value.isoformat()
    try:
        return _dt.fromisoformat(str(value).replace("Z", "+00:00")[:26]).isoformat()
    except (ValueError, TypeError):
        return None


def _json_value(response) -> object:
    """A provider body as JSON, or ``None`` when there is no usable one.

    Both halves matter: a non-200 has no body to read, and a body that is not JSON
    is a version of the API this worker does not understand — either way the answer
    is *unknown*, which is a different statement from an empty list.
    """
    if response is None or response.status_code != 200:
        return None
    try:
        return response.json()
    except ValueError:
        return None


def _json_object(response) -> dict | None:
    value = _json_value(response)
    return value if isinstance(value, dict) else None


def _aware(value: _dt) -> _dt:
    """The same instant with a zone, so two timestamps can be compared at all."""
    return value.replace(tzinfo=_timezone.utc) if value.tzinfo is None else value


def _catalogue_changed_since(incident: dict, checkpoint: str) -> bool:
    """Whether one catalogue record is newer than what the core already holds.

    Both of the source's own timestamps count: an incident whose ``AddedDate`` predates
    the checkpoint can still have been corrected since (``ModifiedDate``), and a
    correction the platform does not re-read is a row that argues with the provider.
    A record carrying neither timestamp counts as changed, because the alternative is to
    drop an incident on the strength of a field the source did not send. A checkpoint the
    core did not send in a form this worker understands counts as changed for the same
    reason: an unanswerable question is not an answer of "no".
    """
    try:
        since = _aware(_dt.fromisoformat(str(checkpoint).replace("Z", "+00:00")))
    except (TypeError, ValueError):
        return True
    newest: _dt | None = None
    for key in ("AddedDate", "ModifiedDate"):
        raw = _parse_dt(incident.get(key))
        if not raw:
            continue
        try:
            parsed = _aware(_dt.fromisoformat(raw))
        except ValueError:
            continue
        if newest is None or parsed > newest:
            newest = parsed
    return True if newest is None else newest > since


def _parse_nonnegative_int(value) -> int:
    try:
        return max(int(value or 0), 0)
    except (TypeError, ValueError):
        return 0


def _mask_password(plain: str | None) -> str | None:
    if not plain:
        return None
    if len(plain) <= 4:
        return "*" * len(plain)
    head, tail = plain[:2], plain[-2:]
    middle = "*" * max(len(plain) - 4, 4)
    return f"{head}{middle}{tail}"


#: The exposure classes this module reports, in the vocabulary the core validates
#: (``backend/app/services/ingestion_service.py``). Words are duplicated rather than
#: imported because a connector is built and shipped without the core's code; a class
#: the core does not know is refused at storage, which is the check that matters.
PASTE = "paste"
STEALER_LOG = "stealer_log"

#: Bounds on the identifiers a paste or a stealer-log entry contributes. The names are
#: provider identifiers — a paste id, a website — and the core stores them inside a
#: dedup key, so they are clipped here rather than at the edge of a database column.
MAX_PASTE_ID_LEN = 128
MAX_STEALER_SITE_LEN = 255


def _paste_finding(entry: object, email: str) -> dict | None:
    """One ``/pasteAccount`` entry as a finding, or ``None`` when it cannot be one.

    A paste has no incident name: the dedup key the core uses is
    ``(source, breach_name, matched_email)``, so the paste's own id becomes the name
    (``paste:<id>``). Without an id there is nothing to tell two pastes of the same
    address apart, and storing either would collapse them into one row — so the entry
    is counted and skipped instead.

    ``breach_date`` is the paste's own date when the service published one. When it did
    not, the finding says ``metadata_incomplete`` and the core records the observation
    instant, which is the rule it already applies to a leak with no catalogue entry
    (F-02).
    """
    if not isinstance(entry, dict):
        return None
    paste_id = str(entry.get("Id") or "").strip()[:MAX_PASTE_ID_LEN]
    if not paste_id:
        return None
    source = str(entry.get("Source") or "").strip()[:64]
    attributes: dict[str, object] = {"paste_id": paste_id}
    if source:
        attributes["paste_source"] = source
    title = str(entry.get("Title") or "").strip()[:255]
    if title:
        attributes["paste_title"] = title
    count = _parse_nonnegative_int(entry.get("EmailCount"))
    if count:
        # The size of the paste, not the number of our accounts in it: it is a fact
        # about the document, so it is an attribute rather than ``pwn_count``.
        attributes["paste_email_count"] = count
    pasted_at = _parse_dt(entry.get("Date"))
    if pasted_at:
        attributes["paste_date"] = pasted_at
    else:
        attributes["metadata_incomplete"] = True
    return {
        "exposure_kind": PASTE,
        "breach_name": f"paste:{paste_id}",
        "title": f"Paste {paste_id}" + (f" — {title}" if title else ""),
        "domain": source.lower() or "",
        "breach_date": _parse_date(entry.get("Date")),
        "data_classes": [],
        "attributes": attributes,
        "matched_email": email[:255],
        "matched_domain": None,
    }


def _stealer_log_finding(site: str, email: str, domain: str | None) -> dict:
    """One website where a stolen password for ``email`` was found (WI-18).

    The stealer-log routes answer with names and nothing else: no incident, no date, no
    count of accounts, no classes of data. Inventing any of those would be the F-02
    defect again, so the row says ``metadata_incomplete`` and carries only the site —
    and the core records when the platform saw it rather than pretending that is when
    the machine was infected.
    """
    safe_site = site[:MAX_STEALER_SITE_LEN]
    return {
        "exposure_kind": STEALER_LOG,
        "breach_name": f"stealerlog:{safe_site}",
        "title": f"Stealer log — {safe_site}",
        "domain": safe_site,
        "data_classes": [],
        "attributes": {
            "metadata_incomplete": True,
            "stealer_log_site": safe_site,
        },
        "matched_email": email[:255],
        "matched_domain": (domain or None),
    }


def _site_names(value: object) -> list[str] | None:
    """A provider answer as website names, bounded and de-duplicated, order kept.

    The routes are documented as returning an array of strings. Anything else is an
    answer this worker cannot read, and the caller has to be able to tell that from an
    empty list — which is why this returns ``None`` rather than ``[]`` for a shape it
    does not recognize.
    """
    if not isinstance(value, list):
        return None
    names: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            continue
        name = item.strip().strip(".").lower()[:MAX_STEALER_SITE_LEN]
        if not name or name in seen:
            continue
        seen.add(name)
        names.append(name)
    return names


#: The provider's own classification flags, in the shape every breach payload carries.
#: Kept in one table because the finding path and the catalogue path must agree about
#: what a flag is called: the core's noise policy (WI-05) reads the same names on both.
_CATALOGUE_FLAGS = (
    ("IsVerified", "is_verified"),
    ("IsFabricated", "is_fabricated"),
    ("IsSensitive", "is_sensitive"),
    ("IsRetired", "is_retired"),
    ("IsSpamList", "is_spam_list"),
    ("IsMalware", "is_malware"),
)


def _provider_flags(meta: dict) -> dict:
    """The source's own classification flags, under the names every payload uses.

    One table for both paths because they have to agree: the core's noise policy (WI-05)
    reads these names on a finding *and* on a catalogue entry, and an entry that
    renamed them would be stored as an incident nothing can classify.
    """
    return {neutral: bool(meta.get(key, False)) for key, neutral in _CATALOGUE_FLAGS}


def _catalogue_attributes(meta: dict) -> dict:
    """What one catalogue record knows beyond the neutral facts.

    The flags and the provider's logo path, and nothing else: the exposed-secret sample a
    finding may carry belongs to the address it was recovered from, and a catalogue is a
    description of incidents rather than a second place to store credentials.
    """
    attributes: dict[str, object] = _provider_flags(meta)
    logo = str(meta.get("LogoPath") or "")[:1024]
    if logo:
        attributes["logo_path"] = logo
    return attributes


def _catalogue_entry(meta: object) -> dict | None:
    """One upstream catalogue record in the shape the core's entry schema declares.

    A record without a name is not an incident and is skipped rather than stored as an
    anonymous row; everything else keeps the source's own timestamps, because the
    platform's diff is "have I seen this incident" and the source's ``AddedDate`` is a
    fact about the incident, not about this installation (WI-13).
    """
    if not isinstance(meta, dict):
        return None
    name = str(meta.get("Name") or "").strip()
    if not name:
        return None
    classes = [
        str(item).strip()[:255]
        for item in (meta.get("DataClasses") or [])
        if isinstance(item, str) and item.strip()
    ]
    return {
        "breach_name": name[:255],
        "title": str(meta.get("Title") or "")[:512],
        "domain": str(meta.get("Domain") or "")[:255],
        "breach_date": _parse_date(meta.get("BreachDate")),
        "added_date": _parse_dt(meta.get("AddedDate")),
        "modified_date": _parse_dt(meta.get("ModifiedDate")),
        "pwn_count": _parse_nonnegative_int(meta.get("PwnCount")),
        "data_classes": classes,
        "attributes": _catalogue_attributes(meta),
    }


class HibpConnector(ConnectorBase):
    BASE = "https://haveibeenpwned.com/api/v3"
    UA = {"User-Agent": "OpenDRP-Connector/1.0"}

    #: The accounts this worker asks about and the reference data it can read. The
    #: stealer-log route is added at runtime only while the operator has it on (see
    #: ``readiness_capabilities``): the core admits a scan on what its worker
    #: reported, so a route nobody enabled must not be promised to it.
    CAPABILITIES = ("email_account", "domain", "catalogue", "paste")
    #: The two buckets this worker may reserve an account's provider quota against
    #: (see the module-level ``OPERATIONS``, which explains what each one names).
    OPERATIONS = ("lookup", "search")
    #: The environment key is the fallback for installations without an account;
    #: ``credentials_configured`` is overridden below because a key fetched from
    #: the core is not visible in ``self.env``.
    CREDENTIAL_ENV = ("HIBP_API_KEY",)

    def __init__(self) -> None:
        super().__init__()
        #: The environment variable stays the fallback for every installation that
        #: has one, which is what makes binding a source account an operator's
        #: decision rather than an upgrade requirement (F-15).
        self._env_api_key = self.env.get("HIBP_API_KEY", "").strip()
        self.api_key = self._env_api_key
        #: True only while the core has handed this worker an account's key. It is
        #: what makes the account's budget the authority: reserving provider quota
        #: against an installation that has no account would be a refusal, not a
        #: safety measure (WI-04).
        self._account_bound = False
        self.credential_state = "unknown"
        self.provider_error: str | None = None
        self._provider_errors: list[str] = []
        #: Why the scan could not do something, counted rather than dropped (the
        #: intelligence worker's own ``skipped`` map, in the same shape). A scan that
        #: reports a count of findings and nothing else cannot be told apart from one
        #: whose targets were all refused.
        self._skipped: dict[str, int] = {}
        #: One ``/breach/{name}`` answer per incident per scan: the same incident
        #: names every affected address, and asking for it once per address is the
        #: request amplification WI-03 removes.
        self._metadata_cache: dict[str, dict | None] = {}
        self._limiter = RateLimiter(
            POLICY["requests_per_minute"][2], POLICY["burst"][2]
        )
        #: Which of our domains the account may be asked about, and what it answered
        #: about the subscription. Both are read once per scan and reported: a domain
        #: the account may not ask about must not read as a domain with no breaches
        #: (F-04, WI-14).
        self._subscribed_domains: set[str] | None = None
        #: Domains that were asked about and refused, by reason. Read by the summary
        #: and by nothing else: the finding flow is untouched.
        self._domains_unscanned: dict[str, str] = {}
        self._domain_http: dict[str, int] = {}
        #: The account's own accounting from the last reservation (WI-15). ``None``
        #: when no account is bound, which is when there is no budget to report.
        self._account_budget: int | None = None
        self._remaining_today: int | None = None
        self._budget_left = POLICY["max_requests_per_scan"][2]
        self._budget_started = self._budget_left
        #: The source's own words for the classes of data it reports (F-04), cached for
        #: the life of the worker: a vocabulary is reference data rather than a fact about
        #: one scan, and ``None`` is "not read yet" — distinct from a source that answered
        #: with nothing, which is an empty mapping.
        self._data_class_labels: dict[str, str] | None = None
        self._data_class_labels_read = False
        #: ``True`` only when the scan stopped with work still to do because there
        #: was nothing left to spend. A scan that used its whole budget on the work
        #: it was given is not a scan that was cut short, and the summary has to be
        #: able to tell those apart.
        self._stopped_short = False
        #: What the subscription said about stealer-log access: ``True``/``False`` when
        #: ``/subscription/status`` answered the key at all, ``None`` when it did not.
        #: Only an explicit ``True`` lets the paid routes be called — a missing answer
        #: is not permission, and a 403 discovered by asking is a request spent to
        #: learn something this row already knows (WI-18).
        self._stealer_logs_entitled: bool | None = None
        #: The switch as the last scan read it. Readiness is published before a scan's
        #: config is known (registration), so the row reports the last state the worker
        #: was actually told rather than a default it never applied.
        self._stealer_logs_enabled = FLAGS["stealer_logs_enabled"]
        #: Whether this subscription offers the hash-range search (``IncludesKAnon``):
        #: ``True``/``False`` when the provider stated it, ``None`` when it did not. Only
        #: an explicit ``True`` replaces the address form; a paid route is not spent on
        #: an assumption, and the summary names which form was used either way (WI-19).
        self._kanon_entitled: bool | None = None
        self._range_lookup_enabled = FLAGS["breachedaccount_range_enabled"]
        self._pastes_enabled = FLAGS["pastes_enabled"]
        #: What the hash form did, per scan: prefixes asked, buckets whose suffix was
        #: ours, negatives, the mixed-case retries, and incident names whose metadata did
        #: not arrive. Counted because "we asked and nothing matched" and "we could not
        #: ask" are different sentences about an address (F-04).
        self._range_prefixes_asked = 0
        self._range_matched = 0
        self._range_unmatched = 0
        self._range_case_retries = 0
        self._range_metadata_missing = 0
        #: The domain-shaped stealer-log routes have their own, lower allowance; they
        #: are paced by both buckets rather than by the key's alone.
        self._stealer_limiter = RateLimiter(
            POLICY["stealer_logs_domain_requests_per_minute"][2], 1
        )

    # ------------------------------------------------------------------
    # Run state
    # ------------------------------------------------------------------

    async def register(self) -> None:
        await super().register()
        await self.refresh_credential()
        await self.report_readiness()

    async def refresh_credential(self) -> None:
        """Take the key the core holds for this connector's account, if there is one.

        An answer of ``configured: false`` is not an error: it is an installation
        whose key is in its own environment, which is how this worker ran before an
        account existed. A network or HTTP failure likewise keeps the last key, so
        a restart of the core cannot stop a scan that already has one.
        """
        try:
            response = await self._request(
                "GET", "/api/v1/connectors/me/credential"
            )
            key = _core_credential(response.json())
        except (ConnectorAPIError, ValueError) as exc:
            log.warning("hibp_credential_refresh_failed", err=type(exc).__name__)
            return
        self._account_bound = key is not None
        self.api_key = key or self._env_api_key

    def credentials_configured(self) -> bool:
        """Whether this worker holds a key at all, from the core or its environment.

        Readiness is published after every credential read, so this answers for the
        key that will actually be used rather than only for the container's env.
        """
        return bool(self.api_key)

    def readiness_capabilities(self) -> list[str]:
        """The declaration, plus the paid route only while the operator enabled it.

        The Settings page reads this row to answer "can this source scan?", and the
        core reads the capability list before it admits a scan — a worker whose key
        is absent is not a worker that found nothing (F-04).
        """
        capabilities = list(self.CAPABILITIES)
        if self._stealer_logs_entitled and self._stealer_logs_enabled:
            capabilities.append("stealer_log")
        return capabilities

    def readiness_payload(self) -> dict:
        """Publish the provider's own data-class labels even before they are read.

        An empty mapping is a statement ("this worker has no vocabulary yet"), and
        the page distinguishes it from a missing field, so the key is always sent.
        """
        payload = super().readiness_payload()
        payload["data_class_labels"] = dict(self._data_class_labels or {})
        return payload

    async def _reserve(self, bucket: str) -> bool:
        """Charge one provider request to the account's budget, or stop asking.

        Without an account this is a no-op: the environment key is not a budget the
        platform can see, and inventing one would refuse scans on installations that
        never configured a source account. With one, a refusal is the account's own
        answer — exhausted, revoked, disabled — and the scan stops and says so,
        rather than spending past it.
        """
        if not self._account_bound:
            return True
        try:
            accounting = await self.reserve_provider_request(bucket)
        except ConnectorAPIError as exc:
            self._skip(
                {
                    429: "provider_budget_exhausted",
                    403: "provider_access_denied",
                    409: "provider_source_disabled",
                }.get(exc.status_code, "provider_budget_unavailable")
            )
            self._stopped_short = True
            return False
        budget = accounting.get("request_budget")
        if isinstance(budget, int) and not isinstance(budget, bool):
            self._account_budget = budget
        remaining = accounting.get("remaining_today")
        if isinstance(remaining, int) and not isinstance(remaining, bool):
            self._remaining_today = remaining
        return True

    def manifest_payload(self) -> dict:
        """Declare the policy keys, so the core renders them instead of a constant.

        The numbers ride in the manifest for the same reason the scan validates
        against the same table: an operator editing a range in the Settings page and
        a worker enforcing a different one is how a setting stops being one.
        """
        manifest = super().manifest_payload()
        manifest.setdefault(
            "config_schema",
            {
                **{
                    key: {
                        "type": "int",
                        "default": limits[2],
                        "description": f"Integer {limits[0]}..{limits[1]}",
                        "label": key.replace("_", " "),
                    }
                    for key, limits in POLICY.items()
                },
                **{
                    key: {
                        "type": "bool",
                        "default": default,
                        "description": "Switch; off unless the operator turns it on",
                        "label": key.replace("_", " "),
                    }
                    for key, default in FLAGS.items()
                },
            },
        )
        return manifest

    def _stealer_logs_plan(self, params, policy, enabled: bool) -> dict:
        """Whether this scan may spend the paid routes at all, and why not (WI-18).

        Three separate answers, because they need three different operators: the pass is
        off (a setting), the subscription does not include stealer logs (a plan), or the
        last pass is inside the interval (nothing to do). ``subscription_unknown`` is a
        fourth: the provider was not asked, or did not answer, and a paid route is not
        called on an assumption.

        The interval is read from the core's answer about the last stealer-log exposure
        it holds, so a worker restarted between two scans does not repeat the week's
        spend, and a fresh installation asks on its first scan.
        """
        window = params.get("stealer_logs")
        window = window if isinstance(window, dict) else {}
        last = window.get("last_seen_at")
        last_text = last.strip() if isinstance(last, str) and last.strip() else None
        plan: dict[str, object] = {
            "status": "skipped",
            "enabled": enabled,
            "due": False,
            "interval_hours": int(policy["stealer_logs_interval_hours"]),
            "last_seen_at": last_text,
        }
        if not enabled:
            plan["reason"] = "disabled"
            return plan
        if self._stealer_logs_entitled is not True:
            plan["reason"] = (
                "not_in_subscription"
                if self._stealer_logs_entitled is False
                else "subscription_unknown"
            )
            self._skip(f"stealer_logs_{plan['reason']}")
            return plan
        if last_text:
            try:
                seen = _aware(_dt.fromisoformat(last_text.replace("Z", "+00:00")))
            except ValueError:
                seen = None
            if seen is not None:
                elapsed = _dt.now(_timezone.utc) - seen
                if elapsed < _timedelta(hours=int(policy["stealer_logs_interval_hours"])):
                    plan["reason"] = "not_due"
                    plan["hours_since_last"] = round(elapsed.total_seconds() / 3600, 2)
                    return plan
        plan["status"] = "ran"
        plan["due"] = True
        return plan

    def _skip(self, reason: str) -> None:
        self._skipped[reason] = self._skipped.get(reason, 0) + 1

    def _out_of_budget(self) -> bool:
        """Whether the scan must stop: nothing left to spend, and it said so.

        Called at the top of each unit of work rather than after it, so a lookup that
        was never made is never counted as one this scan asked about.
        """
        if self._budget_left > 0:
            return False
        self._stopped_short = True
        self._skip("request_budget_exhausted")
        return True

    # ------------------------------------------------------------------
    # HIBP API
    # ------------------------------------------------------------------

    def _hibp_headers(self) -> dict:
        return {**self.UA, "hibp-api-key": self.api_key}

    async def _get(
        self,
        client: httpx.AsyncClient,
        url: str,
        *,
        params: dict | None = None,
        headers: dict | None = None,
        bucket: str = "search",
        extra_limiter: "RateLimiter | None" = None,
    ) -> httpx.Response | None:
        """One provider call, under the run's pace and its request budget.

        Returns ``None`` when the call was not made at all (the budget is spent, or
        the bound account refused it) or when it raised; both are counted, so the
        summary can tell "we stopped asking" from "the provider answered nothing".
        """
        if self._out_of_budget():
            return None
        if not await self._reserve(bucket):
            return None
        await self._limiter.acquire()
        if extra_limiter is not None:
            # A route with its own, lower allowance waits for both: the key's pace is
            # not permission to spend a per-route limit faster than it exists (WI-18).
            await extra_limiter.acquire()
        self._budget_left -= 1
        try:
            response = await client.get(url, params=params, headers=headers)
        except Exception as exc:  # noqa: BLE001 - any transport failure is one outcome
            self._provider_errors.append("network_error")
            log.warning("hibp_network_failed", err=str(exc)[:200])
            return None
        if response.status_code == 429:
            # The provider's own answer about when to come back. Read before the
            # error is classified, because the pause applies even when the caller
            # treats the status as just another failure.
            retry_after = _retry_after_seconds(response.headers.get("Retry-After"))
            if retry_after:
                self._limiter.pause(retry_after)
        elif response.status_code == 401:
            # The key itself was refused, which is a statement about the credential
            # rather than about this incident: the readiness row has to carry it, or
            # an operator sees a scan that found nothing (F-04).
            self.credential_state = "invalid"
            self.provider_error = "invalid_credentials"
        elif response.status_code == 200:
            self.credential_state = "valid"
            self.provider_error = None
        return response

    async def _post(
        self,
        client: httpx.AsyncClient,
        url: str,
        *,
        json: dict,
        headers: dict | None = None,
        bucket: str = "search",
    ) -> httpx.Response | None:
        """One provider call that carries a body, under the same pace and budget.

        The verification routes answer questions about one domain and take their input in
        the body rather than the path, so this mirrors :meth:`_get`: the same budget
        check, the same reservation against the account, the same ``Retry-After`` and
        credential bookkeeping. A second way of spending money would be the thing that is
        not paced.
        """
        if self._out_of_budget():
            return None
        if not await self._reserve(bucket):
            return None
        await self._limiter.acquire()
        self._budget_left -= 1
        try:
            response = await client.post(url, json=json, headers=headers)
        except Exception as exc:  # noqa: BLE001 - any transport failure is one outcome
            self._provider_errors.append("network_error")
            log.warning("hibp_network_failed", err=str(exc)[:200])
            return None
        if response.status_code == 429:
            retry_after = _retry_after_seconds(response.headers.get("Retry-After"))
            if retry_after:
                self._limiter.pause(retry_after)
        elif response.status_code == 401:
            self.credential_state = "invalid"
            self.provider_error = "invalid_credentials"
        elif response.status_code == 200:
            self.credential_state = "valid"
            self.provider_error = None
        return response

    async def generate_domain_token(self, client: httpx.AsyncClient, domain: str) -> dict:
        """The DNS record this domain has to publish, as the provider states it (WI-20).

        The value is returned exactly as the provider gave it, because that is what the
        operator pastes into the zone: shortening or re-formatting it would produce a
        record the provider then refuses. Only the shape is checked — a 200 whose body has
        no value is a malformed answer, not an empty record.
        """
        response = await self._post(
            client,
            f"{self.BASE}/domainVerification/generateDnsToken",
            json={"DomainName": domain},
            headers=self._hibp_headers(),
            bucket="lookup",
        )
        if response is None:
            return {"status": "failed", "reason": "not_answered"}
        if response.status_code != 200:
            self._provider_errors.append(f"http_{response.status_code}")
            log.warning(
                "hibp_verification_generate_failed",
                status=response.status_code,
                err=response.text[:200],
            )
            return {"status": "failed", "reason": _verification_reason(response.status_code)}
        payload = _json_object(response)
        value = str((payload or {}).get("txtRecordValue") or "").strip()
        if not value:
            self._provider_errors.append("invalid_json")
            return {"status": "failed", "reason": "malformed_answer"}
        return {"status": "generated", "txt_record_value": value[:1024]}

    async def verify_domain_token(self, client: httpx.AsyncClient, domain: str) -> dict:
        """Whether the published token is there yet, in four distinct words (WI-20).

        ``verified`` is the provider's 200. A 400 is ``not_verified`` rather than
        ``failed``: that is the answer a domain whose TXT record has not propagated yet
        gets, and an operator reading "failed" would go looking for a problem that is
        usually just DNS TTL. Everything else is a refusal or a transport failure, and is
        reported as such instead of as "the record is missing".
        """
        response = await self._post(
            client,
            f"{self.BASE}/domainVerification/verifyDnsToken",
            json={"DomainName": domain},
            headers=self._hibp_headers(),
            bucket="lookup",
        )
        if response is None:
            return {"status": "failed", "reason": "not_answered"}
        if response.status_code == 200:
            return {"status": "verified"}
        if response.status_code == 400:
            # Documented as the answer for a token the provider cannot find on the domain: a
            # normal step of the flow rather than an error, so it is not a provider error.
            return {"status": "not_verified", "reason": "token_not_found"}
        self._provider_errors.append(f"http_{response.status_code}")
        log.warning(
            "hibp_verification_verify_failed",
            status=response.status_code,
            err=response.text[:200],
        )
        return {"status": "failed", "reason": _verification_reason(response.status_code)}

    async def run_domain_verification(
        self, work: dict, policy: dict, request: dict, *, reset_readiness: bool = True
    ) -> tuple[list[dict], dict]:
        """One verification question, as the whole job (WI-20).

        Returns no findings — verification creates exposure by *allowing* a later scan, not
        by storing a row — and its summary is what the core reads back: the TXT value to
        publish, or the word for what went wrong, plus what the call cost.
        """
        action = str(request.get("action") or "").strip().lower()
        domain = str(request.get("domain") or "").strip().lower()
        if reset_readiness:
            self._provider_errors = []
            self._skipped = {}
        self._budget_started = policy["max_requests_per_scan"]
        self._budget_left = policy["max_requests_per_scan"]
        self._stopped_short = False
        outcome: dict = {
            "action": action,
            "domain": domain,
            "status": "failed",
            "reason": None,
            "txt_record_value": None,
        }
        if action not in VERIFICATION_ACTIONS or not domain:
            # The core validates both before queueing; a direct caller that names something
            # else is refused by name rather than asked of the provider.
            outcome["reason"] = "invalid_request"
        else:
            timeout = httpx.Timeout(30.0)
            async with httpx.AsyncClient(timeout=timeout) as client:
                if action == VERIFICATION_GENERATE:
                    result = await self.generate_domain_token(client, domain)
                else:
                    result = await self.verify_domain_token(client, domain)
            outcome.update(result)
            if outcome["status"] == "failed":
                self._skip(f"domain_verification_{outcome['reason']}")
        summary = {
            "task": "hibp_domain_verification",
            "domain_verification": outcome,
            "requests_spent": self._budget_started - self._budget_left,
            "request_budget": self._budget_started,
            "budget_exhausted": self._stopped_short,
            "skipped_reasons": dict(sorted(self._skipped.items())),
            "provider_errors": sorted(set(self._provider_errors)),
            "status": "success" if outcome["status"] != "failed" else "partial",
        }
        try:
            await self.report_readiness()
        except ConnectorAPIError as exc:
            log.warning("hibp_readiness_report_failed", err=type(exc).__name__)
        return [], summary

    async def search_email_breaches(self, client: httpx.AsyncClient, email: str) -> list[dict]:
        if not self.api_key:
            return []
        url = f"{self.BASE}/breachedaccount/{email}"
        params = {"truncateResponse": "false", "includeUnverified": "true"}
        response = await self._get(
            client, url, params=params, headers=self._hibp_headers(), bucket="lookup"
        )
        if response is None:
            return []
        if response.status_code == 404:
            return []
        if response.status_code != 200:
            self._provider_errors.append(f"http_{response.status_code}")
            log.warning(
                "hibp_email_http_error",
                status=response.status_code,
                err=response.text[:200],
            )
            return []
        try:
            return response.json() or []
        except Exception as exc:  # noqa: BLE001 - a malformed body is one outcome
            self._provider_errors.append("invalid_json")
            log.warning("hibp_email_json_failed", err=str(exc)[:200])
            return []

    async def search_domain_breaches(self, client: httpx.AsyncClient, domain: str) -> dict[str, list[str]]:
        """Returns {alias: [breach names]} for every breached address."""
        if not self.api_key:
            return {}
        url = f"{self.BASE}/breacheddomain/{domain}"
        response = await self._get(
            client, url, headers=self._hibp_headers(), bucket="lookup"
        )
        if response is None:
            return {}
        if response.status_code == 404:
            return {}
        if response.status_code != 200:
            # Remembered per domain, because a refusal is about *this* domain rather
            # than about the scan: the summary has to be able to say the domain was
            # not asked about instead of reporting an empty result (F-04).
            self._domain_http[str(domain)] = response.status_code
            self._provider_errors.append(f"http_{response.status_code}")
            log.warning(
                "hibp_domain_http_error",
                domain=domain,
                status=response.status_code,
                err=response.text[:200],
            )
            return {}
        try:
            raw = response.json()
        except Exception as exc:  # noqa: BLE001 - a malformed body is one outcome
            self._provider_errors.append("invalid_json")
            log.warning("hibp_domain_json_failed", err=str(exc)[:200])
            return {}
        result: dict[str, list[str]] = {}
        if isinstance(raw, dict):
            for alias, value in raw.items():
                a = str(alias).strip()
                if not a:
                    continue
                names: list[str] = []
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, str) and item.strip():
                            names.append(item.strip()[:255])
                        elif isinstance(item, dict):
                            n = item.get("Name")
                            if isinstance(n, str) and n.strip():
                                names.append(n.strip()[:255])
                if names:
                    result[a[:255]] = names
        return result

    def _lookup_form(self) -> tuple[bool, str | None]:
        """Whether an address search is replaced by a hash range, and why not.

        Three answers, and they need three different operators: the operator turned the
        range form off (a setting), the subscription does not include it (a plan), or the
        provider was never asked what the plan includes (an unread question is not
        permission to spend a paid route). In the last two cases the documented address
        form is used, which is the behaviour this worker had before the range existed and
        the one every plan supports — and the summary states it, so "the address form was
        used" is never something an operator has to infer (WI-19).
        """
        if not self._range_lookup_enabled:
            return False, "disabled_by_operator"
        if self._kanon_entitled is True:
            return True, None
        return False, (
            "not_in_subscription" if self._kanon_entitled is False else "subscription_unknown"
        )

    async def range_breach_names(
        self, client: httpx.AsyncClient, email: str, *, case: str = "lower"
    ) -> tuple[list[str], bool] | None:
        """The incidents a hash prefix is in, and whether our suffix was among them.

        Returns ``(names, matched)``, or ``None`` when the question was not answered. The
        provider's bucket holds every account that shares the prefix, so the entry is
        identified by the *suffix*: an entry whose ``hashSuffix`` is not ours belongs to
        somebody else and contributes nothing — matching on the prefix alone would
        attribute a stranger's incidents to this installation.
        """
        if not self.api_key:
            return None
        prefix, suffix = _email_hash_parts(email, case=case)
        response = await self._get(
            client,
            f"{self.BASE}/breachedaccount/range/{prefix}",
            headers=self._hibp_headers(),
            bucket="lookup",
        )
        if response is None:
            return None
        if response.status_code == 404:
            # Documented as "nothing in this range", which is an answer about the bucket
            # rather than a refusal.
            return [], False
        if response.status_code != 200:
            self._provider_errors.append(f"http_{response.status_code}")
            log.warning(
                "hibp_range_http_error", status=response.status_code, err=response.text[:200]
            )
            return None
        payload = _json_value(response)
        if not isinstance(payload, list):
            self._provider_errors.append("invalid_json")
            return None
        names: list[str] = []
        matched = False
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            if str(entry.get("hashSuffix") or "").strip().upper() != suffix:
                continue
            matched = True
            websites = entry.get("websites")
            if not isinstance(websites, list):
                continue
            for item in websites:
                if isinstance(item, str) and item.strip() and item.strip()[:255] not in names:
                    names.append(item.strip()[:255])
        return names, matched

    async def _range_breach_names(
        self, client: httpx.AsyncClient, email: str
    ) -> tuple[list[str], bool, int] | None:
        """The hash lookup, with one retry when a mixed-case address matches nothing.

        ``(names, matched, attempts)``, or ``None`` when neither attempt was answered.
        The retry exists because the provider documents *that* it hashes the address but
        not how it normalizes it first: for an address that could hash two ways, a
        negative answer on the lowercased digest is confirmed with the raw-case one. It
        costs one request, only for such an address, and only when the first answer was
        negative — the alternative is a real account reading as "not breached".
        """
        outcome = await self.range_breach_names(client, email)
        if outcome is None:
            return None
        names, matched = outcome
        attempts = 1
        if not matched and any(character.isupper() for character in email):
            retried = await self.range_breach_names(client, email, case="raw")
            if retried is not None:
                attempts = 2
                names, matched = retried
        return names, matched, attempts

    async def range_email_breaches(self, client: httpx.AsyncClient, email: str) -> list[dict] | None:
        """The incidents of one address, read without the address leaving (WI-19).

        ``None`` is an unanswered question, and a list either way otherwise — including
        the empty one a bucket with no matching suffix produces, which is the negative
        answer. Every named incident is then read from the catalogue exactly as a domain
        alias reads it, so the range form and the address form produce the same rows from
        the same metadata; an incident whose metadata does not arrive is counted rather
        than submitted without a date (F-02).
        """
        outcome = await self._range_breach_names(client, email)
        if outcome is None:
            return None
        names, matched, attempts = outcome
        self._range_prefixes_asked += 1
        self._range_case_retries += attempts - 1
        if matched:
            self._range_matched += 1
        else:
            self._range_unmatched += 1
        incidents: list[dict] = []
        for name in names:
            if self._out_of_budget():
                return incidents
            meta = await self.get_breach_metadata(client, name)
            if meta is None:
                self._range_metadata_missing += 1
                continue
            incidents.append(meta)
        return incidents

    async def search_pastes(self, client: httpx.AsyncClient, email: str) -> list[dict] | None:
        """The pastes a provider knows this address appears in (WI-17).

        ``None`` is "the question was not answered" — no key, a refusal, a body that is
        not a list — and an empty list is a provider that answered with nothing. A
        caller that treated both the same would report a refused lookup as a clean
        address, which is the F-04 defect in a new place.
        """
        if not self.api_key:
            return None
        response = await self._get(
            client,
            f"{self.BASE}/pasteAccount/{email}",
            headers=self._hibp_headers(),
            bucket="lookup",
        )
        if response is None:
            return None
        if response.status_code == 404:
            # Documented as "no pastes": an answer, not a refusal.
            return []
        if response.status_code != 200:
            self._provider_errors.append(f"http_{response.status_code}")
            log.warning(
                "hibp_paste_http_error", status=response.status_code, err=response.text[:200]
            )
            return None
        payload = _json_value(response)
        if not isinstance(payload, list):
            self._provider_errors.append("invalid_json")
            return None
        return payload

    async def search_stealer_log_sites(
        self, client: httpx.AsyncClient, email: str
    ) -> list[str] | None:
        """The websites a stealer log names for one address (WI-18).

        Returns the site names, or ``None`` when the question was not answered. A `404`
        is the documented "nothing for this address" and becomes an empty list.
        """
        if not self.api_key:
            return None
        response = await self._get(
            client,
            f"{self.BASE}/stealerLogsByEmail/{email}",
            headers=self._hibp_headers(),
            bucket="lookup",
        )
        if response is None:
            return None
        if response.status_code == 404:
            return []
        if response.status_code != 200:
            self._provider_errors.append(f"http_{response.status_code}")
            log.warning(
                "hibp_stealer_email_http_error",
                status=response.status_code,
                err=response.text[:200],
            )
            return None
        payload = _json_value(response)
        names = _site_names(payload)
        if names is None:
            self._provider_errors.append("invalid_json")
        return names

    async def search_stealer_logs_for_email_domain(
        self, client: httpx.AsyncClient, domain: str
    ) -> dict[str, list[str]] | None:
        """Alias -> websites for one monitored domain, under the route's own pace.

        The provider documents these domain routes with a separate, much lower
        allowance than the key's, so the request waits on both buckets (WI-18).
        ``None`` is an unanswered question, and an empty mapping a domain with no
        entries.
        """
        if not self.api_key:
            return None
        response = await self._get(
            client,
            f"{self.BASE}/stealerLogsByEmailDomain/{domain}",
            headers=self._hibp_headers(),
            bucket="lookup",
            extra_limiter=self._stealer_limiter,
        )
        if response is None:
            return None
        if response.status_code == 404:
            return {}
        if response.status_code != 200:
            # Remembered per domain like every other refusal, so the summary can say
            # the domain was not scanned instead of that it had nothing (F-04).
            self._domain_http[str(domain)] = response.status_code
            self._provider_errors.append(f"http_{response.status_code}")
            log.warning(
                "hibp_stealer_domain_http_error",
                domain=domain,
                status=response.status_code,
                err=response.text[:200],
            )
            return None
        payload = _json_value(response)
        if not isinstance(payload, dict):
            self._provider_errors.append("invalid_json")
            return None
        result: dict[str, list[str]] = {}
        for alias, value in payload.items():
            name = str(alias).strip()
            if not name:
                continue
            sites = _site_names(value)
            if sites:
                result[name[:255]] = sites
        return result

    # ------------------------------------------------------------------
    # Provider readiness
    # ------------------------------------------------------------------

    def _domain_refusal_reason(self, domain: str) -> str:
        """Why a domain was refused, in the words the readiness row can act on.

        ``403`` on ``/breacheddomain`` means either "this account has not verified
        that domain" or "the domain is verified but outside what this subscription
        allows", and the two need different operators. ``/subscribedDomains`` is what
        tells them apart: a domain it names was refused for the plan's reasons, and a
        domain it does not name has not been verified. When that list could not be
        read at all, the refusal stays unnamed rather than guessed at.
        """
        if self._subscribed_domains is None:
            return "domain_access_denied"
        return (
            "domain_not_verified"
            if str(domain).strip().lower() not in self._subscribed_domains
            else "domain_outside_allowance"
        )

    async def read_provider_readiness(self, client: httpx.AsyncClient) -> dict:
        """What the key is entitled to, and which domains it may be asked about.

        Two questions, both provider requests like any other — paced, budgeted and
        reserved against the account — and both best effort: a refusal leaves the
        answer *unknown*, which the summary states, rather than being read as "there
        is nothing to find" (WI-14, WI-15).
        """
        facts: dict[str, object] = {}
        response = await self._get(
            client, f"{self.BASE}/subscription/status", headers=self._hibp_headers(), bucket="lookup"
        )
        payload = _json_object(response)
        if payload is not None:
            name = str(payload.get("SubscriptionName") or "")[:64]
            if name:
                facts["subscription"] = name
            rpm = payload.get("Rpm")
            if isinstance(rpm, int) and not isinstance(rpm, bool) and rpm > 0:
                # Only when the provider states one: the public status shape is
                # versioned per account, and inventing a pace from a field that is
                # absent is how this worker got a fixed sleep in the first place.
                facts["reported_requests_per_minute"] = rpm
            for key, name in (
                ("IncludesStealerLogs", "includes_stealer_logs"),
                ("IncludesKAnon", "includes_kanon"),
            ):
                if key in payload:
                    facts[name] = bool(payload.get(key))
            # Kept on the worker because the paid routes are gated on it, and the
            # answer has to outlive this function: absent means the provider did not
            # state it, which is not the same as stating ``false`` (WI-18).
            if isinstance(facts.get("includes_stealer_logs"), bool):
                self._stealer_logs_entitled = bool(facts["includes_stealer_logs"])
            # The range search is gated the same way and kept for the same reason: the
            # answer decides which form the address search uses (WI-19).
            if isinstance(facts.get("includes_kanon"), bool):
                self._kanon_entitled = bool(facts["includes_kanon"])
        elif response is not None:
            facts["subscription_status_http"] = response.status_code

        response = await self._get(
            client, f"{self.BASE}/subscribedDomains", headers=self._hibp_headers(), bucket="lookup"
        )
        payload = _json_value(response)
        if isinstance(payload, list):
            self._subscribed_domains = {
                str(item).strip().lower()
                for item in payload
                if isinstance(item, str) and item.strip()
            }
            facts["subscribed_domains"] = len(self._subscribed_domains)
        elif response is not None:
            facts["subscribed_domains_http"] = response.status_code
        return facts

    # ------------------------------------------------------------------
    # Incident catalogue (WI-13)
    # ------------------------------------------------------------------

    async def catalogue_latest(self, client: httpx.AsyncClient) -> tuple[dict | None, bool]:
        """The most recently added incident: the cheapest question about a catalogue.

        Returns ``(incident, answered)``. ``answered`` is false when the question was not
        answered at all — the budget refused the request, the transport failed — and the
        caller then sweeps rather than reading "I could not ask" as "nothing changed". A
        ``404`` *is* an answer: this route names the newest incident and the provider has
        none, which is a catalogue nothing can be newer than.  Both spellings are
        returned because ``None`` alone cannot tell them apart.
        """
        response = await self._get(
            client, f"{self.BASE}/latestBreach", headers=self._hibp_headers(), bucket="search"
        )
        if response is None:
            return None, False
        if response.status_code not in (200, 404):
            self._provider_errors.append(f"http_{response.status_code}")
            return None, False
        return _json_object(response), True

    async def catalogue_sweep(self, client: httpx.AsyncClient, limit: int) -> dict:
        """The source's whole catalogue, bounded, as entries the core accepts.

        ``entries`` is what the core may be sent, ``truncated`` says the corpus was
        longer than the bound — the provider answers this route with everything it has in
        one body, so the bound is what keeps a first sync of a fresh installation a fixed
        cost — and ``answered`` separates a provider that read out its catalogue from one
        that refused or did not answer: an unanswered sweep is not an empty catalogue.
        """
        response = await self._get(
            client, f"{self.BASE}/breaches", headers=self._hibp_headers(), bucket="search"
        )
        if response is None:
            return {"entries": [], "truncated": False, "answered": False}
        payload = _json_value(response)
        if not isinstance(payload, list):
            self._provider_errors.append(f"http_{response.status_code}")
            log.warning("hibp_catalogue_http_error", status=response.status_code)
            return {"entries": [], "truncated": False, "answered": False}
        entries = [entry for entry in (_catalogue_entry(item) for item in payload) if entry]
        return {
            "entries": entries[:limit],
            "truncated": len(entries) > limit,
            "answered": True,
        }

    async def sync_catalogue_phase(
        self, client: httpx.AsyncClient, work: dict, params: dict, policy: dict
    ) -> dict:
        """Read the catalogue and hand it to the core, in batches, before any scan.

        The checkpoint in the job's params says what the core already holds: with one, the
        sweep is skipped when ``/latestBreach`` says nothing was added or changed since;
        without one — a fresh installation, or a source never synced — the sweep is what
        tells the core where this installation stands. The returned mapping is the
        scan's own account of the work: a phase that reports only a count cannot be told
        apart from one whose provider refused to answer, which is what ``status`` and the
        truncation flag are for.
        """
        checkpoint = params.get("catalogue")
        checkpoint = checkpoint if isinstance(checkpoint, dict) else {}
        since = checkpoint.get("last_synced_at")
        summary: dict[str, object] = {
            "status": CATALOGUE_FAILED,
            "checkpoint": since,
            "stored_before": int(checkpoint.get("incidents") or 0),
            "swept": False,
            "entries_read": 0,
            "entries_stored": 0,
            "created": 0,
            "updated": 0,
            "unchanged": 0,
            "new_incidents": 0,
        }
        if since:
            latest, answered = await self.catalogue_latest(client)
            if not answered:
                # The cheap question was not answered, so the expensive one is asked: a
                # sweep the provider refuses costs the same as one it answers, and a
                # worker that skipped it would leave the core's catalogue frozen.
                summary["latest_unavailable"] = True
            elif latest is None:
                # A 404 from a route that names the newest incident: there is nothing a
                # sweep could find that is newer than the checkpoint.
                summary["status"] = CATALOGUE_UP_TO_DATE
                summary["latest_empty"] = True
                return summary
            elif not _catalogue_changed_since(latest, str(since)):
                summary["status"] = CATALOGUE_UP_TO_DATE
                return summary
        sweep = await self.catalogue_sweep(client, int(policy["max_catalogue_entries"]))
        entries = sweep["entries"]
        summary["swept"] = True
        summary["entries_read"] = len(entries)
        summary["truncated"] = sweep["truncated"]
        if not sweep["answered"]:
            # Refused, or a body this worker cannot read: the phase stays *failed*, which
            # is the one status that says the catalogue in the core was not refreshed.
            return summary
        if sweep["truncated"]:
            # Counted like any other piece of work the scan could not finish, so the
            # summary says the catalogue it stored is short rather than complete.
            self._skip("catalogue_truncated")
        if not entries:
            # The provider answered, and its corpus is empty. Stated rather than left to
            # a count of zero, because "nothing in the catalogue" and "never asked" are
            # different sentences about the domains being watched.
            summary["status"] = CATALOGUE_SYNCED
            summary["empty"] = True
            return summary
        stored = 0
        for start in range(0, len(entries), CATALOGUE_BATCH):
            batch = entries[start : start + CATALOGUE_BATCH]
            result = await self.submit_catalogue(work["job_id"], batch)
            stored += int(result.get("received", 0))
            for key in ("created", "updated", "unchanged", "new_incidents"):
                summary[key] = int(summary[key]) + int(result.get(key, 0))
        summary["entries_stored"] = stored
        summary["status"] = CATALOGUE_SYNCED
        return summary

    async def read_data_class_labels(self, client: httpx.AsyncClient) -> dict[str, str]:
        """The source's own words for the classes of data it reports (F-04).

        Read once for the life of the worker and republished with every readiness row: a
        provider's vocabulary is reference data, so re-asking per scan would spend a
        request on a question whose answer cannot have changed. Best effort — a source
        without the route, or one that refuses it, publishes nothing, and the page falls
        back to the stored class name, which is what it showed before labels existed.
        """
        if self._data_class_labels is not None:
            return self._data_class_labels
        response = await self._get(
            client,
            f"{self.BASE}/dataClasses/descriptions",
            headers=self._hibp_headers(),
            bucket="search",
        )
        payload = _json_value(response)
        labels: dict[str, str] = {}
        if isinstance(payload, dict):
            for key, value in payload.items():
                if not (isinstance(key, str) and isinstance(value, str)):
                    continue
                name, description = key.strip(), value.strip()
                if not name or not description:
                    continue
                labels[name[:128]] = description[:MAX_DATA_CLASS_LABEL_LEN]
                if len(labels) >= MAX_DATA_CLASS_LABELS:
                    break
        #: ``read`` says the provider *answered*, which is a different statement from
        #: "it answered with no labels over the ones it does not publish".
        self._data_class_labels_read = isinstance(payload, dict)
        self._data_class_labels = labels
        return labels

    async def get_breach_metadata(self, client: httpx.AsyncClient, breach_name: str) -> dict | None:
        """One incident's catalogue entry, asked for once per scan.

        ``None`` means the metadata did not arrive — a 404 for a name this API
        version does not know, a refusal, or a network failure — and the caller
        reports the *address* as incomplete. It used to be answered with a stub
        ``{"Name": name, "Title": name, "Domain": ""}``, which the core then stored
        as a finding with no date and no vendor: a row the platform made up, on a
        page an analyst reads as evidence (F-02).
        """
        safe = str(breach_name).strip()
        if not safe or len(safe) > 255:
            return None
        if safe in self._metadata_cache:
            return self._metadata_cache[safe]
        url = f"{self.BASE}/breach/{safe}"
        response = await self._get(client, url, headers=self.UA, bucket="lookup")
        metadata: dict | None = None
        if response is not None and response.status_code == 200:
            try:
                payload = response.json()
            except Exception:  # noqa: BLE001 - a malformed body is "no metadata"
                payload = None
            if isinstance(payload, dict):
                metadata = payload
        self._metadata_cache[safe] = metadata
        return metadata

    # ------------------------------------------------------------------
    # Finding normalization
    # ------------------------------------------------------------------

    def _normalize_breach(self, meta: dict) -> dict:
        """Map one upstream catalogue record onto the neutral finding schema.

        The core stores what every breach source can supply; everything this
        source knows *beyond* that (its own classification flags, the exposed
        secret sample, its catalogue timestamps and logo) travels in
        ``attributes``, so this connector declares its own payload shape instead
        of relying on the core modelling this vendor.
        """
        attributes: dict[str, object] = _provider_flags(meta)
        masked = _mask_password(meta.get("Password"))
        if masked:
            attributes["masked_password"] = masked
        added = _parse_dt(meta.get("AddedDate"))
        if added:
            attributes["added_date"] = added
        modified = _parse_dt(meta.get("ModifiedDate"))
        if modified:
            attributes["modified_date"] = modified
        logo = str(meta.get("LogoPath") or "")[:1024]
        if logo:
            attributes["logo_path"] = logo

        return {
            "breach_name": str(meta.get("Name", ""))[:255],
            "title": str(meta.get("Title", ""))[:255],
            "domain": str(meta.get("Domain") or "")[:255],
            "breach_date": _parse_date(meta.get("BreachDate")),
            "pwn_count": _parse_nonnegative_int(meta.get("PwnCount")),
            "description": (str(meta.get("Description") or "") or None),
            "data_classes": meta.get("DataClasses") or [],
            "attributes": attributes,
        }

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------

    async def run_scan(self, work: dict) -> tuple[list[dict], dict]:
        self._provider_errors = []
        self._skipped = {}
        self._metadata_cache = {}
        # One scan's answers about the account, and one scan's refusals: a domain
        # refused in the previous scan must not be reported as refused in this one,
        # whose /subscribedDomains answer may since have changed.
        self._subscribed_domains = None
        self._domains_unscanned = {}
        self._domain_http = {}
        self._account_budget = None
        self._remaining_today = None
        # Stealer-log access is re-asked every scan: a plan that lapsed since the last
        # one must stop the paid routes now, and ``None`` (the provider did not answer)
        # is a refusal to call them, not a carry-over of yesterday's permission.
        self._stealer_logs_entitled = None
        self._kanon_entitled = None
        self._range_prefixes_asked = 0
        self._range_matched = 0
        self._range_unmatched = 0
        self._range_case_retries = 0
        self._range_metadata_missing = 0
        # A key rotated in the core takes effect on the next scan rather than on the
        # next container restart, and the readiness row is refreshed with what this
        # scan learns about it (WI-04).
        self.credential_state = "unknown"
        self.provider_error = None
        await self.refresh_credential()
        policy = _policy_from_config(work.get("config"))
        flags = _flags_from_config(work.get("config"))
        self._stealer_logs_enabled = flags["stealer_logs_enabled"]
        self._range_lookup_enabled = flags["breachedaccount_range_enabled"]
        self._pastes_enabled = flags["pastes_enabled"]
        self._stealer_limiter = RateLimiter(
            policy["stealer_logs_domain_requests_per_minute"], 1
        )
        self._limiter = RateLimiter(
            policy["requests_per_minute"], policy["burst"]
        )
        self._budget_left = policy["max_requests_per_scan"]
        self._budget_started = self._budget_left
        self._stopped_short = False

        params = work.get("params") or {}
        emails = params.get("emails") or []
        domains = params.get("domains") or []
        # Targeted jobs are created by the API with an explicit snapshot.
        # Keep the connector contract generic: no provider-specific endpoint
        # logic is required in the core.

        # A domain-verification job is not a scan (WI-20). It is admitted through the same
        # route, claimed by the same worker and reported the same way, but it asks one
        # question about one domain and stores nothing: running the scan phases as well
        # would spend a whole scan's budget every time an operator copies a TXT record.
        verification = params.get("domain_verification")
        if isinstance(verification, dict):
            if not self.api_key:
                return [], {
                    "task": "hibp_domain_verification",
                    "skipped": "HIBP_API_KEY not configured",
                    "status": "skipped",
                    "domain_verification": {
                        "action": str(verification.get("action") or ""),
                        "domain": str(verification.get("domain") or ""),
                        "status": "failed",
                        "reason": "no_credential",
                        "txt_record_value": None,
                    },
                }
            return await self.run_domain_verification(
                work, policy, verification, reset_readiness=True
            )

        if not self.api_key:
            return [], {
                "task": "hibp_daily_scan",
                "skipped": "HIBP_API_KEY not configured",
                "status": "skipped",
                "new_breach_rows": 0,
            }

        # ``emails_scanned`` counts monitored *email assets* only. Domain
        # aliases are a different unit of work (one API call each, no asset
        # behind them) and used to be added to this counter, which made the
        # summary claim 15 "emails" for a single monitored mailbox.
        emails_scanned = 0
        #: Address questions the worker could not get an answer to at all. The address
        #: form has always been silent about this (it returns an empty list either way),
        #: which is why the range form counts it and reports it (F-04, WI-19).
        emails_unavailable = 0
        domains_scanned = 0
        aliases_found = 0
        new_rows = 0
        incomplete_aliases = 0
        incomplete_samples: list[str] = []
        aliases_over_limit = 0
        #: Pastes and stealer-log exposure (WI-17, WI-18). One count per unit of work
        #: and per reason it could not be done, so a phase that was refused is not an
        #: address with a clean identity.
        pastes_looked_up = 0
        paste_rows = 0
        pastes_unavailable = 0
        pastes_skipped = False
        stealer_emails_asked = 0
        stealer_domains_asked = 0
        stealer_sites = 0
        stealer_rows = 0
        stealer_sites_over_limit = 0
        stealer_aliases_over_limit = 0
        stealer_unavailable = 0
        pacing: dict[str, object] = {}
        #: The catalogue phase's own account of itself. Defaulted to *failed* rather
        #: than to an empty success: a phase that never ran must not read as a catalogue
        #: that had nothing to report (WI-13).
        catalogue: dict[str, object] = {
            "status": CATALOGUE_FAILED,
            "error": "not_attempted",
        }

        async def submit(batch: list[dict]) -> int:
            result = await self.submit_findings(work["job_id"], batch)
            return int(result.get("accepted", 0))

        async def submit_all(batch: list[dict]) -> int:
            """A phase's whole answer, in batches the core will accept.

            A paste list or a stealer-log dump can name more rows than one request may
            carry; splitting here is what keeps the bound at the edge from turning real
            exposure into a rejected submission.
            """
            stored = 0
            for start in range(0, len(batch), FINDINGS_BATCH):
                stored += await submit(batch[start : start + FINDINGS_BATCH])
            return stored

        timeout = httpx.Timeout(30.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            # 0. What the account can be asked, before anything is asked of it. The
            # answer also decides the pace: a subscription's own number is a ceiling
            # on the operator's, never a replacement for it (WI-14, WI-15).
            readiness = await self.read_provider_readiness(client)
            reported_rpm = readiness.get("reported_requests_per_minute")
            applied_rpm = policy["requests_per_minute"]
            if isinstance(reported_rpm, int) and reported_rpm > 0:
                applied_rpm = min(applied_rpm, reported_rpm)
                self._limiter = RateLimiter(applied_rpm, policy["burst"])
            pacing = {
                "configured_requests_per_minute": policy["requests_per_minute"],
                "applied_requests_per_minute": applied_rpm,
                "adjusted": applied_rpm != policy["requests_per_minute"],
                "stealer_logs_domain_requests_per_minute": policy[
                    "stealer_logs_domain_requests_per_minute"
                ],
            }
            # 0a. Whether the paid stealer-log routes may be asked at all (WI-18).
            # Decided here, once the subscription's own answer is known: a pass the
            # plan does not include, or one that is not due, spends nothing.
            stealer_plan = self._stealer_logs_plan(
                params, policy, flags["stealer_logs_enabled"]
            )
            # 0b. Which form the address search uses: the hash range when the plan
            # includes it, the documented address form otherwise. Decided once, from the
            # subscription's own answer, and reported in the summary (WI-19).
            range_form, range_reason = self._lookup_form()

            # 0a. The source's own vocabulary for the classes of data it reports (F-04).
            # Cached for the life of the worker and republished with readiness, so this
            # is one request per worker rather than one per scan.
            await self.read_data_class_labels(client)

            # 0b. The source's own catalogue, read before any address of ours is asked
            # about (WI-13): the incident nobody's address has reached yet is exactly
            # what a findings-only platform cannot see. A core that refuses the batch
            # must not cost the scan its findings, so a failure is reported and the
            # address scanning below carries on.
            try:
                catalogue = await self.sync_catalogue_phase(client, work, params, policy)
            except ConnectorAPIError as exc:
                log.warning("hibp_catalogue_sync_failed", err=type(exc).__name__)
                catalogue = {"status": CATALOGUE_FAILED, "error": "core_rejected_catalogue"}

            # 1. Email accounts.
            for email in emails:
                if self._out_of_budget():
                    break
                if range_form:
                    # The address is hashed here and only its prefix travels; the
                    # incidents come back as names and are read from the catalogue.
                    breaches = await self.range_email_breaches(client, email)
                    if breaches is None:
                        # Refused or unanswered: reported, and never quietly downgraded
                        # to the address form — the operator asked for the address not
                        # to leave, so sending it after a failure would be the opposite
                        # of what this form exists for.
                        emails_unavailable += 1
                        emails_scanned += 1
                        continue
                else:
                    breaches = await self.search_email_breaches(client, email)
                batch = []
                for b in breaches:
                    f = self._normalize_breach(b)
                    f["matched_email"] = email[:255]
                    f["matched_domain"] = None
                    batch.append(f)
                if batch:
                    new_rows += await submit(batch)
                emails_scanned += 1
                # 1a. Pastes: one request per address, one row per paste (WI-17). The
                # row is exposure of the same address in a different kind of document,
                # which is why it is a class of this module rather than a new one.
                if not self._pastes_enabled:
                    # The provider's paste route takes the address itself and has no hash
                    # form, so it is the one lookup a range-plan operator may want off
                    # (WI-19). Turned off, it is not asked and the phase says so.
                    pastes_skipped = True
                    continue
                if self._out_of_budget():
                    break
                entries = await self.search_pastes(client, email)
                if entries is None:
                    pastes_unavailable += 1
                    continue
                pastes_looked_up += 1
                paste_batch = [
                    item
                    for item in (_paste_finding(entry, email) for entry in entries)
                    if item
                ]
                if len(paste_batch) < len(entries):
                    # An entry with no id cannot be told from another paste of the same
                    # address; storing it would collapse both into one row.
                    self._skip("paste_without_id")
                if paste_batch:
                    paste_rows += await submit_all(paste_batch)

            # 2. Domains — alias expansion into per-address findings, bounded.
            for domain in domains:
                if self._out_of_budget():
                    break
                alias_map = await self.search_domain_breaches(client, domain)
                refused = self._domain_http.get(str(domain))
                if refused is not None:
                    # Not a scan that found nothing: the domain was refused, and the
                    # summary names why so the page and Jobs cannot disagree with
                    # each other about it (F-04).
                    reason = self._domain_refusal_reason(domain)
                    self._domains_unscanned[str(domain)] = reason
                    self._skip(reason)
                    domains_scanned += 1
                    continue
                aliases = list(alias_map.items())
                limit = policy["max_aliases_per_domain"]
                if len(aliases) > limit:
                    # A leaked list for a shared hosting domain is thousands of
                    # addresses, and every one of them is a metadata call. The bound
                    # is reported rather than silent: an operator whose domain
                    # genuinely needs more raises it, which is a decision about their
                    # own budget.
                    aliases_over_limit += len(aliases) - limit
                    aliases = aliases[:limit]
                for alias, breach_names in aliases:
                    if self._out_of_budget():
                        break
                    full_email = f"{alias}@{domain}"
                    batch = []
                    missing = 0
                    for name in breach_names:
                        meta = await self.get_breach_metadata(client, name)
                        if meta is None:
                            # No stub finding: the address is reported as incomplete
                            # below and the incident is not invented (WI-02).
                            missing += 1
                            continue
                        f = self._normalize_breach(meta)
                        f["matched_email"] = full_email[:255]
                        f["matched_domain"] = domain[:255]
                        batch.append(f)
                    if batch:
                        new_rows += await submit(batch)
                    if missing:
                        incomplete_aliases += 1
                        if len(incomplete_samples) < 5:
                            incomplete_samples.append(
                                f"{alias} ({missing} incident metadata unavailable)"
                            )
                    aliases_found += 1
                domains_scanned += 1

            # 3. Stealer-log exposure, when the operator asked for it, the plan
            # includes it and the week is up (WI-18). Asked last because it is the one
            # phase the provider sells separately: a scan that runs out of budget on
            # our own incidents should not have spent its last request on a site list.
            if stealer_plan["status"] == "ran":
                site_limit = policy["max_stealer_log_sites_per_asset"]
                for email in emails:
                    if self._out_of_budget():
                        break
                    sites = await self.search_stealer_log_sites(client, email)
                    if sites is None:
                        stealer_unavailable += 1
                        continue
                    stealer_emails_asked += 1
                    if len(sites) > site_limit:
                        stealer_sites_over_limit += len(sites) - site_limit
                        sites = sites[:site_limit]
                    stealer_sites += len(sites)
                    if sites:
                        stealer_rows += await submit_all(
                            [_stealer_log_finding(site, email, None) for site in sites]
                        )
                for domain in domains:
                    if self._out_of_budget():
                        break
                    mapping = await self.search_stealer_logs_for_email_domain(
                        client, domain
                    )
                    if mapping is None:
                        stealer_unavailable += 1
                        continue
                    stealer_domains_asked += 1
                    aliases = list(mapping.items())
                    alias_limit = policy["max_aliases_per_domain"]
                    if len(aliases) > alias_limit:
                        stealer_aliases_over_limit += len(aliases) - alias_limit
                        aliases = aliases[:alias_limit]
                    for alias, sites in aliases:
                        if self._out_of_budget():
                            break
                        if len(sites) > site_limit:
                            stealer_sites_over_limit += len(sites) - site_limit
                            sites = sites[:site_limit]
                        stealer_sites += len(sites)
                        if not sites:
                            continue
                        full_email = f"{alias}@{domain}"
                        stealer_rows += await submit_all(
                            [
                                _stealer_log_finding(site, full_email, domain)
                                for site in sites
                            ]
                        )
        summary = {
            "task": "hibp_daily_scan",
            "emails_scanned": emails_scanned,
            "domains_scanned": domains_scanned,
            "domain_aliases_found": aliases_found,
            "new_breach_rows": new_rows,
            # Pastes (WI-17): how many addresses were actually asked about, how many
            # rows that produced, and how many questions were refused — a lookup that
            # did not answer is not an address with no pastes.
            "pastes": {
                "status": "skipped" if pastes_skipped else "ran",
                "reason": "disabled" if pastes_skipped else None,
                "emails_looked_up": pastes_looked_up,
                "rows": paste_rows,
                "unavailable": pastes_unavailable,
            },
            # Which form the address search used, and what the hash form saw (WI-19):
            # "range" means no address left the platform, "cleartext" is the documented
            # form every plan supports, and the reason names whose decision that was.
            "email_lookup": {
                "form": "range" if range_form else "cleartext",
                "reason": range_reason,
                "emails_unavailable": emails_unavailable,
                # Which routes of this scan still name an address. The range form removes
                # the breach lookup from the list; it cannot remove a route the provider
                # only offers in address form, and the operator is told instead of left to
                # assume (WI-17, WI-19).
                "address_routes": (
                    [] if range_form else ["breachedaccount"]
                ) + (["pasteAccount"] if emails and self._pastes_enabled else []),
                "range": {
                    "prefixes_asked": self._range_prefixes_asked,
                    "matched": self._range_matched,
                    "unmatched": self._range_unmatched,
                    "case_retries": self._range_case_retries,
                    "metadata_missing": self._range_metadata_missing,
                },
            },
            # Stealer-log exposure (WI-18): the phase's own account of whether it ran
            # and why not, plus the weekly bound it applied to what it stored.
            "stealer_logs": {
                **stealer_plan,
                "emails_asked": stealer_emails_asked,
                "domains_asked": stealer_domains_asked,
                "sites": stealer_sites,
                "rows": stealer_rows,
                "sites_over_limit": stealer_sites_over_limit,
                "aliases_over_limit": stealer_aliases_over_limit,
                "unavailable": stealer_unavailable,
            },
            # What the scan could not do, and what it spent doing the rest: a job
            # that reports findings alone reads as a complete scan.
            "incomplete_aliases": incomplete_aliases,
            "incomplete_aliases_sample": incomplete_samples,
            "aliases_over_limit": aliases_over_limit,
            # What the key is entitled to ask, and which domains it may ask about:
            # facts the page and the job reader need in order to tell "the account may
            # not scan this domain" from "the domain has no breaches" (WI-14).
            "provider_readiness": readiness,
            # What the catalogue phase did: the checkpoint it was given, whether it
            # swept, how many incidents it stored and how many were new enough to name a
            # domain this installation watches (WI-13).
            "catalogue": catalogue,
            # What the source calls the classes of data it reports, and whether it
            # published any: the page renders the stored name when it did not (F-04).
            "data_class_labels": {
                "read": self._data_class_labels_read,
                "labels": len(self._data_class_labels or {}),
            },
            # Which domains were not asked about, and why, one row per domain.
            "domains_unscanned": [
                {"domain": domain, "reason": reason}
                for domain, reason in sorted(self._domains_unscanned.items())
            ],
            "pacing": pacing,
            # The bound account's own accounting, when there is one (WI-15). Absent
            # for an environment key, which is spending a budget nobody measured.
            **(
                {
                    "account_request_budget": self._account_budget,
                    "account_remaining_today": self._remaining_today,
                }
                if self._account_bound
                else {}
            ),
            "skipped_reasons": dict(sorted(self._skipped.items())),
            "requests_spent": self._budget_started - self._budget_left,
            "request_budget": self._budget_started,
            "budget_exhausted": self._stopped_short,
            "status": (
                "partial"
                if self._provider_errors
                or self._skipped
                or incomplete_aliases
                or pastes_unavailable
                or emails_unavailable
                or stealer_unavailable
                or catalogue.get("status") == CATALOGUE_FAILED
                else "success"
            ),
            "provider_errors": sorted(set(self._provider_errors)),
        }
        try:
            await self.report_readiness()
        except ConnectorAPIError as exc:
            # A readiness row that could not be written must not fail a scan whose
            # findings were already submitted.
            log.warning("hibp_readiness_report_failed", err=type(exc).__name__)
        return [], summary


def main() -> None:
    connector = HibpConnector()
    connector.main()


if __name__ == "__main__":
    main()
