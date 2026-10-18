"""Shodan connector.

Brand-hunting over Shodan host search, one provider question per capability,
each individually togglable:

* ``scan_ssl_text``     — ``ssl:"<domain>"`` searches (SSL certificate text)
* ``scan_http_title``   — ``http.title:"<title>"`` searches (page titles)
* ``scan_favicon``      — ``http.favicon.hash:`` search for domain assets
* ``scan_http_body``    — ``http.html:"<brand>"`` searches (page body)
* ``scan_cert_subject`` — ``ssl.cert.subject.cn:"<look-alike>"`` for candidates
* ``scan_html_hash``    — ``http.html_hash:`` pivot on our own pages
* ``scan_pivots``       — ``org:"<organization>"`` / ``net:<ip>/24`` pivots
* ``scan_host_lookup``  — the free ``/shodan/host/{ip}`` enrichment

Capability switches arrive from the core registry per scan (admin-editable
in the UI) with connector env vars as fallback defaults:
``SHODAN_SCAN_SSL_TEXT`` / ``SHODAN_SCAN_HTTP_TITLE`` / ``SHODAN_SCAN_FAVICON``
/ ``SHODAN_SCAN_HTTP_BODY`` / ``SHODAN_SCAN_CERT_SUBJECT`` /
``SHODAN_SCAN_HTML_HASH`` / ``SHODAN_SCAN_PIVOTS`` / ``SHODAN_SCAN_HOST_LOOKUP``.
They are namespaced like the other Shodan settings (``SHODAN_API_KEY``,
``SHODAN_MIN_REQUEST_INTERVAL_SECONDS``), because ``.env`` is a single namespace
shared by every service.

The three original questions keep their historical default (on); **every
question this wave adds ships off**, for two reasons an operator can act on:
Shodan bills query credits by search and by result page (the vendor's own guide:
a filtered search costs one query credit, and each 100 results past the first
page cost another), and the two questions that depend on vendor field names —
``ssl.cert.subject.cn`` and ``ssl.cert.subject.O`` — are confirmed against the
paying account by ``connectors/shodan/live_check.py`` before a capability that
uses them may be relied on. ``scan_host_lookup`` is off with them even though
the vendor's API guide states IP lookups consume no query credits: it is a new
provider question, and which fields *this* account answers with is what the same
spike answers.

Each capability reports its own outcome in the job summary
(``capability_results``): how many provider queries it ran, how many hosts those
queries matched, how many findings it tried to submit and how many the core
actually stored. Without that split, "the favicon search found nothing" is
indistinguishable from "the favicon search is broken".

What the scan could not do is named in ``skipped`` (``expression_too_broad``,
``no_domain_assets``, ``favicon_unavailable``, ``html_hash_unavailable``,
``provider_quota_exhausted``, ``source_disabled``, ``provider_access_denied``),
and what the allowed work cost is reported beside it: ``spent`` and
``budget_left`` against the job's own request budget, ``daily_budget`` /
``daily_budget_left`` from the account's reservation, ``retry_after_seconds``
when the core named a wait, and ``pages`` / ``billed_pages`` — the second being
the pages past the first, which is the unit the vendor bills.

The free lookup and the pivots are the two places where a *paid* question is
deliberately not asked: ``/shodan/host/{ip}`` is documented as not consuming
query credits, so it reserves nothing from the account's budget, and a pivot is
bounded by its own policy key rather than by the scan's remaining pages.

This connector owns all Shodan API access; the core only receives normalized findings.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import os
import re
import time

import httpx
import mmh3
import structlog

from opendrp_connector import ConnectorBase
from opendrp_connector.base import ConnectorAPIError
from opendrp_connector.network import is_safe_external_ip
from opendrp_connector.provider import (
    NETWORK_ERROR,
    NETWORK_TIMEOUT,
    ProviderClient,
    ProviderLimits,
)

log = structlog.get_logger()

_SHODAN_PAGE_SIZE = 100
_SHODAN_MAX_RETRIES = 2
#: Pages a search may walk when no policy was passed. The value is the historical
#: constant ``_SHODAN_MAX_PAGES``: it is now the *default* of the ``max_pages``
#: policy key, because how many result pages an installation is willing to pay for
#: is a statement about its Shodan plan and not about this connector.
_SHODAN_DEFAULT_MAX_PAGES = 3
_SHODAN_DEFAULT_MIN_INTERVAL = 1.0
_SHODAN_DEFAULT_TIMEOUT = 30.0
_SHODAN_MAX_RETRY_DELAY = 30.0
#: The largest body a provider answer may carry before it is refused undecoded.
#: A page of 100 minified banners is far below it, while the old unbounded read
#: would hold whatever a provider (or something in front of it) sent back — the
#: defect the shared client closes for every connector at once.
_SHODAN_MAX_RESPONSE_BYTES = 2_000_000
_SHODAN_COUNT_API = "https://api.shodan.io/shodan/host/count"
_SHODAN_HOST_API = "https://api.shodan.io/shodan/host/{ip}"
_SHODAN_TOKENS_API = "https://api.shodan.io/shodan/host/search/tokens"

#: Every operator-settable value of one scan, with its accepted range and default.
#: The core validates the same names through ``app/services/provider_quota.py``
#: before it reserves anything, so a value outside a range is refused there *and*
#: here: a connector that quietly clamped an operator's ``max_pages`` to its own
#: constant would be the old hardcoded behaviour wearing a setting's name.
POLICY = {
    "requests_per_minute": (1, 600, 10),
    "daily_budget": (1, 100000, 100),
    "max_requests": (1, 1000, 20),
    "max_pages": (1, 100, _SHODAN_DEFAULT_MAX_PAGES),
    "max_results": (1, 5000, 100),
    "max_targets": (1, 1000, 20),
    "scan_timeout_seconds": (10, 3600, 300),
    "cooldown_seconds": (0, 86400, 60),
    #: The largest result set a *broad* expression may have before this worker
    #: refuses to page through it. A brand in a page body, or an organisation
    #: pivot, can match a hundred thousand hosts, and ten pages of those answer
    #: nothing an analyst can act on. The size is asked for first (``/host/count``),
    #: so the refusal is one request instead of the scan's whole page budget.
    "max_broad_results": (1, 1000000, 1000),
    #: How many pivot searches (``org:``/``net:``) one scan may run at all. A pivot
    #: is how one look-alike leads to the actor behind it, and it is also how a
    #: single scan turns into an unbounded crawl — the cap is what makes the first
    #: useful and the second impossible.
    "max_pivots": (0, 20, 3),
    #: How many of our own hosts are written into the query as negative filters.
    #: The rest are still filtered locally before anything is submitted; this bounds
    #: how long a paid query can get on an installation with hundreds of assets.
    "max_exclusions": (0, 100, 15),
}

#: Capability key -> env fallback. Declared as a table so the connector's config
#: form, its env fallbacks and its summary cannot disagree about which questions
#: exist.
CAPABILITIES = {
    "scan_ssl_text": "SHODAN_SCAN_SSL_TEXT",
    "scan_http_title": "SHODAN_SCAN_HTTP_TITLE",
    "scan_favicon": "SHODAN_SCAN_FAVICON",
    "scan_http_body": "SHODAN_SCAN_HTTP_BODY",
    "scan_cert_subject": "SHODAN_SCAN_CERT_SUBJECT",
    "scan_html_hash": "SHODAN_SCAN_HTML_HASH",
    "scan_pivots": "SHODAN_SCAN_PIVOTS",
    "scan_host_lookup": "SHODAN_SCAN_HOST_LOOKUP",
}

#: The capabilities that were already there, and therefore stay on by default.
#: Everything else is opt-in — see the module docstring.
_DEFAULT_ON = frozenset({"scan_ssl_text", "scan_http_title", "scan_favicon"})

#: The operator's acknowledgement of the plan these opt-in questions are billed to
#: (F-12, WI-25). The three historical questions keep running: they were already
#: being asked when this gate arrived, and silently stopping them would be a change
#: nobody chose. Every capability added with the budget wave is off until the
#: operator states that their account may be spent this way — the same shape the DNS
#: workers use for a public non-commercial tier.
TERMS_ACK_KEY = "provider_terms_acknowledged"
TERMS_ACK_ENV = "SHODAN_TERMS_ACKNOWLEDGED"

#: A keyword carrying one of these cannot be quoted into a Shodan phrase: the
#: platform validates the same set at the edge (``KEYWORD_MAX_LENGTH`` and
#: ``_KEYWORD_FORBIDDEN_RE`` in ``app/schemas/asset.py``), and this connector
#: still refuses such a value so a scan can never widen an operator's query.
_UNQUOTABLE_KEYWORD_RE = re.compile(r'["\\\x00-\x1f]')
_FAVICON_FETCH_TIMEOUT = 10.0
_FAVICON_MAX_BYTES = 2 * 1024 * 1024  # a favicon larger than 2 MB is suspicious
#: How many same-host redirects a favicon lookup may follow. ``/favicon.ico``
#: is commonly a redirect (to ``/static/icon.png``, or http -> https), and a
#: lookup that gives up on the first hop silently reports zero findings.
_FAVICON_MAX_REDIRECTS = 3
#: Findings per submit request. Small batches keep one wide scan from holding
#: thousands of rows in memory and make progress visible in the job summary.
_SUBMIT_BATCH_SIZE = 25
#: The longest value this connector puts into a query phrase or into an evidence
#: attribute. Provider strings are bounded before they are quoted or stored: a
#: banner field is attacker-influenced text, and neither the query grammar nor the
#: core's attribute limit should be reachable with it.
_MAX_VALUE_LEN = 255


class ProviderRefusal(RuntimeError):
    """The core refused to spend, with a name for why.

    A spent budget (429), a source an operator disabled mid-scan (409) and a job
    whose lease is gone (403) all mean "no more provider requests may be sent",
    and none of them is a provider failure. Recorded as a provider error they would
    tell the operator their credentials are broken, and the readiness row would keep
    saying so long after the cause passed; this class carries the reason instead, and
    the scan reports it as a skip.
    """

    def __init__(self, reason: str, retry_after: float | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.retry_after = retry_after


def _env_flag(value: str | None, default: bool = True) -> bool:
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _config_flag(value: object, *, default: bool = False) -> bool:
    """A flag from registry config (bool) or the environment (text), one rule."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return _env_flag(str(value), default=default)


def _bounded(value: object) -> str | None:
    """A provider string as evidence: stripped, control-free, length-bounded.

    Values read out of a banner are text a stranger wrote. They end up in a query
    phrase and in the core's attribute payload, so the bound belongs here rather
    than in each caller's own slicing.
    """
    if value is None or isinstance(value, (dict, list)):
        return None
    text = "".join(character for character in str(value) if ord(character) >= 0x20).strip()
    return text[:_MAX_VALUE_LEN] or None


class ShodanConnector(ConnectorBase):
    API = "https://api.shodan.io/shodan/host/search"
    HEADERS = {"User-Agent": "OpenDRP-Connector/1.0"}
    #: What this worker can be asked for, declared to the core at startup. The
    #: three historical questions are always advertised; the budget-wave ones are
    #: gated in ``run_scan`` by the operator's acknowledgement, exactly as before.
    CAPABILITIES = ("certificate", "title", "favicon", "body")
    #: Only ``search``: the free host lookup reserves nothing, so declaring a bucket
    #: for it would claim this connector spends a budget it does not.
    OPERATIONS = ("search",)
    CREDENTIAL_ENV = ("SHODAN_API_KEY",)

    def __init__(self) -> None:
        super().__init__()
        self.api_key = self.env.get("SHODAN_API_KEY", "").strip()
        self._provider_errors: list[str] = []
        self._last_provider_request = 0.0
        self._min_request_interval = max(
            0.0,
            min(60.0, float(self.env.get("SHODAN_MIN_REQUEST_INTERVAL_SECONDS", str(_SHODAN_DEFAULT_MIN_INTERVAL)))),
        )
        self._request_timeout = max(
            5.0,
            min(120.0, float(self.env.get("SHODAN_REQUEST_TIMEOUT_SECONDS", str(_SHODAN_DEFAULT_TIMEOUT)))),
        )
        #: Every provider call is held to these. Three attempts and a 30 second
        #: ceiling on any single wait are the connector's historical constants;
        #: the body bound is what the shared client adds, and
        #: ``abort_when_retry_after_exceeds=None`` keeps the older answer to a long
        #: ``Retry-After`` — wait out the ceiling and retry rather than abandon the
        #: call. Turning the abort on is a behaviour change and belongs to its own
        #: commit, not to a refactor.
        self._provider_limits = ProviderLimits(
            max_attempts=_SHODAN_MAX_RETRIES + 1,
            max_retry_delay=_SHODAN_MAX_RETRY_DELAY,
            max_response_bytes=_SHODAN_MAX_RESPONSE_BYTES,
            timeout=self._request_timeout,
            abort_when_retry_after_exceeds=None,
        )
        # ---- per-run state ------------------------------------------------
        #: The job id of the scan being executed. Which provider request is billed
        #: to which job is part of the reservation, so the connector has to keep it.
        self._job_id = ""
        #: The run's policy values, with the defaults, so a helper called directly
        #: (a unit test, a future CLI) behaves the same as one called by a scan.
        self._policy: dict[str, int] = {key: limits[2] for key, limits in POLICY.items()}
        self._skipped: dict[str, int] = {}
        self._refusal: str | None = None
        #: Named apart from the provider's own ``Retry-After`` header, which the
        #: shared client reads and honours; this is the wait the *core* named when
        #: it refused a request.
        self._named_retry_after: float | None = None
        self._spent = 0
        self._budget_left: int | None = None
        self._daily_budget: int | None = None
        self._daily_budget_left: int | None = None
        self._pages = 0
        self._billed_pages = 0
        self._free_lookups = 0
        self._candidates_built = 0
        #: What discovery found, as ``(host, matched_asset, ip, org)``: the seeds the
        #: pivots and the free enrichment work from. The organisation travels with
        #: the banner it arrived in, because that is the only place the platform
        #: learned it and asking the provider again would pay twice for one answer.
        #: Bounded by ``max_results``: this is what the scan will later ask about.
        self._discovered: list[tuple[str, str, str | None, str | None]] = []
        #: Our own organisation, as the free lookup reported it for an owned
        #: address. Used as a negative filter, so a pivot cannot return our estate
        #: to us as a look-alike.
        self._own_org: str | None = None
        self._exclusions_dropped = 0

    # ------------------------------------------------------------------
    # Capabilities: registry config (from work payload) wins over env.
    # ------------------------------------------------------------------

    async def register(self) -> None:
        await super().register()
        # The payload shape lives in the SDK: a worker that spelled out its own
        # readiness row drifted from the others, and the core reads one contract.
        await self.report_readiness()

    def manifest_payload(self) -> dict:
        """Declare the policy keys so the core renders them instead of the constant.

        The capability toggles stay in the config schema the Compose service
        declares; the numbers come from here, because they are the same table the
        scan validates against — two places that could disagree about a range is
        exactly how a setting stops being one. The terms acknowledgement is declared
        here too, so an installation that does not use the Compose service can still
        state it in Settings instead of editing the container's environment.
        """
        manifest = super().manifest_payload()
        schema = dict(manifest.get("config_schema") or {})
        schema.setdefault(
            TERMS_ACK_KEY,
            {
                "type": "bool",
                "default": False,
                "label": "provider terms acknowledged",
                "description": (
                    "Required before any capability added with the budget wave runs: "
                    "confirm in your account that the plan permits these queries"
                ),
            },
        )
        for key, (low, high, default) in POLICY.items():
            schema.setdefault(
                key,
                {
                    "type": "int",
                    "default": default,
                    "description": f"Integer {low}..{high}",
                    "label": key.replace("_", " "),
                },
            )
        manifest["config_schema"] = schema
        return manifest

    def _capabilities(self, config: dict) -> dict[str, bool]:
        """The questions this scan may ask, after the plan acknowledgement.

        Registry config wins over the env fallback, as it does for every toggle. An
        opt-in capability stays off until the operator has acknowledged that their
        account may be spent on it, whatever the toggle says: turning a switch on is
        not the same act as confirming the plan it is billed to.
        """
        acknowledged = _config_flag(
            config.get(TERMS_ACK_KEY, self.env.get(TERMS_ACK_ENV)), default=False
        )
        capabilities = {
            key: bool(
                config.get(
                    key,
                    _env_flag(self.env.get(env_name), key in _DEFAULT_ON),
                )
            )
            for key, env_name in CAPABILITIES.items()
        }
        if not acknowledged:
            for key in capabilities:
                if key not in _DEFAULT_ON:
                    capabilities[key] = False
        return capabilities

    @staticmethod
    def _read_policy(config: dict) -> dict[str, int]:
        """The run's policy values, or a refusal to run at all.

        A value outside its range raises instead of falling back to the default: a
        operator who set ``max_pages: 500`` on a 100-credit account has to hear
        about it, and a connector that silently used three would be spending their
        money under a setting they never chose.
        """
        policy: dict[str, int] = {}
        for key, (low, high, default) in POLICY.items():
            value = config.get(key, default)
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise ValueError(f"invalid_scan_policy:{key}")
            policy[key] = value
        return policy

    # ------------------------------------------------------------------
    # Query grammar
    # ------------------------------------------------------------------

    @staticmethod
    def _query_phrase(value: str) -> str | None:
        """A quoted provider phrase, or ``None`` when the keyword cannot be quoted.

        Shodan's query language has no escape for a double quote inside a
        phrase, so ``evil" -host:owned.example`` would end the phrase there and
        append filters of its own to the operator's query (AST-30). Refusing the
        phrase is the only safe answer; the caller reports which keyword it was.
        """
        value = value.strip()
        if not value or _UNQUOTABLE_KEYWORD_RE.search(value):
            return None
        return f'"{value}"'

    @classmethod
    def _keyword_queries(cls, field: str, items: list) -> tuple[list[tuple[str, str]], list[str]]:
        """Build ``<field>:"<keyword>"`` queries plus the keywords left out."""
        queries: list[tuple[str, str]] = []
        skipped: list[str] = []
        for item in items:
            value = cls._keyword_value(item).strip()
            phrase = cls._query_phrase(value)
            if phrase is None:
                if value:
                    skipped.append(value)
                continue
            queries.append((f"{field}:{phrase}", value))
        return queries, sorted(skipped)

    @staticmethod
    def _keyword_value(item) -> str:
        """Read one keyword entry.

        ``keyword_domains`` arrives as ``{"value": ..., "type": ...}``; titles
        arrive as plain strings, but accepting the typed shape for both keeps the
        connector indifferent to how the core chose to shape its inventory.
        """
        if isinstance(item, dict):
            return str(item.get("value") or "")
        return str(item)

    @staticmethod
    def _is_address(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _narrow(self, query: str, exclude: set[str]) -> str:
        """Remove what is ours inside the query, before any page of it is paid for.

        The post-filter below the pager is what *guarantees* nothing owned is
        stored; this is what stops paying for it. ``-domain:`` and ``-hostname:``
        are documented filters and the vendor documents the leading-minus form on
        its own examples (``-port:22,80,443``), while a single owned *address* has
        no documented negative filter — an exclusion list is a mixed bag of names
        and addresses, so addresses are left to the local filter and named in the
        summary instead of being silently turned into a filter that does not exist.

        The list is capped by ``max_exclusions``: the values beyond the cap are
        counted in ``exclusions_dropped`` and still filtered locally, because a
        query is a request an operator pays for and its length is not free either.
        """
        clauses = []
        if self._own_org:
            phrase = self._query_phrase(self._own_org)
            if phrase is not None:
                clauses.append(f"-org:{phrase}")
        values = sorted({value.strip().lower() for value in exclude if value and not self._is_address(value)})
        limit = self._policy["max_exclusions"]
        for value in values[:limit]:
            phrase = self._query_phrase(value)
            if phrase is None:
                continue
            clauses.append(f"-domain:{phrase}")
            clauses.append(f"-hostname:{phrase}")
        self._exclusions_dropped = max(self._exclusions_dropped, max(0, len(values) - limit))
        return " ".join([query, *clauses]) if clauses else query

    @staticmethod
    def _narrowed_address(value: str) -> str | None:
        """A /24 around an address, which is the network pivot the vendor documents."""
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return None
        if address.version == 4:
            network = ipaddress.ip_network(f"{address}/24", strict=False)
        else:
            network = ipaddress.ip_network(f"{address}/48", strict=False)
        return str(network)

    # ------------------------------------------------------------------
    # Shodan API
    # ------------------------------------------------------------------

    async def _pace_provider_request(self) -> None:
        """Keep sequential queries below a conservative provider request rate.

        Shodan's documented general API rate is one request per second; the
        useful limit for a scan is query credits, not merely HTTP requests, and
        the limit varies by plan. A small minimum interval prevents a rescan
        with several capabilities/pages from bursting all queries at once while
        still allowing operators to tune it for their plan.
        """
        elapsed = time.monotonic() - self._last_provider_request
        delay = self._min_request_interval - elapsed
        if delay > 0:
            await asyncio.sleep(delay)
        self._last_provider_request = time.monotonic()

    @staticmethod
    def _error_code(status: int, body: str) -> str:
        """Shodan's own wording for a refusal, on top of the shared vocabulary.

        A 403 is not one thing at this vendor: a key without access and an account
        whose query credits are spent both answer with it, and the second must reach
        the operator as ``quota_exhausted`` or a topped-up account reads as a
        permissions problem. The sentence in the body is what separates them, which
        is why the shared client hands a bounded snippet to this table instead of
        guessing from the status alone.
        """
        if status == 403 and "credit" in body.lower():
            return "quota_exhausted"
        return f"http_{status}"

    def _note_provider_error(self, code: str) -> None:
        """Record a provider failure once, in the order it happened."""
        if code not in self._provider_errors:
            self._provider_errors.append(code)

    async def _reserve(self, bucket: str = "search") -> None:
        """Reserve one provider request, or stop the scan with a named reason.

        The read of the reservation's own body is the difference between reporting
        a spend and reporting a ceiling: the core's answer carries the account's
        remaining requests for the day, and a worker that discarded it could only
        say what it was allowed to spend, never whether the next scan can run.
        """
        active = self._active_job
        if not active:
            # Which job a request is billed to is part of the reservation, and the
            # lease is what proves the claim; a call with neither is a spend nobody
            # asked for.
            raise ProviderRefusal("provider_request_unowned")
        job_id = active[0]
        try:
            response = await self._request(
                "POST",
                "/api/v1/connectors/me/quota/provider",
                params={"job_id": job_id, "bucket": bucket},
                headers={"X-Connector-Lease": self._lease_for(job_id)},
            )
        except ConnectorAPIError as exc:
            self._named_retry_after = exc.retry_after
            if exc.status_code == 429:
                raise ProviderRefusal("provider_quota_exhausted", exc.retry_after) from exc
            if exc.status_code == 409:
                raise ProviderRefusal("source_disabled") from exc
            if exc.status_code == 403:
                raise ProviderRefusal("provider_access_denied") from exc
            raise ProviderRefusal("provider_quota_backend_unavailable") from exc
        payload: dict = {}
        try:
            body = response.json()
            if isinstance(body, dict):
                payload = body
        except ValueError:
            payload = {}
        budget = payload.get("request_budget")
        if isinstance(budget, int) and not isinstance(budget, bool):
            self._daily_budget = budget
        remaining = payload.get("remaining_today")
        if isinstance(remaining, int) and not isinstance(remaining, bool):
            self._daily_budget_left = remaining
        self._spent += 1
        self._budget_left = max(0, self._policy["max_requests"] - self._spent)

    async def _get(self, client: httpx.AsyncClient, url: str, params: dict, *, free: bool = False) -> dict | None:
        """One paced and classified provider GET; ``None`` when it did not answer.

        Every provider request in this connector goes through here, so the pace,
        the budget reservation, the retries and the failure classification cannot
        be forgotten at a call site — a request that skipped the reservation would
        be spending without asking, which is the one thing the account's quota
        exists to prevent. The mechanisms themselves live in
        :class:`ProviderClient`, shared with the other metered connectors; what
        stays here is what only Shodan knows: the bucket a request is billed to,
        the interval its plan implies, and the sentence that turns a 403 into an
        exhausted quota. ``free=True`` is the documented no-credit case (an IP
        lookup), and it is deliberately explicit: charging for a call the vendor
        does not bill would make this platform refuse enrichment it never paid for.
        """
        provider = ProviderClient(
            http=client,
            limits=self._provider_limits,
            reserve=lambda: self._reserve("search"),
            pace=self._pace_provider_request,
            classify_error=self._error_code,
        )
        result = await provider.get_json(
            url,
            params=params,
            headers=self.HEADERS,
            free=free,
            # Connecting is bounded separately from reading: a host that never
            # completes a handshake should not be waited on for the whole read
            # budget, which is what one flat timeout would do.
            timeout=httpx.Timeout(
                self._request_timeout, connect=min(10.0, self._request_timeout)
            ),
        )
        if result.outcome is not None:
            self._note_provider_error(result.outcome)
            if result.outcome == NETWORK_TIMEOUT:
                log.warning("shodan_req_timeout", err=result.outcome)
            elif result.outcome == NETWORK_ERROR:
                log.warning("shodan_req_failed", err=result.outcome)
            elif result.status is not None and result.status != 200:
                log.warning(
                    "shodan_request_non_200", status=result.status, error_code=result.outcome
                )
            else:
                # A 200 whose body could not be used: invalid JSON, a payload that
                # is not an object, or one larger than this connector will decode.
                log.warning("shodan_response_unusable", error_code=result.outcome)
            return None
        payload = result.payload
        if isinstance(payload, dict):
            return payload
        self._note_provider_error("invalid_response")
        return None

    def _params(self, query: str, **extra) -> dict:
        return {"key": self.api_key, "query": query, "minify": True, **extra}

    async def _count(self, query: str, exclude: set[str]) -> int | None:
        """How large a result set a broad expression has, before it is paged.

        Asked only for expressions that can be enormous (a brand in a page body, an
        organisation pivot). The vendor's reference does not charge this route a
        query credit, but the request is still reserved and paced like any other,
        because the platform's own ledger is what bounds a scan: one counted
        refusal is cheaper than the ten pages it replaces.
        """
        if not self.api_key:
            return None
        timeout = httpx.Timeout(self._request_timeout, connect=min(10.0, self._request_timeout))
        async with httpx.AsyncClient(timeout=timeout) as client:
            payload = await self._get(client, _SHODAN_COUNT_API, self._params(self._narrow(query, exclude)))
        if payload is None:
            return None
        total = payload.get("total")
        if isinstance(total, bool) or not isinstance(total, int) or total < 0:
            self._note_provider_error("invalid_response")
            return None
        return total

    async def _search(self, query: str, exclude: set[str], *, max_pages: int | None = None) -> list[dict]:
        """Page one query and return the banners that are not ours.

        ``max_pages`` lets the caller spend the pages a known result set actually
        needs (from :meth:`_count`) instead of always walking the policy maximum,
        and it can never raise that maximum: the policy is the operator's ceiling.
        """
        if not self.api_key:
            log.warning("shodan_no_api_key")
            return []
        limit = self._policy["max_pages"] if max_pages is None else min(max_pages, self._policy["max_pages"])
        results: list[dict] = []
        timeout = httpx.Timeout(self._request_timeout, connect=min(10.0, self._request_timeout))
        async with httpx.AsyncClient(timeout=timeout) as client:
            page = 1
            while page <= max(1, limit):
                payload = await self._get(
                    client, self.API, self._params(self._narrow(query, exclude), page=page)
                )
                if payload is None:
                    break
                matches = payload.get("matches")
                if not isinstance(matches, list):
                    self._note_provider_error("invalid_response")
                    break
                results.extend(matches)
                self._pages += 1
                if page > 1:
                    # The vendor's billing unit: pages past the first are what the
                    # credit guide charges for, and a summary that reported only
                    # request counts would hide the number an operator's invoice
                    # is built from.
                    self._billed_pages += 1
                if len(matches) < _SHODAN_PAGE_SIZE:
                    break
                page += 1
        return self._filter(results, exclude)

    @staticmethod
    def _filter(results: list[dict], exclude: set[str]) -> list[dict]:
        """Drop banners naming anything of ours.

        The guarantee, not the optimisation: the query's negative filters are what
        stop the platform paying for owned hosts, and this is what stops one being
        *stored* if the provider ignored a filter or returned a host whose name is
        a subdomain of an excluded one.
        """
        filtered = []
        for match in results:
            ip = match.get("ip_str") or ""
            domains = {str(d) for d in (match.get("domains") or [])}
            hostnames = {str(h) for h in (match.get("hostnames") or [])}
            if ip in exclude or domains & exclude or hostnames & exclude:
                continue
            filtered.append(match)
        return filtered

    async def _lookup_host(self, address: str) -> dict | None:
        """``/shodan/host/{ip}``: the free half of Shodan's API.

        The vendor's API guide states IP lookups consume no query credits, so this
        reserves nothing. It is still the same classified, paced call, and it still
        counts in ``free_lookups``: "we asked and the account was not billed" is a
        fact about the run an operator should be able to read off the summary.
        """
        if not self.api_key:
            return None
        timeout = httpx.Timeout(self._request_timeout, connect=min(10.0, self._request_timeout))
        async with httpx.AsyncClient(timeout=timeout) as client:
            payload = await self._get(
                client, _SHODAN_HOST_API.format(ip=address), {"key": self.api_key, "minify": True}, free=True
            )
        if payload is not None:
            self._free_lookups += 1
        return payload

    @staticmethod
    def _host_facts(payload: dict) -> dict:
        """The free lookup's fields, in the names the core's evidence reads.

        Absent means absent: a provider publishes a banner's properties per host, so
        a missing favicon or JARM is a host this account has no such record for, and
        it is left out rather than filled with a placeholder. ``http.html_hash`` is
        kept as a number on purpose — it is computed by Shodan's crawlers and no
        algorithm of theirs is published, so the platform can compare it and never
        recompute it.
        """
        http = payload.get("http") if isinstance(payload.get("http"), dict) else {}
        favicon = http.get("favicon") if isinstance(http.get("favicon"), dict) else {}
        ssl = payload.get("ssl") if isinstance(payload.get("ssl"), dict) else {}
        certificate = ssl.get("cert") if isinstance(ssl.get("cert"), dict) else {}
        subject = certificate.get("subject") if isinstance(certificate.get("subject"), dict) else {}
        issuer = certificate.get("issuer") if isinstance(certificate.get("issuer"), dict) else {}
        facts: dict = {}
        for key, value in (
            ("asn", payload.get("asn")),
            ("org", payload.get("org")),
            ("title", http.get("title")),
            ("jarm", ssl.get("jarm")),
            ("cert_subject_cn", subject.get("CN")),
            ("cert_issuer_cn", issuer.get("CN")),
        ):
            text = _bounded(value)
            if text:
                facts[key] = text
        favicon_hash = favicon.get("hash")
        if isinstance(favicon_hash, int) and not isinstance(favicon_hash, bool):
            facts["favicon_hash"] = favicon_hash
        html_hash = http.get("html_hash")
        if isinstance(html_hash, int) and not isinstance(html_hash, bool):
            facts["html_hash"] = html_hash
        return facts

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------

    async def run_scan(self, work: dict) -> tuple[list[dict], dict]:
        params = work.get("params", {}) or {}
        config = work.get("config") or {}
        self._provider_errors = []
        self._skipped = {}
        self._refusal = None
        self._named_retry_after = None
        self._spent = 0
        self._pages = 0
        self._billed_pages = 0
        self._free_lookups = 0
        self._candidates_built = 0
        self._exclusions_dropped = 0
        self._discovered = []
        self._own_org = None
        self._job_id = str(work["job_id"])
        self._policy = self._read_policy(config)
        caps = self._capabilities(config)
        # An opt-in question the operator switched on but has not acknowledged is a
        # refusal, not a silent downgrade: the summary names it so the switch does not
        # look broken while nothing is being asked (F-12, WI-25).
        blocked = [
            key
            for key, env_name in CAPABILITIES.items()
            if key not in _DEFAULT_ON
            and _config_flag(
                config.get(key, self.env.get(env_name)), default=False
            )
            and not caps[key]
        ]
        if blocked:
            self._skipped["licence_acknowledgement_required"] = len(blocked)

        kw_domains = params.get("keyword_domains") or []  # [{value, type}]
        kw_titles = params.get("keyword_titles") or []
        candidates = [str(value) for value in (params.get("candidates") or [])]
        addresses = [str(value) for value in (params.get("ips") or [])]
        exclude = set(params.get("exclude") or [])

        if not self.api_key:
            return [], {
                "task": "shodan_brand_hunting",
                "skipped": {"missing_api_key": 1},
                "status": "skipped",
                "capabilities_run": [],
                "capability_results": {},
                "new_discovered": 0,
            }

        active = [name for name, on in caps.items() if on]
        if not active:
            return [], {
                "task": "shodan_brand_hunting",
                "skipped": {"no_capabilities_enabled": 1, **self._skipped},
                "status": "skipped",
                "capabilities_run": [],
                "capability_results": {},
                "new_discovered": 0,
            }

        job_id = self._job_id
        run_caps: list[str] = []
        capability_results: dict[str, dict] = {}
        saved = 0

        ssl_queries, ssl_skipped = self._keyword_queries("ssl", kw_domains)
        title_queries, title_skipped = self._keyword_queries("http.title", kw_titles)
        # A brand is a keyword the platform monitors, as opposed to a domain it owns
        # (the ``domain`` type). The body question is asked about the brand: "which
        # page carries our name" is what a look-alike's page does.
        brands = [
            self._keyword_value(item)
            for item in kw_domains
            if (item.get("type") if isinstance(item, dict) else "domain") == "keyword_domain"
        ]
        body_queries, body_skipped = self._keyword_queries("http.html", brands)
        skipped_keywords = sorted(set(ssl_skipped) | set(title_skipped) | set(body_skipped))
        owned_domains = [
            self._keyword_value(item)
            for item in kw_domains
            if (item.get("type") if isinstance(item, dict) else "domain") == "domain"
        ]

        try:
            async with asyncio.timeout(self._policy["scan_timeout_seconds"]):
                if addresses:
                    # Our own organisation, learned for free before the first paid
                    # query: it is the one negative filter that keeps a pivot from
                    # handing our own estate back to us as a look-alike, and only an
                    # address we own can answer what the provider calls us.
                    await self._learn_own_org(addresses, exclude)

                if caps["scan_ssl_text"]:
                    run_caps.append("ssl")
                    capability_results["ssl"] = await self._keyword_capability(
                        job_id=job_id,
                        source="shodan_ssl",
                        queries=ssl_queries,
                        exclude=exclude,
                        skipped=ssl_skipped,
                    )
                    saved += capability_results["ssl"]["stored"]

                if caps["scan_http_title"]:
                    run_caps.append("title")
                    capability_results["title"] = await self._keyword_capability(
                        job_id=job_id,
                        source="shodan_title",
                        queries=title_queries,
                        exclude=exclude,
                        skipped=title_skipped,
                    )
                    saved += capability_results["title"]["stored"]

                if caps["scan_http_body"]:
                    run_caps.append("body")
                    capability_results["body"] = await self._keyword_capability(
                        job_id=job_id,
                        source="shodan_body",
                        queries=body_queries,
                        exclude=exclude,
                        skipped=body_skipped,
                        counted=True,
                    )
                    saved += capability_results["body"]["stored"]

                if caps["scan_favicon"]:
                    run_caps.append("favicon")
                    capability_results["favicon"] = await self._favicon_capability(
                        job_id=job_id,
                        domain_assets=owned_domains,
                        exclude=exclude,
                    )
                    saved += capability_results["favicon"]["stored"]

                if caps["scan_cert_subject"]:
                    run_caps.append("cert_subject")
                    capability_results["cert_subject"] = await self._cert_subject_capability(
                        job_id=job_id, candidates=candidates, exclude=exclude
                    )
                    saved += capability_results["cert_subject"]["stored"]

                if caps["scan_html_hash"]:
                    run_caps.append("html_hash")
                    capability_results["html_hash"] = await self._html_hash_capability(
                        job_id=job_id, addresses=addresses, exclude=exclude
                    )
                    saved += capability_results["html_hash"]["stored"]

                if caps["scan_pivots"]:
                    run_caps.append("pivots")
                    capability_results["pivots"] = await self._pivot_capability(
                        job_id=job_id, exclude=exclude
                    )
                    saved += capability_results["pivots"]["stored"]

                if caps["scan_host_lookup"]:
                    run_caps.append("host_lookup")
                    capability_results["host_lookup"] = await self._host_lookup_capability(
                        job_id=job_id, exclude=exclude, brands=brands
                    )
                    saved += capability_results["host_lookup"]["stored"]
        except ProviderRefusal as exc:
            self._refusal = exc.reason
            self._named_retry_after = exc.retry_after
            self._skipped[exc.reason] = self._skipped.get(exc.reason, 0) + 1
        except TimeoutError:
            self._skipped["scan_deadline_exceeded"] = self._skipped.get("scan_deadline_exceeded", 0) + 1

        summary = {
            "task": "shodan_brand_hunting",
            "kw_domains": len(kw_domains),
            "kw_titles": len(kw_titles),
            "capabilities_run": run_caps,
            "capability_results": capability_results,
            "new_discovered": saved,
            # Keywords the provider grammar cannot carry are named here rather
            # than silently dropped: a scan that skipped one is not "clean".
            "skipped_keywords": skipped_keywords,
            "status": self._status(saved),
            "provider_errors": sorted(set(self._provider_errors)),
            # What the scan could not do, and what the allowed work cost.
            "skipped": dict(self._skipped) or None,
            "spent": self._spent,
            "budget_left": max(0, self._policy["max_requests"] - self._spent),
            "daily_budget": self._daily_budget,
            "daily_budget_left": self._daily_budget_left,
            "retry_after_seconds": self._named_retry_after,
            "pages": self._pages,
            # Pages past the first: the unit the vendor's credit guide bills.
            "billed_pages": self._billed_pages,
            "free_lookups": self._free_lookups,
        }
        if self._exclusions_dropped:
            summary["exclusions_dropped"] = self._exclusions_dropped
        return [], summary

    def _status(self, saved: int) -> str:
        """What the job row says: a named stop is not a broken provider.

        ``partial`` when findings survived a skip (the scan did what it could),
        ``skipped`` when the allowed work produced nothing, and a provider error
        keeps its historical meaning — credentials or the provider itself.
        """
        if self._refusal or self._skipped:
            return "partial" if saved else "skipped"
        if self._provider_errors:
            return "partial"
        return "success"

    # ------------------------------------------------------------------
    # Capability execution
    # ------------------------------------------------------------------

    @staticmethod
    def _empty_tally() -> dict:
        """The per-capability counters every capability reports.

        ``matches`` counts provider hits, ``candidates`` the findings built from
        them, ``stored`` the ones the core accepted. ``matches`` above ``stored``
        is therefore either deduplication (``phishing_domain`` is unique in the
        core, so a re-discovered host is rejected, not updated) or hosts the
        exclude set removed — never a silent drop.
        """
        return {"queries": 0, "matches": 0, "candidates": 0, "stored": 0, "skipped": None}

    def _budget_exhausted(self) -> bool:
        """Whether the scan has used every candidate the policy allows it to store."""
        return self._candidates_built >= self._policy["max_results"]

    def _remember(self, host: str, matched: str, match: dict) -> None:
        """Keep one discovery as a seed for the pivots and the free enrichment.

        Bounded by ``max_results``: this list is what the scan will later ask the
        provider about, and an unbounded one would make the enrichment the largest
        part of a wide scan.
        """
        address = match.get("ip_str")
        address = address.strip() if isinstance(address, str) and address.strip() else None
        self._discovered.append((host, matched, address, _bounded(match.get("org"))))

    async def _keyword_capability(
        self,
        *,
        job_id: str,
        source: str,
        queries: list[tuple[str, str]],
        exclude: set[str],
        skipped: list[str] | None = None,
        counted: bool = False,
    ) -> dict:
        """Run one ``<field>:"<keyword>"`` capability and report its outcome.

        ``queries`` pairs every provider query with the keyword it was built
        from, because that keyword is the ``matched_asset`` of each finding the
        query returns. Findings go out in bounded batches as they arrive, so a
        wide scan reports progress instead of holding every row in memory and a
        single submit at the end.

        ``counted`` asks how large each result set is before paging it. That is
        where a broad expression is refused by name (``expression_too_broad``)
        and where an empty one costs no search request at all — for a page body
        the difference is between one request and the scan's whole page budget.
        """
        tally = self._empty_tally()
        tally["skipped"] = sorted(skipped) or None
        batch: list[dict] = []
        for query, matched in queries:
            if self._budget_exhausted():
                break
            max_pages = None
            if counted:
                total = await self._count(query, exclude)
                if total is not None:
                    if total > self._policy["max_broad_results"]:
                        self._skipped["expression_too_broad"] = (
                            self._skipped.get("expression_too_broad", 0) + 1
                        )
                        continue
                    if total == 0:
                        # Asked and answered: nothing matches, and no search page
                        # has to be paid for to learn it.
                        continue
                    max_pages = max(1, -(-total // _SHODAN_PAGE_SIZE))
            # A narrow question keeps the pager's default call shape; only a counted
            # one passes a page bound, because only then is there a number to bound
            # it with.
            bounds = {"max_pages": max_pages} if max_pages is not None else {}
            matches = await self._search(query, exclude, **bounds)
            tally["queries"] += 1
            tally["matches"] += len(matches)
            for match in matches:
                host = self._pick_host(match)
                if not host:
                    continue
                self._remember(host, matched, match)
                batch.append(self._finding(host, matched, match, source))
                tally["candidates"] += 1
                self._candidates_built += 1
                if len(batch) >= _SUBMIT_BATCH_SIZE:
                    tally["stored"] += await self._submit_batch(job_id, batch)
                    batch = []
        if batch:
            tally["stored"] += await self._submit_batch(job_id, batch)
        return tally

    async def _cert_subject_capability(self, *, job_id: str, candidates: list[str], exclude: set[str]) -> dict:
        """Ask what a confirmed look-alike presents as its certificate name.

        ``ssl.cert.subject.cn:"<look-alike>"`` is the reverse of the brand question:
        it does not look for our name in someone else's certificate, it looks for the
        look-alike's own name in *theirs* — which is how a shared certificate or a
        registration certificate for the copy itself becomes visible. Only names an
        analyst has already confirmed reach this (the core sends no others), because
        a paid question about every generated permutation would be a coin flip.
        """
        tally = self._empty_tally()
        queries: list[tuple[str, str]] = []
        refused: list[str] = []
        for candidate in candidates:
            value = candidate.strip()
            phrase = self._query_phrase(value)
            if phrase is None:
                if value:
                    refused.append(value)
                continue
            queries.append((f"ssl.cert.subject.cn:{phrase}", value))
        if not queries:
            tally["skipped"] = "no_confirmed_candidates"
            return tally
        tally["skipped"] = sorted(refused) or None
        batch: list[dict] = []
        for query, matched in queries:
            if self._budget_exhausted():
                break
            matches = await self._search(query, exclude, max_pages=1)
            tally["queries"] += 1
            tally["matches"] += len(matches)
            for match in matches:
                host = self._pick_host(match)
                if not host:
                    continue
                self._remember(host, matched, match)
                batch.append(self._finding(host, matched, match, "shodan_cert_subject"))
                tally["candidates"] += 1
                self._candidates_built += 1
                if len(batch) >= _SUBMIT_BATCH_SIZE:
                    tally["stored"] += await self._submit_batch(job_id, batch)
                    batch = []
        if batch:
            tally["stored"] += await self._submit_batch(job_id, batch)
        return tally

    async def _learn_own_org(self, addresses: list[str], exclude: set[str]) -> None:
        """Learn this installation's organisation from a free lookup of its own address.

        Our own organisation is the one negative filter that keeps an ``org:`` pivot
        from returning our whole estate as look-alikes, and only the provider knows
        what it calls us. The lookup is free, so learning it costs the account
        nothing; a run with no owned address to ask about simply has no such filter,
        and says so by leaving the value absent.
        """
        for value in addresses:
            address = value.strip()
            if not address or self._is_address(address) is False:
                continue
            if address in exclude:
                continue
            payload = await self._lookup_host(address)
            if payload is None:
                return
            org = _bounded(payload.get("org"))
            if org:
                self._own_org = org
                return
        return

    async def _html_hash_capability(self, *, job_id: str, addresses: list[str], exclude: set[str]) -> dict:
        """Pivot on our own pages' HTML hash, read from the provider that computes it.

        ``http.html_hash`` is a number Shodan's crawlers calculate; no algorithm of
        theirs is published, so the platform can never compute it from a page it
        fetches itself — a hash this connector made up would compare equal to
        nothing. The value is therefore *read* from the free lookup of an address we
        already own, and the pivot is the paid question that follows: which other
        hosts serve byte-identical HTML.
        """
        tally = self._empty_tally()
        hashes: list[int] = []
        for value in addresses:
            address = value.strip()
            if not address or not self._is_address(address) or address in exclude:
                continue
            if len(hashes) >= self._policy["max_targets"]:
                break
            payload = await self._lookup_host(address)
            if payload is None:
                continue
            html_hash = self._host_facts(payload).get("html_hash")
            if isinstance(html_hash, int):
                hashes.append(html_hash)
        if not hashes:
            # Nothing to search with, and the difference matters: "our HTML hash is
            # nowhere else" and "no HTML hash was available to ask about" are not the
            # same answer, as with the favicon capability.
            tally["skipped"] = "html_hash_unavailable"
            return tally
        for html_hash in dict.fromkeys(hashes):
            if self._budget_exhausted():
                break
            matches = await self._search(f"http.html_hash:{html_hash}", exclude)
            tally["queries"] += 1
            tally["matches"] += len(matches)
            batch: list[dict] = []
            for match in matches:
                host = self._pick_host(match)
                if not host:
                    continue
                self._remember(host, str(html_hash), match)
                batch.append(self._finding(host, str(html_hash), match, "shodan_html_hash"))
                tally["candidates"] += 1
                self._candidates_built += 1
            if batch:
                tally["stored"] += await self._submit_batch(job_id, batch)
        return tally

    async def _pivot_capability(self, *, job_id: str, exclude: set[str]) -> dict:
        """Follow what was found to the rest of what the same actor runs.

        Two documented pivots, and both are *narrowing* questions asked about a host
        this scan just found: ``org:"<organization>"`` (what else is on this actor's
        infrastructure, which is how one look-alike becomes a campaign) and
        ``net:<ip>/24`` (the neighbouring addresses). The organisation pivot is
        counted before it is paged — an organisation that is also a hosting reseller
        matches without bound — and both are capped by ``max_pivots`` and the page
        policy, so one finding cannot turn a scan into a crawl.
        """
        tally = self._empty_tally()
        if not self._discovered:
            tally["skipped"] = "nothing_discovered_to_pivot_from"
            return tally
        seeds = list(dict.fromkeys(self._discovered))
        pivots: list[tuple[str, str, str]] = []
        for _host, matched, address, org in seeds:
            if len(pivots) >= self._policy["max_pivots"]:
                break
            if org and (not self._own_org or org.casefold() != self._own_org.casefold()):
                phrase = self._query_phrase(org)
                if phrase is not None:
                    pivots.append((f"org:{phrase}", matched, "pivot_org"))
            if len(pivots) >= self._policy["max_pivots"]:
                break
            if address:
                network = self._narrowed_address(address)
                if network:
                    pivots.append((f"net:{network}", matched, "pivot_net"))
        if not pivots:
            tally["skipped"] = "no_pivot_seed"
            return tally
        tally["skipped"] = None
        for query, matched, capability in pivots[: self._policy["max_pivots"]]:
            if self._budget_exhausted():
                break
            max_pages = None
            if capability == "pivot_org":
                total = await self._count(query, exclude)
                if total is not None and total > self._policy["max_broad_results"]:
                    self._skipped["expression_too_broad"] = (
                        self._skipped.get("expression_too_broad", 0) + 1
                    )
                    continue
                if total == 0:
                    continue
                if total is not None:
                    max_pages = max(1, -(-total // _SHODAN_PAGE_SIZE))
            matches = await self._search(query, exclude, max_pages=max_pages)
            tally["queries"] += 1
            tally["matches"] += len(matches)
            batch: list[dict] = []
            for match in matches:
                host = self._pick_host(match)
                if not host or any(host == seed[0] for seed in seeds):
                    continue
                batch.append(self._finding(host, matched, match, capability))
                tally["candidates"] += 1
                self._candidates_built += 1
                if len(batch) >= _SUBMIT_BATCH_SIZE:
                    tally["stored"] += await self._submit_batch(job_id, batch)
                    batch = []
            if batch:
                tally["stored"] += await self._submit_batch(job_id, batch)
        return tally

    @staticmethod
    def _title_carries_brand(title: str, brands: list[str]) -> bool:
        """Whether the enriched page's title names a brand this scan monitors.

        Compared here rather than left for the core because the comparison is the one
        thing this connector learned that the lookup's own fields do not state: the
        provider answers what the title *is*, and the brand list is the platform's.
        Short brands are ignored — a two-letter brand matches inside almost any title,
        and a fact that fires on everything is not evidence.
        """
        folded = title.casefold()
        return any(brand.strip().casefold() in folded for brand in brands if len(brand.strip()) >= 3)

    async def _host_lookup_capability(
        self, *, job_id: str, exclude: set[str], brands: list[str]
    ) -> dict:
        """Enrich each discovered host with the free lookup, as candidate evidence.

        The lookup answers what a host *is* — its network (ASN, organisation), its
        page title, its icon hash, its TLS handshake (JARM) and its certificate
        names — and every one of those is a fact about a look-alike the platform
        already stores. They are submitted as evidence rows attached to that
        candidate (``capability: host_lookup``), not as new discoveries: nothing
        here was found, it was explained, and the evidence list has to keep the two
        apart.

        The vendor bills no query credit for an IP lookup, so this reserves nothing
        from the account's budget. What bounds it is ``max_results`` and the scan
        deadline — not the credit balance, which is the whole point of doing it.
        """
        tally = self._empty_tally()
        if not self._discovered:
            tally["skipped"] = "nothing_discovered_to_enrich"
            return tally
        seen: set[str] = set()
        batch: list[dict] = []
        unavailable = 0
        for host, matched, address, _org in dict.fromkeys(self._discovered):
            if not address or address in seen or address in exclude:
                continue
            if self._budget_exhausted():
                break
            seen.add(address)
            payload = await self._lookup_host(address)
            if payload is None:
                unavailable += 1
                continue
            facts = self._host_facts(payload)
            if not facts:
                unavailable += 1
                continue
            title = facts.get("title")
            if isinstance(title, str) and self._title_carries_brand(title, brands):
                # The scored fact, reported as the observation it is: the page carries
                # the brand in its title, and the core records the signal from it
                # instead of asking a provider again (W3.4).
                facts["brand_in_title"] = True
            tally["matches"] += 1
            batch.append(
                {
                    "phishing_domain": host[:512],
                    "matched_asset": str(matched)[:512],
                    "ip_address": address[:255],
                    "detection_source": "shodan_host_lookup",
                    "metadata": {
                        "capability": "host_lookup",
                        "provider": "shodan",
                        "evidence": "shodan_free_host_lookup",
                        "association": "discovered_host",
                        **facts,
                    },
                }
            )
            tally["candidates"] += 1
            self._candidates_built += 1
            if len(batch) >= _SUBMIT_BATCH_SIZE:
                tally["stored"] += await self._submit_batch(job_id, batch)
                batch = []
        if batch:
            tally["stored"] += await self._submit_batch(job_id, batch)
        if unavailable and not tally["matches"]:
            # Every lookup failed or answered nothing: a bare zero would read as
            # "enriched and found nothing", which is not what happened.
            tally["skipped"] = "host_lookup_unavailable"
        return tally

    async def _favicon_capability(
        self, *, job_id: str, domain_assets: list[str], exclude: set[str]
    ) -> dict:
        """Hash each owned domain's favicon and hunt for the same icon elsewhere.

        The capability works off *our* domains, so it needs at least one
        ``domain`` asset to hash. Saying so is the difference between "nothing
        matched" and "there was nothing to search with": both used to read as a
        bare zero.
        """
        tally = self._empty_tally()
        if not domain_assets:
            tally["skipped"] = "no_domain_assets"
            return tally
        unusable = 0
        for asset in domain_assets:
            outcome = await self._favicon_findings(asset, exclude, job_id)
            if outcome["skipped"]:
                unusable += 1
            for key in ("queries", "matches", "candidates", "stored"):
                tally[key] += outcome[key]
        if unusable == len(domain_assets):
            tally["skipped"] = "favicon_unavailable"
        return tally

    def _pick_host(self, m: dict) -> str | None:
        candidates = (m.get("domains") or []) + (m.get("hostnames") or [])
        for c in candidates:
            s = str(c).strip().lower()
            if s:
                return s[:512]
        ip = m.get("ip_str")
        if ip:
            return str(ip).strip()[:512]
        return None

    def _finding(self, host: str, matched: str, m: dict, source: str) -> dict:
        return {
            "phishing_domain": host[:512],
            "matched_asset": str(matched)[:512],
            "ip_address": (m.get("ip_str") or "")[:255] or None,
            "web_ports": (str(m.get("port")) if m.get("port") else None),
            "detection_source": source,
        }

    @staticmethod
    def _same_host_redirect(location: str, host: str) -> str | None:
        """The follow-up URL for a same-host redirect, or ``None`` to stop.

        Only the host whose addresses were already resolved and checked against
        :func:`is_safe_external_ip` may be followed: a favicon lookup must never
        be turned into a request against an address the asset chose for us. The
        next URL is rebuilt from that validated host plus the target's path and
        query rather than taken verbatim, so a ``Location`` header cannot smuggle
        userinfo or another authority into the follow-up request.
        """
        from urllib.parse import urlparse

        parsed = urlparse(location)
        if parsed.scheme not in {"http", "https"} or (parsed.hostname or "") != host:
            return None
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return f"{parsed.scheme}://{host}{path}"

    async def _fetch_favicon(self, host: str, scheme: str) -> bytes | None:
        # Assets and redirects are untrusted network targets. Resolve and pin
        # only public addresses; never let a connector turn favicon lookup into
        # a request against loopback, Docker, RFC1918 or cloud metadata.
        import socket

        if os.environ.get("TESTING") == "1" or os.environ.get("APP_ENV") == "test":
            addresses = {host}
        else:
            try:
                addresses = {info[4][0] for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
            except OSError:
                return None
            if not addresses or not all(is_safe_external_ip(address) for address in addresses):
                return None
        url = f"{scheme}://{host.rstrip('/')}/favicon.ico"
        async with httpx.AsyncClient(
            timeout=_FAVICON_FETCH_TIMEOUT,
            verify=(scheme == "https"),
            follow_redirects=False,
            limits=httpx.Limits(max_connections=5),
        ) as client:
            # Redirects are followed by hand, not by httpx, so every hop can be
            # checked against the host that was just validated. A favicon behind
            # a same-host redirect is ordinary; abandoning it made the favicon
            # capability report nothing at all.
            for _ in range(_FAVICON_MAX_REDIRECTS + 1):
                async with client.stream(
                    "GET", url, headers={"User-Agent": self.HEADERS["User-Agent"]}
                ) as r:
                    if r.status_code in {301, 302, 303, 307, 308}:
                        target = self._same_host_redirect(r.headers.get("location", ""), host)
                        if target is None:
                            return None
                        url = target
                        continue
                    if r.status_code == 200:
                        return await self._read_favicon(r) or None
                    return None
        return None

    async def _read_favicon(self, response) -> bytes:
        """The icon's bytes, up to ``_FAVICON_MAX_BYTES``, read as they arrive.

        The bound used to be a slice applied to a body that was already complete:
        this fetch read whatever the target's host sent into memory and compared
        its length afterwards, which is the buffering a bound exists to prevent.
        It is also the one request a connector makes to the *target* rather than to
        its provider, so the bytes are as untrusted as the URL that named them.

        What is returned is the same slice as before — truncated at the bound, not
        refused — because an icon that is too large is a fact about the target, and
        half of one hashes to a value that is not an icon at all. Only the amount
        held in memory changes.
        """
        content = bytearray()
        try:
            async for chunk in response.aiter_bytes():
                remaining = _FAVICON_MAX_BYTES - len(content)
                if len(chunk) >= remaining:
                    content.extend(chunk[:remaining])
                    break
                content.extend(chunk)
        except httpx.HTTPError:
            return b""
        return bytes(content)

    async def _favicon_findings(self, domain_asset: str, exclude: set[str], job_id: str) -> dict:
        """Hash one domain's favicon and search for it. Returns a capability tally."""
        host = domain_asset.rstrip("/")
        favicon_content: bytes | None = None
        for scheme in ("https", "http"):
            try:
                favicon_content = await self._fetch_favicon(host, scheme)
            except Exception:
                continue
            if favicon_content:
                break
        if not favicon_content:
            # No icon to hash: the host serves none, redirects off-host, or is
            # unreachable. Reported as a skip reason, because a bare zero in the
            # findings count reads as "searched and matched nothing".
            log.info("shodan_favicon_unavailable", host=host)
            tally = self._empty_tally()
            tally["skipped"] = "favicon_unavailable"
            return tally

        favicon_hash = mmh3.hash(base64.encodebytes(favicon_content), signed=True)
        matches = await self._search(f"http.favicon.hash:{favicon_hash}", exclude)
        batch: list[dict] = []
        for m in matches:
            ph = self._pick_host(m)
            if not ph:
                continue
            self._remember(ph, domain_asset, m)
            batch.append(self._finding(ph, domain_asset, m, "shodan_favicon"))
        tally = self._empty_tally()
        tally["queries"] = 1
        tally["matches"] = len(matches)
        tally["candidates"] = len(batch)
        if batch:
            tally["stored"] = await self._submit_batch(job_id, batch)
        return tally

    async def _submit_batch(self, job_id: str, batch: list[dict]) -> int:
        """Submit one batch; returns how many findings the core stored."""
        result = await self.submit_findings(job_id, batch)
        return int(result.get("accepted", 0))


def main() -> None:
    connector = ShodanConnector()
    connector.main()


if __name__ == "__main__":
    main()
