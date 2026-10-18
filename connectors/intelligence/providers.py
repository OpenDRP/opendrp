"""Passive provider contracts (Netlas only); never submit targets or request live scans."""

import asyncio
import ipaddress
import json
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import quote, urlsplit

import httpx

BASES = {
    "netlas": "https://app.netlas.io/api",
}
KEYS = {
    "netlas": "NETLAS_API_TOKEN",
}


def core_credential(payload):
    """The provider key the core returned for this connector, or ``None``.

    Anything other than an explicit ``configured: true`` with a non-empty string
    is treated as no key, so a malformed response can never produce one.
    """
    if not isinstance(payload, dict) or payload.get("configured") is not True:
        return None
    key = payload.get("api_key")
    return key if isinstance(key, str) and key else None


CAPABILITIES = {
    "netlas": (
        "hostname",
        "ip",
        #: Which endpoints name our domain. Discovery for the DNS and exposure
        #: modules, and a partial answer for phishing: a certificate that carries our
        #: name *and* someone else's proves a shared certificate, not a double.
        "certificate",
        #: The same collection asked from the *brand* instead: who else claims to be
        #: us. A double does not name our domain - it names something that looks like
        #: it - so this is the question that finds one, and it is deliberately a
        #: capability of its own rather than a rewrite of the one above.
        "certificate_brand",
        "title",
        "body",
        #: Our icon found elsewhere: the same image byte for byte, and - from the same
        #: capability - an image the provider considers one edit away from ours (a
        #: recoloured or resized copy), which evidence names ``favicon_similar``.
        "favicon",
        #: Registration facts and mail capability of a domain the platform already
        #: knows: both are evidence about a candidate, never a way to discover one.
        "whois",
        "mx",
        "lookup",
        "passive_dns",
    ),
}


class ProviderError(RuntimeError):
    """Safe codes only, never raw URLs, response bodies or credentials."""

    def __init__(self, code, retry_after=None):
        super().__init__(code)
        self.retry_after = retry_after


#: Where a Netlas response document keeps the facts the certificate rules score on.
#:
#: Several spellings are accepted because these names are confirmed by the provider spike
#: (docs/dns-security.md) rather than by a schema this repository ships, and the map is the
#: single place a confirmed name goes. A field that arrives under none of them is absent
#: from the observation - never invented - and a response that yields no signal at all is
#: reported by the worker as an unreadable shape instead of a clean scan.
#:
#: Why these keys matter at all: R4 compares a JARM plus a title or favicon between our
#: service and a copy of it, the shared-infrastructure suppression needs ``org``/``asn``
#: to recognise a CDN, and an ``asn`` scope exception reads ``asn``. Nothing in the
#: platform wrote any of them, so all three decisions were unreachable (F-10/F-11).
SIGNAL_PATHS = {
    "org": ("organization", "org", "autonomous_system.name", "net.name", "asn.name"),
    "asn": ("asn", "asn_number", "autonomous_system.number", "net.asn", "asn.number"),
    "jarm": ("jarm", "jarm_hash", "tls.jarm", "jarm.fingerprint"),
    "title": ("title", "http.title", "http_title"),
    "favicon_hash": ("favicon.hash", "http.favicon.hash", "favicon_hash"),
}

#: Where a Netlas response document keeps the icon hashes, and where a WHOIS document
#: keeps the two registration facts. The same rule as :data:`SIGNAL_PATHS` applies: a
#: field that arrives under none of these names is absent from the observation rather
#: than invented, and a document that carries none of them is reported as an unreadable
#: shape instead of as a clean answer.
FAVICON_PATHS = {
    "sha256": (
        "http.favicon.hash_sha256",
        "favicon.hash_sha256",
        "favicon_hash_sha256",
    ),
    "perceptual": (
        "http.favicon.perceptual_hash",
        "favicon.perceptual_hash",
        "favicon_perceptual_hash",
    ),
}

#: A certificate or WHOIS organisation is a bounded string, never a structure the
#: platform has to walk: ``registrar`` is documented as sharing the registrant group's
#: shape, and that group's ``name``/``organization`` is what an operator reads.
WHOIS_PATHS = {
    "created": ("created_date", "created", "registration_date", "domain.created_date"),
    "registrar": ("registrar.name", "registrar.organization", "registrar"),
}

#: A fingerprint or serial taken from provider data is interpolated into a search
#: expression, so it is validated as hex first and refused otherwise: provider data is
#: untrusted input, exactly like a value an operator typed.
_HEX_VALUE = re.compile(r"^[0-9a-fA-F]{4,128}$")

#: A favicon hash as the provider reports it, under the same rule as a fingerprint.
#: Hex only, so a value that arrived as base64 or as shodan's integer hash is refused
#: instead of being searched for - an expression built from the wrong alphabet answers
#: "nothing matched", which is indistinguishable from a real absence.
_FAVICON_HASH = re.compile(r"^[0-9a-fA-F]{8,64}$")

#: A brand as an operator typed it: one letter or digit first, then letters, digits,
#: spaces, dots, underscores, ampersands and hyphens, 2..100 characters. Anything else
#: (a quote, a colon, a wildcard, a control character) is refused rather than escaped
#: into a query nobody asked for.
_BRAND = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._&-]{1,99}$")


def brand_parts(value):
    """A brand as the two halves of one certificate expression.

    The phrase half keeps the spelling an operator chose and is escaped by
    :func:`quoted`. The wildcard half is *generated*: everything that is not a letter,
    a digit or a hyphen is removed, so no metacharacter of the query grammar can
    survive into a part that is not a quoted phrase. A brand with fewer than three
    usable characters has no wildcard half worth searching for and is refused.
    """
    candidate = value.strip() if isinstance(value, str) else ""
    if not _BRAND.fullmatch(candidate):
        raise ProviderError("invalid_brand_value")
    token = re.sub(r"[^a-z0-9-]+", "", candidate.lower())
    if len(token) < 3:
        raise ProviderError("invalid_brand_value")
    return candidate, token


def dig(document, path):
    """A dotted path's value, or ``None`` when any step is missing."""
    current = document
    for step in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(step)
    return current


def certificate_signals(row):
    """The scored facts a response row carries, by the map above.

    Only values of the expected shape survive: an organisation or title is a bounded
    string, an ASN is an integer inside the legal range, and a JARM or favicon hash is a
    bounded token. Anything else is dropped rather than stored as a signal a rule would
    score on, because a rule that fires on a malformed value is worse than one that never
    fires.
    """
    signals = {}
    for signal, paths in SIGNAL_PATHS.items():
        for path in paths:
            value = dig(row, path)
            if signal == "asn":
                if isinstance(value, str) and value.isdecimal():
                    value = int(value)
                if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 4294967295:
                    continue
            elif not isinstance(value, str) or not value.strip() or len(value) > 200 or any(ord(c) < 32 for c in value):
                continue
            else:
                value = value.strip()
            signals[signal] = value
            break
    return signals


def whois_facts(rows, adapter=None):
    """The registration facts a candidate is judged on, kept only when well formed.

    Two facts and no more: when the domain was registered, and who registered it. A
    registrar name that is not a bounded string, or a date the platform cannot read, is
    dropped rather than stored as a fact a rule would score on - the same rule the
    certificate signals follow.
    """
    facts = {}
    for row in rows:
        if not isinstance(row, dict):
            if adapter:
                adapter.record_error("invalid_whois_record")
            continue
        for key, paths in WHOIS_PATHS.items():
            if key in facts:
                continue
            for path in paths:
                value = dig(row, path)
                if value is None:
                    continue
                # The first spelling that carries a value decides the fact - accepted or
                # rejected. Continuing past it would let the *whole* ``registrar`` object
                # (a later spelling of the same fact) overwrite the name that was just
                # read, which is how a well-formed document came to be reported as an
                # unreadable registrar.
                if key == "created":
                    try:
                        facts["created"] = observed(value)
                    except ProviderError as exc:
                        if adapter:
                            adapter.record_error(str(exc))
                    break
                if (
                    not isinstance(value, str)
                    or not value.strip()
                    or len(value) > 255
                    or any(ord(char) < 32 for char in value)
                ):
                    if adapter:
                        adapter.record_error("invalid_whois_registrar")
                    break
                facts["registrar"] = value.strip()
                break
        if facts.get("created") and facts.get("registrar"):
            break
    return facts


def mail_facts(rows, adapter=None):
    """Whether a domain receives mail, and under which hostnames.

    The absence of an ``mx`` list on every row is a real answer - the domain does not
    receive mail - and it is reported as one. A row whose ``mx`` is not a list is not an
    answer at all and is recorded as an unreadable shape.
    """
    hosts = []
    timestamp = None
    for row in rows:
        if not isinstance(row, dict):
            if adapter:
                adapter.record_error("invalid_mail_record")
            continue
        values = row.get("mx")
        if isinstance(values, str):
            values = [values]
        if values is None:
            values = []
        if not isinstance(values, list):
            if adapter:
                adapter.record_error("invalid_mail_record")
            continue
        for value in values[:20]:
            try:
                hosts.append(host(value))
            except ProviderError:
                if adapter:
                    adapter.record_error("invalid_mail_host")
        if timestamp is None:
            try:
                timestamp = observed(row.get("last_updated") or row.get("@timestamp"))
            except ProviderError as exc:
                if adapter:
                    adapter.record_error(str(exc))
    return {
        "mail_capable": bool(hosts),
        "mx_hosts": sorted(set(hosts))[:10],
        "provider_observed_at": timestamp or "unknown",
    }


def quoted(value):
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or any(ord(c) < 32 for c in value)
    ):
        raise ProviderError("invalid_search_value")
    # Escape search grammar metacharacters before adding the phrase delimiter.
    return '"' + re.sub(r'([\\"*?:(){}\[\]])', r"\\\1", value) + '"'


def query(provider, capability, value):
    fields = {
        "netlas": {
            "certificate": "certificate.names",
            "title": "http.title",
            "body": "http.body",
            "hostname": "host",
            "ip": "ip",
        },
    }
    field = fields.get(provider, {}).get(capability)
    if field is None:
        raise ProviderError("unsupported_capability")
    return field + ":" + quoted(value)


def brand_certificate_expression(brand):
    """The documented brand question, in one expression.

    ``certificate.subject.organization`` is the provider's own example of an
    organisation query, and ``certificate.names`` is a full-text field, so a wildcard
    on it is the documented way to ask "which certificates name us at all". Both halves
    are needed: a certificate that claims our organisation but names nothing like us,
    and one that names us without claiming our organisation, are both worth seeing, and
    asking either half alone hides the other.
    """
    phrase, token = brand_parts(brand)
    return (
        "certificate.subject.organization:"
        + quoted(phrase)
        + " OR certificate.names:*"
        + token
        + "*"
    )


def favicon_expression(algorithm, value):
    """The icon question, exact or fuzzy, from a hash the provider reported.

    The fuzzy operator belongs to a *term*, not to a quoted phrase: ``field:value~1``
    is one edit away from ``value``, which is exactly what a recoloured or resized copy
    of our icon is. Quoting it would turn the search into "an icon whose hash is
    literally this string", which is the question the exact search already asks.
    """
    if not isinstance(value, str) or not _FAVICON_HASH.fullmatch(value):
        raise ProviderError("invalid_favicon_hash")
    digest = value.lower()
    if algorithm == "sha256":
        return "http.favicon.hash_sha256:" + quoted(digest)
    if algorithm == "perceptual":
        return "http.favicon.perceptual_hash:" + digest + "~1"
    raise ProviderError("unsupported_capability")


def host(value):
    if not isinstance(value, str) or len(value) > 253:
        raise ProviderError("invalid_endpoint")
    value = value.rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ProviderError("invalid_endpoint") from exc
    if not re.fullmatch(
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
        value,
    ):
        raise ProviderError("invalid_endpoint")
    return value


def classify_http_error(provider, status_code, body):
    """Return a small safe error code; provider response text is never exposed."""
    text = body.decode("utf-8", errors="ignore").lower()[:8192]
    try:
        payload = json.loads(text)
    except (ValueError, TypeError):
        payload = None
    if isinstance(payload, dict):
        fragments = [
            str(value)
            for key, value in payload.items()
            if key.lower() in {"detail", "message", "errmsg", "error", "reason"}
            and isinstance(value, (str, int, float))
        ]
        text = " ".join(fragments).lower()[:8192] or text

    if status_code in {401} or (
        provider == "netlas"
        and status_code == 400
        and any(
            phrase in text
            for phrase in ("api key not found", "invalid api key", "api key is invalid")
        )
    ):
        return "invalid_credentials"
    if status_code == 403:
        return "access_denied"
    if status_code == 402:
        return "credits_exhausted"
    if status_code == 429:
        return "rate_limited"
    return f"http_{status_code}" if status_code != 400 else "provider_rejected_request"


def retry_delay(value):
    """Parse Retry-After delta-seconds or HTTP-date, capped to one day."""
    try:
        if value.strip().isdigit():
            seconds = int(value.strip())
        else:
            deadline = parsedate_to_datetime(value)
            if deadline.tzinfo is None:
                deadline = deadline.replace(tzinfo=timezone.utc)
            seconds = int((deadline - datetime.now(timezone.utc)).total_seconds())
        return min(86400, max(0, seconds))
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None


def observed(value):
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            date = datetime.fromtimestamp(
                value / 1000 if value > 10**11 else value, timezone.utc
            )
        else:
            date = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return (
            date.replace(tzinfo=timezone.utc).isoformat()
            if date.tzinfo is None
            else date.astimezone(timezone.utc).isoformat()
        )
    except (ValueError, OverflowError, OSError):
        raise ProviderError("invalid_observation_timestamp") from None


class Adapter:
    def __init__(self, provider, env, reserve, *, transport=None):
        if provider not in BASES:
            raise ProviderError("unsupported_provider")
        self.provider, self.env, self.reserve = provider, env, reserve
        self.transport = transport
        self.requests = 0
        self.max_requests = 20
        self.truncated = False
        self.record_errors = 0
        self.record_error_codes = []

    def record_error(self, code="invalid_record"):
        self.record_errors += 1
        if len(self.record_error_codes) < 20:
            self.record_error_codes.append(code)

    def _validated_result_batch(self, items, *, limit):
        if not isinstance(items, list):
            raise ProviderError("invalid_response")
        batch = []
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("data"), dict):
                self.record_error()
                continue
            batch.append(item["data"])
        if len(batch) > limit:
            self.truncated = True
        return batch[:limit]

    async def search_certificates(self, value, *, max_pages=3, max_results=100):
        """Which certificates name this domain, from the keyed field only.

        The keyed field is the exact question and the sparse one: a certificate that
        names our domain somewhere in its SAN list. It stays the DNS and exposure
        module's discovery query - and it is *not* the phishing question, which is what
        :meth:`search_brand_certificates` is for.
        """
        return await self.certificate_pages(
            "certificate.names.keyword:" + quoted(host(value)),
            max_pages=max_pages,
            max_results=max_results,
        )

    async def search_brand_certificates(self, brand, *, max_pages=3, max_results=100):
        """Who else claims this brand in a certificate.

        Netlas rate-limits the certificate collections to three requests a minute, so
        this is declared as the certificate operation it is: the reservation comes from
        the certificate bucket and the account's certificate budget is what pays for it.
        A brand search is also the broadest query this connector makes, which is why the
        worker counts its result set before it pages through it.
        """
        return await self.certificate_pages(
            brand_certificate_expression(brand),
            max_pages=max_pages,
            max_results=max_results,
        )

    async def certificate_pages(self, expression, *, max_pages=3, max_results=100):
        """Page Netlas' documented certificate collection under one expression."""
        if self.provider != "netlas":
            raise ProviderError("unsupported_capability")
        if max_pages < 1 or max_results < 1:
            raise ProviderError("invalid_search_limit")
        certificates, start = [], 0
        async with self.client() as client:
            for _ in range(max_pages):
                response = await self.request(
                    client,
                    "GET",
                    "/certs/",
                    params={
                        "q": expression,
                        "fields": "names,fingerprint_sha256,serial_number,subject_dn,issuer_dn,validity,extensions.subject_alt_name.dns_names",
                        "start": start,
                    },
                    bucket="certificate",
                )
                items = response.get("items")
                if not isinstance(items, list):
                    raise ProviderError("invalid_response")
                batch = self._validated_result_batch(items, limit=max_results)
                for document in batch:
                    fingerprint = document.get("fingerprint_sha256")
                    if (
                        not isinstance(document.get("names"), list)
                        or not isinstance(fingerprint, str)
                        or not re.fullmatch(r"[0-9a-fA-F]{64}", fingerprint)
                    ):
                        self.record_error("invalid_certificate_record")
                        continue
                    certificates.append(document)
                more = len(items) == 20
                if len(certificates) >= max_results:
                    self.truncated = (
                        self.truncated or more or len(certificates) > max_results
                    )
                    return certificates[:max_results]
                if not more:
                    return certificates
                start += 20
            self.truncated = True
        return certificates

    async def search_domains(self, value, *, max_pages=3, max_results=100):
        """Query Netlas' documented passive DNS Domains collection only."""
        if self.provider != "netlas":
            raise ProviderError("unsupported_capability")
        target = host(value)
        if max_pages < 1 or max_results < 1:
            raise ProviderError("invalid_search_limit")
        rows, start = [], 0
        async with self.client() as client:
            for _ in range(max_pages):
                response = await self.request(
                    client,
                    "GET",
                    "/domains/",
                    params={
                        # Netlas documents this wildcard query for passive DNS
                        # discovery; keep the wildcard syntax generated, never user-supplied.
                        "q": f"domain:*.{target}",
                        "fields": "domain,a,aaaa,ns,last_updated",
                        "start": start,
                    },
                    bucket="search",
                )
                batch = self._validated_result_batch(
                    response.get("items"), limit=max_results
                )
                rows.extend(batch)
                more = len(response["items"]) == 20
                if len(rows) >= max_results:
                    self.truncated = self.truncated or more or len(rows) > max_results
                    return rows[:max_results]
                if not more:
                    return rows
                start += 20
            self.truncated = True
        return rows

    async def search_mail_records(self, value, *, max_pages=1, max_results=20):
        """Whether a domain receives mail, from the passive DNS collection.

        ``domain:`` with ``mx:*`` is the documented existence test for the field, so the
        question is asked in the collection's own query language instead of downloading
        address rows and guessing from them. A look-alike that answers mail is one a
        campaign can be run from, which is a different fact from one that merely resolves.
        """
        if self.provider != "netlas":
            raise ProviderError("unsupported_capability")
        if max_pages < 1 or max_results < 1:
            raise ProviderError("invalid_search_limit")
        expression = "domain:" + quoted(host(value)) + " AND mx:*"
        rows, start = [], 0
        async with self.client() as client:
            for _ in range(max_pages):
                response = await self.request(
                    client,
                    "GET",
                    "/domains/",
                    params={
                        "q": expression,
                        "fields": "domain,mx,ns,last_updated",
                        "start": start,
                    },
                    bucket="search",
                )
                items = response.get("items")
                if not isinstance(items, list):
                    raise ProviderError("invalid_response")
                batch = self._validated_result_batch(items, limit=max_results)
                rows.extend(batch)
                more = len(items) == 20
                if len(rows) >= max_results:
                    self.truncated = self.truncated or more or len(rows) > max_results
                    return rows[:max_results]
                if not more:
                    return rows
                start += 20
            self.truncated = True
        return rows

    async def search_whois(self, value, *, max_pages=1, max_results=20):
        """Registration facts for one domain, from the WHOIS collection.

        Passive on purpose. The platform's own WHOIS enrichment opens a connection to
        the registrar on port 43, once, when a candidate first appears - and an
        installation whose environment refuses that connection stores no registration
        facts at all. This asks the provider's stored copy instead, which is what lets an
        analyst re-read the same fact later and read it for a domain the registrar itself
        will not answer for.
        """
        if self.provider != "netlas":
            raise ProviderError("unsupported_capability")
        if max_pages < 1 or max_results < 1:
            raise ProviderError("invalid_search_limit")
        expression = "domain:" + quoted(host(value))
        rows, start = [], 0
        async with self.client() as client:
            for _ in range(max_pages):
                response = await self.request(
                    client,
                    "GET",
                    "/whois_domains/",
                    params={
                        "q": expression,
                        "fields": "domain,created_date,registrar,registrant.organization",
                        "start": start,
                    },
                    bucket="search",
                )
                items = response.get("items")
                if not isinstance(items, list):
                    raise ProviderError("invalid_response")
                batch = self._validated_result_batch(items, limit=max_results)
                rows.extend(batch)
                more = len(items) == 20
                if len(rows) >= max_results:
                    self.truncated = self.truncated or more or len(rows) > max_results
                    return rows[:max_results]
                if not more:
                    return rows
                start += 20
            self.truncated = True
        return rows

    async def count_responses(self, expression, *, bucket="search"):
        """How many rows an expression would return, before any of them is fetched.

        A brand or a body expression can match a hundred thousand endpoints, and paging
        through them is neither useful nor affordable. The count route answers with the
        size of the result set on its own - exact below a thousand, and an estimate the
        provider documents as within three percent above it - so the caller can decide
        to skip the expression instead of spending the scan's budget on a query nobody
        can read to the end.
        """
        if self.provider != "netlas":
            raise ProviderError("unsupported_capability")
        if (
            not isinstance(expression, str)
            or not expression
            or len(expression) > 512
            or any(ord(char) < 32 for char in expression)
        ):
            raise ProviderError("invalid_search_value")
        async with self.client() as client:
            response = await self.request(
                client,
                "GET",
                "/responses_count/",
                params={"q": expression},
                bucket=bucket,
            )
        count = response.get("count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ProviderError("invalid_response")
        return count

    async def own_favicon_hashes(self, value, *, max_results=20):
        """The icon hashes the provider reports for one of our own endpoints.

        The perceptual hash is the provider's own view of the image, and that is the
        whole reason it is read from here instead of computed: a hash this connector
        calculated with its own algorithm would be compared against the provider's by
        Hamming distance, and two different algorithms make that distance meaningless.
        So the fuzzy search takes its value from the provider or it is not asked at all.
        """
        target = host(value)
        async with self.client() as client:
            response = await self.request(
                client,
                "GET",
                "/responses/",
                params={
                    "q": "host:" + quoted(target),
                    "fields": "http.favicon.hash_sha256,http.favicon.perceptual_hash,host",
                    "start": 0,
                },
                bucket="search",
            )
        batch = self._validated_result_batch(
            response.get("items"), limit=max_results
        )
        found = {}
        for document in batch:
            for algorithm, paths in FAVICON_PATHS.items():
                if algorithm in found:
                    continue
                for path in paths:
                    candidate = dig(document, path)
                    if candidate is None:
                        continue
                    if not isinstance(candidate, str) or not _FAVICON_HASH.fullmatch(
                        candidate.strip()
                    ):
                        self.record_error("unreadable_favicon_hash")
                        continue
                    found[algorithm] = candidate.strip().lower()
                    break
        return found

    async def search_favicon(self, algorithm, value, *, max_pages=1, max_results=100):
        """Who else serves this icon: byte for byte, or one edit away from it."""
        return await self.responses_pages(
            favicon_expression(algorithm, value),
            max_pages=max_pages,
            max_results=max_results,
        )

    async def search_certificate_responses(
        self, fingerprint, *, max_pages=3, max_results=100
    ):
        """Every endpoint an index says serves this certificate.

        This is the reverse of discovery. Discovery asks "which certificates name our
        domain"; a copy of our service is found by the opposite question - "where else is
        the certificate we serve being served" - and the answer is the collection that
        carries the serving address together with the JARM and HTTP facts R4 compares and
        the organisation that tells a CDN from a copy.
        """
        if self.provider != "netlas":
            raise ProviderError("unsupported_capability")
        if not isinstance(fingerprint, str) or not _HEX_VALUE.fullmatch(fingerprint):
            raise ProviderError("invalid_certificate_fingerprint")
        if max_pages < 1 or max_results < 1:
            raise ProviderError("invalid_search_limit")
        rows, start = [], 0
        expression = 'certificate.fingerprint_sha256:' + quoted(fingerprint.lower())
        async with self.client() as client:
            for _ in range(max_pages):
                response = await self.request(
                    client,
                    "GET",
                    "/responses/",
                    params={
                        "q": expression,
                        "fields": "host,ip,port,protocol,organization,asn,jarm,http.title,certificate",
                        "start": start,
                    },
                    bucket="certificate",
                )
                items = response.get("items")
                if not isinstance(items, list):
                    raise ProviderError("invalid_response")
                batch = self._validated_result_batch(items, limit=max_results)
                rows.extend(batch)
                more = len(items) == 20
                if len(rows) >= max_results:
                    self.truncated = self.truncated or more or len(rows) > max_results
                    return rows[:max_results]
                if not more:
                    return rows
                start += 20
            self.truncated = True
        return rows

    def certificate_responses(self, target, rows):
        """One observation per endpoint that serves the searched certificate.

        Our own endpoint is in this answer too, and that is deliberate: the core decides
        what is ours (an address its own probe verified, or an ``ip_address`` asset), and a
        connector that filtered the answer here would hide the copy it cannot name.
        """
        target = host(target)
        observations = []
        for row in rows:
            raw_name = row.get("host") or row.get("domain") or row.get("ip")
            try:
                name = host(raw_name)
            except ProviderError:
                self.record_error("invalid_response_endpoint")
                continue
            ip = row.get("ip")
            if ip is not None:
                try:
                    ip = str(ipaddress.ip_address(ip))
                except (ValueError, TypeError):
                    self.record_error("invalid_response_ip")
                    ip = None
            port = row.get("port")
            if isinstance(port, str) and port.isdecimal():
                port = int(port)
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                port = None
            certificate = row.get("certificate") if isinstance(row.get("certificate"), dict) else {}
            fingerprint = certificate.get("fingerprint_sha256") or certificate.get("fingerprint")
            if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", fingerprint):
                fingerprint = None
            signals = certificate_signals(row)
            if fingerprint is None and not signals:
                # An endpoint that carries nothing the rules can score: a shape the spike
                # has not confirmed yet, reported rather than read as a clean answer.
                self.record_error("unreadable_certificate_response")
            metadata = {
                "evidence": "netlas_certificate_response",
                "source_domain": target,
                "wildcard": name.startswith("*."),
                **signals,
            }
            if ip:
                metadata["ip"] = ip
            if port:
                metadata["port"] = port
            if fingerprint:
                metadata["fingerprint_sha256"] = fingerprint.lower()
            observations.append(
                {
                    "observation_type": "certificate_response",
                    "subject": name,
                    "record_type": "TLS",
                    "value": f"https://{name}" + (f":{port}" if port else ""),
                    "status": "historical",
                    "metadata": metadata,
                }
            )
        return observations

    def dns_observations(self, target, rows):
        """Normalize DNS RRsets without treating provider data as ownership."""
        target = host(target)
        observations = []
        for row in rows:
            raw_domain = row.get("domain")
            try:
                domain = host(raw_domain)
            except ProviderError:
                self.record_error()
                continue
            if domain != target and not domain.endswith("." + target):
                self.record_error()
                continue
            try:
                timestamp = observed(row.get("last_updated") or row.get("@timestamp"))
            except ProviderError as exc:
                self.record_error(str(exc))
                timestamp = None
            for record_type, key, version in (
                ("A", "a", 4),
                ("AAAA", "aaaa", 6),
                ("NS", "ns", None),
            ):
                values = row.get(key, [])
                if values is None:
                    values = []
                if not isinstance(values, list):
                    self.record_error()
                    continue
                valid = []
                for value in values[:20]:
                    if version is not None:
                        try:
                            address = ipaddress.ip_address(value)
                        except (ValueError, TypeError):
                            self.record_error()
                            continue
                        if address.version != version:
                            self.record_error()
                            continue
                        valid.append(str(address))
                    else:
                        try:
                            valid.append(host(value))
                        except ProviderError:
                            self.record_error()
                if not valid:
                    continue
                normalized_values = sorted(set(valid))
                observations.append(
                    {
                        "observation_type": "passive_dns",
                        "subject": domain,
                        "record_type": record_type,
                        "value": "; ".join(normalized_values)[:1000],
                        "status": "historical",
                        "metadata": {
                            "evidence": "netlas_passive_dns_dataset",
                            "source_domain": target,
                            "provider_observed_at": timestamp or "unknown",
                            "record_values": normalized_values,
                        },
                    }
                )
        return observations

    @property
    def configured(self):
        return bool(self.env.get(KEYS[self.provider], "").strip())

    async def request(
        self, client, method, path, *, params=None, body=None, bucket="search"
    ):
        key = self.env.get(KEYS[self.provider], "").strip()
        if not key or len(key) > 512 or any(ord(c) < 33 for c in key):
            raise ProviderError("credentials_unconfigured")
        headers = {"Accept": "application/json", "Authorization": "Bearer " + key}
        params = dict(params or {})

        for attempt in range(3):
            if self.requests >= self.max_requests:
                raise ProviderError("scan_request_budget_exhausted")
            # Charge each physical attempt against both the shared provider
            # quota and per-job request budget; retries are never free.
            await self.reserve(bucket)
            self.requests += 1
            try:
                retry_wait = None
                async with client.stream(
                    method,
                    BASES[self.provider] + path,
                    params=params,
                    json=body,
                    headers=headers,
                ) as response:
                    if response.status_code != 200:
                        chunks = bytearray()
                        async for chunk in response.aiter_bytes():
                            chunks.extend(chunk[: 8192 - len(chunks)])
                            if len(chunks) >= 8192:
                                break
                        code = classify_http_error(
                            self.provider, response.status_code, bytes(chunks)
                        )
                        retry_after = retry_delay(
                            response.headers.get("Retry-After", "")
                        )
                        error = ProviderError(code, retry_after)
                        if (
                            response.status_code != 429
                            and not 500 <= response.status_code <= 599
                        ):
                            raise error
                        if attempt == 2 or self.requests >= self.max_requests:
                            raise error
                        retry_wait = min(
                            5,
                            retry_after
                            if retry_after is not None
                            else 0.25 * (2**attempt),
                        )
                    else:
                        data = bytearray()
                        async for chunk in response.aiter_bytes():
                            if len(data) + len(chunk) > 2_000_000:
                                raise ProviderError("response_too_large")
                            data.extend(chunk)
                        result = json.loads(data)
                if retry_wait is not None:
                    await asyncio.sleep(retry_wait)
                    continue
                break
            except ProviderError:
                raise
            except httpx.HTTPError as exc:
                if attempt == 2 or self.requests >= self.max_requests:
                    raise ProviderError("network_or_invalid_response") from exc
                await asyncio.sleep(0.25 * (2**attempt))
            except (ValueError, UnicodeError) as exc:
                raise ProviderError("network_or_invalid_response") from exc
        else:
            raise ProviderError("network_or_invalid_response")

        if not isinstance(result, dict):
            raise ProviderError("invalid_response")
        if result.get("error"):
            raise ProviderError("provider_application_error")
        return result

    def client(self):
        return httpx.AsyncClient(
            timeout=httpx.Timeout(30, connect=5),
            follow_redirects=False,
            transport=self.transport,
        )

    async def search(self, capability, value, *, max_pages=3, max_results=100):
        if self.provider == "netlas" and capability == "certificate":
            return await self.search_certificates(
                value, max_pages=max_pages, max_results=max_results
            )
        if self.provider == "netlas" and capability == "certificate_brand":
            return await self.search_brand_certificates(
                value, max_pages=max_pages, max_results=max_results
            )
        return await self.responses_pages(
            query(self.provider, capability, value),
            max_pages=max_pages,
            max_results=max_results,
        )

    async def responses_pages(self, expression, *, max_pages=3, max_results=100):
        """Page the responses collection under one already-built expression."""
        if max_pages < 1 or max_results < 1:
            raise ProviderError("invalid_search_limit")
        rows = []
        async with self.client() as client:
            for page in range(max_pages):
                response = await self.request(
                    client,
                    "GET",
                    "/responses/",
                    params={"q": expression, "start": page * 20},
                    bucket="search",
                )
                items = response.get("items")
                if not isinstance(items, list):
                    raise ProviderError("invalid_response")
                batch = self._validated_result_batch(items, limit=max_results)
                more = len(items) == 20
                rows.extend(batch)
                if len(rows) >= max_results:
                    self.truncated = more or len(rows) > max_results
                    return rows[:max_results]
                if not more:
                    return rows
            self.truncated = True
        return rows

    async def lookup_host(self, value, *, max_results=100):
        target = host(value)
        async with self.client() as client:
            response = await self.request(
                client, "GET", "/host/" + quote(target, safe="") + "/", bucket="lookup"
            )
        ports = response.get("ports", [])
        if not isinstance(ports, list):
            raise ProviderError("invalid_response")
        ip = response.get("ip")
        if ip is not None:
            try:
                ip = str(ipaddress.ip_address(ip))
            except ValueError:
                raise ProviderError("invalid_endpoint_ip") from None
        whois = response.get("whois") if isinstance(response.get("whois"), dict) else {}
        timestamp = whois.get("@timestamp") or response.get("@timestamp")
        rows = []
        for item in ports[:max_results]:
            if not isinstance(item, dict):
                self.record_error()
                continue
            protocol = item.get("prot7") or item.get("protocol") or "unknown"
            transport = item.get("prot4") or "tcp"
            rows.append(
                {
                    "host": target,
                    "ip": ip,
                    "port": item.get("port"),
                    "protocol": protocol,
                    "transport_protocol": transport,
                    "last_updated": timestamp,
                }
            )
        self.truncated = len(ports) > max_results
        return rows


def endpoints(row, adapter=None):
    """Actual host/web records only: a SAN never proves endpoint ownership."""
    if not isinstance(row, dict):
        raise ProviderError("invalid_record")
    if "names" in row and ("fingerprint_sha256" in row or "subject_dn" in row):
        names = row.get("names")
        if not isinstance(names, list):
            if adapter:
                adapter.record_error()
                return []
            raise ProviderError("invalid_certificate_names")
        validity = row.get("validity")
        validity = validity if isinstance(validity, dict) else {}
        certificate = {}
        fingerprint = row.get("fingerprint_sha256")
        if isinstance(fingerprint, str) and re.fullmatch(
            r"[0-9a-fA-F]{64}", fingerprint
        ):
            certificate["sha256"] = fingerprint.lower()
        elif fingerprint is not None and adapter:
            adapter.record_error()
        for source_key, target_key in (("start", "valid_from"), ("end", "valid_to")):
            if validity.get(source_key):
                try:
                    certificate[target_key] = observed(validity[source_key])
                except ProviderError as exc:
                    if adapter:
                        adapter.record_error(str(exc))
        for key in ("subject_dn", "issuer_dn"):
            value = row.get(key)
            if isinstance(value, str) and not any(ord(char) < 32 for char in value):
                certificate[key] = value[:512]
        records = []
        for name in names[:100]:
            if not isinstance(name, str) or name.startswith("*."):
                continue
            try:
                subject = host(name)
            except ProviderError:
                if adapter:
                    adapter.record_error()
                continue
            records.append(
                {
                    "subject": subject,
                    "ip": None,
                    "port": None,
                    "transport": "tcp",
                    "protocol": "tls-certificate",
                    "observed_at": certificate.get("valid_from"),
                    "title": "TLS certificate",
                    "certificate": certificate,
                }
            )
        return records
    try:
        record = endpoint(row)
        return [record] if record else []
    except ProviderError as exc:
        if not adapter:
            raise
        adapter.record_error(str(exc))
        return []


#: Keys a provider row can name its subject under, in the order ``endpoint`` reads
#: them. Used to tell "this row names nothing" from "everything on this row was
#: filtered out", which are different outcomes for the caller: the first is a
#: partial scan, the second is a row that simply produced no observation.
SUBJECT_KEYS = ("hostname", "domain", "host", "ip", "ip_address", "uri")


def has_subject(row) -> bool:
    """Whether a provider row names anything this connector could attribute."""
    return isinstance(row, dict) and any(row.get(key) for key in SUBJECT_KEYS)


def endpoint(row):
    ip = row.get("ip") or row.get("ip_address")
    if ip:
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            raise ProviderError("invalid_endpoint_ip") from None
    subject = row.get("hostname") or row.get("domain") or row.get("host") or ip
    uri = row.get("uri") or row.get("host")
    port = row.get("port")
    if isinstance(uri, str) and uri:
        # Providers may emit both URLs and bare hostname:port / [IPv6]:port.
        try:
            ipaddress.ip_address(uri)
        except ValueError:
            parsed = urlsplit(uri if "://" in uri else "//" + uri)
            if parsed.username or parsed.password:
                raise ProviderError("invalid_endpoint")
            if parsed.hostname:
                subject = parsed.hostname
                try:
                    port = port or parsed.port
                except ValueError:
                    raise ProviderError("invalid_endpoint_port") from None
    if not subject:
        return None
    if isinstance(port, str) and port.isdecimal():
        port = int(port)
    if port is not None and (
        isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
    ):
        raise ProviderError("invalid_endpoint_port")
    protocol = row.get("protocol") or "unknown"
    if not isinstance(protocol, str) or len(protocol) > 32:
        raise ProviderError("invalid_endpoint_protocol")
    transport = str(
        row.get("transport_protocol") or row.get("transport") or "tcp"
    ).lower()
    if transport not in {"tcp", "udp"}:
        raise ProviderError("invalid_endpoint_transport")
    return {
        "subject": host(subject),
        "ip": ip,
        "port": port,
        "transport": transport,
        "protocol": protocol.lower(),
        "observed_at": observed(
            row.get("last_updated")
            or row.get("lastupdatetime")
            or row.get("scan_time")
            or row.get("@timestamp")
        ),
        "title": str(row.get("title") or "")[:1000],
    }
