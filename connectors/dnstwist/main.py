"""DNSTwist connector.

Runs the ``dnstwist`` binary against every active ``domain`` asset reported
by the core, resolves candidates, and submits normalized phishing findings.
The job summary separates the three counts an operator needs to read a scan
that discovered nothing: permutations generated (``candidates``), permutations
that resolved to a public address (``resolved``), and findings the core stored
(``new_discovered``).

What the scan *asks for* is chosen in classes rather than as a raw fuzzer list
(``DNSTWIST_FUZZER_CLASSES``, default ``typo``): the CLI's vocabulary has one token
per technique, and several techniques are useless — or refused — without their
companion file, which a raw list cannot express. ``dictionary`` and ``tld`` pull the
package's own word list and TLD dictionary (overridable through
``DNSTWIST_DICTIONARY`` / ``DNSTWIST_TLD_DICTIONARY``), and the connector checks the
file exists before it builds a command the binary would reject. The expensive
dimensions stay opt-in because one scan with all of them can produce thousands of DNS
requests for a single asset.

Three further bounds sit beside the class choice:

* ``DNSTWIST_MAX_CANDIDATES`` caps how many permutations one domain may ask about.
  The CLI has no such option — it generates what the fuzzers generate — so the bound
  is applied here, where a permutation that is never resolved and never submitted
  costs nothing. Whether it bit is reported (``domains_truncated``); a silent cap
  would look exactly like a domain with fewer look-alikes.
* ``DNSTWIST_MX_CHECK`` passes ``--mxcheck`` (the CLI's own MX check) and asks the
  candidate's TXT records for an SPF policy, so the ``mx_without_spf`` fact is
  reported from an answer the platform actually has instead of assumed. It is off by
  default: the check is free of provider credits but not free of network activity —
  the CLI connects to the candidate's mail server.
* ``DNSTWIST_CONTENT_INSPECTION`` passes ``--lsh tlsh`` (page similarity against our
  own page), and is refused with a named skip when the TLSh module is not installed:
  a capability the image cannot run is reported as unavailable, not as a domain with
  no similar page. ``--phash`` and screenshots are deliberately not used — they need a
  headless browser, and the decision recorded in the plan is that this connector
  renders nothing.

This connector owns the DNSTwist subprocess; the core only receives normalized findings.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import socket
import subprocess
import sys
from dataclasses import dataclass, field

if sys.platform != "win32":
    import os as _os

import aiodns
import structlog

from opendrp_connector import ConnectorBase, ConnectorPreflightError
from opendrp_connector.base import DEFAULT_SUBMIT_BATCH
from opendrp_connector.network import is_safe_external_ip

log = structlog.get_logger()

#: Every DNSTwist fuzzer this connector can ask for, grouped into the classes an
#: operator chooses between. The names are the CLI's own vocabulary for the pinned
#: release: ``tld`` is *not* a fuzzer (the class runs ``tld-swap``, whose dictionary
#: arrives separately through ``--tld``), ``*original`` is the input echoed back and
#: is therefore not offered at all, and ``various`` is kept for completeness even
#: though the default never selects it.
FUZZER_CLASSES: dict[str, tuple[str, ...]] = {
    "typo": (
        "addition",
        "omission",
        "repetition",
        "hyphenation",
        "insertion",
        "replacement",
        "transposition",
        "vowel-swap",
    ),
    "idn": ("homoglyph", "cyrillic"),
    "bitsquatting": ("bitsquatting",),
    "plural": ("plural",),
    "subdomain": ("subdomain",),
    "dictionary": ("dictionary",),
    "various": ("various",),
    "tld": ("tld-swap",),
}

#: What a scan runs unless an operator says otherwise. The full set together with a
#: TLD dictionary can produce thousands of DNS requests for one asset: useful for an
#: operator who asked for it, a trap for one who did not, and a scan that occupies the
#: connector until the lease timeout when the resolver is slow.
_DEFAULT_FUZZER_CLASSES = "typo"

#: Where the Debian package keeps the dictionaries the CLI asks for. The paths come
#: from that package's own file list, and they are *checked* rather than assumed: a
#: package that lays them out differently is reported as a named skip per domain,
#: instead of the binary failing the domain with a message nobody reads.
_PACKAGED_TLD_DICTIONARIES = ("/usr/share/dnstwist/dictionaries/common_tlds.dict",)
_PACKAGED_WORDLISTS = ("/usr/share/dnstwist/dictionaries/english.dict",)

#: How many permutations one domain may ask about, when the class choice alone would
#: produce more. A permutation that is never resolved and never submitted costs no
#: DNS request, which is the whole reason the bound is here rather than in the CLI.
_DEFAULT_MAX_CANDIDATES = 250

# An empty value uses the resolver configured in /etc/resolv.conf. In Docker
# this is the embedded resolver, which is reachable from the connector network;
# hardcoding public resolvers made the previous default hang when UDP/53 egress
# was filtered.
_DEFAULT_NAMESERVERS: list[str] = []
def _env_number(value: str | None, default: float, low: float, high: float) -> float:
    """A bounded numeric setting; an unusable value falls back to the default.

    The same rule the other workers' settings follow. Without it a typo killed the
    process at import (``abc`` raised before the worker could register) and a
    negative value was accepted, which made every scan time out at once.
    """
    try:
        number = float(str(value).strip())
    except (TypeError, ValueError):
        return default
    return number if low <= number <= high else default


# Upper bound for a single dnstwist subprocess run; a hang must not pin the
# connector forever. One second is the floor: a shorter bound is a scan that can
# never finish, which is a misconfiguration rather than a preference.
_DNSTWIST_SUBPROCESS_TIMEOUT = _env_number(
    os.environ.get("DNSTWIST_TIMEOUT_SECONDS"), 120.0, 1.0, 3600.0
)

#: The DNSTwist CLI release this connector is written against. The images pin it
#: (`dnstwist=0~20250130-1`, whose CLI answers ``dnstwist 20250130``), so the pin
#: and this line are one decision written twice; `tests/test_dnstwist_cli_version.py`
#: is where they meet, and `verify_cli_version()` is what makes a mismatch loud.
_EXPECTED_DNSTWIST_VERSION = "20250130"
#: How long the version probe may take. A ``dnstwist`` that will not answer at all
#: is as much a mismatch as a wrong number.
_DNSTWIST_VERSION_TIMEOUT = 15.0


def _env_flag(value: str | None, default: bool = False) -> bool:
    """A connector env var read as a switch, with an explicit default.

    Unlike the Shodan connector's capability flags these default to off: everything
    the flag turns on widens the scan's network footprint (a SMTP check against a
    stranger's mail server, a similarity fetch of a page), and a flag nobody set must
    not do that.
    """
    if value is None or not value.strip():
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _tlsh_available() -> bool:
    """Whether this interpreter can run the CLI's ``--lsh tlsh`` comparison.

    The CLI imports the module itself, from the same interpreter its shebang points
    at, so asking the question here is asking it about the thing that would fail.
    """
    try:
        return importlib.util.find_spec("tlsh") is not None
    except (ImportError, ValueError):
        return False


class DnstwistVersionMismatch(ConnectorPreflightError):
    """The installed CLI is not the one this connector was written against.

    A preflight refusal rather than a per-job ``partial``: the JSON field names, the
    fuzzer vocabulary and the resolved-address dictionary are all properties of the
    CLI, so a different release can return fewer look-alikes for the same domain —
    and a scan that quietly reports fewer is indistinguishable from a domain that
    has none. Raised before the connector registers, so the container exits non-zero
    with one instruction instead of failing every job with the same cause.
    """


async def installed_cli_version() -> str | None:
    """The release ``dnstwist --version`` reports, or ``None`` if it will not run.

    The CLI answers ``dnstwist 20250130`` and exits 0; the last whitespace-separated
    token is the release, which is also the upstream version the Debian package
    ``0~20250130-1`` is derived from.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "dnstwist",
            "--version",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except OSError:
        return None
    try:
        stdout, _ = await asyncio.wait_for(
            proc.communicate(), timeout=_DNSTWIST_VERSION_TIMEOUT
        )
    except asyncio.CancelledError:
        proc.kill()
        await proc.wait()
        raise
    except Exception:
        # A timeout lands here too: a CLI that cannot answer is a mismatch.
        try:
            proc.kill()
            await proc.wait()
        except Exception:
            pass
        return None
    if proc.returncode != 0:
        return None
    text = stdout.decode(errors="ignore").strip()
    return text.split()[-1] if text else None


@dataclass
class DomainScan:
    """What one domain's scan produced, and why it may look quiet.

    These four facts used to travel on the connector instance
    (``_last_domain_error`` and its neighbours), so the result of a scan was only
    readable by inspecting the worker's mutable state after the call. Returning
    them makes the outcome part of the value: two domains could be scanned
    concurrently, or a subclass could reuse ``run_domain``, without either
    reading the other's flags.
    """

    tally: dict[str, int]
    error: bool = False
    truncated: bool = False
    skips: list[str] = field(default_factory=list)


class DNSTwistConnector(ConnectorBase):
    #: It scans the monitored ``domain`` assets and produces phishing candidates
    #: about them; that is the one asset type the core may queue to this worker.
    CAPABILITIES = ("domain",)
    #: No provider quota: the only third parties asked are DNS resolvers and the
    #: candidates' own web servers, and neither bills a metered account.
    OPERATIONS: tuple[str, ...] = ()
    #: No provider credential at all. Declaring the empty tuple is what makes the
    #: readiness row say ``credentials_configured: false`` truthfully instead of
    #: looking like a provider worker whose key somebody forgot.
    CREDENTIAL_ENV: tuple[str, ...] = ()

    def __init__(self) -> None:
        super().__init__()
        self.nameservers = [
            ns.strip()
            for ns in self.env.get("DNS_NAMESERVERS", "").split(",")
            if ns.strip()
        ]
        self.fuzzer_classes = [
            name.strip().lower()
            for name in self.env.get("DNSTWIST_FUZZER_CLASSES", _DEFAULT_FUZZER_CLASSES).split(",")
            if name.strip()
        ]
        self.tld_dictionary = self.env.get("DNSTWIST_TLD_DICTIONARY", "").strip()
        self.dictionary = self.env.get("DNSTWIST_DICTIONARY", "").strip()
        self.max_candidates = int(
            _env_number(
                self.env.get("DNSTWIST_MAX_CANDIDATES"),
                _DEFAULT_MAX_CANDIDATES,
                1,
                5000,
            )
        )
        self.mx_check = _env_flag(self.env.get("DNSTWIST_MX_CHECK"), False)
        self.content_inspection = _env_flag(
            self.env.get("DNSTWIST_CONTENT_INSPECTION"), False
        )
        self.threads = int(_env_number(self.env.get("DNSTWIST_THREADS"), 8, 1, 32))
        #: The resolver is built on first use, not here: a connector that has no
        #: candidates to resolve never needs one, and on a platform where ``aiodns``
        #: cannot run at all (a Windows host, a Proactor event loop) constructing it
        #: unconditionally turned a domain with nothing to resolve into a crash — which
        #: is how the missing ``winloop``/selector-loop dependency reached this file.
        self._resolver: object | None = None
        self._resolver_unavailable = False

    async def register(self) -> None:
        """Register, then declare readiness like every other worker.

        A compute-only connector has no key to check, so its row answers "no provider
        credential is needed" rather than leaving the core to infer it from silence.
        """
        await super().register()
        await self.report_readiness()

    def _select_fuzzers(self) -> tuple[str, list[str]]:
        """The ``--fuzzers`` list for the chosen classes, plus what could not run.

        A class with no companion file is left out rather than passed on: the CLI
        rejects ``--tld``/``--dictionary`` unless their fuzzer is in the same command,
        so a class without its file is an invocation the binary would refuse. The
        returned reasons become per-domain skips (``tld_dictionary_missing``,
        ``wordlist_missing``), which is how an operator learns that the class they
        enabled did not run instead of reading a smaller candidate count.
        """
        selected: list[str] = []
        skipped: list[str] = []
        for name in self.fuzzer_classes:
            fuzzers = FUZZER_CLASSES.get(name)
            if not fuzzers:
                skipped.append(f"unknown_fuzzer_class:{name}")
                continue
            if name == "dictionary" and not self._companion_file(self.dictionary, _PACKAGED_WORDLISTS):
                skipped.append("wordlist_missing")
                continue
            if name == "tld" and not self._companion_file(self.tld_dictionary, _PACKAGED_TLD_DICTIONARIES):
                skipped.append("tld_dictionary_missing")
                continue
            selected.extend(fuzzers)
        ordered = list(dict.fromkeys(selected))
        if not ordered:
            # Every class was refused, so the scan has nothing to ask for. The typo
            # class is the connector's documented baseline and needs no companion
            # file; falling back to it keeps a misconfigured deployment scanning
            # rather than silently reporting zero candidates.
            ordered = list(FUZZER_CLASSES[_DEFAULT_FUZZER_CLASSES])
        return ",".join(ordered), skipped

    def _companion_file(self, configured: str, packaged: tuple[str, ...]) -> str | None:
        """The dictionary to pass to the CLI: the operator's path, or the packaged one."""
        if configured:
            return configured if os.path.isfile(configured) else None
        return next((path for path in packaged if os.path.isfile(path)), None)

    async def _resolver_or_none(self):
        """The ``aiodns`` resolver, built on first use, or ``None`` if it cannot run.

        Lazy for two reasons. A scan with nothing to resolve must not construct one at
        all — that is how a domain whose permutations are simply not registered became a
        hard failure on a host where ``aiodns`` cannot start. And the failure itself is
        not fatal: what this connector needs is a resolver, not this particular client
        (see :meth:`_resolve_addresses`).
        """
        if self._resolver is not None or self._resolver_unavailable:
            return self._resolver
        try:
            self._resolver = aiodns.DNSResolver(
                nameservers=self.nameservers, timeout=2, tries=2
            )
        except Exception as exc:
            self._resolver_unavailable = True
            self._resolver = None
            log.warning("dnstwist_resolver_unavailable", err=type(exc).__name__)
        return self._resolver

    async def _resolve_addresses(self, name: str) -> list[str]:
        """The public A/AAAA addresses of a candidate.

        ``aiodns`` when it can run, the event loop's own resolver when it cannot: the
        second asks the same system resolver, and both are filtered by the same
        :func:`is_safe_external_ip` rule, so what changes is the DNS client — not the
        decision about which addresses may be stored. Without the fallback a host where
        ``aiodns`` refuses to start (Windows without a Selector loop) reports every
        permutation as unregistered, which is indistinguishable from a quiet domain.
        """
        addresses: list[str] = []
        resolver = await self._resolver_or_none()
        if resolver is not None:
            for record_type in ("A", "AAAA"):
                try:
                    answers = await resolver.query(name, record_type)
                except Exception:
                    continue
                addresses.extend(
                    record.host
                    for record in answers
                    if hasattr(record, "host") and isinstance(record.host, str)
                )
        else:
            try:
                infos = await asyncio.get_running_loop().getaddrinfo(
                    name, None, type=socket.SOCK_STREAM
                )
            except Exception:
                infos = []
            addresses.extend(info[4][0] for info in infos if info[4])
        return [
            address for address in dict.fromkeys(addresses) if is_safe_external_ip(address)
        ]

    async def _spf_published(self, name: str) -> bool | None:
        """Whether a candidate publishes an SPF policy; ``None`` when nobody answered.

        One free DNS question, asked only for a candidate that points at mail servers.
        ``None`` is not ``False``: a TXT lookup that timed out says nothing about the
        policy, and scoring silence as "publishes no SPF" would hand the weight to every
        candidate whose resolver was slow.
        """
        resolver = await self._resolver_or_none()
        if resolver is None:
            return None
        try:
            answers = await resolver.query(name, "TXT")
        except Exception:
            return None
        for answer in answers:
            text = getattr(answer, "text", None)
            if isinstance(text, str) and "v=spf1" in text.lower():
                return True
        return False

    async def _mail_facts(self, name: str, entry: dict) -> dict:
        """The MX facts of one candidate, as evidence the core can score.

        Three facts, and the third is the one §4.4 weighs: the mail servers the
        candidate points at (``mx_hosts``), whether one of them accepted a mail exchange
        for it (``mx_spy``), and — only when the candidate has mail servers *and*
        publishes no SPF policy — ``mx_without_spf``. The rule reads "accepts mail and
        publishes no SPF record", so the two halves are answered separately instead of
        inferred from each other, and a candidate whose TXT lookup failed reports neither
        rather than being scored on what the platform could not see.
        """
        raw_mx = entry.get("dns_mx")
        if isinstance(raw_mx, str):
            raw_mx = [raw_mx]
        hosts = [
            str(host).strip()[:255]
            for host in (raw_mx if isinstance(raw_mx, list) else [])
            if str(host).strip()
        ]
        metadata: dict = {}
        if hosts:
            metadata["mx_hosts"] = hosts[:20]
        if entry.get("mx_spy"):
            metadata["mx_spy"] = True
        if hosts and await self._spf_published(name) is False:
            metadata["mx_without_spf"] = True
        if metadata:
            # The question these facts answer, named the way the provider workers name
            # it: the same question asked of another source is the same capability.
            metadata["capability"] = "mx"
        return metadata

    # ------------------------------------------------------------------
    # Assets come from the core API (same JWT-less path is not available,
    # so the core includes the asset list in the work payload).
    # ------------------------------------------------------------------

    @staticmethod
    def _empty_tally() -> dict[str, int]:
        """Per-domain counters: permutations seen, permutations that resolved to
        a public address, and findings the core stored."""
        return {"candidates": 0, "resolved": 0, "stored": 0}

    async def preflight(self) -> None:
        """Refuse to start against a DNSTwist that is not the pinned one.

        Runs once before registration, so a container built with a different CLI
        never claims work at all: no job can be reported as ``partial`` (or, worse,
        as a clean scan) by a scanner that is not the one this code was written for.
        """
        unknown = sorted(set(self.fuzzer_classes) - set(FUZZER_CLASSES))
        if unknown:
            # Refused rather than ignored: a class name nobody recognises would leave
            # the operator believing they enabled a technique, and the scan reporting
            # fewer candidates is the only trace it left.
            raise ConnectorPreflightError(
                f"DNSTWIST_FUZZER_CLASSES names {unknown}, which this connector does not "
                f"know. Known classes: {sorted(FUZZER_CLASSES)}."
            )
        installed = await installed_cli_version()
        if installed == _EXPECTED_DNSTWIST_VERSION:
            return
        raise DnstwistVersionMismatch(
            f"the dnstwist CLI in this container reports "
            f"'{installed or 'no version (it did not run)'}', but this connector "
            f"is written against {_EXPECTED_DNSTWIST_VERSION}. The image pins "
            f"dnstwist=0~{_EXPECTED_DNSTWIST_VERSION}-1; rebuild the connector "
            f"from this checkout (`docker compose build connector-phishing-dnstwist`) "
            f"instead of running it against a system dnstwist, and change "
            f"_EXPECTED_DNSTWIST_VERSION together with that pin if the upgrade "
            f"is deliberate."
        )

    async def run_scan(self, work: dict) -> tuple[list[dict], dict]:
        domains: list[str] = work.get("params", {}).get("domains") or []
        if not domains:
            await self.report_readiness()
            return [], {
                "task": "scan_dnstwist",
                "domains_scanned": 0,
                "candidates": 0,
                "resolved": 0,
                "new_discovered": 0,
                "domains_truncated": 0,
                "max_candidates": self.max_candidates,
                "fuzzer_classes": list(self.fuzzer_classes),
                "skipped": None,
                "status": "success",
            }

        tally = self._empty_tally()
        errors = 0
        truncated = 0
        skips: dict[str, int] = {}
        for domain in domains:
            outcome = await self.run_domain(domain, str(work["job_id"]))
            for key in tally:
                tally[key] += outcome.tally[key]
            errors += 1 if outcome.error else 0
            truncated += 1 if outcome.truncated else 0
            for reason in outcome.skips:
                skips[reason] = skips.get(reason, 0) + 1
        summary = {
            "task": "scan_dnstwist",
            "domains_scanned": len(domains),
            # ``new_discovered`` alone cannot distinguish a broken scan from a
            # quiet one. Next to the other two counters it can: no candidates
            # means the fuzzers produced nothing, candidates that never resolve
            # means the look-alikes are simply not registered, and candidates
            # that resolve but are not stored are findings the platform already
            # has (``phishing_domain`` is unique, so a re-found host is rejected
            # rather than updated).
            "candidates": tally["candidates"],
            "resolved": tally["resolved"],
            "new_discovered": tally["stored"],
            "domains_with_errors": errors,
            # A class that could not run, and a candidate set the cap shortened: both
            # are reasons a scan looks quiet without being quiet, and neither is
            # visible in the three counts above.
            "domains_truncated": truncated,
            "max_candidates": self.max_candidates,
            "fuzzer_classes": list(self.fuzzer_classes),
            "skipped": skips or None,
            "status": "partial" if errors or skips or truncated else "success",
        }
        # Findings were already submitted in batches inside run_domain. Readiness
        # last, so the row reflects this run rather than only the startup state.
        await self.report_readiness()
        return [], summary

    async def run_domain(self, domain: str, job_id: str) -> DomainScan:
        """Scan one domain and report what DNSTwist produced for it.

        The tally is the contract ``run_scan`` sums; the error, truncation and
        skip flags travel beside it rather than on ``self``, so a caller does not
        have to know the order in which the worker mutates itself.
        """
        tally = self._empty_tally()
        fuzzers, skips = self._select_fuzzers()
        cmd = [
            "dnstwist",
            "--format",
            "json",
            "--registered",
            "--fuzzers",
            fuzzers,
            "--threads",
            str(self.threads),
        ]
        if self.nameservers:
            cmd.extend(["--nameservers", ",".join(self.nameservers)])
        if "dictionary" in self.fuzzer_classes:
            wordlist = self._companion_file(self.dictionary, _PACKAGED_WORDLISTS)
            if wordlist:
                # The CLI refuses ``--dictionary`` unless the ``dictionary`` fuzzer is
                # in the same command; ``_select_fuzzers`` is what keeps the file and
                # the fuzzer from being decided apart.
                cmd.extend(["--dictionary", wordlist])
        if "tld" in self.fuzzer_classes:
            dictionary = self._companion_file(self.tld_dictionary, _PACKAGED_TLD_DICTIONARIES)
            if dictionary:
                cmd.extend(["--tld", dictionary])
        if self.mx_check:
            # The CLI's own MX question: which mail servers this candidate points at,
            # and whether one of them accepts a mail exchange for it.
            cmd.append("--mxcheck")
        if self.content_inspection:
            if _tlsh_available():
                cmd.extend(["--lsh", "tlsh"])
            else:
                skips.append("content_inspection_unavailable")
                log.warning("dnstwist_content_inspection_unavailable")
        cmd.append(domain)
        try:
            spawn_kwargs = {
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
            }
            # dnstwist may create resolver subprocesses. Start a process group
            # so a timeout cannot leave descendants running after the job has
            # already been reported as partial/error.
            if sys.platform != "win32":
                spawn_kwargs["start_new_session"] = True
            proc = await asyncio.create_subprocess_exec(*cmd, **spawn_kwargs)
        except Exception as exc:
            log.warning("dnstwist_exec_error", domain=domain, err=str(exc))
            return DomainScan(tally=tally, error=True, skips=skips)

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=_DNSTWIST_SUBPROCESS_TIMEOUT
            )
        except (asyncio.TimeoutError, asyncio.CancelledError) as cancellation:
            try:
                if sys.platform != "win32" and getattr(proc, "pid", None):
                    _os.killpg(proc.pid, _os.SIGKILL)
                else:
                    proc.kill()
                await proc.wait()
            except Exception:
                # The process may have exited between timeout and termination.
                # The timeout itself remains a provider error either way.
                pass
            if isinstance(cancellation, asyncio.CancelledError):
                raise
            log.warning("dnstwist_timeout", domain=domain, timeout=_DNSTWIST_SUBPROCESS_TIMEOUT)
            return DomainScan(tally=tally, error=True, skips=skips)
        except Exception as exc:
            log.warning("dnstwist_exec_error", domain=domain, err=str(exc))
            return DomainScan(tally=tally, error=True, skips=skips)

        if proc.returncode != 0:
            log.warning(
                "dnstwist_failed",
                domain=domain,
                returncode=proc.returncode,
                err=stderr.decode(errors="ignore")[:200],
            )
            return DomainScan(tally=tally, error=True, skips=skips)

        try:
            entries = json.loads(stdout.decode(errors="ignore") or "[]")
        except Exception as exc:
            log.warning("dnstwist_json_parse_error", domain=domain, err=str(exc))
            return DomainScan(tally=tally, error=True, skips=skips)

        # Filter out the original domain (*original) and empty entries.
        candidates = []
        for e in entries:
            if not isinstance(e, dict):
                continue
            dname = e.get("domain") or e.get("domain-name")
            fuzzer = str(e.get("fuzzer") or "")
            if not dname or not fuzzer or fuzzer.lstrip("*") == "original" or dname == domain:
                continue
            candidates.append(e)
        # The candidate bound, where it costs nothing: a permutation that is never
        # resolved and never submitted spends no DNS request. How many were dropped is
        # kept, because a silent cap and a domain with fewer look-alikes look alike.
        truncated = len(candidates) > self.max_candidates
        candidates = candidates[: self.max_candidates]
        tally["candidates"] = len(candidates)

        batch: list[dict] = []

        for entry in candidates:
            dname = entry.get("domain") or entry.get("domain-name")
            if not dname:
                continue

            raw_a = entry.get("dns_a") or []
            if isinstance(raw_a, str):
                raw_a = [raw_a]
            raw_aaaa = entry.get("dns_aaaa") or []
            if isinstance(raw_aaaa, str):
                raw_aaaa = [raw_aaaa]
            valid_ips = [
                ip.strip()
                for ip in (raw_a + raw_aaaa)
                if isinstance(ip, str) and ip.strip() and not ip.startswith("!") and is_safe_external_ip(ip.strip())
            ]
            if not valid_ips:
                valid_ips.extend(await self._resolve_addresses(str(dname)))
            if not valid_ips:
                continue
            tally["resolved"] += 1

            primary_ip = valid_ips[0]

            # Check web ports (80, 443).
            open_ports = []
            for port in (80, 443):
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(primary_ip, port), timeout=1.5
                    )
                    writer.close()
                    await writer.wait_closed()
                    open_ports.append(str(port))
                except Exception:
                    pass

            finding = {
                "phishing_domain": str(dname)[:512],
                "matched_asset": domain,
                "ip_address": primary_ip,
                "web_ports": ", ".join(open_ports) or None,
                "detection_source": "dnstwist",
                "original_domain": domain,
            }
            if self.mx_check:
                metadata = await self._mail_facts(str(dname), entry)
                if metadata:
                    finding["metadata"] = metadata
            batch.append(finding)

            # The SDK's core-wide batch size: one request per 500 findings, which is
            # the largest body the core accepts. A per-domain scan rarely reaches it.
            if len(batch) >= DEFAULT_SUBMIT_BATCH:
                result = await self.submit_findings(job_id, batch)
                tally["stored"] += int(result.get("accepted", 0))
                batch = []

        if batch:
            result = await self.submit_findings(job_id, batch)
            tally["stored"] += int(result.get("accepted", 0))
        return DomainScan(tally=tally, truncated=truncated, skips=skips)


def main() -> None:
    if sys.platform == "win32":
        # ``aiodns`` needs a Selector event loop. Windows defaults to Proactor, so a
        # connector started there fails on its first resolution with a message about
        # ``winloop`` instead of scanning. Set for the process this connector *starts*
        # (never at import: a library that picks the loop of whoever imported it would
        # break its host, and this repository's test suite imports this module).
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    connector = DNSTwistConnector()
    connector.main()


if __name__ == "__main__":
    main()
