"""DNSTwist connector.

Runs the ``dnstwist`` binary against every active ``domain`` asset reported
by the core, resolves candidates, and submits normalized phishing findings.
The job summary separates the three counts an operator needs to read a scan
that discovered nothing: permutations generated (``candidates``), permutations
that resolved to a public address (``resolved``), and findings the core stored
(``new_discovered``).
This connector owns the DNSTwist subprocess; the core only receives normalized findings.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys

if sys.platform != "win32":
    import os as _os

import aiodns
import structlog

from opendrp_connector import ConnectorBase
from opendrp_connector.network import is_safe_external_ip

log = structlog.get_logger()

# The full DNSTwist fuzzing set plus a 100-entry TLD dictionary can produce
# thousands of DNS requests for one asset. That is useful for an operator who
# explicitly opts into it, but it is not a safe default for a small deployment:
# one slow resolver can occupy the connector until the lease timeout. Keep the
# default bounded and make the expensive dimensions explicit configuration.
_DEFAULT_FUZZERS = ",".join(
    (
        "addition",
        "omission",
        "repetition",
        "hyphenation",
        "insertion",
        "replacement",
        "transposition",
        "vowel-swap",
    )
)
# An empty value uses the resolver configured in /etc/resolv.conf. In Docker
# this is the embedded resolver, which is reachable from the connector network;
# hardcoding public resolvers made the previous default hang when UDP/53 egress
# was filtered.
_DEFAULT_NAMESERVERS: list[str] = []
# Upper bound for a single dnstwist subprocess run; a hang must not pin the
# connector forever.
_DNSTWIST_SUBPROCESS_TIMEOUT = float(os.environ.get("DNSTWIST_TIMEOUT_SECONDS", "120"))


class DNSTwistConnector(ConnectorBase):
    def __init__(self) -> None:
        super().__init__()
        self.nameservers = [
            ns.strip()
            for ns in self.env.get("DNS_NAMESERVERS", "").split(",")
            if ns.strip()
        ]
        self.fuzzers = self.env.get("DNSTWIST_FUZZERS", _DEFAULT_FUZZERS).strip()
        self.tld_dictionary = self.env.get("DNSTWIST_TLD_DICTIONARY", "").strip()
        self.threads = max(1, min(int(self.env.get("DNSTWIST_THREADS", "8")), 32))

    # ------------------------------------------------------------------
    # Assets come from the core API (same JWT-less path is not available,
    # so the core includes the asset list in the work payload).
    # ------------------------------------------------------------------

    @staticmethod
    def _empty_tally() -> dict[str, int]:
        """Per-domain counters: permutations seen, permutations that resolved to
        a public address, and findings the core stored."""
        return {"candidates": 0, "resolved": 0, "stored": 0}

    async def run_scan(self, work: dict) -> tuple[list[dict], dict]:
        domains: list[str] = work.get("params", {}).get("domains") or []
        if not domains:
            return [], {
                "task": "scan_dnstwist",
                "domains_scanned": 0,
                "candidates": 0,
                "resolved": 0,
                "new_discovered": 0,
                "status": "success",
            }

        tally = self._empty_tally()
        errors = 0
        for domain in domains:
            outcome = await self.run_domain(domain, str(work["job_id"]))
            for key in tally:
                tally[key] += outcome[key]
            errors += 1 if getattr(self, "_last_domain_error", False) else 0
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
            "status": "partial" if errors else "success",
        }
        # Findings were already submitted in batches inside run_domain.
        return [], summary

    async def run_domain(self, domain: str, job_id: str) -> dict[str, int]:
        """Scan one domain and report what DNSTwist produced for it."""
        tally = self._empty_tally()
        cmd = [
            "dnstwist",
            "--format",
            "json",
            "--registered",
            "--fuzzers",
            self.fuzzers or _DEFAULT_FUZZERS,
            "--threads",
            str(self.threads),
        ]
        if self.nameservers:
            cmd.extend(["--nameservers", ",".join(self.nameservers)])
        if self.tld_dictionary:
            if not os.path.isfile(self.tld_dictionary):
                self._last_domain_error = True
                log.warning("dnstwist_tld_dictionary_missing", path=self.tld_dictionary)
                return tally
            cmd.extend(["--tld", self.tld_dictionary])
        cmd.append(domain)

        self._last_domain_error = False
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
            self._last_domain_error = True
            log.warning("dnstwist_exec_error", domain=domain, err=str(exc))
            return tally

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=_DNSTWIST_SUBPROCESS_TIMEOUT
            )
        except asyncio.TimeoutError:
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
            self._last_domain_error = True
            log.warning("dnstwist_timeout", domain=domain, timeout=_DNSTWIST_SUBPROCESS_TIMEOUT)
            return tally
        except Exception as exc:
            self._last_domain_error = True
            log.warning("dnstwist_exec_error", domain=domain, err=str(exc))
            return tally

        if proc.returncode != 0:
            self._last_domain_error = True
            log.warning(
                "dnstwist_failed",
                domain=domain,
                returncode=proc.returncode,
                err=stderr.decode(errors="ignore")[:200],
            )
            return tally

        try:
            entries = json.loads(stdout.decode(errors="ignore") or "[]")
        except Exception as exc:
            self._last_domain_error = True
            log.warning("dnstwist_json_parse_error", domain=domain, err=str(exc))
            return tally

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
        tally["candidates"] = len(candidates)

        resolver = aiodns.DNSResolver(nameservers=self.nameservers, timeout=2, tries=2)
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
                try:
                    a_ans = await resolver.query(dname, "A")
                    valid_ips.extend([r.host for r in a_ans if hasattr(r, "host") and is_safe_external_ip(r.host)])
                except Exception:
                    pass
                try:
                    aaaa_ans = await resolver.query(dname, "AAAA")
                    valid_ips.extend([r.host for r in aaaa_ans if hasattr(r, "host") and is_safe_external_ip(r.host)])
                except Exception:
                    pass
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

            batch.append(
                {
                    "phishing_domain": str(dname)[:512],
                    "matched_asset": domain,
                    "ip_address": primary_ip,
                    "web_ports": ", ".join(open_ports) or None,
                    "detection_source": "dnstwist",
                    "original_domain": domain,
                }
            )

            # Submit in batches of 25 to keep request sizes bounded.
            if len(batch) >= 25:
                result = await self.submit_findings(job_id, batch)
                tally["stored"] += int(result.get("accepted", 0))
                batch = []

        if batch:
            result = await self.submit_findings(job_id, batch)
            tally["stored"] += int(result.get("accepted", 0))
        return tally


def main() -> None:
    connector = DNSTwistConnector()
    connector.main()


if __name__ == "__main__":
    main()
