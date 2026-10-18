"""Active TLS probe: what a monitored host serves *right now*.

Certificate Transparency says a certificate was **issued**; only a handshake says
which one a service **serves**. The DNS Security expiry monitor used to read CT
alone, so it could remind an operator about a renewal that was never deployed and
stay silent about an expired certificate that no log indexed (F-05 in the DNS &
TLS audit). This module answers the second question with one `curl` call per
(host, port) against our own asset, addressed by `--resolve` so the URL, the SNI
and the certificate name check all stay on the monitored hostname while the IP is
only the transport target.

Three deliberate choices:

* **curl, not a library.** The call is the exact command an operator runs by hand
  to reproduce the result (`docs/dns-security.md` prints it), and its exit code is
  a documented taxonomy: `0` verified, `60` verification failed, `6`/`7`/`28`/`35`
  transport, `90`/`91` certificate status. `%{exitcode}` is recorded with the
  result so a stored judgement can be re-read years later.
* **No certificate library.** The facts this platform acts on are the DER
  fingerprints, the validity dates, the serial and the SPKI hash; those are read
  here by a bounded DER walker rather than by adding `cryptography` to a
  hash-pinned connector lock that `scripts/lock_requirements.py` refuses to
  regenerate for this image. `tests/test_dns_security.py` pins the reader against
  `cryptography` on real certificates, including a deliberately broken chain, so
  the two cannot drift apart unnoticed. Subject and issuer DNs are *not* decoded:
  a half-decoded DN would look authoritative, and nothing decides on it.
* **Verification is never disabled for the authoritative pass.** A failed
  handshake is evidence in its own right; `--insecure` would turn "this host
  serves an expired certificate" into "this host serves a certificate".
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import re
from datetime import datetime, timezone
from typing import Any

#: Ports probed when the operator has not chosen any. 443 first: it is the one that
#: carries the certificate a visitor sees.
DEFAULT_PORTS: tuple[int, ...] = (443,)
#: An allowlist stays a list only if it is short; three ports is a web service with
#: a management interface, thirty is a port scanner.
MAX_PORTS = 3
DEFAULT_MAX_PROBES = 200
MAX_MAX_PROBES = 2000
#: Four at a time: enough that a 200-host scan finishes in minutes, few enough that
#: a monitoring host does not look like a flood to its own network.
CONCURRENCY = 4
CONNECT_TIMEOUT_SECONDS = 3
MAX_TIME_SECONDS = 8
MAX_PATH_CHARS = 200
#: `%{certs}` and `%{num_certs}` appear in curl 7.88; on anything older the chain
#: would be silently empty and the probe would look like a host without a
#: certificate, so the version is checked and recorded.
MINIMUM_CURL_FOR_CERTS = (7, 88)
#: The marker keeps curl's own output (`-w`) apart from anything the server sent.
#: `-o /dev/null` already discards the body; this makes the boundary explicit.
MARKER = "__OPEDRP_TLS__"
WRITE_OUT = (
    f"\n{MARKER}%{{exitcode}}|%{{ssl_verify_result}}|%{{num_certs}}|%{{ssl_version}}\n%{{certs}}"
)

_PEM_BLOCK = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)
_OID_SUBJECT_ALT_NAME = b"\x55\x1d\x11"  # 2.5.29.17, DER-encoded OID body
_DER_DNS_NAME = 0x82  # GeneralName ::= dNSName [2] IMPLICIT IA5String


class CertificateParseError(Exception):
    """A chain this reader cannot read.

    Raised instead of returning an empty result: "no certificate" and "a
    certificate this code failed to parse" have to stay different answers.
    """


def parse_ports(value: object) -> tuple[list[int], list[str]]:
    """An allowlist of ports from `DNS_SECURITY_TLS_PORTS`; never a silent default.

    A malformed entry is dropped and reported, and an operator who asked for four
    ports gets none rather than an arbitrary three: probing a port nobody asked
    about spends traffic on someone else's service.
    """
    if value is None or not str(value).strip():
        return list(DEFAULT_PORTS), []
    ports: list[int] = []
    errors: list[str] = []
    for item in str(value).split(","):
        text = item.strip()
        if not text:
            continue
        if not text.isdigit() or not 1 <= int(text) <= 65535 or int(text) in ports:
            errors.append("invalid_tls_port")
            continue
        ports.append(int(text))
    if len(ports) > MAX_PORTS:
        return [], ["too_many_tls_ports"]
    return ports, errors


def parse_path(value: object) -> tuple[str, list[str]]:
    """The request path, bounded and printable, defaulting to `/`."""
    path = str(value or "/")
    if (
        len(path) > MAX_PATH_CHARS
        or not path.startswith("/")
        or any(ord(char) < 33 or ord(char) > 126 for char in path)
    ):
        return "/", ["invalid_tls_path"]
    return path, []


def build_argv(host: str, address: str, port: int, path: str) -> list[str]:
    """The exact command an operator can paste, including the IP pinning.

    `--resolve` keeps the URL, the SNI and the name check on the monitored
    hostname; `-q` ignores a `.curlrc` that would change the meaning, `--proxy ""`
    refuses an ambient proxy, and nothing here is ever `--insecure` or `-k`.
    """
    target = f"[{address}]" if ":" in address else address
    return [
        "curl",
        "-q",
        "-sS",
        "--no-progress-meter",
        "--proxy",
        "",
        "--connect-timeout",
        str(CONNECT_TIMEOUT_SECONDS),
        "--max-time",
        str(MAX_TIME_SECONDS),
        "--tlsv1.2",
        "--resolve",
        f"{host}:{port}:{target}",
        "-o",
        os.devnull,
        "-w",
        WRITE_OUT,
        f"https://{host}:{port}{path}",
    ]


def parse_output(stdout: bytes) -> dict[str, Any]:
    """Split curl's `-w` preamble from the PEM chain it appended to it."""
    index = stdout.find(MARKER.encode("ascii"))
    if index < 0:
        return {"exit": None, "verify_result": None, "num_certs": None, "tls_version": None, "chain": b""}
    head, _, rest = stdout[index + len(MARKER):].partition(b"\n")
    fields = head.decode("ascii", "replace").split("|")
    while len(fields) < 4:
        fields.append("")
    pem = rest if _PEM_BLOCK.search(rest) else b""
    return {
        "exit": _as_int(fields[0]),
        "verify_result": _as_int(fields[1]),
        "num_certs": _as_int(fields[2]),
        "tls_version": fields[3].strip()[:32] or None,
        "chain": pem,
    }


def _as_int(text: str) -> int | None:
    text = text.strip()
    return int(text) if text.isdigit() else None


def _der_element(data: bytes, offset: int) -> tuple[int, bytes, int, int]:
    """One DER element: ``(tag, value, raw_start, next_offset)``."""
    if offset >= len(data):
        raise CertificateParseError("truncated DER")
    tag = data[offset]
    index = offset + 1
    if index >= len(data):
        raise CertificateParseError("truncated DER length")
    first = data[index]
    index += 1
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or count > 4 or index + count > len(data):
            raise CertificateParseError("unsupported DER length")
        length = int.from_bytes(data[index:index + count], "big")
        index += count
    else:
        length = first
    end = index + length
    if end > len(data):
        raise CertificateParseError("DER element exceeds its container")
    return tag, data[index:end], offset, end


def _der_children(value: bytes) -> list[tuple[int, bytes, int, int]]:
    children: list[tuple[int, bytes, int, int]] = []
    cursor = 0
    while cursor < len(value):
        child = _der_element(value, cursor)
        children.append(child)
        cursor = child[3]
    return children


def _der_time(value: bytes) -> str | None:
    """UTCTime or GeneralizedTime, as an ISO 8601 instant in UTC.

    UTCTime carries two digits of year: RFC 5280 fixes the window so that `50`–`99`
    are 1950–1999 and `00`–`49` are 2000–2049, which is what `%y` already does.
    Optional seconds and a `+hhmm` offset are accepted the way the RFC allows them.
    """
    text = value.decode("ascii", "strict").strip()
    for fmt in ("%y%m%d%H%M%SZ", "%y%m%d%H%MZ", "%Y%m%d%H%M%SZ", "%Y%m%d%H%MZ"):
        try:
            moment = datetime.strptime(text, fmt)
        except ValueError:
            continue
        return moment.replace(tzinfo=timezone.utc).isoformat()
    raise CertificateParseError("unsupported time encoding")


def _san_dns_names(extensions: bytes) -> list[str]:
    """dNSName entries of the SAN extension, in the order the certificate lists them."""
    names: list[str] = []
    try:
        entries = _der_children(extensions)
        if len(entries) == 1 and entries[0][0] == 0x30:
            entries = _der_children(entries[0][1])
        for entry in entries:
            if entry[0] != 0x30:
                continue
            fields = _der_children(entry[1])
            if len(fields) < 2 or fields[0][1] != _OID_SUBJECT_ALT_NAME:
                continue
            inner = _der_element(fields[-1][1], 0)
            if inner[0] != 0x30:
                continue
            for name in _der_children(inner[1]):
                if name[0] != _DER_DNS_NAME:
                    continue
                candidate = name[1].decode("ascii", "replace").strip().rstrip(".").lower()[:253]
                if candidate and candidate not in names:
                    names.append(candidate)
    except (CertificateParseError, UnicodeError):
        return names
    return names


def read_certificate(pem: bytes) -> dict[str, Any]:
    """The facts this platform acts on, from one PEM certificate."""
    match = _PEM_BLOCK.search(pem)
    if match is None:
        raise CertificateParseError("no PEM certificate block")
    body = re.sub(rb"\s+", b"", match.group(0).split(b"-----", 3)[2])
    try:
        der = base64.b64decode(body, validate=True)
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        raise CertificateParseError("invalid base64 in PEM block") from exc
    tag, certificate, _, end = _der_element(der, 0)
    if tag != 0x30 or end != len(der):
        raise CertificateParseError("not a DER certificate")
    outer = _der_children(certificate)
    if not outer or outer[0][0] != 0x30:
        raise CertificateParseError("no tbsCertificate")
    tbs = _der_children(outer[0][1])
    # [0] EXPLICIT version is optional and its absence means v1.
    first = 1 if tbs and tbs[0][0] == 0xA0 else 0
    if len(tbs) < first + 6:
        raise CertificateParseError("tbsCertificate is too short")
    validity = _der_children(tbs[first + 3][1])
    if len(validity) < 2:
        raise CertificateParseError("validity carries fewer than two times")
    not_before, not_after = _der_time(validity[0][1]), _der_time(validity[1][1])
    spki = tbs[first + 5]
    extensions_index = first + 6
    san_dns: list[str] = []
    if len(tbs) > extensions_index and tbs[extensions_index][0] == 0xA3:
        san_dns = _san_dns_names(tbs[extensions_index][1])
    return {
        "fingerprint_sha256": hashlib.sha256(der).hexdigest(),
        # A SHA-1 fingerprint is the certificate's identifier as CAs and CT tools
        # print it, not a signature this probe trusts.
        "fingerprint_sha1": hashlib.sha1(der, usedforsecurity=False).hexdigest(),
        "spki_sha256": hashlib.sha256(outer[0][1][spki[2]:spki[3]]).hexdigest(),
        "serial_hex": tbs[first][1].hex(),
        "not_before": not_before,
        "not_after": not_after,
        "san_dns": san_dns,
    }


def read_chain(pem: bytes) -> list[dict[str, Any]]:
    """Every certificate in the chain, leaf first, skipping any unreadable member.

    A chain member this reader cannot parse is dropped rather than failing the
    leaf: the leaf is what the monitor and the alert are about.
    """
    facts: list[dict[str, Any]] = []
    for block in _PEM_BLOCK.findall(pem):
        try:
            facts.append(read_certificate(block))
        except CertificateParseError:
            continue
    return facts


def classify(
    *, exit_code: int | None, verify_result: int | None, facts: dict[str, Any] | None, host: str, now: datetime
) -> tuple[str, str]:
    """`(check_state, verification)` from curl's own verdict, not from our opinion.

    A verification failure is split into the three cases an operator acts on
    differently, using the leaf the handshake still delivered: expired, a name that
    is not this host, or a chain the system store does not trust. Everything else
    that failed leaves `verification` at the transport category, because claiming
    more than curl said is how a monitor starts inventing findings.
    """
    if exit_code == 0:
        return "verified", "verified"
    after = facts.get("not_after") if facts else None
    if after is not None and datetime.fromisoformat(after) <= now:
        return "expired", "expired"
    if exit_code == 60:
        names = list(facts.get("san_dns") or []) if facts else []
        if names and not any(name == host or host.endswith("." + name.lstrip("*.")) or name == "*." + host.split(".", 1)[-1] for name in names):
            return "failed", "name_mismatch"
        return "failed", "untrusted_or_self_signed"
    if verify_result not in (None, 0):
        return "failed", "verification_failed"
    return "failed", {
        6: "name_resolution",
        7: "connection_refused",
        28: "timeout",
        35: "tls_handshake",
        60: "verification_failed",
        90: "pinned_key_mismatch",
        91: "certificate_status",
    }.get(exit_code, "probe_error")


async def run_curl(argv: list[str]) -> tuple[int, bytes, bytes]:
    """Run one bounded command; the process is always reaped, no shell is involved."""
    process = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await process.communicate()
    return process.returncode if process.returncode is not None else 1, stdout, stderr


async def curl_version() -> str | None:
    """`curl --version`'s first line, recorded with every probe.

    The whole design assumes `%{certs}`, which needs curl 7.88. An image built on
    an older curl has to be visible in the stored evidence rather than quietly
    producing certificate-less results.
    """
    try:
        code, stdout, _ = await run_curl(["curl", "--version"])
    except (OSError, NotImplementedError):
        return None
    if code != 0 or not stdout:
        return None
    return stdout.splitlines()[0].decode("utf-8", "replace")[:120] or None


def version_is_sufficient(version_line: str | None) -> bool:
    """Whether a `curl --version` line can produce a certificate chain at all."""
    if not version_line:
        return False
    match = re.search(r"curl (\d+)\.(\d+)", version_line)
    if match is None:
        return False
    return (int(match.group(1)), int(match.group(2))) >= MINIMUM_CURL_FOR_CERTS
