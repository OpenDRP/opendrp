"""The active TLS probe: its certificate reader, its classifier and its rows.

Two things are pinned here that nothing else would see.

The reader is ours, and it is deliberately not `cryptography`: that dependency
cannot be added to this image's hash-pinned lock (`scripts/lock_requirements.py`
refuses a connector requirements file that does not pin `greenlet`), so the DER
walker in `tls_probe.py` is compared value by value against `cryptography`, which
the backend already trusts, on real generated certificates. A reader that drifts
from the reference implementation is a monitor that reports the wrong expiry.

The rows are the wire contract. `app.schemas.connector.DNSObservationPayload` is
the boundary that accepts or refuses them, so the probe's control and evidence rows
are validated against it here rather than discovered to be malformed in production;
the import is skipped only where the backend package is absent, which is not the CI
job that runs this suite.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import main
import tls_probe
from main import TLSProbeConnector
from test_dns_security import make_connector


def make_certificate(
    *,
    common_name: str = "www.example.com",
    sans: tuple[str, ...] = ("www.example.com", "example.com"),
    serial: int = 0x1234,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
):
    """A real, self-signed certificate: the reader is checked against the library."""
    now = datetime.now(timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before or now - timedelta(days=1))
        .not_valid_after(not_after or now + timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(value) for value in sans]), critical=False
        )
        .sign(key, hashes.SHA256())
    )


def pem_of(certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.PEM)


def marker_output(exit_code: int, verify_result: int, num_certs: int, pem: bytes) -> bytes:
    return b"\n" + tls_probe.MARKER.encode() + f"{exit_code}|{verify_result}|{num_certs}|TLSv1.3\n".encode() + pem


def test_the_reader_agrees_with_cryptography_on_a_real_certificate():
    certificate = make_certificate()
    facts = tls_probe.read_certificate(pem_of(certificate))
    assert facts["fingerprint_sha256"] == certificate.fingerprint(hashes.SHA256()).hex()
    # SHA-1 here is the identifier the probe reports, compared against the
    # canonical fingerprint of the same DER; it is not a signature check.
    assert facts["fingerprint_sha1"] == certificate.fingerprint(hashes.SHA1()).hex()  # nosec B303
    assert facts["serial_hex"] == format(certificate.serial_number, "x")
    assert facts["not_before"] == certificate.not_valid_before_utc.isoformat()
    assert facts["not_after"] == certificate.not_valid_after_utc.isoformat()
    assert facts["san_dns"] == ["www.example.com", "example.com"]
    assert facts["spki_sha256"] == hashlib.sha256(
        certificate.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).hexdigest()


def test_an_unreadable_member_is_dropped_and_a_broken_leaf_is_an_error():
    """A chain member we cannot read is not a chain we may call empty."""
    good = pem_of(make_certificate())
    chain = good + b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
    assert len(tls_probe.read_chain(chain)) == 1
    with pytest.raises(tls_probe.CertificateParseError):
        tls_probe.read_certificate(chain[len(good) :])
    with pytest.raises(tls_probe.CertificateParseError):
        tls_probe.read_certificate(good[: len(good) // 2])


def test_a_certificate_without_a_san_extension_still_reads():
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "plain.example.com")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(7)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    facts = tls_probe.read_certificate(pem_of(certificate))
    assert facts["san_dns"] == []
    assert facts["fingerprint_sha256"] == certificate.fingerprint(hashes.SHA256()).hex()


def facts(not_after: datetime | None, sans: list[str] | None) -> dict:
    return {
        "not_after": not_after.isoformat() if not_after else None,
        "san_dns": sans or [],
    }


@pytest.mark.parametrize(
    "exit_code,verify_result,leaf,expected",
    [
        (0, 0, facts(datetime.now(timezone.utc) + timedelta(days=30), ["www.example.com"]), ("verified", "verified")),
        (60, 0, facts(datetime.now(timezone.utc) - timedelta(days=1), ["www.example.com"]), ("expired", "expired")),
        (60, 0, facts(datetime.now(timezone.utc) + timedelta(days=30), ["other.example"]), ("failed", "name_mismatch")),
        (60, 0, facts(datetime.now(timezone.utc) + timedelta(days=30), ["www.example.com"]), ("failed", "untrusted_or_self_signed")),
        (60, 0, facts(datetime.now(timezone.utc) + timedelta(days=30), []), ("failed", "untrusted_or_self_signed")),
        (60, 0, None, ("failed", "untrusted_or_self_signed")),
        (7, None, None, ("failed", "connection_refused")),
        (28, None, None, ("failed", "timeout")),
        (35, None, None, ("failed", "tls_handshake")),
        (91, None, None, ("failed", "certificate_status")),
        (99, None, None, ("failed", "probe_error")),
    ],
)
def test_the_verdict_comes_from_curls_own_exit_code(exit_code, verify_result, leaf, expected):
    assert tls_probe.classify(
        exit_code=exit_code, verify_result=verify_result, facts=leaf,
        host="www.example.com", now=datetime.now(timezone.utc),
    ) == expected


def test_a_subdomain_of_a_listed_name_is_a_name_mismatch_not_an_untrusted_chain():
    # A certificate for example.com does not cover evil.example.com, and a wildcard
    # covers one label only. curl refused both; the label must say why.
    now = datetime.now(timezone.utc)
    valid = now + timedelta(days=30)
    assert tls_probe.classify(
        exit_code=60, verify_result=0, facts=facts(valid, ["example.com"]),
        host="evil.example.com", now=now,
    ) == ("failed", "name_mismatch")
    assert tls_probe.classify(
        exit_code=60, verify_result=0, facts=facts(valid, ["*.example.com"]),
        host="a.b.example.com", now=now,
    ) == ("failed", "name_mismatch")
    assert tls_probe.classify(
        exit_code=60, verify_result=0, facts=facts(valid, ["*.example.com"]),
        host="a.example.com", now=now,
    ) == ("failed", "untrusted_or_self_signed")


def test_curl_output_splits_its_verdict_from_the_chain():
    certificate = make_certificate()
    parsed = tls_probe.parse_output(marker_output(0, 0, 1, pem_of(certificate)))
    assert (parsed["exit"], parsed["verify_result"], parsed["num_certs"], parsed["tls_version"]) == (0, 0, 1, "TLSv1.3")
    assert tls_probe.read_chain(parsed["chain"])[0]["fingerprint_sha256"] == certificate.fingerprint(hashes.SHA256()).hex()
    # A curl that never got to write its `-w` string (missing binary, killed) is not
    # a host without a certificate.
    assert tls_probe.parse_output(b"curl: (7) Failed to connect") == {
        "exit": None, "verify_result": None, "num_certs": None, "tls_version": None, "chain": b"",
    }


def test_ports_path_and_argv_are_bounded():
    assert tls_probe.parse_ports("") == ([443], [])
    assert tls_probe.parse_ports("443,8443") == ([443, 8443], [])
    # A non-numeric port, an out-of-range one and a repeat all report the same
    # code: the list stays an allowlist instead of growing duplicates silently.
    assert tls_probe.parse_ports("8443,not-a-port,0,8443") == ([8443], ["invalid_tls_port"] * 3)
    assert tls_probe.parse_ports("1,2,3,4") == ([], ["too_many_tls_ports"])
    assert tls_probe.parse_path("no-slash") == ("/", ["invalid_tls_path"])
    assert tls_probe.parse_path("/health") == ("/health", [])

    argv = tls_probe.build_argv("www.example.com", "203.0.113.9", 443, "/")
    assert argv[argv.index("--resolve") + 1] == "www.example.com:443:203.0.113.9"
    assert not {"-k", "--insecure"} & set(argv), "the authoritative pass never disables verification"
    assert argv[argv.index("-q") + 1] == "-sS", "-q must come first so a .curlrc cannot change the call"
    ipv6 = tls_probe.build_argv("www.example.com", "2001:db8::1", 443, "/")
    assert ipv6[ipv6.index("--resolve") + 1] == "www.example.com:443:[2001:db8::1]"

    assert tls_probe.version_is_sufficient("curl 8.5.0 (x86_64-pc-linux-gnu)")
    assert not tls_probe.version_is_sufficient("curl 7.81.0 (x86_64-pc-linux-gnu)")
    assert not tls_probe.version_is_sufficient(None)


@pytest.mark.asyncio
async def test_the_worker_records_the_served_certificate_and_its_chain(monkeypatch):
    certificate = make_certificate()
    pem = pem_of(certificate)

    async def fake_run_curl(argv):
        assert argv[0] == "curl"
        return 0, marker_output(0, 0, 1, pem), b""

    async def fake_version():
        return "curl 8.5.0 (x86_64-pc-linux-gnu)"

    monkeypatch.setattr(main, "run_curl", fake_run_curl)
    monkeypatch.setattr(main, "curl_version", fake_version)
    monkeypatch.setattr(main, "resolve_public_ips", lambda host: ("203.0.113.9",))
    connector = make_connector(TLSProbeConnector)
    rows = await connector._run_tlsprobe(["www.example.com"])

    control, evidence = rows
    assert control["observation_type"] == "tls_probe"
    assert control["record_type"] == "TLS" and control["subject"] == "www.example.com"
    assert control["metadata"]["check_state"] == "verified"
    assert control["metadata"]["probe_ip"] == "203.0.113.9"
    assert control["metadata"]["evidence"] == "active_tls_probe"
    assert control["expires_at"] == certificate.not_valid_after_utc.isoformat()
    assert evidence["observation_type"] == "tls_certificate"
    assert evidence["metadata"]["id"] == certificate.fingerprint(hashes.SHA256()).hex()
    assert evidence["metadata"]["chain_fingerprints"] == [evidence["metadata"]["id"]]
    assert evidence["metadata"]["san_dns"] == ["www.example.com", "example.com"]
    assert connector._errors == []


@pytest.mark.asyncio
async def test_a_second_port_gets_its_own_control_row(monkeypatch):
    """The port is part of the storage identity, or 8443 would overwrite 443."""
    certificate = make_certificate()
    pem = pem_of(certificate)

    async def fake_run_curl(argv):
        return 0, marker_output(0, 0, 1, pem), b""

    async def fake_version():
        return "curl 8.5.0"

    monkeypatch.setattr(main, "run_curl", fake_run_curl)
    monkeypatch.setattr(main, "curl_version", fake_version)
    monkeypatch.setattr(main, "resolve_public_ips", lambda host: ("203.0.113.9",))
    connector = make_connector(TLSProbeConnector, {"DNS_SECURITY_TLS_PORTS": "443,8443"})
    rows = await connector._run_tlsprobe(["www.example.com"])
    record_types = [row["record_type"] for row in rows if row["observation_type"] == "tls_probe"]
    assert record_types == ["TLS", "TLS:8443"]


@pytest.mark.asyncio
async def test_a_non_public_host_is_reported_rather_than_skipped(monkeypatch):
    async def fake_version():
        return "curl 8.5.0"

    monkeypatch.setattr(main, "curl_version", fake_version)
    monkeypatch.setattr(main, "resolve_public_ips", lambda host: ())
    connector = make_connector(TLSProbeConnector)
    rows = await connector._run_tlsprobe(["internal.example.com"])
    assert [row["metadata"]["check_state"] for row in rows] == ["skipped_no_public_address"]
    assert rows[0]["observation_type"] == "tls_probe"
    assert connector._errors == []


@pytest.mark.asyncio
async def test_a_curl_too_old_for_certs_probes_nothing(monkeypatch):
    async def fake_version():
        return "curl 7.81.0 (x86_64-pc-linux-gnu)"

    monkeypatch.setattr(main, "curl_version", fake_version)
    monkeypatch.setattr(main, "resolve_public_ips", lambda host: ("203.0.113.9",))
    connector = make_connector(TLSProbeConnector)
    assert await connector._run_tlsprobe(["www.example.com"]) == []
    assert connector._errors == ["curl_certs_unsupported"]


@pytest.mark.asyncio
async def test_the_probe_budget_bounds_the_handshakes(monkeypatch):
    certificate = make_certificate()
    pem = pem_of(certificate)
    seen: list[str] = []

    async def fake_run_curl(argv):
        seen.append(argv[argv.index("--resolve") + 1])
        return 0, marker_output(0, 0, 1, pem), b""

    async def fake_version():
        return "curl 8.5.0"

    monkeypatch.setattr(main, "run_curl", fake_run_curl)
    monkeypatch.setattr(main, "curl_version", fake_version)
    monkeypatch.setattr(main, "resolve_public_ips", lambda host: (f"203.0.113.{len(seen) + 1}",))
    connector = make_connector(TLSProbeConnector, {"DNS_SECURITY_TLS_MAX_PROBES": "2"})
    rows = await connector._run_tlsprobe(["a.example.com", "b.example.com", "c.example.com"])
    assert len(seen) == 2
    assert "probe_budget_reached" in connector._errors
    assert len([row for row in rows if row["observation_type"] == "tls_probe"]) == 2


@pytest.mark.asyncio
async def test_every_probe_row_passes_the_core_wire_schema():
    """The rows are validated where they will be accepted or refused: the boundary."""
    schema = pytest.importorskip("app.schemas.connector")
    certificate = make_certificate()
    pem = pem_of(certificate)

    async def fake_run_curl(argv):
        return 0, marker_output(0, 0, 1, pem), b""

    async def fake_version():
        return "curl 8.5.0"

    original_run, original_version, original_resolve = main.run_curl, main.curl_version, main.resolve_public_ips
    main.run_curl, main.curl_version = fake_run_curl, fake_version
    main.resolve_public_ips = lambda host: ("203.0.113.9",)
    try:
        connector = make_connector(TLSProbeConnector, {"DNS_SECURITY_TLS_PORTS": "443,8443"})
        rows = await connector._run_tlsprobe(["www.example.com"])
    finally:
        main.run_curl, main.curl_version, main.resolve_public_ips = original_run, original_version, original_resolve
    assert len(rows) == 4
    for row in rows:
        schema.DNSObservationPayload(**row)
