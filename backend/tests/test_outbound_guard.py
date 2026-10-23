"""The destination policy: what the platform refuses to connect to, and why.

Deterministic by construction: name resolution is monkeypatched wherever a
hostname is involved, so these tests describe the *policy* rather than the DNS
of the machine running them. The one real resolution (`ensure_allowed` on an IP
literal) needs no network at all.
"""

from __future__ import annotations

import pytest

from app.core import outbound
from app.core.config import settings
from app.core.outbound import (
    REASON_BLOCKED_NETWORK,
    REASON_EMPTY,
    REASON_INVALID,
    REASON_OWN_NETWORK,
    OutboundBlocked,
    classify_address,
    ensure_allowed,
    validate_domain_target,
    validate_smtp_host,
    validate_telegram_token,
)


class TestWhoisHops:
    """AUD-032: a WHOIS lookup dials two servers, and one of them is chosen by
    whoever answers the first. Both hops pass the same guard the lookup's target
    passed, or the policy does not describe the request that is actually made."""

    @staticmethod
    def _client(monkeypatch, answer: bytes):
        from app.services.phishing import whois_service

        connected: list[tuple[str, int]] = []

        class FakeSocket:
            def __init__(self):
                self.answer = answer

            def settimeout(self, value):
                return None

            def sendall(self, payload):
                return None

            def recv(self, size):
                chunk, self.answer = self.answer, b""
                return chunk

            def close(self):
                return None

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def fake_connection(address, timeout=None):
            connected.append(address)
            if address[0] == "127.0.0.1":
                raise AssertionError("dialled the referral host the guard never saw")
            return FakeSocket()

        monkeypatch.setattr(whois_service.socket, "create_connection", fake_connection)
        return whois_service, connected

    def test_a_referral_to_a_private_address_is_refused_before_it_is_dialled(
        self, monkeypatch
    ):
        whois_service, connected = self._client(
            monkeypatch,
            b"Domain Name: evil.example\nWhois Server: 127.0.0.1\n",
        )

        with pytest.raises(OutboundBlocked) as excinfo:
            whois_service.GuardedNICClient().whois(
                b"evil.example", "whois.registry.invalid", 1
            )

        assert excinfo.value.reason == REASON_BLOCKED_NETWORK
        assert connected == [("whois.registry.invalid", 43)]

    def test_a_public_referral_is_followed_through_the_same_guard(self, monkeypatch):
        whois_service, connected = self._client(
            monkeypatch,
            b"Domain Name: evil.example\nWhois Server: whois.registrar.invalid\n",
        )

        text = whois_service.GuardedNICClient().whois(
            b"evil.example", "whois.registry.invalid", 1
        )

        assert connected == [
            ("whois.registry.invalid", 43),
            ("whois.registrar.invalid", 43),
        ]
        assert "Whois Server: whois.registrar.invalid" in text


class TestClassifyAddress:
    @pytest.mark.parametrize(
        "address",
        [
            "127.0.0.1",
            "127.9.9.9",
            "::1",
            "::ffff:127.0.0.1",  # a v4-mapped loopback address
            "169.254.169.254",  # the cloud metadata endpoint
            "100.100.100.200",  # Alibaba Cloud
            "192.0.0.192",  # Oracle Cloud
            "0.0.0.0",
            "239.1.2.3",
            "fe80::1",
            "ff02::1",
        ],
    )
    def test_never_a_legitimate_destination(self, address):
        assert classify_address(address) == REASON_BLOCKED_NETWORK

    def test_the_deployments_own_networks_are_named_separately(self):
        """The reason an operator sees should say which rule they hit."""
        for address in ("172.18.20.5", "172.18.10.7", "172.18.30.9", "172.18.0.1"):
            assert classify_address(address) == REASON_OWN_NETWORK

    @pytest.mark.parametrize(
        "address",
        ["8.8.8.8", "10.0.0.5", "192.168.5.20", "2001:4860:4860::8888"],
    )
    def test_ordinary_destinations_stay_usable(self, address):
        """Private ranges are not blocked: an internal mail relay lives there."""
        assert classify_address(address) is None

    def test_garbage_is_reported_as_invalid(self):
        assert classify_address("not-an-address") == REASON_INVALID


class TestEnsureAllowed:
    def test_an_ip_literal_is_checked_without_resolving(self):
        assert ensure_allowed("8.8.8.8") == ("8.8.8.8",)

    def test_a_blocked_literal_raises_with_the_offending_address(self):
        with pytest.raises(OutboundBlocked) as excinfo:
            ensure_allowed("169.254.169.254", port=80)
        assert excinfo.value.reason == REASON_BLOCKED_NETWORK
        assert excinfo.value.address == "169.254.169.254"
        assert excinfo.value.as_audit_details() == {
            "host": "169.254.169.254",
            "reason": REASON_BLOCKED_NETWORK,
            "port": 80,
            "address": "169.254.169.254",
        }

    def test_an_empty_host_is_refused(self):
        with pytest.raises(OutboundBlocked) as excinfo:
            ensure_allowed("   ")
        assert excinfo.value.reason == REASON_EMPTY

    def test_a_name_that_does_not_resolve_is_not_a_refusal(self, monkeypatch):
        """Nothing resolved means nothing to reach, so the guard has no verdict.

        Refusing here would report a resolver hiccup — or a test stand-in host,
        or a relay that is briefly missing from split-horizon DNS — as a security
        event and tell the operator to allowlist a host that is fine. The
        connection attempt is what fails, and it names the real problem.
        """
        monkeypatch.setattr(outbound, "resolve_addresses", lambda host: ())
        assert ensure_allowed("nothing-here.invalid") == ("nothing-here.invalid",)

    @pytest.mark.parametrize(
        "value",
        [
            "http://169.254.169.254/latest/meta-data/",
            "user:pass@smtp.example.com",
            "smtp.example.com/path",
            "smtp.example.com?x=1",
            "[::1]",
            "smtp example.com",
        ],
    )
    def test_a_url_shaped_host_is_refused_without_resolving(self, value, monkeypatch):
        """A value that never passed a validate_* call is still not a URL here."""
        def _unexpected(host):  # pragma: no cover - must not be reached
            raise AssertionError("a URL-shaped host must be refused before resolving")

        monkeypatch.setattr(outbound, "resolve_addresses", _unexpected)
        with pytest.raises(OutboundBlocked) as excinfo:
            ensure_allowed(value)
        assert excinfo.value.reason == REASON_INVALID

    def test_an_ipv6_literal_is_not_mistaken_for_a_url(self):
        """The colon in an IPv6 address is not a scheme separator."""
        assert ensure_allowed("2001:4860:4860::8888") == ("2001:4860:4860::8888",)

    def test_every_resolved_address_is_checked(self, monkeypatch):
        """One blocked answer behind a public one is not an acceptable host."""
        monkeypatch.setattr(
            outbound,
            "resolve_addresses",
            lambda host: ("93.184.216.34", "169.254.169.254"),
        )
        with pytest.raises(OutboundBlocked) as excinfo:
            ensure_allowed("relay.example.com")
        assert excinfo.value.address == "169.254.169.254"

    def test_a_hostname_in_the_allowlist_is_accepted(self, monkeypatch):
        monkeypatch.setattr(outbound, "resolve_addresses", lambda host: ("172.18.20.5",))
        monkeypatch.setattr(settings, "OUTBOUND_ALLOWED_HOSTS", "relay.example.com")
        assert ensure_allowed("relay.example.com") == ("172.18.20.5",)
        # Case is not part of the comparison.
        assert ensure_allowed("RELAY.example.com") == ("172.18.20.5",)

    def test_a_cidr_in_the_allowlist_is_accepted(self, monkeypatch):
        monkeypatch.setattr(outbound, "resolve_addresses", lambda host: ("172.18.20.5",))
        monkeypatch.setattr(settings, "OUTBOUND_ALLOWED_HOSTS", "172.18.20.0/24")
        assert ensure_allowed("relay.example.com") == ("172.18.20.5",)

    def test_the_allowlist_does_not_widen_anything_else(self, monkeypatch):
        monkeypatch.setattr(outbound, "resolve_addresses", lambda host: ("10.1.2.3",))
        monkeypatch.setattr(settings, "OUTBOUND_ALLOWED_HOSTS", "172.18.20.0/24")
        # 10.1.2.3 was allowed before the allowlist applied and still is; the
        # point of the assertion is that an unrelated entry changes nothing.
        assert ensure_allowed("relay.example.com") == ("10.1.2.3",)

    def test_extra_blocked_ranges_are_additive(self, monkeypatch):
        monkeypatch.setattr(outbound, "resolve_addresses", lambda host: ("10.1.2.3",))
        monkeypatch.setattr(settings, "OUTBOUND_BLOCKED_CIDRS", "10.1.0.0/16")
        with pytest.raises(OutboundBlocked) as excinfo:
            ensure_allowed("relay.example.com")
        assert excinfo.value.reason == REASON_BLOCKED_NETWORK

    def test_a_malformed_blocked_range_cannot_widen_the_policy(self, monkeypatch):
        monkeypatch.setattr(outbound, "resolve_addresses", lambda host: ("169.254.169.254",))
        monkeypatch.setattr(settings, "OUTBOUND_BLOCKED_CIDRS", "not-a-network")
        with pytest.raises(OutboundBlocked):
            ensure_allowed("relay.example.com")

    def test_a_malformed_allowlist_entry_is_skipped_not_fatal(self, monkeypatch):
        """A typo in the allowlist must not disable it, nor permit anything.

        `10.0.0.0/99` is neither a hostname nor a network. The two outcomes that
        matter: the guard still refuses the metadata endpoint, and a *valid* entry
        beside the broken one still works — an operator who fat-fingers one value
        should not have to take the platform down to notice.
        """
        monkeypatch.setattr(outbound, "resolve_addresses", lambda host: ("169.254.169.254",))
        monkeypatch.setattr(settings, "OUTBOUND_ALLOWED_HOSTS", "10.0.0.0/99")
        with pytest.raises(OutboundBlocked) as excinfo:
            ensure_allowed("relay.example.com")
        assert excinfo.value.reason == REASON_BLOCKED_NETWORK

        monkeypatch.setattr(
            settings, "OUTBOUND_ALLOWED_HOSTS", "10.0.0.0/99,relay.example.com"
        )
        assert ensure_allowed("relay.example.com") == ("169.254.169.254",)

    def test_a_literal_is_classified_even_when_the_resolver_returns_nothing(self, monkeypatch):
        """An IP literal does not need DNS, so a resolver failure is not an answer.

        The no-answer branch returns the candidate for a *name* (the connection
        attempt reports, the guard does not guess). For a literal there is nothing
        to resolve and the address is right there, so skipping classification
        would let a blocked address through exactly when DNS is broken.
        """
        monkeypatch.setattr(outbound, "resolve_addresses", lambda host: ())
        with pytest.raises(OutboundBlocked) as excinfo:
            ensure_allowed("169.254.169.254")
        assert excinfo.value.address == "169.254.169.254"


class TestTelegramToken:
    def test_a_token_shaped_like_telegram_issues_is_accepted(self):
        token = "123456789:" + "A" * 35
        assert validate_telegram_token(token) == token

    @pytest.mark.parametrize("value", ["tok", "123456789", "123456789:A", "a" * 200])
    def test_a_value_that_is_merely_odd_is_accepted(self, value):
        """The token goes into a *path*, under a host this module owns.

        Refusing a value that does not match the documented `NNNN:XXXX` shape
        would reject a token Telegram has not issued yet, and one restored from a
        backup written before the schema grew the check. The shape rule belongs
        in the settings schema, on what an operator writes; this one guards what
        is about to be used.
        """
        assert validate_telegram_token(value) == value

    def test_surrounding_whitespace_is_trimmed_rather_than_refused(self):
        assert validate_telegram_token("  tok  ") == "tok"

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "   ",
            "123456789:" + "A" * 35 + "@evil.example/x",  # a URL, not a token
            "123456789:@evil.example/x",
            "1:AAAAAAAAAAAAAAAAAAAAAAAAAAAA/../x",
            "123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA?x=y",
            "tok#fragment",
            "tok\\backslash",
            "tok with spaces",
            "tok\nheader-showing",
            "a" * 257,
        ],
    )
    def test_anything_that_could_break_out_of_the_path_is_refused(self, value):
        with pytest.raises(ValueError):
            validate_telegram_token(value)


class TestPinnedSmtpSocket:
    """The socket the platform actually opens, once the host was approved.

    `pinned_smtp_class` is what keeps a resolved-and-checked address from being
    re-resolved by the SMTP library (the DNS-rebinding window). The branches here
    are the ones that only run when a connection goes wrong, which is also when a
    leaked descriptor would be least visible.
    """

    class _Ctx:
        def __init__(self, failure=None):
            self.failure = failure

        def wrap_socket(self, sock, server_hostname=None):
            if self.failure is not None:
                raise self.failure
            return f"tls:{sock}"

    class _Base:
        source_address = None

        def __init__(self, failure=None):
            self.context = TestPinnedSmtpSocket._Ctx(failure)

    def test_a_failed_tls_handshake_closes_the_raw_socket(self, monkeypatch):
        closed: list[bool] = []

        class _Socket:
            def close(self):
                closed.append(True)

        monkeypatch.setattr(
            outbound.socket,
            "create_connection",
            lambda target, timeout, source: _Socket(),
        )
        pinned = outbound.pinned_smtp_class(
            self._Base, ("93.184.216.34",), implicit_tls=True
        )

        connection = pinned(RuntimeError("handshake failed"))
        with pytest.raises(RuntimeError, match="handshake failed"):
            connection._get_socket("relay.example.com", 587, 5)

        # The half-open connection is the leak: the caller only sees the handshake
        # exception, so the socket has to be closed before it is re-raised.
        assert closed == [True]

    def test_the_next_validated_address_is_tried_after_a_connect_failure(self, monkeypatch):
        attempts: list[str] = []

        def _connect(target, timeout, source):
            address, port = target
            attempts.append(f"{address}:{port}")
            if address == "93.184.216.34":
                raise OSError("no route to host")
            return f"socket:{address}:{timeout}"

        monkeypatch.setattr(outbound.socket, "create_connection", _connect)
        pinned = outbound.pinned_smtp_class(
            self._Base, ("93.184.216.34", "198.51.100.7")
        )

        assert pinned()._get_socket("relay.example.com", 25, 7) == (
            "socket:198.51.100.7:7"
        )
        assert attempts == ["93.184.216.34:25", "198.51.100.7:25"]

    def test_every_address_failing_reports_the_last_connection_error(self, monkeypatch):
        def _connect(target, timeout, source):
            raise OSError(f"cannot reach {target[0]}")

        monkeypatch.setattr(outbound.socket, "create_connection", _connect)
        pinned = outbound.pinned_smtp_class(
            self._Base, ("93.184.216.34", "198.51.100.7")
        )

        # The last error names a real address the operator can test, unlike a
        # generic "no validated address" that hides which one was refused.
        with pytest.raises(OSError, match="cannot reach 198.51.100.7"):
            pinned()._get_socket("relay.example.com", 25, 5)


class TestSmtpHost:
    @pytest.mark.parametrize(
        "value",
        ["smtp.example.com", "10.0.0.5", "mail", "relay.internal.example."],
    )
    def test_hostnames_and_literals_are_accepted(self, value):
        assert validate_smtp_host(value) == value.rstrip(".")

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "   ",
            "smtp://user:pass@smtp.example.com:25",
            "smtp.example.com:25",
            "smtp.example.com/path",
            "user@smtp.example.com",
            "http://169.254.169.254/latest/meta-data/",
            "-bad.example.com",
            "smtp..example.com",
        ],
    )
    def test_a_url_or_anything_with_a_separator_is_refused(self, value):
        with pytest.raises(ValueError):
            validate_smtp_host(value)

    def test_a_host_longer_than_the_dns_limit_is_refused(self):
        """253 characters is the DNS name limit; anything longer is a payload.

        It would be refused by the resolver anyway, but as a lookup failure that
        reads like a network problem rather than a stored value that is wrong.
        """
        with pytest.raises(ValueError, match="longer than 253"):
            validate_smtp_host("a" * 254)

        # The longest legal name still passes, so the bound is not off by one:
        # four labels of at most 63 characters, separated by dots, at 253 total.
        longest = ".".join(["a" * 63] * 3 + ["a" * 61])
        assert len(longest) == 253
        assert validate_smtp_host(longest) == longest


class TestDomainTarget:
    def test_a_public_name_is_accepted(self):
        assert validate_domain_target("Example.com.") == "Example.com"

    def test_an_ip_literal_is_accepted(self):
        assert validate_domain_target("93.184.216.34") == "93.184.216.34"

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "localhost",  # a single label: not something a finding should reach
            "postgres",
            "http://example.com",
            "example.com/../../etc/passwd",
            "example.com:43",
            "exa mple.com",
        ],
    )
    def test_a_name_that_is_not_a_domain_is_refused(self, value):
        with pytest.raises(ValueError):
            validate_domain_target(value)
