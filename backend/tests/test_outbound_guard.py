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
