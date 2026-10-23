"""The branches in ``app/api/deps.py`` that decide an identity and an address.

Coverage batch 01 starts here because this module is where two of the platform's
security facts are produced: *who the caller is* (and what they owe before the rest
of the platform opens) and *which address an action is attributed to*. The suite in
`test_security_boundaries.py` already pins the happy path of both; what it leaves
unexecuted is the shape a deployment actually meets on a bad day:

* a forwarded header carrying a port, a bracketed IPv6 address, or something that
  is not an address at all;
* a ``TRUSTED_PROXY_IPS`` value with a typo in it;
* a peer whose address cannot be read, because the socket is already gone;
* an audit write that fails while a refusal is being recorded;
* the deployment-wide second-factor policy refusing an administrator.

Each test names the behaviour rather than the line: the address recorded must be
one the platform can defend, and a refusal must not become a 500 because the trail
could not be written.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.api import deps
from app.core.config import settings
from app.core.exceptions import ForbiddenException


def _request(host: str | None, headers: dict[str, str] | None = None) -> MagicMock:
    request = MagicMock()
    if host is None:
        request.client = None
    else:
        request.client.host = host
    request.headers.get.side_effect = (headers or {}).get
    request.url.path = "/api/v1/assets"
    request.method = "GET"
    request.path_params = {}
    return request


class TestForwardedAddressParsing:
    """``_normalize_ip`` is the only place a header value becomes an address."""

    @pytest.mark.parametrize(
        ("header_value", "expected"),
        [
            ('"198.51.100.7"', "198.51.100.7"),
            ("  198.51.100.7  ", "198.51.100.7"),
            ("198.51.100.7:41234", "198.51.100.7"),
            ("[2001:db8::1]:8443", "2001:db8::1"),
            ("2001:db8::1", "2001:db8::1"),
            # An unterminated bracket is tolerated: what remains is still a
            # complete address, and the property this function exists for is that
            # it never records a fragment of one.
            ("[2001:db8::1", "2001:db8::1"),
        ],
    )
    def test_the_forms_a_proxy_writes_are_understood(self, header_value, expected):
        assert deps._normalize_ip(header_value) == expected

    @pytest.mark.parametrize(
        "header_value",
        [
            "",
            "   ",
            "not-an-ip",
            "[not-an-ip]:443",
            "198.51.100.7:https",
            "example.com:443",
            "[]:443",
        ],
    )
    def test_anything_else_is_refused_rather_than_recorded(self, header_value):
        """A malformed hop is skipped, so the audit row never carries a fragment."""
        assert deps._normalize_ip(header_value) is None


class TestTrustedProxyConfiguration:
    def test_unparsable_entries_are_skipped_not_fatal(self, monkeypatch):
        """A typo in ``TRUSTED_PROXY_IPS`` must not stop the API from answering.

        The list is operator input read on every request. One bad entry used to be
        indistinguishable from "no proxies trusted" in review; here the valid
        entries still apply, so the edge is still believed.
        """
        monkeypatch.setattr(
            settings,
            "TRUSTED_PROXY_IPS",
            " ,127.0.0.1, not-a-network, 10.0.0.0/33, ::1 ",
        )
        request = _request("127.0.0.1", {"x-forwarded-for": "203.0.113.9"})
        assert deps.extract_ip(request) == "203.0.113.9"

    def test_a_settings_failure_leaves_forwarded_headers_untrusted(self, monkeypatch):
        """If the policy cannot be read, believe the socket and nothing else."""

        class _BrokenSettings:
            @property
            def TRUSTED_PROXY_IPS(self):
                raise RuntimeError("configuration unavailable")

        monkeypatch.setattr("app.core.config.settings", _BrokenSettings())
        request = _request("127.0.0.1", {"x-forwarded-for": "203.0.113.9"})
        assert deps.extract_ip(request) == "127.0.0.1"

    def test_a_peer_that_is_not_an_address_is_not_a_trusted_proxy(self, monkeypatch):
        monkeypatch.setattr(settings, "TRUSTED_PROXY_IPS", "127.0.0.1")
        request = _request("localhost", {"x-forwarded-for": "203.0.113.9"})
        assert deps.extract_ip(request) == "localhost"

    def test_a_request_without_a_peer_is_unknown(self):
        assert deps.extract_ip(_request(None)) == "unknown"

    def test_a_peer_whose_address_raises_is_unknown(self):
        """The socket may be closed between the request and the audit write."""

        class _NoPeer:
            @property
            def client(self):
                raise RuntimeError("peer already disconnected")

            headers: dict[str, str] = {}

            url = MagicMock(path="/api/v1/assets")

        assert deps.extract_ip(_NoPeer()) == "unknown"


class TestDependencyRefusals:
    @pytest.mark.asyncio
    async def test_an_undecodable_token_is_refused_before_any_database_work(self):
        """A forged or expired token costs a signature check, not a query."""
        db = AsyncMock()
        with patch.object(deps, "decode_token", return_value=None):
            with pytest.raises(Exception) as exc_info:
                await deps.get_current_user(
                    request=_request("198.51.100.7"), token="forged", db=db
                )

        assert exc_info.value.detail == "Could not validate credentials"
        db.execute.assert_not_awaited()

    def test_a_refusal_without_a_named_target_records_none(self):
        """``authz.denied`` says which object was aimed at, when the route has one."""
        request = _request("198.51.100.7")
        request.path_params = {"unrelated": "x"}
        assert deps._denied_target(request) is None


class TestPolicyFactorAudit:
    @pytest.mark.asyncio
    async def test_a_failed_audit_write_does_not_replace_the_refusal(self):
        """Best effort by design: the request is refused, not turned into a 500."""
        request = _request("198.51.100.7")
        user = MagicMock(id=uuid.uuid4(), role="admin")

        with patch.object(
            deps.AuditLogger, "emit", new=AsyncMock(side_effect=RuntimeError("db down"))
        ):
            await deps._audit_missing_policy_factor(request, user, AsyncMock())

    @pytest.mark.asyncio
    async def test_the_policy_refusal_is_audited_and_says_which_step_is_owed(
        self, monkeypatch
    ):
        monkeypatch.setattr(settings, "REQUIRE_MFA_ROLES", "")
        monkeypatch.setattr(settings, "REQUIRE_MFA_FOR_ADMINS", True)
        user = MagicMock(id=uuid.uuid4(), role="admin", totp_enabled_at=None)

        with patch.object(deps.AuditLogger, "emit", new=AsyncMock()) as emit:
            with pytest.raises(ForbiddenException) as exc_info:
                await deps.require_admin(_request("198.51.100.7"), user, AsyncMock())

        assert "mfa_required" in exc_info.value.detail
        emit.assert_awaited_once()
        action = emit.await_args.kwargs["action"]
        assert action == "auth.mfa.required"
        assert emit.await_args.kwargs["details"]["role"] == "admin"
