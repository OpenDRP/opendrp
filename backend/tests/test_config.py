import pytest
from pydantic import ValidationError

from app.core.config import Settings, _parse_cors_origins

pytestmark = pytest.mark.usefixtures("without_testing_switch")

#: A production configuration that passes every other production check, so that
#: the tests below fail only for the reason each one is about.
_PRODUCTION = {
    "APP_ENV": "production",
    "OPENDRP_VERSION": "0.2.0",
    "JWT_SECRET_KEY": "j" * 48,
    "ENCRYPTION_KEY": "Zm9yLXRlc3Qtb25seS1mZXJuZXQta2V5LXZhbHVlLXBhZGRlZA==",
    "AUTH_COOKIE_SECURE": True,
    "TRUSTED_PROXY_IPS": "127.0.0.1,::1",
    # Pinned rather than inherited: the production validator refuses a broker URL
    # without a password unless its host is loopback, so a fixture that let the
    # environment decide would pass in CI (`REDIS_URL=redis://127.0.0.1:6379/0`)
    # and fail on a host whose value is `redis://redis:6379/0` — for a reason
    # unrelated to what these tests assert.
    "REDIS_URL": "redis://127.0.0.1:6379/0",
    "DATABASE_URL": "postgresql://opendrp:not-a-placeholder@postgres:5432/opendrp",
    # The audit chain key is required in production on purpose (see the validator):
    # a key derived from ENCRYPTION_KEY would change under a rotation and make
    # every existing entry look tampered with.
    "AUDIT_CHAIN_KEYS": "chain-key-for-tests-only-" * 3,
}


def _production(**overrides) -> Settings:
    return Settings(**{**_PRODUCTION, **overrides})  # type: ignore[arg-type]


def test_production_requires_a_pinned_release_version():
    with pytest.raises(ValidationError, match="OPENDRP_VERSION"):
        _production(OPENDRP_VERSION="latest")


def test_production_accepts_a_pinned_release_version():
    assert _production(OPENDRP_VERSION="0.2.0").OPENDRP_VERSION == "0.2.0"


class TestTestingFlag:
    """`TESTING` is a test-suite switch, not a way to deploy without controls.

    The flag turns scan admission fail-open and makes the rate limiter act as if
    Redis were unreachable, which removes the login lockout. A test `.env` copied
    into a deployment, or a debugging export inherited from a shell, would remove
    both without a word; the production validator is where that has to be refused.
    """

    def test_the_testing_switch_is_refused_in_production(self, monkeypatch):
        monkeypatch.setenv("TESTING", "1")
        with pytest.raises(ValidationError, match="TESTING"):
            _production()

    @pytest.mark.parametrize("value", ["0", "false", "False", "no", "off", ""])
    def test_an_explicit_off_value_is_accepted(self, monkeypatch, value):
        """`TESTING=0` is the documented way to keep a shared environment file."""
        monkeypatch.setenv("TESTING", value)
        assert _production().APP_ENV == "production"

    def test_development_may_still_use_the_testing_switch(self, monkeypatch):
        """The suite and a developer's shell are the two places it belongs."""
        monkeypatch.setenv("TESTING", "1")
        assert Settings(APP_ENV="development").APP_ENV == "development"  # type: ignore[call-arg]





class TestParseCorsOrigins:
    def test_none_returns_localhost_default(self):
        assert _parse_cors_origins(None) == ["http://localhost:3000"]

    def test_empty_string_returns_default(self):
        assert _parse_cors_origins("") == ["http://localhost:3000"]
        assert _parse_cors_origins("   ") == ["http://localhost:3000"]

    def test_comma_separated_string(self):
        r = _parse_cors_origins("http://a.local , http://b.local,")
        assert r == ["http://a.local", "http://b.local"]

    def test_json_array_string(self):
        import json
        data = ["https://app.example.com", "http://localhost:5173"]
        result = _parse_cors_origins(json.dumps(data))
        assert result == data

    def test_list_passthrough_stripped(self):
        r = _parse_cors_origins([" http://one.local", " ", "http://two.local "])
        assert r == ["http://one.local", "http://two.local"]

    def test_tuple_works_like_list(self):
        r = _parse_cors_origins(("http://a", "http://b"))
        assert r == ["http://a", "http://b"]


class TestDatabaseURLAsyncPG:
    def test_asyncpg_suffix_postgresql(self):
        from app.core.config import Settings
        s = Settings(DATABASE_URL="postgresql://user:p@h:5432/db")  # type: ignore[call-arg]
        assert s.DATABASE_URL_ASYNCPG.startswith("postgresql+asyncpg://")

    def test_asyncpg_suffix_postgres_shorthand(self):
        from app.core.config import Settings
        s = Settings(DATABASE_URL="postgres://u:p@h/db")  # type: ignore[call-arg]
        assert s.DATABASE_URL_ASYNCPG.startswith("postgresql+asyncpg://")

    def test_unknown_scheme_passthrough(self):
        s = Settings(DATABASE_URL="sqlite+aiosqlite:///./file.db")  # type: ignore[call-arg]
        assert s.DATABASE_URL_ASYNCPG == "sqlite+aiosqlite:///./file.db"


class TestNetworkRangeConsistency:
    """The network subnets must stay inside the range nginx is trusted from.

    These are checked in every environment on purpose. A subnet moved out of the
    parent range is not an error the platform notices at runtime: it starts, it
    serves, and every audit row quietly records the proxy container's address
    instead of the client's — which is only discovered by someone trying to
    answer "who deleted this asset".
    """

    def test_shipped_defaults_are_consistent(self):
        s = Settings()  # type: ignore[call-arg]
        assert len(s.deployment_networks) == 4

    def test_subnet_outside_the_parent_is_rejected(self):
        with pytest.raises(ValidationError):
            Settings(OPENDRP_NETWORK_SUBNET="10.99.0.0/16")  # type: ignore[call-arg]

    def test_moving_every_range_together_is_accepted(self):
        s = Settings(  # type: ignore[call-arg]
            OPENDRP_NETWORK_SUBNET="10.99.0.0/16",
            OPENDRP_EDGE_SUBNET="10.99.10.0/24",
            OPENDRP_DATA_SUBNET="10.99.20.0/24",
            OPENDRP_CONNECTOR_SUBNET="10.99.30.0/24",
        )
        assert len(s.deployment_networks) == 4

    def test_unparsable_subnet_is_rejected(self):
        with pytest.raises(ValidationError):
            Settings(OPENDRP_CONNECTOR_SUBNET="not-a-network")  # type: ignore[call-arg]

    def test_spelling_a_single_host_is_accepted(self):
        """A /32 network is a legitimate way to pin one address."""
        s = Settings(  # type: ignore[call-arg]
            OPENDRP_EDGE_SUBNET="172.18.10.5/32",
        )
        assert len(s.deployment_networks) == 4


class TestTrustedProxyRange:
    """Only the edge may be trusted, never the deployment's own address space.

    A trusted network is one whose `X-Forwarded-For` entries are believed, so the
    value decides whose claims about a client address reach the audit chain. The
    range that used to be named here was the parent — which contains the
    connector network, and connectors are the one part of the deployment this
    platform did not write. A compromised connector could then record its own
    actions against any address it chose, and nothing at runtime complains: the
    forge is a well-formed audit row.
    """

    def test_the_parent_range_is_rejected(self):
        with pytest.raises(ValidationError, match="audit trail"):
            Settings(TRUSTED_PROXY_IPS="127.0.0.1,::1,172.18.0.0/16")  # type: ignore[call-arg]

    @pytest.mark.parametrize(
        "entry",
        [
            "172.18.20.0/24",  # the data network
            "172.18.30.0/24",  # the connector network
            "172.18.30.7/32",  # one connector container
        ],
    )
    def test_a_network_whose_containers_must_not_be_believed_is_rejected(self, entry):
        with pytest.raises(ValidationError, match="audit trail"):
            Settings(TRUSTED_PROXY_IPS=f"127.0.0.1,{entry}")  # type: ignore[call-arg]

    def test_a_wider_range_that_contains_the_networks_is_rejected(self):
        """Containment counts both ways: this is the parent range by another name."""
        with pytest.raises(ValidationError, match="audit trail"):
            Settings(TRUSTED_PROXY_IPS="172.16.0.0/12")  # type: ignore[call-arg]

    def test_loopback_and_the_edge_subnet_are_accepted(self):
        """The shipped shape: nginx reaches the API from the edge network."""
        s = Settings(TRUSTED_PROXY_IPS="127.0.0.1,::1,172.18.10.0/24")  # type: ignore[call-arg]

        assert s.TRUSTED_PROXY_IPS.endswith("172.18.10.0/24")

    def test_an_ipv6_entry_beside_the_ipv4_networks_is_accepted(self):
        """Different address families do not overlap, and must not raise."""
        s = Settings(TRUSTED_PROXY_IPS="::1,fe80::/10")  # type: ignore[call-arg]

        assert s.TRUSTED_PROXY_IPS == "::1,fe80::/10"

    def test_a_deployment_that_moved_its_ranges_trusts_its_own_edge(self):
        s = Settings(  # type: ignore[call-arg]
            OPENDRP_NETWORK_SUBNET="10.99.0.0/16",
            OPENDRP_EDGE_SUBNET="10.99.10.0/24",
            OPENDRP_DATA_SUBNET="10.99.20.0/24",
            OPENDRP_CONNECTOR_SUBNET="10.99.30.0/24",
            TRUSTED_PROXY_IPS="127.0.0.1,10.99.10.0/24",
        )

        assert s.TRUSTED_PROXY_IPS.endswith("10.99.10.0/24")


class TestProductionBrokerCredential:
    """Production must not reach a remote Redis without a password.

    Compose requires the value by interpolation, which covers the documented
    deployment; this covers the one that is not run through Compose — and it is
    the one where a passwordless broker is easiest to leave behind.
    """

    def test_remote_broker_without_a_password_is_rejected(self):
        with pytest.raises(ValidationError):
            _production(REDIS_URL="redis://redis:6379/0")

    def test_empty_password_is_not_a_password(self):
        with pytest.raises(ValidationError):
            _production(REDIS_URL="redis://:@redis:6379/0")

    def test_password_in_the_url_is_accepted(self):
        s = _production(REDIS_URL="redis://:generated-password@redis:6379/0")
        assert s.REDIS_URL.endswith("@redis:6379/0")

    def test_loopback_broker_without_a_password_is_allowed(self):
        """A local-only broker is not reachable by anything that matters."""
        s = _production(REDIS_URL="redis://127.0.0.1:6379/0")
        assert s.REDIS_URL == "redis://127.0.0.1:6379/0"

    def test_non_production_is_unaffected(self):
        """The test suite itself runs against a passwordless local Redis."""
        s = Settings(APP_ENV="test", REDIS_URL="redis://127.0.0.1:6379/0")  # type: ignore[call-arg]
        assert s.REDIS_URL == "redis://127.0.0.1:6379/0"


class TestSecondFactorPolicy:
    """The gate that makes a second factor mandatory is opt-in.

    A deployment that turns it on without understanding the recovery path can
    lock its own administrator out of every admin screen, so the default has to
    be the permissive one and an upgrade must never flip it silently: the
    documented way to enable it is the environment, not a code change.
    """

    def test_the_default_is_off(self):
        assert Settings().REQUIRE_MFA_FOR_ADMINS is False  # type: ignore[call-arg]

    def test_the_default_holds_in_production_too(self):
        assert _production().REQUIRE_MFA_FOR_ADMINS is False

    def test_it_can_be_turned_on(self):
        assert _production(REQUIRE_MFA_FOR_ADMINS=True).REQUIRE_MFA_FOR_ADMINS is True

    def test_the_roles_list_is_empty_by_default(self):
        assert Settings().REQUIRE_MFA_ROLES == ""  # type: ignore[call-arg]

    def test_the_roles_list_is_normalised(self):
        """Spacing and case are the operator's; the policy compares role names."""
        assert Settings(REQUIRE_MFA_ROLES=" Admin , analyst ").REQUIRE_MFA_ROLES == "admin,analyst"  # type: ignore[call-arg]

    def test_an_unknown_role_name_is_a_startup_failure(self):
        """Otherwise a typo requires a factor from nobody and looks like it worked."""
        with pytest.raises(ValidationError) as failure:
            Settings(REQUIRE_MFA_ROLES="admin,root")  # type: ignore[call-arg]
        assert "root" in str(failure.value)

    def test_every_role_this_platform_has_is_accepted(self):
        """The validator's name list and ``UserRole`` have to keep agreeing."""
        from app.models.user import UserRole

        for member in UserRole:
            assert Settings(REQUIRE_MFA_ROLES=member.value).REQUIRE_MFA_ROLES == member.value  # type: ignore[call-arg]


class TestCorsOriginShapes:
    """`CORS_ORIGINS` arrives as a JSON array, a JSON string or a comma list.

    All three are documented in `.env.example`, and the failure mode of guessing
    wrong is an API that answers every browser with a CORS error — a deployment
    that looks up and serves nothing.
    """

    def test_a_json_string_of_origins_is_split_like_a_comma_list(self):
        import json

        assert _parse_cors_origins(json.dumps("http://a.local,http://b.local")) == [
            "http://a.local",
            "http://b.local",
        ]

    def test_a_value_that_is_not_a_list_or_a_string_falls_back_to_localhost(self):
        assert _parse_cors_origins({"origin": "http://a.local"}) == ["http://localhost:3000"]
        assert _parse_cors_origins(42) == ["http://localhost:3000"]


class TestProxyAllowlistShapes:
    """Every spelling a forwarded-for allowlist can arrive in is checked.

    A wildcard or an unparsable entry does not fail at request time — it makes
    `extract_ip` trust the wrong thing and every audit row record an address that
    is not the client's, which is discovered only by someone reading the trail.
    """

    def test_a_star_forwarded_allowlist_is_refused(self):
        with pytest.raises(ValidationError, match="must not be"):
            Settings(UVICORN_FORWARDED_ALLOW_IPS="*")  # type: ignore[call-arg]

    def test_an_empty_entry_is_refused(self):
        with pytest.raises(ValidationError, match="empty entry"):
            Settings(TRUSTED_PROXY_IPS="127.0.0.1,,::1")  # type: ignore[call-arg]

    def test_a_wildcard_beside_addresses_is_refused(self):
        with pytest.raises(ValidationError, match="only IPs or CIDRs"):
            Settings(TRUSTED_PROXY_IPS="127.0.0.1,*")  # type: ignore[call-arg]

    def test_an_unparsable_entry_is_refused(self):
        with pytest.raises(ValidationError, match="invalid IP/CIDR"):
            Settings(TRUSTED_PROXY_IPS="127.0.0.1,not-an-address")  # type: ignore[call-arg]


class TestBreachNoisePolicy:
    """A typo in the noise policy must not silently mean "report everything"."""

    def test_an_unknown_policy_is_refused_with_the_accepted_values(self):
        with pytest.raises(ValidationError, match="ALERT_BREACH_NOISE_POLICY must be one of"):
            Settings(ALERT_BREACH_NOISE_POLICY="store-only-spam")  # type: ignore[call-arg]

    def test_each_documented_policy_is_accepted(self):
        for policy in ("store_only_spam", "verified_only", "all"):
            assert Settings(ALERT_BREACH_NOISE_POLICY=policy).ALERT_BREACH_NOISE_POLICY == policy  # type: ignore[call-arg]


class TestProductionStartupRefusals:
    """The remaining production checks, each naming the variable it refused."""

    def test_a_parent_subnet_that_is_not_a_network_is_named(self):
        with pytest.raises(ValidationError, match="OPENDRP_NETWORK_SUBNET is not an IP network"):
            Settings(OPENDRP_NETWORK_SUBNET="not-a-network")  # type: ignore[call-arg]

    def test_an_unparsable_database_url_is_named(self):
        with pytest.raises(ValidationError, match="DATABASE_URL is invalid"):
            _production(DATABASE_URL="postgresql://[::1/db")

    def test_an_unparsable_broker_url_is_named(self):
        with pytest.raises(ValidationError, match="REDIS_URL is invalid"):
            _production(REDIS_URL="redis://[::1/0")

    def test_an_insecure_session_cookie_is_refused(self):
        with pytest.raises(ValidationError, match="AUTH_COOKIE_SECURE"):
            _production(AUTH_COOKIE_SECURE=False)

    def test_a_short_jwt_secret_is_refused(self):
        with pytest.raises(ValidationError, match="at least 32 characters"):
            Settings(JWT_SECRET_KEY="too-short")  # type: ignore[call-arg]


class TestTokenLifetimes:
    """A lifetime of zero is a login that cannot succeed, not a policy.

    Both values are read straight into the token claims, so `0` mints a token
    that is already expired and a negative value mints one that expired before it
    was signed. Nothing else in the stack validates them: the failure appears as
    every login answering 200 with a token the API then rejects, which is the
    shape of an incident rather than of a misconfiguration.
    """

    @pytest.mark.parametrize("value", [0, -1, -60])
    def test_an_access_lifetime_must_be_at_least_a_minute(self, value):
        with pytest.raises(ValidationError, match="JWT_ACCESS_TOKEN_EXPIRE_MINUTES"):
            Settings(JWT_ACCESS_TOKEN_EXPIRE_MINUTES=value)

    @pytest.mark.parametrize("value", [0, -1])
    def test_a_refresh_lifetime_must_be_at_least_a_day(self, value):
        with pytest.raises(ValidationError, match="JWT_REFRESH_TOKEN_EXPIRE_DAYS"):
            Settings(JWT_REFRESH_TOKEN_EXPIRE_DAYS=value)

    def test_the_documented_defaults_still_load(self):
        settings = Settings()
        assert settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES == 15
        assert settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS == 3


class TestAppEnvVocabulary:
    """`APP_ENV` is a switch, so a typo must fail instead of switching nothing on.

    Everything it gates — the secret refusals, the cookie-Secure check, the
    pinned version, the shutdown of `/api/docs` — is keyed on the *exact* value
    `production`. Before the allowlist, `APP_ENV=prod` was accepted and answered
    "not production": a deployment that serves API documentation publicly and
    skips every production check, with nothing in the log to say so.
    """

    @pytest.mark.parametrize("value", ["prod", "staging", "pre-production", "produktion"])
    def test_an_unknown_environment_is_refused(self, value):
        with pytest.raises(ValidationError, match="APP_ENV must be one of"):
            Settings(APP_ENV=value)  # type: ignore[call-arg]

    def test_the_non_production_environments_are_accepted(self):
        for value in ("development", "test", "integration"):
            assert Settings(APP_ENV=value).APP_ENV == value  # type: ignore[call-arg]

    def test_a_spelled_environment_is_normalised(self):
        """Case and surrounding whitespace: the two ways a right value arrives wrong.

        `APP_ENV=" Production "` used to compare unequal to `production` and skip
        every production check; it now normalises and runs them — which is why it is
        asserted through `_production`, whose other values are already deployment
        shaped.
        """
        assert Settings(APP_ENV=" Test ").APP_ENV == "test"  # type: ignore[call-arg]
        assert Settings(APP_ENV="INTEGRATION").APP_ENV == "integration"  # type: ignore[call-arg]
        assert _production(APP_ENV=" Production ").APP_ENV == "production"

    def test_the_default_is_the_documented_development(self, monkeypatch):
        monkeypatch.delenv("APP_ENV", raising=False)
        assert Settings().APP_ENV == "development"
