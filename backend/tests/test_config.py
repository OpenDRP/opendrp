import pytest
from pydantic import ValidationError

from app.core.config import Settings, _parse_cors_origins

#: A production configuration that passes every other production check, so that
#: the tests below fail only for the reason each one is about.
_PRODUCTION = {
    "APP_ENV": "production",
    "OPENDRP_VERSION": "0.1.0",
    "JWT_SECRET_KEY": "j" * 48,
    "ENCRYPTION_KEY": "Zm9yLXRlc3Qtb25seS1mZXJuZXQta2V5LXZhbHVlLXBhZGRlZA==",
    "AUTH_COOKIE_SECURE": True,
    "TRUSTED_PROXY_IPS": "127.0.0.1,::1",
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
    assert _production(OPENDRP_VERSION="0.1.0").OPENDRP_VERSION == "0.1.0"





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
