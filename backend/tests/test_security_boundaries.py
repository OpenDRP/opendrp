from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.api.deps import (
    extract_ip,
    get_current_user,
    require_admin,
    require_analyst_or_admin,
    require_viewer_plus,
)
from app.core.config import Settings, settings
from app.schemas.connector import BreachFinding, PhishingFinding


def test_production_rejects_placeholder_like_secrets():
    with pytest.raises(ValueError, match="JWT_SECRET_KEY"):
        Settings(
            APP_ENV="production",
            DATABASE_URL="postgresql://app:real-password@db:5432/opendrp",
            JWT_SECRET_KEY="ChangeThisJWTSecretKeyMustBeVeryLongAndRandom123!",
            ENCRYPTION_KEY="real-encryption-key-placeholder-but-long-enough",
        )


def test_production_rejects_placeholder_database_password():
    with pytest.raises(ValueError, match="POSTGRES_PASSWORD"):
        Settings(
            APP_ENV="production",
            DATABASE_URL="postgresql://app:ChangeThisStrongPostgresPassword123!@db:5432/opendrp",
            JWT_SECRET_KEY="a" * 48,
            ENCRYPTION_KEY="b" * 44,
        )


def _request(client_host: str, headers: dict[str, str]) -> MagicMock:
    request = MagicMock()
    request.client.host = client_host
    request.headers.get.side_effect = headers.get
    return request


def test_extract_ip_uses_nearest_untrusted_hop_from_trusted_proxy():
    """The hop adjacent to our proxy is the only one we can vouch for."""
    request = _request(
        "127.0.0.1", {"x-forwarded-for": "203.0.113.9, 10.0.0.1"}
    )
    assert extract_ip(request) == "10.0.0.1"


def test_extract_ip_ignores_spoofed_leftmost_entry():
    """A client-supplied X-Forwarded-For must not be able to frame an address.

    nginx appends the real peer via ``$proxy_add_x_forwarded_for``, so a forged
    leftmost entry arrives *before* the true one and must lose.
    """
    request = _request(
        "127.0.0.1",
        {"x-forwarded-for": "203.0.113.9, 198.51.100.77"},
    )
    assert extract_ip(request) == "198.51.100.77"


def test_extract_ip_skips_declared_intermediate_proxy(monkeypatch):
    monkeypatch.setattr(
        settings, "TRUSTED_PROXY_IPS", "127.0.0.1,::1,10.0.0.1"
    )
    request = _request(
        "127.0.0.1", {"x-forwarded-for": "203.0.113.9, 10.0.0.1"}
    )
    assert extract_ip(request) == "203.0.113.9"


def test_extract_ip_all_hops_trusted_falls_back_to_socket_peer(monkeypatch):
    monkeypatch.setattr(
        settings, "TRUSTED_PROXY_IPS", "127.0.0.1,::1,10.0.0.0/8"
    )
    request = _request("127.0.0.1", {"x-forwarded-for": "10.0.0.1, 10.0.0.2"})
    assert extract_ip(request) == "127.0.0.1"


def test_extract_ip_skips_malformed_entries_and_ports():
    malformed = _request(
        "127.0.0.1", {"x-forwarded-for": "not-an-ip, 198.51.100.7"}
    )
    assert extract_ip(malformed) == "198.51.100.7"

    with_port = _request(
        "127.0.0.1", {"x-forwarded-for": "198.51.100.7:41234"}
    )
    assert extract_ip(with_port) == "198.51.100.7"


def test_extract_ip_ignores_forwarded_ip_from_untrusted_client():
    request = _request(
        "198.51.100.5", {"x-forwarded-for": "203.0.113.9"}
    )
    assert extract_ip(request) == "198.51.100.5"


def test_extract_ip_without_request_is_unknown():
    assert extract_ip(None) == "unknown"


def test_extract_ip_uses_real_ip_from_trusted_proxy():
    request = _request("127.0.0.1", {"x-real-ip": "2001:db8::10"})
    assert extract_ip(request) == "2001:db8::10"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({"type": "refresh", "sub": "00000000-0000-0000-0000-000000000001"}, "Invalid token type"),
        ({"type": "access"}, "Invalid token payload"),
        ({"type": "access", "sub": "not-a-uuid"}, "Invalid token payload"),
    ],
)
async def test_get_current_user_rejects_invalid_access_payload(payload, expected):
    db = AsyncMock()
    with patch("app.api.deps.decode_token", return_value=payload):
        with pytest.raises(Exception) as exc_info:
            await _current_user(db)
    assert exc_info.value.detail == expected


async def _current_user(db, token: str = "token"):
    """Resolve the dependency the way FastAPI does, request included.

    ``request`` is a real parameter of ``get_current_user`` (it feeds the
    rate-limit audit), so the older positional ``(token, db)`` call silently
    bound ``db`` to ``request`` and tested nothing.
    """
    return await get_current_user(request=_request("203.0.113.7", {}), token=token, db=db)


@pytest.mark.asyncio
async def test_get_current_user_rejects_missing_and_inactive_users():
    db = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = None
    db.execute.return_value = result
    with patch(
        "app.api.deps.decode_token",
        return_value={"type": "access", "sub": "00000000-0000-0000-0000-000000000001"},
    ):
        with pytest.raises(Exception) as exc_info:
            await _current_user(db)
    assert exc_info.value.detail == "User not found"

    inactive = MagicMock(is_active=False)
    result.scalar_one_or_none.return_value = inactive
    with patch(
        "app.api.deps.decode_token",
        return_value={"type": "access", "sub": "00000000-0000-0000-0000-000000000001"},
    ):
        with pytest.raises(Exception) as exc_info:
            await _current_user(db)
    assert exc_info.value.detail == "User is inactive"


def _user(role: str, active: bool = True) -> MagicMock:
    return MagicMock(role=role, is_active=active)


@pytest.mark.asyncio
async def test_role_dependencies_enforce_admin_analyst_and_active_viewer():
    admin = _user("admin")
    analyst = _user("analyst")
    viewer = _user("viewer")
    # `require_admin` is the one gate that is async and takes the request and the
    # session: the optional second-factor requirement sits on top of the role
    # check, and a refusal has to be audited with the address it came from.
    request = _request("127.0.0.1", {})
    db = AsyncMock()
    assert await require_admin(request, admin, db) is admin
    assert require_analyst_or_admin(admin) is admin
    assert require_analyst_or_admin(analyst) is analyst
    assert require_viewer_plus(viewer) is viewer

    with pytest.raises(Exception) as exc_info:
        await require_admin(request, viewer, db)
    assert exc_info.value.status_code == 403
    with pytest.raises(Exception) as exc_info:
        require_analyst_or_admin(viewer)
    assert exc_info.value.status_code == 403
    with pytest.raises(Exception) as exc_info:
        require_viewer_plus(_user("viewer", active=False))
    assert exc_info.value.status_code == 401


    with pytest.raises(ValueError):
        PhishingFinding(
            phishing_domain="evil.example\nX-Injected: true",
            matched_asset="example.com",
        )
    with pytest.raises(ValueError):
        BreachFinding(breach_name="Leak", matched_email="user@example.com", unknown="x")


def test_breach_finding_uses_strict_types_and_bounds():
    with pytest.raises(ValueError):
        BreachFinding(
            breach_name="Leak",
            matched_email="user@example.com",
            pwn_count=True,
        )
    with pytest.raises(ValueError):
        BreachFinding(
            breach_name="Leak",
            matched_email="user@example.com",
            data_classes=["x" * 256],
        )


def test_postgres_pool_config_is_explicit_and_sql_uses_bound_statements():
    database_source = Path("app/core/database.py").read_text(encoding="utf-8")
    assert '"pool_pre_ping"' in database_source
    assert '"pool_size"' in database_source
    assert '"max_overflow"' in database_source
    assert '"pool_timeout"' in database_source

    runtime_source = "\n".join(
        p.read_text(encoding="utf-8")
        for p in Path("app").rglob("*.py")
        if "tests" not in p.parts
    )
    assert "text(f\"SELECT" not in runtime_source
    assert "text(f' SELECT" not in runtime_source
