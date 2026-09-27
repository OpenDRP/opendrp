from pathlib import Path

import pytest

from app.core.config import Settings
from app.schemas.connector import BreachFinding, PhishingFinding
from app.services.connector_credentials import generate_token, hash_token


_APP_ROOT = Path("app")


def test_celery_discovers_only_core_owned_tasks():
    source = Path("app/core/celery_app.py").read_text(encoding="utf-8")
    assert '"app.tasks.phishing_tasks"' not in source
    assert '"app.tasks.hibp_tasks"' not in source
    assert '"app.tasks.scheduler_tasks"' in source
    assert '"app.tasks.report_tasks"' in source


def test_core_celery_module_has_no_provider_execution_imports():
    source = Path("app/core/celery_app.py").read_text(encoding="utf-8")
    for provider in ("HibpService", "ShodanService", "DNSTwistService"):
        assert provider not in source


def test_legacy_service_health_router_is_removed():
    assert not Path("app/api/v1/routers/services.py").exists()


def test_provider_execution_is_not_imported_by_core_runtime():
    runtime_files = [
        path
        for path in _APP_ROOT.rglob("*.py")
        if "tests" not in path.parts
        and path.name not in {"hibp_service.py", "shodan_service.py", "dnstwist_service.py", "hibp_tasks.py", "phishing_tasks.py"}
    ]
    forbidden = (
        "from app.services.hibp_service",
        "from app.services.phishing.shodan_service",
        "from app.services.phishing.dnstwist_service",
        "from app.tasks.hibp_tasks",
        "from app.tasks.phishing_tasks",
    )
    for path in runtime_files:
        source = path.read_text(encoding="utf-8")
        assert not any(token in source for token in forbidden), path


def test_postgres_engine_configuration_has_pooling():
    source = Path("app/core/database.py").read_text(encoding="utf-8")
    for setting in ("pool_size", "max_overflow", "pool_recycle", "pool_timeout", "pool_pre_ping"):
        assert setting in source


def test_no_platform_wide_connector_secret_exists():
    """Connectors must authenticate with their own digest, never a shared secret.

    A single platform-wide value could be replayed as any connector and could not
    be revoked for one of them alone, so the core must not have such a setting.
    """
    offenders = [
        str(path)
        for path in _APP_ROOT.rglob("*.py")
        if "CONNECTOR_TOKEN" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


def test_connector_credentials_are_issued_as_digests():
    token = generate_token("connector-hibp")
    digest = hash_token(token)
    assert digest != token and len(digest) == 64
    assert token not in digest


def test_connector_finding_schemas_reject_unknown_or_malformed_fields():
    with pytest.raises(ValueError):
        PhishingFinding(phishing_domain="evil.example", matched_asset="asset", unexpected=True)
    with pytest.raises(ValueError):
        PhishingFinding(phishing_domain="evil.example", matched_asset="asset", ip_address="not-an-ip")
    with pytest.raises(ValueError):
        BreachFinding(breach_name="Leak", matched_email="not-an-email")


def test_production_settings_reject_shipped_defaults():
    with pytest.raises(ValueError):
        Settings(
            APP_ENV="production",
            DATABASE_URL="postgresql://opendrp:opendrp@db:5432/opendrp",
            JWT_SECRET_KEY="change-me-in-production-please-very-long-key",
            ENCRYPTION_KEY="Z0FBQUFBQm1hbmRvbV9rZXlfZm9yX2ZlbmNyeXB0aW9uXzMyYnl0ZXM=",
        )
