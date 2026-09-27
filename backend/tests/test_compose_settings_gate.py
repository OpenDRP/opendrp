"""The Compose gate has to see a container that cannot start.

`restart: unless-stopped` turns a process that exits on import into a container
that is restarted forever while the rest of the stack reports healthy. Whatever
only that container did then stops happening, and nothing says so: the logs are
the only trace, and nobody reads the logs of a service that is "up".

`celery-beat` was exactly that. Its environment did not carry
`AUDIT_CHAIN_KEYS`, production `Settings` refused to load without it, and the
only place the alert delivery queue is drained from is a beat-scheduled task — so
every finding was stored and no notification was ever sent, while the API, the
workers, the connectors and every health endpoint looked fine.

Two directions are asserted here, because the rule has both: a service that runs
the application must be given what it needs to start, and a container that runs
no application must not be handed the platform's secrets as a precaution. The
requirement list itself is pinned against the real `Settings` model, so a
validator that starts demanding another value fails this file rather than
shipping.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import Settings

_ROOT = Path(__file__).resolve().parents[2]
_GATE = _ROOT / "scripts" / "check_compose_healthchecks.py"
_COMPOSE = _ROOT / "docker-compose.yml"

if not _GATE.is_file() or not _COMPOSE.is_file():
    # The dev overlay mounts the repository's scripts/ read-only for this suite;
    # a trimmed checkout cannot answer the question, and a hard error would look
    # like a gate failure rather than a missing file.
    pytest.skip(
        f"not a repository checkout: {_GATE.name} or {_COMPOSE.name} missing",
        allow_module_level=True,
    )


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


gate = _load(_GATE, "opendrp_test_check_compose_settings")


#: A production configuration that passes everything except what a test removes,
#: mirroring the baseline in `tests/test_config.py`. `AUTH_COOKIE_SECURE` is
#: deliberately absent: its default is the value production demands, which is why
#: the gate does not require Compose to pass it.
_PRODUCTION: dict[str, str] = {
    "APP_ENV": "production",
    "OPENDRP_VERSION": "0.1.0",
    "JWT_SECRET_KEY": "j" * 48,
    "ENCRYPTION_KEY": "Zm9yLXRlc3Qtb25seS1mZXJuZXQta2V5LXZhbHVlLXBhZGRlZA==",
    "AUDIT_CHAIN_KEYS": "chain-key-for-tests-only-" * 3,
    "DATABASE_URL": "postgresql://opendrp:a-long-random-password@postgres:5432/opendrp",
    "REDIS_URL": "redis://:a-long-random-password@redis:6379/0",
    "TRUSTED_PROXY_IPS": "127.0.0.1,::1",
}


def _service(name: str, environment: dict[str, str]) -> str:
    lines = [f"  {name}:", "    image: opendrp/backend:0.1.0", "    environment:"]
    lines.extend(f"      {key}: {value}" for key, value in environment.items())
    return "\n".join(lines) + "\n"


def _compose(*services: str) -> str:
    return "services:\n" + "\n".join(services)


def _findings(text: str) -> list[str]:
    services, _ = gate.parse_services(text)
    return gate._check_application_settings(services)


# ==============================================================================
# The shipped stack
# ==============================================================================
def test_the_shipped_stack_gives_every_application_process_its_settings() -> None:
    """The real file, as CI runs the gate over it."""
    findings = _findings(_COMPOSE.read_text(encoding="utf-8"))

    assert findings == [], "\n".join(findings)


def test_the_services_that_run_the_application_are_the_ones_carrying_app_env() -> None:
    """The marker is what the rule keys on, and it has to stay meaningful."""
    services, _ = gate.parse_services(_COMPOSE.read_text(encoding="utf-8"))
    carrying = {service.name for service in services if service.env("APP_ENV")}

    assert carrying == {"backend", "celery-worker", "celery-beat"}


# ==============================================================================
# The defect this rule was written for
# ==============================================================================
def test_the_scheduler_that_alone_drains_the_alert_queue_is_reported() -> None:
    """`celery-beat` without `AUDIT_CHAIN_KEYS`, as it shipped in 0.1.0."""
    beat = {
        key: value for key, value in _PRODUCTION.items() if key != "AUDIT_CHAIN_KEYS"
    }
    findings = _findings(
        _compose(
            _service("backend", _PRODUCTION),
            _service("celery-worker", _PRODUCTION),
            _service("celery-beat", beat),
        )
    )

    assert len(findings) == 1, findings
    assert "celery-beat" in findings[0]
    assert "AUDIT_CHAIN_KEYS" in findings[0]
    # The message has to name the symptom, because the container itself reports
    # nothing but a restart count.
    assert "restarts" in findings[0]


def test_two_missing_settings_are_both_named() -> None:
    findings = _findings(
        _compose(
            _service(
                "celery-worker",
                {
                    key: value
                    for key, value in _PRODUCTION.items()
                    if key not in {"AUDIT_CHAIN_KEYS", "TRUSTED_PROXY_IPS"}
                },
            )
        )
    )

    assert len(findings) == 1
    assert "AUDIT_CHAIN_KEYS" in findings[0]
    assert "TRUSTED_PROXY_IPS" in findings[0]


# ==============================================================================
# The other direction: containers that run no application
# ==============================================================================
def test_a_container_that_runs_no_application_is_not_asked_for_the_secrets() -> None:
    """Handing the datastores or the frontend the JWT secret is the same defect.

    The rule keys on `APP_ENV` rather than a list of service names, so this
    asserts the marker is the thing that decides: a new service with no
    application in it stays out of scope, and one that starts the application is
    in scope whether or not anybody remembered to add it to a list.
    """
    findings = _findings(
        _compose(
            _service("postgres", {"POSTGRES_PASSWORD": "p", "POSTGRES_DB": "opendrp"}),
            _service("frontend", {"FRONTEND_PORT": "127.0.0.1:3000"}),
            _service(
                "connector-shodan",
                {"CORE_URL": "http://backend:8000", "CONNECTOR_TOKEN": "t"},
            ),
            _service("backup", {"PGPASSWORD": "p"}),
        )
    )

    assert findings == []


# ==============================================================================
# The requirement list is the application's, not this gate's invention
# ==============================================================================
def test_the_required_list_is_exactly_the_documented_set() -> None:
    """A statement of the rule, so that changing it is a deliberate edit."""
    assert set(gate._REQUIRED_APP_SETTINGS) == {
        "OPENDRP_VERSION",
        "DATABASE_URL",
        "REDIS_URL",
        "JWT_SECRET_KEY",
        "ENCRYPTION_KEY",
        "AUDIT_CHAIN_KEYS",
        "TRUSTED_PROXY_IPS",
    }


@pytest.mark.parametrize("key", gate._REFUSED_WITHOUT)
def test_production_refuses_to_start_without_each_required_setting(
    key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each name is one `app.core.config` fails on, verified against the model.

    Without this, the gate could require a variable nothing reads (harmless but
    misleading) or, worse, miss one the application added — which is how the
    `celery-beat` defect shipped in the first place.
    """
    monkeypatch.setenv("APP_ENV", "production")
    Settings(**_PRODUCTION)  # the baseline itself is valid

    with pytest.raises(ValidationError):
        Settings(**{**_PRODUCTION, key: ""})


def test_the_broker_url_is_required_even_though_startup_accepts_an_empty_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The second reason a setting is on the list, stated rather than assumed.

    An empty `REDIS_URL` is not a validation error, so the parametrized test
    above cannot cover it — and it is still a container that publishes and
    consumes nothing. That is why the gate keeps the two reasons apart instead of
    treating the list as one kind of requirement.
    """
    monkeypatch.setenv("APP_ENV", "production")

    assert Settings(**{**_PRODUCTION, "REDIS_URL": ""}).REDIS_URL == ""
    assert "REDIS_URL" in gate._REQUIRED_TO_WORK
    assert "REDIS_URL" not in gate._REFUSED_WITHOUT


def test_the_cookie_flag_is_not_required_because_its_default_already_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Why `AUTH_COOKIE_SECURE` may be absent from a service's environment."""
    monkeypatch.setenv("APP_ENV", "production")

    assert Settings(**_PRODUCTION).AUTH_COOKIE_SECURE is True
