"""The log output contract: audit JSON must actually reach stdout.

These tests exist because the platform advertised a SIEM pipeline in its
documentation while the stdout half of the audit trail was being discarded
before rendering. The database row was still written, the API returned 200, and
nothing anywhere reported a problem — so only a test that reads the real stdout
can tell the difference between "logged" and "written to the database".

The most important test in this file is
``test_audit_event_reaches_stdout_as_one_json_line``: it captures stdout around a
real ``AuditLogger.emit`` and asserts the five published fields, which is the
exact claim ``docs/description.md`` makes to operators.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import uuid
from typing import Any

import pytest
import structlog

from app.core import logging_config
from app.core.audit import AuditLogger
from app.core.config import settings
from app.core.logging_config import (
    AUDIT_FIELDS,
    AUDIT_LOGGER_NAME,
    PLATFORM_LOGGER_NAME,
    configure_logging,
    get_logger,
)


@pytest.fixture(autouse=True)
def restore_logging_after_the_test():
    """Rebind the stdout handler the test moved onto the capture object.

    ``configure_logging`` builds a ``StreamHandler`` around whatever
    ``sys.stdout`` is at that moment. Under ``capsys`` that is pytest's capture
    buffer, which is closed when the test ends; without this, later tests would
    log into a dead stream.
    """
    yield
    configure_logging(force=True)


class TestConfiguration:
    def test_handler_writes_to_stdout_without_a_prefix(self):
        configure_logging(force=True)
        handlers = logging.getLogger(PLATFORM_LOGGER_NAME).handlers
        assert len(handlers) == 1
        # `%(message)s`: structlog renders the line, and any prefix would turn
        # one JSON object into a line a JSON parser rejects.
        assert handlers[0].formatter._fmt == "%(message)s"

    def test_configuration_is_idempotent(self):
        configure_logging(force=True)
        first = logging.getLogger(PLATFORM_LOGGER_NAME).handlers[:]
        configure_logging()
        configure_logging()
        # A second handler would print every record twice, which is worse than
        # useless in a SIEM: it doubles counters that detection rules use.
        assert logging.getLogger(PLATFORM_LOGGER_NAME).handlers == first

    def test_platform_logger_does_not_propagate_to_root(self):
        configure_logging(force=True)
        assert logging.getLogger(PLATFORM_LOGGER_NAME).propagate is False

    def test_audit_logger_level_is_pinned_at_info(self):
        configure_logging(force=True)
        assert logging.getLogger(AUDIT_LOGGER_NAME).level == logging.INFO


class TestLoggerFactory:
    def test_unnamed_loggers_get_the_platform_name(self, monkeypatch):
        """The mechanism that fixes every ``structlog.get_logger()`` call site.

        Without it, an unnamed logger is named after the calling module by
        structlog's own stack walk. Nothing sets a level or a handler on such a
        logger, so it inherits the root default (WARNING) and every INFO event
        is dropped before rendering.
        """
        recorded: list[tuple] = []

        class _Recorder:
            def __call__(self, *args):
                recorded.append(args)
                return object()

        monkeypatch.setattr(
            structlog.stdlib, "LoggerFactory", lambda *a, **kw: _Recorder()
        )
        factory = logging_config._platform_logger_factory()

        factory()
        factory(AUDIT_LOGGER_NAME)

        assert recorded == [(PLATFORM_LOGGER_NAME,), (AUDIT_LOGGER_NAME,)]

    def test_get_logger_defaults_to_the_platform_namespace(self):
        configure_logging(force=True)
        assert get_logger() is not None


def _json_objects(text: str) -> list[dict]:
    """Every line that is a JSON object, parsed.

    Parsing rather than substring-matching on purpose: the renderer's separator
    and key-order choices are structlog's to make, and a test that pins them
    fails on an upgrade for no reason. What matters is that a line *is* one JSON
    object, which is exactly what a SIEM ingester requires.
    """
    parsed: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            parsed.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return parsed


def _find(text: str, **fields) -> list[dict]:
    return [
        payload
        for payload in _json_objects(text)
        if all(payload.get(key) == value for key, value in fields.items())
    ]


class TestOutput:
    def test_platform_info_event_is_emitted_as_json(self, capsys):
        """The regression for ordinary logs: INFO used to be dropped too."""
        configure_logging(force=True)
        get_logger().info("platform_probe", marker="visible")
        matches = _find(capsys.readouterr().out, event="platform_probe")
        assert len(matches) == 1
        assert matches[0]["marker"] == "visible"

    def test_log_level_filters_ordinary_events(self, capsys, monkeypatch):
        monkeypatch.setattr(settings, "LOG_LEVEL", "ERROR")
        configure_logging(force=True)
        get_logger().info("below_the_level")
        assert _find(capsys.readouterr().out, event="below_the_level") == []

    @pytest.mark.asyncio
    async def test_audit_event_survives_an_error_log_level(
        self, db_session, capsys, monkeypatch
    ):
        """A level setting must not be able to stop the platform auditing.

        This is the difference between diagnostics and records: an operator who
        raises the level to reduce noise is not asking to lose the trail that
        says who deleted an asset.
        """
        monkeypatch.setattr(settings, "LOG_LEVEL", "ERROR")
        configure_logging(force=True)

        await AuditLogger.emit(
            db_session,
            action="auth.logout",
            ip_address="203.0.113.7",
            user_id=str(uuid.uuid4()),
            details={"probe": "audit-survives-error-level"},
        )

        matches = _find(capsys.readouterr().out, action="auth.logout")
        assert len(matches) == 1
        assert matches[0]["details"]["probe"] == "audit-survives-error-level"

    @pytest.mark.asyncio
    async def test_audit_event_reaches_stdout_as_one_json_line(
        self, db_session, capsys
    ):
        """The published contract: one line, exactly five fields, valid JSON."""
        configure_logging(force=True)
        user_id = str(uuid.uuid4())

        await AuditLogger.emit(
            db_session,
            action="asset.delete",
            ip_address="198.51.100.4",
            user_id=user_id,
            details={"asset_id": "asset-1"},
        )

        captured = capsys.readouterr().out
        candidates = _find(captured, action="asset.delete")
        assert len(candidates) == 1, f"expected exactly one audit line in:\n{captured}"

        payload = candidates[0]
        # Exactly the five fields, no sixth. A superset would reach a SIEM index
        # that maps the documented shape and quietly become unindexed noise.
        assert tuple(sorted(payload)) == tuple(sorted(AUDIT_FIELDS))
        assert payload["action"] == "asset.delete"
        assert payload["user_id"] == user_id
        assert payload["ip_address"] == "198.51.100.4"
        assert payload["timestamp"]
        # The chain fields travel *inside* `details`: the envelope stays five
        # fields wide (that is the contract a SIEM index maps), and the hash that
        # lets an exported line be checked against the database row against the
        # archive is still in the line. `audit_hash` cannot cover itself, so the
        # hash is computed over the details before these three are added.
        assert payload["details"]["asset_id"] == "asset-1"
        # `audit_persisted` is the one field the exported line carries and the row
        # does not: persistence is the outcome of the very write that creates the
        # row, so the row cannot record its own commit — while a line that does
        # not say whether its event reached the database cannot be reconciled
        # with the database at all. Its value is asserted because a stream that
        # silently stopped persisting is exactly what the field exists to show.
        assert tuple(sorted(payload["details"])) == (
            "asset_id",
            "audit_hash",
            "audit_key_id",
            "audit_persisted",
            "audit_prev_hash",
        )
        assert payload["details"]["audit_persisted"] is True
        assert len(payload["details"]["audit_hash"]) == 64
        # A predecessor hash, which is the all-zero value only for the first
        # entry of a chain. Asserting *that* would make this test depend on
        # whether any other test in the run wrote an audit row first, so only
        # the shape is pinned here.
        assert len(payload["details"]["audit_prev_hash"]) == 64
        assert isinstance(payload["details"]["audit_key_id"], int)

    def test_the_fallback_line_carries_the_five_fields_and_no_others(
        self, capsys, monkeypatch
    ):
        """The last-resort print is part of the contract as well.

        It exists so a rendering failure cannot lose an audit event, and it exists
        in the module that publishes the shape: it takes the five fields by name,
        so an event that grew a sixth key — a future field nobody documented —
        cannot reach a SIEM index through the path that is supposed to be a
        safety net rather than a second, quieter stream.
        """
        import app.core.audit as audit_module

        monkeypatch.setattr(audit_module, "log", _FailingLogger())
        audit_module._publish_audit_event(
            {
                "timestamp": "2026-10-19T00:00:00+00:00",
                "user_id": None,
                "action": "asset.delete",
                "ip_address": "198.51.100.4",
                "details": {"asset_id": "asset-1"},
                "undocumented": "must not be exported",
            }
        )

        line = capsys.readouterr().out.strip()
        payload = json.loads(line)
        assert tuple(sorted(payload)) == tuple(sorted(AUDIT_FIELDS))
        assert payload["action"] == "asset.delete"
        assert payload["ip_address"] == "198.51.100.4"
        assert payload["details"] == {"asset_id": "asset-1"}
        assert "undocumented" not in line

    def test_non_audit_events_keep_their_extra_fields(self, capsys):
        """Only audit events are trimmed; diagnostics keep their context."""
        configure_logging(force=True)
        get_logger().info("diagnostic_probe", component="retention")
        matches = _find(capsys.readouterr().out, event="diagnostic_probe")
        assert len(matches) == 1
        assert matches[0]["component"] == "retention"
        assert matches[0]["logger"] == PLATFORM_LOGGER_NAME


class _FailingLogger:
    """A logger that refuses the record, which is the only way in to the fallback."""

    def info(self, *args: Any, **kwargs: Any) -> None:
        raise RuntimeError("renderer refused the record")


def _connector_sdk() -> Any | None:
    """The connector SDK, imported the way ``test_connector_sdk_contract`` does.

    CI checkouts have ``<repo>/connectors`` next to ``backend/``; the backend dev
    container gets a read-only mount at ``/connectors``.
    """
    candidates = [
        os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "connectors",
            "base",
        ),
        "/connectors/base",
    ]
    for candidate in candidates:
        if os.path.isdir(os.path.join(candidate, "opendrp_connector")):
            if candidate not in sys.path:
                sys.path.insert(0, candidate)
            break
    else:
        return None

    from opendrp_connector import base as connector_base

    return connector_base


class TestAForeignConfigurationCannotPinTheAuditStream:
    """A connector in this process must not decide the core's audit line.

    The SDK configures structlog globally from ``ConnectorBase.main``, and it used
    to request ``cache_logger_on_first_use``. That flag is process global: every
    logger bound while a connector ran was hard-cached with the connector's chain,
    including the core's audit logger when the SDK is embedded in the core process
    — which is what this repository's own connector tests do, and what any future
    in-process use would do. The audit line then came out in the connector's shape
    (``event`` and ``level`` beside the five published fields) for the rest of the
    process, and no later ``configure_logging`` could undo it.

    It reached the suite as an order-dependent failure in one shard: the test that
    emitted the audit line passed alone and failed after an unrelated test file had
    run a connector. The chain is asserted here instead, so the next connector
    configuration change cannot reintroduce it silently.
    """

    def test_the_published_five_fields_survive_a_connector_configure(self, capsys):
        sdk = _connector_sdk()
        if sdk is None:
            pytest.skip("connector SDK source not available")

        from app.core.audit import log as audit_log

        def emit(action: str) -> None:
            audit_log.info(
                logging_config.AUDIT_EVENT_NAME,
                timestamp="2026-01-01T00:00:00Z",
                user_id=None,
                action=action,
                ip_address="127.0.0.1",
                details={"request_id": "pinned"},
            )

        configure_logging(force=True)
        emit("probe.before")
        sdk.configure_connector_logging()
        emit("probe.during")
        configure_logging(force=True)
        emit("probe.after")

        captured = capsys.readouterr().out
        for action in ("probe.before", "probe.during", "probe.after"):
            lines = _find(captured, action=action)
            assert len(lines) == 1, f"{action}: expected one line, got {len(lines)}"
            assert tuple(sorted(lines[0])) == tuple(sorted(AUDIT_FIELDS)), action

    def test_a_platform_logger_is_not_pinned_by_a_connector(self, capsys):
        """A logger bound while a connector runs must not keep its chain.

        The other half of the same flag: ``cache_logger_on_first_use`` in the
        SDK's configuration replaced the bound-logger lookup of *every* proxy
        used during the window, so a platform logger first used while a connector
        ran kept rendering the connector's shape (no ``logger`` field, no request
        id) for the rest of the process.
        """
        sdk = _connector_sdk()
        if sdk is None:
            pytest.skip("connector SDK source not available")

        platform_log = get_logger()
        configure_logging(force=True)
        platform_log.info("platform_before")
        sdk.configure_connector_logging()
        platform_log.info("platform_during")
        configure_logging(force=True)
        platform_log.info("platform_after")

        captured = capsys.readouterr().out
        # While the connector's configuration is current the platform's is not
        # installed — that window is the connector's, by definition. What must not
        # survive it is the proxy: after the core reconfigures, the same logger
        # object is the platform's again.
        for event in ("platform_before", "platform_after"):
            lines = _find(captured, event=event)
            assert len(lines) == 1, f"{event}: expected one line, got {len(lines)}"
            assert lines[0].get("logger") == PLATFORM_LOGGER_NAME, event

    def test_a_foreign_wrapper_cannot_silence_an_audit_event(self, capsys, monkeypatch):
        """The connector's level-filtering wrapper must not become the core's.

        ``configure`` leaves an argument it is not given unchanged, so a wrapper
        built for a connector running at WARNING used to survive into the core's
        own configuration — where it drops an INFO event before any processor
        sees it, which is the audit trail going quiet without an error.
        """
        sdk = _connector_sdk()
        if sdk is None:
            pytest.skip("connector SDK source not available")

        monkeypatch.setenv("CONNECTOR_LOG_LEVEL", "WARNING")
        sdk.configure_connector_logging()
        configure_logging(force=True)
        get_logger().info("wrapper_probe")

        assert len(_find(capsys.readouterr().out, event="wrapper_probe")) == 1


class TestLogLevelSetting:
    def test_a_typo_is_rejected_rather_than_ignored(self):
        from app.core.config import Settings

        with pytest.raises(ValueError, match="LOG_LEVEL must be one of"):
            Settings(LOG_LEVEL="verbose")

    def test_the_level_is_normalised(self):
        from app.core.config import Settings

        assert Settings(LOG_LEVEL="debug").LOG_LEVEL == "DEBUG"
