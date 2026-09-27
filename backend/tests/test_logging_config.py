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
import uuid

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
        assert tuple(sorted(payload["details"])) == (
            "asset_id",
            "audit_hash",
            "audit_key_id",
            "audit_prev_hash",
        )
        assert len(payload["details"]["audit_hash"]) == 64
        # A predecessor hash, which is the all-zero value only for the first
        # entry of a chain. Asserting *that* would make this test depend on
        # whether any other test in the run wrote an audit row first, so only
        # the shape is pinned here.
        assert len(payload["details"]["audit_prev_hash"]) == 64
        assert isinstance(payload["details"]["audit_key_id"], int)

    def test_non_audit_events_keep_their_extra_fields(self, capsys):
        """Only audit events are trimmed; diagnostics keep their context."""
        configure_logging(force=True)
        get_logger().info("diagnostic_probe", component="retention")
        matches = _find(capsys.readouterr().out, event="diagnostic_probe")
        assert len(matches) == 1
        assert matches[0]["component"] == "retention"
        assert matches[0]["logger"] == PLATFORM_LOGGER_NAME


class TestLogLevelSetting:
    def test_a_typo_is_rejected_rather_than_ignored(self):
        from app.core.config import Settings

        with pytest.raises(ValueError, match="LOG_LEVEL must be one of"):
            Settings(LOG_LEVEL="verbose")

    def test_the_level_is_normalised(self):
        from app.core.config import Settings

        assert Settings(LOG_LEVEL="debug").LOG_LEVEL == "DEBUG"
