from __future__ import annotations

import datetime as dt
import decimal
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AUDIT_ALLOWED_ACTIONS, AuditLogger, _safe_jsonable
from app.models.audit import AuditLog


class TestAuditActionWhitelist:
    def test_known_actions_allowed(self):
        expected = {
            "auth.login.success", "auth.login.failure", "auth.login.locked",
            "auth.logout", "auth.refresh.success", "auth.refresh.failure",
            "asset.create", "asset.update", "asset.delete", "asset.list", "asset.view",
            "settings.update", "settings.view", "settings.test_email_sent",
            "settings.test_email_failed",
            "report.generate", "report.generate.failed", "report.list",
            "report.download", "report.delete",
            "phishing.scan.dnstwist.start", "phishing.scan.shodan.start",
            "phishing.threat.list", "phishing.threat.view",
            "phishing.threat.update", "phishing.scan.scheduled",
            "breach.list", "breach.view", "breach.scan.start",
            "alert.dispatch.success", "alert.dispatch.failed",
            "task.started", "task.completed", "task.failed",
            "dashboard.view",
            "user.created", "user.locked", "user.unlocked",
        }
        for a in expected:
            assert a in AUDIT_ALLOWED_ACTIONS, a

    def test_every_action_the_audit_ui_labels_is_a_real_action(self):
        """The label map is a second list, and second lists drift.

        A label without an action is a typo: the API never emits that name, so
        the row it was written for either uses a different action or is written
        outside the allowlist and reported as unrecognized on every occurrence.
        The other direction is deliberately not enforced — an unlabelled action
        renders with its raw name, which is ugly but honest, and a hard gate there
        would only produce churn.
        """
        from app.api.v1.routers.audit import AUDIT_ACTION_LABELS

        unknown = sorted(set(AUDIT_ACTION_LABELS) - AUDIT_ALLOWED_ACTIONS)
        assert unknown == [], f"labelled but not allowlisted: {unknown}"

    def test_every_action_the_api_emits_is_allowlisted(self):
        """A call site that names an action the allowlist does not know is a bug

        with a specific symptom: the row is written, but the write is logged as
        `audit_action_unrecognized` and a SIEM rule built from the published
        action list will not match it.
        """
        import re
        from pathlib import Path

        emitted: set[str] = set()
        root = Path(__file__).resolve().parents[1] / "app"
        pattern = re.compile(r'action="([a-z][a-z0-9._]*)"')
        for path in root.rglob("*.py"):
            emitted.update(pattern.findall(path.read_text(encoding="utf-8")))

        unknown = sorted(emitted - AUDIT_ALLOWED_ACTIONS)
        assert unknown == [], f"emitted but not allowlisted: {unknown}"


class TestSafeJsonable:
    def test_primitives_pass(self):
        assert _safe_jsonable({"a": 1, "b": "x", "c": None, "d": [1, 2, 3]}) == {
            "a": 1, "b": "x", "c": None, "d": [1, 2, 3],
        }

    def test_special_values_become_json_primitives(self):
        u = uuid.uuid4()
        out = _safe_jsonable(
            {
                "id": u,
                "when": dt.datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc),
                "date": dt.date(2026, 9, 5),
                "time": dt.time(12, 0),
                "duration": dt.timedelta(seconds=1.5),
                "amount": decimal.Decimal("1.25"),
                "raw": b"safe",
            }
        )
        assert out == {
            "id": str(u),
            "when": "2026-09-05T12:00:00+00:00",
            "date": "2026-09-05",
            "time": "12:00:00",
            "duration": 1.5,
            "amount": "1.25",
            "raw": "safe",
        }

    def test_normalized_details_are_stdlib_json_serializable(self):
        import json

        details = _safe_jsonable({"id": uuid.uuid4(), "amount": decimal.Decimal("2.50")})
        assert json.dumps(details)

    def test_unserializable_value_is_stringified(self):
        class _C:
            def __repr__(self):
                return "<C>"
        result = _safe_jsonable({"obj": _C()})
        assert "obj" in result
        assert isinstance(result["obj"], str)


class TestAuditLoggerEmit:
    @pytest.mark.asyncio
    async def test_emit_writes_row_and_returns_none(self, db_session: AsyncSession):
        u = uuid.uuid4()
        ts = datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc)
        await AuditLogger.emit(
            db_session,
            action="asset.create",
            ip_address="127.0.0.1",
            user_id=u,
            details={"asset_type": "domain", "asset_value": "example.com"},
            timestamp=ts,
        )
        rows = (await db_session.execute(select(AuditLog))).scalars().all()
        assert len(rows) == 1
        row = rows[0]
        assert row.action == "asset.create"
        assert row.ip_address == "127.0.0.1"
        assert row.user_id == u
        assert row.details["asset_value"] == "example.com"
        assert row.timestamp is not None
        assert row.timestamp.year == 2026 and row.timestamp.month == 9 and row.timestamp.day == 5

    @pytest.mark.asyncio
    async def test_emit_unrecognized_action_still_persists(self, db_session: AsyncSession):
        await AuditLogger.emit(
            db_session,
            action="weird.custom.action",
            ip_address="5.5.5.5",
            user_id=None,
            details={},
        )
        rows = (await db_session.execute(select(AuditLog).where(AuditLog.action == "weird.custom.action"))).scalars().all()
        assert len(rows) == 1

    @pytest.mark.asyncio
    async def test_emit_bad_user_id_sets_none(self, db_session: AsyncSession):
        await AuditLogger.emit(
            db_session, action="asset.list", ip_address="4.4.4.4",
            user_id="not-a-uuid", details={},
        )
        row = (await db_session.execute(select(AuditLog))).scalars().one()
        assert row.user_id is None

    @pytest.mark.asyncio
    async def test_emit_ip_none_defaults_unknown(self, db_session: AsyncSession):
        await AuditLogger.emit(
            db_session, action="asset.delete", ip_address=None, details={},
        )
        row = (await db_session.execute(select(AuditLog))).scalars().one()
        assert row.ip_address == "unknown"

    @pytest.mark.asyncio
    async def test_emit_whitespace_ip_becomes_unknown(self, db_session: AsyncSession):
        await AuditLogger.emit(
            db_session, action="asset.delete", ip_address="   ", details={},
        )
        row = (await db_session.execute(select(AuditLog))).scalars().one()
        assert row.ip_address == "unknown"

    @pytest.mark.asyncio
    async def test_emit_catches_db_write_failure_via_rollback(self, db_session: AsyncSession, monkeypatch):
        bad_db = MagicMock()
        bad_db.add = MagicMock()
        bad_db.commit = AsyncMock(side_effect=RuntimeError("boom"))
        bad_db.rollback = AsyncMock()

        error_calls = []

        def fake_error(*args, **kwargs):
            error_calls.append((args, kwargs))

        from app.core import audit as audit_mod
        monkeypatch.setattr(audit_mod.log, "error", fake_error)

        await AuditLogger.emit(
            bad_db, action="asset.create", ip_address="10.0.0.1", details={},
        )
        bad_db.rollback.assert_awaited_once()
        assert len(error_calls) == 1

    @pytest.mark.asyncio
    async def test_stdout_event_has_exact_5_mandatory_keys(self, db_session: AsyncSession, monkeypatch):
        stdout_calls = []

        def fake_info(event_name, **kwargs):
            stdout_calls.append(dict(kwargs))

        from app.core import audit as audit_mod
        monkeypatch.setattr(audit_mod.log, "info", fake_info)

        await AuditLogger.emit(
            db_session,
            action="auth.logout",
            ip_address="2.2.2.2",
            user_id=str(uuid.uuid4()),
            details={"email": "a@b.com"},
            timestamp=datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc),
        )
        assert len(stdout_calls) == 1, f"stdout_calls len={len(stdout_calls)}"
        ev = stdout_calls[0]
        assert set(ev.keys()) == {"timestamp", "user_id", "action", "ip_address", "details"}, (
            f"unexpected keys: {set(ev.keys())}"
        )
        assert ev["action"] == "auth.logout"
        assert ev["ip_address"] == "2.2.2.2"
        assert ev["details"]["email"] == "a@b.com"
        assert ev["timestamp"].startswith("2026-09-05T12:00:00")


class TestAuditLoggerBackground:
    @pytest.mark.asyncio
    async def test_emit_background_writes_row_with_new_session(self, db_session: AsyncSession):
        await AuditLogger.emit_background(
            db_session, action="asset.view", ip_address="1.2.3.4", details={"asset_id": "x"},
        )
        rows = (await db_session.execute(select(AuditLog))).scalars().all()
        assert len(rows) == 1
        row = rows[0]
        assert row.action == "asset.view"
        assert row.ip_address == "1.2.3.4"
        assert row.details["asset_id"] == "x"
        # The row carries the chain link in its own columns, and the same values
        # ride along in `details` so the exported stdout line and the row can be
        # compared without guessing.
        assert set(row.details) == {"asset_id", "audit_hash", "audit_prev_hash", "audit_key_id"}
        assert row.entry_hash == row.details["audit_hash"]
        assert row.prev_hash == row.details["audit_prev_hash"]
        assert row.key_id == row.details["audit_key_id"]
        assert row.seq is not None

    @pytest.mark.asyncio
    async def test_emit_background_is_independent_of_caller_session(self, db_session: AsyncSession):
        await db_session.rollback()
        await AuditLogger.emit_background(
            db_session, action="report.list", ip_address="9.9.9.9", details={"n": 1},
        )
        rows = (await db_session.execute(select(AuditLog).where(AuditLog.action == "report.list"))).scalars().all()
        assert len(rows) == 1
        assert rows[0].details["n"] == 1
        # The chain link is written even though the caller's transaction was
        # rolled back: `emit_background` commits in a session of its own, which is
        # exactly why this entry survived the rollback at all.
        assert len(rows[0].entry_hash) == 64
        assert rows[0].seq is not None
