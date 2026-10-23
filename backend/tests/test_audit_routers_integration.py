from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditLogger
from app.core.audit_chain import chain_state
from app.core.config import settings
from app.models.audit import AuditArchive, AuditLog
from app.schemas.asset import AssetCreate

INTEGRITY = "/api/v1/audit/integrity"


async def _emit(db, *, action: str, user_id=None, details=None):
    """One signed audit row, the same writer the platform uses."""
    await AuditLogger.emit(
        db, action=action, ip_address="203.0.113.10", user_id=user_id, details=details or {}
    )
    return (
        await db.execute(
            select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.seq.desc())
        )
    ).scalars().first()


@pytest.mark.asyncio
async def test_login_success_writes_audit_row(
    client,
    db_session: AsyncSession,
):
    from app.core.security import hash_password
    from app.models.user import User

    u = User(
        email="audit-login@example.com",
        password_hash=hash_password("Password123!"),
        role="analyst",
        is_active=True,
    )
    db_session.add(u)
    await db_session.commit()
    await db_session.refresh(u)

    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "audit-login@example.com", "password": "Password123!"},
    )
    assert r.status_code == 200, r.text

    rows = (await db_session.execute(
        select(AuditLog).where(AuditLog.action == "auth.login.success")
    )).scalars().all()
    assert len(rows) == 1
    assert rows[0].user_id == u.id
    assert rows[0].details.get("email") == "audit-login@example.com"


@pytest.mark.asyncio
async def test_logout_writes_audit_row_when_authenticated(
    client,
    db_session: AsyncSession,
    auth_headers_analyst,
    analyst_user,
):
    r = await client.post("/api/v1/auth/logout", headers=auth_headers_analyst)
    assert r.status_code == 204

    rows = (await db_session.execute(
        select(AuditLog).where(AuditLog.action == "auth.logout")
    )).scalars().all()
    assert len(rows) == 1
    assert rows[0].user_id == analyst_user.id


@pytest.mark.asyncio
async def test_asset_create_update_delete_audit_integration(
    client,
    db_session: AsyncSession,
    auth_headers_analyst,
    admin_user,
    auth_headers_admin,
):
    create = AssetCreate(
        asset_type="domain",
        asset_value="audit-domain.example.com",
        criticality="medium",
        is_active=True,
    )
    r = await client.post(
        "/api/v1/assets",
        json=create.model_dump(mode="json"),
        headers=auth_headers_analyst,
    )
    assert r.status_code == 201, r.text
    data = r.json()
    asset_id = data["id"]

    r = await client.patch(
        f"/api/v1/assets/{asset_id}",
        json={"description": "patched"},
        headers=auth_headers_analyst,
    )
    assert r.status_code == 200, r.text

    r = await client.delete(
        f"/api/v1/assets/{asset_id}",
        headers=auth_headers_admin,
    )
    assert r.status_code == 204

    rows = (await db_session.execute(
        select(AuditLog).where(
            AuditLog.action.in_(["asset.create", "asset.update", "asset.delete"])
        ).order_by(AuditLog.timestamp.asc())
    )).scalars().all()
    actions = [r.action for r in rows]
    assert actions == ["asset.create", "asset.update", "asset.delete"]
    assert rows[0].details["asset_value"] == "audit-domain.example.com"
    assert "changed_fields" in rows[1].details
    assert rows[2].details["asset_id"] == asset_id


@pytest.mark.asyncio
async def test_asset_list_view_actions_write_audit(
    client,
    db_session: AsyncSession,
    auth_headers_viewer,
    seeded_asset,
):
    r_list = await client.get("/api/v1/assets", headers=auth_headers_viewer)
    assert r_list.status_code == 200, r_list.text

    r_view = await client.get(f"/api/v1/assets/{seeded_asset.id}", headers=auth_headers_viewer)
    assert r_view.status_code == 200, r_view.text

    import asyncio
    pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    await asyncio.gather(*pending, return_exceptions=True)
    await asyncio.sleep(0.05)

    rows = (await db_session.execute(
        select(AuditLog).where(
            AuditLog.action.in_(["asset.list", "asset.view"])
        )
    )).scalars().all()
    actions = sorted(r.action for r in rows)
    assert "asset.list" in actions
    assert "asset.view" in actions


@pytest.mark.asyncio
async def test_settings_update_writes_audit_row(
    client,
    db_session: AsyncSession,
    auth_headers_admin,
):
    r = await client.put(
        "/api/v1/settings",
        json={"smtp_port": 2525, "alert_recipient_email": "soc@example.com"},
        headers=auth_headers_admin,
    )
    assert r.status_code == 200, r.text
    rows = (await db_session.execute(
        select(AuditLog).where(AuditLog.action == "settings.update")
    )).scalars().all()
    assert len(rows) == 1
    assert set(rows[0].details["updated_fields"]) == {"smtp_port", "alert_recipient_email"}


async def _settings_update_rows(db_session: AsyncSession) -> list[AuditLog]:
    return list(
        (
            await db_session.execute(
                select(AuditLog)
                .where(AuditLog.action == "settings.update")
                .order_by(AuditLog.timestamp.asc())
            )
        )
        .scalars()
        .all()
    )


@pytest.mark.asyncio
async def test_settings_update_records_the_transition_not_only_the_field_name(
    client, db_session: AsyncSession, auth_headers_admin
):
    """The row has to answer *what the setting became*, not just which field moved.

    A rule written against `updated_fields` can see that an alert threshold was
    touched; it cannot see whether paging moved from 80 to 90 or from 80 to 10,
    which is the difference between a tuning change and an outage. The stored
    values are what an investigator compares against, and an earlier save may
    already have overwritten the first half of the pair.
    """
    first = await client.put(
        "/api/v1/settings",
        json={"alert_confidence_direct": 80, "alert_confidence_digest": 50},
        headers=auth_headers_admin,
    )
    assert first.status_code == 200, first.text
    second = await client.put(
        "/api/v1/settings",
        json={"alert_confidence_direct": 90},
        headers=auth_headers_admin,
    )
    assert second.status_code == 200, second.text

    latest = (await _settings_update_rows(db_session))[-1]
    assert latest.details["changes"]["alert_confidence_direct"] == {"from": 80, "to": 90}
    assert "alert_confidence_digest" not in latest.details["changes"]
    assert latest.details["updated_fields"] == ["alert_confidence_direct"]


@pytest.mark.asyncio
async def test_a_settings_save_that_changes_nothing_records_no_change(
    client, db_session: AsyncSession, auth_headers_admin
):
    """`updated_fields` is the difference, not the submission.

    The page sends back the whole form on every save, so a row that named every
    submitted field claimed a change on every visit — the same defect the breach
    triage row had (AUD-029). A no-op save is still a save (it carries a version
    and an actor), but it changed nothing.
    """
    await client.put(
        "/api/v1/settings",
        json={"alert_no_channel_retry_hours": 4},
        headers=auth_headers_admin,
    )
    repeated = await client.put(
        "/api/v1/settings",
        json={"alert_no_channel_retry_hours": 4},
        headers=auth_headers_admin,
    )
    assert repeated.status_code == 200, repeated.text

    latest = (await _settings_update_rows(db_session))[-1]
    assert latest.details["updated_fields"] == []
    assert latest.details["changes"] == {}


@pytest.mark.asyncio
async def test_a_secret_change_is_recorded_without_the_secret(
    client, db_session: AsyncSession, auth_headers_admin
):
    """Presence, not value: the trail is shipped to a SIEM.

    A credential that reached a `details` value would put the thing the platform
    was trusted to hold onto a search index for the whole retention period (the
    same rule AUD-009 enforces for provider errors). What a reader needs is that
    it changed and whether it is now set or cleared.
    """
    secret = "smtp-password-that-must-not-be-logged"
    response = await client.put(
        "/api/v1/settings",
        json={"smtp_password": secret},
        headers=auth_headers_admin,
    )
    assert response.status_code == 200, response.text

    latest = (await _settings_update_rows(db_session))[-1]
    assert latest.details["changes"]["smtp_password"] == {"from": "unset", "to": "set"}
    assert secret not in str(latest.details)


@pytest.mark.asyncio
async def test_module_update_records_both_ends_of_a_rename(
    client, db_session: AsyncSession, auth_headers_admin
):
    """A rename row names the old label as well as the new one.

    Findings carry the module id, and the label is how an operator reads that id
    on every page — so a trail that records only the new name cannot answer "what
    was this module called when the finding in it arrived".
    """
    declared = await client.post(
        "/api/v1/modules",
        headers=auth_headers_admin,
        json={
            "id": "s21_probe",
            "label": "Before the rename",
            "description": "a module the audit suite declares and renames",
            "fields": {"repository": {"type": "str", "required": True}},
            "dedup_fields": ["repository"],
            "asset_types": ["domain"],
        },
    )
    assert declared.status_code == 201, declared.text

    renamed = await client.patch(
        "/api/v1/modules/s21_probe",
        headers=auth_headers_admin,
        json={"label": "After the rename"},
    )
    assert renamed.status_code == 200, renamed.text

    row = (
        await db_session.execute(
            select(AuditLog)
            .where(AuditLog.action == "module.updated")
            .order_by(AuditLog.timestamp.asc())
        )
    ).scalars().all()[-1]
    assert row.details["changes"] == {
        "label": {"from": "Before the rename", "to": "After the rename"}
    }


@pytest.mark.asyncio
async def test_dashboard_view_writes_audit(
    client,
    db_session: AsyncSession,
    auth_headers_viewer,
):
    r = await client.get("/api/v1/dashboard/stats", headers=auth_headers_viewer)
    assert r.status_code == 200, r.text

    import asyncio
    pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    await asyncio.gather(*pending, return_exceptions=True)
    await asyncio.sleep(0.05)

    rows = (await db_session.execute(
        select(AuditLog).where(AuditLog.action == "dashboard.view")
    )).scalars().all()
    assert len(rows) == 1
    assert "total_assets" in rows[0].details
    assert "total_breaches" in rows[0].details


@pytest.mark.asyncio
async def test_report_generate_writes_audit(
    client,
    db_session: AsyncSession,
    auth_headers_analyst,
    monkeypatch,
):
    from app.tasks import report_tasks
    fake_result = MagicMock()
    fake_result.id = "task-report-123"
    with patch.object(report_tasks.generate_report_task, "apply_async", side_effect=RuntimeError("celery not available")):
        r = await client.post(
            "/api/v1/reports/generate",
            json={"report_name": "Audit Report One"},
            headers=auth_headers_analyst,
        )
    assert r.status_code == 503, r.text
    rows = (await db_session.execute(
        select(AuditLog).where(AuditLog.action == "report.generate")
    )).scalars().all()
    assert len(rows) == 1
    assert rows[0].details["report_name"] == "Audit Report One"
    assert rows[0].details["schedule_ok"] is False


@pytest.mark.asyncio
async def test_phishing_scan_shodan_writes_audit_when_no_connector(
    client,
    db_session: AsyncSession,
    auth_headers_analyst,
):
    # No connector registered: the endpoint still answers 202 with a clear
    # "no_connector" status and writes the audit event.
    r = await client.post("/api/v1/phishing/scan/shodan", headers=auth_headers_analyst)
    assert r.status_code == 202, r.text
    assert r.json()["status"] == "no_connector"

    rows = (await db_session.execute(
        select(AuditLog).where(AuditLog.action == "phishing.scan.shodan.start")
    )).scalars().all()
    assert len(rows) == 1
    assert rows[0].details["status"] == "no_connector"


@pytest.mark.asyncio
async def test_integrity_reports_the_chain_state_and_records_the_view(
    client,
    db_session: AsyncSession,
    auth_headers_admin,
    admin_user,
):
    """The status endpoint: what the chain holds, and the fact that it was read.

    The numbers the response carries are seeded here through the real writer and
    the real chain state, not by patching `chain_state`: an operator reads this
    page to decide whether audit history is intact, so the test has to fail if
    the endpoint stops reading the store it claims to read.
    """
    first = await _emit(
        db_session, action="asset.create", user_id=admin_user.id, details={"asset": "alpha.example.com"}
    )
    last = await _emit(
        db_session, action="asset.delete", user_id=None, details={"asset": "beta.example.com"}
    )
    # Read before the commit below expires them: the fixture session does not
    # lazy-load a detached attribute inside an async test.
    first_seq, last_seq = first.seq, last.seq
    first_hash, last_hash = first.entry_hash, last.entry_hash

    state = await chain_state(db_session)
    state.full_verify_upper_seq = last_seq
    state.full_verify_upper_hash = last_hash
    state.full_verify_cursor = first_seq
    state.full_verify_cursor_hash = first_hash
    state.last_full_verified_at = datetime(2026, 10, 19, 3, 0, tzinfo=timezone.utc)
    state.last_failure_seq = 7
    state.last_failure_reason = "hash mismatch"
    state.last_verified_seq = first_seq
    state.last_verified_at = datetime(2026, 10, 19, 2, 0, tzinfo=timezone.utc)
    state.retired_through_seq = 0
    committed_seq = int(state.committed_seq or 0)
    await db_session.commit()

    r = await client.get(INTEGRITY, headers=auth_headers_admin)
    assert r.status_code == 200, r.text
    body = r.json()

    assert set(body) == {
        "full_verification",
        "committed",
        "archive",
        "retained",
        "retired",
        "last_verification",
        "keys",
    }
    # Every block the page prints, level by level: the seven top-level keys are
    # not enough when a nested field can vanish. `committed` and `retired` share
    # one shape on purpose, and both `at` fields are checked below in their own
    # spelling — the composer passes one through and converts the other.
    assert set(body["full_verification"]) == {
        "upper_seq",
        "cursor",
        "in_progress",
        "at",
        "failure_seq",
        "failure_reason",
    }
    assert set(body["committed"]) == {"through_seq", "tip_hash"}
    assert set(body["retired"]) == {"through_seq", "tip_hash"}
    assert set(body["archive"]) == {"configured", "hold", "last_seq", "retired"}
    assert set(body["retained"]) == {"rows", "first_seq", "last_seq"}
    assert set(body["last_verification"]) == {"through_seq", "at"}
    assert set(body["keys"]) == {"configured"}
    # Counted before the request wrote its own row: the aggregate answers "how
    # much history is retained", not "how much after this page view".
    assert body["retained"] == {"rows": 2, "first_seq": first_seq, "last_seq": last_seq}
    assert body["retired"] == {"through_seq": 0, "tip_hash": None}
    assert body["full_verification"]["upper_seq"] == last_seq
    assert body["full_verification"]["cursor"] == first_seq
    assert body["full_verification"]["in_progress"] is True
    assert body["full_verification"]["failure_seq"] == 7
    assert body["full_verification"]["failure_reason"] == "hash mismatch"
    assert str(body["full_verification"]["at"]).startswith("2026-10-19T03:00:00")
    assert body["last_verification"]["through_seq"] == first_seq
    assert body["last_verification"]["at"].startswith("2026-10-19T02:00:00")
    assert body["committed"]["through_seq"] >= committed_seq
    assert body["archive"]["configured"] == bool(settings.AUDIT_ARCHIVE_DIR)
    assert body["archive"]["hold"] == settings.AUDIT_RETENTION_HOLD
    assert body["archive"]["last_seq"] is None
    assert body["archive"]["retired"] is False
    assert body["keys"] == {"configured": len(settings.audit_chain_keys)}

    rows = (
        await db_session.execute(
            select(AuditLog)
            .where(AuditLog.action == "audit.integrity.view")
            .order_by(AuditLog.seq.desc())
        )
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].user_id == admin_user.id
    assert rows[0].details["retained_rows"] == 2
    assert rows[0].details["retired_through_seq"] == 0
    # The view wrote into the same chain it reports on.
    assert rows[0].seq > last_seq
    assert rows[0].prev_hash == last_hash
    assert body["committed"]["through_seq"] == rows[0].seq
    assert body["committed"]["tip_hash"] == rows[0].entry_hash


@pytest.mark.asyncio
async def test_integrity_reports_the_archive_it_retains_and_its_retirement(
    client,
    db_session: AsyncSession,
    auth_headers_admin,
    monkeypatch,
    tmp_path,
):
    """An archive that exists is reported with its range, and marked once retired."""
    monkeypatch.setattr(settings, "AUDIT_ARCHIVE_DIR", str(tmp_path))
    row = await _emit(db_session, action="asset.create", details={"asset": "alpha.example.com"})
    seq = row.seq

    db_session.add(
        AuditArchive(
            first_seq=1,
            last_seq=seq,
            content_hash="a" * 64,
            manifest_name="archive-0001.jsonl",
            created_at=datetime(2026, 10, 1, 0, 0, tzinfo=timezone.utc),
            retired_at=None,
        )
    )
    await db_session.commit()

    r = await client.get(INTEGRITY, headers=auth_headers_admin)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["archive"]["configured"] is True
    assert body["archive"]["last_seq"] == seq
    assert body["archive"]["retired"] is False
    # Nothing has verified this chain yet, so the read reports "never" rather
    # than inventing a timestamp.
    assert body["last_verification"] == {"through_seq": 0, "at": None}

    archive = (await db_session.execute(select(AuditArchive))).scalar_one()
    archive.retired_at = datetime(2026, 10, 2, 0, 0, tzinfo=timezone.utc)
    await db_session.commit()

    r = await client.get(INTEGRITY, headers=auth_headers_admin)
    assert r.status_code == 200, r.text
    assert r.json()["archive"]["retired"] is True
    assert r.json()["archive"]["last_seq"] == seq


@pytest.mark.asyncio
async def test_integrity_reports_an_empty_chain_as_zero_rather_than_null(
    client,
    db_session: AsyncSession,
    auth_headers_admin,
):
    """A fresh installation has no history: the aggregates answer 0, not null.

    This is the state an operator sees on day one and after a full retention
    sweep, and it is the one where an ``int(aggregate[1] or 0)`` that was written
    carelessly would surface as a JSON ``null`` a dashboard then sums.
    """
    r = await client.get(INTEGRITY, headers=auth_headers_admin)
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["retained"] == {"rows": 0, "first_seq": 0, "last_seq": 0}
    assert body["retired"] == {"through_seq": 0, "tip_hash": None}
    assert body["committed"]["through_seq"] == 1
    assert body["last_verification"] == {"through_seq": 0, "at": None}


@pytest.mark.asyncio
async def test_integrity_reports_the_prefix_retention_has_retired(
    client,
    db_session: AsyncSession,
    auth_headers_admin,
):
    """After retention, the gap at the start of the chain is stated, not implied."""
    rows = [
        await _emit(db_session, action="asset.create", details={"asset": f"a{index}.example.com"})
        for index in range(3)
    ]
    seqs = [row.seq for row in rows]
    hashes = [row.entry_hash for row in rows]
    retired_tip = hashes[1]

    # The sweep deletes by age and records where it stopped; the chain state
    # carries that watermark, the rows are gone.
    await db_session.execute(delete(AuditLog).where(AuditLog.seq <= seqs[1]))
    state = await chain_state(db_session)
    state.retired_through_seq = seqs[1]
    state.retired_tip_hash = retired_tip
    await db_session.commit()

    r = await client.get(INTEGRITY, headers=auth_headers_admin)
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["retired"] == {"through_seq": seqs[1], "tip_hash": retired_tip}
    # The surviving prefix now starts after the retired watermark, and the count
    # is of what is retained, not of what was ever written.
    assert body["retained"] == {"rows": 1, "first_seq": seqs[2], "last_seq": seqs[2]}

    recorded = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "audit.integrity.view")
        )
    ).scalars().one()
    assert recorded.details["retired_through_seq"] == seqs[1]
    assert recorded.details["retained_rows"] == 1


@pytest.mark.asyncio
async def test_integrity_is_refused_to_non_admins_and_records_no_view(
    client,
    db_session: AsyncSession,
    auth_headers_analyst,
    auth_headers_viewer,
):
    """The chain's status is an operator surface: analysts and viewers get 403."""
    for headers in (auth_headers_analyst, auth_headers_viewer):
        r = await client.get(INTEGRITY, headers=headers)
        assert r.status_code == 403, r.text

    views = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "audit.integrity.view")
        )
    ).scalars().all()
    assert views == []
    # The refusal is still recorded, which is what makes a probe of this surface
    # visible to whoever reads the trail.
    denied = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "authz.denied")
        )
    ).scalars().all()
    assert len(denied) >= 1
