import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text

from app.core.audit import AuditLogger
from app.core.audit_chain import verify
from app.core.config import settings
from app.models.audit import AuditLog
from app.services.audit_archive import archive_prefix, verify_archive


async def entries(db, count=3):
    for index in range(count):
        await AuditLogger.emit(db, action="asset.view", ip_address="internal:test", details={"index": index}, timestamp=datetime.now(timezone.utc) - timedelta(days=400), require_persistence=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("where", ["seq >= 2", "seq >= 1"])
async def test_suffix_deletion_is_detected_and_append_refused(db_session, where):
    await entries(db_session)
    await db_session.execute(text(f"DELETE FROM drp_audit_logs WHERE {where}"))
    await db_session.commit()
    assert not (await verify(db_session, full=True)).ok
    await db_session.rollback()
    with pytest.raises(Exception, match="not persisted"):
        await AuditLogger.emit(db_session, action="asset.view", ip_address="test", require_persistence=True)


@pytest.mark.asyncio
async def test_full_check_revisits_old_verified_rows(db_session):
    await entries(db_session)
    assert (await verify(db_session, full=True)).ok
    await db_session.execute(text("UPDATE drp_audit_logs SET action='asset.delete' WHERE seq=1"))
    await db_session.commit()
    assert not (await verify(db_session, full=True)).ok


@pytest.mark.asyncio
async def test_archive_round_trip_and_tamper_detection(db_session, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "AUDIT_ARCHIVE_DIR", str(tmp_path))
    await entries(db_session)
    result = await archive_prefix(db_session, cutoff=datetime.now(timezone.utc), limit=10)
    assert result["deleted"] == 3
    manifest = next(tmp_path.glob("*.manifest.json"))
    assert verify_archive(manifest)["row_count"] == 3
    from scripts.audit_archive import main
    assert main(["--verify", str(manifest)]) == 0
    assert (await verify(db_session, full=True)).ok
    ndjson = next(tmp_path.glob("*.ndjson"))
    lines = ndjson.read_text(encoding="utf-8").splitlines()
    assert set(json.loads(lines[0])) == {"timestamp", "user_id", "action", "ip_address", "details"}
    ndjson.write_text("\n".join(lines[:-1]), encoding="utf-8")
    with pytest.raises(ValueError):
        verify_archive(manifest)
    assert main(["--verify", str(manifest)]) == 1


@pytest.mark.asyncio
async def test_missing_archive_or_hold_never_deletes(db_session, monkeypatch):
    await entries(db_session)
    monkeypatch.setattr(settings, "AUDIT_ARCHIVE_DIR", "")
    with pytest.raises(ValueError):
        await archive_prefix(db_session, cutoff=datetime.now(timezone.utc), limit=10)
    assert len(list((await db_session.execute(select(AuditLog))).scalars())) == 3


@pytest.mark.asyncio
async def test_retention_only_deletes_contiguous_expired_prefix(db_session, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "AUDIT_ARCHIVE_DIR", str(tmp_path))
    await entries(db_session, 1)
    await AuditLogger.emit(db_session, action="asset.view", ip_address="test", require_persistence=True)
    await entries(db_session, 1)
    result = await archive_prefix(db_session, cutoff=datetime.now(timezone.utc) - timedelta(days=365), limit=10)
    assert result["deleted"] == 1
    assert [row.seq for row in (await db_session.execute(select(AuditLog).order_by(AuditLog.seq))).scalars()] == [2, 3]
    assert (await verify(db_session, full=True)).ok
