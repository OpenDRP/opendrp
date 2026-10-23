"""The refusals behind archive-before-retire.

`test_audit_archive_reliability.py` pins the round trip and the tamper that a
truncated ndjson produces. This file pins the rest of the contract, because the
archive is the only copy of the audit history retention is allowed to delete:

* an artifact is immutable once written, including when a second writer races it;
* a manifest is believed only when its own signature, name and version agree;
* a data file is believed only when every line is the five-field envelope and
  links to the one before it;
* and a sweep is refused when the chain state, the receipt or the prefix no
  longer describes the rows it is about to retire.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import delete, select, update

from app.core.audit import AuditLogger
from app.core.audit_chain import chain_keys
from app.core.config import settings
from app.models.audit import AuditArchive, AuditChain, AuditLog
from app.services import audit_archive as archive_module
from app.services.audit_archive import archive_prefix, canonical, finalize, verify_archive


async def entries(db, count: int = 3) -> None:
    """Old, signed audit rows: the prefix a sweep may retire."""
    for index in range(count):
        await AuditLogger.emit(
            db,
            action="asset.view",
            ip_address="internal:test",
            details={"index": index},
            timestamp=datetime.now(timezone.utc) - timedelta(days=400),
            require_persistence=True,
        )


def _resign(manifest: dict) -> bytes:
    """A manifest body signed with the configured key, as the writer does."""
    body = {key: value for key, value in manifest.items() if key != "signature"}
    signature = hmac.new(chain_keys()[0].encode(), canonical(body), hashlib.sha256).hexdigest()
    return canonical({**body, "signature": signature})


def _symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):  # pragma: no cover - platform
        pytest.skip("symlinks are not available in this environment")


# ---------------------------------------------------------------------------
# The artifact on disk
# ---------------------------------------------------------------------------


def test_an_artifact_already_on_disk_is_never_rewritten(tmp_path):
    """Finalization is "write once": a second writer either agrees or is refused."""
    target = tmp_path / "audit-1-3.ndjson"
    finalize(target, b"one\n")
    assert target.read_bytes() == b"one\n"

    finalize(target, b"one\n")  # the same bytes after a crash: reuse, not rewrite
    assert target.read_bytes() == b"one\n"

    with pytest.raises(ValueError, match="collision or corruption"):
        finalize(target, b"two\n")
    assert target.read_bytes() == b"one\n"

    link = tmp_path / "linked.ndjson"
    _symlink(link, target)
    with pytest.raises(ValueError, match="collision or corruption"):
        finalize(link, b"one\n")


@pytest.mark.parametrize("identical", [True, False])
def test_a_second_writer_that_wins_the_link_race_is_still_checked(tmp_path, monkeypatch, identical):
    """``os.link`` is exclusive, and losing it is not the same as agreeing.

    A concurrent sweeper that created the name between our check and our link is
    either the same artifact (crash recovery) or a different one (an archive that
    must not be silently replaced), and the code has to tell those apart.
    """
    target = tmp_path / "audit-1-3.ndjson"

    def racing_link(_source, destination):
        Path(destination).write_bytes(b"one\n" if identical else b"other\n")
        raise FileExistsError

    monkeypatch.setattr(os, "link", racing_link)
    if identical:
        finalize(target, b"one\n")
        assert target.read_bytes() == b"one\n"
    else:
        with pytest.raises(ValueError, match="Archive collision"):
            finalize(target, b"one\n")


def test_an_artifact_that_appears_while_the_temporary_file_is_open_is_refused(tmp_path, monkeypatch):
    """The write is not atomic by itself: the re-check before linking is what is.

    A sweeper killed mid-write leaves only the temporary file, and the next run
    reuses the finalized name. The window this covers is the one where the name
    exists *after* the first check — an artifact the earlier run finished writing.
    """
    target = tmp_path / "audit-1-3.ndjson"
    real_mkstemp = tempfile.mkstemp

    def mkstemp_then_lose_the_race(*args, **kwargs):
        descriptor, name = real_mkstemp(*args, **kwargs)
        target.write_bytes(b"other\n")
        return descriptor, name

    monkeypatch.setattr(tempfile, "mkstemp", mkstemp_then_lose_the_race)
    with pytest.raises(ValueError, match="Archive collision"):
        finalize(target, b"one\n")


# ---------------------------------------------------------------------------
# What the manifest is allowed to say
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_manifest_is_believed_only_with_its_own_signature_name_and_version(db_session, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "AUDIT_ARCHIVE_DIR", str(tmp_path))
    await entries(db_session)
    assert (await archive_prefix(db_session, cutoff=datetime.now(timezone.utc), limit=10))["deleted"] == 3
    manifest_path = next(tmp_path.glob("*.manifest.json"))
    original = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert verify_archive(manifest_path)["row_count"] == 3

    forged = dict(original)
    forged["signature"] = "0" * 64
    manifest_path.write_text(json.dumps(forged), encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid archive manifest signature"):
        verify_archive(manifest_path)

    # A signature is not enough on its own: the fields it covers are fixed too, so
    # a manifest that re-signs a different version or a different file name is
    # still not an archive this platform wrote.
    manifest_path.write_text(_resign({**original, "version": 2}).decode("utf-8"), encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid archive name or version"):
        verify_archive(manifest_path)

    manifest_path.write_bytes(_resign({**original, "file": "audit-1-3-other.ndjson"}))
    with pytest.raises(ValueError, match="Invalid archive name or version"):
        verify_archive(manifest_path)

    renamed = tmp_path / "renamed.manifest.json"
    manifest_path.write_bytes(_resign(original))
    manifest_path.rename(renamed)
    with pytest.raises(ValueError, match="Invalid archive name or version"):
        verify_archive(renamed)


@pytest.mark.asyncio
async def test_a_symlinked_manifest_or_data_file_is_refused(db_session, monkeypatch, tmp_path):
    """A symlink is how an archive is made to point somewhere retention did not write."""
    monkeypatch.setattr(settings, "AUDIT_ARCHIVE_DIR", str(tmp_path))
    await entries(db_session)
    await archive_prefix(db_session, cutoff=datetime.now(timezone.utc), limit=10)
    manifest_path = next(tmp_path.glob("*.manifest.json"))
    data_path = next(tmp_path.glob("*.ndjson"))

    linked_manifest = tmp_path / "linked.manifest.json"
    _symlink(linked_manifest, manifest_path)
    with pytest.raises(ValueError, match="Symlink manifest refused"):
        verify_archive(linked_manifest)

    moved = tmp_path / "real.ndjson"
    data_path.rename(moved)
    _symlink(data_path, moved)
    with pytest.raises(ValueError, match="Symlink archive refused"):
        verify_archive(manifest_path)


@pytest.mark.asyncio
async def test_a_line_that_is_not_the_envelope_or_does_not_link_is_refused(db_session, monkeypatch, tmp_path):
    """Every line is an audit event, and every event is the one before it plus one."""
    monkeypatch.setattr(settings, "AUDIT_ARCHIVE_DIR", str(tmp_path))
    await entries(db_session)
    await archive_prefix(db_session, cutoff=datetime.now(timezone.utc), limit=10)
    manifest_path = next(tmp_path.glob("*.manifest.json"))
    data_path = next(tmp_path.glob("*.ndjson"))
    original_lines = data_path.read_text(encoding="utf-8").splitlines()

    extra_key = json.loads(original_lines[0])
    extra_key["injected"] = "field"
    data_path.write_text("\n".join([json.dumps(extra_key), *original_lines[1:]]) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid audit envelope"):
        verify_archive(manifest_path)

    broken_chain = json.loads(original_lines[0])
    broken_chain["details"]["audit_hash"] = "0" * 64
    data_path.write_text("\n".join([json.dumps(broken_chain), *original_lines[1:]]) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Archive chain does not verify"):
        verify_archive(manifest_path)


# ---------------------------------------------------------------------------
# What stops the sweep
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_hold_switch_archives_and_deletes_nothing(db_session, monkeypatch, tmp_path):
    """An operator pulling the brake must not have to empty a directory to use it."""
    monkeypatch.setattr(settings, "AUDIT_ARCHIVE_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "AUDIT_RETENTION_HOLD", True)
    await entries(db_session)

    assert await archive_prefix(db_session, cutoff=datetime.now(timezone.utc), limit=10) == {"deleted": 0, "hold": True}
    assert list(tmp_path.iterdir()) == []
    assert len(list((await db_session.execute(select(AuditLog))).scalars())) == 3


@pytest.mark.asyncio
async def test_a_chunk_the_full_pass_has_not_read_is_left_alone(db_session, monkeypatch, tmp_path):
    """A resumable full verification owns the rows it has not read yet.

    Retiring them would delete the positions the next chunk of the full pass is
    about to verify, and the pass would report a breach where retention had done
    exactly what it was told.
    """
    monkeypatch.setattr(settings, "AUDIT_ARCHIVE_DIR", str(tmp_path))
    await entries(db_session)
    await db_session.execute(
        update(AuditChain).values(full_verify_upper_hash="f" * 64, full_verify_cursor=0)
    )
    await db_session.commit()
    db_session.expire_all()

    assert await archive_prefix(db_session, cutoff=datetime.now(timezone.utc), limit=10) == {"deleted": 0}
    assert list(tmp_path.iterdir()) == []
    assert len(list((await db_session.execute(select(AuditLog))).scalars())) == 3


@pytest.mark.asyncio
async def test_a_checkpoint_that_does_not_describe_the_rows_is_refused(db_session, monkeypatch, tmp_path):
    """The checkpoint is the writer's promise about the tip; retention trusts it first."""
    monkeypatch.setattr(settings, "AUDIT_ARCHIVE_DIR", str(tmp_path))
    await entries(db_session)
    await db_session.execute(update(AuditChain).values(committed_seq=2))
    await db_session.commit()

    with pytest.raises(ValueError, match="Committed checkpoint mismatch"):
        await archive_prefix(db_session, cutoff=datetime.now(timezone.utc), limit=10)
    assert list(tmp_path.iterdir()) == []
    assert len(list((await db_session.execute(select(AuditLog))).scalars())) == 3


@pytest.mark.asyncio
async def test_a_gap_inside_the_prefix_stops_the_sweep(db_session, monkeypatch, tmp_path):
    """A missing position is a finding, not a chunk to archive around."""
    monkeypatch.setattr(settings, "AUDIT_ARCHIVE_DIR", str(tmp_path))
    await entries(db_session)
    await db_session.execute(delete(AuditLog).where(AuditLog.seq == 2))
    await db_session.commit()

    with pytest.raises(ValueError, match="Prefix chain gap"):
        await archive_prefix(db_session, cutoff=datetime.now(timezone.utc), limit=10)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.asyncio
async def test_a_receipt_that_names_another_archive_is_refused(db_session, monkeypatch, tmp_path):
    """The receipt is what proves the bytes were durable, so it has to match them."""
    monkeypatch.setattr(settings, "AUDIT_ARCHIVE_DIR", str(tmp_path))
    await entries(db_session)
    db_session.add(
        AuditArchive(
            first_seq=1,
            last_seq=1,
            content_hash="0" * 64,
            manifest_name="audit-1-1-old.manifest.json",
            created_at=datetime.now(timezone.utc),
        )
    )
    await db_session.commit()

    with pytest.raises(ValueError, match="Archive receipt mismatch"):
        await archive_prefix(db_session, cutoff=datetime.now(timezone.utc), limit=10)
    assert len(list((await db_session.execute(select(AuditLog))).scalars())) == 3


@pytest.mark.asyncio
async def test_a_hold_raised_mid_sweep_stops_the_deletion(db_session, monkeypatch, tmp_path):
    """The brake is read again before the delete, and it wins over a half-finished run.

    An operator who sets the hold while a sweep is between "archived" and "deleted"
    asked for the history to stay; the archive on disk is harmless, and the rows
    must survive the transaction.
    """
    monkeypatch.setattr(settings, "AUDIT_ARCHIVE_DIR", str(tmp_path))
    await entries(db_session)
    real_verify = archive_module.verify_archive

    def verify_then_pull_the_brake(manifest_path):
        manifest = real_verify(manifest_path)
        # Through monkeypatch, so the brake is released when this test ends.
        monkeypatch.setattr(settings, "AUDIT_RETENTION_HOLD", True)
        return manifest

    monkeypatch.setattr(archive_module, "verify_archive", verify_then_pull_the_brake)
    with pytest.raises(ValueError, match="Archive prefix changed"):
        await archive_prefix(db_session, cutoff=datetime.now(timezone.utc), limit=10)

    assert len(list((await db_session.execute(select(AuditLog))).scalars())) == 3
    state = (await db_session.execute(select(AuditChain).execution_options(populate_existing=True))).scalar_one()
    assert state.retired_through_seq == 0
