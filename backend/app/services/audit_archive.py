"""Fail-closed archive-before-retire. Local storage is not WORM or offsite."""
import asyncio
import hashlib
import hmac
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import delete, select

from app.core.audit_chain import _acquire_write_lock, chain_key_pairs, chain_keys, chain_state, compute_entry_hash, entry_payload, key_id_for, retire
from app.core.config import settings
from app.models.audit import AuditArchive, AuditLog


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def finalize(path, content):
    if path.exists():
        if path.is_symlink() or path.read_bytes() != content:
            raise ValueError("Archive collision or corruption")
        return
    fd, name = tempfile.mkstemp(prefix=".audit-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        # Same-directory rename is atomic. Existing artifacts are immutable.
        if path.exists():
            if path.read_bytes() != content:
                raise ValueError("Archive collision")
        else:
            try:
                os.link(name, path)  # Exclusive finalization; no concurrent overwrite.
            except FileExistsError:
                if path.is_symlink() or path.read_bytes() != content:
                    raise ValueError("Archive collision")
        if os.name != "nt":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def verify_archive(manifest_path):
    path = Path(manifest_path)
    if path.is_symlink():
        raise ValueError("Symlink manifest refused")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    signature = manifest.pop("signature", None)
    candidates = [key for identity, key in chain_key_pairs() if identity == manifest.get("signing_key_id")]
    if not any(hmac.compare_digest(str(signature), hmac.new(key.encode(), canonical(manifest), hashlib.sha256).hexdigest()) for key in candidates):
        raise ValueError("Invalid archive manifest signature")
    first, last = manifest["first_seq"], manifest["last_seq"]
    expected_name = f"audit-{first}-{last}-{manifest['content_hash']}.ndjson"
    if manifest.get("version") != 1 or manifest.get("file") != expected_name or path.name != expected_name.replace(".ndjson", ".manifest.json"):
        raise ValueError("Invalid archive name or version")
    data_path = path.parent / expected_name
    if data_path.is_symlink():
        raise ValueError("Symlink archive refused")
    digest = hashlib.sha256()
    previous = manifest["prior_hash"]
    count = 0
    with data_path.open("rb") as handle:
        for raw in handle:
            digest.update(raw)
            event = json.loads(raw)
            if set(event) != {"timestamp", "user_id", "action", "ip_address", "details"}:
                raise ValueError("Invalid audit envelope")
            details = event["details"]
            pairs = [key for identity, key in chain_key_pairs() if identity == details.get("audit_key_id")]
            payload = entry_payload(timestamp=datetime.fromisoformat(event["timestamp"]), user_id=event["user_id"], action=event["action"], ip_address=event["ip_address"], details=details)
            if details.get("audit_prev_hash") != previous or not any(compute_entry_hash(key, payload=payload, prev_hash=previous, key_id=details["audit_key_id"]) == details.get("audit_hash") for key in pairs):
                raise ValueError("Archive chain does not verify")
            previous = details["audit_hash"]
            count += 1
    if digest.hexdigest() != manifest["content_hash"] or count != manifest["row_count"] or count != last - first + 1 or previous != manifest["tip_hash"]:
        raise ValueError("Archive hash, range or count mismatch")
    return manifest


async def archive_prefix(db, *, cutoff, limit):
    if settings.AUDIT_RETENTION_HOLD:
        return {"deleted": 0, "hold": True}
    root = Path(settings.AUDIT_ARCHIVE_DIR) if settings.AUDIT_ARCHIVE_DIR else None
    if root is None or not root.is_dir() or root.is_symlink():
        raise ValueError("Dedicated AUDIT_ARCHIVE_DIR is missing or unusable; retention blocked")
    await _acquire_write_lock(db)
    state = await chain_state(db)
    newest = (await db.execute(select(AuditLog.seq, AuditLog.entry_hash).order_by(AuditLog.seq.desc()).limit(1))).first()
    actual_seq = newest.seq if newest else state.retired_through_seq
    actual_tip = newest.entry_hash if newest else state.retired_tip_hash
    if actual_seq != state.committed_seq or (actual_tip or "0" * 64) != (state.committed_tip_hash or "0" * 64):
        raise ValueError("Committed checkpoint mismatch; retirement refused")
    start = int(state.retired_through_seq or 0) + 1
    previous = state.retired_tip_hash or "0" * 64
    candidates = list((await db.execute(select(AuditLog).where(AuditLog.seq >= start).order_by(AuditLog.seq).limit(limit))).scalars())
    events = []
    for row in candidates:
        if state.full_verify_upper_hash and row.seq > state.full_verify_cursor:
            break  # Do not retire a chunk the resumable full pass has not read.
        if row.timestamp.replace(tzinfo=timezone.utc) >= cutoff.replace(tzinfo=timezone.utc):
            break
        if row.seq != start + len(events) or row.prev_hash != previous:
            raise ValueError("Prefix chain gap; retirement refused")
        details = {**row.details, "audit_hash": row.entry_hash, "audit_prev_hash": row.prev_hash, "audit_key_id": row.key_id}
        events.append({"timestamp": row.timestamp.replace(tzinfo=timezone.utc).isoformat(), "user_id": str(row.user_id) if row.user_id else None, "action": row.action, "ip_address": row.ip_address, "details": details})
        previous = row.entry_hash
    if not events:
        await db.commit()
        return {"deleted": 0}
    last = start + len(events) - 1
    prior = state.retired_tip_hash or "0" * 64
    await db.commit()  # Release DB connection before filesystem work.
    content = b"".join(canonical(event) + b"\n" for event in events)
    digest = hashlib.sha256(content).hexdigest()
    name = f"audit-{start}-{last}-{digest}"
    created = datetime.now(timezone.utc)
    manifest = {"version": 1, "file": name + ".ndjson", "first_seq": start, "last_seq": last, "row_count": len(events), "prior_hash": prior, "tip_hash": previous, "content_hash": digest, "created_at": created.isoformat(), "signing_key_id": key_id_for(chain_keys()[0])}
    manifest["signature"] = hmac.new(chain_keys()[0].encode(), canonical(manifest), hashlib.sha256).hexdigest()
    manifest_path = root / (name + ".manifest.json")
    # Reuse an already finalized manifest after a crash (its creation time differs).
    await asyncio.to_thread(finalize, root / (name + ".ndjson"), content)
    if not manifest_path.exists():
        await asyncio.to_thread(finalize, manifest_path, canonical(manifest))
    verified = await asyncio.to_thread(verify_archive, manifest_path)
    await _acquire_write_lock(db)
    receipt = await db.get(AuditArchive, start)
    if receipt is None:
        receipt = AuditArchive(first_seq=start, last_seq=last, content_hash=digest, manifest_name=manifest_path.name, created_at=datetime.fromisoformat(verified["created_at"]))
        db.add(receipt)
    elif receipt.content_hash != digest or receipt.last_seq != last:
        raise ValueError("Archive receipt mismatch")
    await db.commit()  # Verified durable receipt precedes deletion.
    await _acquire_write_lock(db)
    state = (await db.execute(select(type(state)).execution_options(populate_existing=True))).scalar_one()
    current = list((await db.execute(select(AuditLog).where(AuditLog.seq.between(start, last)).order_by(AuditLog.seq).execution_options(populate_existing=True))).scalars())
    current_events = [{"timestamp": row.timestamp.replace(tzinfo=timezone.utc).isoformat(), "user_id": str(row.user_id) if row.user_id else None, "action": row.action, "ip_address": row.ip_address, "details": {**row.details, "audit_hash": row.entry_hash, "audit_prev_hash": row.prev_hash, "audit_key_id": row.key_id}} for row in current]
    if state.retired_through_seq != start - 1 or b"".join(canonical(event) + b"\n" for event in current_events) != content or settings.AUDIT_RETENTION_HOLD:
        await db.rollback()
        raise ValueError("Archive prefix changed; deletion refused")
    await retire(db, through_seq=last, tip_hash=previous)
    await db.execute(delete(AuditLog).where(AuditLog.seq.between(start, last)))
    receipt.retired_at = datetime.now(timezone.utc)
    await db.commit()
    return {"deleted": len(events), "through_seq": last, "tip_hash": previous, "manifest": manifest_path.name}
