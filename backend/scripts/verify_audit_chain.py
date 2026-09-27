"""Verify the audit hash chain, in the database or in an exported log stream.

The scheduled task (``verify_audit_chain``) checks the database every night. This
is the tool for the two cases a schedule cannot cover:

* an operator who needs a pass *now* — after a restore, after a suspicious
  finding, or before an audit — and wants to see where a break is rather than
  just that one exists;
* an auditor holding only the *log* copy. The audit event is written to stdout
  with the same two hashes inside ``details``, so an exported NDJSON file can be
  verified with the same code and without database access at all. That is the
  point of publishing the hashes: neither copy can be trusted alone, and the
  comparison is what makes an edit visible.

Run inside the backend container:

    docker compose exec backend python -m scripts.verify_audit_chain --full
    python -m scripts.verify_audit_chain --ndjson /backups/audit-2026-09.ndjson

Exit codes: 0 verified, 1 the chain does not verify, 2 unusable input.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

from app.core.audit_chain import (
    GENESIS_PREV_HASH,
    chain_key_pairs,
    chain_keys,
    compute_entry_hash,
    entry_payload,
    verify,
)


def _print_report(result, *, full: bool, keys: int) -> None:
    mode = "full" if full else "incremental"
    print(f"[OpenDRP] audit chain verification ({mode} pass, {keys} signing key(s))")
    print(f"  checked entries      : {result.checked}")
    print(f"  positions examined   : {result.from_seq} .. {result.through_seq}")
    print(f"  retired through      : {result.retired_through_seq}")
    if result.truncated:
        print("  NOTE: the row cap was reached; the remaining entries were not read")
    if result.ok:
        print("  result               : OK — every retained entry links and hashes")
    else:
        print(f"  result               : BROKEN at position {result.first_broken_seq}")
        print(f"  reason               : {result.reason}")
        print(
            "  next step            : compare that position against the SIEM's copy "
            "of the audit stream before touching the database"
        )


async def _verify_database(
    *, full: bool, since: int | None, max_rows: int, as_json: bool
) -> int:
    from app.core.database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        result = await verify(db, full=full, since=since, max_rows=max_rows)

    if as_json:
        print(
            json.dumps(
                {
                    "ok": result.ok,
                    "mode": "full" if full else "incremental",
                    "keys": len(chain_keys()),
                    **result.as_details(),
                },
                ensure_ascii=False,
            )
        )
    else:
        _print_report(result, full=full, keys=len(chain_keys()))
    return 0 if result.ok else 1


def _verify_ndjson(path: Path) -> int:
    """Verify an exported audit stream on its own.

    The stream is append-only from the platform's point of view, so the property
    to check is the same one the database pass checks: each entry's hash
    recomputes from its own five fields and the previous entry's hash. A stream
    that verifies end to end cannot have had a line edited, reordered or removed
    (a *removal* shows up as a broken link; the positions and the retirement
    watermark are the database's job to police).
    """
    # Addressed by fingerprint: a stream written across a key rotation contains
    # entries signed by more than one key, and the key that signed a line has to
    # be found by the id the line records rather than by position in this file's
    # writer's list.
    by_id = dict(chain_key_pairs())
    checked = 0
    expected_prev = GENESIS_PREV_HASH

    try:
        handle = path.open("r", encoding="utf-8")
    except OSError as exc:
        print(f"[OpenDRP] cannot read {path}: {exc}")
        return 2

    with handle:
        for number, raw in enumerate(handle, start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"[OpenDRP] {path}:{number} is not JSON: {exc}")
                return 2
            if not isinstance(event, dict) or "action" not in event:
                # Other structured log lines live in the same stream; only audit
                # events carry the reserved hash fields.
                continue

            details = event.get("details") or {}
            entry_hash = details.get("audit_hash")
            prev_hash = details.get("audit_prev_hash")
            if not entry_hash:
                # The platform signs every audit event it writes, so a line
                # without the reserved hash fields did not come from it.
                print(
                    f"[OpenDRP] BROKEN: line {number} is an audit event without a hash"
                )
                return 1

            timestamp = event.get("timestamp")
            try:
                parsed = datetime.fromisoformat(str(timestamp))
            except ValueError:
                print(f"[OpenDRP] line {number}: unusable timestamp {timestamp!r}")
                return 2
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)

            payload = entry_payload(
                timestamp=parsed.astimezone(timezone.utc),
                user_id=event.get("user_id"),
                action=str(event.get("action")),
                ip_address=str(event.get("ip_address") or "unknown"),
                details=details,
            )
            raw_key_id = details.get("audit_key_id")
            if raw_key_id is None:
                # No key id on the line. Nothing this build writes looks like
                # that, so it is a stream from a writer that predates the field:
                # that writer used the then-current key with a key id of 0, so the
                # first configured key is the only candidate worth trying and a
                # missing key id is simply not treated as an unknown key.
                if not by_id:
                    print("[OpenDRP] no AUDIT_CHAIN_KEYS are configured")
                    return 2
                key_id, key = chain_key_pairs()[0]
            else:
                try:
                    key_id = int(raw_key_id)
                except (TypeError, ValueError):
                    print(f"[OpenDRP] line {number}: unusable audit_key_id {raw_key_id!r}")
                    return 2
                key = by_id.get(key_id)
                if key is None:
                    # A line whose key is not configured here cannot be checked.
                    # Say so rather than hashing it under the wrong key and
                    # calling the result a broken chain.
                    print(
                        f"[OpenDRP] line {number}: signed with key id {key_id}, which is "
                        "not among the configured AUDIT_CHAIN_KEYS"
                    )
                    return 2

            expected = compute_entry_hash(
                key, payload=payload, prev_hash=str(prev_hash or ""), key_id=key_id
            )
            if expected != entry_hash:
                print(
                    f"[OpenDRP] BROKEN: line {number} does not hash to its recorded "
                    f"value (action={event.get('action')!r})"
                )
                return 1
            if str(prev_hash) != expected_prev:
                print(
                    f"[OpenDRP] BROKEN: line {number} links to {str(prev_hash)[:12]}… "
                    f"but the previous entry hashed to {expected_prev[:12]}…"
                )
                return 1

            expected_prev = str(entry_hash)
            checked += 1

    print(f"[OpenDRP] stream verification of {path}")
    print(f"  entries checked        : {checked}")
    if checked == 0:
        print("  result                 : no signed audit events found")
        return 2
    print("  result                 : OK — the chain in this file is intact")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the OpenDRP audit hash chain (database or exported stream)."
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="re-derive the whole retained chain instead of continuing from the last pass",
    )
    parser.add_argument(
        "--since",
        type=int,
        default=None,
        help="start after this audit position instead of the recorded watermark",
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=250_000,
        help="bound on entries read in one pass (default: 250000)",
    )
    parser.add_argument(
        "--ndjson",
        type=Path,
        default=None,
        help="verify an exported audit stream instead of the database",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the database result as JSON rather than as a report",
    )
    args = parser.parse_args(argv)

    if args.ndjson is not None:
        if args.full or args.since is not None:
            print("[OpenDRP] --full/--since apply to the database; ignoring them")
        return _verify_ndjson(args.ndjson)

    try:
        return asyncio.run(
            _verify_database(
                full=args.full,
                since=args.since,
                max_rows=args.max_rows,
                as_json=args.json,
            )
        )
    except KeyboardInterrupt:  # pragma: no cover - operator interrupt
        print("\n[OpenDRP] interrupted")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
