"""Signed audit archive CLI; export retires only a verified expired prefix."""
import argparse
import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.core.config import settings
from app.services.audit_archive import archive_prefix, verify_archive


async def export(limit):
    from app.core.database import AsyncSessionLocal
    if settings.AUDIT_RETENTION_DAYS <= 0:
        raise ValueError("Audit retention disabled")
    async with AsyncSessionLocal() as db:
        return await archive_prefix(db, cutoff=datetime.now(timezone.utc) - timedelta(days=settings.AUDIT_RETENTION_DAYS), limit=limit)


def build_parser():
    """The command line this script accepts, as an object a caller can inspect.

    Separate from `main` so the documentation gate can compare what a page tells
    an operator to type with the flags that exist.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--verify", type=Path, metavar="MANIFEST")
    group.add_argument("--export-expired", action="store_true")
    parser.add_argument("--limit", type=int, default=1000)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not 1 <= args.limit <= 10000:
        parser.error("limit must be 1..10000")
    try:
        result = verify_archive(args.verify) if args.verify else asyncio.run(export(args.limit))
        print(json.dumps({"ok": True, **result}, ensure_ascii=False))
        return 0
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
