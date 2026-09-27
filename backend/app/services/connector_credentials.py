"""Per-connector credentials.

A connector used to authenticate with one platform-wide shared secret, so any
container that learned it could claim *any* connector's work, read another
connector's configuration and submit findings under another connector's name.
A leaked secret was uncontainable and unrevocable without re-keying every
connector at once.

Now each connector owns a credential:

* the token is a high-entropy random string, issued by an operator (CLI or
  admin API) and stored by the core as a SHA-256 digest — the plaintext is
  shown exactly once and never persisted;
* identity comes from the credential itself, so a token cannot be used to act
  as a different connector (the optional ``X-Connector-Name`` header is only
  checked for agreement);
* rotation and revocation are per connector, so one leaked token is contained
  and can be re-keyed without touching the others.

SHA-256 (not bcrypt) is deliberate: the secret is machine-generated with ~256
bits of entropy, so it is not brute-forceable, and verification happens on every
work-poll — a deliberately slow KDF would tax the platform for no security gain.
Comparisons are constant-time anyway.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import structlog
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundException
from app.models import Connector

log = structlog.get_logger()

TOKEN_PREFIX = "opendrp"
#: Entropy of the random part: 32 bytes -> 43 url-safe characters.
_TOKEN_BYTES = 32
TOKEN_PREFIX_LEN = 16
#: ``token_last_used_at`` is bookkeeping, not a request counter: connectors poll
#: every few seconds, so one write per minute per connector is plenty.
_LAST_USED_WRITE_INTERVAL = timedelta(minutes=1)


def hash_token(token: str) -> str:
    """Digest a connector token for storage and lookup."""
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()


def generate_token(connector_name: str) -> str:
    """Create a fresh token that identifies the connector it belongs to.

    The name inside the token is a convenience for operators reading logs or a
    secrets manager; authority still comes from the stored digest.
    """
    safe_name = "".join(ch for ch in str(connector_name).lower() if ch.isalnum() or ch in "-_")
    return f"{TOKEN_PREFIX}_{safe_name[:24]}_{secrets.token_urlsafe(_TOKEN_BYTES)}"


def connector_name_from_token(token: str | None) -> str | None:
    """Return the connector name a token *claims*, or ``None``.

    Read by the rejection path, so that a rejected credential can be attributed
    in the platform's log instead of only in the connector's own crash loop. The
    value is a **hint and never an identity**: it is text inside a value the
    caller chose, so nothing is authorized by it, and the only thing that ever
    names a connector is a digest that resolves (:meth:`ConnectorCredentials.resolve`).
    """
    parts = (token or "").strip().split("_", 2)
    if len(parts) < 3 or parts[0] != TOKEN_PREFIX:
        return None
    return parts[1].strip().lower() or None


class ConnectorCredentials:
    """Issue, resolve and revoke per-connector tokens."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------
    # Operator side
    # ------------------------------------------------------------------

    async def issue(self, connector: Connector) -> tuple[str, bool]:
        """Issue (or rotate) a connector's token; returns (plaintext, rotated).

        The plaintext is returned to the caller exactly once. Rotating replaces
        the digest, so the previous token stops authenticating immediately.
        """
        rotated = bool(connector.token_hash)
        token = generate_token(connector.name)
        connector.token_hash = hash_token(token)
        connector.token_prefix = token[:TOKEN_PREFIX_LEN]
        connector.token_created_at = datetime.now(timezone.utc)
        connector.token_last_used_at = None
        await self.db.commit()
        await self.db.refresh(connector)
        log.info(
            "connector_token_issued",
            connector=connector.name,
            rotated=rotated,
            token_prefix=connector.token_prefix,
        )
        return token, rotated

    async def revoke(self, connector: Connector) -> None:
        """Drop the connector's credential; it can no longer authenticate."""
        connector.token_hash = None
        connector.token_prefix = None
        connector.token_created_at = None
        connector.token_last_used_at = None
        await self.db.commit()
        log.warning("connector_token_revoked", connector=connector.name)

    async def get(self, connector_id) -> Connector:
        connector = await self.db.get(Connector, connector_id)
        if connector is None:
            raise NotFoundException("Connector not found")
        return connector

    # ------------------------------------------------------------------
    # Connector side
    # ------------------------------------------------------------------

    async def resolve(self, token: str) -> Connector | None:
        """Return the connector this token belongs to, or ``None``.

        A digest that matches more than one connector means the same secret was
        provisioned twice. That is refused rather than guessed at, because
        picking one would let a connector act as another.
        """
        raw = (token or "").strip()
        if not raw:
            return None
        digest = hash_token(raw)
        rows = list(
            (
                await self.db.execute(select(Connector).where(Connector.token_hash == digest))
            )
            .scalars()
            .all()
        )
        if not rows:
            return None
        if len(rows) > 1:
            log.error(
                "connector_token_ambiguous",
                connectors=sorted(row.name for row in rows),
            )
            return None
        connector = rows[0]
        # Constant-time comparison of the digest we looked up, so a timing signal
        # cannot be used to probe stored digests byte by byte.
        if not secrets.compare_digest(connector.token_hash or "", digest):
            return None
        return connector

    async def touch_last_used(self, connector: Connector) -> None:
        """Record credential use, throttled to one write per minute."""
        now = datetime.now(timezone.utc)
        last = connector.token_last_used_at
        if last is not None and last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        if last is not None and now - last < _LAST_USED_WRITE_INTERVAL:
            return
        await self.db.execute(
            update(Connector)
            .where(Connector.id == connector.id)
            .values(token_last_used_at=now)
        )
        await self.db.commit()
        connector.token_last_used_at = now
