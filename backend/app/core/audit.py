from __future__ import annotations

import datetime as _dt
import decimal as _decimal
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.core.database import AsyncSessionLocal
from app.core.logging_config import (
    AUDIT_EVENT_NAME,
    AUDIT_FIELDS,
    configure_logging,
    get_audit_logger,
)
from app.core.audit_chain import prepare_entry
from app.core.request_context import current_request_id
from app.models.audit import AuditLog

# Configuration lives in app/core/logging_config.py, which owns the renderer for
# audit events, the stdout handler they need, and the reason the audit logger
# keeps its own level. It is called from here as well as from the process entry
# points because this module is the one that publishes the contract it protects,
# and because the call is idempotent.
configure_logging()

# The audit stream's own logger, pinned to the audit chain by logging_config:
# the trail must not share a level with diagnostic logging, and its line must not
# change shape because a connector configured structlog in this process. See
# `get_audit_logger` for the failure that used to cause.
log = get_audit_logger()

# Process-local degradation marker. Security-critical callers can expose this in
# readiness/health telemetry without making every ordinary read fail closed when
# a database audit insert is temporarily unavailable.
_audit_degraded = False


def audit_is_degraded() -> bool:
    return _audit_degraded


def clear_audit_degraded() -> None:
    global _audit_degraded
    _audit_degraded = False


def _publish_audit_event(event: dict[str, Any]) -> None:
    """Send an already durable audit event to the structured stdout stream."""
    try:
        # The configured processor removes the synthetic event name and
        # serializes exactly the five audit fields as one JSON line.
        log.info(AUDIT_EVENT_NAME, **event)
    except Exception:
        # Last-resort path only. A record dropped for being below the level
        # raises ``structlog.DropEvent``, which derives from BaseException and is
        # why the audit logger's level is pinned in logging_config.
        #
        # The line is built from the five documented fields rather than from the
        # event as it stands: this path exists so a rendering failure cannot lose
        # the trail, and the one thing it must not do is put a sixth key on the
        # stream because an event happened to grow one — the renderer the log call
        # above goes through drops unknown keys for the same reason.
        published = {field: event.get(field) for field in AUDIT_FIELDS}
        print(json.dumps(published, default=str, ensure_ascii=False), flush=True)


def _publish_deferred_audit_events(session: Session) -> None:
    """Publish `commit=False` events only after their caller commits the change."""
    pending = session.info.pop("opendrp.pending_audit_events", [])
    for event_payload in pending:
        _publish_audit_event(event_payload)


def _discard_deferred_audit_events(session: Session) -> None:
    """Do not export an event whose accompanying transaction was rolled back."""
    session.info.pop("opendrp.pending_audit_events", None)


event.listen(Session, "after_commit", _publish_deferred_audit_events)
event.listen(Session, "after_rollback", _discard_deferred_audit_events)


AUDIT_ALLOWED_ACTIONS = frozenset(
    {
        "auth.login.success",
        "auth.login.failure",
        "auth.login.locked",
        # Second-factor events. Both sides are recorded on purpose: an
        # enrolment that was started and never completed is a fact worth being
        # able to see, and a challenge that failed is the shape a brute-force
        # attempt against a six-digit code takes.
        "auth.mfa.setup_started",
        "auth.mfa.setup_failed",
        "auth.mfa.enrolled",
        "auth.mfa.disabled",
        "auth.mfa.success",
        "auth.mfa.failure",
        # An administrator reached an admin route without a second factor while
        # the deployment requires one. Recorded rather than merely refused: it is
        # the signal that an account is being driven by someone who has the
        # password and not the token — on a timeline, right next to the login
        # that produced it.
        "auth.mfa.required",
        # The account holder replaced the password someone else had chosen for
        # them, and the refusal that precedes it. Both sides are recorded for the
        # same reason the second-factor pair is: the change is the point at which
        # the credential stops being shared, and a failure is the shape a session
        # that is not the owner's takes — someone holding a token and guessing at
        # the password behind it.
        "auth.password.changed",
        "auth.password.change_failed",
        "auth.logout",
        "auth.refresh.success",
        "auth.refresh.failure",
        "auth.session.revoked",
        "auth.sessions.revoked_others",
        "auth.mfa.recovery_codes.rotated",
        # An authenticated account was refused by a role gate. One row per account,
        # method and route inside a window (app/core/authorization_audit.py): the
        # event is the signal that somebody is trying the boundary, and a row per
        # refused request would let a client ignoring the 403 write its own load.
        # The second-factor policy refusal stays `auth.mfa.required` — one refusal
        # with two names is one a SIEM rule cannot be written against.
        "authz.denied",
        "asset.create",
        "asset.update",
        "asset.delete",
        "asset.list",
        "asset.view",
        # The asset → findings view (WI-12). A read, but one that resolves the
        # asset against four modules at once, so "who looked at what" has to be
        # answerable from the trail.
        "asset.findings.list",
        # Inventory in bulk (WI-18): one summary row per call, naming the
        # operation, how much of it applied, and which named assets were not
        # found — the alternative was a hundred `asset.update` rows burying the
        # call that produced them.
        "asset.import",
        "asset.export",
        "asset.bulk.activate",
        "asset.bulk.deactivate",
        "asset.bulk.criticality",
        "asset.bulk.delete",
        "settings.update",
        "settings.view",
        "settings.runtime.view",
        "settings.test_email_sent",
        "settings.test_email_failed",
        "settings.test_telegram_sent",
        "settings.test_telegram_failed",
        "settings.telegram.validate",
        "settings.telegram.validate_failed",
        "alert.test_sent",
        "report.generate",
        "report.generate.failed",
        "report.generate.completed",
        "report.generate.retry",
        # A generation no worker owns any more: the retention sweep returned it to
        # `failed` so the report queue's global admission slot is not held by a
        # report nobody is producing.
        "report.generate.abandoned",
        "report.retention.expired",
        "report.delete",
        "report.list",
        "report.download",
        "report.download.missing",
        # A stored artifact value that is not an artifact name: a row pointing
        # somewhere this platform never writes. Distinct from `.missing` on
        # purpose — one is a lost file, the other is a wrong row.
        "report.artifact.rejected",
        # A destination the policy refused: an operator-supplied host (SMTP) or a
        # discovery-supplied one (WHOIS) that resolved into loopback, the cloud
        # metadata range, or one of this deployment's own networks.
        "outbound.blocked",
        # The nightly verification of the hash chain: one action for a pass that
        # held, one for a pass that did not, so a SIEM rule does not have to parse
        # prose out of a details blob.
        "audit.chain.verified",
        "audit.chain.progress",
        "audit.chain.broken",
        # An administrator looking at where the chain stands. A read of the
        # *integrity state* rather than of the entries, which is why it is
        # separate from `audit.log.view`.
        "audit.integrity.view",
        "phishing.scan.dnstwist.start",
        "phishing.scan.shodan.start",
        "phishing.threat.list",
        "phishing.threat.view",
        "phishing.threat.update",
        # The analyst's decision about a candidate (WI-12, W1.6). Declared rather than
        # written as a free string: the decision is what a later reader asks about
        # ("who dismissed this, and why?"), and an undeclared action is one a SIEM
        # rule cannot be written against without reading the source.
        "phishing.threat.verdict",
        "phishing.threat.delete",
        "phishing.threat.orphans.cleaned",
        # Taking a finding's own value under monitoring (AWI-13/U-1). The
        # already-exists pair is separate because "the inventory already covered
        # this" is a different answer from "this request added it".
        "phishing.asset.promoted",
        "phishing.asset.already_exists",
        "phishing.scan.scheduled",
        "breach.scan.scheduled",
        "dns_security.scan.scheduled",
        "dns_security.scan.started",
        "dns_security.scan.queued",
        "dns_security.observation.orphans.cleaned",
        "dns_security.observation.delete",
        "dns_security.observations.list",
        "dns_security.asset.promoted",
        "dns_security.asset.already_exists",
        "dns_security.certificates.list",
        "dns_security.certificate_exceptions.list",
        # One action per verdict rather than a template: the allowlist is what a SIEM
        # rule is built from, and `tls.sighting.*` would match nothing an operator can
        # write a rule against.
        "tls.sighting.candidate",
        "tls.sighting.expected",
        "tls.sighting.shared_infrastructure",
        "tls.sighting.confirmed_foreign",
        "tls.sighting.rejected",
        "tls.exception.added",
        "tls.exception.removed",
        "breach.list",
        "breach.view",
        "breach.delete",
        "breach.update",
        "breach.orphans.cleaned",
        "breaches.asset.promoted",
        "breaches.asset.already_exists",
        "breach.scan.start",
        "breach.scan.email",
        "breach.scan.domain",
        # A domain enrolled in the source's own dashboard (WI-20). Recorded before
        # the step is queued, because "nobody asked" and "nobody could ask" are
        # different answers to why a domain is still unscannable.
        "breach.domain_verification.requested",
        "alert.dispatch.success",
        "alert.dispatch.failed",
        "task.started",
        "task.completed",
        "task.failed",
        "dashboard.view",
        "user.created",
        "user.deleted",
        "user.updated",
        "user.password_reset",
        "user.locked",
        "user.unlocked",
        # An administrator clearing someone's second factor. This is the account
        # recovery path, which is why it is auditable separately from a generic
        # user update: it is the one action that removes a factor from an account
        # the administrator does not own.
        "user.mfa.reset",
        # The host-side escape hatch clearing an account's onboarding flags. Its
        # own action rather than a `user.updated`: releasing an account from the
        # forced password change leaves a password somebody else chose in force,
        # so the release has to be findable without reading prose out of details.
        "user.onboarding.cleared",
        # The account holder was told what an administrator did to their account.
        # The outcome is part of the event: "we tried" and "we could not reach
        # SMTP" are different, and an installation whose notification silently
        # never sends would otherwise look exactly like one that works (RWI-15).
        "user.notification.sent",
        "user.notification.failed",
        "user.notification.skipped",
        # Reading the user table as a file is a read, but it is the read that
        # leaves the platform with names, roles and sign-in history in it, which
        # is why an export names itself and its filter (U-1).
        "users.export",
        # One activation change over a selection, recorded once for the batch:
        # "who was deactivated in this operation" is one decision, and N rows
        # would make an off-boarding look like N unrelated events (U-5).
        "users.bulk",
        # An administrator ending somebody else's sessions. Distinct from
        # `auth.sessions.revoked_others`, where the account ends its own (U-2).
        "user.sessions.revoked",
        # An account created without a password the administrator knows (U-7).
        # The invitation mail's outcome is its own event, because "invited" and
        # "the owner was actually told" are different facts.
        "user.invited",
        "user.invitation.sent",
        "user.invitation.failed",
        "user.invitation.skipped",
        "auth.invitation.accepted",
        "audit.log.view",
        # The retention sweep is itself a security-relevant event: deleting audit
        # history is exactly the action an attacker with database access would
        # want to hide, so it is recorded with what was removed and when.
        "audit.retention.purged",
        "connectors.health.view",
        "connectors.modules.view",
        "alerts.health.view",
        # An administrator ending a recipient's hold after an ambiguous delivery.
        # The operator is asserting they reconciled a send whose outcome nobody
        # knew, and the other possible outcome of that assertion is a duplicate
        # notification, so the decision is recorded rather than merely applied.
        "alerts.recipient.released",
        "connectors.list",
        # Module registry: a module is data, so declaring or toggling one is an
        # auditable change to what the platform can collect and store.
        "modules.list",
        "module.declared",
        "module.updated",
        "findings.list",
        "source.scan.queued",
        "source.observations.list",
        "source_account.provisioned",
        "source_account.credential_ref.updated",
        "source_account.policy.updated",
        "source_account.api_key.updated",
        "source_account.api_key.cleared",
        "connector.credential.read",
        "connector.account.bound",
        "source_account.quota_denied",
        "exposure.observation.status_update",
        "exposure.asset.promoted",
        "exposure.asset.already_exists",
        "connector.registered",
        "connector.findings.ingested",
        # The incident catalogue a breach connector submits (WI-13): the other half
        # of the picture, about incidents no monitored address is in yet.
        "connector.catalogue.ingested",
        "connector.scan.completed",
        "connector.scan.failed",
        "connector.status.updated",
        "connector.config.updated",
        "connector.token.issued",
        "connector.token.rotated",
        "connector.token.revoked",
        "users.list",
        "users.view",
        "jobs.list",
        "job.view",
        "job.delete",
        "rate_limit.manual_action_blocked",
        "rate_limit.request_blocked",
        "finding.status_update",
    }
)


_PRIMITIVE_TYPES = (type(None), bool, int, float, str)
_JSON_SPECIAL_TYPES = (uuid.UUID, _dt.datetime, _dt.date, _dt.time, _dt.timedelta, _decimal.Decimal)


def _safe_jsonable(value: Any) -> Any:
    """Convert arbitrary audit details to values accepted by JSON encoders."""
    if isinstance(value, _PRIMITIVE_TYPES):
        return value
    if isinstance(value, _JSON_SPECIAL_TYPES):
        if isinstance(value, _dt.timedelta):
            return value.total_seconds()
        if isinstance(value, _decimal.Decimal):
            return str(value)
        if isinstance(value, (uuid.UUID, _dt.datetime, _dt.date, _dt.time)):
            return value.isoformat() if hasattr(value, "isoformat") else str(value)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return {_safe_jsonable_key(k): _safe_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_safe_jsonable(x) for x in value]
    return str(value)[:500]


def _safe_jsonable_key(key: Any) -> str:
    if isinstance(key, str):
        return key
    return str(key)


#: The bounds a half-trusted caller cannot raise. A connector's `summary` reaches
#: the audit trail, and an immutable chain entry whose size is chosen by the
#: connector is an entry the connector can make unreadable — or expensive to
#: export. These are defense in depth beside the wire schema, not formatting.
MAX_DETAIL_STRING = 200
MAX_DETAIL_ITEMS = 20
MAX_DETAIL_DEPTH = 4
MAX_DETAIL_KEYS = 64
MAX_DETAILS_JSON = 8_000


def bound_details(value: Any, *, _depth: int = 0) -> Any:
    """Cut a details tree down to the shape the audit trail promises.

    Strings lose their tail, lists keep their head, and nesting stops at a fixed
    depth. The cut is silent here because the caller records the fact once, at
    the level where it is observable: `_stdout_event` marks the event
    `details_truncated` when the cap below actually dropped something.
    """
    if isinstance(value, str):
        return value if len(value) <= MAX_DETAIL_STRING else value[:MAX_DETAIL_STRING]
    if isinstance(value, dict):
        if _depth >= MAX_DETAIL_DEPTH:
            return "…"
        items = list(value.items())
        if len(items) > MAX_DETAIL_KEYS:
            items = items[:MAX_DETAIL_KEYS]
        return {_safe_jsonable_key(k): bound_details(v, _depth=_depth + 1) for k, v in items}
    if isinstance(value, (list, tuple, set, frozenset)):
        if _depth >= MAX_DETAIL_DEPTH:
            return "…"
        return [bound_details(item, _depth=_depth + 1) for item in list(value)[:MAX_DETAIL_ITEMS]]
    return value


def _fit_details(details: dict) -> tuple[dict, bool]:
    """Apply the bounds, then the total-size cap, and say whether anything was cut.

    The per-value bounds leave a tree that is small in practice; the serialized
    cap is the hard stop behind them, because sixty-four values of two hundred
    characters still add up. When it bites, the fields are kept in name order
    while they fit and the event says so -- a truncated record that claims to be
    complete is worse than a small one that admits the cut.
    """
    bounded = bound_details(details)
    if not isinstance(bounded, dict):
        return details, False
    if len(json.dumps(bounded, ensure_ascii=False, default=str)) <= MAX_DETAILS_JSON:
        return bounded, bounded != details

    kept: dict[str, Any] = {}
    budget = MAX_DETAILS_JSON - 200
    for key in sorted(bounded):
        chunk = json.dumps({key: bounded[key]}, ensure_ascii=False, default=str)
        if len(chunk) > budget:
            continue
        kept[key] = bounded[key]
        budget -= len(chunk)
    kept["details_truncated"] = True
    return kept, True


class AuditPersistenceError(RuntimeError):
    """A required audit event could not be durably committed."""


class AuditLogger:
    """
    Strict JSON audit logger (AGENTS Rule 3).

    Emits:
      1. Persistent row in drp_audit_logs (PostgreSQL).
      2. One-line JSON log event on stdout with exactly 5 mandatory top-level
         keys: timestamp, user_id, action, ip_address, details
         — ready for direct ingestion into an Elastic Security pipeline.
    """

    @staticmethod
    def _normalize_action(action: str) -> str:
        if action in AUDIT_ALLOWED_ACTIONS:
            return action
        log.warning("audit_action_unrecognized", action=action)
        return action

    @staticmethod
    def _stdout_event(
        ts: datetime,
        user_id: uuid.UUID | str | None,
        action: str,
        ip_address: str | None,
        details: dict | None,
    ) -> tuple[dict, uuid.UUID | None, str, str, datetime]:
        ts_iso = ts.astimezone(timezone.utc).isoformat()
        uid = None
        if user_id is not None:
            try:
                uid = uuid.UUID(str(user_id))
            except (ValueError, TypeError, AttributeError):
                uid = None
        ip = (ip_address or "unknown").strip() or "unknown"
        normalized_action = AuditLogger._normalize_action(action)
        det = {k: _safe_jsonable(v) for k, v in (details or {}).items()}
        det, cut = _fit_details(det)
        if cut:
            det["details_truncated"] = True
        # Correlation goes *inside* details, never beside it: the five top-level
        # fields are a published contract (see logging_config.AUDIT_FIELDS), and a
        # sixth would reach a SIEM index that maps the documented shape and
        # quietly become unindexed noise. A caller that already set its own id —
        # a Celery task adopting its producer's — wins.
        request_id = current_request_id()
        if request_id and "request_id" not in det:
            det["request_id"] = request_id
        return {
            "timestamp": ts_iso,
            "user_id": str(uid) if uid else None,
            "action": normalized_action,
            "ip_address": ip,
            "details": det,
        }, uid, ip, normalized_action, ts

    @staticmethod
    async def emit(
        db: AsyncSession,
        *,
        action: str,
        ip_address: str | None,
        user_id: uuid.UUID | str | None = None,
        details: dict | None = None,
        timestamp: datetime | None = None,
        require_persistence: bool = False,
        commit: bool = True,
    ) -> bool:
        """Write one audit event to the trail and to stdout.

        ``require_persistence`` is for the events the platform promises to
        record — an asset added or removed, an inventory changed by a promotion.
        When it is set and the row could not be written, this raises
        ``AuditPersistenceError`` instead of returning a flag nobody reads.

        ``commit=False`` writes into the caller's transaction rather than
        committing: the mutation this event describes is not durable until the
        caller commits, so neither is the event. That is what makes the promise
        hold — a caller that owns a mutation and its audit row in one transaction
        cannot end up with the first without the second. Use it with
        ``require_persistence`` and an explicit commit in the caller.
        """
        ts = timestamp or datetime.now(timezone.utc)
        event, uid, ip, normalized_action, ts_db = AuditLogger._stdout_event(
            ts, user_id, action, ip_address, details
        )
        event["details"]["audit_persisted"] = True

        persisted = False
        try:
            # The hash chain, computed against the final `details` (which already
            # carries the request id) and the position this row takes. Both the
            # database row and the stdout line carry the result, so the two copies
            # of the same event can be compared without guessing — see
            # app/core/audit_chain.py for what that comparison can and cannot
            # prove.
            if uid is not None and "actor_email" not in event["details"]:
                from app.models.user import User
                actor = await db.get(User, uid)
                if actor is not None:
                    event["details"]["actor_email"] = actor.email
            link = await prepare_entry(
                db,
                timestamp=ts_db,
                user_id=uid,
                action=normalized_action,
                ip_address=ip,
                details=event["details"],
            )
            # Added *after* hashing, and therefore excluded when the hash is
            # recomputed: a hash cannot cover itself.
            event["details"]["audit_hash"] = link.entry_hash
            event["details"]["audit_prev_hash"] = link.prev_hash
            # The fingerprint of the key that signed this entry. The database row
            # has a column for it; the exported stream does not, and a stream is
            # the copy a SIEM holds. Without it, an installation that rotated its
            # chain key could not verify its own archive.
            event["details"]["audit_key_id"] = link.key_id

            row_details = dict(event["details"])
            # Persistence is transport metadata, not part of the signed audit
            # record: the stdout copy can report it, while DB rows retain only
            # fields whose meaning does not depend on the outcome of their own
            # commit. Reserved in the canonical payload so a caller cannot forge it.
            row_details.pop("audit_persisted", None)
            row = AuditLog(
                timestamp=ts_db,
                user_id=uid,
                action=normalized_action,
                ip_address=ip,
                details=row_details,
                seq=link.seq,
                entry_hash=link.entry_hash,
                prev_hash=link.prev_hash,
                key_id=link.key_id,
            )
            db.add(row)
            if commit:
                await db.commit()
            else:
                # Part of the caller's transaction: the mutation and the event
                # become durable together. Defer stdout until that transaction's
                # commit so an outer rollback cannot export a false success.
                await db.flush()
            persisted = True
            # A later successful write proves the audit path recovered. Keep
            # readiness degraded only while the failure is current, rather than
            # carrying a transient database/SQLite error forever in this worker.
            clear_audit_degraded()
        except Exception as e:
            global _audit_degraded
            _audit_degraded = True
            try:
                await db.rollback()
            except Exception:
                pass
            log.error("audit_db_write_failed", err=str(e)[:300], audit_degraded=True)

        # Make persistence status explicit in the export. This transport marker
        # is intentionally excluded from the HMAC: the row cannot contain the
        # result of its own commit, and an unconfirmed write must not export a
        # candidate hash as if it were part of the durable chain.
        if not persisted:
            for key in ("audit_hash", "audit_prev_hash", "audit_key_id"):
                event["details"].pop(key, None)
        event["details"]["audit_persisted"] = persisted

        if persisted and not commit:
            db.sync_session.info.setdefault("opendrp.pending_audit_events", []).append(event)
            return True

        _publish_audit_event(event)

        if require_persistence and not persisted:
            raise AuditPersistenceError(
                f"required audit event {normalized_action!r} was not persisted"
            )
        return persisted

    @staticmethod
    async def emit_background(
        db: AsyncSession | None = None,
        *,
        action: str,
        ip_address: str | None,
        user_id: uuid.UUID | str | None = None,
        details: dict | None = None,
        timestamp: datetime | None = None,
    ) -> None:
        """Emit an audit row for read-heavy list/view endpoints.

        If a caller-scoped ``db`` session is provided it is used directly
        (``emit_background`` now runs in the request stack and never
        schedules fire-and-forget tasks). Otherwise a brand new isolated
        ``AsyncSessionLocal()`` is opened for the audit write.

        Guarantees:

        * No ``IllegalStateChangeError`` races — there is no ``ensure_future``.
        * No SQLite ``database is locked`` in tests — callers pass the same
          scoped session so only one DB connection is ever active.
        """
        if db is not None:
            await AuditLogger.emit(
                db,
                action=action,
                ip_address=ip_address,
                user_id=user_id,
                details=details,
                timestamp=timestamp,
            )
            return

        fresh_db: AsyncSession | None = None
        try:
            fresh_db = AsyncSessionLocal()
            await AuditLogger.emit(
                fresh_db,
                action=action,
                ip_address=ip_address,
                user_id=user_id,
                details=details,
                timestamp=timestamp,
            )
        finally:
            if fresh_db is not None:
                try:
                    await fresh_db.close()
                except Exception:
                    pass
