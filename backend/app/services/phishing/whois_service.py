import asyncio
import datetime as _dt

import structlog
import whois
from dateutil import parser as _dp
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.outbound import OutboundBlocked, ensure_allowed, validate_domain_target

log = structlog.get_logger()


class WhoisService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def enrich(self, threat) -> None:
        # The domain came out of a finding, which means it came from outside the
        # platform, and a WHOIS client resolves whatever it is handed. Both the
        # shape check and the destination check happen before the lookup: this is
        # the one enrichment whose target an attacker can choose.
        try:
            target = validate_domain_target(getattr(threat, "phishing_domain", None))
        except ValueError as exc:
            log.warning("whois_target_refused", reason=str(exc)[:120])
            return

        def _sync_whois():
            try:
                # Resolution and lookup both belong off the event loop, so the
                # guard runs in here with them.
                ensure_allowed(target, port=43)
                return whois.whois(target)
            except OutboundBlocked:
                raise
            except Exception:
                return None

        loop = asyncio.get_running_loop()
        try:
            from app.core.config import settings
            info = await asyncio.wait_for(
                loop.run_in_executor(None, _sync_whois),
                timeout=max(1.0, float(settings.OUTBOUND_DNS_TIMEOUT_SECONDS)),
            )
        except OutboundBlocked as blocked:
            log.warning("outbound_blocked", operation="whois", **blocked.as_audit_details())
            return
        except Exception:
            return
        if not info:
            return
        registrar = info.get("registrar")
        emails = info.get("emails") or []
        abuse_email = None
        if isinstance(emails, list):
            for e in emails:
                if "abuse" in str(e).lower():
                    abuse_email = e
                    break
            if not abuse_email and emails:
                abuse_email = (
                    emails[0] if isinstance(emails[0], str) else str(emails[0])
                )
        elif isinstance(emails, str):
            abuse_email = emails
        cdate = info.get("creation_date")
        if isinstance(cdate, list):
            cdate = cdate[0]
        if registrar and not threat.whois_registrar:
            threat.whois_registrar = str(registrar)[:255]
        if abuse_email and not threat.whois_abuse_email:
            threat.whois_abuse_email = str(abuse_email)[:255]
        if cdate and not threat.domain_created_at:
            try:
                if isinstance(cdate, _dt.datetime):
                    threat.domain_created_at = cdate
                else:
                    threat.domain_created_at = _dp.parse(str(cdate))
            except Exception:
                pass
        await self.db.commit()
        await self.db.refresh(threat)
