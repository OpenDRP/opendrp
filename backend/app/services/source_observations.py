from datetime import datetime, timezone
import hashlib
import json

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from app.models.source_observation import SourceObservation
from app.services.dns_security_service import normalize_subject
from app.services.module_aliases import canonical_module_id


def source_identity(connector):
    """Stable trusted provider id across safe display-name migrations."""
    if connector.provider:
        return connector.provider
    aliases = connector.aliases or []
    if aliases:
        legacy_name = str(aliases[0])
        # The original passive-DNS workers were named ``dns-<source>``;
        # retain the historical observation identity after display renaming.
        if canonical_module_id(connector.connector_type) == "dns" and legacy_name.startswith("dns-"):
            return legacy_name.removeprefix("dns-")
        return legacy_name
    name = connector.name or ""
    if canonical_module_id(connector.connector_type) == "dns" and name.startswith("dns-"):
        # A worker that has not been renamed is still called ``dns-<source>``.
        # Its observations belong to ``<source>``, exactly as they do once the
        # same label survives as an alias — otherwise the same provider would
        # hold two identities depending on whether a display rename had happened.
        return name.removeprefix("dns-")
    return connector.name


async def persist(db, *, module, source, finding, job_id=None, candidate_id=None, connector=None, commit=True):
    now = datetime.now(timezone.utc)
    raw_subject = finding.get("subject") or finding.get("phishing_domain")
    subject = str(raw_subject).strip().lower() if module == "breaches" and "@" in str(raw_subject) else normalize_subject(raw_subject)
    payload = dict(finding)
    if isinstance(payload.get("observed_at"), datetime):
        payload["observed_at"] = payload["observed_at"].isoformat()
    identity = {"subject": subject, "matched_asset": finding["matched_asset"], "port": finding.get("port"), "transport": finding.get("transport"), "hostname": finding.get("hostname"), "capability": (finding.get("metadata") or {}).get("capability"), "certificate": (finding.get("metadata") or {}).get("fingerprint")}
    if module == "breaches":
        identity["incident"] = finding.get("incident_id") or finding.get("breach_name")
    key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    existing = (await db.execute(select(SourceObservation).where(SourceObservation.module == module, SourceObservation.source == source, SourceObservation.observation_key == key))).scalar_one_or_none()
    changed = existing is None or existing.payload != payload
    values = dict(module=module, source=source, observation_key=key, subject=subject, matched_asset=finding["matched_asset"], candidate_id=candidate_id, job_id=job_id, first_seen_at=now, last_seen_at=now, observed_at=finding.get("observed_at"), payload=payload, status="observed")
    if connector is not None:
        values.update(connector_id=connector.id, source_account_id=connector.source_account_id,
                      provenance={"connector_id": str(connector.id), "source_id": source_identity(connector),
                                  "source_account_id": str(connector.source_account_id) if connector.source_account_id else None,
                                  "module": module, "job_id": str(job_id) if job_id else None})
    if isinstance(values["observed_at"], str):
        values["observed_at"] = datetime.fromisoformat(values["observed_at"].replace("Z", "+00:00"))
    factory = pg_insert if db.bind.dialect.name == "postgresql" else sqlite_insert
    stmt = factory(SourceObservation).values(values)
    stmt = stmt.on_conflict_do_update(index_elements=["module", "source", "observation_key"], set_={"last_seen_at": now, "observed_at": stmt.excluded.observed_at, "payload": stmt.excluded.payload, "job_id": stmt.excluded.job_id, "candidate_id": stmt.excluded.candidate_id, "updated_at": now})
    if connector is not None:
        stmt = factory(SourceObservation).values(values)
        stmt = stmt.on_conflict_do_update(index_elements=["module", "source", "observation_key"], set_={key: stmt.excluded[key] for key in ("last_seen_at", "observed_at", "payload", "job_id", "candidate_id", "connector_id", "source_account_id", "provenance")} | {"updated_at": now})
    await db.execute(stmt)
    if commit:
        await db.commit()
    else:
        await db.flush()
    return changed
