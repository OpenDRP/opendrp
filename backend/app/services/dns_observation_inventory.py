"""Analyst inventory projection; raw RRsets and certificate evidence stay intact."""
from __future__ import annotations

from sqlalchemy import String, case, cast, func, literal, select, true, union_all
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from app.models.dns_observation import DNSObservation


#: Certificate evidence, however it was obtained: a Certificate Transparency record or
#: the certificate an active TLS probe read from the service. Both are historical rows
#: keyed by certificate identity, so both belong in the same one-row-per-group projection
#: instead of one list row per certificate in a chain.
_CERTIFICATE_EVIDENCE = ("certificate", "tls_certificate")


def inventory_query(db: AsyncSession):
    """Expand RRsets and collapse certificates BEFORE counting and pagination."""
    table = DNSObservation.__table__
    is_rrset = (table.c.source == "resolver") & (table.c.observation_type == "dns_record")
    # The worker retains complete RRsets as structured metadata. Old single-value
    # observations without this metadata still get exactly one inventory row.
    values = table.c.metadata_json["record_values"]
    member_value: ColumnElement[str]
    if db.bind.dialect.name == "postgresql":
        array = case((func.json_typeof(values) == "array", values), else_=func.json_build_array(table.c.value))
        members = func.json_array_elements_text(array).table_valued("value").render_derived().lateral()
        member_value = members.c.value
    else:
        array = case((func.json_type(values) == "array", values), else_=func.json_array(table.c.value))
        members = func.json_each(array).table_valued("value")
        member_value = cast(members.c.value, String)
    # A single fact is never grouped with another source or with wildcard CT.
    wildcard = func.coalesce(table.c.metadata_json["wildcard"].as_boolean(), False)
    partition = [table.c.source, table.c.subject, wildcard]
    ordinary = select(
        table.c.id.label("observation_id"), table.c.value.label("display_value"),
        literal(1).label("evidence_count"), table.c.first_seen_at.label("inventory_first_seen"),
    ).where(~is_rrset, table.c.observation_type.notin_(_CERTIFICATE_EVIDENCE))
    rrsets = select(
        table.c.id.label("observation_id"), member_value.label("display_value"),
        literal(1).label("evidence_count"), table.c.first_seen_at.label("inventory_first_seen"),
    ).select_from(table.join(members, true())).where(is_rrset)
    certificates = select(
        table.c.id.label("observation_id"), table.c.value.label("display_value"),
        func.count().over(partition_by=partition).label("evidence_count"),
        func.min(table.c.first_seen_at).over(partition_by=partition).label("inventory_first_seen"),
        func.row_number().over(partition_by=partition, order_by=[func.coalesce(table.c.metadata_json["not_before"].as_string(), "").desc(), table.c.id.desc()]).label("rank"),
    ).where(table.c.observation_type.in_(_CERTIFICATE_EVIDENCE)).subquery()
    latest = select(certificates.c.observation_id, certificates.c.display_value, certificates.c.evidence_count, certificates.c.inventory_first_seen).where(certificates.c.rank == 1)
    inventory = union_all(ordinary, rrsets, latest).subquery()
    return select(DNSObservation, inventory.c.display_value, inventory.c.evidence_count, inventory.c.inventory_first_seen).join(inventory, DNSObservation.id == inventory.c.observation_id)


def certificate_group(row: DNSObservation):
    """Group identity matches the inventory window, including wildcard scope."""
    return (
        (DNSObservation.observation_type.in_(_CERTIFICATE_EVIDENCE))
        & (DNSObservation.source == row.source)
        & (DNSObservation.subject == row.subject)
        & (func.coalesce(DNSObservation.metadata_json["wildcard"].as_boolean(), False) == (row.metadata_json.get("wildcard") is True))
    )


def rrset_members(row: DNSObservation) -> list[str]:
    values = row.metadata_json.get("record_values")
    return list(dict.fromkeys(values)) if isinstance(values, list) and all(isinstance(v, str) for v in values) else [row.value] if row.value else []
