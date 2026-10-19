"""Canonical names for modules and connectors, with transitional aliases.

The DNS module was called ``dns_security`` and its workers ``<provider>-dns-security-default``.
The canonical names are ``dns`` and the module-first template ``<module>-<provider>-<task>``.
Old names keep working: every input that names a module, a job type or a connector is
passed through :func:`canonical_module_id` or :func:`canonical_job_type` first, and a
migrated connector keeps its old label in ``aliases`` so existing tokens still authenticate
and existing observations keep their source identity.

Remove an alias only after every worker image and operator script has moved to the new name.
"""

from __future__ import annotations

#: Module ids that were renamed. The key is accepted on input; the value is stored.
MODULE_ALIASES: dict[str, str] = {"dns_security": "dns"}

#: Connector names renamed to the ``<module>-<provider>-<task>`` template. The spelling a
#: worker registered under before the rename is kept as an alias by the migration, so it
#: keeps authenticating.
CONNECTOR_NAME_RENAMES: dict[str, str] = {
    "rdap-dns-security-default": "dns-rdap",
    "resolver-dns-security-default": "dns-resolver",
    "ctlogs-dns-security-default": "dns-ctlogs",
    "virustotal-dns-security-default": "dns-virustotal",
    "netlas-dns-security-default": "dns-netlas",
    "dnstwist-phishing-default": "phishing-dnstwist",
    "shodan-phishing-default": "phishing-shodan",
    "netlas-phishing-default": "phishing-netlas",
    "hibp-breaches-default": "breaches-hibp",
    "netlas-exposure-default": "exposure-netlas",
}


def canonical_module_id(raw: str | None) -> str:
    """The stored module id for ``raw``, resolving renamed modules. Shape is not checked here."""
    module = str(raw or "").strip().lower()
    return MODULE_ALIASES.get(module, module)


def canonical_job_type(raw: str | None) -> str:
    """Rewrite the module prefix of a namespaced job type, keeping the connector suffix."""
    job_type = str(raw or "").strip().lower()
    module, dot, rest = job_type.partition(".")
    if not dot:
        return job_type
    return f"{canonical_module_id(module)}.{rest}"


def rename_connector_row(
    name: str,
    aliases: list[str] | None,
    provider: str | None,
    connector_type: str | None,
) -> tuple[str, list[str], str]:
    """The new ``(name, aliases, connector_type)`` for one connector row.

    ``aliases[0]`` (or the name, when there are no aliases) is what
    :func:`app.services.source_observations.source_identity` reads, so it must stay first:
    the migrated row keeps the same observation identity. Every old label remains an alias.
    """
    old_aliases = [str(item) for item in (aliases or [])]
    anchor = old_aliases[0] if old_aliases else name
    new_name = CONNECTOR_NAME_RENAMES.get(name, name)
    ordered: list[str] = []
    for label in [anchor, *old_aliases, name]:
        if label and label not in ordered:
            ordered.append(label)
    return new_name, ordered, canonical_module_id(connector_type)
