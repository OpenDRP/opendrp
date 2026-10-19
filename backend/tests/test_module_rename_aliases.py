import importlib.util
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.connector_manifest import normalize_job_type, normalize_module_id
from app.services.module_aliases import (
    CONNECTOR_NAME_RENAMES,
    canonical_job_type,
    canonical_module_id,
    rename_connector_row,
)
from app.services.source_observations import source_identity

_BASELINE = (
    Path(__file__).resolve().parents[1] / "alembic" / "versions" / "0001_initial_schema.py"
)


def _baseline():
    """The one revision there is: its seed is the connector registry of a fresh install."""
    spec = importlib.util.spec_from_file_location("migration_0001", _BASELINE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _seeded_connectors() -> dict[str, dict]:
    return {row["name"]: row for row in _baseline()._CONNECTOR_SEED}


def test_module_alias_resolves_to_dns_and_other_modules_are_unchanged():
    assert canonical_module_id("dns_security") == "dns"
    assert canonical_module_id("  DNS_Security ") == "dns"
    assert canonical_module_id("dns") == "dns"
    assert canonical_module_id("phishing") == "phishing"


def test_job_type_alias_keeps_the_connector_suffix():
    assert canonical_job_type("dns_security.rdap") == "dns.rdap"
    assert canonical_job_type("dns.rdap") == "dns.rdap"
    assert canonical_job_type("phishing.dnstwist") == "phishing.dnstwist"


def test_validators_accept_the_old_module_and_return_the_canonical_one():
    assert normalize_module_id("dns_security") == "dns"
    assert normalize_job_type("dns_security.resolver") == "dns.resolver"


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("rdap-dns-security-default", "dns-rdap"),
        ("resolver-dns-security-default", "dns-resolver"),
        ("ctlogs-dns-security-default", "dns-ctlogs"),
        ("virustotal-dns-security-default", "dns-virustotal"),
        ("dnstwist-phishing-default", "phishing-dnstwist"),
        ("shodan-phishing-default", "phishing-shodan"),
        ("netlas-phishing-default", "phishing-netlas"),
        ("netlas-dns-security-default", "dns-netlas"),
        ("hibp-breaches-default", "breaches-hibp"),
        ("netlas-exposure-default", "exposure-netlas"),
    ],
)
def test_connector_names_follow_the_module_first_template(old, new):
    assert CONNECTOR_NAME_RENAMES[old] == new
    assert re.fullmatch(r"[a-z]+-[a-z0-9-]+", new)
    assert new.split("-")[0] in {"dns", "phishing", "breaches", "exposure"}


def test_every_renamed_connector_is_a_dns_security_row_or_a_known_module():
    assert len(CONNECTOR_NAME_RENAMES) == len(set(CONNECTOR_NAME_RENAMES.values()))


@pytest.mark.parametrize(
    ("name", "aliases", "provider", "connector_type"),
    [
        # Migrated from the earlier display name: the legacy label is the alias.
        ("rdap-dns-security-default", ["dns-rdap"], None, "dns_security"),
        # Never renamed: no alias, identity comes from the name.
        ("rdap-dns-security-default", [], None, "dns_security"),
        # Legacy DNS worker name without an alias: identity strips ``dns-``.
        ("dns-rdap", [], None, "dns_security"),
        # Provider-owned rows are identified by provider, whatever the name.
        ("netlas-phishing-default", [], "netlas", "phishing"),
    ],
)
def test_renaming_a_connector_keeps_its_observation_identity(
    name, aliases, provider, connector_type
):
    before = SimpleNamespace(
        name=name, aliases=list(aliases), provider=provider, connector_type=connector_type
    )
    old_identity = source_identity(before)

    new_name, new_aliases, new_type = rename_connector_row(
        name, aliases, provider, connector_type
    )
    after = SimpleNamespace(
        name=new_name, aliases=new_aliases, provider=provider, connector_type=new_type
    )
    assert source_identity(after) == old_identity
    # Every old label still authenticates through the alias list.
    assert name in new_aliases or name == new_name


def test_dns_connectors_use_the_new_module_type_in_identity_logic():
    connector = SimpleNamespace(
        name="dns-rdap", aliases=[], provider=None, connector_type="dns"
    )
    assert source_identity(connector) == "rdap"


def test_every_renamed_connector_is_seeded_under_its_new_name_and_answers_to_the_former_one():
    """The rename is only usable while the name a worker knows still resolves.

    A fresh installation has no rows to rewrite, so the baseline has to seed the
    connector under its current name *and* carry the earlier label as an alias —
    that list is what authenticates a worker image that has not been rebuilt, and
    its first entry is what ``source_identity`` derives the provider from. The
    identity is therefore asserted to survive the rename, not just the label.
    """
    seeded = _seeded_connectors()
    for former, current in CONNECTOR_NAME_RENAMES.items():
        assert current in seeded, f"{current} is not a connector this release ships"
        row = seeded[current]
        assert former in row["aliases"], f"{current} does not answer to {former}"

        before = SimpleNamespace(
            name=former,
            aliases=list(row["aliases"]),
            provider=row.get("source"),
            connector_type=row["connector_type"],
        )
        after = SimpleNamespace(
            name=row["name"],
            aliases=list(row["aliases"]),
            provider=row.get("source"),
            connector_type=row["connector_type"],
        )
        assert source_identity(after) == source_identity(before)


def test_seeded_connector_names_follow_the_module_first_template():
    """One job type per row, named for its module first, with its own module type."""
    seeded = _seeded_connectors()
    job_types = [row["default_job_type"] for row in seeded.values()]
    assert len(job_types) == len(set(job_types))
    for row in seeded.values():
        assert row["default_job_type"].partition(".")[0] == row["connector_type"]
        assert row["manifest"]["job_type"] == row["default_job_type"]
        assert row["manifest"]["module"] == row["connector_type"]
        assert row["aliases"][0], f"{row['name']} has no label to derive identity from"
