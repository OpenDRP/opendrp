"""0001_initial_schema

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-09-24 00:00:00.000000

The single baseline revision: it creates the schema this release runs on.

This file is the whole migration history. The schema a deployment runs *is* the
schema this revision creates, because the earlier chain was folded back into it
once every step in that chain described a database created by a build nobody has
outside this repository — a state no deployment can be in, and therefore one no
test can exercise (`tests/test_no_legacy_surface.py` refuses a second file in
this directory for the same reason).

Folding history is schema-neutral, and it is not a data operation:

* a *fresh* database runs this file once and reaches the current schema;
* a database created by an earlier build already holds this schema, so this
  revision is recorded onto it (``scripts/migrate.py`` does that itself when it
  finds a recorded revision this file no longer contains; ``alembic stamp``
  cannot, because it resolves the recorded revision before it writes).
  :doc:`../../docs/upgrading.md` states the procedure and the equality check
  that precedes it.

Three things are raw SQL rather than ``op.*`` calls, deliberately:

* the two enum types, because ``sa.Enum`` creates the type implicitly and a
  second create is an error — matching how the rest of the repository asks for
  ``uuid-ossp`` and ``pg_trgm``;
* the trigram indexes behind substring search (``gin`` + ``gin_trgm_ops``) and
  the expression indexes that match ``app/services/asset_matching.py::sql_key``
  character for character. Neither has a portable spelling, which is also why
  neither is declared on the models: the unit-test schema is built with
  ``create_all`` on SQLite.

The two heavy index families are also why this revision is a maintenance-window
upgrade on a populated database: building them takes a write-blocking lock.
``docs/upgrading.md`` says so.

The seed rows are the platform's own declarations rather than sample data: the
modules (compared with ``app/services/module_registry.py`` by
``tests/test_module_registry.py``) and one row per connector this release ships,
each owning exactly one job type. A connector keeps its earlier label in
``aliases`` because the first alias is what ``source_identity`` derives the
provider from, so a worker image that registers under its former name still
attaches its observations to the same provider. ``storage.adapter`` below is
load-bearing, not decoration: ``ingestion_service._NATIVE_INGESTORS`` dispatches
on it, and an adapter the application does not recognise sends every finding of
that module into ``drp_findings`` instead of its own table.

``downgrade`` returns the schema to empty. There is no earlier revision to
return to and half a baseline is a state no deployment can reach.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


#: The platform's own modules. They are rows, not code: a built-in module and an
#: operator-declared one take the same path through the registry. This tuple is a
#: copy rather than an import — a revision describes its own schema and must not
#: depend on application code that may have moved on — and
#: `tests/test_module_registry.py` compares it with
#: `app.services.module_registry.BUILTIN_MODULE_DEFINITIONS` so the two copies
#: cannot drift.
_MODULE_SEED = (
    {
        "id": "exposure",
        "label": "Exposure",
        "description": "Provider-observed external services; not a vulnerability verification.",
        "finding_kind": "exposure",
        "asset_types": ["domain", "ip_address"],
        "fields": {},
        "dedup_fields": [],
        "title_field": None,
        "storage": {
            "kind": "table",
            "table": "source_observations",
            "adapter": "exposure",
        },
    },
    {
        "id": "phishing",
        "label": "Phishing",
        "description": "Look-alike and malicious domains impersonating your assets.",
        "finding_kind": "phishing",
        "asset_types": ["domain"],
        "fields": {},
        "dedup_fields": ["phishing_domain"],
        "title_field": "phishing_domain",
        "storage": {
            "kind": "table",
            "table": "drp_phishing_domains",
            "adapter": "phishing",
        },
    },
    {
        "id": "breaches",
        "label": "Credential breaches",
        "description": "Credential exposures affecting your monitored accounts and domains.",
        "finding_kind": "breach",
        "asset_types": ["email_account", "domain"],
        "fields": {},
        "dedup_fields": ["breach_name"],
        "title_field": "breach_name",
        "storage": {
            "kind": "table",
            "table": "drp_breaches",
            "adapter": "breach",
        },
    },
    {
        "id": "dns",
        "label": "DNS Security",
        "description": (
            "Current DNS records, registration data, certificate history, and "
            "threat-intelligence observations for monitored domains."
        ),
        "finding_kind": "dns_observation",
        "asset_types": ["domain"],
        "fields": {},
        "dedup_fields": [],
        "title_field": None,
        "storage": {
            "kind": "table",
            "table": "dns_security_observations",
            "adapter": "dns_observation",
        },
    },
)

#: The connectors this release ships, one row per job type. ``source`` names the
#: source account a provider-backed row is attached to; the account row is seeded
#: first and looked up by ``source_id``, so the identifiers written here are the
#: ones a fresh installation reports in ``/connectors``.
_CONNECTOR_SEED = (
    {
        "name": "phishing-dnstwist",
        "connector_type": "phishing",
        "default_job_type": "phishing.dnstwist",
        "manifest": {
            "module": "phishing",
            "job_type": "phishing.dnstwist",
            "finding_kind": "phishing",
            "asset_types": ["domain"],
            "config_schema": {},
        },
        "aliases": ["dnstwist", "dnstwist-phishing-default"],
    },
    {
        "name": "phishing-shodan",
        "connector_type": "phishing",
        "default_job_type": "phishing.shodan",
        "manifest": {
            "module": "phishing",
            "job_type": "phishing.shodan",
            "finding_kind": "phishing",
            "asset_types": ["domain", "keyword_domain", "keyword_title", "ip_address"],
            "config_schema": {
                "scan_ssl_text": {
                    "type": "bool",
                    "label": "Certificate text search",
                    "default": True,
                },
                "scan_http_title": {
                    "type": "bool",
                    "label": "Page title search",
                    "default": True,
                },
                "scan_favicon": {
                    "type": "bool",
                    "label": "Favicon hash search",
                    "default": True,
                },
            },
        },
        "aliases": ["shodan", "shodan-phishing-default"],
        "source": "shodan",
        "status": "enabled",
    },
    {
        "name": "breaches-hibp",
        "connector_type": "breaches",
        "default_job_type": "breaches.hibp",
        "manifest": {
            "module": "breaches",
            "job_type": "breaches.hibp",
            "finding_kind": "breach",
            "asset_types": ["email_account", "domain"],
            "config_schema": {},
        },
        "aliases": ["hibp", "hibp-breaches-default"],
        # The key this worker reads is an account credential, not a container
        # setting: with a provider the core can gate the scan on readiness, draw
        # the requests from one budget and name a refusal instead of returning a
        # short list that reads like "no breaches".
        "source": "hibp",
    },
    {
        "name": "dns-rdap",
        "connector_type": "dns",
        "default_job_type": "dns.rdap",
        "manifest": {
            "module": "dns",
            "job_type": "dns.rdap",
            "finding_kind": "dns_observation",
            "asset_types": ["domain"],
            "config_schema": {},
        },
        "aliases": ["dns-rdap", "rdap-dns-security-default"],
    },
    {
        "name": "dns-resolver",
        "connector_type": "dns",
        "default_job_type": "dns.resolver",
        "manifest": {
            "module": "dns",
            "job_type": "dns.resolver",
            "finding_kind": "dns_observation",
            "asset_types": ["domain"],
            "config_schema": {},
        },
        "aliases": ["dns-resolver", "resolver-dns-security-default"],
    },
    {
        "name": "dns-ctlogs",
        "connector_type": "dns",
        "default_job_type": "dns.ctlogs",
        "manifest": {
            "module": "dns",
            "job_type": "dns.ctlogs",
            "finding_kind": "dns_observation",
            "asset_types": ["domain"],
            "config_schema": {},
        },
        "aliases": ["dns-ctlogs", "ctlogs-dns-security-default"],
    },
    {
        "name": "dns-virustotal",
        "connector_type": "dns",
        "default_job_type": "dns.virustotal",
        "manifest": {
            "module": "dns",
            "job_type": "dns.virustotal",
            "finding_kind": "dns_observation",
            "asset_types": ["domain"],
            "config_schema": {},
        },
        "aliases": ["dns-virustotal", "virustotal-dns-security-default"],
        "source": "virustotal",
        "status": "enabled",
    },
    {
        # The provider read of our *own* addresses. Its free host lookup is the
        # independent confirmation that an address of ours serves a certificate (and
        # carries the organisation, ASN, JARM, title and favicon hash the deployment
        # rules score on); its per-scan capped search answers where else that
        # certificate is being served. It takes both inventory sections because an
        # address is a target in its own right, not only a domain's answer.
        "name": "dns-shodan",
        "connector_type": "dns",
        "default_job_type": "dns.shodan",
        "manifest": {
            "module": "dns",
            "job_type": "dns.shodan",
            "finding_kind": "dns_observation",
            "asset_types": ["domain", "ip_address"],
            "config_schema": {},
        },
        "aliases": ["dns-shodan", "shodan-dns-security-default"],
        "source": "shodan",
        "status": "enabled",
    },
    {
        # The active probe: it asks the service itself what certificate it serves, so
        # the expiry monitor is not limited to what Certificate Transparency happened
        # to index. It needs no provider credential and no source account - the only
        # network traffic is our own handshake against our own asset.
        "name": "dns-tlsprobe",
        "connector_type": "dns",
        "default_job_type": "dns.tlsprobe",
        "manifest": {
            "module": "dns",
            "job_type": "dns.tlsprobe",
            "finding_kind": "dns_observation",
            "asset_types": ["domain"],
            "config_schema": {},
        },
        "aliases": ["dns-tlsprobe", "tlsprobe-dns-security-default"],
    },
    {
        "name": "phishing-netlas",
        "connector_type": "phishing",
        "default_job_type": "phishing.netlas",
        "manifest": {
            "module": "phishing",
            "job_type": "phishing.netlas",
            "finding_kind": "phishing",
            "asset_types": ["domain"],
            "config_schema": {},
        },
        "aliases": ["netlas-phishing", "netlas-phishing-default"],
        "source": "netlas",
    },
    {
        "name": "dns-netlas",
        "connector_type": "dns",
        "default_job_type": "dns.netlas",
        "manifest": {
            "module": "dns",
            "job_type": "dns.netlas",
            "finding_kind": "dns_observation",
            "asset_types": ["domain"],
            "config_schema": {},
        },
        "aliases": ["netlas-dns-security", "netlas-dns-security-default"],
        "source": "netlas",
    },
    {
        "name": "exposure-netlas",
        "connector_type": "exposure",
        "default_job_type": "exposure.netlas",
        "manifest": {
            "module": "exposure",
            "job_type": "exposure.netlas",
            "finding_kind": "exposure",
            "asset_types": ["domain", "ip_address"],
            "config_schema": {},
        },
        "aliases": ["netlas-exposure", "netlas-exposure-default"],
        "source": "netlas",
    },
)

#: Provider-backed connectors are seeded switched off: they carry no key until an
#: operator approves the account and supplies one, and a connector row that
#: cannot run should not be advertised as ready.
#: Providers that own an account row from the first start. HIBP is here for the
#: same reason as the rest: its key, its readiness and the requests a scan spends
#: are facts about an account, and a worker outside that mechanism cannot be
#: refused, paced or explained. The row ships unapproved like the others — an
#: operator approves the policy that allows spending.
_SOURCE_ACCOUNTS = ("netlas", "shodan", "virustotal", "hibp")


def upgrade() -> None:
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")

    op.execute(
        """
        DO $$
        BEGIN
            CREATE TYPE user_role AS ENUM ('admin', 'analyst', 'viewer');
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$;
        """
    )
    user_role = postgresql.ENUM(
        "admin", "analyst", "viewer", name="user_role", create_type=False
    )

    op.execute(
        """
        DO $$
        BEGIN
            CREATE TYPE asset_type AS ENUM (
                'domain',
                'ip_address',
                'email_account',
                'keyword_domain',
                'keyword_title'
            );
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$;
        """
    )
    asset_type = postgresql.ENUM(
        "domain",
        "ip_address",
        "email_account",
        "keyword_domain",
        "keyword_title",
        name="asset_type",
        create_type=False,
    )

    # Sequences the schema defaults read from. The audit sequence is not owned by
    # a column: the chain's position must survive an archive retire, so the
    # default is written explicitly and the sequence is created here.
    op.execute("CREATE SEQUENCE IF NOT EXISTS drp_audit_logs_seq_seq START WITH 1")
    op.execute("CREATE SEQUENCE IF NOT EXISTS audit_archives_first_seq_seq START WITH 1")
    op.execute("CREATE SEQUENCE IF NOT EXISTS report_queue_control_id_seq AS integer")

    op.create_table(
        "alert_recipient_state",
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("next_send_at", sa.DateTime(timezone=True)),
        sa.Column("lease_token", sa.String(length=64)),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.PrimaryKeyConstraint("key", name="alert_recipient_state_pkey"),
    )
    op.create_table(
        "assets",
        sa.Column("id", sa.Uuid(), nullable=False, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("asset_type", asset_type, nullable=False),
        sa.Column("asset_value", sa.String(length=512), nullable=False),
        sa.Column("normalized_value", sa.String(length=512)),
        sa.Column("criticality", sa.String(length=50), nullable=False, server_default="medium"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id", name="pk_assets"),
    )
    op.create_index("ix_assets_asset_type", "assets", ["asset_type"])
    op.create_index(
        "ix_assets_asset_value_trgm",
        "assets",
        ["asset_value"],
        postgresql_using="gin",
        postgresql_ops={"asset_value": "gin_trgm_ops"},
    )
    op.create_index("ix_assets_created_at_id", "assets", ["created_at", "id"])
    op.create_index("ix_assets_normalized_value_key", "assets", [sa.text("lower(rtrim(TRIM(BOTH FROM COALESCE(normalized_value, asset_value)), '.'::text))")])
    op.create_index(
        "ix_assets_normalized_value_trgm",
        "assets",
        ["normalized_value"],
        postgresql_using="gin",
        postgresql_ops={"normalized_value": "gin_trgm_ops"},
    )
    op.create_index("uq_assets_type_normalized_value", "assets", ["asset_type", "normalized_value"], unique=True, postgresql_where=sa.text("(normalized_value IS NOT NULL)"))
    op.create_table(
        "audit_archives",
        sa.Column("first_seq", sa.BigInteger(), nullable=False, server_default=sa.text("nextval('audit_archives_first_seq_seq'::regclass)")),
        sa.Column("last_seq", sa.BigInteger(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("manifest_name", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("retired_at", sa.DateTime(timezone=True)),
        sa.PrimaryKeyConstraint("first_seq", name="audit_archives_pkey"),
        sa.UniqueConstraint("last_seq", name="audit_archives_last_seq_key"),
    )
    op.create_table(
        "dns_security_observations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("observation_key", sa.String(length=64), nullable=False),
        sa.Column("observation_type", sa.String(length=32), nullable=False),
        sa.Column("subject", sa.String(length=253), nullable=False),
        sa.Column("record_type", sa.String(length=16)),
        sa.Column("value", sa.String(length=1000)),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="current"),
        sa.Column("metadata_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("alerted_thresholds", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id", name="pk_dns_security_observations"),
        sa.UniqueConstraint("source", "observation_key", name="uq_dns_observation_source_key"),
    )
    op.create_index("ix_dns_observation_expires", "dns_security_observations", ["expires_at"])
    op.create_index("ix_dns_observation_source_seen", "dns_security_observations", ["source", "last_seen_at"])
    op.create_index("ix_dns_observation_subject_type", "dns_security_observations", ["subject", "observation_type"])
    op.create_index("ix_dns_security_observations_observation_type", "dns_security_observations", ["observation_type"])
    op.create_index("ix_dns_security_observations_source", "dns_security_observations", ["source"])
    op.create_index("ix_dns_security_observations_subject", "dns_security_observations", ["subject"])
    op.create_index("ix_dns_security_observations_subject_key", "dns_security_observations", [sa.text("lower(rtrim(TRIM(BOTH FROM subject), '.'::text))")])
    op.create_index("ix_dns_security_observations_value_key", "dns_security_observations", [sa.text("lower(rtrim(TRIM(BOTH FROM value), '.'::text))")])
    op.create_table(
        "drp_audit_chain",
        sa.Column("id", sa.SmallInteger(), nullable=False, server_default=sa.text("'1'::smallint")),
        sa.Column("retired_through_seq", sa.BigInteger(), nullable=False, server_default=sa.text("'0'::bigint")),
        sa.Column("retired_tip_hash", sa.String(length=64)),
        sa.Column("last_verified_seq", sa.BigInteger(), nullable=False, server_default=sa.text("'0'::bigint")),
        sa.Column("last_verified_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("committed_seq", sa.BigInteger(), nullable=False, server_default=sa.text("'0'::bigint")),
        sa.Column("committed_tip_hash", sa.String(length=64)),
        sa.Column("full_verify_upper_seq", sa.BigInteger(), nullable=False, server_default=sa.text("'0'::bigint")),
        sa.Column("full_verify_upper_hash", sa.String(length=64)),
        sa.Column("full_verify_cursor", sa.BigInteger(), nullable=False, server_default=sa.text("'0'::bigint")),
        sa.Column("full_verify_cursor_hash", sa.String(length=64)),
        sa.Column("last_full_verified_at", sa.DateTime(timezone=True)),
        sa.Column("last_failure_seq", sa.BigInteger()),
        sa.Column("last_failure_reason", sa.String(length=64)),
        sa.PrimaryKeyConstraint("id", name="drp_audit_chain_pkey"),
    )
    op.create_table(
        "drp_audit_logs",
        sa.Column("id", sa.Uuid(), nullable=False, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("user_id", sa.Uuid()),
        sa.Column("action", sa.String(length=120), nullable=False),
        sa.Column("ip_address", sa.String(length=64), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("seq", sa.BigInteger(), nullable=False, server_default=sa.text("nextval('drp_audit_logs_seq_seq'::regclass)")),
        sa.Column("entry_hash", sa.String(length=64), nullable=False),
        sa.Column("prev_hash", sa.String(length=64)),
        sa.Column("key_id", sa.SmallInteger(), nullable=False, server_default=sa.text("'0'::smallint")),
        sa.PrimaryKeyConstraint("id", name="pk_drp_audit_logs"),
        sa.UniqueConstraint("seq", name="uq_drp_audit_logs_seq"),
    )
    op.create_index("ix_audit_job_id", "drp_audit_logs", [sa.text("(details ->> 'job_id'::text)")])
    op.create_index("ix_audit_request_id", "drp_audit_logs", [sa.text("(details ->> 'request_id'::text)")])
    op.create_index("ix_audit_timestamp_id", "drp_audit_logs", ["timestamp", "id"])
    op.create_index("ix_drp_audit_logs_action", "drp_audit_logs", ["action"])
    op.create_index("ix_drp_audit_logs_entry_hash", "drp_audit_logs", ["entry_hash"])
    op.create_index("ix_drp_audit_logs_timestamp", "drp_audit_logs", ["timestamp"])
    op.create_index("ix_drp_audit_logs_user_id", "drp_audit_logs", ["user_id"])
    op.create_index("ix_drp_audit_logs_user_timestamp", "drp_audit_logs", ["user_id", "timestamp"])
    op.create_table(
        "drp_breaches",
        sa.Column("id", sa.Uuid(), nullable=False, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("breach_name", sa.String(length=255), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("domain", sa.String(length=255), nullable=False),
        sa.Column("breach_date", sa.Date(), nullable=False),
        sa.Column("pwn_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("description", sa.Text()),
        sa.Column("data_classes", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("matched_email", sa.String(length=255)),
        sa.Column("matched_domain", sa.String(length=255)),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="active"),
        # Which kind of exposure the row records (breach, paste, stealer log). The
        # module's unique pairs are unchanged by it: the class is also encoded in
        # breach_name, so an installation that adopts the column keeps its indexes
        # (WI-21).
        sa.Column("exposure_kind", sa.String(length=32), nullable=False, server_default="breach"),
        # How loud the row is, from the classes of data it exposed (F-13). Stored so the
        # list can filter and sort on it as it does on any other column; ``unknown`` is
        # what a row written before the rule existed honestly is.
        sa.Column("severity", sa.String(length=16), nullable=False, server_default="unknown"),
        sa.Column("attributes", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        # When the source last reported the incident, and when it first confirmed it
        # (WI-08, WI-11). Separate from ``updated_at``, which moves when anything on
        # the row is rewritten - including a scan that found the same facts again.
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("verified_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("source_id", sa.String(length=100), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_drp_breaches"),
        sa.UniqueConstraint("source_id", "breach_name", "matched_email", name="uq_breach_email"),
    )
    op.create_index("ix_drp_breaches_exposure_kind", "drp_breaches", ["exposure_kind"])
    op.create_index("ix_drp_breaches_severity", "drp_breaches", ["severity"])
    op.create_index("ix_drp_breaches_matched_domain", "drp_breaches", ["matched_domain"])
    op.create_index("ix_drp_breaches_matched_domain_key", "drp_breaches", [sa.text("lower(rtrim(TRIM(BOTH FROM matched_domain), '.'::text))")])
    op.create_index("ix_drp_breaches_matched_email", "drp_breaches", ["matched_email"])
    op.create_index("ix_drp_breaches_matched_email_domain", "drp_breaches", [sa.text("lower(split_part(matched_email::text, '@'::text, 2))")])
    op.create_index("ix_drp_breaches_matched_email_key", "drp_breaches", [sa.text("lower(rtrim(TRIM(BOTH FROM matched_email), '.'::text))")])
    op.create_index("ix_drp_breaches_status", "drp_breaches", ["status"])
    op.create_index("uq_breach_domain_only", "drp_breaches", ["source_id", "breach_name", "matched_domain"], unique=True, postgresql_where=sa.text("((matched_domain IS NOT NULL) AND (matched_email IS NULL))"))
    op.create_table(
        "breach_catalogue",
        sa.Column("id", sa.Uuid(), nullable=False, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("source", sa.String(length=100), nullable=False),
        sa.Column("breach_name", sa.String(length=255), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("domain", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("breach_date", sa.Date()),
        # The source's own catalogue timestamps: when it added the incident and when
        # it last changed it. Distinct from ``created_at``/``updated_at``, which are
        # when this platform first saw and last refreshed the row - a source that
        # corrects ``added_date`` must not make an old incident look new (F-09).
        sa.Column("added_date", sa.DateTime(timezone=True)),
        sa.Column("modified_date", sa.DateTime(timezone=True)),
        sa.Column("pwn_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("data_classes", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("attributes", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        # When a sync last confirmed the incident is still in the source's catalogue,
        # which is also what the window handed to the connector is measured from.
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id", name="pk_breach_catalogue"),
        sa.UniqueConstraint("source", "breach_name", name="uq_breach_catalogue_incident"),
    )
    op.create_index("ix_breach_catalogue_source_domain", "breach_catalogue", ["source", "domain"])
    op.create_table(
        "drp_modules",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("label", sa.String(length=120), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("finding_kind", sa.String(length=32), nullable=False),
        sa.Column("asset_types", sa.JSON(), nullable=False),
        sa.Column("fields", sa.JSON(), nullable=False),
        sa.Column("dedup_fields", sa.JSON(), nullable=False),
        sa.Column("title_field", sa.String(length=64)),
        sa.Column("storage", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("builtin", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id", name="pk_drp_modules"),
        sa.UniqueConstraint("finding_kind", name="uq_modules_finding_kind"),
    )
    op.create_table(
        "drp_phishing_domains",
        sa.Column("id", sa.Uuid(), nullable=False, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("phishing_domain", sa.String(length=512), nullable=False),
        sa.Column("matched_asset", sa.String(length=512), nullable=False),
        sa.Column("ip_address", sa.String(length=255)),
        sa.Column("web_ports", sa.String(length=255)),
        sa.Column("detection_source", sa.String(length=100), nullable=False),
        sa.Column("original_domain", sa.String(length=512)),
        sa.Column("whois_registrar", sa.String(length=255)),
        sa.Column("whois_abuse_email", sa.String(length=255)),
        sa.Column("domain_created_at", sa.DateTime(timezone=True)),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="active"),
        sa.Column("confidence", sa.SmallInteger(), nullable=False, server_default="0"),
        sa.Column("signals", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("digest_queued_at", sa.DateTime(timezone=True)),
        # WI-12 (W1.6): the analyst's decision and who made it. Nullable with no
        # default, because "nobody has decided" is the ordinary state and a default
        # verdict would make every candidate look reviewed.
        sa.Column("verdict", sa.String(length=32)),
        sa.Column("verdict_reason", sa.String(length=2000)),
        sa.Column("verdict_by", sa.Uuid()),
        sa.Column("verdict_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id", name="pk_drp_phishing_domains"),
        sa.UniqueConstraint("phishing_domain", name="uq_drp_phishing_domains_phishing_domain"),
    )
    op.create_index("ix_drp_phishing_domains_matched_asset", "drp_phishing_domains", ["matched_asset"])
    op.create_index("ix_drp_phishing_domains_matched_asset_key", "drp_phishing_domains", [sa.text("lower(rtrim(TRIM(BOTH FROM matched_asset), '.'::text))")])
    op.create_index("ix_drp_phishing_domains_phishing_domain", "drp_phishing_domains", ["phishing_domain"], unique=True)
    op.create_index("ix_drp_phishing_domains_status", "drp_phishing_domains", ["status"])
    # Substring search on the candidate list (AST-47): the list asks
    # `ILIKE '%term%'` of the domain, the matched asset and the address, and a
    # btree cannot answer a leading wildcard. Without these every search reads
    # the whole table, which is the platform's most expensive search once
    # candidates accumulate. Same shape as the asset list's search indexes.
    op.create_index(
        "ix_drp_phishing_domains_phishing_domain_trgm",
        "drp_phishing_domains",
        ["phishing_domain"],
        postgresql_using="gin",
        postgresql_ops={"phishing_domain": "gin_trgm_ops"},
    )
    op.create_index(
        "ix_drp_phishing_domains_matched_asset_trgm",
        "drp_phishing_domains",
        ["matched_asset"],
        postgresql_using="gin",
        postgresql_ops={"matched_asset": "gin_trgm_ops"},
    )
    op.create_index(
        "ix_drp_phishing_domains_ip_address_trgm",
        "drp_phishing_domains",
        ["ip_address"],
        postgresql_using="gin",
        postgresql_ops={"ip_address": "gin_trgm_ops"},
    )
    # The candidate list's own access paths (WI-08/WI-11). `confidence` leads both
    # because every read that uses either index starts there: the confidence band
    # of the alert budget, the `min_confidence` filter, and the list ordered by
    # what the scoring decided. `status` rides along in the composite as a
    # filter-only column, so "active, high confidence" does not fall back to the
    # status index and then sort.
    op.create_index("ix_phishing_confidence", "drp_phishing_domains", ["confidence"])
    op.create_index("ix_phishing_domains_confidence_status", "drp_phishing_domains", ["confidence", "status"])
    # The evidence behind a candidate's score, one row per signal that fired. A
    # child table rather than more columns on the candidate: a signal is a fact
    # about a candidate with its own source and time, several of them accumulate
    # over the candidate's life, and the map on the row above is only their
    # summary (WI-08). The cascade is what keeps a deleted candidate from leaving
    # its explanations behind.
    op.create_table(
        "phishing_candidate_signals",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("candidate_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("value", sa.JSON(), nullable=False),
        sa.Column("confidence", sa.SmallInteger(), nullable=False, server_default="0"),
        sa.Column("observed_at", sa.DateTime(timezone=True)),
        sa.Column("source", sa.String(length=100)),
        sa.PrimaryKeyConstraint("id", name="phishing_candidate_signals_pkey"),
        sa.ForeignKeyConstraint(["candidate_id"], ["drp_phishing_domains.id"], name="phishing_candidate_signals_candidate_id_fkey", ondelete="CASCADE"),
    )
    op.create_index("ix_phishing_candidate_signals_candidate", "phishing_candidate_signals", ["candidate_id"])
    op.create_table(
        "drp_refresh_families",
        sa.Column("id", sa.Uuid(), nullable=False, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("family_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("last_jti", sa.String(length=120)),
        sa.Column("last_issued_at", sa.DateTime(timezone=True)),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_reason", sa.String(length=120)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id", name="pk_drp_refresh_families"),
        sa.UniqueConstraint("family_id", name="uq_drp_refresh_families_family_id"),
    )
    op.create_index("ix_drp_refresh_families_family_id", "drp_refresh_families", ["family_id"], unique=True)
    op.create_index("ix_drp_refresh_families_revoked", "drp_refresh_families", ["revoked"])
    op.create_index("ix_drp_refresh_families_user_id", "drp_refresh_families", ["user_id"])
    op.create_table(
        "report_artifact_cleanup",
        sa.Column("artifact_name", sa.String(length=255), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("last_error", sa.Text()),
        sa.Column("report_id", sa.Uuid()),
        sa.PrimaryKeyConstraint("artifact_name", name="pk_report_artifact_cleanup"),
    )
    op.create_index("ix_report_artifact_cleanup_available_at", "report_artifact_cleanup", ["available_at"])
    op.create_index("ix_report_artifact_cleanup_report_id", "report_artifact_cleanup", ["report_id"])
    op.create_table(
        "report_audit_outbox",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("event_key", sa.String(length=255), nullable=False),
        sa.Column("action", sa.String(length=80), nullable=False),
        sa.Column("report_id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid()),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("last_error", sa.Text()),
        sa.PrimaryKeyConstraint("id", name="pk_report_audit_outbox"),
        sa.UniqueConstraint("event_key", name="uq_report_audit_outbox_event_key"),
    )
    op.create_index("ix_report_audit_outbox_available_at", "report_audit_outbox", ["available_at"])
    op.create_index("ix_report_audit_outbox_report_id", "report_audit_outbox", ["report_id"])
    op.create_table(
        "report_queue_control",
        sa.Column("id", sa.Integer(), nullable=False, server_default=sa.text("nextval('report_queue_control_id_seq'::regclass)")),
        sa.Column("touched_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id", name="pk_report_queue_control"),
    )
    op.create_table(
        "source_accounts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("credential_ref", sa.String(length=128)),
        sa.Column("policy", sa.JSON(), nullable=False),
        sa.Column("access_state", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("api_key_encrypted", sa.Text()),
        sa.Column("api_key_hint", sa.String(length=16)),
        sa.PrimaryKeyConstraint("id", name="source_accounts_pkey"),
        sa.UniqueConstraint("source_id", "name", name="uq_source_account"),
    )
    op.create_table(
        "system_settings",
        sa.Column("id", sa.Uuid(), nullable=False, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("smtp_host", sa.String(length=255)),
        sa.Column("smtp_user", sa.String(length=255)),
        sa.Column("smtp_password", sa.String(length=1024)),
        sa.Column("smtp_from_email", sa.String(length=1024)),
        sa.Column("smtp_port", sa.Integer(), nullable=False, server_default=sa.text("587")),
        sa.Column("smtp_security_mode", sa.String(length=16), nullable=False, server_default="starttls"),
        sa.Column("alert_recipient_email", sa.String(length=1024)),
        sa.Column("telegram_bot_token", sa.String(length=1024)),
        sa.Column("telegram_chat_ids", sa.JSON()),
        sa.Column("email_alerts_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("telegram_alerts_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("alert_email_user_ids", sa.JSON()),
        sa.Column("schedule_phishing", sa.JSON()),
        sa.Column("schedule_breaches", sa.JSON()),
        # The operator's half of the alert budget (WI-07/WI-10). Nullable by
        # design: NULL is "the deployment's environment answers this one", so an
        # installation that never saved the Settings page keeps the values its
        # Compose file states, and a save that sets one of them leaves the rest
        # alone. See app/services/alert_policy.py for how the two are merged.
        sa.Column("alert_confidence_direct", sa.SmallInteger()),
        sa.Column("alert_confidence_digest", sa.SmallInteger()),
        sa.Column("alert_phishing_digest_enabled", sa.Boolean()),
        sa.Column("alert_phishing_digest_hour_utc", sa.SmallInteger()),
        sa.Column("alert_no_channel_retry_hours", sa.SmallInteger()),
        sa.Column("alert_candidate_change_notifications", sa.Boolean()),
        # The breach module's half of the budget: which incidents the source's own
        # spam/fabricated flags silence, and how many new incidents one scan reports
        # before the rest wait for the digest (WI-05, WI-06).
        sa.Column("alert_breach_noise_policy", sa.String(length=32)),
        sa.Column("alert_breach_digest_threshold", sa.SmallInteger()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("schedule_dns_security", sa.JSON()),
        sa.Column("schedule_exposure", sa.JSON()),
        sa.Column("schedules", sa.JSON()),
        sa.Column("singleton_key", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("version", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.PrimaryKeyConstraint("id", name="pk_system_settings"),
        sa.UniqueConstraint("singleton_key", name="uq_system_settings_singleton_key"),
        sa.CheckConstraint("singleton_key = 1", name="ck_system_settings_singleton"),
        sa.CheckConstraint(
            "smtp_security_mode IN ('starttls', 'ssl', 'plain')",
            name="ck_system_settings_smtp_security_mode",
        ),
    )
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", user_role, nullable=False, server_default=sa.text("'viewer'::user_role")),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("full_name", sa.String(length=255)),
        sa.Column("last_login_at", sa.DateTime(timezone=True)),
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("locked_until", sa.DateTime(timezone=True)),
        sa.Column("rate_limit_minutes", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("totp_secret", sa.String(length=1024)),
        sa.Column("totp_enabled_at", sa.DateTime(timezone=True)),
        sa.Column("totp_last_used_step", sa.Integer()),
        sa.Column("mfa_failed_attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("mfa_locked_until", sa.DateTime(timezone=True)),
        sa.Column("mfa_recovery_codes", sa.JSON()),
        sa.Column("must_change_password", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("must_enrol_mfa", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        # U-7: an outstanding invitation keeps only a digest of its token, so a
        # database copy carries no usable link.
        sa.Column("invitation_token_hash", sa.String(length=64), nullable=True),
        sa.Column("invitation_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index(
        "ix_users_invitation_token_hash", "users", ["invitation_token_hash"]
    )
    # The verdict's author (WI-12) is the one foreign key this revision cannot state
    # inline: ``drp_phishing_domains`` is created before ``users`` exists, so the
    # constraint is added here, after the table it points at. ``SET NULL`` matches
    # the review columns of the certificate sightings — a deleted account leaves the
    # decision in place, and the audit trail keeps who made it.
    op.create_foreign_key(
        "drp_phishing_domains_verdict_by_fkey",
        "drp_phishing_domains",
        "users",
        ["verdict_by"],
        ["id"],
        ondelete="SET NULL",
    )
    # The refresh family's owner, stated here for the same reason: the family
    # table is created before ``users`` exists. ``CASCADE`` rather than the
    # router's hand-written DELETE, because a family that outlives its account is
    # a session nobody can revoke — the retention sweep deletes by ``revoked_at``
    # and an orphan has no reason recorded to sweep on.
    op.create_foreign_key(
        "fk_drp_refresh_families_user_id_users",
        "drp_refresh_families",
        "users",
        ["user_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_table(
        "dns_expiry_monitors",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("subject", sa.String(length=253), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("successful_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("certificate_id", sa.String(length=128)),
        sa.Column("not_before", sa.DateTime(timezone=True)),
        sa.Column("observation_id", sa.Uuid()),
        sa.Column("cycle", sa.String(length=64)),
        sa.Column("alerted_thresholds", sa.JSON(), nullable=False),
        sa.Column("stale_alerted_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id", name="dns_expiry_monitors_pkey"),
        sa.UniqueConstraint("asset_id", "kind", name="uq_dns_expiry_monitor_asset_kind"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], name="dns_expiry_monitors_asset_id_fkey", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["observation_id"], ["dns_security_observations.id"], name="dns_expiry_monitors_observation_id_fkey", ondelete="SET NULL"),
    )
    op.create_index("ix_dns_expiry_monitor_due", "dns_expiry_monitors", ["state", "expires_at"])
    op.create_table(
        "tls_certificate_identities",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("fingerprint_sha256", sa.String(length=64), nullable=False),
        sa.Column("fingerprint_sha1", sa.String(length=40)),
        sa.Column("spki_sha256", sa.String(length=64)),
        sa.Column("serial_hex", sa.String(length=128)),
        sa.Column("subject_dn", sa.String(length=1000)),
        sa.Column("issuer_dn", sa.String(length=1000)),
        sa.Column("not_before", sa.DateTime(timezone=True)),
        sa.Column("not_after", sa.DateTime(timezone=True)),
        sa.Column("san_dns", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("key_algo", sa.String(length=64)),
        sa.Column("origin", sa.String(length=32), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id", name="tls_certificate_identities_pkey"),
        sa.UniqueConstraint("fingerprint_sha256", name="uq_tls_identity_fingerprint_sha256"),
    )
    op.create_index("ix_tls_identity_serial", "tls_certificate_identities", ["serial_hex"])
    op.create_index("ix_tls_identity_spki", "tls_certificate_identities", ["spki_sha256"])
    op.create_table(
        "tls_certificate_sightings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("identity_id", sa.Uuid(), nullable=False),
        sa.Column("subject", sa.String(length=253)),
        sa.Column("ip", sa.String(length=64)),
        sa.Column("port", sa.Integer()),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_ours", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("confidence", sa.SmallInteger(), nullable=False, server_default="0"),
        sa.Column("signals", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("verdict", sa.String(length=32), nullable=False, server_default="candidate"),
        sa.Column("reviewed_by", sa.Uuid()),
        sa.Column("reviewed_at", sa.DateTime(timezone=True)),
        sa.Column("review_note", sa.String(length=2000)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id", name="tls_certificate_sightings_pkey"),
        sa.UniqueConstraint("identity_id", "ip", "port", "source", name="uq_tls_sighting_identity_endpoint_source"),
        sa.ForeignKeyConstraint(["identity_id"], ["tls_certificate_identities.id"], name="tls_certificate_sightings_identity_id_fkey", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["reviewed_by"], ["users.id"], name="tls_certificate_sightings_reviewed_by_fkey", ondelete="SET NULL"),
    )
    op.create_index("ix_tls_sighting_identity", "tls_certificate_sightings", ["identity_id"])
    op.create_index("ix_tls_sighting_ip", "tls_certificate_sightings", ["ip"])
    op.create_index("ix_tls_sighting_verdict", "tls_certificate_sightings", ["verdict"])
    op.create_table(
        "certificate_scope_exceptions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("match_kind", sa.String(length=16), nullable=False),
        sa.Column("match_value", sa.String(length=255), nullable=False),
        sa.Column("reason", sa.String(length=1000)),
        sa.Column("created_by", sa.Uuid()),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id", name="certificate_scope_exceptions_pkey"),
        sa.UniqueConstraint("match_kind", "match_value", name="uq_certificate_scope_exception"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], name="certificate_scope_exceptions_created_by_fkey", ondelete="SET NULL"),
    )
    op.create_index("ix_tls_exception_kind_value", "certificate_scope_exceptions", ["match_kind", "match_value"])
    op.create_table(
        "drp_connectors",
        sa.Column("id", sa.Uuid(), nullable=False, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("connector_type", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="enabled"),
        sa.Column("api_version", sa.String(length=32)),
        sa.Column("default_job_type", sa.String(length=50), nullable=False),
        sa.Column("manifest", sa.JSON()),
        sa.Column("config", sa.JSON()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.String(length=2000)),
        sa.Column("info", sa.JSON()),
        sa.Column("token_hash", sa.String(length=64)),
        sa.Column("token_prefix", sa.String(length=16)),
        sa.Column("token_created_at", sa.DateTime(timezone=True)),
        sa.Column("token_last_used_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("provider", sa.String(length=32)),
        sa.Column("quota_group", sa.String(length=64)),
        sa.Column("readiness", sa.JSON()),
        sa.Column("last_success_at", sa.DateTime(timezone=True)),
        sa.Column("source_account_id", sa.Uuid()),
        sa.Column("aliases", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")),
        sa.PrimaryKeyConstraint("id", name="pk_drp_connectors"),
        sa.UniqueConstraint("name", name="uq_drp_connectors_name"),
        sa.CheckConstraint("status IN ('enabled', 'disabled')", name="ck_connectors_status"),
        sa.ForeignKeyConstraint(["source_account_id"], ["source_accounts.id"], name="drp_connectors_source_account_id_fkey", ondelete="SET NULL"),
    )
    op.create_index("ix_drp_connectors_connector_type", "drp_connectors", ["connector_type"])
    op.create_index("ix_drp_connectors_name", "drp_connectors", ["name"], unique=True)
    op.create_index("ix_drp_connectors_token_hash", "drp_connectors", ["token_hash"], unique=True)
    op.create_table(
        "drp_findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("module", sa.String(length=32), nullable=False),
        sa.Column("finding_kind", sa.String(length=32), nullable=False),
        sa.Column("connector_name", sa.String(length=100), nullable=False),
        sa.Column("job_id", sa.Uuid()),
        sa.Column("dedup_key", sa.String(length=512), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("matched_asset", sa.String(length=512)),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="active"),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id", name="drp_findings_pkey"),
        sa.UniqueConstraint("module", "dedup_key", name="uq_findings_module_dedup"),
        sa.ForeignKeyConstraint(["module"], ["drp_modules.id"], name="drp_findings_module_fkey", ondelete="RESTRICT"),
    )
    op.create_index("ix_drp_findings_connector_name", "drp_findings", ["connector_name"])
    op.create_index("ix_drp_findings_matched_asset", "drp_findings", ["matched_asset"])
    op.create_index("ix_drp_findings_matched_asset_key", "drp_findings", [sa.text("lower(rtrim(TRIM(BOTH FROM matched_asset), '.'::text))")])
    op.create_index("ix_drp_findings_module_created", "drp_findings", ["module", "created_at"])
    op.create_index("ix_drp_findings_status", "drp_findings", ["status"])
    op.create_table(
        "reports",
        sa.Column("id", sa.Uuid(), nullable=False, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("report_name", sa.String(length=255), nullable=False),
        sa.Column("created_by", sa.Uuid()),
        sa.Column("file_path", sa.String(length=512), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="pending"),
        sa.Column("is_truncated", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("truncation_metadata", sa.JSON()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("generation_started_at", sa.DateTime(timezone=True)),
        sa.PrimaryKeyConstraint("id", name="pk_reports"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], name="fk_reports_created_by_users", ondelete="SET NULL"),
    )
    op.create_index("ix_reports_created_at", "reports", ["created_at"])
    op.create_index("ix_reports_status", "reports", ["status"])
    op.create_table(
        "jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("job_type", sa.String(length=50), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("created_by", sa.Uuid()),
        sa.Column("task_id", sa.String(length=128)),
        sa.Column("title", sa.String(length=255)),
        sa.Column("error_message", sa.Text()),
        sa.Column("params", sa.JSON()),
        sa.Column("result_summary", sa.JSON()),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True)),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("claimed_by_connector", sa.String(length=100)),
        sa.Column("lease_token", sa.String(length=64)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("connector_id", sa.Uuid()),
        sa.Column("schedule_key", sa.String(length=128)),
        sa.PrimaryKeyConstraint("id", name="pk_jobs"),
        sa.UniqueConstraint("schedule_key", name="uq_jobs_schedule_key"),
        sa.CheckConstraint("char_length(job_type::text) >= 1 AND char_length(job_type::text) <= 50", name="ck_jobs_job_type_len"),
        sa.CheckConstraint("char_length(status::text) >= 1 AND char_length(status::text) <= 32", name="ck_jobs_status_len"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], name="fk_jobs_created_by_users", ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["connector_id"], ["drp_connectors.id"], name="jobs_connector_id_fkey", ondelete="SET NULL"),
    )
    op.create_index("ix_jobs_connector_id", "jobs", ["connector_id"])
    op.create_index("ix_jobs_created_by", "jobs", ["created_by"])
    op.create_index("ix_jobs_job_type", "jobs", ["job_type"])
    op.create_index("ix_jobs_lease_expires_at", "jobs", ["lease_expires_at"])
    op.create_index("ix_jobs_status", "jobs", ["status"])
    op.create_index("ix_jobs_task_id", "jobs", ["task_id"])
    # The claim path (`ConnectorService.claim_work`) filters on
    # `status='pending'` and orders by `created_at`, and it runs on every poll of
    # every connector — the most frequent read this table has. `ix_jobs_status`
    # narrows the filter but leaves the order to the planner, so the composite is
    # the one that makes the claim a single index scan.
    op.create_index("ix_jobs_status_created", "jobs", ["status", "created_at"])
    op.create_table(
        "source_observations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("module", sa.String(length=32), nullable=False),
        sa.Column("source", sa.String(length=100), nullable=False),
        sa.Column("observation_key", sa.String(length=64), nullable=False),
        sa.Column("subject", sa.String(length=253), nullable=False),
        sa.Column("matched_asset", sa.String(length=512), nullable=False),
        sa.Column("candidate_id", sa.Uuid()),
        sa.Column("job_id", sa.Uuid()),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True)),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("connector_id", sa.Uuid()),
        sa.Column("source_account_id", sa.Uuid()),
        sa.Column("provenance", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.PrimaryKeyConstraint("id", name="source_observations_pkey"),
        sa.UniqueConstraint("module", "source", "observation_key", name="uq_source_observation"),
        sa.ForeignKeyConstraint(["candidate_id"], ["drp_phishing_domains.id"], name="source_observations_candidate_id_fkey", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["connector_id"], ["drp_connectors.id"], name="source_observations_connector_id_fkey", ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["source_account_id"], ["source_accounts.id"], name="source_observations_source_account_id_fkey", ondelete="SET NULL"),
    )
    op.create_index("ix_source_observations_matched_asset", "source_observations", ["matched_asset"])
    op.create_index("ix_source_observations_matched_asset_key", "source_observations", [sa.text("lower(rtrim(TRIM(BOTH FROM matched_asset), '.'::text))")])
    op.create_index("ix_source_observations_module_seen", "source_observations", ["module", "last_seen_at"])
    op.create_table(
        "alert_deliveries",
        sa.Column("id", sa.Uuid(), nullable=False, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("job_id", sa.Uuid()),
        sa.Column("threat_type", sa.String(length=100), nullable=False),
        sa.Column("channel", sa.String(length=20), nullable=False),
        sa.Column("target", sa.String(length=512)),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("locked_at", sa.DateTime(timezone=True)),
        sa.Column("sent_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("lease_token", sa.String(length=64)),
        sa.Column("batch_id", sa.String(length=64)),
        sa.Column("parts", sa.JSON()),
        sa.Column("acknowledged_parts", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.PrimaryKeyConstraint("id", name="alert_deliveries_pkey"),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], name="alert_deliveries_job_id_fkey", ondelete="SET NULL"),
    )
    op.create_index("ix_alert_deliveries_batch_id", "alert_deliveries", ["batch_id"])
    op.create_index("ix_alert_deliveries_channel", "alert_deliveries", ["channel"])
    op.create_index("ix_alert_deliveries_job_id", "alert_deliveries", ["job_id"])
    op.create_index("ix_alert_deliveries_next_attempt_at", "alert_deliveries", ["next_attempt_at"])
    op.create_index("ix_alert_deliveries_status", "alert_deliveries", ["status"])
    op.create_index("ix_alert_deliveries_target", "alert_deliveries", ["target"])
    op.create_index("ix_alert_deliveries_threat_type", "alert_deliveries", ["threat_type"])
    op.create_index("ix_alert_delivery_due", "alert_deliveries", ["status", "next_attempt_at", "created_at"])
    op.create_table(
        "ingestion_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("event_key", sa.String(length=128), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("module", sa.String(length=32), nullable=False),
        sa.Column("entity_id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid()),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True)),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.String(length=128)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id", name="ingestion_events_pkey"),
        sa.UniqueConstraint("event_key", name="ingestion_events_event_key_key"),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], name="ingestion_events_job_id_fkey", ondelete="SET NULL"),
    )
    # The outbox dispatcher's access path (`ingestion_events.dispatch_notification_events`
    # and `enrich_one_event`): `kind`, `processed_at IS NULL`, a due
    # `next_attempt_at`, ordered by `created_at`. It runs every fifteen seconds
    # over the rows the retention window keeps — which is the whole table the
    # dispatcher is supposed to drain — so without this it is a scan per tick.
    op.create_index(
        "ix_ingestion_events_due",
        "ingestion_events",
        ["kind", "processed_at", "next_attempt_at"],
    )
    op.create_table(
        "schedule_occurrences",
        sa.Column("key", sa.String(length=128), nullable=False),
        sa.Column("job_id", sa.Uuid()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("key", name="schedule_occurrences_pkey"),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], name="schedule_occurrences_job_id_fkey", ondelete="SET NULL"),
    )
    # The archive position and the report queue row are drawn from a sequence the
    # column owns, so the two are linked here exactly as a serial column would be.
    op.execute(
        "ALTER SEQUENCE audit_archives_first_seq_seq OWNED BY audit_archives.first_seq"
    )
    op.execute(
        "ALTER SEQUENCE report_queue_control_id_seq OWNED BY report_queue_control.id"
    )

    # -----------------------------------------------------------------------
    # Seed: built-in modules
    # -----------------------------------------------------------------------
    modules = sa.table(
        "drp_modules",
        sa.column("id", sa.String),
        sa.column("label", sa.String),
        sa.column("description", sa.Text),
        sa.column("finding_kind", sa.String),
        sa.column("asset_types", sa.JSON),
        sa.column("fields", sa.JSON),
        sa.column("dedup_fields", sa.JSON),
        sa.column("title_field", sa.String),
        sa.column("storage", sa.JSON),
        sa.column("enabled", sa.Boolean),
        sa.column("builtin", sa.Boolean),
    )
    op.bulk_insert(
        modules,
        [{**row, "enabled": True, "builtin": True} for row in _MODULE_SEED],
    )

    # -----------------------------------------------------------------------
    # Seed: source accounts
    # -----------------------------------------------------------------------
    # Accounts and connectors are separate rows because a provider is not a
    # module: one key can serve several connectors, and revoking it is a policy
    # decision (`access_state`) rather than a connector setting.
    for source_id in _SOURCE_ACCOUNTS:
        op.execute(
            sa.text(
                """
                INSERT INTO source_accounts
                    (id, source_id, name, policy, access_state, created_at, updated_at)
                VALUES
                    (uuid_generate_v4(), :source_id, 'default',
                     '{"approved": false}'::json, 'unknown', now(), now())
                ON CONFLICT (source_id, name) DO NOTHING
                """
            ).bindparams(source_id=source_id)
        )

    # -----------------------------------------------------------------------
    # Seed: connectors
    # -----------------------------------------------------------------------
    # The seeded declaration is what makes the registry readable before a worker
    # has ever started, and each job type is owned by exactly one row.
    connection = op.get_bind()
    account_ids = {
        row.source_id: row.id
        for row in connection.execute(
            sa.text("SELECT id, source_id FROM source_accounts")
        )
    }
    connectors = sa.table(
        "drp_connectors",
        sa.column("name", sa.String),
        sa.column("connector_type", sa.String),
        sa.column("status", sa.String),
        sa.column("default_job_type", sa.String),
        sa.column("manifest", sa.JSON),
        sa.column("config", sa.JSON),
        sa.column("provider", sa.String),
        sa.column("quota_group", sa.String),
        sa.column("source_account_id", sa.Uuid),
        sa.column("aliases", sa.JSON),
    )
    #: A provider-backed row ships switched off when it needs an operator's key
    #: and an approved budget (netlas), and switched on when the profile that
    #: starts its worker is the whole opt-in (shodan, virustotal) — so the status
    #: is declared per row rather than inferred from the presence of a source.
    seeded_connectors = []
    for row in _CONNECTOR_SEED:
        status = row.get("status", "disabled" if row.get("source") else "enabled")
        seeded_connectors.append(
            {
                "name": row["name"],
                "connector_type": row["connector_type"],
                "status": status,
                "default_job_type": row["default_job_type"],
                "manifest": row["manifest"],
                "config": {} if status == "disabled" else None,
                "provider": row.get("source"),
                "quota_group": "default" if row.get("source") else None,
                "source_account_id": account_ids.get(row.get("source")),
                "aliases": row["aliases"],
            }
        )
    op.bulk_insert(connectors, seeded_connectors)

    # -----------------------------------------------------------------------
    # Seed: settings singleton and the audit chain head
    # -----------------------------------------------------------------------
    op.execute(
        sa.text(
            """
            INSERT INTO system_settings
                (id, schedule_phishing, schedule_breaches, schedule_dns_security,
                 created_at, updated_at)
            VALUES (
                uuid_generate_v4(),
                '{"days": [1, 2, 3, 4, 5], "hour": 2, "minute": 30}'::json,
                '{"days": [1, 2, 3, 4, 5], "hour": 3, "minute": 30}'::json,
                '{"days": [1, 2, 3, 4, 5], "hour": 4, "minute": 0}'::json,
                now(),
                now()
            )
            """
        )
    )
    op.execute(
        "INSERT INTO drp_audit_chain (id, retired_through_seq, last_verified_seq, created_at, updated_at) "
        "VALUES (1, 0, 0, now(), now()) ON CONFLICT (id) DO NOTHING"
    )
    # The report queue's singleton control row exists before the first report is
    # requested: it is the row the queue serialises on, and a queue that has to
    # create it under contention is a queue with a race in it.
    op.execute(
        "INSERT INTO report_queue_control (id, touched_at) VALUES (1, now()) "
        "ON CONFLICT (id) DO NOTHING"
    )


def downgrade() -> None:
    # Reverse creation order: every table is dropped after the tables that
    # reference it. The schema is left empty rather than at some intermediate
    # revision, because this is the only revision there is.
    op.drop_table("schedule_occurrences")
    op.drop_table("ingestion_events")
    op.drop_table("alert_deliveries")
    op.drop_table("source_observations")
    op.drop_table("jobs")
    op.drop_table("reports")
    op.drop_table("drp_findings")
    op.drop_table("drp_connectors")
    op.drop_table("dns_expiry_monitors")
    op.drop_table("tls_certificate_sightings")
    op.drop_table("certificate_scope_exceptions")
    op.drop_table("tls_certificate_identities")
    op.drop_table("users")
    op.drop_table("system_settings")
    op.drop_table("source_accounts")
    op.drop_table("report_queue_control")
    op.drop_table("report_audit_outbox")
    op.drop_table("report_artifact_cleanup")
    op.drop_table("drp_refresh_families")
    op.drop_table("phishing_candidate_signals")
    op.drop_table("drp_phishing_domains")
    op.drop_table("drp_modules")
    op.drop_table("breach_catalogue")
    op.drop_table("drp_breaches")
    op.drop_table("drp_audit_logs")
    op.drop_table("drp_audit_chain")
    op.drop_table("dns_security_observations")
    op.drop_table("audit_archives")
    op.drop_table("assets")
    op.drop_table("alert_recipient_state")

    op.execute("DROP SEQUENCE IF EXISTS report_queue_control_id_seq")
    op.execute("DROP SEQUENCE IF EXISTS audit_archives_first_seq_seq")
    op.execute("DROP SEQUENCE IF EXISTS drp_audit_logs_seq_seq")

    asset_type = postgresql.ENUM(
        "domain",
        "ip_address",
        "email_account",
        "keyword_domain",
        "keyword_title",
        name="asset_type",
    )
    asset_type.drop(op.get_bind(), checkfirst=True)

    user_role = postgresql.ENUM("admin", "analyst", "viewer", name="user_role")
    user_role.drop(op.get_bind(), checkfirst=True)
