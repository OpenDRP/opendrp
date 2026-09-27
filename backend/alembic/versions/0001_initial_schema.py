"""0001_initial_schema

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-09-24 00:00:00.000000

Initial baseline schema for OpenDRP v0.1.0.
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
#:
#: ``storage.adapter`` is load-bearing, not decoration:
#: `ingestion_service._NATIVE_INGESTORS` dispatches on it, so an adapter name the
#: application does not recognise sends every finding of that module down the
#: generic path — writing it into ``drp_findings`` instead of its own table, with
#: no error anywhere. The same caution applies to ``dedup_fields``: it decides
#: which findings are duplicates.
#:
#: The values below are what this baseline creates; there is no earlier chain for
#: them to agree with.
_MODULE_SEED = (
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
)


def upgrade() -> None:
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')

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

    # -----------------------------------------------------------------------
    # Users
    # -----------------------------------------------------------------------
    op.create_table(
        "users",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", user_role, nullable=False, server_default="viewer"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("full_name", sa.String(length=255), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rate_limit_minutes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("totp_secret", sa.String(length=1024), nullable=True),
        sa.Column("totp_enabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("totp_last_used_step", sa.Integer(), nullable=True),
        sa.Column("mfa_failed_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("mfa_locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("mfa_recovery_codes", sa.JSON(), nullable=True),
        sa.Column("must_change_password", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("must_enrol_mfa", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("email", name=op.f("uq_users_email")),
    )
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)

    # -----------------------------------------------------------------------
    # Assets
    # -----------------------------------------------------------------------
    op.create_table(
        "assets",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("asset_type", asset_type, nullable=False),
        sa.Column("asset_value", sa.String(length=512), nullable=False),
        sa.Column("normalized_value", sa.String(length=512), nullable=True),
        sa.Column("criticality", sa.String(length=50), nullable=False, server_default="medium"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_assets")),
    )
    op.create_index(op.f("ix_assets_asset_type"), "assets", ["asset_type"], unique=False)
    op.create_index(
        "uq_assets_type_normalized_value",
        "assets",
        ["asset_type", "normalized_value"],
        unique=True,
        postgresql_where=sa.text("normalized_value IS NOT NULL"),
    )

    # -----------------------------------------------------------------------
    # Phishing domains
    # -----------------------------------------------------------------------
    op.create_table(
        "drp_phishing_domains",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("phishing_domain", sa.String(length=512), nullable=False),
        sa.Column("matched_asset", sa.String(length=512), nullable=False),
        sa.Column("ip_address", sa.String(length=255), nullable=True),
        sa.Column("web_ports", sa.String(length=255), nullable=True),
        sa.Column("detection_source", sa.String(length=100), nullable=False),
        sa.Column("original_domain", sa.String(length=512), nullable=True),
        sa.Column("whois_registrar", sa.String(length=255), nullable=True),
        sa.Column("whois_abuse_email", sa.String(length=255), nullable=True),
        sa.Column("domain_created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_drp_phishing_domains")),
        sa.UniqueConstraint("phishing_domain", name=op.f("uq_drp_phishing_domains_phishing_domain")),
    )
    op.create_index(op.f("ix_drp_phishing_domains_phishing_domain"), "drp_phishing_domains", ["phishing_domain"], unique=True)
    op.create_index(op.f("ix_drp_phishing_domains_status"), "drp_phishing_domains", ["status"], unique=False)

    # -----------------------------------------------------------------------
    # Breaches
    # -----------------------------------------------------------------------
    op.create_table(
        "drp_breaches",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("breach_name", sa.String(length=255), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("domain", sa.String(length=255), nullable=False),
        sa.Column("breach_date", sa.Date(), nullable=False),
        sa.Column("pwn_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("data_classes", postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::json")),
        sa.Column("matched_email", sa.String(length=255), nullable=True),
        sa.Column("matched_domain", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="active"),
        sa.Column("attributes", postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_drp_breaches")),
        sa.UniqueConstraint("breach_name", "matched_email", name="uq_breach_email"),
    )
    op.create_index("ix_drp_breaches_matched_email", "drp_breaches", ["matched_email"], unique=False)
    op.create_index("ix_drp_breaches_matched_domain", "drp_breaches", ["matched_domain"], unique=False)
    op.create_index("ix_drp_breaches_status", "drp_breaches", ["status"], unique=False)
    op.create_index(
        "uq_breach_domain_only",
        "drp_breaches",
        ["breach_name", "matched_domain"],
        unique=True,
        postgresql_where=sa.text("matched_domain IS NOT NULL AND matched_email IS NULL"),
    )

    # -----------------------------------------------------------------------
    # Reports
    # -----------------------------------------------------------------------
    op.create_table(
        "reports",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("report_name", sa.String(length=255), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("file_path", sa.String(length=512), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="pending"),
        sa.Column("is_truncated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("truncation_metadata", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], name=op.f("fk_reports_created_by_users"), ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_reports")),
    )
    op.create_index("ix_reports_created_at", "reports", ["created_at"])
    op.create_index("ix_reports_status", "reports", ["status"])

    # -----------------------------------------------------------------------
    # Jobs
    # -----------------------------------------------------------------------
    op.create_table(
        "jobs",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("job_type", sa.String(length=50), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("task_id", sa.String(length=128), nullable=True),
        sa.Column("title", sa.String(length=255), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("params", sa.JSON(), nullable=True),
        sa.Column("result_summary", sa.JSON(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("claimed_by_connector", sa.String(length=100), nullable=True),
        sa.Column("lease_token", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], name=op.f("fk_jobs_created_by_users"), ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_jobs")),
        sa.CheckConstraint("char_length(job_type) BETWEEN 1 AND 50", name="ck_jobs_job_type_len"),
        sa.CheckConstraint("char_length(status) BETWEEN 1 AND 32", name="ck_jobs_status_len"),
    )
    op.create_index(op.f("ix_jobs_job_type"), "jobs", ["job_type"], unique=False)
    op.create_index(op.f("ix_jobs_status"), "jobs", ["status"], unique=False)
    op.create_index(op.f("ix_jobs_created_by"), "jobs", ["created_by"], unique=False)
    op.create_index(op.f("ix_jobs_task_id"), "jobs", ["task_id"], unique=False)
    op.create_index("ix_jobs_lease_expires_at", "jobs", ["lease_expires_at"], unique=False)

    # -----------------------------------------------------------------------
    # Modules registry
    # -----------------------------------------------------------------------
    op.create_table(
        "drp_modules",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("label", sa.String(length=120), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("finding_kind", sa.String(length=32), nullable=False),
        sa.Column("asset_types", sa.JSON(), nullable=False),
        sa.Column("fields", sa.JSON(), nullable=False),
        sa.Column("dedup_fields", sa.JSON(), nullable=False),
        sa.Column("title_field", sa.String(length=64), nullable=True),
        sa.Column("storage", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("builtin", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_drp_modules"),
        sa.UniqueConstraint("finding_kind", name="uq_modules_finding_kind"),
    )

    # Seed built-in modules. A table rather than a literal INSERT because the
    # values are compared with the application's own definition by
    # tests/test_module_registry.py, and a literal would make that comparison a
    # string parse.
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
    # Generic findings
    # -----------------------------------------------------------------------
    op.create_table(
        "drp_findings",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("module", sa.String(length=32), nullable=False),
        sa.Column("finding_kind", sa.String(length=32), nullable=False),
        sa.Column("connector_name", sa.String(length=100), nullable=False),
        sa.Column("job_id", sa.UUID(), nullable=True),
        sa.Column("dedup_key", sa.String(length=512), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("matched_asset", sa.String(length=512), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="active"),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["module"], ["drp_modules.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("module", "dedup_key", name="uq_findings_module_dedup"),
    )
    op.create_index("ix_drp_findings_connector_name", "drp_findings", ["connector_name"])
    op.create_index("ix_drp_findings_status", "drp_findings", ["status"])
    op.create_index("ix_drp_findings_module_created", "drp_findings", ["module", "created_at"])

    # -----------------------------------------------------------------------
    # Connectors
    # -----------------------------------------------------------------------
    op.create_table(
        "drp_connectors",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("connector_type", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="enabled"),
        sa.Column("api_version", sa.String(length=32), nullable=True),
        sa.Column("default_job_type", sa.String(length=50), nullable=False),
        sa.Column("manifest", sa.JSON(), nullable=True),
        sa.Column("config", sa.JSON(), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=2000), nullable=True),
        sa.Column("info", sa.JSON(), nullable=True),
        sa.Column("token_hash", sa.String(length=64), nullable=True),
        sa.Column("token_prefix", sa.String(length=16), nullable=True),
        sa.Column("token_created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("token_last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_drp_connectors")),
        sa.UniqueConstraint("name", name=op.f("uq_drp_connectors_name")),
        sa.CheckConstraint("status IN ('enabled', 'disabled')", name="ck_connectors_status"),
    )
    op.create_index(op.f("ix_drp_connectors_name"), "drp_connectors", ["name"], unique=True)
    op.create_index(op.f("ix_drp_connectors_connector_type"), "drp_connectors", ["connector_type"], unique=False)
    op.create_index("ix_drp_connectors_token_hash", "drp_connectors", ["token_hash"], unique=True)

    # Seed the connectors this platform ships with, together with the manifest
    # each one re-declares when its container registers. The seeded declaration
    # is what makes the registry readable before a worker has ever started, and
    # each job type is owned by exactly one row.
    op.execute(
        sa.text(
            """
            INSERT INTO drp_connectors (name, connector_type, default_job_type, manifest, status, created_at, updated_at)
            VALUES
            ('dnstwist', 'phishing', 'phishing.dnstwist',
             '{"module": "phishing", "job_type": "phishing.dnstwist", "finding_kind": "phishing", "asset_types": ["domain"], "config_schema": {}}'::json,
             'enabled', now(), now()),
            ('shodan', 'phishing', 'phishing.shodan',
             '{"module": "phishing", "job_type": "phishing.shodan", "finding_kind": "phishing", "asset_types": ["domain", "keyword_domain", "keyword_title", "ip_address"], "config_schema": {"scan_ssl_text": {"type": "bool", "label": "Certificate text search", "default": true}, "scan_http_title": {"type": "bool", "label": "Page title search", "default": true}, "scan_favicon": {"type": "bool", "label": "Favicon hash search", "default": true}}}'::json,
             'enabled', now(), now()),
            ('hibp', 'breaches', 'breaches.hibp',
             '{"module": "breaches", "job_type": "breaches.hibp", "finding_kind": "breach", "asset_types": ["email_account", "domain"], "config_schema": {}}'::json,
             'enabled', now(), now())
            ON CONFLICT (name) DO NOTHING
            """
        )
    )

    # -----------------------------------------------------------------------
    # System settings
    # -----------------------------------------------------------------------
    op.create_table(
        "system_settings",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("smtp_host", sa.String(length=255), nullable=True),
        sa.Column("smtp_user", sa.String(length=255), nullable=True),
        sa.Column("smtp_password", sa.String(length=1024), nullable=True),
        sa.Column("smtp_from_email", sa.String(length=1024), nullable=True),
        sa.Column("smtp_port", sa.Integer(), nullable=False, server_default="587"),
        sa.Column("smtp_security_mode", sa.String(length=16), nullable=False, server_default="starttls"),
        sa.Column("alert_recipient_email", sa.String(length=1024), nullable=True),
        sa.Column("telegram_bot_token", sa.String(length=1024), nullable=True),
        sa.Column("telegram_chat_ids", sa.JSON(), nullable=True),
        sa.Column("email_alerts_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("telegram_alerts_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("alert_email_user_ids", sa.JSON(), nullable=True),
        sa.Column("schedule_phishing", sa.JSON(), nullable=True),
        sa.Column("schedule_breaches", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_system_settings")),
        sa.CheckConstraint("smtp_security_mode IN ('starttls', 'ssl', 'plain')", name="ck_system_settings_smtp_security_mode"),
    )

    # Seed singleton settings row
    op.execute(
        sa.text(
            """
            INSERT INTO system_settings (id, schedule_phishing, schedule_breaches, created_at, updated_at)
            VALUES (
                uuid_generate_v4(),
                '{"days": [1, 2, 3, 4, 5], "hour": 2, "minute": 30}'::json,
                '{"days": [1, 2, 3, 4, 5], "hour": 3, "minute": 30}'::json,
                now(),
                now()
            )
            """
        )
    )

    # -----------------------------------------------------------------------
    # Audit log & hash chain
    # -----------------------------------------------------------------------
    op.execute("CREATE SEQUENCE IF NOT EXISTS drp_audit_logs_seq_seq START WITH 1")
    op.create_table(
        "drp_audit_logs",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=True),
        sa.Column("action", sa.String(length=120), nullable=False),
        sa.Column("ip_address", sa.String(length=64), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column("seq", sa.BigInteger(), server_default=sa.text("nextval('drp_audit_logs_seq_seq')"), nullable=False),
        #: Required by construction: the only writer computes it in the same
        #: transaction, so an unsigned row is a schema violation rather than a
        #: quiet gap in the chain. ``prev_hash`` stays nullable because the first
        #: entry in a chain genuinely links to nothing.
        sa.Column("entry_hash", sa.String(length=64), nullable=False),
        sa.Column("prev_hash", sa.String(length=64), nullable=True),
        sa.Column("key_id", sa.SmallInteger(), nullable=False, server_default="0"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_drp_audit_logs")),
        sa.UniqueConstraint("seq", name="uq_drp_audit_logs_seq"),
    )
    op.create_index(op.f("ix_drp_audit_logs_timestamp"), "drp_audit_logs", ["timestamp"])
    op.create_index(op.f("ix_drp_audit_logs_user_id"), "drp_audit_logs", ["user_id"])
    op.create_index(op.f("ix_drp_audit_logs_action"), "drp_audit_logs", ["action"])
    op.create_index("ix_drp_audit_logs_entry_hash", "drp_audit_logs", ["entry_hash"])
    op.create_index("ix_drp_audit_logs_user_timestamp", "drp_audit_logs", ["user_id", "timestamp"])

    op.create_table(
        "drp_audit_chain",
        sa.Column("id", sa.SmallInteger(), server_default="1", nullable=False),
        sa.Column("retired_through_seq", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("retired_tip_hash", sa.String(length=64), nullable=True),
        sa.Column("last_verified_seq", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.execute("INSERT INTO drp_audit_chain (id, retired_through_seq, last_verified_seq, created_at, updated_at) VALUES (1, 0, 0, now(), now()) ON CONFLICT (id) DO NOTHING")

    # -----------------------------------------------------------------------
    # Refresh families
    # -----------------------------------------------------------------------
    op.create_table(
        "drp_refresh_families",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("family_id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("last_jti", sa.String(length=120), nullable=True),
        sa.Column("last_issued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_reason", sa.String(length=120), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_drp_refresh_families")),
        sa.UniqueConstraint("family_id", name="uq_drp_refresh_families_family_id"),
    )
    op.create_index("ix_drp_refresh_families_family_id", "drp_refresh_families", ["family_id"], unique=True)
    op.create_index("ix_drp_refresh_families_user_id", "drp_refresh_families", ["user_id"])
    op.create_index("ix_drp_refresh_families_revoked", "drp_refresh_families", ["revoked"])

    # -----------------------------------------------------------------------
    # Alert deliveries queue
    # -----------------------------------------------------------------------
    op.create_table(
        "alert_deliveries",
        sa.Column("id", sa.UUID(), server_default=sa.text("uuid_generate_v4()"), nullable=False),
        sa.Column("job_id", sa.UUID(), nullable=True),
        sa.Column("threat_type", sa.String(length=100), nullable=False),
        sa.Column("channel", sa.String(length=20), nullable=False),
        sa.Column("target", sa.String(length=512), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("locked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alert_deliveries_job_id", "alert_deliveries", ["job_id"])
    op.create_index("ix_alert_deliveries_status", "alert_deliveries", ["status"])
    op.create_index("ix_alert_deliveries_next_attempt_at", "alert_deliveries", ["next_attempt_at"])
    op.create_index("ix_alert_deliveries_threat_type", "alert_deliveries", ["threat_type"])
    op.create_index("ix_alert_deliveries_channel", "alert_deliveries", ["channel"])
    op.create_index("ix_alert_deliveries_target", "alert_deliveries", ["target"])


def downgrade() -> None:
    op.drop_table("alert_deliveries")
    op.drop_table("drp_refresh_families")
    op.drop_table("drp_audit_chain")
    op.drop_table("drp_audit_logs")
    op.execute("DROP SEQUENCE IF EXISTS drp_audit_logs_seq_seq")
    op.drop_table("system_settings")
    op.drop_table("drp_connectors")
    op.drop_table("drp_findings")
    op.drop_table("drp_modules")
    op.drop_table("jobs")
    op.drop_table("reports")
    op.drop_table("drp_breaches")
    op.drop_table("drp_phishing_domains")
    op.drop_table("assets")
    op.drop_table("users")

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
