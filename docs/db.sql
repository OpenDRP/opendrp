-- OpenDRP PostgreSQL reference schema
--
-- Migration head: 0001_initial_schema
--
-- This file documents the resulting PostgreSQL schema. The application is
-- migration-driven: deploy with `alembic upgrade head` and do not apply this
-- file as an independent migration source.
--
-- Secrets stored in system_settings are Fernet ciphertext at rest. No secret
-- values belong in this file, .env.example, or the public repository.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ---------------------------------------------------------------------------
-- Enumerated types
-- ---------------------------------------------------------------------------

CREATE TYPE user_role AS ENUM ('admin', 'analyst', 'viewer');

CREATE TYPE asset_type AS ENUM (
    'domain',
    'ip_address',
    'email_account',
    'keyword_domain',
    'keyword_title'
);

-- ---------------------------------------------------------------------------
-- Identity and monitored assets
-- ---------------------------------------------------------------------------

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role user_role NOT NULL DEFAULT 'viewer',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    full_name VARCHAR(255),
    last_login_at TIMESTAMP WITH TIME ZONE,
    rate_limit_minutes INTEGER NOT NULL DEFAULT 0,
    -- Second factor (TOTP). The secret is Fernet ciphertext under
    -- ENCRYPTION_KEY; totp_enabled_at is NULL until a code generated from it has
    -- been verified, and totp_last_used_step makes each accepted code single-use.
    totp_secret VARCHAR(1024),
    totp_enabled_at TIMESTAMP WITH TIME ZONE,
    totp_last_used_step INTEGER,
    mfa_failed_attempts INTEGER NOT NULL DEFAULT 0,
    mfa_locked_until TIMESTAMP WITH TIME ZONE,
    mfa_recovery_codes JSON,
    -- Credential onboarding. A password assigned for this account (created by an
    -- administrator, reset by one, or set through the admin CLI) is temporary
    -- until its owner replaces it through POST /auth/password; a factor removed
    -- for the account must be enrolled again. While either is true the API refuses
    -- every authenticated route except the ones that complete the step.
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    must_enrol_mfa BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT uq_users_email UNIQUE (email)
);

CREATE UNIQUE INDEX ix_users_email ON users (email);

CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_type asset_type NOT NULL,
    asset_value VARCHAR(512) NOT NULL,
    normalized_value VARCHAR(512),
    criticality VARCHAR(50) NOT NULL DEFAULT 'medium',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX ix_assets_asset_type ON assets (asset_type);
CREATE UNIQUE INDEX uq_assets_type_normalized_value
    ON assets (asset_type, normalized_value)
    WHERE normalized_value IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Phishing findings
-- ---------------------------------------------------------------------------

CREATE TABLE drp_phishing_domains (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    phishing_domain VARCHAR(512) NOT NULL,
    matched_asset VARCHAR(512) NOT NULL,
    ip_address VARCHAR(255),
    web_ports VARCHAR(255),
    detection_source VARCHAR(100) NOT NULL,
    original_domain VARCHAR(512),
    whois_registrar VARCHAR(255),
    whois_abuse_email VARCHAR(255),
    domain_created_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_drp_phishing_domains_phishing_domain
        UNIQUE (phishing_domain)
);

-- SQLAlchemy declares both the unique constraint index and the indexed model
-- column. PostgreSQL therefore contains both indexes in migrated databases.
CREATE UNIQUE INDEX ix_drp_phishing_domains_phishing_domain
    ON drp_phishing_domains (phishing_domain);
CREATE INDEX ix_drp_phishing_domains_status
    ON drp_phishing_domains (status);

-- ---------------------------------------------------------------------------
-- Breach findings (any provider)
-- ---------------------------------------------------------------------------
--
-- Named for what it stores, not for the first source that filled it: the
-- connector protocol accepts breach findings from any provider.

CREATE TABLE drp_breaches (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    breach_name VARCHAR(255) NOT NULL,
    title VARCHAR(255) NOT NULL,
    domain VARCHAR(255) NOT NULL,
    breach_date DATE NOT NULL,
    pwn_count INTEGER NOT NULL DEFAULT 0,
    description TEXT,
    data_classes JSON NOT NULL DEFAULT '[]'::json,
    matched_email VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    matched_domain VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    -- Provider-specific payload: classification flags, exposed-secret samples,
    -- the source's own catalog timestamps. The columns above are the fields
    -- every breach source can supply; these belong to the reporting source.
    attributes JSON NOT NULL DEFAULT '{}'::json,
    CONSTRAINT uq_breach_email
        UNIQUE (breach_name, matched_email)
);

-- Partial index for domain deduplication when no specific mailbox is reported (0026).
CREATE UNIQUE INDEX uq_breach_domain_only
    ON drp_breaches (breach_name, matched_domain)
    WHERE matched_domain IS NOT NULL AND matched_email IS NULL;

CREATE INDEX ix_drp_breaches_matched_email
    ON drp_breaches (matched_email);
CREATE INDEX ix_drp_breaches_matched_domain
    ON drp_breaches (matched_domain);
CREATE INDEX ix_drp_breaches_status
    ON drp_breaches (status);

-- ---------------------------------------------------------------------------
-- Reports and jobs
-- ---------------------------------------------------------------------------

CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    report_name VARCHAR(255) NOT NULL,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    -- An artifact *name* ("<uuid>.pdf"), never a path: the directory comes from
    -- REPORTS_STORE_DIR and the value is resolved inside it, so a row cannot
    -- point the reader at a file the platform never wrote. See
    -- app/core/artifact_path.py.
    file_path VARCHAR(512) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    is_truncated BOOLEAN NOT NULL DEFAULT FALSE,
    truncation_metadata JSON,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE jobs (
    id UUID PRIMARY KEY NOT NULL,
    job_type VARCHAR(50) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    task_id VARCHAR(128),
    title VARCHAR(255),
    error_message TEXT,
    params JSON,
    result_summary JSON,
    started_at TIMESTAMP WITH TIME ZONE,
    finished_at TIMESTAMP WITH TIME ZONE,
    -- Connector job leases. Leases bound job ownership, track heartbeats, and
    -- allow zombie jobs to be reclaimed safely.
    lease_expires_at TIMESTAMP WITH TIME ZONE,
    last_heartbeat_at TIMESTAMP WITH TIME ZONE,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    claimed_by_connector VARCHAR(100),
    lease_token VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT ck_jobs_job_type_len
        CHECK (char_length(job_type) BETWEEN 1 AND 50),
    CONSTRAINT ck_jobs_status_len
        CHECK (char_length(status) BETWEEN 1 AND 32)
);

CREATE INDEX ix_jobs_job_type ON jobs (job_type);
CREATE INDEX ix_jobs_status ON jobs (status);
CREATE INDEX ix_jobs_created_by ON jobs (created_by);
CREATE INDEX ix_jobs_task_id ON jobs (task_id);
CREATE INDEX ix_jobs_lease_expires_at ON jobs (lease_expires_at);

-- ---------------------------------------------------------------------------
-- Connector registry
-- ---------------------------------------------------------------------------

CREATE TABLE drp_connectors (
    id UUID PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    connector_type VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'enabled',
    api_version VARCHAR(32),
    -- Job type the connector declared for itself (namespaced, uniquely owned,
    -- required at registration: it is the work this connector alone claims).
    default_job_type VARCHAR(50) NOT NULL,
    -- Self-declared manifest: module, job_type, finding_kind, asset_types and
    -- the operator-editable config_schema. Registration always writes one; the
    -- read path normalises it against the module registry.
    manifest JSON,
    config JSON,
    last_seen_at TIMESTAMP WITH TIME ZONE,
    last_error VARCHAR(2000),
    info JSON,
    -- Per-connector credential: SHA-256 digest of a machine-generated token.
    -- The plaintext is shown once at issuance and never stored. NULL means the
    -- connector cannot authenticate yet; there is no shared connector secret.
    token_hash VARCHAR(64),
    --: Public prefix of the token, so an operator can tell which one is in use.
    token_prefix VARCHAR(16),
    token_created_at TIMESTAMP WITH TIME ZONE,
    token_last_used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_connectors_status
        CHECK (status IN ('enabled', 'disabled'))
    -- No CHECK on connector_type: the module set is data (drp_modules), so any
    -- registered module id is a valid value. 0018 dropped the constraint 0009
    -- created here, which had pinned the column to the two built-in modules.
);

CREATE UNIQUE INDEX ix_drp_connectors_name
    ON drp_connectors (name);
CREATE INDEX ix_drp_connectors_connector_type
    ON drp_connectors (connector_type);
-- One credential identifies exactly one connector.
CREATE UNIQUE INDEX ix_drp_connectors_token_hash
    ON drp_connectors (token_hash);

-- ---------------------------------------------------------------------------
-- Module registry and generic findings
-- ---------------------------------------------------------------------------
--
-- The module set is data: onboarding a data source whose findings do not fit the
-- phishing/breach tables is a row here plus a connector registration, not a core
-- release. A module declares how its findings are identified (dedup_fields),
-- validated (fields) and displayed (label, title_field), and which inventory it
-- consumes (asset_types).

CREATE TABLE drp_modules (
    id VARCHAR(32) PRIMARY KEY,
    label VARCHAR(120) NOT NULL,
    description TEXT,
    -- Finding kind the core validates this module's submissions against. One
    -- kind identifies one module.
    finding_kind VARCHAR(32) NOT NULL,
    -- Inventory sections the module's connectors consume (e.g. domain).
    asset_types JSON NOT NULL,
    -- Declared field specification: findings are validated against it.
    fields JSON NOT NULL,
    -- Fields that identify a finding; together they form the dedup key.
    dedup_fields JSON NOT NULL,
    title_field VARCHAR(64),
    -- Where findings land: {"kind": "table", "table": ..., "adapter": ...} for
    -- a module the core persists natively, {"kind": "generic", "adapter":
    -- "generic"} for one stored in drp_findings.
    storage JSON NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    -- TRUE for the modules the platform ships with; they are seeded by 0018.
    builtin BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_modules_finding_kind UNIQUE (finding_kind)
);

-- Findings for modules that use generic storage. The core still owns the write,
-- dedup and audit; only the shape of the payload is module-declared (JSON) rather
-- than a typed table. A module with a native adapter keeps its own table.

CREATE TABLE drp_findings (
    id UUID PRIMARY KEY,
    module VARCHAR(32) NOT NULL
        REFERENCES drp_modules (id) ON DELETE RESTRICT,
    finding_kind VARCHAR(32) NOT NULL,
    connector_name VARCHAR(100) NOT NULL,
    job_id UUID,
    -- Deterministic key built from the module's declared dedup fields.
    dedup_key VARCHAR(512) NOT NULL,
    title VARCHAR(512) NOT NULL,
    matched_asset VARCHAR(512),
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    -- Validated payload, shaped by the module's declared field specification.
    payload JSON NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_findings_module_dedup UNIQUE (module, dedup_key)
);

CREATE INDEX ix_drp_findings_connector_name ON drp_findings (connector_name);
CREATE INDEX ix_drp_findings_status ON drp_findings (status);
CREATE INDEX ix_drp_findings_module_created ON drp_findings (module, created_at);

-- ---------------------------------------------------------------------------
-- Singleton platform settings
-- ---------------------------------------------------------------------------

CREATE TABLE system_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- Provider API keys are connector-owned and are not stored in core settings.
    smtp_host VARCHAR(255),
    smtp_user VARCHAR(255),
    smtp_password VARCHAR(1024),
    smtp_from_email VARCHAR(1024),
    smtp_port INTEGER NOT NULL DEFAULT 587,
    smtp_security_mode VARCHAR(16) NOT NULL DEFAULT 'starttls' CHECK (smtp_security_mode IN ('starttls', 'ssl', 'plain')),
    alert_recipient_email VARCHAR(1024),
    telegram_bot_token VARCHAR(1024),
    email_alerts_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    telegram_alerts_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    -- JSON array of selected active user UUID strings.
    alert_email_user_ids JSON,
    -- JSON array of Telegram chat ID strings.
    telegram_chat_ids JSON,
    -- {"days": [0..6, 0=Sunday], "hour": 0..23, "minute": 0..59} UTC.
    schedule_phishing JSON,
    schedule_breaches JSON,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------------
-- Audit trail and refresh-token families
-- ---------------------------------------------------------------------------

CREATE TABLE drp_audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    user_id UUID,
    action VARCHAR(120) NOT NULL,
    ip_address VARCHAR(64) NOT NULL,
    details JSON NOT NULL DEFAULT '{}'::json,
    -- Hash chain. ``seq`` is the monotonic position, unique because a duplicate
    -- position is the "delete a row and renumber" shape it exists to catch;
    -- ``entry_hash`` is the HMAC over this row's five fields and the previous
    -- entry's hash, keyed from AUDIT_CHAIN_KEYS in the environment (never from
    -- this database). It is NOT NULL: the single writer signs inside the
    -- inserting transaction, so a row without a hash did not come from the
    -- platform. ``prev_hash`` is NULL only for the first entry of a chain, which
    -- links to nothing. ``key_id`` is the fingerprint of the key that signed the
    -- row rather than its position in the configured list, so a key rotation
    -- does not re-point old rows at a different key. See app/core/audit_chain.py.
    seq BIGINT NOT NULL DEFAULT nextval('drp_audit_logs_seq_seq'),
    entry_hash VARCHAR(64) NOT NULL,
    prev_hash VARCHAR(64),
    key_id SMALLINT NOT NULL DEFAULT 0,
    CONSTRAINT uq_drp_audit_logs_seq UNIQUE (seq)
);

CREATE INDEX ix_drp_audit_logs_timestamp
    ON drp_audit_logs (timestamp);
CREATE INDEX ix_drp_audit_logs_user_id
    ON drp_audit_logs (user_id);
CREATE INDEX ix_drp_audit_logs_action
    ON drp_audit_logs (action);
CREATE INDEX ix_drp_audit_logs_entry_hash
    ON drp_audit_logs (entry_hash);
CREATE INDEX ix_drp_audit_logs_user_timestamp
    ON drp_audit_logs (user_id, timestamp);

-- One row per installation: what retention legitimately deleted, and how far
-- verification has already run. Without the retirement watermark, an age-based
-- sweep would make every subsequent verification report a breach.
CREATE TABLE drp_audit_chain (
    id SMALLINT PRIMARY KEY DEFAULT 1,
    retired_through_seq BIGINT NOT NULL DEFAULT 0,
    retired_tip_hash VARCHAR(64),
    last_verified_seq BIGINT NOT NULL DEFAULT 0,
    last_verified_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE drp_refresh_families (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    family_id UUID NOT NULL,
    user_id UUID NOT NULL,
    last_jti VARCHAR(120),
    last_issued_at TIMESTAMP WITH TIME ZONE,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_reason VARCHAR(120),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_drp_refresh_families_family_id UNIQUE (family_id)
);

CREATE UNIQUE INDEX ix_drp_refresh_families_family_id
    ON drp_refresh_families (family_id);
CREATE INDEX ix_drp_refresh_families_user_id
    ON drp_refresh_families (user_id);
CREATE INDEX ix_drp_refresh_families_revoked
    ON drp_refresh_families (revoked);

-- ---------------------------------------------------------------------------
-- Alert delivery queue
-- ---------------------------------------------------------------------------

CREATE TABLE alert_deliveries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id UUID REFERENCES jobs(id) ON DELETE SET NULL,
    threat_type VARCHAR(100) NOT NULL,
    channel VARCHAR(20) NOT NULL,  -- concrete destination: 'email' or 'telegram'
    target VARCHAR(512),
    payload JSON NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMP WITH TIME ZONE,
    locked_at TIMESTAMP WITH TIME ZONE,
    sent_at TIMESTAMP WITH TIME ZONE,
    last_error TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX ix_alert_deliveries_job_id ON alert_deliveries (job_id);
CREATE INDEX ix_alert_deliveries_status ON alert_deliveries (status);
CREATE INDEX ix_alert_deliveries_next_attempt_at ON alert_deliveries (next_attempt_at);
CREATE INDEX ix_alert_deliveries_threat_type ON alert_deliveries (threat_type);
CREATE INDEX ix_alert_deliveries_channel ON alert_deliveries (channel);
CREATE INDEX ix_alert_deliveries_target ON alert_deliveries (target);

-- ---------------------------------------------------------------------------
-- Migration and deployment notes
-- ---------------------------------------------------------------------------
--
-- OpenDRP v0.1.0 initial schema baseline:
-- 1. 0001_initial_schema creates the complete schema for identity (users,
--    refresh families), monitored assets, phishing domains, breaches, module
--    registry, generic findings, jobs, connector registry, reports, system
--    settings, audit logs with tamper-evident HMAC hash chain, and persistent
--    alert deliveries queue.
--
-- Run Alembic instead of applying this reference DDL directly:
--     alembic upgrade head
