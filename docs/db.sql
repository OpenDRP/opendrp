-- OpenDRP PostgreSQL reference schema
--
-- Schema baseline: 0001_initial_schema, the only revision this release ships
-- and therefore the current head. `backend/alembic/versions/` holds that one
-- file and it creates everything below: identity and sessions, monitored assets,
-- phishing, breaches, the module and connector registries, jobs, connector
-- observations, DNS Security inventory and expiry monitoring, reports, settings,
-- the tamper-evident audit trail with its archive bookkeeping, and the durable
-- alert delivery queue.
--
-- This file is a reference snapshot for reading, not a migration source. The
-- platform is migration-driven: deploy with `python -m scripts.migrate` (or
-- `alembic upgrade head`) and never apply this DDL instead. A database an
-- earlier build created already holds this schema and is adopted by recording
-- 0001_initial_schema as its revision; `scripts/migrate.py` does that itself
-- and `docs/upgrading.md` states the procedure.
--
-- The seed rows the revision inserts are not repeated here: the built-in
-- modules, the connectors this release ships and their source accounts live in
-- the revision itself, and `tests/test_module_registry.py` compares the modules
-- with `app/services/module_registry.py`. Alembic's own `alembic_version` table,
-- which records the applied revision, is not part of the platform schema and is
-- omitted.
--
-- Secrets stored in system_settings are Fernet ciphertext at rest. No secret
-- values belong in this file, .env.example, or the public repository.

-- ---------------------------------------------------------------------------
-- Extensions
-- ---------------------------------------------------------------------------

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;

COMMENT ON EXTENSION pg_trgm IS 'text similarity measurement and index searching based on trigrams';

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';

-- ---------------------------------------------------------------------------
-- Enumerated types
-- ---------------------------------------------------------------------------

CREATE TYPE asset_type AS ENUM (
    'domain',
    'ip_address',
    'email_account',
    'keyword_domain',
    'keyword_title'
);

CREATE TYPE user_role AS ENUM (
    'admin',
    'analyst',
    'viewer'
);

-- ---------------------------------------------------------------------------
-- Tables and their sequences
-- ---------------------------------------------------------------------------

CREATE TABLE alert_deliveries (
    id uuid DEFAULT uuid_generate_v4() NOT NULL,
    job_id uuid,
    threat_type character varying(100) NOT NULL,
    channel character varying(20) NOT NULL,
    target character varying(512),
    payload json NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone,
    locked_at timestamp with time zone,
    sent_at timestamp with time zone,
    last_error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    lease_token character varying(64),
    batch_id character varying(64),
    parts json,
    acknowledged_parts integer DEFAULT 0 NOT NULL
);

CREATE TABLE alert_recipient_state (
    key character varying(64) NOT NULL,
    next_send_at timestamp with time zone,
    lease_token character varying(64),
    lease_expires_at timestamp with time zone
);

CREATE TABLE assets (
    id uuid DEFAULT uuid_generate_v4() NOT NULL,
    asset_type asset_type NOT NULL,
    asset_value character varying(512) NOT NULL,
    normalized_value character varying(512),
    criticality character varying(50) DEFAULT 'medium'::character varying NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE audit_archives (
    first_seq bigint NOT NULL,
    last_seq bigint NOT NULL,
    content_hash character varying(64) NOT NULL,
    manifest_name character varying(255) NOT NULL,
    created_at timestamp with time zone NOT NULL,
    retired_at timestamp with time zone
);

CREATE SEQUENCE audit_archives_first_seq_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE audit_archives_first_seq_seq OWNED BY audit_archives.first_seq;

CREATE TABLE dns_expiry_monitors (
    id uuid NOT NULL,
    asset_id uuid NOT NULL,
    kind character varying(32) NOT NULL,
    subject character varying(253) NOT NULL,
    state character varying(32) NOT NULL,
    checked_at timestamp with time zone NOT NULL,
    successful_at timestamp with time zone,
    expires_at timestamp with time zone,
    certificate_id character varying(128),
    not_before timestamp with time zone,
    observation_id uuid,
    cycle character varying(64),
    alerted_thresholds json NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE dns_security_observations (
    id uuid NOT NULL,
    observation_key character varying(64) NOT NULL,
    observation_type character varying(32) NOT NULL,
    subject character varying(253) NOT NULL,
    record_type character varying(16),
    value character varying(1000),
    source character varying(32) NOT NULL,
    first_seen_at timestamp with time zone NOT NULL,
    last_seen_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone,
    status character varying(16) DEFAULT 'current'::character varying NOT NULL,
    metadata_json json DEFAULT '{}'::json NOT NULL,
    alerted_thresholds json DEFAULT '[]'::json NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE drp_audit_chain (
    id smallint DEFAULT '1'::smallint NOT NULL,
    retired_through_seq bigint DEFAULT '0'::bigint NOT NULL,
    retired_tip_hash character varying(64),
    last_verified_seq bigint DEFAULT '0'::bigint NOT NULL,
    last_verified_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    committed_seq bigint DEFAULT '0'::bigint NOT NULL,
    committed_tip_hash character varying(64),
    full_verify_upper_seq bigint DEFAULT '0'::bigint NOT NULL,
    full_verify_upper_hash character varying(64),
    full_verify_cursor bigint DEFAULT '0'::bigint NOT NULL,
    full_verify_cursor_hash character varying(64),
    last_full_verified_at timestamp with time zone,
    last_failure_seq bigint,
    last_failure_reason character varying(64)
);

CREATE SEQUENCE drp_audit_logs_seq_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

CREATE TABLE drp_audit_logs (
    id uuid DEFAULT uuid_generate_v4() NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    user_id uuid,
    action character varying(120) NOT NULL,
    ip_address character varying(64) NOT NULL,
    details json DEFAULT '{}'::json NOT NULL,
    seq bigint DEFAULT nextval('drp_audit_logs_seq_seq'::regclass) NOT NULL,
    entry_hash character varying(64) NOT NULL,
    prev_hash character varying(64),
    key_id smallint DEFAULT '0'::smallint NOT NULL
);

CREATE TABLE drp_breaches (
    id uuid DEFAULT uuid_generate_v4() NOT NULL,
    breach_name character varying(255) NOT NULL,
    title character varying(255) NOT NULL,
    domain character varying(255) NOT NULL,
    breach_date date NOT NULL,
    pwn_count integer DEFAULT 0 NOT NULL,
    description text,
    data_classes json DEFAULT '[]'::json NOT NULL,
    matched_email character varying(255),
    matched_domain character varying(255),
    status character varying(50) DEFAULT 'active'::character varying NOT NULL,
    attributes json DEFAULT '{}'::json NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    source_id character varying(100) NOT NULL
);

CREATE TABLE drp_connectors (
    id uuid DEFAULT uuid_generate_v4() NOT NULL,
    name character varying(100) NOT NULL,
    connector_type character varying(32) NOT NULL,
    status character varying(32) DEFAULT 'enabled'::character varying NOT NULL,
    api_version character varying(32),
    default_job_type character varying(50) NOT NULL,
    manifest json,
    config json,
    last_seen_at timestamp with time zone,
    last_error character varying(2000),
    info json,
    token_hash character varying(64),
    token_prefix character varying(16),
    token_created_at timestamp with time zone,
    token_last_used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    provider character varying(32),
    quota_group character varying(64),
    readiness json,
    last_success_at timestamp with time zone,
    source_account_id uuid,
    aliases json DEFAULT '[]'::json NOT NULL,
    CONSTRAINT ck_connectors_status CHECK (((status)::text = ANY ((ARRAY['enabled'::character varying, 'disabled'::character varying])::text[])))
);

CREATE TABLE drp_findings (
    id uuid NOT NULL,
    module character varying(32) NOT NULL,
    finding_kind character varying(32) NOT NULL,
    connector_name character varying(100) NOT NULL,
    job_id uuid,
    dedup_key character varying(512) NOT NULL,
    title character varying(512) NOT NULL,
    matched_asset character varying(512),
    status character varying(50) DEFAULT 'active'::character varying NOT NULL,
    payload json NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE drp_modules (
    id character varying(32) NOT NULL,
    label character varying(120) NOT NULL,
    description text,
    finding_kind character varying(32) NOT NULL,
    asset_types json NOT NULL,
    fields json NOT NULL,
    dedup_fields json NOT NULL,
    title_field character varying(64),
    storage json NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    builtin boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE drp_phishing_domains (
    id uuid DEFAULT uuid_generate_v4() NOT NULL,
    phishing_domain character varying(512) NOT NULL,
    matched_asset character varying(512) NOT NULL,
    ip_address character varying(255),
    web_ports character varying(255),
    detection_source character varying(100) NOT NULL,
    original_domain character varying(512),
    whois_registrar character varying(255),
    whois_abuse_email character varying(255),
    domain_created_at timestamp with time zone,
    status character varying(50) DEFAULT 'active'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE drp_refresh_families (
    id uuid DEFAULT uuid_generate_v4() NOT NULL,
    family_id uuid NOT NULL,
    user_id uuid NOT NULL,
    last_jti character varying(120),
    last_issued_at timestamp with time zone,
    revoked boolean DEFAULT false NOT NULL,
    revoked_at timestamp with time zone,
    revoked_reason character varying(120),
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE ingestion_events (
    id uuid NOT NULL,
    event_key character varying(128) NOT NULL,
    kind character varying(32) NOT NULL,
    module character varying(32) NOT NULL,
    entity_id uuid NOT NULL,
    job_id uuid,
    payload json NOT NULL,
    processed_at timestamp with time zone,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone,
    last_error character varying(128),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE jobs (
    id uuid NOT NULL,
    job_type character varying(50) NOT NULL,
    status character varying(32) DEFAULT 'pending'::character varying NOT NULL,
    created_by uuid,
    task_id character varying(128),
    title character varying(255),
    error_message text,
    params json,
    result_summary json,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    lease_expires_at timestamp with time zone,
    last_heartbeat_at timestamp with time zone,
    attempt_count integer DEFAULT 0 NOT NULL,
    claimed_by_connector character varying(100),
    lease_token character varying(64),
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    connector_id uuid,
    schedule_key character varying(128),
    CONSTRAINT ck_jobs_job_type_len CHECK (((char_length((job_type)::text) >= 1) AND (char_length((job_type)::text) <= 50))),
    CONSTRAINT ck_jobs_status_len CHECK (((char_length((status)::text) >= 1) AND (char_length((status)::text) <= 32)))
);

CREATE TABLE report_artifact_cleanup (
    artifact_name character varying(255) NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    available_at timestamp with time zone DEFAULT now() NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    last_error text,
    report_id uuid
);

CREATE TABLE report_audit_outbox (
    id uuid NOT NULL,
    event_key character varying(255) NOT NULL,
    action character varying(80) NOT NULL,
    report_id uuid NOT NULL,
    job_id uuid,
    details json NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    available_at timestamp with time zone DEFAULT now() NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    last_error text
);

CREATE TABLE report_queue_control (
    id integer NOT NULL,
    touched_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE report_queue_control_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE report_queue_control_id_seq OWNED BY report_queue_control.id;

CREATE TABLE reports (
    id uuid DEFAULT uuid_generate_v4() NOT NULL,
    report_name character varying(255) NOT NULL,
    created_by uuid,
    file_path character varying(512) NOT NULL,
    status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    is_truncated boolean DEFAULT false NOT NULL,
    truncation_metadata json,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    generation_started_at timestamp with time zone
);

CREATE TABLE schedule_occurrences (
    key character varying(128) NOT NULL,
    job_id uuid,
    created_at timestamp with time zone NOT NULL
);

CREATE TABLE source_accounts (
    id uuid NOT NULL,
    source_id character varying(32) NOT NULL,
    name character varying(64) NOT NULL,
    credential_ref character varying(128),
    policy json NOT NULL,
    access_state character varying(32) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    api_key_encrypted text,
    api_key_hint character varying(16)
);

CREATE TABLE source_observations (
    id uuid NOT NULL,
    module character varying(32) NOT NULL,
    source character varying(100) NOT NULL,
    observation_key character varying(64) NOT NULL,
    subject character varying(253) NOT NULL,
    matched_asset character varying(512) NOT NULL,
    candidate_id uuid,
    job_id uuid,
    first_seen_at timestamp with time zone NOT NULL,
    last_seen_at timestamp with time zone NOT NULL,
    observed_at timestamp with time zone,
    status character varying(32) NOT NULL,
    payload json NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    connector_id uuid,
    source_account_id uuid,
    provenance json DEFAULT '{}'::json NOT NULL
);

CREATE TABLE system_settings (
    id uuid DEFAULT uuid_generate_v4() NOT NULL,
    smtp_host character varying(255),
    smtp_user character varying(255),
    smtp_password character varying(1024),
    smtp_from_email character varying(1024),
    smtp_port integer DEFAULT 587 NOT NULL,
    smtp_security_mode character varying(16) DEFAULT 'starttls'::character varying NOT NULL,
    alert_recipient_email character varying(1024),
    telegram_bot_token character varying(1024),
    telegram_chat_ids json,
    email_alerts_enabled boolean DEFAULT false NOT NULL,
    telegram_alerts_enabled boolean DEFAULT false NOT NULL,
    alert_email_user_ids json,
    schedule_phishing json,
    schedule_breaches json,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    schedule_dns_security json,
    schedule_exposure json,
    schedules json,
    singleton_key integer DEFAULT 1 NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    CONSTRAINT ck_system_settings_singleton CHECK ((singleton_key = 1)),
    CONSTRAINT ck_system_settings_smtp_security_mode CHECK (((smtp_security_mode)::text = ANY ((ARRAY['starttls'::character varying, 'ssl'::character varying, 'plain'::character varying])::text[])))
);

CREATE TABLE users (
    id uuid DEFAULT uuid_generate_v4() NOT NULL,
    email character varying(255) NOT NULL,
    password_hash character varying(255) NOT NULL,
    role user_role DEFAULT 'viewer'::user_role NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    full_name character varying(255),
    last_login_at timestamp with time zone,
    failed_login_attempts integer DEFAULT 0 NOT NULL,
    locked_until timestamp with time zone,
    rate_limit_minutes integer DEFAULT 0 NOT NULL,
    totp_secret character varying(1024),
    totp_enabled_at timestamp with time zone,
    totp_last_used_step integer,
    mfa_failed_attempts integer DEFAULT 0 NOT NULL,
    mfa_locked_until timestamp with time zone,
    mfa_recovery_codes json,
    must_change_password boolean DEFAULT false NOT NULL,
    must_enrol_mfa boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

-- ---------------------------------------------------------------------------
-- Column defaults, primary keys and unique constraints
-- ---------------------------------------------------------------------------

ALTER TABLE ONLY audit_archives ALTER COLUMN first_seq SET DEFAULT nextval('audit_archives_first_seq_seq'::regclass);

ALTER TABLE ONLY report_queue_control ALTER COLUMN id SET DEFAULT nextval('report_queue_control_id_seq'::regclass);

ALTER TABLE ONLY alert_deliveries
    ADD CONSTRAINT alert_deliveries_pkey PRIMARY KEY (id);

ALTER TABLE ONLY alert_recipient_state
    ADD CONSTRAINT alert_recipient_state_pkey PRIMARY KEY (key);

ALTER TABLE ONLY audit_archives
    ADD CONSTRAINT audit_archives_last_seq_key UNIQUE (last_seq);

ALTER TABLE ONLY audit_archives
    ADD CONSTRAINT audit_archives_pkey PRIMARY KEY (first_seq);

ALTER TABLE ONLY dns_expiry_monitors
    ADD CONSTRAINT dns_expiry_monitors_pkey PRIMARY KEY (id);

ALTER TABLE ONLY drp_audit_chain
    ADD CONSTRAINT drp_audit_chain_pkey PRIMARY KEY (id);

ALTER TABLE ONLY drp_findings
    ADD CONSTRAINT drp_findings_pkey PRIMARY KEY (id);

ALTER TABLE ONLY ingestion_events
    ADD CONSTRAINT ingestion_events_event_key_key UNIQUE (event_key);

ALTER TABLE ONLY ingestion_events
    ADD CONSTRAINT ingestion_events_pkey PRIMARY KEY (id);

ALTER TABLE ONLY assets
    ADD CONSTRAINT pk_assets PRIMARY KEY (id);

ALTER TABLE ONLY dns_security_observations
    ADD CONSTRAINT pk_dns_security_observations PRIMARY KEY (id);

ALTER TABLE ONLY drp_audit_logs
    ADD CONSTRAINT pk_drp_audit_logs PRIMARY KEY (id);

ALTER TABLE ONLY drp_breaches
    ADD CONSTRAINT pk_drp_breaches PRIMARY KEY (id);

ALTER TABLE ONLY drp_connectors
    ADD CONSTRAINT pk_drp_connectors PRIMARY KEY (id);

ALTER TABLE ONLY drp_modules
    ADD CONSTRAINT pk_drp_modules PRIMARY KEY (id);

ALTER TABLE ONLY drp_phishing_domains
    ADD CONSTRAINT pk_drp_phishing_domains PRIMARY KEY (id);

ALTER TABLE ONLY drp_refresh_families
    ADD CONSTRAINT pk_drp_refresh_families PRIMARY KEY (id);

ALTER TABLE ONLY jobs
    ADD CONSTRAINT pk_jobs PRIMARY KEY (id);

ALTER TABLE ONLY report_artifact_cleanup
    ADD CONSTRAINT pk_report_artifact_cleanup PRIMARY KEY (artifact_name);

ALTER TABLE ONLY report_audit_outbox
    ADD CONSTRAINT pk_report_audit_outbox PRIMARY KEY (id);

ALTER TABLE ONLY report_queue_control
    ADD CONSTRAINT pk_report_queue_control PRIMARY KEY (id);

ALTER TABLE ONLY reports
    ADD CONSTRAINT pk_reports PRIMARY KEY (id);

ALTER TABLE ONLY system_settings
    ADD CONSTRAINT pk_system_settings PRIMARY KEY (id);

ALTER TABLE ONLY users
    ADD CONSTRAINT pk_users PRIMARY KEY (id);

ALTER TABLE ONLY schedule_occurrences
    ADD CONSTRAINT schedule_occurrences_pkey PRIMARY KEY (key);

ALTER TABLE ONLY source_accounts
    ADD CONSTRAINT source_accounts_pkey PRIMARY KEY (id);

ALTER TABLE ONLY source_observations
    ADD CONSTRAINT source_observations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY drp_breaches
    ADD CONSTRAINT uq_breach_email UNIQUE (source_id, breach_name, matched_email);

ALTER TABLE ONLY dns_expiry_monitors
    ADD CONSTRAINT uq_dns_expiry_monitor_asset_kind UNIQUE (asset_id, kind);

ALTER TABLE ONLY dns_security_observations
    ADD CONSTRAINT uq_dns_observation_source_key UNIQUE (source, observation_key);

ALTER TABLE ONLY drp_audit_logs
    ADD CONSTRAINT uq_drp_audit_logs_seq UNIQUE (seq);

ALTER TABLE ONLY drp_connectors
    ADD CONSTRAINT uq_drp_connectors_name UNIQUE (name);

ALTER TABLE ONLY drp_phishing_domains
    ADD CONSTRAINT uq_drp_phishing_domains_phishing_domain UNIQUE (phishing_domain);

ALTER TABLE ONLY drp_refresh_families
    ADD CONSTRAINT uq_drp_refresh_families_family_id UNIQUE (family_id);

ALTER TABLE ONLY drp_findings
    ADD CONSTRAINT uq_findings_module_dedup UNIQUE (module, dedup_key);

ALTER TABLE ONLY jobs
    ADD CONSTRAINT uq_jobs_schedule_key UNIQUE (schedule_key);

ALTER TABLE ONLY drp_modules
    ADD CONSTRAINT uq_modules_finding_kind UNIQUE (finding_kind);

ALTER TABLE ONLY report_audit_outbox
    ADD CONSTRAINT uq_report_audit_outbox_event_key UNIQUE (event_key);

ALTER TABLE ONLY source_accounts
    ADD CONSTRAINT uq_source_account UNIQUE (source_id, name);

ALTER TABLE ONLY source_observations
    ADD CONSTRAINT uq_source_observation UNIQUE (module, source, observation_key);

ALTER TABLE ONLY system_settings
    ADD CONSTRAINT uq_system_settings_singleton_key UNIQUE (singleton_key);

ALTER TABLE ONLY users
    ADD CONSTRAINT uq_users_email UNIQUE (email);

-- ---------------------------------------------------------------------------
-- Indexes
-- ---------------------------------------------------------------------------

CREATE INDEX ix_alert_deliveries_batch_id ON alert_deliveries USING btree (batch_id);

CREATE INDEX ix_alert_deliveries_channel ON alert_deliveries USING btree (channel);

CREATE INDEX ix_alert_deliveries_job_id ON alert_deliveries USING btree (job_id);

CREATE INDEX ix_alert_deliveries_next_attempt_at ON alert_deliveries USING btree (next_attempt_at);

CREATE INDEX ix_alert_deliveries_status ON alert_deliveries USING btree (status);

CREATE INDEX ix_alert_deliveries_target ON alert_deliveries USING btree (target);

CREATE INDEX ix_alert_deliveries_threat_type ON alert_deliveries USING btree (threat_type);

CREATE INDEX ix_alert_delivery_due ON alert_deliveries USING btree (status, next_attempt_at, created_at);

CREATE INDEX ix_assets_asset_type ON assets USING btree (asset_type);

CREATE INDEX ix_assets_asset_value_trgm ON assets USING gin (asset_value gin_trgm_ops);

CREATE INDEX ix_assets_created_at_id ON assets USING btree (created_at, id);

CREATE INDEX ix_assets_normalized_value_key ON assets USING btree (lower(rtrim(TRIM(BOTH FROM COALESCE(normalized_value, asset_value)), '.'::text)));

CREATE INDEX ix_assets_normalized_value_trgm ON assets USING gin (normalized_value gin_trgm_ops);

CREATE INDEX ix_audit_job_id ON drp_audit_logs USING btree (((details ->> 'job_id'::text)));

CREATE INDEX ix_audit_request_id ON drp_audit_logs USING btree (((details ->> 'request_id'::text)));

CREATE INDEX ix_audit_timestamp_id ON drp_audit_logs USING btree ("timestamp", id);

CREATE INDEX ix_dns_expiry_monitor_due ON dns_expiry_monitors USING btree (state, expires_at);

CREATE INDEX ix_dns_observation_expires ON dns_security_observations USING btree (expires_at);

CREATE INDEX ix_dns_observation_source_seen ON dns_security_observations USING btree (source, last_seen_at);

CREATE INDEX ix_dns_observation_subject_type ON dns_security_observations USING btree (subject, observation_type);

CREATE INDEX ix_dns_security_observations_observation_type ON dns_security_observations USING btree (observation_type);

CREATE INDEX ix_dns_security_observations_source ON dns_security_observations USING btree (source);

CREATE INDEX ix_dns_security_observations_subject ON dns_security_observations USING btree (subject);

CREATE INDEX ix_dns_security_observations_subject_key ON dns_security_observations USING btree (lower(rtrim(TRIM(BOTH FROM subject), '.'::text)));

CREATE INDEX ix_dns_security_observations_value_key ON dns_security_observations USING btree (lower(rtrim(TRIM(BOTH FROM value), '.'::text)));

CREATE INDEX ix_drp_audit_logs_action ON drp_audit_logs USING btree (action);

CREATE INDEX ix_drp_audit_logs_entry_hash ON drp_audit_logs USING btree (entry_hash);

CREATE INDEX ix_drp_audit_logs_timestamp ON drp_audit_logs USING btree ("timestamp");

CREATE INDEX ix_drp_audit_logs_user_id ON drp_audit_logs USING btree (user_id);

CREATE INDEX ix_drp_audit_logs_user_timestamp ON drp_audit_logs USING btree (user_id, "timestamp");

CREATE INDEX ix_drp_breaches_matched_domain ON drp_breaches USING btree (matched_domain);

CREATE INDEX ix_drp_breaches_matched_domain_key ON drp_breaches USING btree (lower(rtrim(TRIM(BOTH FROM matched_domain), '.'::text)));

CREATE INDEX ix_drp_breaches_matched_email ON drp_breaches USING btree (matched_email);

CREATE INDEX ix_drp_breaches_matched_email_domain ON drp_breaches USING btree (lower(split_part((matched_email)::text, '@'::text, 2)));

CREATE INDEX ix_drp_breaches_matched_email_key ON drp_breaches USING btree (lower(rtrim(TRIM(BOTH FROM matched_email), '.'::text)));

CREATE INDEX ix_drp_breaches_status ON drp_breaches USING btree (status);

CREATE INDEX ix_drp_connectors_connector_type ON drp_connectors USING btree (connector_type);

CREATE UNIQUE INDEX ix_drp_connectors_name ON drp_connectors USING btree (name);

CREATE UNIQUE INDEX ix_drp_connectors_token_hash ON drp_connectors USING btree (token_hash);

CREATE INDEX ix_drp_findings_connector_name ON drp_findings USING btree (connector_name);

CREATE INDEX ix_drp_findings_matched_asset ON drp_findings USING btree (matched_asset);

CREATE INDEX ix_drp_findings_matched_asset_key ON drp_findings USING btree (lower(rtrim(TRIM(BOTH FROM matched_asset), '.'::text)));

CREATE INDEX ix_drp_findings_module_created ON drp_findings USING btree (module, created_at);

CREATE INDEX ix_drp_findings_status ON drp_findings USING btree (status);

CREATE INDEX ix_drp_phishing_domains_matched_asset ON drp_phishing_domains USING btree (matched_asset);

CREATE INDEX ix_drp_phishing_domains_matched_asset_key ON drp_phishing_domains USING btree (lower(rtrim(TRIM(BOTH FROM matched_asset), '.'::text)));

CREATE UNIQUE INDEX ix_drp_phishing_domains_phishing_domain ON drp_phishing_domains USING btree (phishing_domain);

CREATE INDEX ix_drp_phishing_domains_status ON drp_phishing_domains USING btree (status);

CREATE UNIQUE INDEX ix_drp_refresh_families_family_id ON drp_refresh_families USING btree (family_id);

CREATE INDEX ix_drp_refresh_families_revoked ON drp_refresh_families USING btree (revoked);

CREATE INDEX ix_drp_refresh_families_user_id ON drp_refresh_families USING btree (user_id);

CREATE INDEX ix_jobs_connector_id ON jobs USING btree (connector_id);

CREATE INDEX ix_jobs_created_by ON jobs USING btree (created_by);

CREATE INDEX ix_jobs_job_type ON jobs USING btree (job_type);

CREATE INDEX ix_jobs_lease_expires_at ON jobs USING btree (lease_expires_at);

CREATE INDEX ix_jobs_status ON jobs USING btree (status);

CREATE INDEX ix_jobs_task_id ON jobs USING btree (task_id);

CREATE INDEX ix_report_artifact_cleanup_available_at ON report_artifact_cleanup USING btree (available_at);

CREATE INDEX ix_report_artifact_cleanup_report_id ON report_artifact_cleanup USING btree (report_id);

CREATE INDEX ix_report_audit_outbox_available_at ON report_audit_outbox USING btree (available_at);

CREATE INDEX ix_report_audit_outbox_report_id ON report_audit_outbox USING btree (report_id);

CREATE INDEX ix_reports_created_at ON reports USING btree (created_at);

CREATE INDEX ix_reports_status ON reports USING btree (status);

CREATE INDEX ix_source_observations_matched_asset ON source_observations USING btree (matched_asset);

CREATE INDEX ix_source_observations_matched_asset_key ON source_observations USING btree (lower(rtrim(TRIM(BOTH FROM matched_asset), '.'::text)));

CREATE INDEX ix_source_observations_module_seen ON source_observations USING btree (module, last_seen_at);

CREATE UNIQUE INDEX ix_users_email ON users USING btree (email);

CREATE UNIQUE INDEX uq_assets_type_normalized_value ON assets USING btree (asset_type, normalized_value) WHERE (normalized_value IS NOT NULL);

CREATE UNIQUE INDEX uq_breach_domain_only ON drp_breaches USING btree (source_id, breach_name, matched_domain) WHERE ((matched_domain IS NOT NULL) AND (matched_email IS NULL));

-- ---------------------------------------------------------------------------
-- Foreign keys
-- ---------------------------------------------------------------------------

ALTER TABLE ONLY alert_deliveries
    ADD CONSTRAINT alert_deliveries_job_id_fkey FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE SET NULL;

ALTER TABLE ONLY dns_expiry_monitors
    ADD CONSTRAINT dns_expiry_monitors_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE;

ALTER TABLE ONLY dns_expiry_monitors
    ADD CONSTRAINT dns_expiry_monitors_observation_id_fkey FOREIGN KEY (observation_id) REFERENCES dns_security_observations(id) ON DELETE SET NULL;

ALTER TABLE ONLY drp_connectors
    ADD CONSTRAINT drp_connectors_source_account_id_fkey FOREIGN KEY (source_account_id) REFERENCES source_accounts(id) ON DELETE SET NULL;

ALTER TABLE ONLY drp_findings
    ADD CONSTRAINT drp_findings_module_fkey FOREIGN KEY (module) REFERENCES drp_modules(id) ON DELETE RESTRICT;

ALTER TABLE ONLY jobs
    ADD CONSTRAINT fk_jobs_created_by_users FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE ONLY reports
    ADD CONSTRAINT fk_reports_created_by_users FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE ONLY ingestion_events
    ADD CONSTRAINT ingestion_events_job_id_fkey FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE SET NULL;

ALTER TABLE ONLY jobs
    ADD CONSTRAINT jobs_connector_id_fkey FOREIGN KEY (connector_id) REFERENCES drp_connectors(id) ON DELETE SET NULL;

ALTER TABLE ONLY schedule_occurrences
    ADD CONSTRAINT schedule_occurrences_job_id_fkey FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE SET NULL;

ALTER TABLE ONLY source_observations
    ADD CONSTRAINT source_observations_candidate_id_fkey FOREIGN KEY (candidate_id) REFERENCES drp_phishing_domains(id) ON DELETE CASCADE;

ALTER TABLE ONLY source_observations
    ADD CONSTRAINT source_observations_connector_id_fkey FOREIGN KEY (connector_id) REFERENCES drp_connectors(id) ON DELETE SET NULL;

ALTER TABLE ONLY source_observations
    ADD CONSTRAINT source_observations_source_account_id_fkey FOREIGN KEY (source_account_id) REFERENCES source_accounts(id) ON DELETE SET NULL;
