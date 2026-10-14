export type UserRole = "admin" | "analyst" | "viewer";
export type AssetType = "domain" | "ip_address" | "email_account" | "keyword_domain" | "keyword_title";
export type AssetCriticality = "low" | "medium" | "high" | "critical";
export type DNSObservationSource = "rdap" | "resolver" | "ctlogs" | "virustotal" | "netlas";

export interface DNSObservation {
  id: string;
  observation_type: "dns_record" | "rdap" | "certificate" | "certificate_check" | "vt_subdomain" | "vt_resolution";
  subject: string;
  record_type?: string | null;
  value?: string | null;
  source: DNSObservationSource;
  first_seen_at: string;
  last_seen_at: string;
  expires_at?: string | null;
  status: "current" | "historical" | "expired" | "unknown";
  metadata: Record<string, unknown>;
  alerted_thresholds: number[];
  evidence_count: number;
  subject_in_assets: boolean;
  value_asset_target?: string | null;
  value_in_assets: boolean;
  expiry_kind?: "registration" | "certificate" | "dns_cache" | "unknown";
  expiry_monitor?: { kind: string; state: string; checked_at: string; successful_at: string | null; expires_at: string | null; certificate_id: string | null; not_before: string | null; remaining_seconds: number | null } | null;
}

export interface User {
  id: string;
  email: string;
  full_name?: string;
  role: UserRole;
  is_active: boolean;
  /** Minutes between two manual actions of the same scope (0 = unlimited). */
  rate_limit_minutes: number;
  created_at: string;
  updated_at: string;
  /**
   * A password was assigned to this account by somebody else, so the API refuses
   * everything until the owner replaces it. Set by creating a user, resetting a
   * password as an administrator, and the admin CLI.
   */
  must_change_password?: boolean;
  /**
   * A second factor was removed for this account (administrator reset, or the CLI
   * recovery command), so a new one must be enrolled before the rest of the
   * platform opens. Clearing a factor and leaving it cleared would make recovery a
   * permanent downgrade.
   */
  must_enrol_mfa?: boolean;
  /**
   * This deployment requires administrators to use a second factor and this account
   * has none enrolled (`REQUIRE_MFA_FOR_ADMINS`). Computed by the API from the
   * deployment policy and the account on every response, never stored: it is not a
   * property of the account, so it disappears on its own the moment a factor is
   * enrolled, and it applies to administrators only.
   *
   * It is a gate rather than a suggestion. While it is true the API refuses every
   * route except the ones that enrol a factor, so an administrator who signs in
   * without one lands on the onboarding page and can reach nothing else.
   */
  mfa_required_by_policy?: boolean;
  /** When the second factor was enrolled; absent when the account has none. */
  totp_enabled_at?: string | null;
  /** Active brute-force lockout expiration timestamp if temporarily locked. */
  locked_until?: string | null;
  failed_login_attempts?: number;
}

export interface TokenResponse {
  access_token: string;
  token_type: "bearer";
  expires_in: number;
  user: User;
}

/** Second-factor state of the signed-in account (GET /auth/mfa). */
export interface MfaStatus {
  enabled: boolean;
  enabled_at: string | null;
  recovery_codes?: string[];
}

/**
 * One session this account can still be used through.
 *
 * `GET /auth/sessions` answers with usable sessions only — a session that was
 * signed out is an audit event, not a session, and shows up in the activity
 * list instead of here pretending to be a device.
 */
export interface AuthSession {
  id: string;
  created_at: string;
  last_used_at?: string | null;
  current: boolean;
}

export interface SecurityActivity {
  id: string;
  timestamp: string;
  action: string;
  ip_address: string;
  details: Record<string, unknown>;
}

/**
 * A candidate TOTP secret, returned once by POST /auth/mfa/setup.
 *
 * Nothing is enabled until a code generated from `secret` is verified through
 * POST /auth/mfa/enable, so showing this to the user is safe even if they never
 * finish enrolling.
 */
export interface MfaSetup {
  secret: string;
  otpauth_uri: string;
  digits: number;
  period_seconds: number;
}

/**
 * What the platform holds about one asset, per module (WI-20).
 *
 * The counters come from the backend's single matching rule, so a number here
 * and the tab counters on the asset page are the same number. `last_seen` is ISO
 * text per module: a breach reports a disclosure date while a scan reports a
 * timestamp, and the two are never compared.
 */
export interface AssetFindingSummary {
  total: number;
  phishing: number;
  breaches: number;
  dns: number;
  exposure: number;
  findings: number;
  last_seen: Partial<Record<string, string | null>>;
}

export interface Asset {
  id: string;
  asset_type: AssetType;
  asset_value: string;
  normalized_value?: string;
  criticality: AssetCriticality;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  /** Present on list rows (WI-20); absent on a create/update response. */
  findings?: AssetFindingSummary | null;
}

/** The modules whose findings can name an asset, in the order the view shows them. */
export type RelatedFindingModule = "phishing" | "breaches" | "dns" | "exposure" | "findings";

/**
 * One finding that names an asset, in the uniform shape the asset view returns
 * for every module (each module's own list endpoint serves its full payload).
 */
export interface AssetRelatedFinding {
  id: string;
  module: RelatedFindingModule;
  title: string;
  matched_asset: string | null;
  source: string | null;
  status: string | null;
  observed_at: string | null;
}

/**
 * One line of an import report (WI-18). Every line the file contained has an
 * entry, so a failure always names the row it belongs to.
 */
export interface AssetImportRowReport {
  line: number;
  outcome: "created" | "duplicate" | "invalid";
  asset_type: string | null;
  asset_value: string | null;
  detail: string | null;
}

export interface AssetImportReport {
  dry_run: boolean;
  created: number;
  duplicate: number;
  invalid: number;
  rows: AssetImportRowReport[];
}

export interface AssetBulkResult {
  operation: "activate" | "deactivate" | "criticality" | "delete";
  requested: number;
  applied: number;
  missing: string[];
  cascade_findings: boolean;
  findings_deleted: Record<string, number>;
}

export interface AssetFindingsResponse {
  asset: { id: string; asset_type: AssetType; asset_value: string; is_active: boolean };
  counts: Record<RelatedFindingModule, number> & { total: number };
  /** When each module last saw a finding about this asset, as ISO text (WI-20). */
  last_seen?: Partial<Record<string, string | null>>;
  module: RelatedFindingModule;
  items: AssetRelatedFinding[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

export type DetectionSource = string;
export type ThreatStatus = "active" | "investigating" | "resolved";

export interface PhishingThreat {
  id: string;
  phishing_domain: string;
  matched_asset: string;
  ip_address?: string;
  web_ports?: string;
  detection_source: DetectionSource;
  original_domain?: string;
  whois_registrar?: string;
  whois_abuse_email?: string;
  domain_created_at?: string;
  status: ThreatStatus;
  created_at: string;
  updated_at: string;
}

/**
 * A breach finding: the neutral fields any breach source can supply, plus a
 * source-declared `attributes` payload (classification flags, exposed-secret
 * samples, catalog timestamps). Nothing here belongs to one particular vendor.
 */
export interface Breach {
  id: string;
  source_id?: string;
  breach_name: string;
  title: string;
  domain: string;
  breach_date: string;
  pwn_count: number;
  description?: string;
  data_classes: string[];
  matched_email?: string;
  matched_domain?: string;
  matched_asset?: string;
  matched_asset_type?: "domain" | "email_account";
  status: ThreatStatus;
  /** Whatever the reporting source knows beyond the neutral fields. */
  attributes?: Record<string, unknown>;
  created_at: string;
}

export type ReportStatus = "pending" | "generating" | "completed" | "failed";

export interface ReportTruncationSection {
  total: number;
  included: number;
  truncated: boolean;
}

export interface ReportTruncation {
  limit: number;
  truncated: boolean;
  sections: Record<string, ReportTruncationSection>;
}

export interface Report {
  id: string;
  report_name: string;
  created_by?: string;
  created_by_email?: string;
  file_path: string;
  /** False when the artifact is gone from the store; the download must be hidden. */
  file_available?: boolean | null;
  is_truncated?: boolean;
  truncation_metadata?: ReportTruncation | null;
  status: ReportStatus;
  created_at: string;
}

export interface RuntimeConfiguration {
  app_env: string;
  version: string;
  database_pool: { size: number; max_overflow: number; pool_timeout_seconds: number };
  timeouts: { statement_ms: number; command_seconds: number; outbound_dns_seconds: number };
  resource_limits_source: string;
}

export interface SystemSettings {
  id: string;
  version: number;
  telegram_bot_token?: string;
  smtp_host?: string;
  smtp_port?: number;
  smtp_security_mode?: "starttls" | "ssl" | "plain";
  smtp_user?: string;
  smtp_password?: string;
  smtp_from_email?: string;
  alert_recipient_email?: string;
  email_alerts_enabled?: boolean;
  telegram_alerts_enabled?: boolean;
  alert_email_user_ids?: string[];
  telegram_chat_ids?: string[];
  schedule_phishing?: { days: number[]; hour: number; minute: number } | null;
  schedule_breaches?: { days: number[]; hour: number; minute: number } | null;
  schedule_dns_security?: { days: number[]; hour: number; minute: number } | null;
  schedule_exposure?: { days: number[]; hour: number; minute: number } | null;
  schedules?: Record<string, { days: number[]; hour: number; minute: number } | null> | null;
  created_at: string;
  updated_at: string;
}

export type HealthState = "healthy" | "degraded" | "failed" | "disabled" | "not_configured" | "unknown";

export interface ConnectorHealth {
  name: string;
  connector_type: string;
  status: "enabled" | "disabled";
  health: HealthState;
  online?: boolean;
  last_seen_at?: string | null;
  last_error?: string | null;
  info?: Record<string, unknown> | null;
}

export interface ConnectorHealthResponse {
  items: ConnectorHealth[];
  generated_at: string;
}

/** One operator-editable setting, declared by the connector itself. */
export interface ConnectorConfigField {
  type: "bool" | "int" | "float" | "str";
  label?: string;
  default?: boolean | number | string | null;
  description?: string;
}

/**
 * A connector's self-declaration: what it feeds, the job type it alone claims,
 * the finding kind it submits, the inventory it consumes and the settings an
 * operator may edit. The UI renders from this instead of hardcoding vendors.
 */
export interface ConnectorManifest {
  module: string;
  job_type: string;
  finding_kind: string;
  asset_types: string[];
  config_schema: Record<string, ConnectorConfigField>;
}

export interface SourceAccount {
  id: string;
  source_id: string;
  name: string;
  credential_ref?: string | null;
  policy: { approved: boolean; requests_per_minute?: number; daily_budget?: number };
  access_state: string;
  has_api_key?: boolean;
  api_key_hint?: string | null;
}

export interface Connector {
  id: string;
  name: string;
  connector_type: string;
  status: "enabled" | "disabled";
  api_version: string | null;
  default_job_type: string;
  manifest?: ConnectorManifest | null;
  config?: Record<string, unknown> | null;
  last_seen_at?: string | null;
  last_error?: string | null;
  provider?: string | null;
  source_account_id?: string | null;
  quota_group?: string | null;
  readiness?: { credentials_configured: boolean; credential_state: string; provider_error?: string | null; capabilities: string[] } | null;
  last_success_at?: string | null;
  info?: Record<string, unknown> | null;
  /** Credential state. The secret itself never leaves the core. */
  has_token?: boolean;
  token_prefix?: string | null;
  token_created_at?: string | null;
  token_last_used_at?: string | null;
}

/** A freshly issued connector credential; `token` is shown exactly once. */
export interface ConnectorTokenResponse {
  connector: Connector;
  token: string;
  rotated: boolean;
}

export interface ConnectorModuleEntry {
  job_types: string[];
  finding_kind: string;
  connectors: Array<{
    name: string;
    status: string;
    job_type: string;
    asset_types: string[];
    config_schema: Record<string, ConnectorConfigField>;
  }>;
  /** Registry metadata (present since modules became data). */
  label?: string;
  description?: string;
  asset_types?: string[];
  storage?: "table" | "generic";
  enabled?: boolean;
  builtin?: boolean;
}

export interface ConnectorModulesResponse {
  modules: Record<string, ConnectorModuleEntry>;
}

/** One field a module declares for its own findings. */
export interface RegistryModuleField {
  type: "str" | "text" | "int" | "float" | "bool" | "date" | "list_str" | string;
  label?: string;
  description?: string;
  required?: boolean;
}

/** A module as declared on the platform (data, not a hardcoded set). */
export interface RegistryModule {
  id: string;
  label: string;
  description?: string | null;
  finding_kind: string;
  asset_types: string[];
  fields: Record<string, RegistryModuleField>;
  dedup_fields: string[];
  title_field?: string | null;
  /** "table" for a built-in module with its own page, "generic" otherwise. */
  storage: "table" | "generic";
  enabled: boolean;
  builtin: boolean;
}

export interface ModuleListResponse {
  modules: RegistryModule[];
  generated_at: string;
}

/** A finding stored generically for a declared module. */
export interface ModuleFinding {
  id: string;
  module: string;
  finding_kind: string;
  connector_name: string;
  job_id?: string | null;
  title: string;
  matched_asset?: string | null;
  status: FindingStatus;
  /** Exactly the fields the module declared, plus the source's attributes. */
  payload: Record<string, unknown>;
  created_at: string;
}

/**
 * Triage states a finding can be moved to.
 *
 * The same three the built-in phishing module uses, so triaging a declared
 * module's findings behaves the way an analyst already expects.
 */
export type FindingStatus = "active" | "investigating" | "resolved";

export interface AlertChannelHealth {
  channel: string;
  label: string;
  enabled: boolean;
  configured: boolean;
  health: HealthState;
  message: string;
  latency_ms?: number | null;
  /** Null when the channel is disabled and no probe was performed. */
  last_checked_at: string | null;
}

export interface AlertChannelsHealthResponse {
  items: AlertChannelHealth[];
  generated_at: string;
}

export interface TelegramChatValidationResult {
  chat_id: string;
  ok: boolean;
  error_code?: string;
  error?: string;
  chat_type?: string | null;
  username?: string | null;
  title?: string | null;
}

export interface TelegramChatValidationResponse {
  valid: number;
  total: number;
  results: TelegramChatValidationResult[];
}

export interface DashboardStats {
  kpi: {
    total_assets: number;
    total_phishing: number;
    total_breaches: number;
    active_threats_7d: number;
  };
  timeline: { date: string; phishing: number; breaches: number }[];
  phishing_by_source: { source: string; count: number }[];
  assets_by_criticality: { criticality: AssetCriticality; count: number }[];
}

export type JobStatus = "pending" | "running" | "success" | "partial" | "error" | "cancelled" | "skipped";
// Connector job types are declared at runtime, so the UI must accept future
// namespaced values without a frontend release.
export type JobType = string;

export interface Job {
  id: string;
  job_type: JobType;
  status: JobStatus;
  created_by?: string;
  created_by_email?: string;
  task_id?: string;
  title?: string;
  error_message?: string;
  params?: Record<string, unknown> | unknown[];
  result_summary?: Record<string, unknown> | unknown[];
  created_at: string;
  started_at?: string;
  finished_at?: string;
  updated_at: string;
}

export interface Paginated<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
  pages: number;
}
