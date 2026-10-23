export type UserRole = "admin" | "analyst" | "viewer";
export type AssetType = "domain" | "ip_address" | "email_account" | "keyword_domain" | "keyword_title";
export type AssetCriticality = "low" | "medium" | "high" | "critical";
export type DNSObservationSource = "rdap" | "resolver" | "ctlogs" | "virustotal" | "netlas" | "tlsprobe" | "shodan";

export interface DNSObservation {
  id: string;
  observation_type:
    | "dns_record"
    | "rdap"
    | "certificate"
    | "certificate_check"
    | "vt_subdomain"
    | "vt_resolution"
    // The provider's current reputation for the monitored name, rather than one
    // historical discovery row per scan.
    | "vt_domain"
    | "hostname"
    | "passive_dns"
    // The active probe: the mutable control row per host and port, and the
    // certificate it read (evidence, keyed by fingerprint).
    | "tls_probe"
    | "tls_certificate";
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
  expiry_kind?: "registration" | "certificate" | "tls" | "dns_cache" | "unknown";
  expiry_monitor?: { kind: string; state: string; checked_at: string; successful_at: string | null; expires_at: string | null; certificate_id: string | null; not_before: string | null; remaining_seconds: number | null } | null;
}

/**
 * What a reviewer decided about one sighting of a certificate.
 *
 * `candidate` is the state a rule produces and the only one the next sweep
 * re-queues for, so every other value is a human (or the scoring itself) saying
 * "do not ask again". The API rejects anything outside this set, which is why it
 * is a union here rather than a free string.
 */
export type TLSSightingVerdict =
  | "candidate"
  | "expected"
  | "shared_infrastructure"
  | "confirmed_foreign"
  | "rejected";

/**
 * One place a certificate was observed.
 *
 * A sighting without an address is still a sighting: a provider can index a
 * certificate without saying where it is served. `is_ours` is the platform's own
 * answer — a probe of a monitored host, or an address belonging to one of our
 * `ip_address` assets — and never a source's opinion.
 */
export interface TLSCertificateSighting {
  id: string;
  subject: string | null;
  /** Every hostname this certificate was reported for at this endpoint. */
  subjects?: string[];
  ip: string | null;
  port: number | null;
  source: string;
  is_ours: boolean;
  /** 0-100, from the scoring rules that judged this sighting. */
  confidence: number;
  /** The provider facts a rule scored on (org, asn, rules, sources, echo, ...). */
  signals: Record<string, unknown>;
  verdict: TLSSightingVerdict;
  first_seen_at: string;
  last_seen_at: string;
  reviewed_at: string | null;
  review_note: string | null;
}

/**
 * One certificate, as an object that outlives any single hostname.
 *
 * The object the triage view is built on: the same certificate is legitimately
 * seen by our own probe, by Certificate Transparency and by a provider, and the
 * interesting question is asked of the certificate rather than of any one
 * observation.
 */
export interface TLSCertificate {
  id: string;
  fingerprint_sha256: string;
  fingerprint_sha1: string | null;
  /** Subject Public Key Info digest: the identity that survives a re-issue. */
  spki_sha256: string | null;
  serial_hex: string | null;
  subject_dn: string | null;
  issuer_dn: string | null;
  not_before: string | null;
  not_after: string | null;
  san_dns: string[];
  key_algo: string | null;
  /** Which kind of evidence created the row first: our_probe | ct | provider. */
  origin: string;
  first_seen_at: string;
  last_seen_at: string;
  sightings: TLSCertificateSighting[];
  foreign_sightings: number;
}

export type CertificateExceptionKind = "fingerprint" | "spki" | "ip" | "asn" | "issuer";

/** An identity a rule must not alert on, and why (shared hosting, a CDN, a partner). */
export interface CertificateScopeException {
  id: string;
  match_kind: CertificateExceptionKind;
  match_value: string;
  reason: string | null;
  created_by: string | null;
  expires_at: string | null;
  expired: boolean;
  created_at: string;
}

/**
 * What `POST /dns/certificate-exceptions` answers.
 *
 * A named type rather than `Omit<CertificateScopeException, ...>`, because the
 * create route sends five fields and never sent `created_by`. The list row keeps
 * it: the column is filled by the rows this route writes and by older ones that
 * may not carry an account, and `created_by` says which.
 */
export interface CertificateScopeExceptionCreated {
  id: string;
  match_kind: CertificateExceptionKind;
  match_value: string;
  reason: string | null;
  expires_at: string | null;
}

export interface User {
  id: string;
  email: string;
  /**
   * The API serializes the column, so an unset name arrives as `null` — not as an
   * absent key. Both are falsy, but only one type-checks against `String.length`,
   * which is how a nullable field becomes a crash at the first `.trim()`.
   */
  full_name?: string | null;
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
  /**
   * When this account last completed a sign-in, or `null` when it never has.
   * Both `/auth/me` and the admin user list carry it, and `null` is rendered as
   * "never" rather than an empty cell — the two are different answers.
   */
  last_login_at?: string | null;
  /** When an outstanding invitation expires; absent when none is pending. */
  invitation_expires_at?: string | null;
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
  /** `null` when normalization leaves the value unchanged — the API always sends the key. */
  normalized_value?: string | null;
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

/** How the alert budget reports a candidate (WI-07/WI-08). */
export type AlertBand = "direct" | "digest" | "list";

/**
 * The analyst's decision about a candidate (WI-12).
 *
 * It outranks the score wherever the two disagree: a confirmed candidate alerts
 * however low it scores, and a rejected one is silent — including in the daily
 * digest. The server refuses anything outside this set, which is why it is a union
 * here rather than a free string.
 */
export type PhishingVerdict = "confirmed" | "rejected";

export interface PhishingThreat {
  id: string;
  phishing_domain: string;
  matched_asset: string;
  ip_address?: string | null;
  web_ports?: string | null;
  detection_source: DetectionSource;
  original_domain?: string | null;
  whois_registrar?: string | null;
  whois_abuse_email?: string | null;
  domain_created_at?: string | null;
  /**
   * Whole days since the registration, computed by the server from
   * `domain_created_at` when the row is read. `null` means no source has answered
   * the registration date yet — which is not "registered today".
   */
  domain_age_days?: number | null;
  /**
   * The candidate's scored confidence, 0…100, computed by the server from the
   * signals recorded for it (WI-08). `0` means nothing has fired yet — the honest
   * answer for a candidate nothing has been established about.
   */
  confidence: number;
  /**
   * The signals that fired and what each contributed, in weight-table order. The
   * score is the sum of these, which is what makes it auditable: a number without
   * its reasons is one an analyst has to take on faith.
   */
  signals: Record<string, number>;
  /**
   * What the alert budget would do with this candidate, from the deployment's own
   * thresholds: `direct` alerts at once, `digest` waits for the daily summary,
   * `list` is visible without a message. The thresholds are not sent, because the
   * page must not print a number this installation may have changed.
   */
  alert_band: AlertBand;
  /**
   * What an analyst decided, if anyone has. `null` means nobody has looked yet —
   * deliberately distinguishable from a decision, because the two lead to opposite
   * routing and a candidate that merely looks reviewed is worse than one that is
   * obviously untouched.
   */
  verdict: PhishingVerdict | null;
  /** Why the decision was reached, in the analyst's own words (required to reject). */
  verdict_reason?: string | null;
  verdict_by?: string | null;
  verdict_at?: string | null;
  /**
   * Which sources reported this candidate, distinct and sorted (WI-30).
   *
   * Read from the evidence rows by the server rather than stored on the candidate,
   * because a source is an observation. `[]` means no evidence is recorded (or it
   * has been pruned) — it is not the connector that *found* the name, which is
   * `detection_source`, and the page must not present one as the other.
   */
  sources?: string[];
  /** How many of them, so the column does not have to count strings. */
  source_count?: number;
  status: ThreatStatus;
  created_at: string;
  updated_at: string;
}

/**
 * One row of the source evidence behind a candidate (W2.5).
 *
 * `fields` is the allowlisted half of the connector's own payload, and it is what makes
 * the row readable: `capability` names the question that produced it (a certificate
 * that claims the brand, a registration record, a mail lookup), `verdict` says whether
 * the row discovered the name or describes one the platform already had, and the rest
 * are the facts themselves. `observed_at` is when the *provider* saw it, which is not
 * when the platform did — `first_seen_at` is that second number.
 */
export interface PhishingEvidence {
  source: string;
  matched_asset: string;
  observed_at: string | null;
  first_seen_at: string;
  last_seen_at: string;
  fields?: {
    capability?: string;
    verdict?: string;
    title?: string;
    association?: string;
    evidence?: string;
    detection_source?: string;
    ip_address?: string;
    web_ports?: string;
    registrar?: string;
    created?: string;
    mail_capable?: boolean;
    mx_hosts?: string[];
    provider_observed_at?: string;
    wildcard?: boolean;
  } | null;
  payload?: Record<string, unknown>;
}

/**
 * The classes of exposure the breach module represents: an account was
 * compromised, it appeared in a paste, or a site was found in a stealer log.
 * The core closes this vocabulary at ingestion, so a filter can never offer a
 * class the platform refuses to store.
 */
export type BreachExposureKind = "breach" | "paste" | "stealer_log";

/**
 * How loud a finding is, derived by the core from the classes of data it exposed.
 * A closed set: `unknown` is the platform's own admission that it does not
 * recognize the classes, and is deliberately not ranked as harmless.
 */
export type BreachSeverity = "critical" | "high" | "medium" | "low" | "unknown";

/** The source-declared flags the list can be filtered by. */
export type BreachFlagFilter = "verified" | "spam" | "fabricated" | "sensitive";

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
  description?: string | null;
  data_classes: string[];
  matched_email?: string | null;
  matched_domain?: string | null;
  matched_asset?: string | null;
  matched_asset_type?: "domain" | "email_account" | null;
  status: ThreatStatus;
  /**
   * Which class of exposure this row records. Absent on a row stored before the
   * column existed, where "a breach of an account" is what the module could
   * represent and therefore what the row means.
   */
  exposure_kind?: BreachExposureKind;
  /**
   * How loud this row is. Written by the core when the row is written, so the
   * badge, the filter and the sort all read the same value (F-13).
   */
  severity?: BreachSeverity;
  /**
   * How many incidents the platform holds about the same address. Absent when the
   * row names no address, and never narrowed by the current filter: it answers
   * "is this account already known to us", not "how many rows match the view".
   */
  email_incident_count?: number | null;
  /** Whatever the reporting source knows beyond the neutral fields. */
  attributes?: Record<string, unknown>;
  created_at: string;
  /** When the source last reported this incident, and when it first confirmed it. */
  last_seen_at?: string | null;
  verified_at?: string | null;
  /**
   * The row was stored without the facts that normally describe an incident, so
   * `breach_date` is the day it was observed rather than the day it happened.
   */
  metadata_incomplete?: boolean;
}

export interface BreachList extends Paginated<Breach> {
  /** Findings that arrived and no alert channel has reported yet. */
  unannounced: number;
  /** What "new since the last scan" is measured from; null when none finished. */
  new_since?: string | null;
}

/**
 * What the last breach scan was allowed to ask about one domain it was given.
 *
 * `asked` is a domain the scan put its question to, `unscanned` is a refusal by
 * the provider (which always names why), and `unknown` is a domain the scan never
 * reached because it stopped early. Only `asked` means "nothing was found".
 */
export interface BreachDomainReadiness {
  domain: string;
  status: "asked" | "unscanned" | "unknown";
  reason?: string | null;
}

/**
 * What a source answered about enrolling one monitored domain in its account.
 *
 * `generated` carries the TXT value a person has to publish; `verified` means the
 * source accepted it, which is what turns a domain from "not scanned" into one a
 * scan may ask about. A verification stores no finding — it is a fact about the
 * account's access to the domain, so it is shown beside the domains, not in them.
 */
export interface BreachDomainVerification {
  domain: string;
  action: "generate" | "verify";
  status: "generated" | "verified" | "not_verified" | "failed";
  reason?: string | null;
  /** The record exactly as the source stated it, for a person to publish. */
  txt_record_value?: string | null;
  job_id?: string | null;
  requested_at?: string | null;
}

/** What the source says this account may do, in neutral words. */
export interface BreachProviderEntitlements {
  subscription?: string | null;
  requests_per_minute?: number | null;
  includes_stealer_logs?: boolean | null;
  includes_kanon?: boolean | null;
  domains_verified?: number | null;
}

/**
 * What the most recent finished breach scan could ask, read from the scan itself
 * so the page and the job history cannot disagree about the same run.
 */
export interface BreachProviderReadiness {
  scan_job_id?: string | null;
  /** The source the reported scan ran on; the one a verification should ask. */
  connector?: string | null;
  scanned_at?: string | null;
  status?: string | null;
  partial: boolean;
  reasons: Record<string, number>;
  entitlements?: BreachProviderEntitlements | null;
  pacing: Record<string, string | number | boolean>;
  domains: BreachDomainReadiness[];
  unscanned_total: number;
  /** The reporting source's own names for the data classes it publishes. */
  data_class_labels: Record<string, string>;
  /** The newest verification attempt per domain, whether or not a scan ran. */
  verifications?: BreachDomainVerification[];
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
  created_by?: string | null;
  created_by_email?: string | null;
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
  /** A JSON column: absent means "no explicit recipients", and the API serializes that as `null`. */
  alert_email_user_ids?: string[] | null;
  telegram_chat_ids?: string[] | null;
  schedule_phishing?: { days: number[]; hour: number; minute: number } | null;
  schedule_breaches?: { days: number[]; hour: number; minute: number } | null;
  schedule_dns_security?: { days: number[]; hour: number; minute: number } | null;
  schedule_exposure?: { days: number[]; hour: number; minute: number } | null;
  schedules?: Record<string, { days: number[]; hour: number; minute: number } | null> | null;
  // The alert budget as the operator stated it (WI-13). ``null``/absent is not
  // "off" and not "zero": it is "this installation has not decided this one", and
  // the deployment's ALERT_* environment answers it. The resolved answer — the one
  // actually routing findings — is ``AlertPolicy``.
  alert_confidence_direct?: number | null;
  alert_confidence_digest?: number | null;
  alert_phishing_digest_enabled?: boolean | null;
  alert_phishing_digest_hour_utc?: number | null;
  alert_no_channel_retry_hours?: number | null;
  alert_candidate_change_notifications?: boolean | null;
  /**
   * The breach half of the same budget. These two were missing from this type
   * after the alert-budget work landed: the API has serialized them since, and
   * the settings page reads them through an untyped helper, so nothing failed —
   * the interface simply described a response the API no longer sent.
   */
  alert_breach_noise_policy?: BreachNoiseChoice | null;
  alert_breach_digest_threshold?: number | null;
  created_at: string;
  updated_at: string;
}

/** The alert budget in force: the saved values where stated, the environment for
 * the rest, and which row fields were refused as a whole because they did not
 * hold together (``invalid``). */
export interface AlertPolicy {
  confidence_direct: number;
  confidence_digest: number;
  digest_enabled: boolean;
  digest_hour_utc: number;
  no_channel_retry_hours: number;
  candidate_change_notifications: boolean;
  breach_noise_policy: BreachNoisePolicy;
  breach_digest_threshold: number;
  source: "environment" | "settings";
  invalid: string[];
}

/** What the channel does with a breach incident the source labels spam or
 * fabricated. ``all`` is the behaviour before the choice existed. */
export type BreachNoisePolicy = "store_only_spam" | "verified_only" | "all";

/** The stored tri-state of the breach noise policy: the row may state nothing, in
 * which case the deployment's ``ALERT_BREACH_NOISE_POLICY`` answers it. */
export type BreachNoiseChoice = "default" | BreachNoisePolicy;

/** One of the two switches in the alert budget. Three states, because the row's
 * own state is three: not stated (the deployment answers), on, and off. */
export type AlertBudgetChoice = "default" | "on" | "off";

export type HealthState = "healthy" | "degraded" | "failed" | "disabled" | "not_configured" | "unknown";

export interface ConnectorHealth {
  name: string;
  connector_type: string;
  status: "enabled" | "disabled";
  health: HealthState;
  /** The heartbeat flag DNS Security reads to decide whether a source can be
   * asked to scan. The dashboard's badge derives from `health`, which applies
   * the same staleness threshold. */
  online?: boolean;
  last_seen_at?: string | null;
  last_error?: string | null;
  /** Why the core would refuse this provider's next scan, when it would
   * (`provider_account_missing` / `account_policy_unapproved`). Administrator
   * only: the key is always present and `null` for every other role. */
  blocked_reason?: string | null;
  /** The account's remaining provider requests today, the budget they are spent
   * from and why the remainder is unknown. Administrator only, like
   * `blocked_reason`. */
  quota_remaining?: number | null;
  quota_budget?: number | null;
  quota_reason?: string | null;
  /** What the source declared about its provider credentials, in a closed
   * vocabulary. Explains a refusal `health` cannot: a worker can be online and
   * healthy while its key was rejected. Every role sees this. */
  credentials_configured: boolean;
  credential_state: "valid" | "invalid" | "unsupported" | "unknown";
  /** The provider's last failure, from a fixed list rather than provider prose. */
  provider_error: string | null;
  /** When the source last declared readiness — not its heartbeat. */
  checked_at: string | null;
  /** When collection last succeeded; null means it never has. */
  last_success_at: string | null;
  /** Server-computed age of `last_success_at`, so the browser's clock is not
   * used to judge a remote worker. */
  last_success_age_seconds: number | null;
  /** The broad readiness document (capabilities, operations, provider labels).
   * Administrator only; the key is present and null for every other role. */
  readiness?: Record<string, unknown> | null;
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

/** What the delivery queue did for one channel, independent of whether its probe
 * could reach the provider. Numbers only: the response is served to viewers, so
 * it carries no target, batch id or recipient digest. */
export interface AlertDeliverySummary {
  counts: {
    pending: number;
    delivering: number;
    sent: number;
    failed: number;
    cancelled: number;
    ambiguous: number;
  };
  /** Oldest delivery that is not sent or cancelled; null when the queue is clean. */
  oldest_unresolved_at: string | null;
  oldest_unresolved_age_seconds: number | null;
  /** Pending/failed deliveries whose retry window is still in the future. */
  retrying: number;
  /** Ambiguous or failed deliveries older than `ALERT_RECIPIENT_HOLD_SECONDS`. */
  stuck: number;
  /** `delivery_stuck` when `stuck > 0`; the reason the channel is degraded even
   * if its probe succeeded. */
  degraded_reason: string | null;
}

export interface AlertChannelHealth {
  channel: string;
  label: string;
  enabled: boolean;
  configured: boolean;
  health: HealthState;
  message: string;
  latency_ms?: number | null;
  /** What the probe itself did. `saturated` means the SMTP pool had no free
   * slot, so `health` is `unknown` — the channel was not observed, and the
   * probe's queue is not the channel's condition. `skipped` means the channel is
   * disabled and nothing was dialled. */
  probe_state: "ok" | "saturated" | "timeout" | "skipped";
  /** When the probe ran — not when the response was built. Null when no probe
   * ran (disabled channel). A cached answer keeps the time of the probe it
   * repeats, so `from_cache: true` with a recent `checked_at` still means the
   * handshake may be a minute old. */
  checked_at: string | null;
  /** True when this answer repeats an earlier probe within
   * `ALERT_HEALTH_CACHE_SECONDS`. */
  from_cache: boolean;
  /** The queue's own verdict, beside the probe's. */
  delivery: AlertDeliverySummary;
}

export interface AlertChannelsHealthResponse {
  items: AlertChannelHealth[];
  /** Holds and retry windows are keyed by a digest of channel+target, so the
   * count is stated once for the installation rather than guessed per channel. */
  delivery_queue: { waiting_recipients: number };
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

/**
 * The breach numbers the dashboard and the report both publish, from one rule.
 *
 * `total_findings` counts what the sources reported about *our* accounts;
 * `new_incidents_7d` counts what they added to their own catalogues, whether or not
 * any monitored address is in it. `captions` carries the wording that goes with each
 * number, so both surfaces print the same sentence beside the same figure.
 */
export interface BreachKpi {
  window_days: number;
  total_findings: number;
  /** The stored findings split by class of exposure, summing to `total_findings`. */
  findings_by_exposure_kind: Record<string, number>;
  active_findings_7d: number;
  new_incidents_7d: number;
  catalogue_incidents: number;
  undated_incidents: number;
  catalogue_sources: number;
  catalogue_synced_at?: string | null;
  captions: {
    total_findings: string;
    active_findings_7d: string;
    new_incidents_7d: string;
    findings_by_exposure_kind: string;
  };
}

/** Self-diagnostics computed inside `/dashboard/stats` from the same probes
 * `/ready` runs and the same rules the metrics endpoint applies. It is a field
 * of the stats answer so the page needs no fourth request (D11). */
export interface PlatformStatus {
  database: "ok" | "error";
  redis: "ok" | "error";
  /** `/ready` serves 503 on this: audit writes are failing. */
  audit_degraded: boolean;
  connectors: {
    enabled: number;
    disabled: number;
    /** Enabled connectors past the heartbeat threshold, or never seen. */
    silent: number;
    /** The longest silence among enabled connectors; `seconds: null` means the
     * source has never checked in. */
    longest_silence: { name: string; seconds: number | null } | null;
  };
  oldest_running_job_seconds: number | null;
  deliveries: {
    counts: {
      pending: number;
      delivering: number;
      sent: number;
      failed: number;
      cancelled: number;
      ambiguous: number;
    };
    /** Ambiguous or failed deliveries older than the recipient-hold window. */
    stuck: number;
    waiting_recipients: number;
  };
}

/** One line of the finding timeline: a registry module that records findings.
 *
 * The key is the module id, and it is what the row carries; the label is the
 * module's own, so a newly declared module needs no change here or in the page
 * (DHP-11). */
export interface DashboardTimelineSeries {
  key: string;
  label: string;
  module_id: string;
}

/** A registry module the timeline does not count, and the reason code. */
export interface DashboardTimelineExcluded {
  module_id: string;
  label: string;
  reason: string;
}

/** A series' totals for the window and for the 30 days before it (U-4). */
export interface DashboardTimelineComparison {
  current: number;
  previous: number;
}

/** A calendar day with one count per series key. */
export type DashboardTimelineDay = { date: string } & Record<string, number | string>;

export interface DashboardStats {
  kpi: {
    total_assets: number;
    total_phishing: number;
    total_breaches: number;
    active_threats_7d: number;
    /** Incidents the sources added to their catalogues in the window (WI-16). */
    new_breach_incidents_7d: number;
    breach?: BreachKpi;
  };
  timeline: DashboardTimelineDay[];
  /** The series the row is made of, from the module registry. */
  timeline_series: DashboardTimelineSeries[];
  /** Modules left out by declaration, so a zero is never unexplained. */
  timeline_excluded: DashboardTimelineExcluded[];
  timeline_comparison: Record<string, DashboardTimelineComparison>;
  phishing_by_source: { source: string; count: number }[];
  assets_by_criticality: { criticality: AssetCriticality; count: number }[];
  platform?: PlatformStatus;
}

/** Everything the dashboard draws, from one request (DHP-10).
 *
 * The three sections are byte-for-byte the payloads of `/dashboard/stats`,
 * `/connectors/health` and `/alerts/health`: the page reads the same fields it
 * did when it asked those routes directly, and the server writes one
 * `dashboard.view` row instead of three audit rows in three transactions. */
export interface DashboardOverview {
  summary: DashboardStats;
  connectors: ConnectorHealthResponse;
  channels: AlertChannelsHealthResponse;
  generated_at: string;
}

export type JobStatus = "pending" | "running" | "success" | "partial" | "error" | "cancelled" | "skipped";
// Connector job types are declared at runtime, so the UI must accept future
// namespaced values without a frontend release.
export type JobType = string;

export interface Job {
  id: string;
  job_type: JobType;
  status: JobStatus;
  created_by?: string | null;
  created_by_email?: string | null;
  task_id?: string | null;
  title?: string | null;
  error_message?: string | null;
  params?: Record<string, unknown> | unknown[] | null;
  result_summary?: Record<string, unknown> | unknown[] | null;
  created_at: string;
  /** `null` until a worker claims the job; the key is always present. */
  started_at?: string | null;
  finished_at?: string | null;
  // No `updated_at`: `JobResponse` does not serialize it, and the SPA never read
  // it. It was declared here as an always-present field until the response-shape
  // gate compared this interface with the model (AUD-060).
}

export interface Paginated<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

/** Query values a list route accepts; the API validates and bounds them (AUD-060). */
export type QueryParams = Record<string, string | number | boolean | null | undefined>;

/** One audit-trail row as `GET /audit/logs` serializes it (AUD-060). */
export interface AuditLogRow {
  id: string;
  timestamp: string;
  action: string;
  user_email?: string;
  user_id?: string;
  seq?: number;
  entry_hash?: string;
  actor_identity_source?: string;
  ip_address?: string;
  details?: Record<string, unknown>;
}

/** The filter catalogue `GET /audit/actions` publishes (AUD-060). */
export interface AuditActionsCatalog {
  groups?: Array<{ category: string; actions: string[] }>;
  total?: number;
  actions?: string[];
  labels?: Record<string, string>;
}

/**
 * Where the audit chain stands, from `GET /audit/integrity`.
 *
 * Every number an operator acts on — the verified cursor, the retained range, the
 * archive's state — is read from here rather than guessed, which is why the whole
 * payload is typed instead of the four fields the page happens to render.
 */
export interface AuditIntegrity {
  full_verification: {
    upper_seq: number;
    cursor: number;
    in_progress: boolean;
    at: string | null;
    failure_seq: number | null;
    failure_reason: string | null;
  };
  committed: { through_seq: number; tip_hash: string | null };
  archive: { configured: boolean; hold: boolean; last_seq: number | null; retired: boolean };
  retained: { rows: number; first_seq: number; last_seq: number };
  retired: { through_seq: number; tip_hash: string | null };
  last_verification: { through_seq: number; at: string | null };
  keys: { configured: number };
}

/** One queued alert delivery, as `GET /alerts/queue` lists it. */
export interface AlertQueueItem {
  id: string;
  batch_id: string;
  job_id: string | null;
  channel: string;
  status: string;
  attempts: number;
  acknowledged_parts: number;
  parts: number;
  last_error: string | null;
  next_attempt_at: string | null;
}

export interface AlertQueueSummary {
  counts: Record<string, number>;
  items: AlertQueueItem[];
}

/** The active accounts the alert-recipient checkboxes offer. */
export interface UserBrief {
  id: string;
  email: string;
  role: UserRole;
  is_active: boolean;
}

/** One passive exposure observation (the source-inventory list payload). */
export interface ExposureObservation {
  id: string;
  source: string;
  subject: string;
  matched_asset?: string | null;
  first_seen_at: string;
  last_seen_at: string;
  observed_at: string | null;
  status: "observed" | "investigating" | "resolved";
  payload?: {
    port?: number;
    transport?: string;
    protocol?: string;
    metadata?: Record<string, unknown>;
    [key: string]: unknown;
  } | null;
  provenance?: Record<string, unknown> | null;
  connector_id?: string | null;
  source_account_id?: string | null;
}

export interface ExposurePage extends Paginated<ExposureObservation> {}

export interface ExposureTriageResult {
  id: string;
  status: ExposureObservation["status"];
}

/** `GET /phishing/threats/{id}/evidence` answers one array, not a page. */
export interface PhishingEvidenceResponse {
  items: PhishingEvidence[];
}

/** The two bulk cleanups answer the same shape: a status and a count. */
export interface CleanupResult {
  status: string;
  deleted: number;
}

/**
 * How many refresh families a revocation ended.
 *
 * Two routes answer it — ending every session but this browser, and an
 * administrator ending another account's — and they sent the one key as two inline
 * literals until plan 038. A count rather than a list: what an operator needs is
 * that the action happened, and the sessions page shows what is left.
 */
export interface RevokedSessions {
  revoked: number;
}

/**
 * What a scan route answers once its jobs are queued.
 *
 * `sources` and `offline_connectors` are per-route extras rather than a second
 * shape: a caller that only reads `job_ids` works everywhere.
 */
export interface ScanStartResult {
  status: string;
  job_ids: string[];
  sources?: Array<{ connector: string; status: string; reason?: string }>;
  offline_connectors?: string[];
  error?: string;
}

/** What promoting an observation or a finding into an asset answers. */
export interface PromotedAsset {
  already_exists: boolean;
  asset: {
    id?: string;
    asset_value: string;
    asset_type?: AssetType;
    is_active?: boolean;
  };
  source?: string | null;
}

/** The delivery-test and Telegram-validation routes answer service payloads. */
/**
 * What `POST /settings/test-email` answers.
 *
 * One interface used to cover both test-send routes with every field optional,
 * which made the mail answer and the Telegram answer indistinguishable to the
 * compiler — the union was eight optional fields for two payloads whose fields
 * are six and five. They are separate now, because the server sends different
 * shapes and only a separate type can be compared with each response model.
 */
export interface TestEmailResult {
  status: string;
  /** The recipient the mail was sent to, as the API reports it. */
  to: string;
}

/** What `POST /settings/test-telegram` answers, chat by chat. */
export interface TestTelegramResult {
  /** How many chats accepted the test message. */
  sent: number;
  /** How many chats were attempted. */
  total: number;
  /** How many chats the bot could reach before sending. */
  validated: number;
  /** `total` minus `validated`: the chats that failed the reachability check. */
  validation_failed: number;
  results: TelegramChatValidationResult[];
}
