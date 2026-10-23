import { describe, expect, it } from "vitest";

import type {
  Asset,
  Breach,
  BreachList,
  Job,
  Paginated,
  PhishingThreat,
  Report,
  SystemSettings,
  User,
} from "@/types/api";

/**
 * The response shapes this client declares, written the way the API serializes
 * them.
 *
 * The value of this file is the annotation, not the assertions: these fixtures are
 * checked by `tsc -b` (which `npm run build` and CI both run), so a field the API
 * can send as `null` but the interface calls "absent or a string" fails the build.
 * That is how the nullability drift found in the S23 audit is now caught: every
 * property below is one the API emitted as `null` while the interface said
 * `undefined`, so a page could reach `.trim()`, `.length` or `Date.parse()` on a
 * value the compiler promised would not be there.
 *
 * Each interface lists the fields the API *always* includes, because the response
 * model serializes the column whether or not it holds a value. A key that is
 * genuinely omitted is written `?` and no further.
 */

const user: User = {
  id: "b3d1c0de-0000-4000-8000-000000000001",
  email: "analyst@example.com",
  // A new account created without a name: the column is null, the key is present.
  full_name: null,
  role: "analyst",
  is_active: true,
  rate_limit_minutes: 0,
  created_at: "2026-10-22T00:00:00Z",
  updated_at: "2026-10-22T00:00:00Z",
  must_change_password: false,
  must_enrol_mfa: false,
  mfa_required_by_policy: false,
  totp_enabled_at: null,
  last_login_at: null,
  invitation_expires_at: null,
  locked_until: null,
  failed_login_attempts: 0,
};

const asset: Asset = {
  id: "b3d1c0de-0000-4000-8000-000000000002",
  asset_type: "email_account",
  asset_value: "ceo@example.com",
  // Already normalized: the API stores null rather than repeating the value.
  normalized_value: null,
  criticality: "medium",
  is_active: true,
  created_at: "2026-10-22T00:00:00Z",
  updated_at: "2026-10-22T00:00:00Z",
  findings: null,
};

/** A job that has not been claimed yet: four columns are still null. */
const job: Job = {
  id: "b3d1c0de-0000-4000-8000-000000000003",
  job_type: "dns_security.scan",
  status: "pending",
  created_by: null,
  created_by_email: null,
  task_id: null,
  title: null,
  error_message: null,
  params: { asset_ids: [] },
  result_summary: null,
  created_at: "2026-10-22T00:00:00Z",
  started_at: null,
  finished_at: null,
};

/** A breach row whose source supplied no description and that matched no address. */
const breach: Breach = {
  id: "b3d1c0de-0000-4000-8000-000000000004",
  source_id: "hibp",
  breach_name: "ExampleBreach",
  title: "Example Breach",
  domain: "example.com",
  breach_date: "2020-01-01",
  pwn_count: 1,
  description: null,
  data_classes: ["Email addresses"],
  matched_email: null,
  matched_domain: null,
  matched_asset: null,
  matched_asset_type: null,
  status: "active",
  exposure_kind: "breach",
  severity: "unknown",
  email_incident_count: null,
  attributes: {},
  created_at: "2026-10-22T00:00:00Z",
  last_seen_at: null,
  verified_at: null,
  metadata_incomplete: true,
};

const breachPage: BreachList = {
  items: [breach],
  total: 1,
  page: 1,
  size: 25,
  pages: 1,
  unannounced: 0,
  new_since: null,
};

/** A candidate nothing has answered about yet. */
const threat: PhishingThreat = {
  id: "b3d1c0de-0000-4000-8000-000000000005",
  phishing_domain: "examp1e.com",
  matched_asset: "example.com",
  ip_address: null,
  web_ports: null,
  detection_source: "dnstwist",
  original_domain: null,
  whois_registrar: null,
  whois_abuse_email: null,
  domain_created_at: null,
  domain_age_days: null,
  confidence: 0,
  signals: {},
  alert_band: "list",
  verdict: null,
  verdict_reason: null,
  verdict_by: null,
  verdict_at: null,
  sources: [],
  source_count: 0,
  status: "active",
  created_at: "2026-10-22T00:00:00Z",
  updated_at: "2026-10-22T00:00:00Z",
};

const report: Report = {
  id: "b3d1c0de-0000-4000-8000-000000000006",
  report_name: "Weekly",
  created_by: null,
  created_by_email: null,
  file_path: "reports/weekly.pdf",
  file_available: null,
  is_truncated: false,
  truncation_metadata: null,
  status: "completed",
  created_at: "2026-10-22T00:00:00Z",
};

/**
 * The breach half of the alert budget. Both fields were missing from this
 * interface while the API had been sending them since the alert-budget work
 * landed: the settings page reads the response through an untyped helper, so
 * nothing failed and the type simply described a response that no longer existed.
 */
const settings: SystemSettings = {
  id: "b3d1c0de-0000-4000-8000-000000000007",
  version: 3,
  smtp_security_mode: "starttls",
  email_alerts_enabled: false,
  telegram_alerts_enabled: false,
  alert_email_user_ids: null,
  telegram_chat_ids: null,
  alert_breach_noise_policy: "default",
  alert_breach_digest_threshold: null,
  schedules: null,
  created_at: "2026-10-22T00:00:00Z",
  updated_at: "2026-10-22T00:00:00Z",
};

describe("the typed client's response contract", () => {
  it("keeps the pagination envelope exactly the five keys every list route sends", () => {
    // `PaginatedResponse` in the backend declares these five and nothing else, and
    // every list route uses it (`AssetListResponse`, `BreachListResponse`, the
    // `PaginatedResponse[...]` models). A key added on one side alone is drift.
    const page: Paginated<User> = { items: [user], total: 1, page: 1, size: 25, pages: 1 };
    expect(Object.keys(page).sort()).toEqual(["items", "page", "pages", "size", "total"]);
    expect(Object.keys(breachPage).sort()).toEqual(
      ["items", "new_since", "page", "pages", "size", "total", "unannounced"],
    );
  });

  it("survives a JSON round trip with its nulls intact", () => {
    // The wire cannot carry `undefined`: a key the API sends as null is what the
    // page receives, and re-reading it through JSON is how this test refuses to
    // let an interface describe `undefined` for a field that is serialized.
    const wire = JSON.parse(JSON.stringify({ user, asset, job, breach, threat, report, settings }));
    expect(wire.user.full_name).toBeNull();
    expect(wire.asset.normalized_value).toBeNull();
    expect(wire.job.started_at).toBeNull();
    expect(wire.breach.description).toBeNull();
    expect(wire.threat.ip_address).toBeNull();
    expect(wire.report.created_by).toBeNull();
    expect(wire.settings.alert_breach_digest_threshold).toBeNull();
  });
});
