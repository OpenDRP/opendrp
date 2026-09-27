/**
 * Single source of truth for operator-facing labels.
 *
 * Two rules:
 *
 * 1. Provider names never appear in generic wording. A breach finding may come
 *    from any registered breach connector and a phishing finding from any
 *    registered phishing connector, so labels describe the *kind of work*
 *    ("Phishing scan", "Breach email lookup"), not the vendor that performs it.
 *    The concrete connector name is shown where it is real data (the connector
 *    registry, the job title, the detection-source badge).
 * 2. Unknown values degrade gracefully. Any job type, detection source or
 *    summary key a future connector introduces is humanized from the raw string
 *    instead of rendering as `new_vendor.scan` or disappearing from the UI.
 */

import type { AssetType, DetectionSource, JobStatus, ThreatStatus } from "@/types/api";

/** Raw values are humanized as a fallback: `new_vendor.scan` → `New vendor scan`. */
function humanize(raw: string): string {
  const spaced = raw.replace(/[._]+/g, " ").replace(/\s+/g, " ").trim();
  if (!spaced) return raw;
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

/**
 * Humanize an arbitrary identifier for display (`scan_ssl_text` → `Scan ssl
 * text`). Used for settings a newly registered connector declares without
 * supplying a label of its own.
 */
export function humanizeKey(raw: string): string {
  return humanize(raw);
}

// ---------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------

/**
 * Built-in job types per module page.
 *
 * These are a *fallback*, not the source of truth: each module page asks the
 * connector registry for the job types its connectors declare (see
 * `useModuleJobTypes`), so a connector added later shows up on its own. The
 * defaults keep job history populated while that request is in flight or if the
 * registry is unreachable, and cover the core-owned report module.
 */
export const FALLBACK_MODULE_JOB_TYPES = {
  phishing: ["phishing.dnstwist", "phishing.shodan"],
  breaches: ["breaches.hibp"],
  reports: ["report.generate"],
} as const;

const JOB_TYPE_LABELS: Record<string, string> = {
  "phishing.dnstwist": "Phishing scan",
  "phishing.shodan": "Phishing scan",
  "breaches.hibp": "Breach scan (all sources)",
  "report.generate": "Report generation",
  system: "System task",
};

export function jobTypeLabel(jobType: string): string {
  return JOB_TYPE_LABELS[jobType] ?? humanize(jobType);
}

const JOB_STATUS_LABELS: Record<JobStatus | string, string> = {
  pending: "Pending",
  running: "Running",
  success: "Success",
  error: "Error",
  cancelled: "Cancelled",
  skipped: "Skipped",
  partial: "Partial",
};

export function jobStatusLabel(status: string): string {
  return JOB_STATUS_LABELS[status] ?? humanize(status);
}

/**
 * Human-readable labels and units for connector-provided summary keys.
 *
 * Connector summaries are free-form (`{"emails_scanned": 15, "duration_sec": 28.7}`),
 * so the UI maps the keys it knows and humanizes the rest, appending the unit
 * implied by the suffix.
 */
const SUMMARY_LABELS: Record<string, string> = {
  task: "Task",
  emails_scanned: "Email assets scanned",
  domains_scanned: "Domains scanned",
  domain_aliases_found: "Domain aliases found",
  domains_expanded: "Domains expanded",
  new_breach_rows: "New breach matches",
  new_threat_rows: "New phishing findings",
  new_rows: "New findings",
  new_discovered: "New discovered",
  capabilities_run: "Capabilities run",
  capability_results: "Capability results",
  candidates: "Candidates",
  resolved: "Resolved",
  kw_domains: "Keyword domains",
  kw_titles: "Keyword titles",
  domains_with_errors: "Domains with errors",
  provider_errors: "Provider errors",
  matches: "Matches",
  assets_checked: "Assets checked",
  jobs_queued: "Jobs queued",
  report_id: "Report ID",
  status: "Status",
};

function unitSuffix(key: string): string {
  if (key.endsWith("_sec")) return " s";
  if (key.endsWith("_ms")) return " ms";
  if (key.endsWith("_pct")) return " %";
  if (key.endsWith("_bytes")) return " bytes";
  return "";
}

function summaryLabel(key: string): string {
  if (SUMMARY_LABELS[key]) return SUMMARY_LABELS[key];
  const withoutUnit = key.replace(/_(sec|ms|pct|bytes)$/, "");
  return humanize(withoutUnit);
}

/**
 * Render a connector's grouped counters as text: `{ssl: {matches: 21,
 * stored: 10}}` becomes `ssl (matches=21, stored=10)`.
 *
 * A connector that reports one outcome per thing it handled (each capability,
 * each target) would otherwise reach the operator as raw JSON cut off mid-key,
 * which is exactly what these counts exist to prevent. Entries with no value
 * are dropped rather than shown as an empty dash: a null there means "not
 * applicable" (`{"skipped": null}` = this step was not skipped).
 */
function summaryGroup(value: object): string {
  const text = Object.entries(value as Record<string, unknown>)
    .filter(([, inner]) => inner !== null && inner !== undefined)
    .map(([key, inner]) =>
      inner !== null && typeof inner === "object" && !Array.isArray(inner)
        ? `${key} (${summaryGroup(inner)})`
        : `${key}=${summaryValue(inner)}`,
    )
    .join(", ");
  return text.length > 160 ? `${text.slice(0, 160)}…` : text;
}

function summaryValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (Array.isArray(value)) return value.length ? String(value.length) : "none";
  if (typeof value === "object") return summaryGroup(value);
  return String(value);
}

/** `{"emails_scanned": 15, "duration_sec": 28.7}` → `Email assets scanned: 15 · Duration: 28.7 s`. */
export function humanizeSummary(summary: unknown): string {
  if (summary === null || summary === undefined) return "";
  if (Array.isArray(summary)) return summary.length ? JSON.stringify(summary).slice(0, 120) : "";
  if (typeof summary !== "object") return String(summary).slice(0, 120);

  return Object.entries(summary as Record<string, unknown>)
    .map(([key, value]) => `${summaryLabel(key)}: ${summaryValue(value)}${unitSuffix(key)}`)
    .join(" · ");
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

const DETECTION_SOURCE_LABELS: Record<string, string> = {
  dnstwist: "Domain look-alike",
  shodan_ssl: "Certificate text",
  shodan_title: "Page title",
  shodan_favicon: "Favicon hash",
};

export function detectionSourceLabel(source: DetectionSource | string): string {
  return DETECTION_SOURCE_LABELS[source] ?? humanize(source);
}

const THREAT_STATUS_LABELS: Record<ThreatStatus | string, string> = {
  active: "Active",
  investigating: "Investigating",
  resolved: "Resolved",
};

export function threatStatusLabel(status: string): string {
  return THREAT_STATUS_LABELS[status] ?? humanize(status);
}

// ---------------------------------------------------------------------------
// Assets
// ---------------------------------------------------------------------------

const ASSET_TYPE_LABELS: Record<AssetType | string, string> = {
  domain: "Domain",
  ip_address: "IP address",
  email_account: "Email account",
  keyword_domain: "Keyword (domain)",
  keyword_title: "Keyword (page title)",
};

export function assetTypeLabel(assetType: string): string {
  return ASSET_TYPE_LABELS[assetType] ?? humanize(assetType);
}
