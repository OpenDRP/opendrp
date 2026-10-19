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
  phishing: [
    "phishing.dnstwist",
    "phishing.shodan",
    // Same reason the DNS list names its keyed workers: with the registry
    // unreachable the Netlas job type is absent from the table an operator is
    // most likely to be reading (F-14).
    "phishing.netlas",
  ],
  breaches: ["breaches.hibp"],
  reports: ["report.generate"],
  dns: [
    "dns.rdap",
    "dns.resolver",
    "dns.ctlogs",
    "dns.virustotal",
    // The Netlas job was missing from this list, so with the connector registry
    // unreachable its jobs vanished from the table entirely (F-14).
    "dns.netlas",
    "dns.tlsprobe",
    "dns.shodan",
  ],
} as const;

const JOB_TYPE_LABELS: Record<string, string> = {
  "phishing.dnstwist": "Phishing scan",
  "phishing.shodan": "Phishing scan",
  "phishing.netlas": "Phishing scan",
  "breaches.hibp": "Breach scan (all sources)",
  "dns.rdap": "DNS registration lookup",
  "dns.resolver": "DNS record lookup",
  "dns.ctlogs": "Certificate Transparency lookup",
  "dns.virustotal": "Passive DNS lookup",
  "dns.netlas": "Passive DNS lookup",
  "dns.tlsprobe": "TLS certificate probe",
  // Named for what the job asks, not for the provider that answers it: this
  // worker confirms what our own addresses serve and searches where else a
  // certificate of ours is indexed.
  "dns.shodan": "Certificate exposure search",
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

/**
 * The signals a candidate's confidence is made of (WI-08/WI-11).
 *
 * These are the labels the API's `?signal=` vocabulary is described with, and the
 * order is the weight table's — so the picker lists them the way the score adds
 * them up, and a signal a later wave adds (wave 2-4) is humanized from its own name
 * rather than disappearing from the list.
 */
export const SIGNAL_LABELS: Record<string, string> = {
  young_domain: "Young registration",
  mx_without_spf: "Mail-capable, no SPF",
  title_match: "Page title carries the brand",
  favicon_perceptual_match: "Favicon matches ours",
  html_similarity: "Page body resembles ours",
  brand_in_body: "Brand in the page body",
  source_corroboration: "Two or more sources",
  parked_hint: "Looks parked",
  aged_domain: "Aged registration",
  tls_issuer_reuse: "Our certificate issuer",
};

/** The declared signal names, in the order the score weighs them. */
export const SIGNAL_NAMES: string[] = Object.keys(SIGNAL_LABELS);

export function signalLabel(name: string): string {
  return SIGNAL_LABELS[name] ?? humanize(name);
}

/**
 * What the alert budget does with a scored candidate.
 *
 * The thresholds behind these bands belong to the deployment, so the *band* is what
 * the server sends and this only names it: a page that printed "60+" would be
 * telling an operator about a threshold their installation may have raised.
 */
const ALERT_BAND_LABELS: Record<string, string> = {
  direct: "Alerts now",
  digest: "Daily digest",
  list: "List only",
};

export function alertBandLabel(band: string): string {
  return ALERT_BAND_LABELS[band] ?? humanize(band);
}

/**
 * What an analyst decided about a candidate (WI-12).
 *
 * The words are the decision, not the effect: "Confirmed" and "Rejected" are what the
 * analyst did, while *what the channel does about it* is a separate fact the page
 * states where it matters — a badge that read "Alerts now" beside "Confirmed" would
 * be saying one thing twice.
 */
const VERDICT_LABELS: Record<string, string> = {
  confirmed: "Confirmed",
  rejected: "Rejected",
  // The provider's own verdict on a row it produced: the name is a candidate nobody
  // has verified yet, which is a different claim from an analyst's decision and has to
  // read as one.
  candidate_not_verified: "Not verified yet",
};

export function verdictLabel(verdict: string): string {
  return VERDICT_LABELS[verdict] ?? humanize(verdict);
}

/**
 * Which question produced an evidence row (W2.5).
 *
 * An evidence list holds two kinds of row: one that *found* a name (a certificate
 * claiming the brand, a page title carrying it) and one that describes a name the
 * platform already had (a registration record, a mail lookup on a confirmed
 * candidate). Both used to render as a source and a timestamp, which read as the
 * same statement. Naming the question is what tells an operator which one they are
 * looking at - and a capability a later connector adds is humanized from its own
 * name rather than disappearing from the list.
 */
const EVIDENCE_CAPABILITY_LABELS: Record<string, string> = {
  certificate: "Certificate names this domain",
  certificate_brand: "Certificate claims the brand",
  title: "Page title carries it",
  body: "Page body carries it",
  hostname: "Endpoint serves this name",
  favicon: "Favicon is ours, byte for byte",
  favicon_similar: "Favicon resembles ours",
  whois: "Registration record",
  mx: "Mail records",
  passive_dns: "Passive DNS",
  lookup: "Endpoint lookup",
};

export function evidenceCapabilityLabel(capability: string): string {
  return EVIDENCE_CAPABILITY_LABELS[capability] ?? humanize(capability);
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
