/**
 * Breach attribute helpers.
 *
 * A breach finding has two halves: the neutral fields every source can supply
 * (incident name, matched asset, date, affected count, exposed data classes)
 * and a source-declared `attributes` payload holding whatever the reporting
 * connector knows beyond that. The UI therefore never assumes a particular
 * vendor's field set — it reads declared attributes by key and renders any key
 * it has never seen with a humanized label.
 */

import { humanizeKey } from "@/lib/labels";
import type {
  Breach,
  BreachDomainVerification,
  BreachExposureKind,
  BreachFlagFilter,
  BreachProviderReadiness,
  BreachSeverity,
} from "@/types/api";

/**
 * The classes of exposure the module stores, in the order the filter offers them.
 *
 * This mirrors the allowlist the core validates a finding against
 * (`app/services/ingestion_service.py`): the API refuses a class outside it, so a
 * filter built from anything else could only ask a question with no answer.
 */
export const BREACH_EXPOSURE_KINDS: BreachExposureKind[] = ["breach", "paste", "stealer_log"];

const BREACH_EXPOSURE_KIND_LABELS: Record<BreachExposureKind, string> = {
  breach: "Breach of an account",
  paste: "Paste",
  stealer_log: "Stealer log",
};

/**
 * The class a row belongs to, defaulting to a breach of an account.
 *
 * A row stored before the column existed, or an API build that predates it, means
 * the module's original exposure class rather than an unknown one.
 */
export function breachExposureKind(breach: Breach): BreachExposureKind {
  const declared = breach.exposure_kind;
  return declared && declared in BREACH_EXPOSURE_KIND_LABELS ? declared : "breach";
}

export function breachExposureKindLabel(kind: string): string {
  return BREACH_EXPOSURE_KIND_LABELS[kind as BreachExposureKind] ?? humanizeKey(kind);
}

//
// Triage: how loud a row is (F-13)
//
// The severity is derived by the core from the classes of data exposed, and the
// page only names and colours it. The order is loudest-first because that is the
// order an analyst works through a morning's findings, and `unknown` sits last
// without being called harmless: it means the platform did not recognize the
// classes, which is a reason to look, not a reason to skip.

export const BREACH_SEVERITIES: BreachSeverity[] = ["critical", "high", "medium", "low", "unknown"];

const BREACH_SEVERITY_LABELS: Record<BreachSeverity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  unknown: "Unclassified",
};

const BREACH_SEVERITY_TONES: Record<BreachSeverity, string> = {
  critical: "bg-red-500/15 text-red-600 border-red-500/30",
  high: "bg-orange-500/15 text-orange-600 border-orange-500/30",
  medium: "bg-amber-500/15 text-amber-600 border-amber-500/30",
  low: "bg-sky-500/15 text-sky-600 border-sky-500/30",
  unknown: "bg-slate-500/15 text-slate-600 border-slate-500/30",
};

/** The severity a row carries; a row stored before the column existed is unclassified. */
export function breachSeverity(breach: Breach): BreachSeverity {
  const declared = breach.severity;
  return declared && declared in BREACH_SEVERITY_LABELS ? declared : "unknown";
}

export function breachSeverityLabel(severity: string): string {
  return BREACH_SEVERITY_LABELS[severity as BreachSeverity] ?? humanizeKey(severity);
}

export function breachSeverityTone(severity: string): string {
  return BREACH_SEVERITY_TONES[severity as BreachSeverity] ?? BREACH_SEVERITY_TONES.unknown;
}

/** The orderings the list offers, as the `sort`/`order` pair the API declares. */
export const BREACH_SORT_OPTIONS = [
  { value: "created_at:desc", sort: "created_at", order: "desc", label: "Newest finding first" },
  { value: "severity:desc", sort: "severity", order: "desc", label: "Loudest finding first" },
  { value: "pwn_count:desc", sort: "pwn_count", order: "desc", label: "Largest incident first" },
  { value: "breach_date:desc", sort: "breach_date", order: "desc", label: "Most recent incident first" },
  { value: "created_at:asc", sort: "created_at", order: "asc", label: "Oldest finding first" },
] as const;

/** The source flags the API filters by, and the words the page offers for them. */
export const BREACH_FLAG_FILTERS: Array<{ value: BreachFlagFilter; label: string }> = [
  { value: "verified", label: "Verified by source" },
  { value: "spam", label: "Spam list" },
  { value: "fabricated", label: "Reported as fabricated" },
  { value: "sensitive", label: "Marked sensitive" },
];

/** Flags rendered as badges in the breach table. */
export const BREACH_FLAG_KEYS = [
  "is_verified",
  "is_spam_list",
  "is_malware",
  "is_fabricated",
  "is_sensitive",
  "is_retired",
] as const;

const BREACH_ATTRIBUTE_LABELS: Record<string, string> = {
  is_verified: "Verified by source",
  is_fabricated: "Reported as fabricated",
  is_sensitive: "Marked sensitive",
  is_retired: "Retired from source catalog",
  is_spam_list: "Spam list",
  is_malware: "Malware-related",
  masked_password: "Exposed secret (masked)",
  added_date: "Added to source catalog",
  modified_date: "Updated in source catalog",
  logo_path: "Source logo reference",
};

export function breachAttributeLabel(key: string): string {
  return BREACH_ATTRIBUTE_LABELS[key] ?? humanizeKey(key);
}

/**
 * Read one attribute from a breach, tolerating the pre-generalization shape.
 *
 * During a rolling upgrade an older API build still returns these values as
 * top-level fields; preferring `attributes` but falling back keeps the page
 * correct on both sides of the rollout.
 */
export function breachAttribute(breach: Breach, key: string): unknown {
  const declared = breach.attributes;
  if (declared && Object.prototype.hasOwnProperty.call(declared, key)) {
    return declared[key];
  }
  return (breach as unknown as Record<string, unknown>)[key];
}

/** Attribute values are opaque, so interpret them the way a human reads them. */
export function breachFlag(breach: Breach, key: string): boolean {
  const value = breachAttribute(breach, key);
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    return normalized !== "" && normalized !== "false" && normalized !== "0" && normalized !== "no";
  }
  if (Array.isArray(value)) return value.length > 0;
  return Boolean(value);
}

export function formatBreachAttributeValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (Array.isArray(value)) return value.length ? value.map((v) => String(v)).join(", ") : "—";
  if (typeof value === "object") {
    const json = JSON.stringify(value);
    return json.length > 120 ? `${json.slice(0, 120)}…` : json;
  }
  return String(value);
}

//
// Provider readiness (F-04, WI-14)
//
// A breach list with nothing in it has two meanings — the source was asked and
// had nothing, or the source refused to be asked — and the page has to say which
// one it is looking at. The scan's own summary holds the difference, so the words
// below describe a refusal without naming a vendor.

/**
 * Why one domain was not searched, in the operator's words.
 *
 * The reason keys are the same ones the job summary carries, so a reader who
 * follows the scan into Jobs history finds the same word; the sentence beside it
 * says what to do about it, because "domain_not_verified" alone does not.
 */
const BREACH_READINESS_REASON_LABELS: Record<string, string> = {
  domain_not_verified: "the source has not verified this domain, so it refuses to search it",
  domain_outside_allowance: "the domain is verified but outside what the subscription allows",
  domain_access_denied: "access was refused and the source did not say which of the two it was",
  scan_stopped_short: "the scan spent its request budget before reaching this domain",
};

/** The three answers a scan can give about a domain, none of them "clean". */
export function breachReadinessStatusLabel(status: string): string {
  if (status === "asked") return "Asked";
  if (status === "unscanned") return "Not scanned";
  if (status === "unknown") return "Not reached";
  return humanizeKey(status);
}

export function breachReadinessReasonLabel(reason?: string | null): string | null {
  if (!reason) return null;
  return BREACH_READINESS_REASON_LABELS[reason] ?? humanizeKey(reason);
}

/**
 * The source's own name for a class of data, falling back to the stored name.
 *
 * A source that publishes no labels leaves the page showing exactly what it
 * showed before labels existed, rather than an English word this platform chose.
 */
export function breachDataClassLabel(key: string, labels?: Record<string, string> | null): string {
  const declared = labels?.[key];
  return typeof declared === "string" && declared.trim() ? declared : key;
}

/**
 * One sentence for the readiness card: was the source asked about the domains
 * this scan covered, or was it refused?
 */
export function breachReadinessVerdict(readiness: BreachProviderReadiness): string {
  const domains = readiness.domains ?? [];
  if (!readiness.scan_job_id) {
    return "No breach scan has finished yet, so a domain with no findings and a domain nobody was allowed to ask about look the same. Run a scan to find out which.";
  }
  const unscanned = readiness.unscanned_total || domains.filter((d) => d.status === "unscanned").length;
  const notReached = domains.filter((d) => d.status === "unknown").length;
  if (unscanned > 0) {
    return `${unscanned} of ${domains.length} domain${domains.length === 1 ? "" : "s"} could not be searched, so a short list here is not a clean result.`;
  }
  if (notReached > 0) {
    return `${notReached} domain${notReached === 1 ? "" : "s"} were never reached because the scan stopped early, so absence of findings says nothing about them.`;
  }
  if (!domains.length) {
    return "The last scan named no domains, so it says nothing about any of them.";
  }
  return `Every domain this scan covered (${domains.length}) was searched, so an empty list means the source had nothing about them.`;
}

//
// Domain verification (WI-20)
//
// A refused domain is only actionable if the page can say what to do next, so the
// words below are the four answers a verification attempt can give and the reasons
// a source states for refusing one. The status names the attempt; the sentence
// beside it says whether a person still has work to do.

const BREACH_VERIFICATION_STATUS_LABELS: Record<string, string> = {
  generated: "DNS record issued — publish it",
  verified: "Domain verified",
  not_verified: "Record not visible to the source yet",
  failed: "Attempt did not complete",
};

/**
 * The reason a source gave for refusing a verification, in the operator's words.
 *
 * The keys are the ones the worker reports, so following an attempt into Jobs
 * finds the same word. A reason this page has never seen is humanized rather than
 * hidden, because a new refusal is still a refusal.
 */
const BREACH_VERIFICATION_REASON_LABELS: Record<string, string> = {
  token_not_found: "the TXT record is not visible yet; DNS may still be propagating",
  no_credential: "this source has no credential configured, so nothing was asked",
  invalid_credentials: "the source rejected the configured credential",
  access_denied:
    "the source refused: either the account may not enrol domains or the domain belongs to somebody else",
  unknown_domain: "the source does not know this domain",
  rate_limited: "the source's rate limit was reached; try again later",
  not_answered: "the source did not answer",
  malformed_answer: "the source's answer could not be read",
  invalid_request: "the source does not accept that request",
  provider_refused: "the source refused without saying why",
};

export function breachVerificationStatusLabel(status: string): string {
  return BREACH_VERIFICATION_STATUS_LABELS[status] ?? humanizeKey(status);
}

export function breachVerificationReasonLabel(reason?: string | null): string | null {
  if (!reason) return null;
  return BREACH_VERIFICATION_REASON_LABELS[reason] ?? humanizeKey(reason);
}

/** Whether a person still has to publish (or wait for) a record for this attempt. */
export function breachVerificationAwaitingRecord(verification: BreachDomainVerification): boolean {
  return verification.status === "generated" || verification.status === "not_verified";
}

/**
 * The newest attempt for one domain, or nothing.
 *
 * Read beside the scan's own verdict rather than merged into it: a domain the last
 * scan could not ask about may have been verified since, and an attempt that failed
 * says nothing about whether the domain is monitored.
 */
export function breachVerificationFor(
  readiness: BreachProviderReadiness | undefined,
  domain: string,
): BreachDomainVerification | undefined {
  return (readiness?.verifications ?? []).find((attempt) => attempt.domain === domain);
}

/**
 * Attributes an operator should see in the detail view, excluding the flags
 * that already have their own column and empty values.
 */
export function breachExtraAttributes(breach: Breach): Array<{ key: string; label: string; value: string }> {
  const flags = new Set<string>(BREACH_FLAG_KEYS);
  const declared = breach.attributes && typeof breach.attributes === "object" ? breach.attributes : {};
  return Object.keys(declared)
    .filter((key) => !flags.has(key))
    .filter((key) => {
      const value = declared[key];
      if (value === null || value === undefined) return false;
      if (Array.isArray(value)) return value.length > 0;
      if (typeof value === "boolean") return value;
      return String(value).length > 0;
    })
    .sort()
    .map((key) => ({
      key,
      label: breachAttributeLabel(key),
      value: formatBreachAttributeValue(declared[key]),
    }));
}
