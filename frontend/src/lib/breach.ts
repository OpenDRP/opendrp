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
import type { Breach } from "@/types/api";

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
