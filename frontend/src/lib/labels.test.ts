import { describe, expect, it } from "vitest";
import {
  FALLBACK_MODULE_JOB_TYPES,
  assetTypeLabel,
  detectionSourceLabel,
  humanizeKey,
  humanizeSummary,
  jobStatusLabel,
  jobTypeLabel,
  threatStatusLabel,
} from "@/lib/labels";

describe("job labels", () => {
  it("keeps phishing labels source-agnostic", () => {
    expect(jobTypeLabel("phishing.dnstwist")).toBe("Phishing scan");
    expect(jobTypeLabel("phishing.shodan")).toBe("Phishing scan");
  });

  it("labels breach scans without naming a provider in generic wording", () => {
    expect(jobTypeLabel("breaches.hibp")).toBe("Breach scan (all sources)");
  });

  it("humanizes a job type from a connector the UI has never seen", () => {
    expect(jobTypeLabel("new_vendor.scan_domains")).toBe("New vendor scan domains");
  });

  it("keeps a built-in fallback per module for when the registry is unknown", () => {
    // The registry is the source of truth; this table only covers the window
    // before it answers, so job history is never silently empty.
    expect(FALLBACK_MODULE_JOB_TYPES.phishing).toContain("phishing.dnstwist");
    expect(FALLBACK_MODULE_JOB_TYPES.breaches).toContain("breaches.hibp");
    expect(FALLBACK_MODULE_JOB_TYPES.reports).toEqual(["report.generate"]);
  });

  it("humanizes a setting key a connector declared without a label", () => {
    expect(humanizeKey("scan_ssl_text")).toBe("Scan ssl text");
  });

  it("humanizes statuses", () => {
    expect(jobStatusLabel("success")).toBe("Success");
    expect(threatStatusLabel("investigating")).toBe("Investigating");
    expect(threatStatusLabel("escalated")).toBe("Escalated");
  });
});

describe("humanizeSummary", () => {
  it("turns raw connector keys into labelled values with units", () => {
    const text = humanizeSummary({ emails_scanned: 15, duration_sec: 28.7 });
    expect(text).toBe("Email assets scanned: 15 · Duration: 28.7 s");
  });

  it("humanizes unknown keys instead of dropping them", () => {
    expect(humanizeSummary({ widgets_found: 3 })).toBe("Widgets found: 3");
  });

  it("handles booleans, arrays, objects and empty input", () => {
    expect(humanizeSummary({ ok: true })).toBe("Ok: Yes");
    expect(humanizeSummary({ items: ["a", "b"] })).toBe("Items: 2");
    expect(humanizeSummary({ nested: { a: 1 } })).toContain("Nested:");
    expect(humanizeSummary(null)).toBe("");
    expect(humanizeSummary({})).toBe("");
    expect(humanizeSummary("plain")).toBe("plain");
  });

  it("renders per-thing counters as text instead of truncated JSON", () => {
    // What a connector reports when it ran one capability per group: the
    // operator has to be able to read "matched 1, stored 0" straight from the
    // job history, without opening the database.
    const text = humanizeSummary({
      capability_results: {
        ssl: { queries: 2, matches: 4, candidates: 4, stored: 0, skipped: null },
      },
    });
    expect(text).toBe("Capability results: ssl (queries=2, matches=4, candidates=4, stored=0)");
  });

  it("labels the dnstwist counters that explain a quiet scan", () => {
    expect(humanizeSummary({ candidates: 12, resolved: 3, new_discovered: 0 })).toBe(
      "Candidates: 12 · Resolved: 3 · New discovered: 0",
    );
  });
});

describe("typed value labels", () => {
  it("labels assets and detection sources, with a humanized fallback", () => {
    expect(assetTypeLabel("ip_address")).toBe("IP address");
    expect(assetTypeLabel("email_account")).toBe("Email account");
    expect(assetTypeLabel("social_profile")).toBe("Social profile");
    expect(detectionSourceLabel("shodan_favicon")).toBe("Favicon hash");
    expect(detectionSourceLabel("brand_watcher")).toBe("Brand watcher");
  });
});
