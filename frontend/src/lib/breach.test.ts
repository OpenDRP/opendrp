import { describe, expect, it } from "vitest";
import {
  BREACH_EXPOSURE_KINDS,
  BREACH_SEVERITIES,
  breachDataClassLabel,
  breachExposureKind,
  breachExposureKindLabel,
  breachReadinessReasonLabel,
  breachSeverity,
  breachSeverityLabel,
  breachSeverityTone,
  breachReadinessStatusLabel,
  breachReadinessVerdict,
  breachVerificationAwaitingRecord,
  breachVerificationFor,
  breachVerificationReasonLabel,
  breachVerificationStatusLabel,
} from "@/lib/breach";
import type { Breach, BreachDomainVerification, BreachProviderReadiness } from "@/types/api";

function readiness(overrides: Partial<BreachProviderReadiness> = {}): BreachProviderReadiness {
  return {
    scan_job_id: "job-1",
    scanned_at: "2026-01-01T00:00:00Z",
    status: "success",
    partial: false,
    reasons: {},
    entitlements: null,
    pacing: {},
    domains: [],
    unscanned_total: 0,
    data_class_labels: {},
    ...overrides,
  };
}

describe("breach readiness labels", () => {
  it("keeps the three answers about a domain apart", () => {
    // "asked" is the only one of them that means "nothing was found".
    expect(breachReadinessStatusLabel("asked")).toBe("Asked");
    expect(breachReadinessStatusLabel("unscanned")).toBe("Not scanned");
    expect(breachReadinessStatusLabel("unknown")).toBe("Not reached");
  });

  it("explains a refusal reason and humanizes one it has never seen", () => {
    expect(breachReadinessReasonLabel("domain_not_verified")).toContain("has not verified");
    expect(breachReadinessReasonLabel("domain_outside_allowance")).toContain("subscription");
    expect(breachReadinessReasonLabel("something_new")).toBe("Something new");
    expect(breachReadinessReasonLabel(null)).toBeNull();
  });

  it("uses the source's own name for a data class, and the stored name when the source has none", () => {
    expect(breachDataClassLabel("Passwords", { Passwords: "Account passwords" })).toBe("Account passwords");
    expect(breachDataClassLabel("Passwords", {})).toBe("Passwords");
    expect(breachDataClassLabel("Passwords", null)).toBe("Passwords");
    expect(breachDataClassLabel("Passwords", { Passwords: "   " })).toBe("Passwords");
  });
});

describe("breach exposure classes", () => {
  const breach = (exposure_kind?: unknown) => ({ exposure_kind } as unknown as Breach);

  it("names the class of exposure the module stores", () => {
    expect(BREACH_EXPOSURE_KINDS).toEqual(["breach", "paste", "stealer_log"]);
    expect(breachExposureKindLabel("breach")).toBe("Breach of an account");
    expect(breachExposureKindLabel("paste")).toBe("Paste");
    expect(breachExposureKindLabel("stealer_log")).toBe("Stealer log");
    // A class this build has never heard of is humanized rather than hidden.
    expect(breachExposureKindLabel("paste_dump")).toBe("Paste dump");
  });

  it("reads a row stored before the column existed as a breach of an account", () => {
    expect(breachExposureKind(breach("paste"))).toBe("paste");
    expect(breachExposureKind(breach(undefined))).toBe("breach");
    expect(breachExposureKind(breach("something_else"))).toBe("breach");
  });
});

describe("breach severity", () => {
  it("names every severity the core derives, loudest first", () => {
    expect(BREACH_SEVERITIES).toEqual(["critical", "high", "medium", "low", "unknown"]);
    expect(breachSeverityLabel("critical")).toBe("Critical");
    expect(breachSeverityLabel("high")).toBe("High");
    // "Unknown" is the platform's admission that it does not recognize the data
    // classes, so the page never calls such a row harmless.
    expect(breachSeverityLabel("unknown")).toBe("Unclassified");
  });

  it("gives each level its own tone and falls back for one it has never seen", () => {
    const tones = BREACH_SEVERITIES.map((level) => breachSeverityTone(level));
    expect(new Set(tones).size).toBe(BREACH_SEVERITIES.length);
    expect(breachSeverityTone("catastrophic")).toBe(breachSeverityTone("unknown"));
  });

  it("reads a row stored before the column existed as unclassified", () => {
    expect(breachSeverity({ severity: "high" } as unknown as Breach)).toBe("high");
    expect(breachSeverity({} as unknown as Breach)).toBe("unknown");
    expect(breachSeverity({ severity: "catastrophic" } as unknown as Breach)).toBe("unknown");
  });
});

describe("breach readiness verdict", () => {
  it("says nothing has been asked when no scan has finished", () => {
    const text = breachReadinessVerdict(readiness({ scan_job_id: null, domains: [] }));
    expect(text).toContain("No breach scan has finished yet");
  });

  it("names a domain the provider refused instead of reporting a clean list", () => {
    const text = breachReadinessVerdict(
      readiness({
        partial: true,
        domains: [
          { domain: "acme.test", status: "unscanned", reason: "domain_not_verified" },
          { domain: "other.test", status: "asked" },
        ],
        unscanned_total: 1,
      }),
    );
    expect(text).toContain("1 of 2 domains could not be searched");
    expect(text).toContain("not a clean result");
  });

  it("does not claim a domain the scan never reached was searched", () => {
    const text = breachReadinessVerdict(
      readiness({ domains: [{ domain: "acme.test", status: "unknown", reason: "scan_stopped_short" }] }),
    );
    expect(text).toContain("never reached");
  });

  it("says the question was answered when every domain was searched", () => {
    const text = breachReadinessVerdict(
      readiness({ domains: [{ domain: "acme.test", status: "asked" }] }),
    );
    expect(text).toContain("Every domain this scan covered (1) was searched");
  });
});

function attempt(overrides: Partial<BreachDomainVerification> = {}): BreachDomainVerification {
  return {
    domain: "acme.test",
    action: "generate",
    status: "generated",
    reason: null,
    txt_record_value: "opendrp-verify=abc",
    job_id: "job-2",
    requested_at: "2026-01-02T00:00:00Z",
    ...overrides,
  };
}

describe("breach domain verification", () => {
  it("says whether a person still has work to do", () => {
    // A generated record and one the source cannot see yet both wait on a person;
    // a verified domain does not.
    expect(breachVerificationAwaitingRecord(attempt())).toBe(true);
    expect(breachVerificationAwaitingRecord(attempt({ status: "not_verified" }))).toBe(true);
    expect(breachVerificationAwaitingRecord(attempt({ status: "verified" }))).toBe(false);
    expect(breachVerificationAwaitingRecord(attempt({ status: "failed" }))).toBe(false);
  });

  it("reads an attempt beside the domain it belongs to", () => {
    const body = readiness({
      verifications: [attempt(), attempt({ domain: "beta.test", status: "verified" })],
    });
    expect(breachVerificationFor(body, "beta.test")?.status).toBe("verified");
    expect(breachVerificationFor(body, "gamma.test")).toBeUndefined();
    expect(breachVerificationFor(undefined, "acme.test")).toBeUndefined();
  });

  it("names the attempt and explains a reason it was refused", () => {
    expect(breachVerificationStatusLabel("generated")).toContain("publish");
    expect(breachVerificationStatusLabel("verified")).toBe("Domain verified");
    expect(breachVerificationReasonLabel("token_not_found")).toContain("propagating");
    expect(breachVerificationReasonLabel("no_credential")).toContain("no credential");
    expect(breachVerificationReasonLabel(null)).toBeNull();
    // A reason this build has never seen is still a reason.
    expect(breachVerificationReasonLabel("something_new")).toBe("Something new");
  });
});
