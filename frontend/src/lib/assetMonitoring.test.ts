import { describe, expect, it } from "vitest";
import {
  coverageByAssetType,
  coverageDescription,
  coverageForType,
  involvementBreakdown,
  lastSeenAt,
} from "@/lib/assetMonitoring";
import type { ConnectorModulesResponse } from "@/types/api";

const registry = {
  modules: {
    phishing: {
      label: "Phishing",
      enabled: true,
      asset_types: ["domain"],
      connectors: [
        { name: "dnstwist", status: "enabled", asset_types: ["domain"] },
        { name: "retired-scanner", status: "disabled", asset_types: ["domain"] },
      ],
    },
    breaches: {
      label: "Breaches",
      enabled: true,
      asset_types: ["domain", "email_account"],
      connectors: [],
    },
    "some-module": {
      // No label: the registry id is the honest name.
      enabled: true,
      asset_types: ["domain"],
      connectors: [],
    },
    disabled: {
      label: "Disabled",
      enabled: false,
      asset_types: ["ip_address"],
      connectors: [],
    },
  },
} as unknown as ConnectorModulesResponse;

describe("coverageByAssetType", () => {
  it("says which enabled modules and connectors consume each type", () => {
    const coverage = coverageByAssetType(registry);
    expect(coverage.domain.modules.sort()).toEqual(["Breaches", "Phishing", "some-module"]);
    // A disabled connector is not monitoring, so it is not coverage.
    expect(coverage.domain.connectors).toEqual(["dnstwist"]);
    expect(coverage.email_account.modules).toEqual(["Breaches"]);
  });

  it("leaves out a disabled module entirely", () => {
    // Counting it would show scanning that is not happening — the opposite of
    // what the operator opened this view for (WI-20).
    expect(coverageByAssetType(registry).ip_address).toBeUndefined();
  });

  it("has no coverage for a type the registry never mentions, and no data at all", () => {
    expect(coverageByAssetType(registry).keyword_title).toBeUndefined();
    expect(coverageByAssetType(undefined).domain).toBeUndefined();
    expect(coverageForType(coverageByAssetType(undefined), "domain")).toEqual({
      modules: [],
      connectors: [],
    });
  });
});

describe("coverageDescription", () => {
  it("names modules and connectors", () => {
    expect(
      coverageDescription({ modules: ["Phishing"], connectors: ["dnstwist"] }),
    ).toBe("Monitored by modules Phishing; connectors dnstwist.");
  });

  it("says a type nothing enabled consumes is recorded but not scanned", () => {
    expect(coverageDescription({ modules: [], connectors: [] })).toMatch(
      /No enabled module consumes this type of asset/,
    );
  });
});

describe("lastSeenAt", () => {
  it("returns the latest moment across modules", () => {
    // A disclosure date and a scan timestamp are both ISO text, so the later
    // one wins without comparing two different kinds of value.
    expect(
      lastSeenAt({
        total: 2,
        phishing: 1,
        breaches: 1,
        dns: 0,
        exposure: 0,
        findings: 0,
        last_seen: { phishing: "2026-01-02T00:00:00+00:00", breaches: "2024-01-01" },
      }),
    ).toBe("2026-01-02T00:00:00+00:00");
  });

  it("compares instants, not text, when a date meets a timestamp", () => {
    // `2026-10-15` as a date is midnight UTC. The timestamp below is 22:00 UTC
    // on the 14th, so the date is the later observation — while text comparison
    // picks the timestamp because `T` sorts after the end of the string. The
    // helper must answer with the moment, not with the alphabetically longer
    // value.
    expect(
      lastSeenAt({
        total: 2, phishing: 1, breaches: 1, dns: 0, exposure: 0, findings: 0,
        last_seen: {
          breaches: "2026-10-15",
          phishing: "2026-10-15T00:00:00+02:00",
        },
      }),
    ).toBe("2026-10-15");
    expect(
      lastSeenAt({
        total: 2, phishing: 1, breaches: 1, dns: 0, exposure: 0, findings: 0,
        last_seen: {
          breaches: "2026-10-15",
          phishing: "2026-10-15T12:00:00+00:00",
        },
      }),
    ).toBe("2026-10-15T12:00:00+00:00");
  });

  it("ignores a value the browser cannot parse rather than letting it win", () => {
    expect(
      lastSeenAt({
        total: 2, phishing: 1, breaches: 1, dns: 0, exposure: 0, findings: 0,
        last_seen: { breaches: "not-a-date", phishing: "2026-01-02T00:00:00+00:00" },
      }),
    ).toBe("2026-01-02T00:00:00+00:00");
    expect(
      lastSeenAt({
        total: 1, phishing: 0, breaches: 0, dns: 1, exposure: 0, findings: 0,
        last_seen: { dns: "2026-13-45T99:99:99Z" },
      }),
    ).toBeNull();
  });

  it("is null when nothing ever matched, or there is no summary", () => {
    const empty = {
      total: 0,
      phishing: 0,
      breaches: 0,
      dns: 0,
      exposure: 0,
      findings: 0,
      last_seen: { phishing: null },
    };
    expect(lastSeenAt(empty)).toBeNull();
    expect(lastSeenAt(undefined)).toBeNull();
  });
});

describe("involvementBreakdown", () => {
  it("names every module's count, so a number can be read without a second screen", () => {
    expect(
      involvementBreakdown({
        total: 4,
        phishing: 1,
        breaches: 2,
        dns: 0,
        exposure: 0,
        findings: 1,
        last_seen: {},
      }),
    ).toBe(
      "4 related findings: phishing 1, breaches 2, DNS Security 0, exposure 0, other modules 1",
    );
  });
});
