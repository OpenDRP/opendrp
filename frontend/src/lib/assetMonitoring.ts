/**
 * What is watching an asset, and how much it has seen (WI-20 / AST-27).
 *
 * The inventory listed what the operator had configured, and nothing said which
 * of those assets any module actually consumed: an asset whose type no enabled
 * module scans sat in the table looking exactly like one that is scanned daily.
 * These helpers answer that from the connector registry (`GET /connectors/modules`)
 * — the same declaration that drives job types and navigation, so a module
 * declared after this build is covered without a frontend change.
 *
 * "Coverage" here means an *enabled* module or a connector that is not disabled:
 * a disabled declaration consumes nothing, and counting it would show monitoring
 * that is not happening. The involvement counters themselves come from the
 * backend, computed from its single matching rule.
 */

import type {
  AssetFindingSummary,
  ConnectorModulesResponse,
} from "@/types/api";

export interface AssetTypeCoverage {
  /** Labels of the enabled modules that declare this asset type. */
  modules: string[];
  /** Names of the enabled connectors that declared this asset type. */
  connectors: string[];
}

/** Which modules and connectors consume each asset type, keyed by asset type. */
export function coverageByAssetType(
  modules: ConnectorModulesResponse | undefined,
): Record<string, AssetTypeCoverage> {
  const coverage: Record<string, AssetTypeCoverage> = {};
  const entryFor = (assetType: string): AssetTypeCoverage =>
    (coverage[assetType] ??= { modules: [], connectors: [] });

  for (const [id, entry] of Object.entries(modules?.modules ?? {})) {
    if (entry.enabled === false) continue;
    const label = entry.label || id;
    for (const assetType of entry.asset_types ?? []) {
      const record = entryFor(assetType);
      if (!record.modules.includes(label)) record.modules.push(label);
    }
    for (const connector of entry.connectors ?? []) {
      if (connector.status === "disabled") continue;
      for (const assetType of connector.asset_types ?? []) {
        const record = entryFor(assetType);
        if (!record.connectors.includes(connector.name)) {
          record.connectors.push(connector.name);
        }
      }
    }
  }
  return coverage;
}

/** The coverage of one asset type; never undefined, so callers need no default. */
export function coverageForType(
  coverage: Record<string, AssetTypeCoverage>,
  assetType: string,
): AssetTypeCoverage {
  return coverage[assetType] ?? { modules: [], connectors: [] };
}

/** One sentence naming what consumes an asset type, or that nothing does. */
export function coverageDescription(coverage: AssetTypeCoverage): string {
  const { modules, connectors } = coverage;
  if (modules.length === 0 && connectors.length === 0) {
    return "No enabled module consumes this type of asset: it is recorded, but nothing scans it.";
  }
  const parts: string[] = [];
  if (modules.length > 0) parts.push(`modules ${modules.join(", ")}`);
  if (connectors.length > 0) parts.push(`connectors ${connectors.join(", ")}`);
  return `Monitored by ${parts.join("; ")}.`;
}

/**
 * The latest moment any module saw this asset, as the backend published it.
 *
 * The moments are ISO-8601 text, and the invariant is that the API publishes
 * them in UTC: a breach reports a disclosure date (`2024-01-01`) while a scan
 * reports a timestamp (`2026-01-02T00:00:00+00:00`). Comparing the strings — as
 * this helper used to do — happens to put a bare date before every timestamp in
 * the same year, and silently misorders a date-only value against a timestamp
 * from a different one (`2026-10-15` vs `2026-10-15T12:00:00+00:00` is fine,
 * but `2026-10-15` vs `2026-10-14T23:00:00+00:00` is not what a reader expects
 * once offsets differ). Parsing to an instant compares what the values mean.
 * A value the browser cannot parse is ignored rather than allowed to win: a
 * malformed date must not hide a real observation.
 */
export function lastSeenAt(
  summary: AssetFindingSummary | null | undefined,
): string | null {
  const moments = Object.values(summary?.last_seen ?? {}).filter(
    (moment): moment is string => Boolean(moment),
  );
  let latest: string | null = null;
  let latestAt = Number.NEGATIVE_INFINITY;
  for (const moment of moments) {
    const parsed = Date.parse(moment);
    if (Number.isNaN(parsed)) continue;
    if (parsed > latestAt) {
      latestAt = parsed;
      latest = moment;
    }
  }
  return latest;
}

/**
 * A tooltip breakdown of the counters, so a row can say where its number came
 * from without a second screen.
 */
export function involvementBreakdown(summary: AssetFindingSummary): string {
  const parts = [
    `phishing ${summary.phishing}`,
    `breaches ${summary.breaches}`,
    `DNS Security ${summary.dns}`,
    `exposure ${summary.exposure}`,
    `other modules ${summary.findings}`,
  ];
  return `${summary.total} related findings: ${parts.join(", ")}`;
}
