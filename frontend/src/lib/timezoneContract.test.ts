import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { collectModuleGraph } from "@/lib/moduleGraph";

/**
 * The time-zone contract, as a test rather than as a sentence in a docstring.
 *
 * Every timestamp the platform displays is a stored UTC instant, and the pages
 * that show one say so (`TIME_ZONE_HINT`). Three ways of breaking that are easy
 * to write and invisible in review:
 *
 * * rendering the instant with a locale-sensitive API (`toLocaleString`,
 *   `Intl.DateTimeFormat`), which silently uses the browser's zone — the row then
 *   disagrees with the audit filter, the scan schedule and the expiry thresholds
 *   an operator compares it against;
 * * rendering it with a locale-sensitive *number* formatter, so the same count
 *   renders as `1,234` or `1 234` or `١٢٣٤` depending on the client;
 * * adding a table of instants without saying which zone it is in.
 *
 * The third one is why this is a test and not a convention: a missing hint has no
 * symptom until an operator in another zone misreads an incident timeline. The
 * check runs over the modules the bundle is actually built from — the same walk
 * `moduleGraph` uses, which already skips tests, declarations and build output.
 */

/** The source directory, whichever directory the suite was started from. */
const SRC =
  [resolve(process.cwd(), "src"), resolve(process.cwd(), "frontend/src")].find((dir) =>
    existsSync(resolve(dir, "main.tsx")),
  ) ?? resolve(process.cwd(), "src");

/** The one module allowed to translate between a stored instant and the display. */
const TIME_ZONE_MODULE = "/src/lib/datetime.ts";

/** Where a locale-aware value is created without naming the locale. */
const UNPINNED_FORMATTER = /\bnew\s+Intl\.(NumberFormat|DateTimeFormat|RelativeTimeFormat)\s*\(\s*\)/;

/** The locale-sensitive conversions on `Date` and `Number`. */
const LOCALE_CONVERSION = /\.toLocale(?:String|DateString|TimeString)\s*\(/;

/** Where an instant is formatted, whatever the module does with the result. */
const FORMATTER_CALL = /\b(formatDateTime|formatDate|formatDateTimeOrNever)\s*\(/;

const appModules = collectModuleGraph(SRC);

/** A path as a failure message should print it. */
function label(file: string): string {
  const marker = file.indexOf("/src/");
  return marker === -1 ? file : file.slice(marker + 1);
}

function source(file: string): string {
  return readFileSync(file, "utf8");
}

describe("the time-zone contract of the UI", () => {
  it("finds the application's own modules", () => {
    // A walk that silently returns nothing would make every check below pass.
    expect(appModules.length).toBeGreaterThan(40);
    expect(appModules.map((node) => label(node.id))).toContain("src/lib/datetime.ts");
  });

  it("creates no locale-dependent formatter outside the time-zone module", () => {
    const offenders = appModules
      .filter((node) => !node.id.endsWith(TIME_ZONE_MODULE))
      .filter((node) => UNPINNED_FORMATTER.test(source(node.id)))
      .map((node) => label(node.id));

    expect(
      offenders,
      "A formatter built without a locale renders whatever the browser is set to. " +
        "Pin the locale (the UI ships English), or render the value through " +
        "@/lib/datetime, which fixes UTC.",
    ).toEqual([]);
  });

  it("renders no stored instant through the browser's own zone or format", () => {
    const offenders = appModules
      .filter((node) => !node.id.endsWith(TIME_ZONE_MODULE))
      .filter((node) => LOCALE_CONVERSION.test(source(node.id)))
      .map((node) => label(node.id));

    expect(
      offenders,
      "Use formatDateTime/formatDate from @/lib/datetime: the value on screen must " +
        "be the UTC instant that was stored, not that instant in the reader's zone.",
    ).toEqual([]);
  });

  it("states the zone wherever an instant is displayed", () => {
    const offenders = appModules
      .filter((node) => FORMATTER_CALL.test(source(node.id)))
      .filter((node) => !source(node.id).includes("TIME_ZONE_HINT"))
      .map((node) => label(node.id));

    expect(
      offenders,
      "A table or card that prints timestamps has to say which zone they are in " +
        "(surface TIME_ZONE_HINT next to it); otherwise a reader assumes their own.",
    ).toEqual([]);
  });
});
