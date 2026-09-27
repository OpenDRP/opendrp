import { describe, expect, it } from "vitest";
import { TIME_ZONE_HINT, formatDate, formatDateTime, formatDateTimeOrNever } from "@/lib/datetime";

describe("timestamp formatting", () => {
  it("renders instants in UTC regardless of the browser time zone", () => {
    // 14:47 UTC stays 14:47 even in a UTC+5 browser session.
    expect(formatDateTime("2026-09-06T14:47:00Z")).toBe("2026-09-06 14:47:00");
    expect(formatDateTime("2026-09-06T23:30:00+05:00")).toBe("2026-09-06 18:30:00");
    expect(formatDate("2026-09-06T23:30:00+05:00")).toBe("2026-09-06");
  });

  it("uses an em dash for missing values and never for absent timestamps", () => {
    expect(formatDateTime(null)).toBe("—");
    expect(formatDateTime("")).toBe("—");
    expect(formatDateTime("not-a-date")).toBe("—");
    expect(formatDateTimeOrNever(null)).toBe("never");
    expect(formatDateTimeOrNever("2026-01-01T00:00:00Z")).toBe("2026-01-01 00:00:00");
  });

  it("exposes the hint shown next to timestamped tables", () => {
    expect(TIME_ZONE_HINT).toMatch(/UTC/);
  });
});
