import dayjs from "dayjs";
import utc from "dayjs/plugin/utc";

dayjs.extend(utc);

/**
 * Centralized date-time formatting for the whole UI.
 *
 * Two rules, applied everywhere:
 *
 * 1. Timestamps are rendered in **UTC**. The API, the audit filter (`from`/`to`
 *    are UTC day boundaries), the scan schedules and report names are all UTC,
 *    so rendering local time made a row's displayed date disagree with the
 *    filter that selected it.
 * 2. The pattern is the machine-readable "YYYY-MM-DD HH:mm:ss" (unambiguous,
 *    sortable, locale-independent).
 *
 * Pages that display timestamps must surface `TIME_ZONE_HINT` so an operator
 * never has to guess the zone.
 */

/** Shown next to tables and filters that render timestamps. */
export const TIME_ZONE_HINT = "All times are UTC";

/** Full timestamp: 2026-09-06 19:18:42 (falls back to "—" for null/empty). */
export function formatDateTime(value?: string | number | Date | null): string {
  if (value === null || value === undefined || value === "") return "—";
  const d = dayjs.utc(value);
  return d.isValid() ? d.format("YYYY-MM-DD HH:mm:ss") : "—";
}

/** Date only: 2026-09-06 (for date-only fields such as breach dates). */
export function formatDate(value?: string | number | Date | null): string {
  if (value === null || value === undefined || value === "") return "—";
  const d = dayjs.utc(value);
  return d.isValid() ? d.format("YYYY-MM-DD") : "—";
}

/** Same as formatDateTime, but empty values render as an explicit "never". */
export function formatDateTimeOrNever(value?: string | number | Date | null): string {
  if (value === null || value === undefined || value === "") return "never";
  return formatDateTime(value);
}
