/**
 * Human-readable audit entries.
 *
 * The audit trail is written for machines. `auth.mfa.enrolled` is a stable
 * identifier an administrator can filter on, and it tells the account holder
 * nothing about what happened to their own account. This module is the one place
 * that turns that vocabulary into a sentence, and it is shared on purpose: the
 * audit log (administrators) and My security (every role) must not describe the
 * same event two different ways.
 *
 * Two rules, the same as lib/labels.ts:
 *
 * 1. A sentence is built from the entry's own `details`, so it says what happened
 *    *this* time — "Sign-in attempt refused — the account is temporarily locked
 *    after repeated failures" rather than "Failed login attempt".
 * 2. An unknown value degrades gracefully. An action a later release adds is
 *    humanized from its identifier and its details are listed, never rendered as
 *    a bare code: `new_vendor.rotate` becomes "New vendor rotate · scope: …".
 *
 * Where the platform shows an event, this module decides the wording; where it
 * shows *storage*, `lib/labels.ts` does.
 */

import { humanizeKey } from "@/lib/labels";
import type { SecurityActivity } from "@/types/api";

/** The shape this module reads: an action, and whatever the API kept about it. */
export interface AuditEntryLike {
  action: string;
  details?: Record<string, unknown> | null;
}

type Details = Record<string, unknown>;

const CATEGORY_FALLBACK = "system";

/**
 * Every action `GET /auth/security-activity` can return — the same list as
 * `security_actions` in `app/api/v1/routers/auth.py`.
 *
 * Duplicated deliberately: `audit.test.ts` fails when one of these has no
 * description of its own, which is the drift that would put `auth.mfa.enrolled`
 * back in front of a user as a code.
 */
export const ACCOUNT_SECURITY_ACTIONS = [
  "auth.login.success",
  "auth.login.failure",
  "auth.login.locked",
  "auth.mfa.success",
  "auth.mfa.failure",
  "auth.mfa.enrolled",
  "auth.mfa.disabled",
  "auth.password.changed",
  "auth.password.change_failed",
  "auth.session.revoked",
  "auth.sessions.revoked_others",
  "auth.logout",
  "auth.refresh.failure",
] as const;

/** The category prefix, used to pick an icon and a tone. */
export function auditCategory(action: string): string {
  const [first] = action.split(".");
  return first && first.length > 0 ? first : CATEGORY_FALLBACK;
}

/** The short label for an action: the API's own map first, then humanized. */
export function auditActionLabel(
  action: string,
  labels?: Record<string, string> | null,
): string {
  return labels?.[action] ?? humanizeKey(action);
}

// ---------------------------------------------------------------------------
// Details
// ---------------------------------------------------------------------------

function asText(value: unknown): string | null {
  if (typeof value === "string") return value.trim() || null;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) {
    const parts = value.map(asText).filter((part): part is string => part !== null);
    return parts.length > 0 ? parts.join(", ") : null;
  }
  return null;
}

function asCount(value: unknown): number | null {
  const n = typeof value === "number" ? value : Number(asText(value));
  return Number.isFinite(n) ? n : null;
}

function plural(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

/**
 * Turn a machine reason into prose. An unrecognized reason is humanized rather
 * than dropped: a new refusal mode must read as *something*, not vanish into a
 * sentence that claims the generic case.
 */
function reason(raw: unknown, labels: Record<string, string>, fallback: string): string {
  const key = typeof raw === "string" ? raw.trim() : "";
  if (!key) return fallback;
  return labels[key] ?? humanizeKey(key);
}

/** `Added asset example.com`, or nothing when the entry did not name it. */
function named(prefix: string, ...candidates: unknown[]): string {
  for (const candidate of candidates) {
    const value = asText(candidate);
    if (value) return `${prefix} ${value}`;
  }
  return prefix;
}

const LOGIN_FAILURE_REASONS: Record<string, string> = {
  invalid_credentials: "the password did not match an active account",
  account_locked: "the account is temporarily locked after repeated failures",
  account_disabled: "the account is deactivated",
  missing_credentials: "the request carried no email or password",
};

const MFA_FAILURE_REASONS: Record<string, string> = {
  code_missing: "no code was supplied",
  invalid_code: "the code was wrong or had expired",
  replay_detected: "the code had already been used",
  invalid_password_on_recovery_codes: "the password did not match",
};

const REFRESH_FAILURE_REASONS: Record<string, string> = {
  invalid_token: "the token was malformed or its signature did not verify",
  bad_token_type: "the token was not a refresh token",
  user_missing_or_inactive: "the account no longer exists or is deactivated",
  family_not_found: "the session is no longer known",
  family_revoked: "the session had already been signed out",
  family_user_mismatch: "the token belonged to a different account",
  reuse_detected: "an already-used token was presented, so the session was signed out",
};

// ---------------------------------------------------------------------------
// Descriptions
// ---------------------------------------------------------------------------

function signInLocked(details: Details): string {
  const windows = asCount(details.lock_window_seconds);
  const forHowLong = windows === null ? "" : ` for ${Math.max(1, Math.round(windows / 60))} min`;

  const locked = [details.email_locked === true, details.ip_locked === true].filter(Boolean).length;
  if (locked === 2) {
    return `Sign-in blocked after repeated failures — this address and account are locked${forHowLong}`;
  }
  if (details.ip_locked === true) {
    return `Sign-in blocked after repeated failures — this address is locked${forHowLong}`;
  }
  if (details.email_locked === true) {
    return `Sign-in blocked after repeated failures — the account is locked${forHowLong}`;
  }
  return `Sign-in blocked after repeated failures${forHowLong}`;
}

function sessionsRevoked(details: Details, verb: string): string {
  const revoked = asCount(details.refresh_families_revoked);
  if (revoked === null || revoked <= 0) return verb;
  return `${verb} — ${plural(revoked, "other session")} signed out`;
}

function extraSessions(details: Details, verb: string): string {
  const revoked = asCount(details.revoked_count);
  return revoked !== null && revoked > 0 ? `${verb} (${revoked})` : verb;
}

/** `3 breach matches whose asset was removed were cleaned up`. */
function cleanedUp(details: Details, noun: string): string {
  const deleted = asCount(details.deleted);
  if (deleted === null) return `Orphaned ${noun}s were cleaned up`;
  if (deleted <= 0) return `No orphaned ${noun}s to clean up`;
  return `${plural(deleted, noun)} whose asset was removed were cleaned up`;
}

/**
 * One sentence per action, for entries whose details refine it no further.
 *
 * A missing action falls through to `fallbackDescription`, so adding a case here
 * is how an event stops looking like a log line and starts reading like a fact.
 */
const AUDIT_DESCRIPTIONS: Record<string, (details: Details) => string> = {
  // --- this account: sign in and sessions ---
  "auth.login.success": () => "Signed in with the password",
  "auth.login.failure": (d) =>
    `Sign-in attempt refused — ${reason(
      d.reason,
      LOGIN_FAILURE_REASONS,
      "the credentials were not accepted",
    )}`,
  "auth.login.locked": signInLocked,
  // A separate row from the password step, so it says that step and not the
  // whole sign-in: the two read in sequence and neither repeats the other.
  "auth.mfa.success": (d) =>
    d.method === "recovery_code"
      ? "Second factor confirmed with a recovery code"
      : "Second factor confirmed with the authenticator app",
  "auth.mfa.failure": (d) =>
    `Second factor refused — ${reason(d.reason, MFA_FAILURE_REASONS, "the code was not accepted")}`,
  "auth.mfa.setup_started": () => "Second-factor enrolment started",
  "auth.mfa.setup_failed": (d) =>
    `Second-factor enrolment refused — ${reason(
      d.reason,
      MFA_FAILURE_REASONS,
      "the password did not match",
    )}`,
  "auth.mfa.enrolled": (d) =>
    d.was_required === true
      ? "Second factor turned on — this installation requires one for administrators"
      : "Second factor turned on",
  "auth.mfa.disabled": () =>
    "Second factor turned off — sign-in asks for the password only until a new one is enrolled",
  "auth.mfa.required": () => "Administrator action refused: this installation requires a second factor",
  "auth.mfa.recovery_codes.rotated": (d) => {
    const codes = asCount(d.count);
    return codes === null
      ? "Recovery codes replaced — older codes no longer work"
      : `${plural(codes, "new recovery code")} generated — older codes no longer work`;
  },
  "auth.password.changed": (d) => sessionsRevoked(d, "Password changed"),
  "auth.password.change_failed": () =>
    "Password change refused — the current password did not match",
  "auth.session.revoked": () => "A signed-in session was revoked",
  "auth.sessions.revoked_others": (d) => extraSessions(d, "Other sessions signed out"),
  "auth.logout": () => "Signed out",
  "auth.refresh.success": () => "Session refreshed",
  "auth.refresh.failure": (d) =>
    `Session refresh refused — ${reason(
      d.reason,
      REFRESH_FAILURE_REASONS,
      "the session is no longer valid",
    )}`,

  // --- users ---
  "user.created": (d) =>
    named("Created user", d.target_email, d.target_user_id),
  "user.updated": (d) =>
    named("Updated user", d.target_email, d.target_user_id),
  "user.deleted": (d) =>
    named("Permanently deleted user", d.target_email, d.target_user_id),
  "user.password_reset": (d) =>
    named("Reset the password of", d.target_email, d.target_user_id),
  "user.mfa.reset": (d) =>
    d.was_enabled === true
      ? `${named("Cleared the second factor of", d.target_email, d.target_user_id)} — enrolment is required at the next sign-in`
      : named("Cleared the second factor of", d.target_email, d.target_user_id),
  "user.locked": (d) => named("Deactivated user", d.target_email, d.target_user_id),
  "user.unlocked": (d) => named("Activated user", d.target_email, d.target_user_id),

  // --- assets ---
  "asset.create": (d) => named("Added asset", d.asset_value, d.asset_id),
  "asset.update": (d) => named("Updated asset", d.asset_value, d.asset_id),
  "asset.delete": (d) => named("Deleted asset", d.asset_value, d.asset_id),

  // --- phishing ---
  "phishing.threat.update": (d) =>
    named("Updated phishing finding", d.phishing_domain, d.threat_id),
  "phishing.threat.delete": (d) =>
    named("Deleted phishing finding", d.phishing_domain, d.threat_id),
  "phishing.scan.scheduled": (d) =>
    named("Scheduled scan started for", d.modules, "the configured modules"),
  "phishing.threat.orphans.cleaned": (d) =>
    cleanedUp(d, "phishing finding"),

  // --- breaches ---
  "breach.scan.email": (d) =>
    `Breach lookup for ${asText(d.email) ?? "an email account"} — ${
      asCount(d.found) === null ? "no matches" : plural(asCount(d.found) as number, "match")
    }`,
  "breach.scan.domain": (d) =>
    `Breach lookup for ${asText(d.domain) ?? "a domain"} — ${
      asCount(d.found) === null ? "no matches" : plural(asCount(d.found) as number, "match")
    }`,
  "breach.delete": (d) => named("Deleted breach match", d.breach_name, d.breach_id),
  "breach.orphans.cleaned": (d) => cleanedUp(d, "breach match"),

  // --- reports ---
  "report.generate": (d) => named("Report generation started", d.report_name, d.report_id),
  "report.generate.failed": (d) => named("Report generation failed", d.report_name, d.report_id),
  "report.download": (d) => named("Downloaded report", d.report_name, d.report_id),
  "report.download.missing": (d) =>
    named("Report artifact missing for", d.report_name, d.report_id),
  "report.artifact.rejected": (d) =>
    named("Refused the artifact name of report", d.report_name, d.report_id),
  "report.delete": (d) => named("Deleted report", d.report_name, d.report_id),

  // --- connectors and modules ---
  "connector.registered": (d) => named("Connector registered:", d.connector, d.name),
  "connector.scan.completed": (d) => named("Connector scan completed:", d.connector),
  "connector.scan.failed": (d) => named("Connector scan failed:", d.connector),
  "connector.status.updated": (d) => named("Connector status changed:", d.connector),
  "connector.config.updated": (d) => named("Connector configuration updated:", d.connector),
  "connector.token.issued": (d) => named("Connector token issued for", d.connector),
  "connector.token.rotated": (d) => named("Connector token replaced for", d.connector),
  "connector.token.revoked": (d) => named("Connector token revoked for", d.connector),
  "module.declared": (d) => named("Module declared:", d.module),
  "module.updated": (d) =>
    d.enabled === false
      ? named("Module disabled:", d.module)
      : d.enabled === true
        ? named("Module enabled:", d.module)
        : named("Module updated:", d.module),

  // --- settings and alerts ---
  "settings.update": (d) =>
    Array.isArray(d.updated_fields) && d.updated_fields.length > 0
      ? `Updated settings: ${d.updated_fields.join(", ")}`
      : "Settings updated",
  "settings.test_email_sent": (d) => named("Sent a test email to", d.to),
  "settings.test_email_failed": (d) => named("Test email failed for", d.to),
  "settings.test_telegram_sent": () => "Sent a test message to the configured Telegram chats",
  "settings.test_telegram_failed": () => "Test message to Telegram failed",
  "settings.telegram.validate": () => "Telegram chats validated",
  "settings.telegram.validate_failed": () => "Telegram chats refused by the provider",
  "alert.dispatch.success": (d) => named("Alert delivered via", d.channel, "a channel"),
  "alert.dispatch.failed": (d) => named("Alert delivery failed via", d.channel, "a channel"),
  "alert.test_sent": () => "Alert test message sent",

  // --- platform ---
  "outbound.blocked": (d) =>
    `Refused an outbound connection to ${asText(d.host) ?? "a destination outside the allowlist"}`,
  "rate_limit.request_blocked": () => "A request was refused by the platform rate limit",
  "rate_limit.manual_action_blocked": (d) =>
    `Repeated ${asText(d.scope) ?? "action"} refused by the rate limit (${plural(
      asCount(d.retry_after_seconds) ?? 0,
      "second",
    )} to wait)`,
  "audit.chain.verified": (d) => {
    const entries = asCount(d.checked);
    const through = asText(d.through_seq);
    if (entries === null) return "Audit hash chain verified";
    const range = through === null ? "" : `, through sequence ${through}`;
    return `Audit hash chain verified over ${entries} ${entries === 1 ? "entry" : "entries"}${range}`;
  },
  "audit.chain.broken": (d) => {
    const at = asText(d.first_broken_seq);
    const why = asText(d.reason);
    return `Audit hash chain verification FAILED${at ? ` at sequence ${at}` : ""}${
      why ? ` — ${humanizeKey(why)}` : ""
    }`;
  },
  "audit.log.view": (d) =>
    asText(d.action_filter)
      ? `Viewed the audit log (filter: ${asText(d.action_filter)})`
      : "Viewed the audit log",
  "audit.integrity.view": () => "Viewed the audit chain status",
  "audit.retention.purged": (d) => {
    const tables = (d.tables ?? {}) as Record<string, { deleted_rows?: unknown } | undefined>;
    const rows = Object.values(tables).reduce(
      (total, table) => total + (asCount(table?.deleted_rows) ?? 0),
      0,
    );
    if (rows <= 0) return "Purged expired data";
    return `Purged ${plural(rows, "expired row")}${
      d.truncated === true ? " — the sweep continues on the next run" : ""
    }`;
  },
  "task.started": (d) => named("Background task started:", d.task),
  "task.completed": (d) => named("Background task completed:", d.task),
  "task.failed": (d) => named("Background task failed:", d.task),
  "job.delete": (d) => named("Deleted job", d.job_type, d.job_id),
  "finding.status_update": (d) => {
    const to = asText(d.to) ?? asText(d.status);
    const from = asText(d.from);
    return to
      ? `Finding marked as ${to}${from && from !== to ? ` (was ${from})` : ""}`
      : "Finding status updated";
  },
  "dashboard.view": () => "Viewed the dashboard",
  "jobs.list": (d) =>
    asCount(d.total) === null ? "Viewed the job list" : `Viewed the job list (${d.total} entries)`,
};

function fallbackDescription(entry: AuditEntryLike): string {
  const label = auditActionLabel(entry.action);
  const entries = Object.entries(entry.details ?? {}).slice(0, 4);
  if (entries.length === 0) return label;
  return `${label} · ${entries
    .map(([key, value]) => `${key}: ${asText(value) ?? JSON.stringify(value)}`)
    .join(", ")}`;
}

/**
 * What actually happened, in one line, for an operator to read rather than parse.
 */
export function describeAuditEntry(entry: AuditEntryLike): string {
  const describe = AUDIT_DESCRIPTIONS[entry.action];
  if (!describe) return fallbackDescription(entry);
  return describe((entry.details ?? {}) as Details);
}

/** Actions this module describes in words of its own. */
export function describedActions(): string[] {
  return Object.keys(AUDIT_DESCRIPTIONS);
}

// ---------------------------------------------------------------------------
// Emphasis
// ---------------------------------------------------------------------------

export type AuditTone = "danger" | "warning" | "neutral";

/**
 * How much attention an entry deserves on an account page.
 *
 * Refusals are `danger` because they are the events a person did not cause: a
 * failed sign-in, a re-used refresh token, a rejected code are exactly what
 * "did someone else try" looks like in this list. Weakening the factor is
 * `warning` — the account holder may well have done it, and it is still the
 * change that reduces their protection. Everything else is routine.
 */
const DANGEROUS_ACTIONS = new Set([
  "auth.login.failure",
  "auth.login.locked",
  "auth.mfa.failure",
  "auth.mfa.setup_failed",
  "auth.mfa.required",
  "auth.password.change_failed",
  "auth.refresh.failure",
  "audit.chain.broken",
  "outbound.blocked",
  "rate_limit.request_blocked",
  "rate_limit.manual_action_blocked",
]);

const WARNING_ACTIONS = new Set([
  "auth.mfa.disabled",
  "auth.password.changed",
  "auth.session.revoked",
  "auth.sessions.revoked_others",
]);

export function auditTone(action: string): AuditTone {
  if (DANGEROUS_ACTIONS.has(action)) return "danger";
  if (WARNING_ACTIONS.has(action)) return "warning";
  return "neutral";
}
