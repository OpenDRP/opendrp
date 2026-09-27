import { describe, expect, it } from "vitest";
import {
  ACCOUNT_SECURITY_ACTIONS,
  auditActionLabel,
  auditCategory,
  auditTone,
  describeAuditEntry,
  describedActions,
} from "@/lib/audit";

/**
 * What an operator reads in the audit log and on My security.
 *
 * The defect these tests were written for: My security listed raw action codes
 * (`auth.mfa.enrolled`), so the person the event was *about* could not tell what
 * had happened to their own account. A code is a filter key, and a sentence is
 * what the page owes the reader.
 */
describe("describeAuditEntry", () => {
  it("describes every event the account page can show", () => {
    for (const action of ACCOUNT_SECURITY_ACTIONS) {
      const text = describeAuditEntry({ action, details: {} });
      // The fallback is the humanized code itself; anything equal to it means the
      // action never got a sentence of its own.
      expect(text, `${action} has no description`).not.toBe(auditActionLabel(action));
      expect(text.trim().length).toBeGreaterThan(5);
    }
  });

  it("names what this sign-in was, not the general case", () => {
    expect(describeAuditEntry({ action: "auth.mfa.enrolled", details: {} })).toBe(
      "Second factor turned on",
    );
    expect(
      describeAuditEntry({ action: "auth.mfa.enrolled", details: { was_required: true } }),
    ).toContain("this installation requires one");
    expect(describeAuditEntry({ action: "auth.password.changed", details: {} })).toBe(
      "Password changed",
    );
    expect(
      describeAuditEntry({
        action: "auth.password.changed",
        details: { refresh_families_revoked: 3 },
      }),
    ).toBe("Password changed — 3 other sessions signed out");
    expect(describeAuditEntry({ action: "auth.logout", details: {} })).toBe("Signed out");
  });

  it("turns a refusal reason into prose", () => {
    expect(
      describeAuditEntry({ action: "auth.login.failure", details: { reason: "account_locked" } }),
    ).toBe("Sign-in attempt refused — the account is temporarily locked after repeated failures");
    expect(
      describeAuditEntry({
        action: "auth.refresh.failure",
        details: { reason: "reuse_detected" },
      }),
    ).toContain("an already-used token was presented");
    expect(
      describeAuditEntry({ action: "auth.mfa.failure", details: { reason: "replay_detected" } }),
    ).toBe("Second factor refused — the code had already been used");
  });

  it("humanizes a reason this release has never seen", () => {
    // A later release may add a refusal mode. It must read as *something*: the
    // sentence claiming the generic case would hide the new one.
    expect(
      describeAuditEntry({ action: "auth.login.failure", details: { reason: "device_mismatch" } }),
    ).toBe("Sign-in attempt refused — Device mismatch");
  });

  it("describes a lock with what was locked", () => {
    expect(
      describeAuditEntry({
        action: "auth.login.locked",
        details: { email_locked: true, ip_locked: true, lock_window_seconds: 900 },
      }),
    ).toBe(
      "Sign-in blocked after repeated failures — this address and account are locked for 15 min",
    );
  });

  it("reads a routine entry as a fact", () => {
    expect(
      describeAuditEntry({ action: "asset.create", details: { asset_value: "example.com" } }),
    ).toBe("Added asset example.com");
    expect(
      describeAuditEntry({ action: "connector.token.issued", details: { connector: "shodan" } }),
    ).toBe("Connector token issued for shodan");
    expect(
      describeAuditEntry({
        action: "finding.status_update",
        details: { to: "resolved", from: "active" },
      }),
    ).toBe("Finding marked as resolved (was active)");
  });

  it("keeps the values of an action it does not know", () => {
    // The graceful path: a module or connector added later still produces a
    // readable line, never a bare code and never nothing at all.
    const text = describeAuditEntry({
      action: "brand_watcher.rotate",
      details: { scope: "global", count: 2 },
    });
    expect(text).toBe("Brand watcher rotate · scope: global, count: 2");
    expect(describeAuditEntry({ action: "brand_watcher.rotate" })).toBe("Brand watcher rotate");
  });

  it("survives details that are not the shape it expects", () => {
    expect(describeAuditEntry({ action: "asset.create", details: null })).toBe("Added asset");
    expect(
      describeAuditEntry({ action: "finding.status_update", details: { to: { nested: true } } }),
    ).toBe("Finding status updated");
  });

  it("covers its own vocabulary", () => {
    // A description that no longer matches an allowed action is dead code the
    // next reader would trust; this keeps the map honest in both directions.
    for (const action of describedActions()) {
      expect(action).toMatch(/^[a-z][a-z0-9._]*$/);
    }
    expect(describedActions().length).toBeGreaterThanOrEqual(ACCOUNT_SECURITY_ACTIONS.length);
  });
});

describe("auditCategory", () => {
  it("groups by the first segment and falls back to system", () => {
    expect(auditCategory("auth.mfa.enrolled")).toBe("auth");
    expect(auditCategory("connector.token.issued")).toBe("connector");
    expect(auditCategory("")).toBe("system");
  });
});

describe("auditActionLabel", () => {
  it("prefers the API's own label and humanizes the rest", () => {
    expect(auditActionLabel("asset.create", { "asset.create": "Asset created" })).toBe(
      "Asset created",
    );
    expect(auditActionLabel("connector.token.issued")).toBe("Connector token issued");
  });
});

describe("auditTone", () => {
  it("marks what a person did not do as the loudest thing on the page", () => {
    // This list is where an account holder notices a sign-in they did not make.
    expect(auditTone("auth.login.failure")).toBe("danger");
    expect(auditTone("auth.refresh.failure")).toBe("danger");
    expect(auditTone("auth.mfa.failure")).toBe("danger");
    expect(auditTone("auth.mfa.disabled")).toBe("warning");
    expect(auditTone("auth.login.success")).toBe("neutral");
    expect(auditTone("auth.mfa.enrolled")).toBe("neutral");
  });
});
