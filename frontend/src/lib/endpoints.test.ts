import { afterEach, describe, expect, it } from "vitest";
import type { AxiosRequestConfig } from "axios";

import { endpoints, api } from "@/lib/api";

/**
 * The SPA's wire contract: one row per endpoint, one assertion per part of the
 * request that the API decides on.
 *
 * These helpers are the only place the SPA writes a path or chooses a verb, and a
 * wrong one is not a rendering bug — it is a `404`/`405` in production that no
 * component test would see, because the component's own test mocks the helper.
 * That is why this file invokes the helpers themselves through an axios adapter
 * and checks the method, the path, the query and the body as the API will receive
 * them, including the ids that must be encoded and the two requests that are not
 * JSON (a CSV upload and the three downloads).
 *
 * It is deliberately table-driven: adding an endpoint without adding a row leaves
 * it uncovered, and the coverage floor in `vite.config.ts` is what notices.
 */

type Case = {
  name: string;
  method: "get" | "post" | "put" | "patch" | "delete";
  url: string;
  call: () => Promise<unknown>;
  params?: Record<string, unknown>;
  /** Parsed as JSON and compared; `undefined` means the request has no body. */
  body?: unknown;
  /** A body sent verbatim, with the content type it is sent as. */
  rawBody?: string;
  contentType?: string;
  responseType?: string;
};

const id = "b3d1c0de-0000-4000-8000-000000000001";
const otherId = "b3d1c0de-0000-4000-8000-000000000002";

const cases: Case[] = [
  // --- Authentication and the account's own surface -------------------------
  {
    name: "login",
    method: "post",
    url: "/auth/login",
    body: { email: "a@example.com", password: "secret" },
    call: () => endpoints.login("a@example.com", "secret"),
  },
  {
    name: "login with a second factor",
    method: "post",
    url: "/auth/login",
    body: { email: "a@example.com", password: "secret", totp_code: "123456" },
    call: () => endpoints.login("a@example.com", "secret", "123456"),
  },
  {
    name: "login with a recovery code",
    method: "post",
    url: "/auth/login",
    body: { email: "a@example.com", password: "secret", recovery_code: "rc-1" },
    call: () => endpoints.login("a@example.com", "secret", undefined, "rc-1"),
  },
  {
    name: "changePassword",
    method: "post",
    url: "/auth/password",
    body: { current_password: "old", new_password: "new" },
    call: () => endpoints.changePassword("old", "new"),
  },
  { name: "mfaStatus", method: "get", url: "/auth/mfa", call: () => endpoints.mfaStatus() },
  {
    name: "mfaSetup",
    method: "post",
    url: "/auth/mfa/setup",
    body: { password: "secret" },
    call: () => endpoints.mfaSetup("secret"),
  },
  {
    name: "mfaQr",
    method: "get",
    url: "/auth/mfa/qr",
    responseType: "blob",
    call: () => endpoints.mfaQr(),
  },
  {
    name: "mfaEnable",
    method: "post",
    url: "/auth/mfa/enable",
    body: { password: "secret", code: "123456" },
    call: () => endpoints.mfaEnable("secret", "123456"),
  },
  {
    name: "mfaDisable",
    method: "post",
    url: "/auth/mfa/disable",
    body: { password: "secret", code: "123456" },
    call: () => endpoints.mfaDisable("secret", "123456"),
  },
  {
    name: "mfaRotateRecoveryCodes",
    method: "post",
    url: "/auth/mfa/recovery-codes/rotate",
    body: { password: "secret", code: "123456" },
    call: () => endpoints.mfaRotateRecoveryCodes("secret", "123456"),
  },
  { name: "listSessions", method: "get", url: "/auth/sessions", call: () => endpoints.listSessions() },
  {
    name: "revokeSession",
    method: "delete",
    url: `/auth/sessions/${id}`,
    call: () => endpoints.revokeSession(id),
  },
  {
    name: "revokeOtherSessions",
    method: "post",
    url: "/auth/sessions/revoke-others",
    call: () => endpoints.revokeOtherSessions(),
  },
  {
    name: "securityActivity",
    method: "get",
    url: "/auth/security-activity",
    call: () => endpoints.securityActivity(),
  },
  {
    name: "acceptInvitation",
    method: "post",
    url: "/auth/accept-invitation",
    body: { token: "tok", new_password: "new" },
    call: () => endpoints.acceptInvitation("tok", "new"),
  },
  {
    name: "me",
    method: "get",
    url: "/auth/me",
    call: () => endpoints.me(),
  },
  // --- Users and their administrative actions -------------------------------
  {
    name: "resetUserMfa",
    method: "post",
    url: `/users/${id}/mfa/reset`,
    call: () => endpoints.resetUserMfa(id),
  },
  { name: "unlockUser", method: "post", url: `/users/${id}/unlock`, call: () => endpoints.unlockUser(id) },
  {
    name: "inviteUser",
    method: "post",
    url: "/users/invite",
    body: { email: "new@example.com", role: "viewer" },
    call: () => endpoints.inviteUser({ email: "new@example.com", role: "viewer" }),
  },
  {
    name: "reissueInvitation",
    method: "post",
    url: `/users/${id}/invitation`,
    call: () => endpoints.reissueInvitation(id),
  },
  {
    name: "listUsers",
    method: "get",
    url: "/users",
    params: { page: 2, size: 50, role: "admin" },
    call: () => endpoints.listUsers({ page: 2, size: 50, role: "admin" }),
  },
  {
    name: "exportUsers",
    method: "get",
    url: "/users/export",
    params: { role: "admin" },
    responseType: "blob",
    call: () => endpoints.exportUsers({ role: "admin" }),
  },
  {
    name: "listUsersBrief",
    method: "get",
    url: "/users/brief",
    call: () => endpoints.listUsersBrief(),
  },
  {
    name: "listUserSessions",
    method: "get",
    url: `/users/${id}/sessions`,
    call: () => endpoints.listUserSessions(id),
  },
  {
    name: "revokeUserSessions",
    method: "delete",
    url: `/users/${id}/sessions`,
    call: () => endpoints.revokeUserSessions(id),
  },
  {
    name: "bulkUsers",
    method: "post",
    url: "/users/bulk",
    body: { operation: "deactivate", user_ids: [id] },
    call: () => endpoints.bulkUsers({ operation: "deactivate", user_ids: [id] }),
  },
  {
    name: "createUser",
    method: "post",
    url: "/users",
    body: { email: "new@example.com", role: "analyst" },
    call: () => endpoints.createUser({ email: "new@example.com", role: "analyst" }),
  },
  { name: "getUser", method: "get", url: `/users/${id}`, call: () => endpoints.getUser(id) },
  {
    name: "updateUser",
    method: "put",
    url: `/users/${id}`,
    body: { is_active: false },
    call: () => endpoints.updateUser(id, { is_active: false }),
  },
  { name: "deleteUser", method: "delete", url: `/users/${id}`, call: () => endpoints.deleteUser(id) },

  // --- Modules, exposure and DNS & TLS --------------------------------------
  {
    name: "scanModule",
    method: "post",
    url: "/modules/phishing%20and%20brand/scan",
    call: () => endpoints.scanModule("phishing and brand"),
  },
  {
    name: "listExposure",
    method: "get",
    url: "/exposure/observations",
    params: { page: 1, size: 20, source: "netlas" },
    call: () => endpoints.listExposure({ page: 1, size: 20, source: "netlas" }),
  },
  {
    name: "updateExposure",
    method: "patch",
    url: `/exposure/observations/${id}`,
    body: { status: "resolved" },
    call: () => endpoints.updateExposure(id, "resolved"),
  },
  {
    name: "promoteExposureObservation",
    method: "post",
    url: `/exposure/observations/${id}/asset`,
    call: () => endpoints.promoteExposureObservation(id),
  },
  {
    name: "phishingEvidence",
    method: "get",
    url: `/phishing/threats/${id}/evidence`,
    call: () => endpoints.phishingEvidence(id),
  },
  {
    name: "dashboardOverview",
    method: "get",
    url: "/dashboard/overview",
    call: () => endpoints.dashboardOverview(),
  },
  {
    name: "listDNSObservations",
    method: "get",
    url: "/dns/observations",
    params: { status: "historical", page: 1 },
    call: () => endpoints.listDNSObservations({ status: "historical", page: 1 }),
  },
  {
    name: "scanDNSSecurity",
    method: "post",
    url: "/dns/scan",
    call: () => endpoints.scanDNSSecurity(),
  },
  {
    name: "cleanOrphanDNSObservations",
    method: "post",
    url: "/dns/observations/cleanup-orphans",
    call: () => endpoints.cleanOrphanDNSObservations(),
  },
  {
    name: "promoteDNSObservation",
    method: "post",
    url: `/dns/observations/${id}/asset`,
    body: { target: "example.com" },
    call: () => endpoints.promoteDNSObservation(id, "example.com"),
  },
  {
    name: "deleteDNSObservation",
    method: "delete",
    url: `/dns/observations/${id}`,
    params: { value: "mail.example.com" },
    call: () => endpoints.deleteDNSObservation(id, "mail.example.com"),
  },
  {
    name: "listTLSCertificates",
    method: "get",
    url: "/dns/certificates",
    params: { verdict: "confirmed_foreign", foreign_only: true, page: 1, size: 20 },
    call: () =>
      endpoints.listTLSCertificates({ verdict: "confirmed_foreign", foreign_only: true, page: 1, size: 20 }),
  },
  {
    name: "reviewTLSSighting",
    method: "patch",
    url: `/dns/certificates/sightings/${id}`,
    body: { verdict: "expected", note: "our CDN" },
    call: () => endpoints.reviewTLSSighting(id, { verdict: "expected", note: "our CDN" }),
  },
  {
    name: "listCertificateExceptions",
    method: "get",
    url: "/dns/certificate-exceptions",
    call: () => endpoints.listCertificateExceptions(),
  },
  {
    name: "createCertificateException",
    method: "post",
    url: "/dns/certificate-exceptions",
    body: { match_kind: "fingerprint", match_value: "ab".repeat(32), reason: "our CDN" },
    call: () =>
      endpoints.createCertificateException({
        match_kind: "fingerprint",
        match_value: "ab".repeat(32),
        reason: "our CDN",
      }),
  },
  {
    name: "deleteCertificateException",
    method: "delete",
    url: `/dns/certificate-exceptions/${id}`,
    call: () => endpoints.deleteCertificateException(id),
  },
  {
    name: "connectorsHealth",
    method: "get",
    url: "/connectors/health",
    call: () => endpoints.connectorsHealth(),
  },

  // --- Assets ---------------------------------------------------------------
  {
    name: "listAssets",
    method: "get",
    url: "/assets",
    params: { page: 1, size: 50, asset_type: "domain" },
    call: () => endpoints.listAssets({ page: 1, size: 50, asset_type: "domain" }),
  },
  { name: "getAsset", method: "get", url: `/assets/${id}`, call: () => endpoints.getAsset(id) },
  {
    name: "createAsset",
    method: "post",
    url: "/assets",
    body: { asset_type: "domain", asset_value: "example.com" },
    call: () => endpoints.createAsset({ asset_type: "domain", asset_value: "example.com" }),
  },
  {
    name: "updateAsset",
    method: "patch",
    url: `/assets/${id}`,
    body: { criticality: "high" },
    call: () => endpoints.updateAsset(id, { criticality: "high" }),
  },
  {
    name: "deleteAsset",
    method: "delete",
    url: `/assets/${id}`,
    params: { cascade_findings: true },
    call: () => endpoints.deleteAsset(id, true),
  },
  {
    name: "assetFindings",
    method: "get",
    url: `/assets/${id}/findings`,
    params: { module: "dns", page: 1 },
    call: () => endpoints.assetFindings(id, { module: "dns", page: 1 }),
  },
  {
    name: "importAssets",
    method: "post",
    url: "/assets/import",
    body: { items: [{ asset_type: "domain" }], dry_run: true },
    call: () => endpoints.importAssets([{ asset_type: "domain" }], true),
  },
  {
    name: "importAssetsCsv",
    method: "post",
    url: "/assets/import/csv",
    params: { dry_run: false },
    rawBody: "asset_type,asset_value\ndomain,example.com\n",
    contentType: "text/csv",
    call: () => endpoints.importAssetsCsv("asset_type,asset_value\ndomain,example.com\n", false),
  },
  {
    name: "exportAssets",
    method: "get",
    url: "/assets/export",
    params: { asset_type: "domain", format: "csv" },
    responseType: "blob",
    call: () => endpoints.exportAssets({ asset_type: "domain", format: "csv" }),
  },
  {
    name: "bulkAssets",
    method: "post",
    url: "/assets/bulk",
    body: { operation: "deactivate", ids: [id] },
    call: () => endpoints.bulkAssets({ operation: "deactivate", ids: [id] }),
  },

  // --- Phishing, breaches and reports ---------------------------------------
  {
    name: "listPhishing",
    method: "get",
    url: "/phishing/threats",
    params: { page: 1, sort: "confidence" },
    call: () => endpoints.listPhishing({ page: 1, sort: "confidence" }),
  },
  {
    name: "updatePhishingThreat",
    method: "patch",
    url: `/phishing/threats/${id}`,
    body: { status: "investigating" },
    call: () => endpoints.updatePhishingThreat(id, { status: "investigating" }),
  },
  {
    name: "deletePhishingThreat",
    method: "delete",
    url: `/phishing/threats/${id}`,
    call: () => endpoints.deletePhishingThreat(id),
  },
  {
    name: "cleanOrphanPhishing",
    method: "post",
    url: "/phishing/threats/cleanup-orphans",
    call: () => endpoints.cleanOrphanPhishing(),
  },
  { name: "scanDnstwist", method: "post", url: "/phishing/scan/dnstwist", call: () => endpoints.scanDnstwist() },
  { name: "scanShodan", method: "post", url: "/phishing/scan/shodan", call: () => endpoints.scanShodan() },
  {
    name: "promotePhishingAsset",
    method: "post",
    url: `/phishing/threats/${id}/asset`,
    call: () => endpoints.promotePhishingAsset(id),
  },
  {
    name: "listBreaches",
    method: "get",
    url: "/breaches",
    params: { page: 1, status: "new" },
    call: () => endpoints.listBreaches({ page: 1, status: "new" }),
  },
  {
    name: "breachProviderReadiness",
    method: "get",
    url: "/breaches/provider-readiness",
    call: () => endpoints.breachProviderReadiness(),
  },
  {
    name: "requestBreachDomainVerification",
    method: "post",
    url: "/breaches/domain-verification",
    body: { domain: "example.com", action: "verify", connector: "hibp" },
    call: () =>
      endpoints.requestBreachDomainVerification({
        domain: "example.com",
        action: "verify",
        connector: "hibp",
      }),
  },
  {
    name: "updateBreach",
    method: "patch",
    url: `/breaches/${id}`,
    body: { status: "resolved" },
    call: () => endpoints.updateBreach(id, { status: "resolved" }),
  },
  {
    name: "promoteBreachAsset",
    method: "post",
    url: `/breaches/${id}/asset`,
    call: () => endpoints.promoteBreachAsset(id),
  },
  {
    name: "cleanOrphanBreaches",
    method: "post",
    url: "/breaches/cleanup-orphans",
    call: () => endpoints.cleanOrphanBreaches(),
  },
  { name: "scanBreaches", method: "post", url: "/breaches/scan", call: () => endpoints.scanBreaches() },
  {
    name: "scanBreachEmail",
    method: "post",
    url: "/breaches/scan-email",
    body: { email: "a@example.com" },
    call: () => endpoints.scanBreachEmail("a@example.com"),
  },
  {
    name: "scanBreachDomain",
    method: "post",
    url: "/breaches/scan-domain",
    body: { domain: "example.com" },
    call: () => endpoints.scanBreachDomain("example.com"),
  },
  { name: "getBreach", method: "get", url: `/breaches/${id}`, call: () => endpoints.getBreach(id) },
  { name: "deleteBreach", method: "delete", url: `/breaches/${id}`, call: () => endpoints.deleteBreach(id) },
  {
    name: "generateReport with a name",
    method: "post",
    url: "/reports/generate",
    body: { report_name: "Weekly" },
    call: () => endpoints.generateReport("Weekly"),
  },
  {
    name: "generateReport without a name",
    method: "post",
    url: "/reports/generate",
    body: { report_name: null },
    call: () => endpoints.generateReport(),
  },
  {
    name: "listReports",
    method: "get",
    url: "/reports",
    params: { page: 1, size: 20 },
    call: () => endpoints.listReports({ page: 1, size: 20 }),
  },
  {
    name: "downloadReportBlob",
    method: "get",
    url: `/reports/${id}/download`,
    responseType: "blob",
    call: () => endpoints.downloadReportBlob(id),
  },
  { name: "deleteReport", method: "delete", url: `/reports/${id}`, call: () => endpoints.deleteReport(id) },

  // --- Audit, alerts and settings -------------------------------------------
  {
    name: "listAuditLogs",
    method: "get",
    url: "/audit/logs",
    params: { page: 1, category: "auth" },
    call: () => endpoints.listAuditLogs({ page: 1, category: "auth" }),
  },
  { name: "auditIntegrity", method: "get", url: "/audit/integrity", call: () => endpoints.auditIntegrity() },
  { name: "alertQueue", method: "get", url: "/alerts/queue", call: () => endpoints.alertQueue() },
  { name: "listAuditActions", method: "get", url: "/audit/actions", call: () => endpoints.listAuditActions() },
  { name: "getSettings", method: "get", url: "/settings", call: () => endpoints.getSettings() },
  {
    name: "getRuntimeConfiguration",
    method: "get",
    url: "/settings/runtime",
    call: () => endpoints.getRuntimeConfiguration(),
  },
  {
    name: "getAlertPolicy",
    method: "get",
    url: "/settings/alert-policy",
    call: () => endpoints.getAlertPolicy(),
  },
  {
    name: "updateSettings",
    method: "put",
    url: "/settings",
    body: { alert_confidence_direct: 90 },
    call: () => endpoints.updateSettings({ alert_confidence_direct: 90 }),
  },
  {
    name: "validateTelegramChats without a chat",
    method: "post",
    url: "/settings/validate-telegram",
    body: {},
    call: () => endpoints.validateTelegramChats(),
  },
  {
    name: "validateTelegramChats with a chat",
    method: "post",
    url: "/settings/validate-telegram",
    body: { chat_id: "-100123" },
    call: () => endpoints.validateTelegramChats("-100123"),
  },
  {
    name: "sendTestTelegram without a chat",
    method: "post",
    url: "/settings/test-telegram",
    body: {},
    call: () => endpoints.sendTestTelegram(),
  },
  {
    name: "sendTestTelegram with a chat",
    method: "post",
    url: "/settings/test-telegram",
    body: { chat_id: "-100123" },
    call: () => endpoints.sendTestTelegram("-100123"),
  },
  {
    name: "sendTestEmail without a recipient",
    method: "post",
    url: "/settings/test-email",
    body: { to: null },
    call: () => endpoints.sendTestEmail(),
  },
  {
    name: "sendTestEmail with a recipient",
    method: "post",
    url: "/settings/test-email",
    body: { to: "soc@example.com" },
    call: () => endpoints.sendTestEmail("soc@example.com"),
  },

  // --- Jobs and the connector registry --------------------------------------
  {
    name: "listJobs",
    method: "get",
    url: "/jobs",
    params: { page: 1, status: "failed" },
    call: () => endpoints.listJobs({ page: 1, status: "failed" }),
  },
  { name: "getJob", method: "get", url: `/jobs/${id}`, call: () => endpoints.getJob(id) },
  { name: "deleteJob", method: "delete", url: `/jobs/${id}`, call: () => endpoints.deleteJob(id) },
  { name: "listConnectors", method: "get", url: "/connectors", call: () => endpoints.listConnectors() },
  {
    name: "listSourceAccounts",
    method: "get",
    url: "/connectors/accounts",
    call: () => endpoints.listSourceAccounts(),
  },
  {
    name: "createSourceAccount",
    method: "post",
    url: "/connectors/accounts",
    body: { source_id: "netlas", name: "primary" },
    call: () => endpoints.createSourceAccount({ source_id: "netlas", name: "primary" }),
  },
  {
    name: "approveSourceAccount",
    method: "patch",
    url: `/connectors/accounts/${id}/policy`,
    body: { approved: true, requests_per_minute: 30, daily_budget: 100 },
    call: () =>
      endpoints.approveSourceAccount(id, {
        approved: true,
        requests_per_minute: 30,
        daily_budget: 100,
      }),
  },
  {
    name: "setSourceAccountApiKey",
    method: "put",
    url: `/connectors/accounts/${id}/api-key`,
    body: { api_key: "key-material" },
    call: () => endpoints.setSourceAccountApiKey(id, "key-material"),
  },
  {
    name: "clearSourceAccountApiKey",
    method: "delete",
    url: `/connectors/accounts/${id}/api-key`,
    call: () => endpoints.clearSourceAccountApiKey(id),
  },
  {
    name: "bindConnectorAccount",
    method: "patch",
    url: `/connectors/${id}/account`,
    params: { account_id: otherId },
    call: () => endpoints.bindConnectorAccount(id, otherId),
  },
  {
    name: "setConnectorStatus",
    method: "patch",
    url: `/connectors/${id}/status`,
    body: { status: "disabled" },
    call: () => endpoints.setConnectorStatus(id, "disabled"),
  },
  {
    name: "setConnectorConfig",
    method: "patch",
    url: `/connectors/${id}/config`,
    body: { api_key: "***" },
    call: () => endpoints.setConnectorConfig(id, { api_key: "***" }),
  },
];

function jsonBody(config: AxiosRequestConfig): unknown {
  if (config.data === undefined || config.data === null || config.data === "") return undefined;
  if (typeof config.data !== "string") return config.data;
  try {
    return JSON.parse(config.data);
  } catch {
    return config.data;
  }
}

describe("the SPA's endpoint map", () => {
  const originalAdapter = api.defaults.adapter;

  afterEach(() => {
    api.defaults.adapter = originalAdapter;
  });

  async function capture(call: () => Promise<unknown>): Promise<AxiosRequestConfig> {
    let captured: AxiosRequestConfig | undefined;
    api.defaults.adapter = async (config) => {
      captured = config;
      return {
        data: config.responseType === "blob" ? new Blob(["body"]) : {},
        status: 200,
        statusText: "OK",
        headers: {},
        config: config as never,
      };
    };
    await call();
    if (!captured) throw new Error("the endpoint made no request");
    return captured;
  }

  it.each(cases.map((entry) => [entry.name, entry] as const))(
    "%s sends the method, path and arguments the API expects",
    async (_name, entry) => {
      const received = await capture(entry.call);

      expect(String(received.method).toLowerCase()).toBe(entry.method);
      expect(received.url).toBe(entry.url);

      if (entry.params) {
        expect(received.params).toEqual(entry.params);
      } else {
        expect(received.params ?? {}).toEqual({});
      }

      if (entry.rawBody !== undefined) {
        expect(received.data).toBe(entry.rawBody);
        expect(String(received.headers?.["Content-Type"])).toContain(entry.contentType);
      } else if (entry.body !== undefined) {
        expect(jsonBody(received)).toEqual(entry.body);
        expect(String(received.headers?.["Content-Type"])).toContain("application/json");
      } else {
        // Axios serializes an explicit `null` body as the string "null"; either
        // spelling means this request carries no payload.
        expect(jsonBody(received) ?? null).toBeNull();
      }

      if (entry.responseType) {
        expect(received.responseType).toBe(entry.responseType);
      }
    },
  );

  it("every declared endpoint has a row here", () => {
    // A new helper with no row is not covered by this file, and the floor in
    // vite.config.ts is what turns that into a failing build rather than a gap
    // somebody has to notice.
    const named = new Set(cases.map((entry) => entry.name.split(" ")[0]));
    // Signing out is asserted by its own test below, because it is the one helper
    // whose contract includes swallowing a transport failure.
    named.add("logout");
    const missing = Object.keys(endpoints).filter((name) => !named.has(name));
    expect(missing).toEqual([]);
  });

  it("signing out reaches the API and still resolves when it cannot", async () => {
    const sent = await capture(() => endpoints.logout());
    expect(sent.method).toBe("post");
    expect(sent.url).toBe("/auth/logout");

    api.defaults.adapter = async () => {
      throw new Error("network down");
    };
    // The local session is cleared by the caller; failing to revoke it on the
    // server must not make the page report a sign-out that did not happen.
    await expect(endpoints.logout()).resolves.toBeUndefined();
  });
});
