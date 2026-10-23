import axios, {
  type AxiosInstance,
  type AxiosRequestConfig,
  type InternalAxiosRequestConfig,
} from "axios";
import type {
  AuditActionsCatalog,
  AuditIntegrity,
  AuditLogRow,
  AlertQueueSummary,
  CleanupResult,
  ExposurePage,
  ExposureTriageResult,
  PhishingEvidenceResponse,
  PromotedAsset,
  QueryParams,
  RevokedSessions,
  ScanStartResult,
  TestEmailResult,
  TestTelegramResult,
  UserBrief,
  Job,
  AlertPolicy,
  Asset,
  AssetBulkResult,
  AssetCriticality,
  AssetFindingsResponse,
  AssetImportReport,
  AuthSession,
  Breach,
  BreachList,
  BreachProviderReadiness,
  CertificateExceptionKind,
  CertificateScopeException,
  CertificateScopeExceptionCreated,
  Connector,
  ConnectorHealthResponse,
  DNSObservation,
  DashboardOverview,
  MfaSetup,
  MfaStatus,
  Paginated,
  PhishingThreat,
  PhishingVerdict,
  Report,
  RuntimeConfiguration,
  SecurityActivity,
  SourceAccount,
  SystemSettings,
  TLSCertificate,
  TLSSightingVerdict,
  TelegramChatValidationResponse,
  ThreatStatus,
  TokenResponse,
  User,
  UserRole,
} from "@/types/api";
import {
  sessionAdopt,
  sessionClear,
  sessionPresent,
  sessionToken,
} from "@/lib/session-bridge";

const VITE_API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "/api/v1";

/**
 * Marks the request that asks the API whether this browser has a session at all.
 *
 * Its `401` is an answer, not a failure: every anonymous visitor gets one. The
 * interceptor treats it differently for that reason — see `clearAuth`.
 */
const SESSION_RESTORE = { _sessionRestore: true } as AxiosRequestConfig;

/**
 * Marks a request whose `401` is the API refusing the credential *in the request*
 * rather than the session.
 *
 * These routes verify something the operator typed: the current password, a
 * second-factor code, an invitation token. The API answers a wrong value with
 * `401` — `"Current password is incorrect"`, `"Invalid MFA code"`, `"This
 * invitation is invalid or has expired"` (`app/api/v1/routers/auth.py`) — which is
 * the same status an expired access token gets. Without this marker the
 * interceptor cannot tell the two apart, and it used to treat every one of them
 * as a lost session: it cleared a valid one, announced "Session expired", and
 * navigated the operator away from the form they were filling in — taking the
 * enrolment secret with it. Retrying is equally wrong: no refreshed token makes a
 * wrong password right.
 *
 * `logout` carries it for the mirror-image reason: its `401` means the refresh
 * cookie had already lapsed, which is the outcome the operator asked for, so
 * announcing an expired session after a deliberate sign-out explains it wrongly.
 */
const CREDENTIAL_CHECK = { _credentialCheck: true } as AxiosRequestConfig;

export const api: AxiosInstance = axios.create({
  baseURL: VITE_API_BASE_URL,
  // Above both the default DB statement (30 s) and async command (45 s)
  // timeouts, allowing the API to return its structured timeout response.
  timeout: 50_000,
  withCredentials: true,
  headers: { "Content-Type": "application/json" },
});

function csrfToken() {
  try {
    return document.cookie
      .split(";")
      .map((v) => v.trim())
      .find((v) => v.startsWith("opendrp_csrf="))
      ?.slice("opendrp_csrf=".length) || null;
  } catch {
    return null;
  }
}

/**
 * Forget the session in this browser.
 *
 * The announcement is what tells the router to explain the sign-out and to take
 * the operator to the sign-in page, so it is the default. The boot-time session
 * restore turns it off: there the `401` means "this browser has no session",
 * which is the normal state of every anonymous visitor, and announcing it would
 * tell somebody who never signed in that their session had expired. The session
 * is still dropped locally in both cases — it is only the explanation that is
 * withheld.
 */
function clearAuth({ announce = true }: { announce?: boolean } = {}) {
  sessionClear();
  if (announce) window.dispatchEvent(new Event("auth:unauthorized"));
}

/**
 * Whether a response is the API refusing an admin route because the deployment
 * requires a second factor and this account has none.
 *
 * The marker is the literal `mfa_required` token in the detail, which the API
 * puts there deliberately (app/api/deps.py). It is matched as a token rather
 * than as prose so that rewording the human-readable sentence cannot silently
 * disable the client-side handling, and a plain `403` is not enough to trigger
 * it: an administrator who simply lacks the role gets a 403 too, and sending
 * them to the security page would be advice they cannot act on.
 */
export function isMfaRequiredError(error: unknown): boolean {
  const err = error as { response?: { status?: number; data?: { detail?: unknown } } } | undefined;
  if (err?.response?.status !== 403) return false;
  const detail = err.response.data?.detail;
  return typeof detail === "string" && detail.includes("mfa_required");
}

/**
 * Whether a response is the API refusing everything because this account still
 * owes a credential step: a password somebody else chose, or a second factor
 * that was cleared for it.
 *
 * Same contract as `isMfaRequiredError` — a token, not prose, and a `403` rather
 * than any error, so a genuine permission refusal is never mistaken for a
 * situation the account holder can fix by themselves.
 */
export function isOnboardingRequiredError(error: unknown): boolean {
  const err = error as { response?: { status?: number; data?: { detail?: unknown } } } | undefined;
  if (err?.response?.status !== 403) return false;
  const detail = err.response.data?.detail;
  return typeof detail === "string" && detail.includes("onboarding_required");
}

/**
 * A correlation id for one request, sent as `X-Request-ID`.
 *
 * The backend validates it, returns it in the response and writes it into the
 * `details` of every audit row the request causes, so a screenshot of a failure
 * is enough to find the matching server-side record. This is an identifier, not
 * a secret: no security decision depends on it, which is why the `Math.random`
 * fallback for contexts without `crypto.randomUUID` is acceptable, and why it is
 * not derived from anything the client considers sensitive.
 */
function newRequestId(): string {
  const cryptoObj = globalThis.crypto;
  if (cryptoObj && typeof cryptoObj.randomUUID === "function") {
    return `web-${cryptoObj.randomUUID().replace(/-/g, "").slice(0, 24)}`;
  }
  return `web-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 10)}`;
}

api.interceptors.request.use((config) => {
  config.headers = config.headers || {};
  // Set before anything can fail, so the id is available to quote even when the
  // request never reaches the API (a proxy error, a timeout, a dropped network).
  config.headers["X-Request-ID"] = newRequestId();

  // Access tokens are intentionally memory-only, and this is the only reader:
  // never trust a token read from browser storage, even if a stale or forged
  // entry exists there. The store registers itself with the bridge at import
  // time (see lib/session-bridge.ts), so this is defined before any request.
  const token = sessionToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }

  const csrf = csrfToken();
  if (csrf && ["post", "put", "patch", "delete"].includes(String(config.method).toLowerCase())) {
    config.headers["X-CSRF-Token"] = csrf;
  }
  return config;
});

let refreshInFlight: Promise<TokenResponse | null> | null = null;

/**
 * Ask the API whether this browser still has a session, at most once at a time.
 *
 * Two callers need this and they can overlap: the boot restore in `main.tsx`, and
 * the interceptor below retrying a request that came back `401`. Two concurrent
 * refreshes are not merely wasteful — the refresh token is rotated on use, so the
 * second presentation of the same token reads as re-use and revokes the whole
 * family, signing the operator out of the tab that was working. One in-flight
 * promise, one request, and both callers see the same answer.
 *
 * The `401` is not a failure here: it is the answer for every anonymous visitor,
 * which is why the request carries `SESSION_RESTORE` and the interceptor keeps
 * quiet about it. A session that *was* in use and could not be refreshed is
 * announced by whoever asked, not by this function.
 *
 * The answer is handed to the store through the bridge rather than returned to be
 * re-applied, so both callers are looking at one session and not two copies.
 */
export function restoreSession(): Promise<TokenResponse | null> {
  if (!refreshInFlight) {
    refreshInFlight = api
      // The refresh credential is HttpOnly, so this browser sends no body at
      // all; the API's optional body exists for callers that hold a token
      // deliberately (a script or an integration), not for this one.
      .post<TokenResponse>("/auth/refresh", undefined, SESSION_RESTORE)
      .then(({ data }) => {
        sessionAdopt(data);
        return data;
      })
      .catch(() => null)
      .finally(() => {
        refreshInFlight = null;
      });
  }
  return refreshInFlight;
}

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error?.config as
      | (InternalAxiosRequestConfig & {
          _authRetry?: boolean;
          _sessionRestore?: boolean;
          _credentialCheck?: boolean;
        })
      | undefined;
    if (error?.response?.status !== 401 || !original || original._authRetry) {
      // Not a session problem, so nothing was cleared: the account is signed in and
      // merely not yet allowed. Announced so the router can offer the page that
      // fixes it, while the caller still receives its rejected promise. Both `403`
      // gates land on the same page, and what the operator is told there comes from
      // the API — every user payload says which step is owed — so this event only
      // decides which of the two situations to explain.
      if (isOnboardingRequiredError(error))
        window.dispatchEvent(new Event("auth:onboarding-required"));
      else if (isMfaRequiredError(error)) window.dispatchEvent(new Event("auth:mfa-required"));
      return Promise.reject(error);
    }

    // The credential in this request was refused, not the session: there is
    // nothing here to refresh and nothing to sign out of. The caller shows the
    // API's own sentence beside the field that produced it (see the tests that
    // pin the wrong-password, wrong-code, lapsed-invitation and sign-out cases).
    if (original._credentialCheck) {
      return Promise.reject(error);
    }

    const hasSession = sessionPresent();
    // The refresh token is HttpOnly and therefore deliberately absent from
    // document.cookie. A session in the auth store is the client-side signal that
    // a cookie worth presenting exists; the API decides whether it is still valid.
    // Never retry auth endpoints to avoid a refresh loop.
    if (!hasSession || String(original.url || "").includes("/auth/")) {
      clearAuth({ announce: !original._sessionRestore });
      return Promise.reject(error);
    }

    try {
      const restored = await restoreSession();
      const token = restored?.access_token;
      if (!token) throw error;
      original._authRetry = true;
      original.headers = original.headers || {};
      original.headers.Authorization = `Bearer ${token}`;
      return api(original);
    } catch {
      clearAuth();
      return Promise.reject(error);
    }
  },
);

export function flattenErrorDetail(detail: unknown): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((item) => item && typeof item === "object" && "msg" in item ? String((item as { msg: unknown }).msg) : String(item))
      .join("; ");
  }
  if (detail && typeof detail === "object") return Object.values(detail as Record<string, unknown>).map(String).join("; ");
  return "";
}

/**
 * Operator-facing description of a failed API call.
 *
 * FastAPI answers a schema violation with `detail` set to a *list* of objects.
 * Handing that raw value to a React node (a toast description, an error state)
 * throws during render and takes the whole page down, so every error surface
 * uses this helper instead of reading `detail` directly.
 */
/**
 * The correlation id to quote for a failed call.
 *
 * Read from the response when there is one, and otherwise from the request that
 * was sent: an error that never reached the API still has an identifier worth
 * reporting, and a proxy-generated failure has no server response at all.
 */
export function apiErrorReference(error: unknown): string | undefined {
  const err = error as
    | {
        response?: { headers?: Record<string, unknown> };
        config?: { headers?: Record<string, unknown> };
      }
    | undefined;
  const fromResponse = err?.response?.headers?.["x-request-id"];
  if (typeof fromResponse === "string" && fromResponse) return fromResponse;
  const fromRequest = err?.config?.headers?.["X-Request-ID"];
  if (typeof fromRequest === "string" && fromRequest) return fromRequest;
  return undefined;
}

export function describeApiError(
  error: unknown,
  fallback = "The request failed. Please try again.",
): string {
  const err = error as
    | { response?: { status?: number; data?: { detail?: unknown } }; message?: string }
    | undefined;
  const status = err?.response?.status;
  const responseData = err?.response?.data as { detail?: unknown; code?: unknown } | undefined;
  const detail = flattenErrorDetail(responseData?.detail);

  let message: string;
  if (responseData?.code === "database_busy") {
    message = "The database stopped this query because it took too long. Narrow the search or retry shortly.";
  } else if (responseData?.code === "query_deadline_exceeded") {
    // A deliberate server-side deadline, not a network failure (AST-50): the
    // same request can succeed once the filter is narrower.
    message = "This query took longer than the server's time budget. Narrow the filter and try again.";
  } else if (detail) message = detail;
  else if (status === 401) message = "Your session has expired. Please sign in again.";
  else if (status === 403) message = "You do not have permission to perform this action.";
  else if (status === 404) message = "The requested item no longer exists. Refresh the list.";
  else if (status === 429) message = "Rate limit reached. Please wait before trying again.";
  else if (status && status >= 500)
    message = "The server reported an error. Please retry shortly.";
  else message = err?.message || fallback;

  // Appended here rather than at each call site: every error surface in the UI
  // already routes through this helper, so one change puts the reference in
  // front of the operator everywhere.
  const reference = apiErrorReference(error);
  return reference ? `${message} (Reference: ${reference})` : message;
}

export const endpoints = {
  // `totpCode` is only sent when the account has a second factor and the user
  // has supplied one; the first attempt deliberately omits it, so an account
  // without MFA never sees a code prompt.
  login: (email: string, password: string, totpCode?: string, recoveryCode?: string) =>
    api
      .post<TokenResponse>("/auth/login", {
        email,
        password,
        ...(totpCode ? { totp_code: totpCode } : {}),
        ...(recoveryCode ? { recovery_code: recoveryCode } : {}),
      })
      .then((r) => r.data),
  changePassword: (currentPassword: string, newPassword: string) =>
    api
      .post<TokenResponse>(
        "/auth/password",
        { current_password: currentPassword, new_password: newPassword },
        CREDENTIAL_CHECK,
      )
      .then((r) => r.data),
  mfaStatus: () => api.get<MfaStatus>("/auth/mfa").then((r) => r.data),
  mfaSetup: (password: string) =>
    api.post<MfaSetup>("/auth/mfa/setup", { password }, CREDENTIAL_CHECK).then((r) => r.data),
  mfaQr: () => api.get<Blob>("/auth/mfa/qr", { responseType: "blob" }).then((r) => r.data),
  mfaEnable: (password: string, code: string) =>
    api
      .post<MfaStatus>("/auth/mfa/enable", { password, code }, CREDENTIAL_CHECK)
      .then((r) => r.data),
  mfaDisable: (password: string, code: string) =>
    api
      .post<MfaStatus>("/auth/mfa/disable", { password, code }, CREDENTIAL_CHECK)
      .then((r) => r.data),
  mfaRotateRecoveryCodes: (password: string, code: string) =>
    api
      .post<{ codes: string[] }>(
        "/auth/mfa/recovery-codes/rotate",
        { password, code },
        CREDENTIAL_CHECK,
      )
      .then((r) => r.data),
  listSessions: () => api.get<AuthSession[]>("/auth/sessions").then((r) => r.data),
  revokeSession: (id: string) => api.delete<void>(`/auth/sessions/${id}`).then(() => undefined),
  revokeOtherSessions: () => api.post<RevokedSessions>("/auth/sessions/revoke-others").then((r) => r.data),
  securityActivity: () => api.get<SecurityActivity[]>("/auth/security-activity").then((r) => r.data),
  resetUserMfa: (id: string) => api.post<User>(`/users/${id}/mfa/reset`).then((r) => r.data),
  // Releases the password lockout only; the API refuses an account that is not
  // locked, so the UI never has to guess whether the button is meaningful.
  unlockUser: (id: string) => api.post<User>(`/users/${id}/unlock`).then((r) => r.data),
  inviteUser: (data: { email: string; role: string; full_name?: string; rate_limit_minutes?: number }) =>
    api.post<{ user: User; invitation_token: string; expires_at: string; email_scheduled: boolean }>(
      "/users/invite",
      data,
    ).then((r) => r.data),
  reissueInvitation: (id: string) =>
    api.post<{ user: User; invitation_token: string; expires_at: string; email_scheduled: boolean }>(
      `/users/${id}/invitation`,
    ).then((r) => r.data),
  acceptInvitation: (token: string, newPassword: string) =>
    api
      .post<{ status: string }>(
        "/auth/accept-invitation",
        { token, new_password: newPassword },
        CREDENTIAL_CHECK,
      )
      .then((r) => r.data),
  me: () => api.get<User>("/auth/me").then((r) => r.data),
  // Signing out has to happen on both sides. Revoking only in the browser would
  // leave the refresh cookie valid for its whole lifetime, and the next load —
  // which asks the API rather than the browser — would restore the session the
  // operator just ended. This half is the server's; clearing the client is the
  // caller's, which is why every caller clears locally *first* and then calls
  // this. Failing to reach the API costs the server-side revocation, and that is
  // the part worth reporting — not a reason to stay signed in.
  logout: async () => {
    try {
      await api.post<void>("/auth/logout", undefined, CREDENTIAL_CHECK);
    } catch {
      // Handled above: the local session goes either way.
    }
  },
  scanModule: (module: string) => api.post<ScanStartResult>(`/modules/${encodeURIComponent(module)}/scan`).then((r) => r.data),
  listExposure: (params: { page: number; size: number; source?: string }) =>
    api.get<ExposurePage>("/exposure/observations", { params }).then((r) => r.data),
  updateExposure: (id: string, status: "observed" | "investigating" | "resolved") =>
    api.patch<ExposureTriageResult>(`/exposure/observations/${id}`, { status }).then((r) => r.data),
  promoteExposureObservation: (id: string) =>
    api.post<PromotedAsset>(`/exposure/observations/${id}/asset`).then((r) => r.data),
  phishingEvidence: (id: string) =>
    api.get<PhishingEvidenceResponse>(`/phishing/threats/${id}/evidence`).then((r) => r.data),
  // One request, one audit row: the page used to ask `/dashboard/stats`,
  // `/connectors/health` and `/alerts/health`, each in its own transaction
  // (DHP-10). `connectorsHealth` stays because DNS Security reads it.
  dashboardOverview: () =>
    api.get<DashboardOverview>("/dashboard/overview").then((r) => r.data),
  listDNSObservations: (params: QueryParams) =>
    api.get<Paginated<DNSObservation>>("/dns/observations", { params }).then((r) => r.data),
  scanDNSSecurity: () => api.post<ScanStartResult>("/dns/scan").then((r) => r.data),
  cleanOrphanDNSObservations: () => api.post<CleanupResult>("/dns/observations/cleanup-orphans").then((r) => r.data),
  promoteDNSObservation: (id: string, target?: string) =>
    api.post<PromotedAsset>(`/dns/observations/${id}/asset`, { target }).then((r) => r.data),
  deleteDNSObservation: (id: string, value?: string | null) =>
    api.delete<void>(`/dns/observations/${id}`, { params: { value } }).then(() => undefined),
  listTLSCertificates: (params: { verdict?: TLSSightingVerdict; foreign_only?: boolean; page?: number; size?: number }) =>
    api
      .get<Paginated<TLSCertificate>>("/dns/certificates", { params })
      .then((r) => r.data),
  reviewTLSSighting: (sightingId: string, payload: { verdict: TLSSightingVerdict; note?: string | null }) =>
    api
      .patch<{ id: string; verdict: TLSSightingVerdict; reviewed_at: string | null }>(
        `/dns/certificates/sightings/${sightingId}`,
        payload,
      )
      .then((r) => r.data),
  listCertificateExceptions: () =>
    api.get<CertificateScopeException[]>("/dns/certificate-exceptions").then((r) => r.data),
  createCertificateException: (payload: {
    match_kind: CertificateExceptionKind;
    match_value: string;
    reason?: string | null;
    expires_at?: string | null;
  }) =>
    api
      .post<CertificateScopeExceptionCreated>("/dns/certificate-exceptions", payload)
      .then((r) => r.data),
  deleteCertificateException: (id: string) =>
    api.delete<void>(`/dns/certificate-exceptions/${id}`).then(() => undefined),
  connectorsHealth: () => api.get<ConnectorHealthResponse>("/connectors/health").then((r) => r.data),
  listAssets: (params: QueryParams) =>
    api.get<Paginated<Asset>>("/assets", { params }).then((r) => r.data),
  // WI-12/AST-44: the asset's own record, read once when its page opens. The
  // findings view used to be the only request that page made, so `asset.view`
  // was never written and the page could not show criticality or the dates.
  getAsset: (id: string) => api.get<Asset>(`/assets/${id}`).then((r) => r.data),
  createAsset: (data: Partial<Asset>) => api.post<Asset>("/assets", data).then((r) => r.data),
  updateAsset: (id: string, data: Partial<Asset>) =>
    api.patch<Asset>(`/assets/${id}`, data).then((r) => r.data),
  deleteAsset: (id: string, cascadeFindings = false) =>
    api.delete<void>(`/assets/${id}`, { params: { cascade_findings: cascadeFindings } }).then(() => ({})),
  assetFindings: (id: string, params: QueryParams) =>
    api.get<AssetFindingsResponse>(`/assets/${id}/findings`, { params }).then((r) => r.data),
  // WI-18: a batch in, a file out. The import report is the response body (one
  // entry per line, so the UI can show where a failure is); the export asks for
  // the raw body so the caller can hand it to the browser as a download.
  importAssets: (items: unknown[], dryRun: boolean) =>
    api.post<AssetImportReport>("/assets/import", { items, dry_run: dryRun }).then((r) => r.data),
  importAssetsCsv: (csv: string, dryRun: boolean) =>
    api
      .post<AssetImportReport>("/assets/import/csv", csv, {
        params: { dry_run: dryRun },
        headers: { "Content-Type": "text/csv" },
      })
      .then((r) => r.data),
  exportAssets: (params: QueryParams) =>
    api.get<Blob>("/assets/export", { params, responseType: "blob" }).then((r) => r.data),
  bulkAssets: (payload: { ids: string[]; operation?: string; criticality?: AssetCriticality; cascade_findings?: boolean }) =>
    api.post<AssetBulkResult>("/assets/bulk", payload).then((r) => r.data),
  listPhishing: (params: QueryParams) =>
    api.get<Paginated<PhishingThreat>>("/phishing/threats", { params }).then((r) => r.data),
  updatePhishingThreat: (id: string, data: { status?: ThreatStatus; verdict?: PhishingVerdict | null; verdict_reason?: string }) =>
    api.patch<PhishingThreat>(`/phishing/threats/${id}`, data).then((r) => r.data),
  deletePhishingThreat: (id: string) =>
    api.delete<void>(`/phishing/threats/${id}`).then(() => ({})),
  cleanOrphanPhishing: () =>
    api.post<CleanupResult>("/phishing/threats/cleanup-orphans").then((r) => r.data),
  scanDnstwist: () => api.post<ScanStartResult>("/phishing/scan/dnstwist").then((r) => r.data),
  scanShodan: () => api.post<ScanStartResult>("/phishing/scan/shodan").then((r) => r.data),
  listBreaches: (params: QueryParams) => api.get<BreachList>("/breaches", { params }).then((r) => r.data),
  breachProviderReadiness: () =>
    api.get<BreachProviderReadiness>("/breaches/provider-readiness").then((r) => r.data),
  // A verification request is an operator's step, not a scan: it names one domain, one
  // action and (when several sources could be asked) one source, and answers 202 with
  // the job ids so the page can wait for the worker's attempt to land.
  requestBreachDomainVerification: (payload: {
    domain: string;
    action: "generate" | "verify";
    connector?: string | null;
  }) =>
    api
      .post<{
        status: string;
        domain: string;
        action: "generate" | "verify";
        job_ids: string[];
        error?: string;
      }>("/breaches/domain-verification", payload)
      .then((r) => r.data),
  updateBreach: (id: string, data: { status: ThreatStatus }) =>
    api.patch<Breach>(`/breaches/${id}`, data).then((r) => r.data),
  // AWI-13/U-1: take the mailbox (or domain) a finding names under monitoring.
  promoteBreachAsset: (id: string) =>
    api.post<PromotedAsset>(`/breaches/${id}/asset`).then((r) => r.data),
  promotePhishingAsset: (id: string) =>
    api.post<PromotedAsset>(`/phishing/threats/${id}/asset`).then((r) => r.data),
  cleanOrphanBreaches: () =>
    api.post<CleanupResult>("/breaches/cleanup-orphans").then((r) => r.data),
  scanBreaches: () => api.post<ScanStartResult>("/breaches/scan").then((r) => r.data),
  scanBreachEmail: (email: string) =>
    api.post<ScanStartResult>("/breaches/scan-email", { email }).then((r) => r.data),
  scanBreachDomain: (domain: string) =>
    api.post<ScanStartResult>("/breaches/scan-domain", { domain }).then((r) => r.data),
  getBreach: (id: string) => api.get<Breach>(`/breaches/${id}`).then((r) => r.data),
  deleteBreach: (id: string) => api.delete<void>(`/breaches/${id}`).then(() => ({})),
  generateReport: (name?: string) => api.post<{ status: "scheduled"; queue_state: "queued"; report_id: string; job_id: string }>("/reports/generate", { report_name: name ?? null }).then((r) => r.data),
  listReports: (params: QueryParams) =>
    api.get<Paginated<Report>>("/reports", { params }).then((r) => r.data),
  downloadReportBlob: (id: string) =>
    api.get<Blob>(`/reports/${id}/download`, { responseType: "blob" }).then((r) => r.data),
  deleteReport: (id: string) => api.delete<void>(`/reports/${id}`).then(() => ({})),
  listUsers: (params: QueryParams) =>
    api.get<Paginated<User>>("/users", { params }).then((r) => r.data),
  // The same filters as the list, rendered as a file for access review. A blob,
  // not parsed JSON: the browser saves what the server produced.
  exportUsers: (params: QueryParams) =>
    api.get<Blob>("/users/export", { params, responseType: "blob" }).then((r) => r.data),
  listUserSessions: (id: string) =>
    api.get<AuthSession[]>(`/users/${id}/sessions`).then((r) => r.data),
  revokeUserSessions: (id: string) =>
    api.delete<RevokedSessions>(`/users/${id}/sessions`).then((r) => r.data),
  bulkUsers: (payload: { operation: "activate" | "deactivate"; user_ids: string[] }) =>
    api.post<{ operation: string; changed: number; skipped: number; revoked_sessions: number }>("/users/bulk", payload).then((r) => r.data),
  createUser: (data: { email: string; role: UserRole; full_name?: string; password?: string; rate_limit_minutes?: number }) =>
    api.post<User>("/users", data).then((r) => r.data),
  getUser: (id: string) => api.get<User>(`/users/${id}`).then((r) => r.data),
  updateUser: (id: string, data: Partial<User> & { password?: string }) =>
    api.put<User>(`/users/${id}`, data).then((r) => r.data),
  deleteUser: (id: string) => api.delete<void>(`/users/${id}`).then(() => ({})),
  listAuditLogs: (params: QueryParams) =>
    api.get<Paginated<AuditLogRow>>("/audit/logs", { params }).then((r) => r.data),
  auditIntegrity: () => api.get<AuditIntegrity>("/audit/integrity").then((r) => r.data),
  alertQueue: () => api.get<AlertQueueSummary>("/alerts/queue").then((r) => r.data),
  listAuditActions: () => api.get<AuditActionsCatalog>("/audit/actions").then((r) => r.data),
  getSettings: () => api.get<SystemSettings>("/settings").then((r) => r.data),
  getRuntimeConfiguration: () =>
    api.get<RuntimeConfiguration>("/settings/runtime").then((r) => r.data),
  getAlertPolicy: () => api.get<AlertPolicy>("/settings/alert-policy").then((r) => r.data),
  updateSettings: (data: Record<string, unknown>) =>
    api.put<SystemSettings>("/settings", data).then((r) => r.data),
  listUsersBrief: () => api.get<UserBrief[]>("/users/brief").then((r) => r.data),
  validateTelegramChats: (chatId?: string) =>
    api
      .post<TelegramChatValidationResponse>(
        "/settings/validate-telegram",
        chatId ? { chat_id: chatId } : {},
      )
      .then((r) => r.data),
  sendTestTelegram: (chatId?: string) =>
    api
      .post<TestTelegramResult>("/settings/test-telegram", chatId ? { chat_id: chatId } : {})
      .then((r) => r.data),
  sendTestEmail: (to?: string) =>
    api.post<TestEmailResult>("/settings/test-email", { to: to ?? null }).then((r) => r.data),
  deleteJob: (id: string) => api.delete<void>(`/jobs/${id}`).then(() => ({})),
  listJobs: (params: QueryParams) =>
    api.get<Paginated<Job>>("/jobs", { params }).then((r) => r.data),
  getJob: (id: string) => api.get<Job>(`/jobs/${id}`).then((r) => r.data),
  listConnectors: () => api.get<Connector[]>("/connectors").then((r) => r.data),
  listSourceAccounts: () => api.get<SourceAccount[]>("/connectors/accounts").then((r) => r.data),
  createSourceAccount: (data: { source_id: string; name: string; credential_ref?: string }) => api.post<{ id: string }>("/connectors/accounts", data).then((r) => r.data),
  approveSourceAccount: (id: string, policy: { approved: boolean; requests_per_minute: number; daily_budget: number }) => api.patch<{ id: string; policy: SourceAccount["policy"] }>(`/connectors/accounts/${id}/policy`, policy).then((r) => r.data),
  setSourceAccountApiKey: (id: string, apiKey: string) => api.put<{ id: string; has_api_key: boolean; api_key_hint: string | null }>(`/connectors/accounts/${id}/api-key`, { api_key: apiKey }).then((r) => r.data),
  clearSourceAccountApiKey: (id: string) => api.delete<{ id: string; has_api_key: boolean; api_key_hint: string | null }>(`/connectors/accounts/${id}/api-key`).then((r) => r.data),
  bindConnectorAccount: (connectorId: string, accountId: string) =>
    api
      .patch<Connector>(`/connectors/${connectorId}/account`, null, {
        params: { account_id: accountId },
      })
      .then((r) => r.data),
  setConnectorStatus: (id: string, status: "enabled" | "disabled") =>
    api.patch<Connector>(`/connectors/${id}/status`, { status }).then((r) => r.data),
  setConnectorConfig: (id: string, config: Record<string, unknown>) =>
    api.patch<Connector>(`/connectors/${id}/config`, config).then((r) => r.data),
};
