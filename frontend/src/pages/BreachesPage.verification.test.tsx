/**
 * Verifying a domain is an operator's step (WI-20).
 *
 * A refused domain is only actionable if the page says what to do about it, so the
 * readiness card offers the two steps beside each domain, shows the record the source
 * issued exactly as the source stated it, and — when no scan has finished yet — still
 * shows the attempt, because a TXT value nobody can see is a step nobody can take.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import BreachesPage from "@/pages/BreachesPage";
import { useAuthStore } from "@/store/auth";

vi.mock("@/components/ui/select", () => ({
  Select: ({ value, onValueChange, children }: any) => (
    <select value={value} onChange={(event) => onValueChange(event.target.value)}>
      {children}
    </select>
  ),
  SelectTrigger: () => null,
  SelectValue: () => null,
  SelectContent: ({ children }: any) => children,
  SelectItem: ({ value, children }: any) => <option value={value}>{children}</option>,
}));

// The page follows a verification job to its answer; a stub keeps the test off the wire
// while leaving the request the page makes untouched.
vi.mock("@/lib/scanPolling", () => ({
  waitForScanJobs: vi.fn(async () => []),
  summarizeScanJobs: () => ({ succeeded: 0, failed: 0, pending: 1 }),
}));

const mocks = vi.hoisted(() => ({
  list: vi.fn(),
  readiness: vi.fn(),
  verify: vi.fn(),
  toast: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  endpoints: {
    listBreaches: mocks.list,
    breachProviderReadiness: mocks.readiness,
    requestBreachDomainVerification: mocks.verify,
    scanBreaches: vi.fn(),
    updateBreach: vi.fn(),
    deleteBreach: vi.fn(),
    cleanOrphanBreaches: vi.fn(),
  },
  flattenErrorDetail: (detail: unknown) => String(detail ?? ""),
  describeApiError: (error: any) => String(error?.message ?? error ?? ""),
}));
vi.mock("@/components/JobsTable", () => ({ JobsTable: () => null }));
vi.mock("@/components/ui/use-toast", () => ({ toast: mocks.toast }));
vi.mock("@/components/ui/confirm-dialog", () => ({ ConfirmDialog: () => null }));
vi.mock("@/components/DataTable", () => ({ PaginatedDataTable: () => null }));

function ready(overrides: Record<string, unknown> = {}) {
  return {
    scan_job_id: "scan-1",
    connector: "source-a",
    scanned_at: "2026-01-02T00:00:00Z",
    status: "partial",
    partial: true,
    reasons: {},
    entitlements: null,
    pacing: {},
    domains: [
      { domain: "acme.test", status: "unscanned", reason: "domain_not_verified" },
      { domain: "beta.test", status: "asked", reason: null },
    ],
    unscanned_total: 1,
    data_class_labels: {},
    verifications: [],
    ...overrides,
  };
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <BreachesPage />
    </QueryClientProvider>,
  );
}

describe("BreachesPage domain verification", () => {
  beforeEach(() => {
    mocks.list.mockReset().mockResolvedValue({
      items: [],
      total: 0,
      page: 1,
      size: 20,
      pages: 0,
      unannounced: 0,
      new_since: null,
    });
    mocks.readiness.mockReset().mockResolvedValue(ready());
    mocks.verify.mockReset().mockResolvedValue({ status: "scheduled", domain: "acme.test", action: "generate", job_ids: ["job-1"] });
    mocks.toast.mockReset();
    useAuthStore.getState().clearAuth();
    useAuthStore.setState({
      user: {
        id: "analyst-1",
        email: "analyst@example.com",
        role: "analyst",
        is_active: true,
        rate_limit_minutes: 0,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      },
      token: "access-token",
      isHydrated: true,
    });
  });

  it("asks the source that ran the last scan to issue a record for the domain", async () => {
    renderPage();

    fireEvent.click((await screen.findAllByRole("button", { name: "Get DNS record" }))[0]);

    await waitFor(() => expect(mocks.verify).toHaveBeenCalledTimes(1));
    // Naming the source matters: a verification belongs to one source's account, so
    // the page sends the one whose readiness it is showing rather than letting the API
    // guess between several.
    expect(mocks.verify).toHaveBeenCalledWith({ domain: "acme.test", action: "generate", connector: "source-a" });
  });

  it("checks a published record without issuing a new one", async () => {
    renderPage();

    fireEvent.click((await screen.findAllByRole("button", { name: "Check DNS now" }))[0]);

    await waitFor(() =>
      expect(mocks.verify).toHaveBeenCalledWith({ domain: "acme.test", action: "verify", connector: "source-a" }),
    );
  });

  it("shows the record exactly as the source stated it, beside why it was refused", async () => {
    mocks.readiness.mockResolvedValue(
      ready({
        verifications: [
          {
            domain: "acme.test",
            action: "generate",
            status: "generated",
            reason: null,
            txt_record_value: "opendrp-verify=AbC123",
            job_id: "job-1",
            requested_at: "2026-01-03T00:00:00Z",
          },
        ],
      }),
    );

    renderPage();

    expect(await screen.findByText("opendrp-verify=AbC123")).toBeInTheDocument();
    expect(screen.getByText("DNS record issued — publish it")).toBeInTheDocument();
    // The refusal that made the step necessary is still readable next to it.
    expect(screen.getByText(/domain_not_verified/)).toBeInTheDocument();
  });

  it("keeps an attempt visible when no scan has named its domain", async () => {
    mocks.readiness.mockResolvedValue(
      ready({
        scan_job_id: null,
        connector: null,
        scanned_at: null,
        status: null,
        partial: false,
        domains: [],
        unscanned_total: 0,
        verifications: [
          {
            domain: "gamma.test",
            action: "verify",
            status: "not_verified",
            reason: "token_not_found",
            txt_record_value: null,
            job_id: "job-2",
            requested_at: "2026-01-04T00:00:00Z",
          },
        ],
      }),
    );

    renderPage();

    expect(await screen.findByText("gamma.test")).toBeInTheDocument();
    expect(screen.getByText("Record not visible to the source yet")).toBeInTheDocument();
    expect(screen.getByText(/DNS may still be propagating/)).toBeInTheDocument();
  });

  it("does not offer the steps to a reader who cannot write", async () => {
    useAuthStore.setState({
      user: {
        id: "viewer-1",
        email: "viewer@example.com",
        role: "viewer",
        is_active: true,
        rate_limit_minutes: 0,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      },
      token: "access-token",
      isHydrated: true,
    });

    renderPage();

    expect(await screen.findByText(/domain_not_verified/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Get DNS record" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Check DNS now" })).not.toBeInTheDocument();
  });
});
