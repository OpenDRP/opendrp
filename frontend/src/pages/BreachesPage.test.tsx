import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import BreachesPage from "@/pages/BreachesPage";
import { useAuthStore } from "@/store/auth";

const {
  listBreachesMock,
  scanBreachesMock,
  updateBreachMock,
  deleteBreachMock,
  cleanOrphansMock,
  readinessMock,
  promoteMock,
  toastMock,
} = vi.hoisted(() => ({
  listBreachesMock: vi.fn(),
  scanBreachesMock: vi.fn(),
  updateBreachMock: vi.fn(),
  deleteBreachMock: vi.fn(),
  cleanOrphansMock: vi.fn(),
  readinessMock: vi.fn(),
  promoteMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  endpoints: {
    listBreaches: listBreachesMock,
    scanBreaches: scanBreachesMock,
    updateBreach: updateBreachMock,
    deleteBreach: deleteBreachMock,
    cleanOrphanBreaches: cleanOrphansMock,
    breachProviderReadiness: readinessMock,
    promoteBreachAsset: promoteMock,
  },
  flattenErrorDetail: (detail: unknown) => String(detail ?? ""),
  describeApiError: (error: any) => { const d = error?.response?.data?.detail; if (typeof d === "string") return d; if (Array.isArray(d)) return d.map((x: any) => x?.msg ?? String(x)).join("; "); return String(error?.message ?? error ?? ""); },
}));

vi.mock("@/components/ui/use-toast", () => ({ toast: toastMock }));
vi.mock("@/components/JobsTable", () => ({ JobsTable: () => null }));
vi.mock("@/components/DataTable", () => ({
  PaginatedDataTable: ({ columns, rows, loading }: any) => (
    <div>
      {loading && rows.length === 0 ? <span>Loading table</span> : null}
      {rows.map((row: any) => (
        <div key={row.id}>
          {columns.map((column: any) => (
            <span key={column.key}>{column.render ? column.render(row) : row[column.key]}</span>
          ))}
        </div>
      ))}
    </div>
  ),
}));
vi.mock("@/components/ui/confirm-dialog", () => ({
  ConfirmDialog: ({ open, title, onConfirm, onCancel }: any) =>
    open ? (
      <div role="dialog">
        <h2>{title}</h2>
        <button onClick={onCancel}>Cancel confirmation</button>
        <button onClick={onConfirm}>Confirm action</button>
      </div>
    ) : null,
}));

const breach = {
  id: "breach-1",
  breach_name: "Acme Leak",
  title: "Acme Leak",
  domain: "acme.test",
  breach_date: "2026-01-01",
  pwn_count: 123,
  data_classes: ["Emails", "Passwords"],
  matched_email: "user@acme.test",
  matched_domain: "acme.test",
  matched_asset: "acme.test",
  matched_asset_type: "domain",
  status: "active",
  // Source-declared payload: the core models no provider field set, so the
  // page renders whatever the reporting connector declared.
  attributes: {
    is_verified: true,
    is_fabricated: false,
    is_spam_list: false,
    masked_password: "su********et",
    added_date: "2026-01-01T00:00:00Z",
  },
  created_at: "2026-01-01T00:00:00Z",
};

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

describe("BreachesPage", () => {
  beforeEach(() => {
    listBreachesMock.mockReset().mockResolvedValue({
      items: [breach],
      total: 1,
      page: 1,
      size: 20,
      pages: 1,
    });
    scanBreachesMock.mockReset().mockResolvedValue({ job_ids: ["breach-job-1"], status: "scheduled" });
    updateBreachMock.mockReset().mockResolvedValue({});
    deleteBreachMock.mockReset().mockResolvedValue({});
    cleanOrphansMock.mockReset().mockResolvedValue({ deleted: 1 });
    promoteMock.mockReset().mockResolvedValue({
      already_exists: false,
      asset: { id: "asset-9", asset_type: "email_account", asset_value: "user@acme.test" },
    });
    readinessMock.mockReset().mockResolvedValue({
      scan_job_id: "breach-job-1",
      scanned_at: "2026-01-01T00:00:00Z",
      status: "success",
      partial: false,
      reasons: {},
      entitlements: {
        subscription: "Paid",
        requests_per_minute: 10,
        includes_stealer_logs: true,
        includes_kanon: false,
        domains_verified: 2,
      },
      pacing: { configured_requests_per_minute: 10, applied_requests_per_minute: 10, adjusted: false },
      domains: [{ domain: "acme.test", status: "asked" }],
      unscanned_total: 0,
      data_class_labels: {},
    });
    toastMock.mockReset();
    useAuthStore.getState().clearAuth();
    useAuthStore.setState({
      user: {
        id: "admin-1",
        email: "admin@example.com",
        role: "admin",
        is_active: true,
        rate_limit_minutes: 0,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      },
      token: "access-token",
      isHydrated: true,
    });
  });

  it("takes the value the finding names under monitoring (AWI-13)", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findAllByText("Acme Leak");

    await user.click(
      screen.getByRole("button", { name: "Monitor the value this breach names" }),
    );

    await waitFor(() => expect(promoteMock).toHaveBeenCalledWith("breach-1"));
    expect(toastMock).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Asset added" }),
    );
  });

  it("loads breach matches and starts a breach scan", async () => {
    const user = userEvent.setup();
    renderPage();

    expect((await screen.findAllByText("Acme Leak")).length).toBeGreaterThan(0);
    expect(screen.getByText("user@acme.test")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Rescan" })).toHaveClass("bg-primary");
    await user.click(screen.getByRole("button", { name: "Rescan" }));
    await waitFor(() => expect(scanBreachesMock).toHaveBeenCalledTimes(1));
    expect(toastMock).toHaveBeenCalledWith(
      expect.objectContaining({
        title: "Breach rescan started",
        description: expect.stringContaining("1 job(s) queued"),
      }),
    );
  });

  it("surfaces the API reason when a rescan is rate limited", async () => {
    const user = userEvent.setup();
    scanBreachesMock.mockRejectedValueOnce({
      response: { status: 429, data: { detail: "Rate limit: breach rescan ..." } },
    });
    renderPage();
    await screen.findAllByText("Acme Leak");

    expect(screen.getByRole("button", { name: "Rescan" })).toHaveClass("bg-primary");
    await user.click(screen.getByRole("button", { name: "Rescan" }));
    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({ variant: "destructive", title: "Rate limit reached" }),
      ),
    );
  });

  it("shows a refused domain as not scanned with its reason, beside the list it left empty", async () => {
    readinessMock.mockResolvedValueOnce({
      scan_job_id: "breach-job-1",
      scanned_at: "2026-01-01T00:00:00Z",
      status: "partial",
      partial: true,
      reasons: { domain_not_verified: 1 },
      entitlements: { subscription: "Free", domains_verified: 1 },
      pacing: { configured_requests_per_minute: 10, applied_requests_per_minute: 10, adjusted: false },
      domains: [
        { domain: "acme.test", status: "unscanned", reason: "domain_not_verified" },
        { domain: "other.test", status: "asked" },
      ],
      unscanned_total: 1,
      // The source's own vocabulary for a class of data it reports. The page shows
      // this rather than the stored name (F-04).
      data_class_labels: { Passwords: "Account passwords" },
    });
    renderPage();
    await screen.findAllByText("Acme Leak");

    expect(await screen.findByText("Not scanned")).toBeInTheDocument();
    expect(screen.getByText("domain_not_verified")).toBeInTheDocument();
    expect(screen.getByText(/has not verified this domain/)).toBeInTheDocument();
    expect(screen.getByText(/1 of 2 domains could not be searched/)).toBeInTheDocument();
    expect(screen.getByText("Account passwords")).toBeInTheDocument();
  });

  it("deletes a breach and cleans orphan entries", async () => {
    const user = userEvent.setup();
    renderPage();
    expect((await screen.findAllByText("Acme Leak")).length).toBeGreaterThan(0);

    await user.click(screen.getByRole("button", { name: "Delete breach match" }));
    await user.click(screen.getByRole("button", { name: "Confirm action" }));
    await waitFor(() => expect(deleteBreachMock).toHaveBeenCalledWith("breach-1"));

    await user.click(screen.getByRole("button", { name: "Clean orphans" }));
    await user.click(screen.getByRole("button", { name: "Confirm action" }));
    await waitFor(() => expect(cleanOrphansMock).toHaveBeenCalledTimes(1));
  });
});
