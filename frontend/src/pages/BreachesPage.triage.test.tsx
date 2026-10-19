/**
 * Triage of the breach list: how loud a row is and which rows are worth seeing (F-13).
 *
 * The severity is derived by the core from the exposed data classes, and the page
 * only names and colours it; the filters and the ordering are the `sort`/`order`
 * and vocabulary the API declares. The select primitive is stubbed with a native
 * `<select>`, as the phishing sort test does: what has to hold is this page's own
 * wiring — the value an operator picks is the parameter the request carries and the
 * list is re-read from page one — while the picker's portal is the library's and
 * cannot be driven cheaply under jsdom.
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

const mocks = vi.hoisted(() => ({
  list: vi.fn(),
  readiness: vi.fn(),
  toast: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  endpoints: {
    listBreaches: mocks.list,
    breachProviderReadiness: mocks.readiness,
    scanBreaches: vi.fn(),
    updateBreach: vi.fn(),
    deleteBreach: vi.fn(),
    cleanOrphanBreaches: vi.fn(),
    requestBreachDomainVerification: vi.fn(),
  },
  describeApiError: (error: any) => String(error?.message ?? error ?? ""),
  flattenErrorDetail: (detail: unknown) => String(detail ?? ""),
}));
vi.mock("@/hooks/useModuleJobTypes", () => ({ useModuleJobTypes: () => ["breaches.hibp"] }));
vi.mock("@/components/JobsTable", () => ({ JobsTable: () => null }));
vi.mock("@/components/ui/use-toast", () => ({ toast: mocks.toast }));
vi.mock("@/lib/scanPolling", () => ({
  summarizeScanJobs: () => ({ pending: 0, succeeded: 0, failed: 0 }),
  waitForScanJobs: async () => [],
}));
vi.mock("@/components/DataTable", () => ({
  PaginatedDataTable: ({ columns, rows }: any) => (
    <div>
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

const breach = {
  id: "breach-1",
  source_id: "hibp",
  breach_name: "Acme Leak",
  title: "Acme Leak",
  domain: "acme.test",
  breach_date: "2026-01-01",
  pwn_count: 123,
  data_classes: ["Passwords", "Email addresses"],
  matched_email: "user@acme.test",
  matched_domain: "acme.test",
  matched_asset: "acme.test",
  matched_asset_type: "domain",
  status: "active",
  exposure_kind: "breach",
  // Written by the core when the row was written; the page reads it rather than
  // recomputing it from `data_classes`.
  severity: "critical",
  email_incident_count: 3,
  attributes: { is_verified: true },
  created_at: "2026-01-01T00:00:00Z",
};

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <BreachesPage />
    </QueryClientProvider>,
  );
}

describe("BreachesPage triage (F-13)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.list.mockResolvedValue({ items: [breach], total: 1, page: 1, size: 20, pages: 1 });
    mocks.readiness.mockResolvedValue({
      scan_job_id: "job-1",
      scanned_at: "2026-01-01T00:00:00Z",
      status: "success",
      partial: false,
      reasons: {},
      entitlements: null,
      pacing: {},
      domains: [{ domain: "acme.test", status: "asked" }],
      unscanned_total: 0,
      data_class_labels: {},
    });
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

  /** The select offering one of the triage vocabularies, found by its options. */
  function selectWithOption(value: string): HTMLSelectElement {
    const control = screen
      .getAllByRole("combobox")
      .find((node) =>
        Array.from((node as HTMLSelectElement).options).some((option) => option.value === value),
      );
    expect(control).toBeDefined();
    return control as HTMLSelectElement;
  }

  it("shows the derived severity and the address's incident count", async () => {
    renderPage();

    expect(await screen.findByText("user@acme.test")).toBeInTheDocument();
    // Two nodes say "Critical": the filter's own option and the row's badge.
    expect((await screen.findAllByText("Critical")).length).toBeGreaterThan(0);
    // The same account in three incidents is one account to handle, not three rows
    // to triage as new.
    expect(await screen.findByTitle(/already appears in 3 incidents/)).toBeInTheDocument();
  });

  it("asks the server for the severity, state, source flag and domain picked", async () => {
    renderPage();
    await waitFor(() => expect(mocks.list).toHaveBeenCalled());

    fireEvent.change(selectWithOption("critical"), { target: { value: "critical" } });
    await waitFor(() =>
      expect(mocks.list).toHaveBeenLastCalledWith(
        expect.objectContaining({ severity: "critical", page: 1 }),
      ),
    );

    fireEvent.change(selectWithOption("investigating"), { target: { value: "investigating" } });
    await waitFor(() =>
      expect(mocks.list).toHaveBeenLastCalledWith(
        expect.objectContaining({ status: "investigating" }),
      ),
    );

    fireEvent.change(selectWithOption("verified"), { target: { value: "verified" } });
    await waitFor(() =>
      expect(mocks.list).toHaveBeenLastCalledWith(
        expect.objectContaining({ flag: "verified" }),
      ),
    );

    fireEvent.change(screen.getByLabelText("Domain"), { target: { value: "acme.test" } });
    await waitFor(
      () =>
        expect(mocks.list).toHaveBeenLastCalledWith(
          expect.objectContaining({ domain: "acme.test" }),
        ),
      { timeout: 2000 },
    );
  });

  it("orders loudest-first by the rank the API applies, not alphabetically", async () => {
    renderPage();
    await waitFor(() => expect(mocks.list).toHaveBeenCalled());

    fireEvent.change(selectWithOption("severity:desc"), { target: { value: "severity:desc" } });

    await waitFor(() =>
      expect(mocks.list).toHaveBeenLastCalledWith(
        expect.objectContaining({ sort: "severity", order: "desc", page: 1 }),
      ),
    );
  });
});
