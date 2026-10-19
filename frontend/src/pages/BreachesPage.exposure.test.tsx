/**
 * The breach list separates the classes of exposure (WI-21).
 *
 * An account being compromised, appearing in a paste and being found in a stealer
 * log are three different things to do about the same row, so the page asks the
 * server for one of them and says which class each row it shows belongs to. The
 * select *primitive* is stubbed with a native `<select>`: what has to hold is the
 * page's own wiring — the class an operator picks is the `exposure_kind` the request
 * carries, the list is re-read from page one, and the column names the class it kept
 * — while the picker's portal and pointer handling are the library's and cost about
 * half a minute to drive under jsdom.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import BreachesPage from "@/pages/BreachesPage";
import { BREACH_EXPOSURE_KINDS } from "@/lib/breach";
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

const mocks = vi.hoisted(() => ({ list: vi.fn(), readiness: vi.fn(), toast: vi.fn() }));

vi.mock("@/lib/api", () => ({
  endpoints: {
    listBreaches: mocks.list,
    breachProviderReadiness: mocks.readiness,
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

function row(overrides: Record<string, unknown>) {
  return {
    id: "breach-1",
    breach_name: "Acme Leak",
    title: "Acme Leak",
    domain: "acme.test",
    breach_date: "2026-01-01",
    pwn_count: 10,
    data_classes: ["Passwords"],
    matched_email: "user@acme.test",
    matched_domain: "acme.test",
    matched_asset: "acme.test",
    matched_asset_type: "domain",
    status: "active",
    created_at: "2026-01-01T00:00:00Z",
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

function exposureControl(): HTMLSelectElement {
  // The stub drops the trigger, so the control is found by the one option only the
  // class filter offers (the status column's picker has no "all").
  const control = screen
    .getAllByRole("combobox")
    .find((node) =>
      Array.from((node as HTMLSelectElement).options).some((option) => option.value === "all"),
    );
  expect(control).toBeDefined();
  return control as HTMLSelectElement;
}

describe("BreachesPage exposure classes", () => {
  beforeEach(() => {
    mocks.list.mockReset().mockResolvedValue({
      items: [row({ exposure_kind: "paste" }), row({ id: "breach-2", exposure_kind: "stealer_log", matched_email: "other@acme.test" })],
      total: 2,
      page: 1,
      size: 20,
      pages: 1,
      unannounced: 0,
      new_since: null,
    });
    mocks.readiness.mockReset().mockResolvedValue({
      status: "success",
      partial: false,
      reasons: {},
      entitlements: null,
      pacing: {},
      domains: [],
      unscanned_total: 0,
      data_class_labels: {},
    });
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

  it("asks for every class until an operator picks one", async () => {
    renderPage();

    await waitFor(() =>
      expect(mocks.list).toHaveBeenCalledWith(expect.objectContaining({ exposure_kind: undefined })),
    );
    // An unfiltered list still says what each row is.
    expect(screen.getByText("Paste")).toBeInTheDocument();
    expect(screen.getByText("Stealer log")).toBeInTheDocument();
  });

  it("filters the list to the class that was picked, from page one", async () => {
    renderPage();
    await waitFor(() => expect(mocks.list).toHaveBeenCalled());

    fireEvent.change(exposureControl(), { target: { value: "stealer_log" } });

    await waitFor(() =>
      expect(mocks.list).toHaveBeenLastCalledWith(
        expect.objectContaining({ exposure_kind: "stealer_log", page: 1 }),
      ),
    );
  });

  it("offers the classes the core stores, and only those", async () => {
    renderPage();

    const offered = Array.from(exposureControl().options).map((option) => option.value);
    // "all" is the absence of a filter; the rest is the vocabulary ingestion validates
    // a finding against, so the picker cannot ask a question the API refuses.
    expect(offered).toEqual(["all", ...BREACH_EXPOSURE_KINDS]);
    expect(offered).toContain("breach");
    expect(offered).toContain("paste");
    expect(offered).toContain("stealer_log");
  });
});
