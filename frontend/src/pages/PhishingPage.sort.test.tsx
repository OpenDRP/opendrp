/**
 * The phishing list asks the server to rank by the age of a registration (WI-05) and
 * by the score of a candidate (WI-08).
 *
 * The select *primitive* is stubbed with a native `<select>`: what has to hold is
 * the page's own wiring — the value an operator picks is the `sort`/`order` pair
 * the request carries and the list is re-read from page one — while the picker's
 * portal and pointer handling are the library's and cannot be driven cheaply under
 * jsdom (opening one Radix portal costs about half a minute here, and it starves
 * whatever test follows it; the repo's own DNS page test fails on that).
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import PhishingPage, { SORT_OPTIONS } from "@/pages/PhishingPage";
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

const mocks = vi.hoisted(() => ({ list: vi.fn(), toast: vi.fn() }));
vi.mock("@/lib/api", () => ({
  endpoints: {
    listPhishing: mocks.list,
    phishingEvidence: vi.fn().mockResolvedValue({ items: [] }),
    updatePhishingThreat: vi.fn(),
    deletePhishingThreat: vi.fn(),
    cleanOrphanPhishing: vi.fn(),
    scanModule: vi.fn(),
  },
  describeApiError: (error: Error) => error.message,
}));
vi.mock("@/hooks/useModuleJobTypes", () => ({ useModuleJobTypes: () => ["phishing.dnstwist"] }));
vi.mock("@/components/JobsTable", () => ({ JobsTable: () => null }));
vi.mock("@/components/ui/use-toast", () => ({ toast: mocks.toast }));
vi.mock("@/lib/scanPolling", () => ({
  summarizeScanJobs: () => ({ pending: 0, succeeded: 0, failed: 0 }),
  waitForScanJobs: async () => [],
}));

describe("PhishingPage sort control (WI-05)", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mocks.list.mockResolvedValue({ items: [], total: 0, page: 1, size: 20, pages: 0 });
    useAuthStore.setState({
      user: { id: "user-1", email: "user@example.com", role: "analyst", is_active: true, rate_limit_minutes: 0, created_at: "2026-01-01", updated_at: "2026-01-01" },
      token: "test",
      isHydrated: true,
    });
  });

  function renderPage() {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    return render(<QueryClientProvider client={client}><PhishingPage /></QueryClientProvider>);
  }

  function sortControl(): HTMLSelectElement {
    // The only select whose value is a `field:direction` pair, which is what the
    // stub renders the value it was handed as.
    const control = screen
      .getAllByRole("combobox")
      .find((node) => (node as HTMLSelectElement).value.includes(":"));
    expect(control).toBeDefined();
    return control as HTMLSelectElement;
  }

  it("ranks by the age of the registration when the operator asks for it", async () => {
    renderPage();
    await waitFor(() => expect(mocks.list).toHaveBeenCalled());

    fireEvent.change(sortControl(), { target: { value: "age:asc" } });

    await waitFor(() =>
      expect(mocks.list).toHaveBeenLastCalledWith(
        expect.objectContaining({ sort: "age", order: "asc", page: 1 }),
      ),
    );
  });

  it("offers the orderings the API declares, and only those", async () => {
    renderPage();
    await waitFor(() => expect(mocks.list).toHaveBeenCalled());
    const offered = Array.from(sortControl().options).map((option) => option.value);

    expect(offered).toEqual([
      "created_at:desc",
      "created_at:asc",
      "confidence:desc",
      "confidence:asc",
      "age:asc",
      "age:desc",
    ]);
    // Every option has to stand for a pair the server accepts, or picking it is a
    // 422 rather than an ordering.
    for (const option of SORT_OPTIONS) {
      expect(option.value).toBe(`${option.sort}:${option.order}`);
    }
    expect([...new Set(SORT_OPTIONS.map((o) => o.sort))]).toEqual([
      "created_at",
      "confidence",
      "age",
    ]);
    expect([...new Set(SORT_OPTIONS.map((o) => o.order))]).toEqual(["desc", "asc"]);
  });

  it("ranks by what the evidence adds up to when the operator asks for it", async () => {
    renderPage();
    await waitFor(() => expect(mocks.list).toHaveBeenCalled());

    fireEvent.change(sortControl(), { target: { value: "confidence:desc" } });

    await waitFor(() =>
      expect(mocks.list).toHaveBeenLastCalledWith(
        expect.objectContaining({ sort: "confidence", order: "desc", page: 1 }),
      ),
    );
  });

  it("re-reads the list from the first page after the order changes", async () => {
    mocks.list.mockResolvedValue({
      items: [{ id: "t1", phishing_domain: "paypa1.example", matched_asset: "paypal.com", detection_source: "dnstwist", domain_age_days: 12, confidence: 40, signals: {}, alert_band: "digest", status: "active", created_at: "2026-10-15T00:00:00Z", updated_at: "2026-10-15T00:00:00Z" }],
      total: 40,
      page: 1,
      size: 20,
      pages: 2,
    });
    renderPage();
    // The row has to be on screen before the pagination control can be used: the
    // table pages from the response it is showing, not from the request it sent.
    await screen.findByText("paypa1.example");
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    await waitFor(() =>
      expect(mocks.list).toHaveBeenLastCalledWith(expect.objectContaining({ page: 2 })),
    );

    // Reordering the list while the operator is on page 2 would otherwise show
    // whatever happens to be second under the new order.
    fireEvent.change(sortControl(), { target: { value: "age:desc" } });

    await waitFor(() =>
      expect(mocks.list).toHaveBeenLastCalledWith(
        expect.objectContaining({ sort: "age", order: "desc", page: 1 }),
      ),
    );
  });
});
