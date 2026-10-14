import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import PhishingPage from "@/pages/PhishingPage";
import { useAuthStore } from "@/store/auth";

const {
  listPhishingMock,
  evidenceMock,
  scanModuleMock,
  updatePhishingMock,
  deletePhishingMock,
  cleanOrphansMock,
  toastMock,
} = vi.hoisted(() => ({
  listPhishingMock: vi.fn(),
  evidenceMock: vi.fn(),
  scanModuleMock: vi.fn(),
  updatePhishingMock: vi.fn(),
  deletePhishingMock: vi.fn(),
  cleanOrphansMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  endpoints: {
    listPhishing: listPhishingMock,
    phishingEvidence: evidenceMock,
    scanModule: scanModuleMock,
    updatePhishingThreat: updatePhishingMock,
    deletePhishingThreat: deletePhishingMock,
    cleanOrphanPhishing: cleanOrphansMock,
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

const threat = {
  id: "threat-1",
  phishing_domain: "evil-example.com",
  matched_asset: "example.com",
  ip_address: "203.0.113.10",
  web_ports: "80,443",
  detection_source: "dnstwist",
  status: "active",
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <PhishingPage />
    </QueryClientProvider>,
  );
}

describe("PhishingPage", () => {
  beforeEach(() => {
    listPhishingMock.mockReset().mockResolvedValue({
      items: [threat],
      total: 1,
      page: 1,
      size: 20,
      pages: 1,
    });
    scanModuleMock.mockReset().mockResolvedValue({ status: "scheduled", job_ids: ["dnstwist-job", "netlas-job"], sources: [{ connector: "dnstwist", status: "queued" }, { connector: "netlas-phishing", status: "queued" }] });
    updatePhishingMock.mockReset().mockResolvedValue({});
    deletePhishingMock.mockReset().mockResolvedValue({});
    cleanOrphansMock.mockReset().mockResolvedValue({ deleted: 2 });
    toastMock.mockReset();
    evidenceMock.mockReset().mockResolvedValue({ items: [{ source: "netlas", matched_asset: "example.com", observed_at: null, first_seen_at: "2026-01-01T00:00:00Z", last_seen_at: "2026-01-02T00:00:00Z" }] });
    useAuthStore.getState().clearAuth();
    useAuthStore.setState({
      user: {
        id: "analyst-1",
        email: "analyst@example.com",
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

  it("loads threats and requests registry-driven scans including new providers", async () => {
    const user = userEvent.setup();
    renderPage();

    expect(await screen.findByText("evil-example.com")).toBeInTheDocument();
    expect(screen.getByText("example.com")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Rescan" })).toHaveClass("bg-primary");
    await user.click(screen.getByRole("button", { name: "Rescan" }));

    await waitFor(() => {
      expect(scanModuleMock).toHaveBeenCalledTimes(1);
      expect(scanModuleMock).toHaveBeenCalledWith("phishing");
    });
    expect(toastMock).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Rescan started" }),
    );
  });

  it("loads corroborating source evidence on demand", async () => {
    renderPage();
    await screen.findByText("evil-example.com");
    expect(evidenceMock).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Source evidence" }));
    await waitFor(() => expect(evidenceMock).toHaveBeenCalledWith(threat.id));
    expect(await screen.findByText(/netlas · example.com/)).toBeInTheDocument();
  });

  it("reports a partial connector scan failure", async () => {
    const user = userEvent.setup();
    scanModuleMock.mockResolvedValueOnce({ status: "scheduled", job_ids: ["dnstwist-job"], sources: [{ connector: "dnstwist", status: "queued" }, { connector: "netlas-phishing", status: "offline" }] });
    renderPage();
    await screen.findByText("evil-example.com");

    expect(screen.getByRole("button", { name: "Rescan" })).toHaveClass("bg-primary");
    await user.click(screen.getByRole("button", { name: "Rescan" }));
    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({
          variant: "destructive",
          title: "Rescan partially started",
        }),
      ),
    );
  });

  it("surfaces the per-connector rate limit reason on a blocked rescan", async () => {
    const user = userEvent.setup();
    scanModuleMock.mockResolvedValueOnce({ status: "scheduled", job_ids: ["dnstwist-job"], sources: [{ connector: "dnstwist", status: "queued" }, { connector: "netlas-phishing", status: "blocked", reason: "Rate limit: source budget exhausted" }] });
    renderPage();
    await screen.findByText("evil-example.com");

    expect(screen.getByRole("button", { name: "Rescan" })).toHaveClass("bg-primary");
    await user.click(screen.getByRole("button", { name: "Rescan" }));
    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({
          variant: "destructive",
          title: "Rescan partially started",
          description: expect.stringContaining("Rate limit"),
        }),
      ),
    );
  });

  it("deletes a threat and cleans orphan entries after confirmation", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("evil-example.com");

    await user.click(screen.getByRole("button", { name: "Delete threat" }));
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Confirm action" }));
    await waitFor(() => expect(deletePhishingMock).toHaveBeenCalledWith("threat-1"));

    await user.click(screen.getByRole("button", { name: "Clean orphans" }));
    await user.click(screen.getByRole("button", { name: "Confirm action" }));
    await waitFor(() => expect(cleanOrphansMock).toHaveBeenCalledTimes(1));
  });
});
