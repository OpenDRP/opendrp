import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import ReportsPage from "@/pages/ReportsPage";
import { useAuthStore } from "@/store/auth";

const {
  listReportsMock,
  generateReportMock,
  downloadReportMock,
  deleteReportMock,
  toastMock,
} = vi.hoisted(() => ({
  listReportsMock: vi.fn(),
  generateReportMock: vi.fn(),
  downloadReportMock: vi.fn(),
  deleteReportMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  endpoints: {
    listReports: listReportsMock,
    generateReport: generateReportMock,
    downloadReportBlob: downloadReportMock,
    deleteReport: deleteReportMock,
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
        <button onClick={onConfirm}>Confirm deletion</button>
      </div>
    ) : null,
}));

const reports = {
  items: [
    {
      id: "completed-report-1",
      report_name: "Weekly exposure report",
      created_by_email: "analyst@example.com",
      file_path: "/tmp/report.pdf",
      file_available: true,
      status: "completed",
      is_truncated: true,
      truncation_metadata: { limit: 5000, truncated: true, sections: { assets: { total: 6000, included: 5000, truncated: true } } },
      created_at: "2026-01-01T00:00:00Z",
    },
    {
      id: "pending-report-2",
      report_name: "Pending report",
      created_by_email: "analyst@example.com",
      file_path: "",
      status: "pending",
      created_at: "2026-01-02T00:00:00Z",
    },
    {
      id: "vanished-report-3",
      report_name: "Vanished report",
      created_by_email: "analyst@example.com",
      file_path: "/tmp/gone.pdf",
      file_available: false,
      status: "completed",
      created_at: "2026-01-03T00:00:00Z",
    },
  ],
  total: 3,
  page: 1,
  size: 50,
  pages: 1,
};

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <ReportsPage />
    </QueryClientProvider>,
  );
}

describe("ReportsPage", () => {
  beforeEach(() => {
    listReportsMock.mockReset().mockResolvedValue(reports);
    generateReportMock.mockReset().mockResolvedValue({
      report_id: "new-report-12345678",
      estimated_seconds: 30,
    });
    downloadReportMock.mockReset().mockResolvedValue(new Blob(["pdf"]));
    deleteReportMock.mockReset().mockResolvedValue({});
    toastMock.mockReset();
    useAuthStore.getState().clearAuth();
    // Admin so the destructive (delete) path stays covered; deletion is
    // admin-only in the API and the button must match.
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
    vi.stubGlobal("URL", {
      createObjectURL: vi.fn(() => "blob:report"),
      revokeObjectURL: vi.fn(),
    });
  });

  it("loads report history and exposes status counts", async () => {
    renderPage();

    expect(await screen.findByText("Weekly exposure report")).toBeInTheDocument();
    expect(screen.getByText("Pending report")).toBeInTheDocument();
    expect(screen.getByText("Total:")).toBeInTheDocument();
    expect(screen.getAllByText("Truncated").length).toBeGreaterThan(0);
    expect(screen.getByText("Limited rows")).toBeInTheDocument();
    expect(listReportsMock).toHaveBeenCalledWith({ page: 1, size: 50 });
  });

  it("starts generation, downloads completed reports, and deletes after confirmation", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("Weekly exposure report");

    await user.click(screen.getByRole("button", { name: "Generate report" }));
    await waitFor(() => expect(generateReportMock).toHaveBeenCalledTimes(1));
    expect(toastMock).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Report generation started" }),
    );

    const anchorClick = vi
      .spyOn(HTMLAnchorElement.prototype, "click")
      .mockImplementation(() => {});
    const downloadButton = screen
      .getAllByRole("button", { name: /Download report/ })
      .find((button) => !button.hasAttribute("disabled"));
    expect(downloadButton).toBeDefined();
    await user.click(downloadButton!);
    anchorClick.mockRestore();
    await waitFor(() => expect(downloadReportMock).toHaveBeenCalledWith("completed-report-1"));
    expect(toastMock).toHaveBeenCalledWith({ title: "Download started" });

    await user.click(screen.getAllByRole("button", { name: "Delete report" })[0]);
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Confirm deletion" }));
    await waitFor(() => expect(deleteReportMock).toHaveBeenCalledWith("completed-report-1"));
  });

  it("lets a viewer generate a report but hides admin-only deletion", async () => {
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
    await screen.findByText("Weekly exposure report");

    expect(screen.getByRole("button", { name: "Generate report" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Delete report" })).not.toBeInTheDocument();
  });

  it("disables the download for a report whose file is gone", async () => {
    renderPage();
    await screen.findByText("Vanished report");

    const buttons = screen.getAllByRole("button", { name: /Download report/ });
    const enabled = buttons.filter((b) => !b.hasAttribute("disabled"));
    // Only the report whose artifact still exists stays downloadable.
    expect(enabled).toHaveLength(1);
    expect(buttons.filter((b) => b.textContent === "File missing")).toHaveLength(1);
  });

  it("reports generation failures without crashing the page", async () => {
    const user = userEvent.setup();
    generateReportMock.mockRejectedValueOnce(new Error("queue unavailable"));
    renderPage();
    await screen.findByText("Weekly exposure report");

    await user.click(screen.getByRole("button", { name: "Generate report" }));
    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({ variant: "destructive", title: "Failed to start report" }),
      ),
    );
  });
});
