import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import ReportsPage from "@/pages/ReportsPage";
import { useAuthStore } from "@/store/auth";

const {
  listReportsMock,
  generateReportMock,
  downloadReportMock,
  deleteReportMock,
  getJobMock,
  toastMock,
} = vi.hoisted(() => ({
  listReportsMock: vi.fn(),
  generateReportMock: vi.fn(),
  downloadReportMock: vi.fn(),
  deleteReportMock: vi.fn(),
  getJobMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  endpoints: {
    listReports: listReportsMock,
    generateReport: generateReportMock,
    downloadReportBlob: downloadReportMock,
    deleteReport: deleteReportMock,
    getJob: getJobMock,
  },
  flattenErrorDetail: (detail: unknown) => String(detail ?? ""),
  describeApiError: (error: any) => { const d = error?.response?.data?.detail; if (typeof d === "string") return d; if (Array.isArray(d)) return d.map((x: any) => x?.msg ?? String(x)).join("; "); return String(error?.message ?? error ?? ""); },
}));

vi.mock("@/components/ui/use-toast", () => ({ toast: toastMock }));
vi.mock("@/components/JobsTable", () => ({ JobsTable: () => null }));
vi.mock("@/components/DataTable", () => ({
  PaginatedDataTable: ({ columns, rows, loading, page, onPageChange }: any) => (
    <div>
      {loading && rows.length === 0 ? <span>Loading table</span> : null}
      <button onClick={() => onPageChange?.(page + 1)}>Next test page</button>
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
  ConfirmDialog: ({ open, title, children, onConfirm, onCancel, confirmLoading, onOpenChange }: any) =>
    open ? (
      <div role="dialog">
        <h2>{title}</h2>
        {children}
        <button onClick={onCancel}>Cancel confirmation</button>
        <button onClick={onConfirm} disabled={confirmLoading}>Confirm deletion</button>
        <button onClick={() => onOpenChange?.(false)}>Close dialog</button>
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
  const view = render(
    <QueryClientProvider client={queryClient}>
      <ReportsPage />
    </QueryClientProvider>,
  );
  return { ...view, queryClient };
}

describe("ReportsPage", () => {
  beforeEach(() => {
    listReportsMock.mockReset().mockResolvedValue(reports);
    generateReportMock.mockReset().mockResolvedValue({
      status: "scheduled",
      queue_state: "queued",
      report_id: "new-report-12345678",
      job_id: "report-job-1",
    });
    downloadReportMock.mockReset().mockResolvedValue(new Blob(["pdf"]));
    deleteReportMock.mockReset().mockResolvedValue({});
    getJobMock.mockReset().mockResolvedValue({ id: "job", status: "running" });
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
      expect.objectContaining({ title: "Report queued", description: expect.stringContaining("status will update automatically") }),
    );
    await waitFor(() => expect(getJobMock).toHaveBeenCalledWith("report-job-1"));

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

  it("keeps deletion confirmation open during failure and supports retry", async () => {
    const user = userEvent.setup();
    let rejectDelete: ((error: Error) => void) | undefined;
    deleteReportMock.mockImplementationOnce(() => new Promise((_, reject) => { rejectDelete = reject; }));
    deleteReportMock.mockRejectedValueOnce(new Error("delete unavailable"));
    renderPage();
    await screen.findByText("Weekly exposure report");
    await user.click(screen.getAllByRole("button", { name: "Delete report" })[0]);
    await user.click(screen.getByRole("button", { name: "Confirm deletion" }));

    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Confirm deletion" })).toBeDisabled();
    rejectDelete?.(new Error("temporary filesystem failure"));
    expect(await screen.findByRole("alert")).toHaveTextContent("temporary filesystem failure");
    expect(screen.getByRole("dialog")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Confirm deletion" }));
    await waitFor(() => expect(deleteReportMock).toHaveBeenCalledTimes(2));
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(await screen.findByRole("alert")).toHaveTextContent("delete unavailable");
  });

  it("continues polling the tracked job independently of report-list pages", async () => {
    const user = userEvent.setup();
    const { queryClient } = renderPage();
    await screen.findByText("Weekly exposure report");
    getJobMock.mockResolvedValue({ id: "report-job-1", status: "running" });
    await user.click(screen.getByRole("button", { name: "Generate report" }));
    await waitFor(() => expect(getJobMock).toHaveBeenCalledWith("report-job-1"));

    await user.click(screen.getByRole("button", { name: "Next test page" }));
    await waitFor(() => expect(listReportsMock).toHaveBeenCalledWith({ page: 2, size: 50 }));
    queryClient.setQueryData(["report-generation-job", "report-job-1"], { id: "report-job-1", status: "success" });
    await waitFor(() => expect(toastMock).toHaveBeenCalledWith({ title: "Report is ready" }));
  });

  it("revokes a download object URL only after the browser had time to consume it", async () => {
    // The delay is the whole point of this test, so it is driven rather than waited
    // for: on the real clock the assertion that the URL is still alive competed with
    // the timer it was asserting about, and a loaded machine (the full suite) let the
    // revocation win — the same test passed on its own and failed in a run of forty
    // files. Fake timers make the two ends of the delay observable instead of racy.
    const anchorClick = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    const revokeObjectURL = vi.fn();
    const urlApi = { createObjectURL: vi.fn(() => "blob:report"), revokeObjectURL };
    vi.stubGlobal("URL", urlApi);
    Object.defineProperty(window, "URL", { configurable: true, value: urlApi });

    renderPage();
    await screen.findByText("Weekly exposure report");

    vi.useFakeTimers();
    try {
      fireEvent.click(screen.getAllByRole("button", { name: /Download report/ }).find((button) => !button.hasAttribute("disabled"))!);
      // The URL is created after the blob request resolves, so the timer that will
      // revoke it does not exist until the microtask queue has drained. Advancing
      // asynchronously is what lets that happen without moving the clock.
      await vi.advanceTimersByTimeAsync(0);
      // The object URL must outlive the synthetic click: revoking it synchronously
      // cancels the download in some browsers.
      expect(revokeObjectURL).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(999);
      expect(revokeObjectURL).not.toHaveBeenCalled();
      // ...and it must not be leaked either.
      await vi.advanceTimersByTimeAsync(1);
      expect(revokeObjectURL).toHaveBeenCalledWith("blob:report");
    } finally {
      vi.useRealTimers();
      anchorClick.mockRestore();
    }
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
