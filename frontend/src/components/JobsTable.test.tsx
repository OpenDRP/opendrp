import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { JobsTable } from "@/components/JobsTable";
import { useAuthStore } from "@/store/auth";

const { listJobsMock, deleteMock, toastMock } = vi.hoisted(() => ({
  listJobsMock: vi.fn(),
  deleteMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  api: { delete: deleteMock },
  endpoints: { listJobs: listJobsMock },
  describeApiError: (error: any) => String(error?.message ?? error ?? ""),
}));
vi.mock("@/components/ui/use-toast", () => ({ toast: toastMock }));
vi.mock("@/components/DataTable", () => ({
  PaginatedDataTable: ({ columns, rows }: any) => (
    <div>{rows.map((row: any) => <div key={row.id}>{columns.map((column: any) => <span key={column.key}>{column.render ? column.render(row) : row[column.key]}</span>)}</div>)}</div>
  ),
}));
vi.mock("@/components/ui/confirm-dialog", () => ({
  ConfirmDialog: ({ open, title, onConfirm, onCancel }: any) => open ? <div role="dialog"><h2>{title}</h2><button onClick={onCancel}>Cancel confirmation</button><button onClick={onConfirm}>Confirm action</button></div> : null,
}));

const job = {
  id: "job-123456789",
  job_type: "phishing.dnstwist",
  status: "error",
  title: "Brand scan",
  error_message: "connector failed",
  created_at: "2026-01-01T00:00:00Z",
  started_at: "2026-01-01T00:00:00Z",
  finished_at: "2026-01-01T00:01:00Z",
  updated_at: "2026-01-01T00:01:00Z",
};

function renderTable() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><JobsTable jobTypes={["phishing.dnstwist"]} /></QueryClientProvider>);
}

describe("JobsTable", () => {
  beforeEach(() => {
    listJobsMock.mockReset().mockResolvedValue({ items: [job], total: 1, page: 1, size: 10, pages: 1 });
    deleteMock.mockReset().mockResolvedValue({});
    toastMock.mockReset();
    useAuthStore.getState().clearAuth();
    useAuthStore.setState({ user: { id: "admin", email: "admin@example.com", role: "admin", is_active: true, rate_limit_minutes: 0, created_at: "2026-01-01", updated_at: "2026-01-01" }, token: "token", isHydrated: true });
  });

  it("loads filtered job history and deletes a job after confirmation", async () => {
    const user = userEvent.setup();
    renderTable();
    expect(await screen.findByText("Phishing scan")).toBeInTheDocument();
    expect(screen.getByText("connector failed")).toBeInTheDocument();
    expect(listJobsMock).toHaveBeenCalledWith(expect.objectContaining({ job_type_in: "phishing.dnstwist" }));
    await user.click(screen.getByRole("button", { name: "Delete job" }));
    await user.click(screen.getByRole("button", { name: "Confirm action" }));
    await waitFor(() => expect(deleteMock).toHaveBeenCalledWith("/jobs/job-123456789"));
  });
});
