import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import AuditPage from "@/pages/AuditPage";

const { actionsMock, logsMock } = vi.hoisted(() => ({
  actionsMock: vi.fn(),
  logsMock: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  endpoints: {
    listAuditActions: actionsMock,
    listAuditLogs: logsMock,
  },
  describeApiError: (error: any) => String(error?.message ?? error ?? ""),
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

const log = {
  id: "audit-1",
  timestamp: "2026-01-01T00:00:00Z",
  action: "asset.create",
  user_email: "admin@example.com",
  ip_address: "203.0.113.10",
  details: { asset_value: "example.com" },
};

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={queryClient}><AuditPage /></QueryClientProvider>);
}

describe("AuditPage", () => {
  beforeEach(() => {
    actionsMock.mockReset().mockResolvedValue({
      actions: ["asset.create", "auth.login.success"],
      labels: { "asset.create": "Asset created" },
    });
    logsMock.mockReset().mockResolvedValue({ items: [log], total: 1, page: 1, size: 20, pages: 1 });
  });

  it("loads and summarizes audit entries", async () => {
    renderPage();
    expect(await screen.findByText("Audit Log")).toBeInTheDocument();
    expect(await screen.findByText("Added asset example.com")).toBeInTheDocument();
    expect(screen.getByText("admin@example.com")).toBeInTheDocument();
    expect(logsMock).toHaveBeenCalledWith(expect.objectContaining({ page: 1, size: 20 }));
  });

  it("resets entered filters and reloads unfiltered audit data", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("Added asset example.com");
    const search = screen.getByRole("textbox", { name: "Search audit entries" });
    await user.type(search, "suspicious");
    await waitFor(() => expect(logsMock).toHaveBeenCalledWith(expect.objectContaining({ search: "suspicious" })));
    await user.click(screen.getByRole("button", { name: "Reset filters" }));
    expect(search).toHaveValue("");
    await waitFor(() => expect(logsMock).toHaveBeenCalledWith(expect.objectContaining({ search: undefined })));
  });
});
