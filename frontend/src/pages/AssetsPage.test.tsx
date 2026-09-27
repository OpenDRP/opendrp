import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import AssetsPage from "@/pages/AssetsPage";
import { useAuthStore } from "@/store/auth";

const { listMock, createMock, updateMock, deleteMock, toastMock } = vi.hoisted(() => ({
  listMock: vi.fn(),
  createMock: vi.fn(),
  updateMock: vi.fn(),
  deleteMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  endpoints: {
    listAssets: listMock,
    createAsset: createMock,
    updateAsset: updateMock,
    deleteAsset: deleteMock,
  },
  describeApiError: (error: any) => String(error?.message ?? error ?? ""),
}));
vi.mock("@/components/ui/use-toast", () => ({ toast: toastMock }));
vi.mock("@/components/DataTable", () => ({
  PaginatedDataTable: ({ columns, rows }: any) => (
    <div>{rows.map((row: any) => <div key={row.id}>{columns.map((column: any) => <span key={column.key}>{column.render ? column.render(row) : row[column.key]}</span>)}</div>)}</div>
  ),
}));
vi.mock("@/components/ui/confirm-dialog", () => ({
  ConfirmDialog: ({ open, title, children, onConfirm, onCancel }: any) => open ? (
    <div role="dialog"><h2>{title}</h2>{children}<button onClick={onCancel}>Cancel confirmation</button><button onClick={onConfirm}>Confirm action</button></div>
  ) : null,
}));

const asset = {
  id: "asset-1",
  asset_type: "domain",
  asset_value: "example.com",
  criticality: "high",
  is_active: true,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={queryClient}><AssetsPage /></QueryClientProvider>);
}

describe("AssetsPage", () => {
  beforeEach(() => {
    listMock.mockReset().mockResolvedValue({ items: [asset], total: 1, page: 1, size: 20, pages: 1 });
    createMock.mockReset().mockResolvedValue(asset);
    updateMock.mockReset().mockResolvedValue(asset);
    deleteMock.mockReset().mockResolvedValue({});
    toastMock.mockReset();
    useAuthStore.getState().clearAuth();
    useAuthStore.setState({
      user: { id: "admin-1", email: "admin@example.com", role: "admin", is_active: true, rate_limit_minutes: 0, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
      token: "access-token",
      isHydrated: true,
    });
  });

  it("loads assets and validates an empty create form", async () => {
    const user = userEvent.setup();
    renderPage();
    expect(await screen.findByText("example.com")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Add asset" }));
    const dialog = screen.getByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(createMock).not.toHaveBeenCalled();
    expect(toastMock).toHaveBeenCalledWith(expect.objectContaining({ variant: "destructive", title: "Validation" }));
  });

  it("creates an asset and deletes related findings with cascade", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("example.com");
    await user.click(screen.getByRole("button", { name: "Add asset" }));
    const dialog = screen.getByRole("dialog");
    await user.type(within(dialog).getByLabelText("Value"), "new.example.com");
    await user.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() => expect(createMock).toHaveBeenCalledWith({ asset_type: "domain", asset_value: "new.example.com", criticality: "medium" }));

    await user.click(screen.getByRole("button", { name: "Delete asset" }));
    const deleteDialog = screen.getByRole("dialog");
    await user.click(within(deleteDialog).getByRole("checkbox"));
    await user.click(within(deleteDialog).getByRole("button", { name: "Confirm action" }));
    await waitFor(() => expect(deleteMock).toHaveBeenCalledWith("asset-1", true));
  });
});
