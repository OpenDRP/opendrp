import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import UsersPage from "@/pages/UsersPage";
import { useAuthStore } from "@/store/auth";

const {
  listUsersMock,
  createUserMock,
  updateUserMock,
  deleteUserMock,
  resetUserMfaMock,
  toastMock,
} = vi.hoisted(() => ({
  listUsersMock: vi.fn(),
  createUserMock: vi.fn(),
  updateUserMock: vi.fn(),
  deleteUserMock: vi.fn(),
  resetUserMfaMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  endpoints: {
    listUsers: listUsersMock,
    createUser: createUserMock,
    updateUser: updateUserMock,
    deleteUser: deleteUserMock,
    resetUserMfa: resetUserMfaMock,
  },
  flattenErrorDetail: (detail: unknown) => String(detail ?? ""),
  describeApiError: (error: any) => String(error?.response?.data?.detail ?? error?.message ?? error ?? ""),
}));

vi.mock("@/components/ui/use-toast", () => ({ toast: toastMock }));
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

const admin = {
  id: "admin-1",
  email: "admin@example.com",
  full_name: "Platform Admin",
  role: "admin" as const,
  is_active: true,
  rate_limit_minutes: 0,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};
const analyst = {
  id: "analyst-1",
  email: "analyst@example.com",
  full_name: "Security Analyst",
  role: "analyst" as const,
  is_active: true,
  rate_limit_minutes: 0,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <UsersPage />
    </QueryClientProvider>,
  );
}

describe("UsersPage", () => {
  beforeEach(() => {
    listUsersMock.mockReset().mockResolvedValue({
      items: [admin, analyst],
      total: 2,
      page: 1,
      size: 20,
      pages: 1,
    });
    createUserMock.mockReset().mockResolvedValue({ ...analyst, id: "new-user" });
    updateUserMock.mockReset().mockResolvedValue(analyst);
    deleteUserMock.mockReset().mockResolvedValue({});
    resetUserMfaMock.mockReset().mockResolvedValue(analyst);
    toastMock.mockReset();
    useAuthStore.getState().clearAuth();
    useAuthStore.setState({
      user: admin,
      token: "access-token",
      isHydrated: true,
    });
  });

  it("loads users and prevents an empty create submission", async () => {
    const user = userEvent.setup();
    renderPage();
    expect(await screen.findByText("analyst@example.com")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Create user" }));
    const dialog = screen.getByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: "Create user" }));

    expect(createUserMock).not.toHaveBeenCalled();
    expect(toastMock).toHaveBeenCalledWith(
      expect.objectContaining({ variant: "destructive", title: "Validation" }),
    );
  });

  it("creates a user with the form values", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("analyst@example.com");

    await user.click(screen.getByRole("button", { name: "Create user" }));
    const dialog = screen.getByRole("dialog");
    await user.type(within(dialog).getByLabelText("Email"), "new@example.com");
    await user.type(within(dialog).getByLabelText("Full name (optional)"), "New Analyst");
    await user.type(within(dialog).getByLabelText("Temporary password"), "StrongPass123!");
    await user.click(within(dialog).getByRole("button", { name: "Create user" }));

    await waitFor(() =>
      expect(createUserMock).toHaveBeenCalledWith({
        email: "new@example.com",
        password: "StrongPass123!",
        full_name: "New Analyst",
        role: "viewer",
        rate_limit_minutes: 0,
      }),
    );
  });

  it("sends the configured rate limit and clamps it to the allowed range", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("analyst@example.com");

    await user.click(screen.getByRole("button", { name: "Create user" }));
    const dialog = screen.getByRole("dialog");
    await user.type(within(dialog).getByLabelText("Email"), "new@example.com");
    await user.type(within(dialog).getByLabelText("Temporary password"), "StrongPass123!");
    const rateLimit = within(dialog).getByLabelText("Rate limit (minutes)");
    await user.clear(rateLimit);
    await user.type(rateLimit, "9999");
    await user.click(within(dialog).getByRole("button", { name: "Create user" }));

    await waitFor(() =>
      expect(createUserMock).toHaveBeenCalledWith(
        expect.objectContaining({ rate_limit_minutes: 1440 }),
      ),
    );
  });

  it("reports what each account owes and clears a second factor", async () => {
    const enrolled = { ...analyst, totp_enabled_at: "2026-02-01T00:00:00Z" };
    const pending = {
      ...analyst,
      id: "pending-1",
      email: "pending@example.com",
      must_change_password: true,
      must_enrol_mfa: true,
      totp_enabled_at: null,
    };
    listUsersMock.mockResolvedValue({
      items: [enrolled, pending],
      total: 2,
      page: 1,
      size: 20,
      pages: 1,
    });
    const user = userEvent.setup();
    renderPage();

    // A support call is answered from the table: whether the account has a factor,
    // and which steps it still owes.
    expect(await screen.findByText("2FA")).toBeInTheDocument();
    expect(screen.getByText("pending: new password + new second factor")).toBeInTheDocument();

    const resetButtons = screen.getAllByRole("button", { name: "Clear second factor" });
    // Only an account that has a factor can have one cleared; offering it for the
    // other would be a guaranteed 409 from the API.
    expect(resetButtons[0]).toBeEnabled();
    expect(resetButtons[1]).toBeDisabled();

    await user.click(resetButtons[0]);
    const dialog = screen.getByRole("dialog");
    expect(
      within(dialog).getByText("Clear this account's second factor?"),
    ).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Confirm action" }));

    await waitFor(() => expect(resetUserMfaMock).toHaveBeenCalledWith("analyst-1"));
  });

  it("holds back the second-factor action for the administrator's own account", async () => {
    // The API refuses clearing your own factor over the API — a session that can
    // remove its own second factor is not a second factor — so the table must not
    // offer it.
    listUsersMock.mockResolvedValue({
      items: [{ ...admin, totp_enabled_at: "2026-02-01T00:00:00Z" }],
      total: 1,
      page: 1,
      size: 20,
      pages: 1,
    });
    renderPage();

    await screen.findByText("admin@example.com");
    expect(screen.getByRole("button", { name: "Clear second factor" })).toBeDisabled();
  });

  it("opens confirmation for deactivation and sends the active-state mutation", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("analyst@example.com");

    const deactivateButton = screen
      .getAllByRole("button", { name: "Deactivate" })
      .find((button) => !button.hasAttribute("disabled"));
    expect(deactivateButton).toBeDefined();
    await user.click(deactivateButton!);
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Confirm action" }));

    await waitFor(() =>
      expect(updateUserMock).toHaveBeenCalledWith("analyst-1", { is_active: false }),
    );
  });
});
