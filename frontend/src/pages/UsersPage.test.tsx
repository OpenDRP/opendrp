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
  unlockUserMock,
  exportUsersMock,
  listUserSessionsMock,
  revokeUserSessionsMock,
  bulkUsersMock,
  inviteUserMock,
  reissueInvitationMock,
  toastMock,
} = vi.hoisted(() => ({
  listUsersMock: vi.fn(),
  createUserMock: vi.fn(),
  updateUserMock: vi.fn(),
  deleteUserMock: vi.fn(),
  resetUserMfaMock: vi.fn(),
  unlockUserMock: vi.fn(),
  exportUsersMock: vi.fn(),
  listUserSessionsMock: vi.fn(),
  revokeUserSessionsMock: vi.fn(),
  bulkUsersMock: vi.fn(),
  inviteUserMock: vi.fn(),
  reissueInvitationMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  endpoints: {
    listUsers: listUsersMock,
    createUser: createUserMock,
    updateUser: updateUserMock,
    deleteUser: deleteUserMock,
    resetUserMfa: resetUserMfaMock,
    unlockUser: unlockUserMock,
    exportUsers: exportUsersMock,
    listUserSessions: listUserSessionsMock,
    revokeUserSessions: revokeUserSessionsMock,
    bulkUsers: bulkUsersMock,
    inviteUser: inviteUserMock,
    reissueInvitation: reissueInvitationMock,
  },
  flattenErrorDetail: (detail: unknown) => String(detail ?? ""),
  describeApiError: (error: any) => String(error?.response?.data?.detail ?? error?.message ?? error ?? ""),
}));

vi.mock("@/components/ui/use-toast", () => ({ toast: toastMock }));
vi.mock("@/components/ui/select", () => ({
  // A native select stands in for the Radix one: the page's contract is
  // `value` + `onValueChange`, and driving Radix's own keyboard handling would
  // test the component library rather than which filter this page sends.
  Select: ({ value, onValueChange, children }: any) => {
    const parts = Array.isArray(children) ? children : [children];
    const label = parts[0]?.props?.["aria-label"];
    const options = parts[parts.length - 1]?.props?.children;
    return (
      <select aria-label={label} value={value} onChange={(event) => onValueChange(event.target.value)}>
        {Array.isArray(options) ? options : null}
      </select>
    );
  },
  SelectTrigger: () => null,
  SelectValue: () => null,
  SelectContent: ({ children }: any) => <>{children}</>,
  SelectItem: ({ value, children }: any) => <option value={value}>{children}</option>,
}));
vi.mock("@/components/DataTable", () => ({
  PaginatedDataTable: ({ columns, rows, loading, selectable, selectedIds = [], onSelectedChange }: any) => (
    <div>
      {loading && rows.length === 0 ? <span>Loading table</span> : null}
      {rows.map((row: any) => (
        <div key={row.id}>
          {selectable && onSelectedChange ? (
            <input
              type="checkbox"
              aria-label={`Select ${row.email}`}
              checked={selectedIds.includes(row.id)}
              onChange={(event) =>
                onSelectedChange(
                  event.target.checked
                    ? [...selectedIds, row.id]
                    : selectedIds.filter((id: string) => id !== row.id),
                )
              }
            />
          ) : null}
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

function selectByLabel(label: string) {
  return screen.getByLabelText(label) as HTMLSelectElement;
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
    unlockUserMock.mockReset().mockResolvedValue(analyst);
    exportUsersMock.mockReset().mockResolvedValue(new Blob(["email\n"]));
    listUserSessionsMock.mockReset().mockResolvedValue([]);
    revokeUserSessionsMock.mockReset().mockResolvedValue({ revoked: 0 });
    bulkUsersMock.mockReset().mockResolvedValue({ operation: "deactivate", changed: 1, skipped: 0, revoked_sessions: 1 });
    inviteUserMock.mockReset().mockResolvedValue({
      user: analyst,
      invitation_token: "invite-token",
      expires_at: "2026-03-01T00:00:00Z",
      email_scheduled: false,
    });
    reissueInvitationMock.mockReset().mockResolvedValue({
      user: analyst,
      invitation_token: "new-token",
      expires_at: "2026-03-01T00:00:00Z",
      email_scheduled: true,
    });
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

  it("releases a brute-force lockout without touching anything else", async () => {
    const locked = {
      ...analyst,
      locked_until: new Date(Date.now() + 15 * 60_000).toISOString(),
      failed_login_attempts: 8,
    };
    listUsersMock.mockResolvedValue({
      items: [locked],
      total: 1,
      page: 1,
      size: 20,
      pages: 1,
    });
    const user = userEvent.setup();
    renderPage();

    expect(await screen.findByText("Locked (Brute-force)")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Unlock" }));

    await waitFor(() => expect(unlockUserMock).toHaveBeenCalledWith("analyst-1"));
    expect(toastMock).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Account unlocked" }),
    );
  });

  it("does not offer an unlock for an account that is not locked", async () => {
    renderPage();
    await screen.findByText("analyst@example.com");

    expect(screen.queryByRole("button", { name: "Unlock" })).not.toBeInTheDocument();
  });

  it("renders a missing sign-in as never, not as an empty cell", async () => {
    listUsersMock.mockResolvedValue({
      items: [
        { ...analyst, last_login_at: "2026-02-01T10:11:12Z" },
        { ...admin, last_login_at: null },
      ],
      total: 2,
      page: 1,
      size: 20,
      pages: 1,
    });
    renderPage();

    expect(await screen.findByText("never")).toBeInTheDocument();
    expect(screen.getByText("2026-02-01 10:11:12")).toBeInTheDocument();
    // The first page asks for every account; "never signed in" is a filter the
    // operator chooses, never the default.
    expect(listUsersMock).toHaveBeenCalledWith(
      expect.objectContaining({ signed_in: undefined }),
    );
  });

  it("asks the server for accounts that have never signed in", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("analyst@example.com");

    await user.selectOptions(screen.getByLabelText("Filter by sign-in history"), "never");

    await waitFor(() =>
      expect(listUsersMock).toHaveBeenLastCalledWith(
        expect.objectContaining({ signed_in: false }),
      ),
    );
  });

  it("shows deployment-required MFA in the security state", async () => {
    listUsersMock.mockResolvedValue({
      items: [{ ...analyst, id: "policy-admin", email: "policy-admin@example.com", role: "admin", mfa_required_by_policy: true }],
      total: 1,
      page: 1,
      size: 20,
      pages: 1,
    });
    renderPage();

    expect(await screen.findByText("pending: MFA required by policy")).toBeInTheDocument();
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

  it("asks the server for the support slice the operator picked", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("analyst@example.com");

    await user.selectOptions(selectByLabel("Filter by support view"), "no-mfa");
    await waitFor(() =>
      expect(listUsersMock).toHaveBeenLastCalledWith(
        expect.objectContaining({ mfa_enrolled: false }),
      ),
    );

    await user.selectOptions(selectByLabel("Filter by support view"), "locked");
    await waitFor(() =>
      expect(listUsersMock).toHaveBeenLastCalledWith(
        expect.objectContaining({ locked: true, mfa_enrolled: undefined }),
      ),
    );
  });

  it("exports with the filters the table is showing", async () => {
    // jsdom has no download navigation; the assertion is about the request the
    // page makes, not about the browser saving a file.
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("analyst@example.com");

    await user.selectOptions(selectByLabel("Filter by support view"), "onboarding");
    await user.click(screen.getByRole("button", { name: "Export CSV" }));

    await waitFor(() =>
      expect(exportUsersMock).toHaveBeenCalledWith(
        expect.objectContaining({
          format: "csv",
          requires_onboarding: true,
          locked: undefined,
        }),
      ),
    );
    click.mockRestore();
  });

  it("lists an account's sessions and ends them without exposing a token", async () => {
    listUserSessionsMock.mockResolvedValue([
      {
        id: "family-1",
        created_at: "2026-02-01T10:00:00Z",
        last_used_at: "2026-02-02T11:00:00Z",
        current: false,
      },
    ]);
    revokeUserSessionsMock.mockResolvedValue({ revoked: 1 });
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("analyst@example.com");

    await user.click(screen.getAllByRole("button", { name: "Show sessions" })[0]);
    expect(await screen.findByText("family-1")).toBeInTheDocument();
    expect(screen.getByText(/Created 2026-02-01 10:00:00/)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "End all sessions" }));
    await waitFor(() => expect(revokeUserSessionsMock).toHaveBeenCalledWith("admin-1"));
  });

  it("invites a user and shows the one-time link exactly once", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("analyst@example.com");

    await user.click(screen.getByRole("button", { name: "Invite user" }));
    const dialog = screen.getByRole("dialog");
    await user.type(within(dialog).getByLabelText("Email"), "invited@example.com");
    await user.click(within(dialog).getByRole("button", { name: "Create invitation" }));

    await waitFor(() =>
      expect(inviteUserMock).toHaveBeenCalledWith({
        email: "invited@example.com",
        role: "viewer",
        full_name: undefined,
      }),
    );
    const link = await screen.findByLabelText("Link for invited@example.com");
    expect((link as HTMLInputElement).value).toContain("/accept-invitation?token=invite-token");
    expect(screen.getByText(/No email was queued/)).toBeInTheDocument();
  });

  it("sends one bulk deactivation for the selected accounts", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("analyst@example.com");

    await user.click(screen.getByRole("checkbox", { name: "Select analyst@example.com" }));
    expect(screen.getByText("1 selected")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Deactivate selected/ }));
    await user.click(screen.getByRole("button", { name: "Confirm action" }));

    await waitFor(() =>
      expect(bulkUsersMock).toHaveBeenCalledWith({
        operation: "deactivate",
        user_ids: ["analyst-1"],
      }),
    );
  });
});
