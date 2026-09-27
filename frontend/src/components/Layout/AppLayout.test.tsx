import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Outlet } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AppLayout } from "@/components/Layout/AppLayout";
import { useAuthStore } from "@/store/auth";
import type { RegistryModule, User } from "@/types/api";

const { fetchModulesMock, logoutMock } = vi.hoisted(() => ({
  fetchModulesMock: vi.fn(),
  logoutMock: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  endpoints: { logout: logoutMock, restoreSession: vi.fn(), login: vi.fn() },
}));

vi.mock("@/lib/modules", async (importOriginal) => ({
  // Keep the real helpers (e.g. declaredModules) and stub only the transport.
  ...(await importOriginal<typeof import("@/lib/modules")>()),
  fetchModules: fetchModulesMock,
}));

vi.mock("@/components/ui/dropdown-menu", () => ({
  DropdownMenu: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  DropdownMenuTrigger: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  DropdownMenuContent: ({ children }: { children: React.ReactNode }) => <div role="menu">{children}</div>,
  DropdownMenuItem: ({ children, onClick }: { children: React.ReactNode; onClick?: () => void }) => <button role="menuitem" onClick={onClick}>{children}</button>,
  DropdownMenuLabel: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  DropdownMenuSeparator: () => <hr />,
}));

vi.mock("@/components/Theme/ThemeToggle", () => ({
  ThemeToggle: () => <button type="button">Theme control</button>,
}));

const viewer: User = {
  id: "viewer-1",
  email: "viewer@example.com",
  role: "viewer",
  is_active: true,
  rate_limit_minutes: 0,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

function renderLayout(user: User) {
  useAuthStore.setState({ user, token: "access-token", isHydrated: true });
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/dashboard"]}>
        <AppLayout />
        <Outlet />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function moduleFixture(overrides: Partial<RegistryModule>): RegistryModule {
  return {
    id: "code_leak",
    label: "Code leaks",
    finding_kind: "code_leak",
    asset_types: ["domain"],
    fields: { repository: { type: "str", required: true } },
    dedup_fields: ["repository"],
    title_field: "repository",
    storage: "generic",
    enabled: true,
    builtin: false,
    ...overrides,
  };
}

describe("AppLayout", () => {
  beforeEach(() => {
    useAuthStore.getState().clearAuth();
    fetchModulesMock.mockReset().mockResolvedValue({
      modules: [],
      generated_at: "2026-01-01T00:00:00Z",
    });
  });

  it("links a module declared on the core, without duplicating built-in pages", async () => {
    fetchModulesMock.mockResolvedValue({
      modules: [
        moduleFixture({}),
        moduleFixture({ id: "phishing", label: "Phishing", storage: "table", builtin: true }),
        moduleFixture({ id: "retired", label: "Retired", enabled: false }),
      ],
      generated_at: "2026-01-01T00:00:00Z",
    });
    renderLayout(viewer);

    const declared = await screen.findByRole("link", { name: "Code leaks" });
    expect(declared).toHaveAttribute("href", "/modules/code_leak");
    // A table-backed module keeps its own page; a disabled one is not linkable.
    expect(screen.getAllByRole("link", { name: "Phishing" })).toHaveLength(1);
    expect(screen.queryByRole("link", { name: "Retired" })).not.toBeInTheDocument();
  });

  it("shows common navigation and hides admin links for viewers", () => {
    renderLayout(viewer);
    expect(screen.getByText("OpenDRP Platform")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Dashboard" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Assets" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Users" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Audit Log" })).not.toBeInTheDocument();
    expect(screen.queryByText("Theme control")).toBeInTheDocument();
  });

  it("shows admin navigation and closes the mobile drawer with Escape", () => {
    renderLayout({ ...viewer, role: "admin" });
    expect(screen.getByRole("link", { name: "Users" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Audit Log" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Settings" })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Open navigation menu" }));
    expect(screen.getByRole("dialog", { name: "Mobile navigation" })).toBeInTheDocument();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog", { name: "Mobile navigation" })).not.toBeInTheDocument();
  });

  it("logs out through the account menu and revokes the session at the API", async () => {
    renderLayout(viewer);
    fireEvent.pointerDown(screen.getByRole("button", { name: /viewer@example.com/i }), { button: 0 });
    const logoutItem = await screen.findByRole("menuitem", { name: "Logout" });
    fireEvent.click(logoutItem);
    expect(useAuthStore.getState().user).toBeNull();
    expect(useAuthStore.getState().token).toBeNull();
    // Clearing the browser alone would not end anything: the refresh cookie is
    // what the next load asks the API about, so the sign-out has to reach it.
    expect(logoutMock).toHaveBeenCalledTimes(1);
  });
});
