import { act, render, screen } from "@testing-library/react";
import { MemoryRouter, Outlet } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "@/App";
import { useAuthStore } from "@/store/auth";
import { toast } from "@/components/ui/use-toast";
import type { User } from "@/types/api";

const { logoutMock, restoreSessionMock } = vi.hoisted(() => ({
  logoutMock: vi.fn(),
  restoreSessionMock: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  endpoints: { logout: logoutMock, restoreSession: restoreSessionMock, login: vi.fn() },
}));

vi.mock("@/components/ui/use-toast", () => ({ toast: vi.fn() }));
vi.mock("@/components/Layout/AppLayout", () => ({
  AppLayout: () => <><div>Application layout</div><Outlet /></>,
}));

vi.mock("@/pages/LoginPage", () => ({ default: () => <div>Login page</div> }));
vi.mock("@/pages/DashboardPage", () => ({ default: () => <div>Dashboard page</div> }));
vi.mock("@/pages/AssetsPage", () => ({ default: () => <div>Assets page</div> }));
vi.mock("@/pages/PhishingPage", () => ({ default: () => <div>Phishing page</div> }));
vi.mock("@/pages/BreachesPage", () => ({ default: () => <div>Breaches page</div> }));
vi.mock("@/pages/ReportsPage", () => ({ default: () => <div>Reports page</div> }));
vi.mock("@/pages/SecurityPage", () => ({ default: () => <div>Security page</div> }));
vi.mock("@/pages/OnboardingPage", () => ({ default: () => <div>Onboarding page</div> }));
vi.mock("@/pages/UsersPage", () => ({ default: () => <div>Users page</div> }));
vi.mock("@/pages/AuditPage", () => ({ default: () => <div>Audit page</div> }));
vi.mock("@/pages/SettingsPage", () => ({ default: () => <div>Settings page</div> }));
vi.mock("@/pages/NotFoundPage", () => ({ default: () => <div>Not found page</div> }));

const user: User = {
  id: "user-1",
  email: "viewer@example.com",
  role: "viewer",
  is_active: true,
  rate_limit_minutes: 0,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

function renderApp(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  );
}

describe("App routes and authorization", () => {
  beforeEach(() => {
    useAuthStore.getState().clearAuth();
    useAuthStore.setState({ isHydrated: true });
  });

  it("keeps public login and not-found routes accessible without a session", () => {
    const { unmount } = renderApp("/login");
    expect(screen.getByText("Login page")).toBeInTheDocument();
    unmount();

    renderApp("/does-not-exist");
    expect(screen.getByText("Not found page")).toBeInTheDocument();
  });

  it("redirects unauthenticated protected routes to login", () => {
    renderApp("/dashboard");
    expect(screen.getByText("Login page")).toBeInTheDocument();
    expect(screen.queryByText("Dashboard page")).not.toBeInTheDocument();
  });

  it("lets every role reach its own security page", () => {
    // The second factor belongs to the account, not to the role: an analyst who
    // cannot open the enrolment page has no way to protect their own account.
    useAuthStore.setState({ user, token: "access-token" });
    const { unmount } = renderApp("/security");
    expect(screen.getByText("Security page")).toBeInTheDocument();
    unmount();
  });

  it("allows viewer routes but denies admin-only routes", () => {
    useAuthStore.setState({ user, token: "access-token" });
    renderApp("/assets");
    expect(screen.getByText("Assets page")).toBeInTheDocument();

    const { unmount } = renderApp("/users");
    expect(screen.getByText("403 — Forbidden")).toBeInTheDocument();
    expect(screen.queryByText("Users page")).not.toBeInTheDocument();
    unmount();
  });

  it("allows admin routes and handles logout and unauthorized events", () => {
    useAuthStore.setState({ user: { ...user, role: "admin" }, token: "access-token" });
    const { unmount } = renderApp("/users");
    expect(screen.getByText("Users page")).toBeInTheDocument();
    unmount();

    renderApp("/logout");
    expect(screen.getByText("Login page")).toBeInTheDocument();
    expect(useAuthStore.getState().token).toBeNull();
    // Reaching the route ends the session on both sides: the client clear alone
    // would be undone by the next load, which asks the API about the cookie.
    expect(logoutMock).toHaveBeenCalledTimes(1);

    useAuthStore.setState({ user: { ...user, role: "admin" }, token: "access-token" });
    renderApp("/dashboard");
    window.dispatchEvent(new Event("auth:unauthorized"));
    expect(screen.getByText("Login page")).toBeInTheDocument();
  });

  it("sends an administrator to onboarding when the API requires a second factor", () => {
    // The deployment gate (`REQUIRE_MFA_FOR_ADMINS`) refuses admin routes for an
    // account with no enrolled authenticator. The account can fix that itself, so
    // the client routes it to the page that does, instead of leaving it on a
    // screen that only reports a permission error.
    useAuthStore.setState({ user: { ...user, role: "admin" }, token: "access-token" });
    vi.mocked(toast).mockClear();
    renderApp("/users");
    expect(screen.getByText("Users page")).toBeInTheDocument();

    // Wrapped in `act`: the listener both navigates and raises a toast, and both
    // are React state updates. Outside `act` they are batched and not flushed
    // before the assertion, so the DOM still shows the page being left.
    act(() => {
      window.dispatchEvent(new Event("auth:mfa-required"));
    });

    expect(screen.getByText("Onboarding page")).toBeInTheDocument();
    expect(screen.queryByText("Users page")).not.toBeInTheDocument();
    expect(vi.mocked(toast)).toHaveBeenCalledTimes(1);
    expect(useAuthStore.getState().token).toBe("access-token");
  });

  it("sends a session to onboarding when a credential step is pending", () => {
    // The other 403 the API raises for an account that owes something: a password
    // somebody else chose, or a factor that was cleared for it.
    useAuthStore.setState({ user, token: "access-token" });
    vi.mocked(toast).mockClear();
    renderApp("/assets");

    act(() => {
      window.dispatchEvent(new Event("auth:onboarding-required"));
    });

    expect(screen.getByText("Onboarding page")).toBeInTheDocument();
    expect(vi.mocked(toast)).toHaveBeenCalledTimes(1);
  });

  it("keeps an account with a pending credential on the onboarding page", () => {
    // The redirect event only fires for a request that was refused. A client
    // whose session predates an administrator's reset has to be stopped by the
    // route guard instead, or it would render a shell full of failing calls.
    useAuthStore.setState({
      user: { ...user, must_change_password: true },
      token: "access-token",
    });
    renderApp("/assets");

    expect(screen.getByText("Onboarding page")).toBeInTheDocument();
    expect(screen.queryByText("Assets page")).not.toBeInTheDocument();
  });

  it("does not redirect when the onboarding page is already open", () => {
    useAuthStore.setState({ user, token: "access-token" });
    vi.mocked(toast).mockClear();
    renderApp("/onboarding");

    act(() => {
      window.dispatchEvent(new Event("auth:onboarding-required"));
    });

    expect(screen.getByText("Onboarding page")).toBeInTheDocument();
    // A toast here would replace the page's own explanation of a failed step with
    // a message about a redirect that never happens.
    expect(vi.mocked(toast)).not.toHaveBeenCalled();
  });
});
