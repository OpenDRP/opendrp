import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { RequireAuth } from "@/components/Auth/RequireAuth";
import { useAuthStore } from "@/store/auth";
import type { User } from "@/types/api";

vi.mock("@/components/ui/use-toast", () => ({
  toast: vi.fn(),
}));

const user: User = {
  id: "user-1",
  email: "viewer@example.com",
  role: "viewer",
  is_active: true,
  rate_limit_minutes: 0,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

function renderGuard() {
  return render(
    <MemoryRouter initialEntries={["/protected"]}>
      <RequireAuth allowedRoles={["admin"]}>
        <div>protected content</div>
      </RequireAuth>
    </MemoryRouter>,
  );
}

describe("RequireAuth", () => {
  beforeEach(() => {
    useAuthStore.getState().clearAuth();
    useAuthStore.setState({ isHydrated: false });
  });

  it("shows a loading state before persisted auth is hydrated", () => {
    renderGuard();
    expect(screen.getByText("Loading session...")).toBeInTheDocument();
  });

  it("redirects unauthenticated users to login after hydration", () => {
    useAuthStore.setState({ isHydrated: true, user: null, token: null });
    renderGuard();
    expect(screen.queryByText("protected content")).not.toBeInTheDocument();
  });

  it("renders protected content for an allowed role", () => {
    useAuthStore.setState({ isHydrated: true, user: { ...user, role: "admin" }, token: "access" });
    renderGuard();
    expect(screen.getByText("protected content")).toBeInTheDocument();
  });

  it("renders an explicit forbidden state for a disallowed role", () => {
    useAuthStore.setState({ isHydrated: true, user, token: "access" });
    renderGuard();
    expect(screen.getByText("403 — Forbidden")).toBeInTheDocument();
    expect(
      screen.getByText(/Your account does not have sufficient permissions/),
    ).toBeInTheDocument();
    expect(screen.getByText("admin")).toBeInTheDocument();
    expect(screen.queryByText("protected content")).not.toBeInTheDocument();
  });
});
