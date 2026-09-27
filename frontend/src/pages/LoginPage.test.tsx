import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import type { User } from "@/types/api";

const { loginMock, toastMock } = vi.hoisted(() => ({ loginMock: vi.fn(), toastMock: vi.fn() }));

vi.mock("@/lib/api", () => ({
  endpoints: {
    login: loginMock,
  },
  describeApiError: (error: any) => { const d = error?.response?.data?.detail; if (typeof d === "string") return d; if (Array.isArray(d)) return d.map((x: any) => x?.msg ?? String(x)).join("; "); return String(error?.message ?? error ?? ""); },
}));

vi.mock("@/components/ui/use-toast", () => ({
  toast: toastMock,
}));

import LoginPage from "@/pages/LoginPage";
import { useAuthStore } from "@/store/auth";

const user: User = {
  id: "user-1",
  email: "admin@example.com",
  role: "admin",
  is_active: true,
  rate_limit_minutes: 0,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

const response = {
  access_token: "access-token",
  token_type: "bearer" as const,
  expires_in: 900,
  user,
};

function renderLogin() {
  return render(
    <MemoryRouter initialEntries={["/login"]}>
      <LoginPage />
    </MemoryRouter>,
  );
}

describe("LoginPage", () => {
  beforeEach(() => {
    loginMock.mockReset();
    toastMock.mockReset();
    useAuthStore.getState().clearAuth();
    useAuthStore.setState({ isHydrated: true });
  });

  it("rejects an empty submission before calling the API", async () => {
    const userEventApi = userEvent.setup();
    renderLogin();

    await userEventApi.click(screen.getByRole("button", { name: "Sign in" }));

    expect(loginMock).not.toHaveBeenCalled();
  });

  it("submits trimmed email, keeps password opaque, and updates auth state", async () => {
    const userEventApi = userEvent.setup();
    loginMock.mockResolvedValue(response);
    renderLogin();

    await userEventApi.type(screen.getByLabelText("Email"), "  admin@example.com  ");
    await userEventApi.type(screen.getByLabelText("Password"), "Password123!");
    expect(screen.getByLabelText("Password")).toHaveAttribute("type", "password");

    await userEventApi.click(screen.getByRole("button", { name: "Sign in" }));

    expect(loginMock).toHaveBeenCalledWith("admin@example.com", "Password123!");
    expect(useAuthStore.getState().token).toBe("access-token");
  });

  it("survives a validation-error payload instead of crashing the app", async () => {
    const userEventApi = userEvent.setup();
    // Regression: FastAPI answers a schema violation with a *list* of objects.
    // Feeding that array into a toast description used to throw during render
    // (React error #31) and replace the whole application with the error
    // boundary screen.
    loginMock.mockRejectedValueOnce({
      response: {
        status: 422,
        data: {
          detail: [
            {
              type: "value_error",
              loc: ["body", "email"],
              msg: "The part after the @-sign is not valid.",
              input: "admin@b",
            },
          ],
        },
      },
    });
    renderLogin();

    await userEventApi.type(screen.getByLabelText("Email"), "admin@b");
    await userEventApi.type(screen.getByLabelText("Password"), "Password123!");
    await userEventApi.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({
          variant: "destructive",
          title: "Sign in failed",
          description: expect.stringContaining("The part after the @-sign is not valid."),
        }),
      ),
    );
    // Still the sign-in form, not the crash fallback.
    expect(screen.getByRole("button", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.queryByText("Something went wrong")).not.toBeInTheDocument();
  });

  it("labels a lockout as too many attempts and keeps the API reason", async () => {
    const userEventApi = userEvent.setup();
    loginMock.mockRejectedValueOnce({
      response: {
        status: 429,
        data: { detail: "Too many failed attempts. Try again in 15 minutes." },
      },
    });
    renderLogin();

    await userEventApi.type(screen.getByLabelText("Email"), "admin@example.com");
    await userEventApi.type(screen.getByLabelText("Password"), "WrongPass123!");
    await userEventApi.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({
          variant: "destructive",
          title: "Too many sign-in attempts",
          description: "Too many failed attempts. Try again in 15 minutes.",
        }),
      ),
    );
  });

  it("rejects an address without a domain before calling the API", async () => {
    const userEventApi = userEvent.setup();
    renderLogin();

    await userEventApi.type(screen.getByLabelText("Email"), "admin");
    await userEventApi.type(screen.getByLabelText("Password"), "Password123!");
    await userEventApi.click(screen.getByRole("button", { name: "Sign in" }));

    expect(loginMock).not.toHaveBeenCalled();
    expect(toastMock).toHaveBeenCalledWith(
      expect.objectContaining({ variant: "destructive", title: "Validation error" }),
    );
  });

  it("asks for an authenticator code only after the API says it is required", async () => {
    const userEventApi = userEvent.setup();
    // The first attempt carries no code, because the platform cannot know before
    // verifying the password whether this account has a second factor.
    loginMock.mockRejectedValueOnce({
      response: { status: 401, data: { detail: "MFA code required" } },
    });
    renderLogin();

    await userEventApi.type(screen.getByLabelText("Email"), "admin@example.com");
    await userEventApi.type(screen.getByLabelText("Password"), "Password123!");
    await userEventApi.click(screen.getByRole("button", { name: "Sign in" }));

    expect(loginMock).toHaveBeenNthCalledWith(1, "admin@example.com", "Password123!");
    const codeField = await screen.findByLabelText("Authenticator code");
    expect(toastMock).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Second factor required" }),
    );

    // A missing code is caught before the request rather than sent empty.
    await userEventApi.click(screen.getByRole("button", { name: "Sign in" }));
    expect(loginMock).toHaveBeenCalledTimes(1);

    loginMock.mockResolvedValueOnce(response);
    await userEventApi.type(codeField, "123456");
    await userEventApi.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() =>
      expect(loginMock).toHaveBeenLastCalledWith("admin@example.com", "Password123!", "123456"),
    );
    expect(useAuthStore.getState().token).toBe("access-token");
  });

  it("keeps the code field hidden when the password is simply wrong", async () => {
    const userEventApi = userEvent.setup();
    loginMock.mockRejectedValueOnce({
      response: { status: 401, data: { detail: "Invalid email or password" } },
    });
    renderLogin();

    await userEventApi.type(screen.getByLabelText("Email"), "admin@example.com");
    await userEventApi.type(screen.getByLabelText("Password"), "WrongPass123!");
    await userEventApi.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({ variant: "destructive", title: "Sign in failed" }),
      ),
    );
    expect(screen.queryByLabelText("Authenticator code")).not.toBeInTheDocument();
  });

  it("allows password visibility to be toggled without changing the value", async () => {
    const userEventApi = userEvent.setup();
    renderLogin();
    const password = screen.getByLabelText("Password");
    await userEventApi.type(password, "Password123!");

    await userEventApi.click(screen.getByRole("button", { name: "Show password" }));

    expect(screen.getByLabelText("Password")).toHaveAttribute("type", "text");
    expect(screen.getByLabelText("Password")).toHaveValue("Password123!");
  });
});
