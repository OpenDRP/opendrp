import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  meMock,
  mfaSetupMock,
  mfaEnableMock,
  changePasswordMock,
  toastMock,
  navigateMock,
} = vi.hoisted(() => ({
  meMock: vi.fn(),
  mfaSetupMock: vi.fn(),
  mfaEnableMock: vi.fn(),
  changePasswordMock: vi.fn(),
  toastMock: vi.fn(),
  navigateMock: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  endpoints: {
    me: meMock,
    mfaSetup: mfaSetupMock,
    mfaEnable: mfaEnableMock,
    changePassword: changePasswordMock,
  },
  describeApiError: (error: any, fallback = "") =>
    String(error?.response?.data?.detail ?? error?.message ?? fallback),
}));

vi.mock("@/components/ui/use-toast", () => ({ toast: toastMock }));

vi.mock("react-router-dom", () => ({
  useNavigate: () => navigateMock,
}));

/** The store as the page uses it: a selector over a mutable state object. */
const storeState = {
  user: null as any,
  setUser: vi.fn(),
  setSession: vi.fn(),
  logout: vi.fn(),
};

vi.mock("@/store/auth", () => ({
  useAuthStore: (selector: any) => selector(storeState),
}));

import OnboardingPage from "@/pages/OnboardingPage";

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <OnboardingPage />
    </QueryClientProvider>,
  );
}

const baseUser = {
  id: "user-1",
  email: "analyst@example.com",
  role: "analyst" as const,
  is_active: true,
  rate_limit_minutes: 0,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

describe("OnboardingPage", () => {
  beforeEach(() => {
    meMock.mockReset();
    mfaSetupMock.mockReset();
    mfaEnableMock.mockReset();
    changePasswordMock.mockReset();
    toastMock.mockReset();
    navigateMock.mockReset();
    storeState.setUser.mockReset();
    storeState.logout.mockReset();
    // The session the page adopts is the one it then reasons about, exactly as the
    // real store works: a step that changes the account has to change what the page
    // shows next.
    storeState.setSession.mockReset();
    storeState.setSession.mockImplementation((data: any) => {
      storeState.user = data.user;
    });
  });

  it("asks for the account's own password and adopts the rotated session", async () => {
    storeState.user = { ...baseUser, must_change_password: true };
    meMock.mockResolvedValue({ ...baseUser, must_change_password: true });
    changePasswordMock.mockResolvedValue({
      access_token: "fresh-token",
      token_type: "bearer",
      expires_in: 900,
      user: { ...baseUser, must_change_password: false },
    });

    const user = userEvent.setup();
    renderPage();

    expect(await screen.findByText("Choose your own password")).toBeInTheDocument();
    // The guidance for a session that cannot complete the step is on the page,
    // not in a support ticket.
    expect(screen.getByText(/Do not have the temporary password/i)).toBeInTheDocument();

    await user.type(screen.getByLabelText("Current (temporary) password"), "TestPass123!");
    await user.type(screen.getByLabelText("New password"), "FreshPass456!");
    await user.type(screen.getByLabelText("Repeat new password"), "FreshPass456!");
    await user.click(screen.getByRole("button", { name: "Save new password" }));

    await waitFor(() =>
      expect(changePasswordMock).toHaveBeenCalledWith("TestPass123!", "FreshPass456!"),
    );
    // The response carries a new session: the change revoked the old refresh
    // cookie, so a client that kept the old token would break on its next call.
    await waitFor(() =>
      expect(storeState.setSession).toHaveBeenCalledWith(
        expect.objectContaining({ access_token: "fresh-token" }),
      ),
    );
    // Nothing else is owed, so the flow ends here rather than on a summary page:
    // the operator came to set a password, not to look at a confirmation.
    await waitFor(() =>
      expect(navigateMock).toHaveBeenCalledWith("/dashboard", { replace: true }),
    );
  });

  it("refuses to submit a mismatched or weak password without calling the API", async () => {
    storeState.user = { ...baseUser, must_change_password: true };
    meMock.mockResolvedValue({ ...baseUser, must_change_password: true });

    const user = userEvent.setup();
    renderPage();
    await screen.findByText("Choose your own password");

    await user.type(screen.getByLabelText("Current (temporary) password"), "TestPass123!");
    await user.type(screen.getByLabelText("New password"), "weak");
    await user.type(screen.getByLabelText("Repeat new password"), "weak");
    await user.click(screen.getByRole("button", { name: "Save new password" }));
    expect(changePasswordMock).not.toHaveBeenCalled();
    expect(screen.getByText(/must be at least 12 characters long/i)).toBeInTheDocument();

    await user.clear(screen.getByLabelText("New password"));
    await user.type(screen.getByLabelText("New password"), "FreshPass456!");
    await user.clear(screen.getByLabelText("Repeat new password"));
    await user.type(screen.getByLabelText("Repeat new password"), "FreshPass457!");
    await user.click(screen.getByRole("button", { name: "Save new password" }));
    expect(changePasswordMock).not.toHaveBeenCalled();
    expect(screen.getByText(/do not match/i)).toBeInTheDocument();
  });

  it("requires a new factor after one was cleared", async () => {
    storeState.user = { ...baseUser, must_enrol_mfa: true };
    meMock.mockResolvedValue({ ...baseUser, must_enrol_mfa: true });
    mfaSetupMock.mockResolvedValue({
      secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      otpauth_uri: "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ",
      digits: 6,
      period_seconds: 30,
    });
    mfaEnableMock.mockResolvedValue({ enabled: true, enabled_at: "2026-02-01T00:00:00Z" });
    meMock
      .mockResolvedValueOnce({ ...baseUser, must_enrol_mfa: true })
      .mockResolvedValue({ ...baseUser, must_enrol_mfa: false });

    const user = userEvent.setup();
    renderPage();

    expect(await screen.findByText("Enrol an authenticator app")).toBeInTheDocument();
    expect(screen.getByText(/never leaves the account weaker/i)).toBeInTheDocument();

    await user.type(screen.getByLabelText("Password"), "TestPass123!");
    await user.click(screen.getByRole("button", { name: "Start enrolment" }));
    await user.type(await screen.findByLabelText("Code from the app"), "123456");
    await user.click(screen.getByRole("button", { name: "Confirm and enable" }));

    await waitFor(() => expect(mfaEnableMock).toHaveBeenCalledWith("TestPass123!", "123456"));
    // The route guard reads the session's flags, so the store has to learn that
    // the requirement is satisfied — otherwise the operator is sent straight back.
    await waitFor(() => expect(storeState.setUser).toHaveBeenCalled());
    await waitFor(() =>
      expect(navigateMock).toHaveBeenCalledWith("/dashboard", { replace: true }),
    );
  });

  it("offers the factor step when the deployment's policy asks for one", async () => {
    // `REQUIRE_MFA_FOR_ADMINS` is computed by the API rather than stored on the
    // account, so the signal is a field on the user — and it is on the response that
    // signed the session in, which is what makes the step appear at the first sign-in
    // instead of on the first admin page that gets refused.
    storeState.user = { ...baseUser, role: "admin", mfa_required_by_policy: true };
    meMock.mockResolvedValue({ ...baseUser, role: "admin", mfa_required_by_policy: true });

    renderPage();

    expect(await screen.findByText("Enrol an authenticator app")).toBeInTheDocument();
    expect(screen.getByText(/This installation requires administrators/i)).toBeInTheDocument();
  });

  /**
   * Both obligations on one account, in the order the server enforces: the factor
   * cannot be attached while a temporary password is in force, so the page has to
   * carry the operator from one step into the next rather than declaring the work
   * done when the password changes.
   */
  it("moves from the password step straight into a factor the installation requires", async () => {
    storeState.user = {
      ...baseUser,
      role: "admin",
      must_change_password: true,
      mfa_required_by_policy: true,
    };
    meMock.mockResolvedValue({ ...storeState.user });
    changePasswordMock.mockResolvedValue({
      access_token: "fresh-token",
      token_type: "bearer",
      expires_in: 900,
      user: {
        ...baseUser,
        role: "admin",
        must_change_password: false,
        mfa_required_by_policy: true,
      },
    });
    mfaSetupMock.mockResolvedValue({
      secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      otpauth_uri: "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ",
      digits: 6,
      period_seconds: 30,
    });

    const user = userEvent.setup();
    renderPage();

    await screen.findByText("Choose your own password");
    await user.type(screen.getByLabelText("Current (temporary) password"), "TestPass123!");
    await user.type(screen.getByLabelText("New password"), "FreshPass456!");
    await user.type(screen.getByLabelText("Repeat new password"), "FreshPass456!");
    await user.click(screen.getByRole("button", { name: "Save new password" }));

    expect(await screen.findByText("Enrol an authenticator app")).toBeInTheDocument();
    // The dashboard would refuse the very next request, so sending the operator
    // there between the two steps would only produce a page of failures.
    expect(navigateMock).not.toHaveBeenCalledWith("/dashboard", { replace: true });
    expect(screen.queryByText("Nothing is pending")).not.toBeInTheDocument();
  });

  it("says so when nothing is pending, instead of inventing a step", async () => {
    storeState.user = baseUser;
    meMock.mockResolvedValue(baseUser);

    renderPage();

    expect(await screen.findByText("Nothing is pending")).toBeInTheDocument();
    expect(screen.queryByLabelText("Current (temporary) password")).not.toBeInTheDocument();
  });

  it("lets a session that cannot complete the step sign out", async () => {
    storeState.user = { ...baseUser, must_change_password: true };
    meMock.mockResolvedValue({ ...baseUser, must_change_password: true });

    const user = userEvent.setup();
    renderPage();
    await screen.findByText("Choose your own password");
    await user.click(screen.getByRole("button", { name: "Sign out" }));

    expect(storeState.logout).toHaveBeenCalled();
    expect(navigateMock).toHaveBeenCalledWith("/login", { replace: true });
  });
});
