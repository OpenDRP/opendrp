import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { statusMock, setupMock, enableMock, disableMock, toastMock, listSessionsMock, activityMock, changePasswordMock, revokeOthersMock, revokeSessionMock, rotateRecoveryMock, setSessionMock } = vi.hoisted(() => ({
  statusMock: vi.fn(), setupMock: vi.fn(), enableMock: vi.fn(), disableMock: vi.fn(), toastMock: vi.fn(),
  listSessionsMock: vi.fn(), activityMock: vi.fn(), changePasswordMock: vi.fn(), revokeOthersMock: vi.fn(), revokeSessionMock: vi.fn(), rotateRecoveryMock: vi.fn(),
  setSessionMock: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  endpoints: {
    mfaStatus: statusMock,
    mfaSetup: setupMock,
    mfaEnable: enableMock,
    mfaDisable: disableMock,
    listSessions: listSessionsMock,
    securityActivity: activityMock,
    changePassword: changePasswordMock,
    revokeOtherSessions: revokeOthersMock,
    revokeSession: revokeSessionMock,
    mfaRotateRecoveryCodes: rotateRecoveryMock,
  },
  describeApiError: (error: any, fallback = "") =>
    String(error?.response?.data?.detail ?? error?.message ?? fallback),
}));

vi.mock("@/components/ui/use-toast", () => ({ toast: toastMock }));

vi.mock("@/store/auth", () => {
  const store = (selector: any) => selector({ user: { email: "analyst@example.com" } });
  // The change-password success path stores the session the API returned, so the
  // stand-in needs the same static accessor the page uses.
  return { useAuthStore: Object.assign(store, { getState: () => ({ setSession: setSessionMock }) }) };
});

import SecurityPage from "@/pages/SecurityPage";

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <SecurityPage />
    </QueryClientProvider>,
  );
}

describe("SecurityPage", () => {
  beforeEach(() => {
    statusMock.mockReset();
    setupMock.mockReset();
    enableMock.mockReset();
    disableMock.mockReset();
    toastMock.mockReset();
    listSessionsMock.mockResolvedValue([]);
    activityMock.mockResolvedValue([]);
    revokeOthersMock.mockResolvedValue({ revoked: 0 });
    revokeSessionMock.mockResolvedValue(undefined);
    rotateRecoveryMock.mockReset();
    changePasswordMock.mockReset();
  });

  it("shows the account as password-only and starts enrolment after the password", async () => {
    statusMock.mockResolvedValue({ enabled: false, enabled_at: null });
    setupMock.mockResolvedValue({
      secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      otpauth_uri: "otpauth://totp/OpenDRP:analyst%40example.com?secret=GEZDGNBVGY3TQOJQ",
      digits: 6,
      period_seconds: 30,
    });
    const user = userEvent.setup();
    renderPage();

    expect(await screen.findByText("Password only")).toBeInTheDocument();

    // The button stays inert until the password is supplied: the API demands it.
    const start = screen.getByRole("button", { name: "Start enrolment" });
    expect(start).toBeDisabled();

    await user.type(screen.getByLabelText("Password"), "Password123!");
    await user.click(start);

    expect(setupMock).toHaveBeenCalledWith("Password123!");
    // The secret is shown for manual entry, and nothing is enabled yet.
    expect(
      await screen.findByText("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
    ).toBeInTheDocument();
    expect(enableMock).not.toHaveBeenCalled();
  });

  it("enables the factor only once a six-digit code is confirmed", async () => {
    statusMock.mockResolvedValue({ enabled: false, enabled_at: null });
    setupMock.mockResolvedValue({
      secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      otpauth_uri: "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ",
      digits: 6,
      period_seconds: 30,
    });
    enableMock.mockResolvedValue({ enabled: true, enabled_at: "2026-01-01T00:00:00Z" });
    const user = userEvent.setup();
    renderPage();

    await screen.findByText("Password only");
    await user.type(screen.getByLabelText("Password"), "Password123!");
    await user.click(screen.getByRole("button", { name: "Start enrolment" }));

    const confirm = await screen.findByRole("button", { name: "Confirm and enable" });
    expect(confirm).toBeDisabled();

    await user.type(screen.getByLabelText("Code from the app"), "123456");
    await user.click(confirm);

    await waitFor(() => expect(enableMock).toHaveBeenCalledWith("Password123!", "123456"));
  });

  it("requires both the password and a live code to disable the factor", async () => {
    statusMock.mockResolvedValue({ enabled: true, enabled_at: "2026-01-01T00:00:00Z" });
    const user = userEvent.setup();
    renderPage();

    expect(await screen.findByText("Two-factor enabled")).toBeInTheDocument();

    const disable = screen.getByRole("button", { name: "Disable two-factor authentication" });
    expect(disable).toBeDisabled();

    await user.type(screen.getByLabelText("Password"), "Password123!");
    expect(disable).toBeDisabled();
    await user.type(screen.getByLabelText("Authenticator code"), "123456");
    expect(disable).toBeEnabled();

    disableMock.mockResolvedValue({ enabled: false, enabled_at: null });
    await user.click(disable);
    await waitFor(() => expect(disableMock).toHaveBeenCalledWith("Password123!", "123456"));
  });

  it("explains the recovery path instead of offering a self-service reset", async () => {
    statusMock.mockResolvedValue({ enabled: true, enabled_at: "2026-01-01T00:00:00Z" });
    renderPage();

    await screen.findByText("Two-factor enabled");
    // The page must not offer a way to remove the factor without a code: that
    // would be the bypass the factor exists to prevent.
    expect(screen.getByText(/administrator can clear the factor/i)).toBeInTheDocument();
  });

  it("describes each recorded security event instead of printing its code", async () => {
    // The account holder is the reader here, and `auth.mfa.enrolled` says
    // nothing to them; the code stays visible only as the audit-trail name.
    statusMock.mockResolvedValue({ enabled: true, enabled_at: "2026-01-01T00:00:00Z" });
    activityMock.mockResolvedValue([
      {
        id: "ev-1",
        timestamp: "2026-01-02T10:00:00Z",
        action: "auth.mfa.enrolled",
        ip_address: "203.0.113.7",
        details: { was_required: false },
      },
      {
        id: "ev-2",
        timestamp: "2026-01-02T09:00:00Z",
        action: "auth.login.failure",
        ip_address: "198.51.100.9",
        details: { reason: "invalid_credentials" },
      },
    ]);
    renderPage();

    expect(await screen.findByText("Second factor turned on")).toBeInTheDocument();
    expect(
      screen.getByText(
        "Sign-in attempt refused — the password did not match an active account",
      ),
    ).toBeInTheDocument();
    // The code is still on the row: it is what the audit log and a support
    // request name the event by.
    expect(screen.getByText("auth.mfa.enrolled")).toBeInTheDocument();
    expect(screen.getByText("203.0.113.7")).toBeInTheDocument();
  });

  it("says so when the account has no recorded activity", async () => {
    statusMock.mockResolvedValue({ enabled: false, enabled_at: null });
    activityMock.mockResolvedValue([]);
    renderPage();

    expect(await screen.findByText(/Nothing recorded yet/i)).toBeInTheDocument();
  });

  it("lists only sessions that can still be used", async () => {
    // The defect this pins: the page used to print rows for sessions the account
    // had already closed, under a card titled "Active sessions", so a session
    // signed out by the reader's own password change read as an unknown device.
    // `GET /auth/sessions` answers with usable sessions only, and the component
    // has no branch that could render a dead one back.
    statusMock.mockResolvedValue({ enabled: true, enabled_at: "2026-01-01T00:00:00Z" });
    listSessionsMock.mockResolvedValue([
      {
        id: "sess-1",
        created_at: "2026-01-02T10:00:00Z",
        last_used_at: "2026-01-02T10:05:00Z",
        current: true,
      },
      {
        id: "sess-2",
        created_at: "2026-01-02T09:00:00Z",
        last_used_at: null,
        current: false,
      },
    ]);
    renderPage();

    expect(await screen.findByText("This browser")).toBeInTheDocument();
    expect(screen.getByText("Another signed-in device")).toBeInTheDocument();
    // Nothing here may describe a session as ended: the API returns only usable
    // ones, so a "(revoked)" row is the old shape coming back.
    expect(screen.queryByText(/\(revoked\)/)).not.toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /Revoke/ })).toHaveLength(1);
    expect(screen.getByRole("button", { name: /Sign out other sessions \(1\)/ })).toBeEnabled();
  });

  it("offers nothing to sign out when this browser is the only session", async () => {
    statusMock.mockResolvedValue({ enabled: false, enabled_at: null });
    listSessionsMock.mockResolvedValue([
      {
        id: "sess-1",
        created_at: "2026-01-02T10:00:00Z",
        last_used_at: "2026-01-02T10:05:00Z",
        current: true,
      },
    ]);
    renderPage();

    expect(await screen.findByText("This browser")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Revoke/ })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign out other sessions" })).toBeDisabled();
  });

  it("moves a revoked session out of the list and into the activity record", async () => {
    statusMock.mockResolvedValue({ enabled: false, enabled_at: null });
    listSessionsMock.mockResolvedValue([
      { id: "sess-1", created_at: "2026-01-02T10:00:00Z", last_used_at: null, current: true },
      { id: "sess-2", created_at: "2026-01-02T09:00:00Z", last_used_at: null, current: false },
    ]);
    revokeSessionMock.mockResolvedValue(undefined);
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByRole("button", { name: "Revoke" }));

    // React Query passes a context object as a second argument, so the id is
    // asserted from the first call rather than from the whole argument list.
    await waitFor(() => expect(revokeSessionMock.mock.calls[0]?.[0]).toBe("sess-2"));
    // The session that was listed a moment ago is now an event in the activity
    // card below, so that list is refetched rather than left stale.
    await waitFor(() => expect(activityMock.mock.calls.length).toBeGreaterThan(1));
  });

  it("states that this browser is the only session when the list is empty", async () => {
    // An empty list is not an error: the access token can be valid while the
    // refresh cookie is not sent (a strict client, a cookie-scoped request), and
    // "nothing to revoke" must read as exactly that.
    statusMock.mockResolvedValue({ enabled: false, enabled_at: null });
    listSessionsMock.mockResolvedValue([]);
    renderPage();

    expect(await screen.findByText(/only signed-in session/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign out other sessions" })).toBeDisabled();
  });

  it("refuses a password change whose two fields disagree, before sending it", async () => {
    // A typo in the repeat field is the common way to lock yourself out of a new
    // password, so the mismatch is caught here and nothing is sent.
    statusMock.mockResolvedValue({ enabled: false, enabled_at: null });
    const user = userEvent.setup();
    renderPage();
    await screen.findByText(/only signed-in session/i);

    await user.type(screen.getByLabelText("Current password"), "old-password-1A");
    await user.type(screen.getByLabelText("New password"), "New-password-1A");
    await user.type(screen.getByLabelText("Repeat new password"), "New-password-1B");
    await user.click(screen.getByRole("button", { name: "Change password" }));

    expect(toastMock).toHaveBeenCalledWith({ variant: "destructive", title: "Passwords do not match" });
    expect(changePasswordMock).not.toHaveBeenCalled();
  });

  it("copies the recovery codes one per line, not with a literal backslash-n", async () => {
    // The join used an escaped backslash, so the clipboard held
    // "AAAA-BBBB\nCCCC-DDDD" as a single line with the two characters `\` and `n`
    // between the codes — unusable from a paste.
    statusMock.mockResolvedValue({ enabled: true, enabled_at: "2026-01-01T00:00:00Z" });
    rotateRecoveryMock.mockResolvedValue({ codes: ["AAAA-BBBB", "CCCC-DDDD"] });
    const writeText = vi.fn().mockResolvedValue(undefined);
    const user = userEvent.setup();
    // After `setup()`: user-event installs its own clipboard stub there, and it
    // would otherwise absorb the write this test is about.
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    renderPage();

    await screen.findByText("Two-factor enabled");
    await user.type(screen.getByLabelText("Password"), "Password123!");
    await user.type(screen.getByLabelText("Authenticator code"), "123456");
    await user.click(screen.getByRole("button", { name: "Generate new recovery codes" }));

    await user.click(await screen.findByRole("button", { name: "Copy codes" }));

    await waitFor(() => expect(writeText).toHaveBeenCalledWith("AAAA-BBBB\nCCCC-DDDD"));
    const copied = writeText.mock.calls[0][0] as string;
    // Two lines, one code each — not one line with an escape in the middle.
    expect(copied.split("\n")).toEqual(["AAAA-BBBB", "CCCC-DDDD"]);
    expect(toastMock).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Recovery codes copied" }),
    );
  });

  it("says the codes were not copied when the clipboard refuses", async () => {
    statusMock.mockResolvedValue({ enabled: true, enabled_at: "2026-01-01T00:00:00Z" });
    rotateRecoveryMock.mockResolvedValue({ codes: ["AAAA-BBBB"] });
    const user = userEvent.setup();
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText: vi.fn().mockRejectedValue(new Error("denied")) },
      configurable: true,
    });
    renderPage();

    await screen.findByText("Two-factor enabled");
    await user.type(screen.getByLabelText("Password"), "Password123!");
    await user.type(screen.getByLabelText("Authenticator code"), "123456");
    await user.click(screen.getByRole("button", { name: "Generate new recovery codes" }));
    await user.click(await screen.findByRole("button", { name: "Copy codes" }));

    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({ variant: "destructive", title: "Could not copy the codes" }),
      ),
    );
  });

  it("settles the stored session when the password change succeeds", async () => {
    // The API answers with a session for the current browser (the change revoked
    // the refresh families), so the client has to adopt that token rather than
    // keep using one the server just invalidated.
    statusMock.mockResolvedValue({ enabled: false, enabled_at: null });
    const session = { access_token: "new-token", token_type: "bearer", user: { email: "analyst@example.com" } };
    changePasswordMock.mockResolvedValue(session);
    const user = userEvent.setup();
    renderPage();
    await screen.findByText(/only signed-in session/i);

    await user.type(screen.getByLabelText("Current password"), "old-password-1A");
    await user.type(screen.getByLabelText("New password"), "New-password-1A");
    await user.type(screen.getByLabelText("Repeat new password"), "New-password-1A");
    await user.click(screen.getByRole("button", { name: "Change password" }));

    await waitFor(() => expect(changePasswordMock).toHaveBeenCalledWith("old-password-1A", "New-password-1A"));
    expect(setSessionMock).toHaveBeenCalledWith(session);
    expect(toastMock).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Password changed", description: "Other sessions were signed out." }),
    );
    // The fields are cleared so the password does not linger on screen.
    expect(screen.getByLabelText("Current password")).toHaveValue("");
    expect(screen.getByLabelText("New password")).toHaveValue("");
  });

  it("signs out every other session and confirms it", async () => {
    statusMock.mockResolvedValue({ enabled: false, enabled_at: null });
    listSessionsMock.mockResolvedValue([
      { id: "sess-1", created_at: "2026-01-02T10:00:00Z", last_used_at: null, current: true },
      { id: "sess-2", created_at: "2026-01-02T09:00:00Z", last_used_at: null, current: false },
    ]);
    revokeOthersMock.mockResolvedValue({ revoked: 1 });
    const user = userEvent.setup();
    renderPage();

    const button = await screen.findByRole("button", { name: /Sign out other sessions \(1\)/ });
    await user.click(button);

    await waitFor(() => expect(revokeOthersMock).toHaveBeenCalledTimes(1));
    expect(toastMock).toHaveBeenCalledWith(expect.objectContaining({ title: "Other sessions revoked" }));
  });
});
