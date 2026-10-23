import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MfaEnrolment } from "@/components/Auth/MfaEnrolment";

const mocks = vi.hoisted(() => ({
  mfaSetup: vi.fn(),
  mfaEnable: vi.fn(),
  mfaQr: vi.fn(),
  toast: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  endpoints: { mfaSetup: mocks.mfaSetup, mfaEnable: mocks.mfaEnable, mfaQr: mocks.mfaQr },
  describeApiError: (error: unknown, fallback?: string) =>
    (error as { message?: string })?.message ?? fallback ?? "Request failed",
}));
vi.mock("@/components/ui/use-toast", () => ({ toast: mocks.toast }));

function renderEnrolment(onEnrolled = vi.fn()) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MfaEnrolment onEnrolled={onEnrolled} />
    </QueryClientProvider>,
  );
}

/** Walk the flow to the step that asks for a code from the app. */
async function startEnrolment(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText("Password"), "correct horse");
  await user.click(screen.getByRole("button", { name: "Start enrolment" }));
  return screen.findByLabelText("Code from the app");
}

describe("MfaEnrolment", () => {
  beforeEach(() => {
    mocks.toast.mockReset();
    mocks.mfaSetup.mockReset().mockResolvedValue({
      secret: "JBSWY3DPEHPK3PXP",
      otpauth_uri: "otpauth://totp/OpenDRP:user@example.com?secret=JBSWY3DPEHPK3PXP",
    });
    mocks.mfaEnable.mockReset().mockResolvedValue({ enabled: true, recovery_codes: [] });
    mocks.mfaQr.mockReset().mockResolvedValue(new Blob(["png"], { type: "image/png" }));
  });

  it("asks for the password before it creates a secret", async () => {
    // A session alone must not be enough to attach an authenticator, so the
    // first request cannot be sent until the account holder re-enters it.
    const user = userEvent.setup();
    renderEnrolment();
    const start = screen.getByRole("button", { name: "Start enrolment" });
    expect(start).toBeDisabled();
    await user.click(start);
    expect(mocks.mfaSetup).not.toHaveBeenCalled();

    await user.type(screen.getByLabelText("Password"), "correct horse");
    await user.click(start);
    await waitFor(() => expect(mocks.mfaSetup).toHaveBeenCalledWith("correct horse"));
  });

  it("names why enrolment could not start and keeps the password form", async () => {
    mocks.mfaSetup.mockRejectedValue(new Error("Your password is incorrect."));
    const user = userEvent.setup();
    renderEnrolment();
    await user.type(screen.getByLabelText("Password"), "wrong");
    await user.click(screen.getByRole("button", { name: "Start enrolment" }));

    await waitFor(() =>
      expect(mocks.toast).toHaveBeenCalledWith(
        expect.objectContaining({
          variant: "destructive",
          title: "Could not start enrolment",
          description: "Your password is incorrect.",
        }),
      ),
    );
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
    expect(screen.queryByLabelText("Code from the app")).not.toBeInTheDocument();
  });

  it("shows the secret and refuses to enable anything until six digits are entered", async () => {
    const user = userEvent.setup();
    renderEnrolment();
    const code = await startEnrolment(user);

    // The secret is on screen for manual entry, and the QR image is the same
    // secret in the form an authenticator app scans.
    expect(screen.getByText("JBSWY3DPEHPK3PXP")).toBeInTheDocument();
    expect(await screen.findByAltText("Authenticator setup QR code")).toBeInTheDocument();

    const confirm = screen.getByRole("button", { name: "Confirm and enable" });
    expect(confirm).toBeDisabled();
    // Letters and spaces are dropped rather than sent: the field is a code, and a
    // value the API would reject should never leave the browser.
    await user.type(code, "12a3 45");
    expect(code).toHaveValue("12345");
    expect(confirm).toBeDisabled();

    await user.type(code, "6");
    expect(confirm).toBeEnabled();
    await user.click(confirm);
    await waitFor(() => expect(mocks.mfaEnable).toHaveBeenCalledWith("correct horse", "123456"));
  });

  it("cancelling leaves the account as it was", async () => {
    const user = userEvent.setup();
    const onEnrolled = vi.fn();
    renderEnrolment(onEnrolled);
    await startEnrolment(user);

    await user.click(screen.getByRole("button", { name: "Cancel" }));

    // The generated secret is dropped and nothing was enabled; the password is
    // kept so a retry does not make the operator type it again, and the caller is
    // not told that a factor was added.
    expect(screen.getByLabelText("Password")).toHaveValue("correct horse");
    expect(screen.getByRole("button", { name: "Start enrolment" })).toBeEnabled();
    expect(screen.queryByText("JBSWY3DPEHPK3PXP")).not.toBeInTheDocument();
    expect(mocks.mfaEnable).not.toHaveBeenCalled();
    expect(onEnrolled).not.toHaveBeenCalled();
  });

  it("keeps the secret on screen when the code is refused", async () => {
    // A wrong code is usually a clock skew, not a reason to lose the secret the
    // operator has already scanned.
    mocks.mfaEnable.mockRejectedValue(new Error("That code was not accepted."));
    const user = userEvent.setup();
    const onEnrolled = vi.fn();
    renderEnrolment(onEnrolled);
    const code = await startEnrolment(user);
    await user.type(code, "000000");
    await user.click(screen.getByRole("button", { name: "Confirm and enable" }));

    await waitFor(() =>
      expect(mocks.toast).toHaveBeenCalledWith(
        expect.objectContaining({
          variant: "destructive",
          title: "That code was not accepted",
          description: "That code was not accepted.",
        }),
      ),
    );
    expect(screen.getByText("JBSWY3DPEHPK3PXP")).toBeInTheDocument();
    expect(onEnrolled).not.toHaveBeenCalled();
  });

  it("hands the recovery codes to the operator once, and only continues after they say they saved them", async () => {
    mocks.mfaEnable.mockResolvedValue({ enabled: true, recovery_codes: ["AAAA-BBBB", "CCCC-DDDD"] });
    const user = userEvent.setup();
    const onEnrolled = vi.fn();
    renderEnrolment(onEnrolled);
    const code = await startEnrolment(user);
    await user.type(code, "123456");
    await user.click(screen.getByRole("button", { name: "Confirm and enable" }));

    expect(await screen.findByText("Save your recovery codes")).toBeInTheDocument();
    expect(screen.getByText("AAAA-BBBB")).toBeInTheDocument();
    expect(screen.getByText("CCCC-DDDD")).toBeInTheDocument();
    expect(mocks.toast).toHaveBeenCalledWith(
      expect.objectContaining({ description: expect.stringContaining("Save your recovery codes") }),
    );
    // The codes are the only way back in if the device is lost, so the flow waits
    // for the operator to confirm they kept them before reporting success.
    expect(onEnrolled).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "I saved the codes" }));
    expect(onEnrolled).toHaveBeenCalledOnce();
  });

  /**
   * The clipboard contents, which is the half of this screen the operator carries
   * away. The join used an escaped backslash, so every code after the first arrived
   * on the same line separated by a literal `\n` — one unusable string pasted into
   * the password manager meant to hold them. The security page had the same bug and
   * was fixed by itself (AUD-068); this block is the other place the codes are shown.
   */
  it("copies the recovery codes one per line", async () => {
    mocks.mfaEnable.mockResolvedValue({ enabled: true, recovery_codes: ["AAAA-BBBB", "CCCC-DDDD"] });
    const user = userEvent.setup();
    renderEnrolment();
    const code = await startEnrolment(user);
    await user.type(code, "123456");
    await user.click(screen.getByRole("button", { name: "Confirm and enable" }));
    expect(await screen.findByText("Save your recovery codes")).toBeInTheDocument();

    // `userEvent.setup()` installs its own clipboard, so the write is replaced
    // after it or the text never reaches the assertion.
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });

    await user.click(screen.getByRole("button", { name: "Copy recovery codes" }));
    expect(writeText).toHaveBeenCalledWith("AAAA-BBBB\nCCCC-DDDD");
    await waitFor(() =>
      expect(mocks.toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Recovery codes copied" }),
      ),
    );
  });

  it("says so when the clipboard refuses the codes, instead of looking like success", async () => {
    mocks.mfaEnable.mockResolvedValue({ enabled: true, recovery_codes: ["AAAA-BBBB"] });
    const user = userEvent.setup();
    renderEnrolment();
    const code = await startEnrolment(user);
    await user.type(code, "123456");
    await user.click(screen.getByRole("button", { name: "Confirm and enable" }));
    expect(await screen.findByText("Save your recovery codes")).toBeInTheDocument();

    const writeText = vi.fn().mockRejectedValue(new Error("denied"));
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    mocks.toast.mockClear();

    await user.click(screen.getByRole("button", { name: "Copy recovery codes" }));
    await waitFor(() =>
      expect(mocks.toast).toHaveBeenCalledWith(
        expect.objectContaining({ variant: "destructive", title: "Could not copy the codes" }),
      ),
    );
  });

  it("reports enrolment complete immediately when the API issues no recovery codes", async () => {
    const user = userEvent.setup();
    const onEnrolled = vi.fn();
    renderEnrolment(onEnrolled);
    const code = await startEnrolment(user);
    await user.type(code, "123456");
    await user.click(screen.getByRole("button", { name: "Confirm and enable" }));

    await waitFor(() => expect(onEnrolled).toHaveBeenCalledOnce());
    expect(mocks.toast).toHaveBeenCalledWith(
      expect.objectContaining({ description: expect.stringContaining("next sign-in will ask for a code") }),
    );
  });
});
