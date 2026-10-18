import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import AcceptInvitationPage from "@/pages/AcceptInvitationPage";

const { acceptInvitationMock } = vi.hoisted(() => ({ acceptInvitationMock: vi.fn() }));

vi.mock("@/lib/api", () => ({
  endpoints: { acceptInvitation: acceptInvitationMock },
  describeApiError: (error: any, fallback?: string) =>
    String(error?.response?.data?.detail ?? error?.message ?? fallback ?? error ?? ""),
}));

function renderPage(entry = "/accept-invitation?token=invite-token") {
  return render(
    <MemoryRouter initialEntries={[entry]}>
      <AcceptInvitationPage />
    </MemoryRouter>,
  );
}

describe("AcceptInvitationPage", () => {
  beforeEach(() => {
    acceptInvitationMock.mockReset().mockResolvedValue({ status: "accepted" });
  });

  it("spends the token with the password the owner chose", async () => {
    const user = userEvent.setup();
    renderPage();

    await user.type(screen.getByLabelText("New password"), "ChosenPass123!");
    await user.type(screen.getByLabelText("Repeat password"), "ChosenPass123!");
    await user.click(screen.getByRole("button", { name: "Set password" }));

    await waitFor(() =>
      expect(acceptInvitationMock).toHaveBeenCalledWith("invite-token", "ChosenPass123!"),
    );
    expect(await screen.findByText("Password set")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Go to sign in" })).toBeInTheDocument();
  });

  it("refuses a mismatch without calling the API", async () => {
    const user = userEvent.setup();
    renderPage();

    await user.type(screen.getByLabelText("New password"), "ChosenPass123!");
    await user.type(screen.getByLabelText("Repeat password"), "OtherPass123!");
    await user.click(screen.getByRole("button", { name: "Set password" }));

    expect(acceptInvitationMock).not.toHaveBeenCalled();
    expect(screen.getByText("The two passwords do not match.")).toBeInTheDocument();
  });

  it("shows the API's own refusal for an expired link", async () => {
    acceptInvitationMock.mockRejectedValue({
      response: { data: { detail: "This invitation is invalid or has expired" } },
    });
    const user = userEvent.setup();
    renderPage();

    await user.type(screen.getByLabelText("New password"), "ChosenPass123!");
    await user.type(screen.getByLabelText("Repeat password"), "ChosenPass123!");
    await user.click(screen.getByRole("button", { name: "Set password" }));

    expect(
      await screen.findByText("This invitation is invalid or has expired"),
    ).toBeInTheDocument();
  });

  it("asks for a link when the page was opened without a token", () => {
    renderPage("/accept-invitation");
    expect(screen.getByText(/needs an invitation link/)).toBeInTheDocument();
  });
});
