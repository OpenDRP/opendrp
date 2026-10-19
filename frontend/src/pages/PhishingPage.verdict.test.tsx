/**
 * What a decision looks like on the phishing list, and what it sends (WI-12, W1.6).
 *
 * The score is the platform's guess and the verdict is a person's answer, so the two
 * have to be distinguishable at a glance and the decision has to be reachable from the
 * row an analyst is looking at — a triage tool that asks for a judgement somewhere
 * else is a tool nobody judges in.
 *
 * Three properties are pinned here, and each is a way the feature could be a field in
 * a form rather than a decision:
 *
 * * an undecided candidate says so, instead of showing an empty cell that reads as
 *   "reviewed and fine";
 * * confirming sends a confirmation and nothing else — the server refuses a reason
 *   without a verdict and a rejection without one, so the client must not produce
 *   either request;
 * * rejecting asks for the reason *before* it can be sent, because the reason is the
 *   only record of why and the server refuses an empty one.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import PhishingPage from "@/pages/PhishingPage";
import { useAuthStore } from "@/store/auth";

const mocks = vi.hoisted(() => ({ list: vi.fn(), update: vi.fn(), toast: vi.fn() }));
vi.mock("@/lib/api", () => ({
  endpoints: {
    listPhishing: mocks.list,
    phishingEvidence: vi.fn().mockResolvedValue({ items: [] }),
    updatePhishingThreat: mocks.update,
    deletePhishingThreat: vi.fn(),
    cleanOrphanPhishing: vi.fn(),
    scanModule: vi.fn(),
  },
  describeApiError: (error: Error) => error.message,
}));
vi.mock("@/hooks/useModuleJobTypes", () => ({ useModuleJobTypes: () => ["phishing.dnstwist"] }));
vi.mock("@/components/JobsTable", () => ({ JobsTable: () => null }));
vi.mock("@/components/ui/use-toast", () => ({ toast: mocks.toast }));
vi.mock("@/lib/scanPolling", () => ({
  summarizeScanJobs: () => ({ pending: 0, succeeded: 0, failed: 0 }),
  waitForScanJobs: async () => [],
}));

const undecided = {
  id: "threat-open",
  phishing_domain: "nearly-ours.example",
  matched_asset: "paypal.com",
  detection_source: "dnstwist",
  confidence: 0,
  signals: {},
  alert_band: "list",
  verdict: null,
  status: "active",
  created_at: "2026-10-15T00:00:00Z",
  updated_at: "2026-10-15T00:00:00Z",
};

const decided = {
  ...undecided,
  id: "threat-decided",
  phishing_domain: "parked-lookalike.example",
  verdict: "rejected",
  verdict_reason: "parked since 2011, no content",
  verdict_at: "2026-10-15T09:00:00Z",
};

function renderPage(threats: unknown[] = [undecided], role: "admin" | "analyst" | "viewer" = "analyst") {
  useAuthStore.setState({
    user: { id: "user-1", email: "user@example.com", role, is_active: true, rate_limit_minutes: 0, created_at: "2026-01-01", updated_at: "2026-01-01" },
    token: "test",
    isHydrated: true,
  });
  mocks.list.mockResolvedValue({ items: threats, total: threats.length, page: 1, size: 20, pages: 1 });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><PhishingPage /></QueryClientProvider>);
}

describe("PhishingPage verdict (WI-12)", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mocks.update.mockResolvedValue({});
  });

  it("says a candidate nobody has decided about is undecided", async () => {
    renderPage();
    await screen.findByText("nearly-ours.example");

    expect(screen.getByRole("columnheader", { name: /Verdict/ })).toBeInTheDocument();
    expect(screen.getByText("Not decided")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Confirm candidate" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reject candidate" })).toBeInTheDocument();
  });

  it("confirms a candidate by sending the verdict, and only that", async () => {
    renderPage();
    await screen.findByText("nearly-ours.example");

    fireEvent.click(screen.getByRole("button", { name: "Confirm candidate" }));

    await waitFor(() =>
      expect(mocks.update).toHaveBeenCalledWith("threat-open", { verdict: "confirmed" }),
    );
    // The message says what changed about the channel, not that a field was saved.
    await waitFor(() =>
      expect(mocks.toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Candidate confirmed" }),
      ),
    );
  });

  it("asks for the reason before a rejection can be sent, and sends it", async () => {
    renderPage();
    await screen.findByText("nearly-ours.example");

    fireEvent.click(screen.getByRole("button", { name: "Reject candidate" }));

    await screen.findByRole("dialog");
    const submit = screen.getByRole("button", { name: "Reject" });
    // Nothing to record yet: the server refuses an empty reason, so the button must
    // not offer a request that cannot succeed.
    expect(submit).toBeDisabled();
    expect(mocks.update).not.toHaveBeenCalled();

    fireEvent.change(screen.getByLabelText("Reason"), {
      target: { value: "parked since 2011, no content" },
    });
    expect(submit).toBeEnabled();
    fireEvent.click(submit);

    await waitFor(() =>
      expect(mocks.update).toHaveBeenCalledWith("threat-open", {
        verdict: "rejected",
        verdict_reason: "parked since 2011, no content",
      }),
    );
    // Recorded and closed: leaving the dialog open would invite a second, identical
    // decision for a candidate that now has one.
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("shows a recorded decision with its reason, and lets it be taken back", async () => {
    renderPage([decided]);
    await screen.findByText("parked-lookalike.example");

    const badge = screen.getByText("Rejected");
    expect(badge).toHaveAttribute("title", "Reason: parked since 2011, no content");
    // The row offers the opposite decision and the way back, not the one already made.
    expect(screen.getByRole("button", { name: "Confirm candidate" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Reject candidate" })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Clear verdict" }));

    await waitFor(() =>
      expect(mocks.update).toHaveBeenCalledWith("threat-decided", { verdict: null }),
    );
  });

  it("discloses who decided, when and why when the row is opened", async () => {
    renderPage([decided]);
    await screen.findByText("parked-lookalike.example");

    fireEvent.click(screen.getByRole("button", { name: "Signals" }));

    expect(screen.getByText("Decision")).toBeInTheDocument();
    const line = (text: string) => screen.getByText((_value, node) => node?.textContent === text);
    expect(line("Verdict: Rejected")).toBeInTheDocument();
    expect(line("Reason: parked since 2011, no content")).toBeInTheDocument();
    expect(line("Decided: 2026-10-15 09:00:00")).toBeInTheDocument();
  });

  it("does not offer the decision to a viewer", async () => {
    renderPage([undecided], "viewer");
    await screen.findByText("nearly-ours.example");

    expect(screen.queryByRole("button", { name: "Confirm candidate" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Reject candidate" })).not.toBeInTheDocument();
    // A viewer still reads the state: hiding the decision would hide why the channel
    // is silent about a candidate they can see.
    expect(screen.getByText("Not decided")).toBeInTheDocument();
  });
});
