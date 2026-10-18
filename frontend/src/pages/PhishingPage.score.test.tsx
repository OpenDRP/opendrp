/**
 * What the phishing list says about a candidate's score (WI-08/WI-11).
 *
 * The platform computes a confidence from the signals it recorded, and until this
 * step an analyst could only see that number on the *nobody's* side: the list showed
 * what a candidate looks like, never how strong the case against it is, and the
 * two questions an operator actually asks — "what is worth my morning" and "what did
 * the score come from" — had no answer in the UI.
 *
 * Three properties are pinned here: the row carries both the number and the decision
 * it leads to (the band, which is the deployment's thresholds and not a constant this
 * page knows); the disclosure accounts for the number signal by signal, and says so
 * when nothing has fired instead of letting "0" read as a verdict; and both scoring
 * filters reach the request the way the API declares them, because a filter the
 * server refuses is a 422 rather than an empty list.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import PhishingPage from "@/pages/PhishingPage";
import { useAuthStore } from "@/store/auth";

// The select *primitive* is stubbed with a native `<select>`, as in the sort test:
// what has to hold is the value the page hands the request, while the picker's portal
// and pointer handling are the library's and cannot be driven cheaply under jsdom.
vi.mock("@/components/ui/select", () => ({
  Select: ({ value, onValueChange, children }: any) => (
    <select value={value} onChange={(event) => onValueChange(event.target.value)}>
      {children}
    </select>
  ),
  SelectTrigger: () => null,
  SelectValue: () => null,
  SelectContent: ({ children }: any) => children,
  SelectItem: ({ value, children }: any) => <option value={value}>{children}</option>,
}));

const mocks = vi.hoisted(() => ({ list: vi.fn(), evidence: vi.fn(), toast: vi.fn() }));
vi.mock("@/lib/api", () => ({
  endpoints: {
    listPhishing: mocks.list,
    phishingEvidence: mocks.evidence,
    updatePhishingThreat: vi.fn(),
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

/** A candidate the platform has established enough about to alert on at once. */
const strong = {
  id: "threat-strong",
  phishing_domain: "paypa1-login.example",
  matched_asset: "paypal.com",
  detection_source: "dnstwist",
  confidence: 80,
  signals: { young_domain: 25, brand_in_body: 15 },
  alert_band: "direct",
  status: "active",
  created_at: "2026-10-15T00:00:00Z",
  updated_at: "2026-10-15T00:00:00Z",
};

/** A candidate nothing has been established about: no signal, no score, list only. */
const empty = {
  ...strong,
  id: "threat-empty",
  phishing_domain: "secure-chase.example",
  confidence: 0,
  signals: {},
  alert_band: "list",
};

function renderPage(threats: unknown[] = [strong, empty]) {
  useAuthStore.setState({
    user: { id: "user-1", email: "user@example.com", role: "analyst", is_active: true, rate_limit_minutes: 0, created_at: "2026-01-01", updated_at: "2026-01-01" },
    token: "test",
    isHydrated: true,
  });
  mocks.list.mockResolvedValue({ items: threats, total: threats.length, page: 1, size: 20, pages: 1 });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><PhishingPage /></QueryClientProvider>);
}

/**
 * One labelled line of the disclosure, whole.
 *
 * A function matcher rather than a string: `getByText` with a string reads only an
 * element's *own* text nodes, and each line keeps its label in a muted `<span>`
 * beside the value — which is exactly the shape a reader sees as one line.
 */
function line(text: string): HTMLElement {
  return screen.getByText((_value, node) => node?.textContent === text);
}

/** The signal filter: the select that offers a declared signal as a value. */
function signalControl(): HTMLSelectElement {
  const control = screen
    .getAllByRole("combobox")
    .find((node) => Array.from((node as HTMLSelectElement).options).some((option) => option.value === "young_domain"));
  expect(control).toBeDefined();
  return control as HTMLSelectElement;
}

describe("PhishingPage score column and filters (WI-08/WI-11)", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mocks.evidence.mockResolvedValue({ items: [] });
  });

  it("puts the score and the decision it leads to on the row", async () => {
    renderPage();
    await screen.findByText("paypa1-login.example");

    // The resize handle inside the header contributes its own label to the
    // accessible name, hence the substring match.
    expect(screen.getByRole("columnheader", { name: /Confidence/ })).toBeInTheDocument();
    // The number alone would leave the reader to guess what it means; the band is
    // what the deployment's own thresholds would do with the candidate.
    expect(line("80")).toBeInTheDocument();
    expect(screen.getByText("Alerts now")).toBeInTheDocument();
    // And the other end of the scale: nothing established stays in the list.
    expect(screen.getByText("List only")).toBeInTheDocument();
  });

  it("accounts for the score signal by signal when the row is opened", async () => {
    renderPage([strong]);
    await screen.findByText("paypa1-login.example");
    expect(mocks.evidence).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Signals" }));

    expect(line("Confidence: 80 — Alerts now")).toBeInTheDocument();
    expect(line("Young registration +25")).toBeInTheDocument();
    expect(line("Brand in the page body +15")).toBeInTheDocument();
  });

  it("says nothing has fired rather than letting zero read as a verdict", async () => {
    renderPage([empty]);
    await screen.findByText("secure-chase.example");

    fireEvent.click(screen.getByRole("button", { name: "Signals" }));

    expect(line("Confidence: 0 — List only")).toBeInTheDocument();
    expect(screen.getByText(/No signal has fired for this candidate yet/)).toBeInTheDocument();
  });

  it("sends the minimum score as the API declares it, clamped to what it accepts", async () => {
    renderPage();
    await screen.findByText("paypa1-login.example");
    const minimum = screen.getByLabelText("Minimum confidence");

    fireEvent.change(minimum, { target: { value: "40" } });
    await waitFor(() =>
      expect(mocks.list).toHaveBeenLastCalledWith(
        expect.objectContaining({ min_confidence: 40, page: 1 }),
      ),
    );

    // The API refuses a score outside 0…100 with 422, so the field cannot be the
    // way a typo turns into an error page instead of a list.
    fireEvent.change(minimum, { target: { value: "150" } });
    await waitFor(() =>
      expect(mocks.list).toHaveBeenLastCalledWith(
        expect.objectContaining({ min_confidence: 100 }),
      ),
    );
  });

  it("filters by a signal that has fired, as the API names it", async () => {
    renderPage();
    await screen.findByText("paypa1-login.example");

    fireEvent.change(signalControl(), { target: { value: "young_domain" } });

    await waitFor(() =>
      expect(mocks.list).toHaveBeenLastCalledWith(
        expect.objectContaining({ signal: "young_domain", page: 1 }),
      ),
    );
  });
});
