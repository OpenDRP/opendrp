/**
 * What a row of the phishing list discloses about a candidate (W0.5).
 *
 * The columns answer "what is it" — domain, matched asset, age, address, status.
 * They do not answer the two questions a phishing analyst opens a candidate with:
 * *who registered it and who can be told to take it down*, and *which sources
 * reported it*. The platform already stores both — the WHOIS enrichment fills the
 * registrar, the abuse contact and the registration date, and every source keeps
 * its own observation — but before this step they reached only the alert email, so
 * triaging from the list meant leaving the page.
 *
 * The disclosure is also where an unresolved fact has to say so: a null registrar
 * is "not resolved yet", never an empty cell that reads as "no registrar", because
 * the difference between the two is whether the enrichment has run at all.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import PhishingPage from "@/pages/PhishingPage";
import { useAuthStore } from "@/store/auth";

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

const resolved = {
  id: "threat-resolved",
  phishing_domain: "paypa1-login.example",
  matched_asset: "paypal.com",
  detection_source: "dnstwist",
  whois_registrar: "Example Registrar",
  whois_abuse_email: "abuse@example-registrar.example",
  domain_created_at: "2026-10-03T00:00:00Z",
  domain_age_days: 12,
  confidence: 55,
  signals: { young_domain: 25 },
  alert_band: "digest",
  status: "active",
  created_at: "2026-10-15T00:00:00Z",
  updated_at: "2026-10-15T00:00:00Z",
};

/** A candidate whose WHOIS answer has not arrived (or never will). */
const unresolved = {
  ...resolved,
  id: "threat-unresolved",
  phishing_domain: "secure-chase.example",
  whois_registrar: undefined,
  whois_abuse_email: undefined,
  domain_created_at: undefined,
  domain_age_days: null,
};

function renderPage(threats: unknown[]) {
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
 * A function matcher rather than a string: `getByText` with a string reads only
 * an element's *own* text nodes, and each line keeps its label in a muted `<span>`
 * beside the value — which is exactly the shape a reader sees as one line.
 */
function line(text: string): HTMLElement {
  return screen.getByText((_value, node) => node?.textContent === text);
}

/** The row's disclosure trigger, once the row itself is on screen. */
async function openDisclosure(): Promise<void> {
  const trigger = await screen.findByRole("button", { name: "Signals" });
  fireEvent.click(trigger);
}

describe("PhishingPage row disclosure (W0.5)", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mocks.evidence.mockResolvedValue({ items: [] });
  });

  it("discloses who registered the candidate and who to report it to", async () => {
    renderPage([resolved]);
    await openDisclosure();

    expect(screen.getByText("Registrar / abuse")).toBeInTheDocument();
    expect(line("Registrar: Example Registrar")).toBeInTheDocument();
    expect(line("Abuse contact: abuse@example-registrar.example")).toBeInTheDocument();
    // The date, read in the zone the rest of the platform renders in.
    expect(line("Registered: 2026-10-03 00:00:00")).toBeInTheDocument();
  });

  it("says a fact nobody resolved is unresolved instead of leaving it blank", async () => {
    renderPage([unresolved]);
    await openDisclosure();

    // Three separate facts, three explicit answers: an empty cell would read as
    // "there is no registrar", which is a different and wrong conclusion.
    expect(line("Registrar: Not resolved yet")).toBeInTheDocument();
    expect(line("Abuse contact: Not resolved yet")).toBeInTheDocument();
    expect(line("Registered: Not resolved yet")).toBeInTheDocument();
  });

  it("lists the sources that reported the candidate as its signals", async () => {
    mocks.evidence.mockResolvedValue({
      items: [
        { source: "dnstwist", matched_asset: "paypal.com", observed_at: null, first_seen_at: "2026-10-14T00:00:00Z", last_seen_at: "2026-10-15T00:00:00Z" },
        { source: "shodan_ssl", matched_asset: "paypal.com", observed_at: "2026-10-15T00:00:00Z", first_seen_at: "2026-10-15T00:00:00Z", last_seen_at: "2026-10-15T00:00:00Z" },
      ],
    });
    renderPage([resolved]);
    // Nothing is read for a row nobody opened: the disclosure is how an operator
    // asks, and asking for twenty rows at once is twenty requests.
    expect(mocks.evidence).not.toHaveBeenCalled();
    await openDisclosure();

    expect(await screen.findByText(/Domain look-alike · paypal\.com/)).toBeInTheDocument();
    expect(screen.getByText(/Certificate text · paypal\.com/)).toBeInTheDocument();
    expect(mocks.evidence).toHaveBeenCalledWith("threat-resolved");
  });
});
